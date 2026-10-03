package app_test

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"

	_ "modernc.org/sqlite"
)

type targetView struct {
	Value  string   `json:"value"`
	Kind   string   `json:"kind"`
	Checks []string `json:"checks"`
}

type fullCase struct {
	ID        int64        `json:"id"`
	Title     string       `json:"title"`
	TicketRef string       `json:"ticket_ref"`
	Status    string       `json:"status"`
	Targets   []targetView `json:"targets"`
	Steps     []step       `json:"steps"`
}

func newCase(h *harness, target string) fullCase {
	h.t.Helper()
	var c fullCase
	if code := h.do("POST", "/api/cases", map[string]string{"target": target}, &c); code != http.StatusCreated {
		h.t.Fatalf("create %q: %d", target, code)
	}
	return c
}

func TestTargetsAreNormalisedAndClassified(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	cases := []struct{ in, value, kind string }{
		{"Example.COM", "example.com", "domain"},
		{"example.com.", "example.com", "domain"},
		{"https://www.Example.com:8443/path?q=1", "www.example.com", "hostname"},
		{"example.co.uk/some/page", "example.co.uk", "domain"},
		{"mail.example.co.uk", "mail.example.co.uk", "hostname"},
		{"  203.0.113.7  ", "203.0.113.7", "ip"},
		{"[2001:DB8::1]", "2001:db8::1", "ip"},
		{"Support@Example.com", "support@example.com", "email"},
		{"bücher.de", "xn--bcher-kva.de", "domain"},
		{"sel._domainkey.Example.com", "sel._domainkey.example.com", "hostname"},
		{"https://user@Example.com/", "example.com", "domain"},
		{"https://medium.com/@bob/post", "medium.com", "domain"},
		{"203.0.113.5:443", "203.0.113.5", "ip"},
		{"[2001:db8::1]:443", "2001:db8::1", "ip"},
		{"example.com:8080", "example.com", "domain"},
		{"github.io", "github.io", "domain"},
		{"someone.github.io", "someone.github.io", "domain"},
	}
	for _, tc := range cases {
		c := newCase(h, tc.in)
		if got := c.Targets[0]; got.Value != tc.value || got.Kind != tc.kind {
			t.Errorf("%q → %s (%s), want %s (%s)", tc.in, got.Value, got.Kind, tc.value, tc.kind)
		}
	}
}

func TestInvalidTargetsAreRejected(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	for _, in := range []string{"", "not a host", "com", "co.uk", "a..b.com", "-bad.com", "two@at@signs.com", "http://"} {
		var body struct{ Error string }
		if code := h.do("POST", "/api/cases", map[string]string{"target": in}, &body); code != http.StatusBadRequest || body.Error == "" {
			t.Errorf("%q: got %d %q, want 400 with a message", in, code, body.Error)
		}
	}
}

func TestOnlyApplicableChecksAreOfferedAndRun(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "203.0.113.7")
	if len(c.Targets[0].Checks) != 0 || len(c.Steps) != 0 {
		t.Fatalf("IP target: checks %v, steps %d; DNS Lookup doesn't apply to IPs", c.Targets[0].Checks, len(c.Steps))
	}
	d := newCase(h, "example.com")
	if !slices.Contains(d.Targets[0].Checks, "dns_lookup") || len(d.Steps) != 1 {
		t.Fatalf("domain target: checks %v, steps %d", d.Targets[0].Checks, len(d.Steps))
	}
}

func TestACaseHoldsSeveralTargets(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	h.waitStep(c.ID)

	var after fullCase
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/targets", map[string]string{"target": "WWW.example.com"}, &after); code != http.StatusOK {
		t.Fatalf("add target: %d", code)
	}
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/targets", map[string]string{"target": "203.0.113.7"}, &after)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/targets", map[string]string{"target": "example.com"}, &after) // duplicate

	var got []string
	for _, tg := range after.Targets {
		got = append(got, tg.Value)
	}
	if want := []string{"example.com", "www.example.com", "203.0.113.7"}; !slices.Equal(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if len(after.Steps) != 2 {
		t.Fatalf("steps = %d, want 2 (DNS Lookup for each name, none for the IP or the duplicate)", len(after.Steps))
	}
	if code := h.do("POST", "/api/cases/999/targets", map[string]string{"target": "example.com"}, nil); code != http.StatusNotFound {
		t.Fatalf("unknown case: %d", code)
	}
}

func TestTitleTicketReferenceAndStatusAreEditable(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	if c.Status != "open" {
		t.Fatalf("new case status %q", c.Status)
	}
	var got fullCase
	h.do("PATCH", "/api/cases/"+itoa(c.ID), map[string]string{"title": "  Mail bouncing  ", "ticket_ref": " #48213 "}, &got)
	if got.Title != "Mail bouncing" || got.TicketRef != "#48213" {
		t.Fatalf("after edit: %+v", got)
	}
	h.do("PATCH", "/api/cases/"+itoa(c.ID), map[string]string{"status": "resolved"}, &got)
	if got.Status != "resolved" || got.Title != "Mail bouncing" {
		t.Fatalf("after resolve: %+v", got)
	}
	h.do("PATCH", "/api/cases/"+itoa(c.ID), map[string]string{"status": "open"}, &got)
	if got.Status != "open" {
		t.Fatalf("after reopen: %+v", got)
	}
	if code := h.do("PATCH", "/api/cases/"+itoa(c.ID), map[string]string{"status": "closed"}, nil); code != http.StatusBadRequest {
		t.Fatalf("bad status: %d", code)
	}
}

func TestRecentCasesListMostRecentlyActiveFirst(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	a := newCase(h, "a.example.com")
	h.do("PATCH", "/api/cases/"+itoa(a.ID), map[string]string{"ticket_ref": "#1"}, nil)
	b := newCase(h, "b.example.com")
	time.Sleep(5 * time.Millisecond)
	h.do("PUT", "/api/active", map[string]any{"case_id": a.ID}, nil)

	var list []fullCase
	h.do("GET", "/api/cases", nil, &list)
	if len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID || list[0].TicketRef != "#1" {
		t.Fatalf("recent = %+v", list)
	}
}

func TestActiveCaseIsRestoredAfterRestart(t *testing.T) {
	dir := t.TempDir()
	resolver := fakeDNS(t, exampleZone, false)
	h := start(t, app.Config{DataDir: dir, Net: app.Net{Resolver: resolver}})

	var active struct{ Case *fullCase }
	h.do("GET", "/api/active", nil, &active)
	if active.Case != nil {
		t.Fatalf("fresh install has an active case: %+v", active.Case)
	}
	c := newCase(h, "example.com")
	h.waitStep(c.ID)
	h.stop()

	h2 := start(t, app.Config{DataDir: dir, Net: app.Net{Resolver: resolver}})
	h2.do("GET", "/api/active", nil, &active)
	if active.Case == nil || active.Case.ID != c.ID || len(active.Case.Steps) != 1 {
		t.Fatalf("after restart active = %+v", active.Case)
	}

	// Starting a new Case clears the active one until a Target is typed.
	h2.do("PUT", "/api/active", map[string]any{"case_id": nil}, nil)
	active.Case = nil
	h2.do("GET", "/api/active", nil, &active)
	if active.Case != nil {
		t.Fatalf("cleared active = %+v", active.Case)
	}
}

func TestDatabaseFromFirstReleaseIsUpgraded(t *testing.T) {
	dir := t.TempDir()
	// The schema and data exactly as the walking skeleton (#2) wrote them.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "stackwell.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE cases (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL);
		CREATE TABLE targets (case_id INTEGER NOT NULL REFERENCES cases(id), value TEXT NOT NULL, UNIQUE (case_id, value));
		CREATE TABLE steps (id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), check_key TEXT NOT NULL,
			target TEXT NOT NULL, status TEXT NOT NULL, result TEXT, error TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL, finished_at TEXT);
		INSERT INTO cases VALUES (1, '2026-10-01T10:00:00Z');
		INSERT INTO targets VALUES (1, 'example.com');
		INSERT INTO steps VALUES (1, 1, 'dns_lookup', 'example.com', 'ok', '{"rcode":"NOERROR","records":{"A":["1.2.3.4"]}}', '', '2026-10-01T10:00:00Z', '2026-10-01T10:00:01Z');`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	h := start(t, app.Config{DataDir: dir, Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	var c fullCase
	if code := h.do("GET", "/api/cases/1", nil, &c); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if c.Status != "open" || c.Targets[0].Value != "example.com" || c.Targets[0].Kind != "domain" || c.Steps[0].Result.Records["A"][0] != "1.2.3.4" {
		t.Fatalf("upgraded case = %+v", c)
	}
	var list []fullCase
	h.do("GET", "/api/cases", nil, &list)
	if len(list) != 1 {
		t.Fatalf("recent = %+v", list)
	}
}
