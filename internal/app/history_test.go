package app_test

import (
	"database/sql"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type listedCase struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	TicketRef string `json:"ticket_ref"`
	Status    string `json:"status"`
	MatchedBy string `json:"matched_by"`
}

func (h *harness) list(query string) []listedCase {
	h.t.Helper()
	var out []listedCase
	if code := h.do("GET", "/api/cases"+query, nil, &out); code != http.StatusOK {
		h.t.Fatalf("list %s: %d", query, code)
	}
	return out
}

func ids(cs []listedCase) []int64 {
	var out []int64
	for _, c := range cs {
		out = append(out, c.ID)
	}
	slices.Sort(out)
	return out
}

// threeCases: an open one with a ticket, one with a missing MX (a Finding),
// and a resolved one.
func threeCases(t *testing.T) (*harness, string, [3]int64) {
	dir := t.TempDir()
	zone := exampleZone + `
nomx.test. 300 IN A 192.0.2.1
nomx.test. 300 IN NS ns.nomx.test.`
	h := start(t, app.Config{DataDir: dir, Net: app.Net{Resolver: fakeDNS(t, zone, false)}})
	a := newCase(h, "example.com")
	h.do("PATCH", "/api/cases/"+itoa(a.ID), map[string]string{"ticket_ref": "#48213", "title": "Bounces from Outlook"}, nil)
	h.do("POST", "/api/cases/"+itoa(a.ID)+"/targets", map[string]string{"target": "mail.example.com"}, nil)
	b := newCase(h, "nomx.test")
	h.waitSteps(b.ID, 1)
	r := newCase(h, "old.example.org")
	h.do("PATCH", "/api/cases/"+itoa(r.ID), map[string]string{"status": "resolved", "ticket_ref": "#10001"}, nil)
	return h, dir, [3]int64{a.ID, b.ID, r.ID}
}

func TestResolvedCasesAreHiddenUnlessAskedFor(t *testing.T) {
	h, _, c := threeCases(t)
	if got := ids(h.list("")); !slices.Equal(got, []int64{c[0], c[1]}) {
		t.Fatalf("default list = %v", got)
	}
	if got := ids(h.list("?resolved=1")); !slices.Equal(got, []int64{c[0], c[1], c[2]}) {
		t.Fatalf("with resolved = %v", got)
	}
}

func TestSearchFindsCasesByTargetTicketOrFinding(t *testing.T) {
	h, _, c := threeCases(t)
	for _, tc := range []struct {
		q       string
		want    []int64
		matched string
	}{
		{"MAIL.example", []int64{c[0]}, "Target"},
		{"48213", []int64{c[0]}, "Ticket"},
		{"outlook", []int64{c[0]}, "Title"},
		{"no mx records", []int64{c[1]}, "Finding"},
		{"10001", []int64{c[2]}, "Ticket"}, // a search reaches resolved Cases too
		{"nothing-matches-this", nil, ""},
	} {
		got := h.list("?q=" + url.QueryEscape(tc.q))
		if !slices.Equal(ids(got), tc.want) {
			t.Errorf("q=%q: %v, want %v", tc.q, ids(got), tc.want)
			continue
		}
		for _, g := range got {
			if !strings.HasPrefix(g.MatchedBy, tc.matched) {
				t.Errorf("q=%q matched_by = %q, want %s…", tc.q, g.MatchedBy, tc.matched)
			}
		}
	}
}

func backdate(t *testing.T, dir string, caseID int64, age time.Duration) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "stackwell.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := time.Now().Add(-age).UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`UPDATE cases SET last_active_at = ?, created_at = ? WHERE id = ?`, old, old, caseID); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeAsksFirstThenRemovesOldCasesEntirely(t *testing.T) {
	h, dir, c := threeCases(t)
	h.do("PUT", "/api/active", map[string]any{"case_id": c[0]}, nil) // the one on screen is never purged
	backdate(t, dir, c[1], 40*24*time.Hour)
	backdate(t, dir, c[2], 100*24*time.Hour)

	var preview struct {
		WouldDelete int `json:"would_delete"`
		Deleted     int `json:"deleted"`
	}
	if code := h.do("POST", "/api/cases/purge", map[string]any{"older_than_days": 30}, &preview); code != http.StatusOK || preview.WouldDelete != 2 || preview.Deleted != 0 {
		t.Fatalf("preview: %d %+v", code, preview)
	}
	if got := ids(h.list("?resolved=1")); len(got) != 3 {
		t.Fatalf("a preview deleted something: %v", got)
	}

	var done struct{ Deleted int }
	h.do("POST", "/api/cases/purge", map[string]any{"older_than_days": 30, "confirm": true}, &done)
	if done.Deleted != 2 {
		t.Fatalf("deleted %d, want 2", done.Deleted)
	}
	if got := ids(h.list("?resolved=1")); !slices.Equal(got, []int64{c[0]}) {
		t.Fatalf("after purge = %v", got)
	}
	if code := h.do("GET", "/api/cases/"+itoa(c[1]), nil, nil); code != http.StatusNotFound {
		t.Fatalf("purged Case still readable: %d", code)
	}
	// Everything a purged Case owned is gone, not orphaned.
	db, _ := sql.Open("sqlite", "file:"+filepath.Join(dir, "stackwell.db"))
	defer db.Close()
	for _, table := range []string{"targets", "steps"} {
		var n int
		db.QueryRow(`SELECT count(*) FROM `+table+` WHERE case_id IN (?, ?)`, c[1], c[2]).Scan(&n)
		if n != 0 {
			t.Errorf("%d orphaned rows in %s", n, table)
		}
	}
}

func TestPurgeNeedsASensibleAge(t *testing.T) {
	h, _, _ := threeCases(t)
	for _, days := range []any{-1, 0, "thirty"} {
		if code := h.do("POST", "/api/cases/purge", map[string]any{"older_than_days": days, "confirm": true}, nil); code != http.StatusBadRequest {
			t.Errorf("older_than_days=%v: %d", days, code)
		}
	}
	if got := ids(h.list("?resolved=1")); len(got) != 3 {
		t.Fatalf("a bad purge deleted Cases: %v", got)
	}
}

func TestWorkingOnACaseKeepsItFromBeingPurged(t *testing.T) {
	h, dir, c := threeCases(t)
	backdate(t, dir, c[0], 40*24*time.Hour)
	backdate(t, dir, c[1], 40*24*time.Hour)
	// Work on the first Case without switching to it: paste Evidence.
	h.do("POST", "/api/cases/"+itoa(c[0])+"/evidence", map[string]string{"kind": "email_headers", "raw": "From: a@example.com\nSubject: hi"}, nil)
	// The second is the one open on screen.
	h.do("PUT", "/api/active", map[string]any{"case_id": c[1]}, nil)
	backdate(t, dir, c[1], 40*24*time.Hour)

	var r struct{ Deleted int }
	h.do("POST", "/api/cases/purge", map[string]any{"older_than_days": 30, "confirm": true}, &r)
	left := ids(h.list("?resolved=1"))
	if !slices.Contains(left, c[0]) {
		t.Error("a Case worked on today was purged")
	}
	if !slices.Contains(left, c[1]) {
		t.Error("the Case open on screen was purged")
	}
}

func TestConfirmDeletesWhatThePreviewCounted(t *testing.T) {
	h, dir, c := threeCases(t)
	h.do("PUT", "/api/active", map[string]any{"case_id": c[0]}, nil)
	backdate(t, dir, c[1], 40*24*time.Hour)
	var preview struct {
		WouldDelete int    `json:"would_delete"`
		Cutoff      string `json:"cutoff"`
	}
	h.do("POST", "/api/cases/purge", map[string]any{"older_than_days": 30}, &preview)
	if preview.WouldDelete != 1 || preview.Cutoff == "" {
		t.Fatalf("preview = %+v", preview)
	}
	// Between preview and confirm another Case ages past the line: active
	// just after the preview's cutoff, so a cutoff recomputed at confirm
	// time would catch it.
	cutoff, _ := time.Parse(time.RFC3339Nano, preview.Cutoff)
	backdate(t, dir, c[2], time.Since(cutoff)-time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	var done struct{ Deleted int }
	h.do("POST", "/api/cases/purge", map[string]any{"older_than_days": 30, "confirm": true, "cutoff": preview.Cutoff}, &done)
	if done.Deleted != 1 {
		t.Fatalf("deleted %d, the preview said 1", done.Deleted)
	}
}
