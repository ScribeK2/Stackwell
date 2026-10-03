package app_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type runView struct {
	ID       int64    `json:"id"`
	Playbook string   `json:"playbook"`
	Label    string   `json:"label"`
	Target   string   `json:"target"`
	Status   string   `json:"status"`
	Boundary []string `json:"boundary"`
	Total    int      `json:"total"`
	Skipped  []struct {
		Entry  string `json:"entry"`
		Reason string `json:"reason"`
	} `json:"skipped"`
}

type runStepView struct {
	ID     int64  `json:"id"`
	Check  string `json:"check"`
	Target string `json:"target"`
	Status string `json:"status"`
	RunID  int64  `json:"run_id"`
}

type runCase struct {
	Targets  []targetView  `json:"targets"`
	Steps    []runStepView `json:"steps"`
	Runs     []runView     `json:"runs"`
	Findings []finding     `json:"findings"`
}

func (h *harness) runCase(caseID int64) runCase {
	h.t.Helper()
	var c runCase
	h.do("GET", "/api/cases/"+itoa(caseID), nil, &c)
	return c
}

// startRun starts a Playbook and returns the new run's id.
func (h *harness) startRun(caseID int64, playbook, target string) int64 {
	h.t.Helper()
	var c runCase
	if code := h.do("POST", "/api/cases/"+itoa(caseID)+"/runs", map[string]string{"playbook": playbook, "target": target}, &c); code != http.StatusOK {
		h.t.Fatalf("start %s on %s: %d", playbook, target, code)
	}
	return c.Runs[len(c.Runs)-1].ID
}

// waitRun polls until the run is no longer running.
func (h *harness) waitRun(caseID, runID int64) runCase {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c := h.runCase(caseID)
		for _, r := range c.Runs {
			if r.ID == runID && r.Status != "running" {
				return c
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatal("run never finished")
	return runCase{}
}

func runSteps(c runCase, runID int64) []runStepView {
	var out []runStepView
	for _, s := range c.Steps {
		if s.RunID == runID {
			out = append(out, s)
		}
	}
	return out
}

func checksOf(steps []runStepView) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.Check+"@"+s.Target)
	}
	slices.Sort(out)
	return out
}

// hangingNet answers nothing: DNS is silent, RDAP and TCP block until cancelled.
func hangingNet(t *testing.T) app.Net {
	rdap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(rdap.Close)
	return app.Net{
		Resolver: fakeDNS(t, "", true),
		RDAP:     map[string]string{"com": rdap.URL + "/"},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
}

// refuseDial refuses every remote address but lets local fakes (RDAP) through.
func refuseDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if strings.HasPrefix(addr, "127.0.0.1:") {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return nil, errors.New("connection refused")
}

func TestPlaybooksAreListedWithTheirKinds(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	var list []struct {
		Name     string   `json:"name"`
		Label    string   `json:"label"`
		Kinds    []string `json:"kinds"`
		Boundary []string `json:"boundary"`
		Entries  []struct {
			ID    string `json:"id"`
			Check string `json:"check"`
		} `json:"entries"`
	}
	h.do("GET", "/api/playbooks", nil, &list)
	i := slices.IndexFunc(list, func(p struct {
		Name     string   `json:"name"`
		Label    string   `json:"label"`
		Kinds    []string `json:"kinds"`
		Boundary []string `json:"boundary"`
		Entries  []struct {
			ID    string `json:"id"`
			Check string `json:"check"`
		} `json:"entries"`
	}) bool {
		return p.Name == "orientation"
	})
	if i == -1 {
		t.Fatalf("no orientation playbook in %+v", list)
	}
	o := list[i]
	if o.Label != "Orientation" || !slices.Equal(o.Kinds, []string{"domain"}) || len(o.Boundary) == 0 || len(o.Entries) != 3 {
		t.Fatalf("orientation = %+v", o)
	}
}

func TestOrientationRunsEndToEnd(t *testing.T) {
	rdap, _ := fakeRDAP(t, 0, rdapDomain(time.Now().AddDate(1, 0, 0)))
	h := start(t, app.Config{Net: app.Net{
		Resolver: fakeDNS(t, exampleZone, false),
		RDAP:     map[string]string{"com": rdap},
		Dial:     refuseDial,
	}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)

	run := h.startRun(c.ID, "orientation", "example.com")
	got := h.waitRun(c.ID, run)
	r := got.Runs[len(got.Runs)-1]
	if r.Status != "done" || r.Label != "Orientation" || r.Target != "example.com" || r.Total != 3 || len(r.Boundary) == 0 {
		t.Fatalf("run = %+v", r)
	}
	steps := runSteps(got, run)
	if want := []string{"dns_lookup@example.com", "hosting_reachability@example.com", "registration@example.com"}; !slices.Equal(checksOf(steps), want) {
		t.Fatalf("run steps = %v, want %v", checksOf(steps), want)
	}
	for _, s := range steps {
		if s.Status != "ok" {
			t.Errorf("step %s = %s", s.Check, s.Status)
		}
	}
	if !slices.Contains(codes(got.Findings), "registration_ok") {
		t.Errorf("findings = %v", codes(got.Findings))
	}
}

func TestIndependentEntriesRunConcurrently(t *testing.T) {
	h := start(t, app.Config{Net: hangingNet(t), CheckTimeout: 5 * time.Second})
	c := newCase(h, "example.com")
	run := h.startRun(c.ID, "orientation", "example.com")
	// Run sequentially, only the first entry would have started by now.
	steps := runSteps(h.runCase(c.ID), run)
	if len(steps) != 3 {
		t.Fatalf("started %d of 3 independent entries at once: %v", len(steps), checksOf(steps))
	}
	for _, s := range steps {
		if s.Status != "running" {
			t.Errorf("%s = %s", s.Check, s.Status)
		}
	}
}

func TestCancellingARunStopsItsSteps(t *testing.T) {
	resolver, setZone := mutableDNS(t, exampleZone, false)
	n := hangingNet(t)
	n.Resolver = resolver
	h := start(t, app.Config{Net: n, CheckTimeout: 5 * time.Second})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1) // a good DNS Lookup first
	setZone(noAnswer)

	run := h.startRun(c.ID, "orientation", "example.com")
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/runs/"+itoa(run)+"/cancel", nil, nil); code != http.StatusOK {
		t.Fatalf("cancel: %d", code)
	}
	got := h.waitRun(c.ID, run)
	if r := got.Runs[len(got.Runs)-1]; r.Status != "cancelled" {
		t.Fatalf("run = %+v", r)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got = h.runCase(c.ID)
		if !slices.ContainsFunc(runSteps(got, run), func(s runStepView) bool { return s.Status == "running" }) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, s := range runSteps(got, run) {
		if s.Status != "cancelled" {
			t.Errorf("%s = %s, want cancelled", s.Check, s.Status)
		}
	}
	fs := codes(got.Findings)
	if slices.Contains(fs, "check_failed") {
		t.Errorf("a cancelled Step was reported as failed: %v", fs)
	}
	if !slices.Contains(fs, "dns_resolves") {
		t.Errorf("a cancelled re-run erased the earlier DNS Findings: %v", fs)
	}
	// Cancelling again is harmless; an unknown run is 404.
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/runs/"+itoa(run)+"/cancel", nil, nil); code != http.StatusOK {
		t.Errorf("second cancel: %d", code)
	}
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/runs/999/cancel", nil, nil); code != http.StatusNotFound {
		t.Errorf("unknown run: %d", code)
	}
}

func TestARunCutShortByARestartIsCancelled(t *testing.T) {
	dir := t.TempDir()
	h := start(t, app.Config{DataDir: dir, Net: hangingNet(t), CheckTimeout: 5 * time.Second})
	c := newCase(h, "example.com")
	run := h.startRun(c.ID, "orientation", "example.com")
	h.stop()
	h2 := start(t, app.Config{DataDir: dir, Net: hangingNet(t)})
	for _, r := range h2.runCase(c.ID).Runs {
		if r.ID == run && r.Status != "cancelled" {
			t.Fatalf("run after restart = %+v", r)
		}
	}
}

func TestAPlaybookOnlyRunsOnTheKindsItDeclares(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "www.example.com")
	h.waitSteps(c.ID, 1)
	for _, tc := range []struct{ playbook, target string }{
		{"orientation", "www.example.com"}, // a hostname
		{"orientation", "other.com"},       // not a Target of the Case
		{"no_such_playbook", "www.example.com"},
	} {
		if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/runs", map[string]string{"playbook": tc.playbook, "target": tc.target}, nil); code != http.StatusBadRequest {
			t.Errorf("%s on %s: %d, want 400", tc.playbook, tc.target, code)
		}
	}
}

// writePlaybook puts one YAML Playbook in a fresh folder and returns the folder.
func writePlaybook(t *testing.T, yaml string) string {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(strings.TrimSpace(yaml)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const mxPlaybook = `
name: mx_check
label: MX check
kinds: [domain]
entries:
  - id: dns
    check: dns_lookup
  - id: mx_ports
    check: hosting_reachability
    depends_on: dns
    target: primary_mx_host
boundary:
  - The mail provider's own queues and logs.
`

func TestADependentEntryRunsOnTheTargetItDerives(t *testing.T) {
	h := start(t, app.Config{
		Net:         app.Net{Resolver: fakeDNS(t, exampleZone+"mail.example.com. 300 IN A 192.0.2.25\n", false), Dial: refuseDial},
		PlaybookDir: writePlaybook(t, mxPlaybook),
	})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	run := h.startRun(c.ID, "mx_check", "example.com")
	got := h.waitRun(c.ID, run)

	if want := []string{"dns_lookup@example.com", "hosting_reachability@mail.example.com"}; !slices.Equal(checksOf(runSteps(got, run)), want) {
		t.Fatalf("run steps = %v, want %v", checksOf(runSteps(got, run)), want)
	}
	if !slices.ContainsFunc(got.Targets, func(t targetView) bool { return t.Value == "mail.example.com" }) {
		t.Fatalf("derived Target not added: %+v", got.Targets)
	}
}

func TestADependentEntryIsSkippedWhenItsTargetCantBeDerived(t *testing.T) {
	for _, tc := range []struct{ name, zone, reason string }{
		{"no mx", "example.com. 300 IN A 192.0.2.1\nexample.com. 300 IN NS ns.example.net.\n", "no MX"},
		{"dependency failed", noAnswer, "did not complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, setZone := mutableDNS(t, exampleZone, false)
			h := start(t, app.Config{
				Net:          app.Net{Resolver: resolver, Dial: refuseDial},
				PlaybookDir:  writePlaybook(t, mxPlaybook),
				CheckTimeout: 300 * time.Millisecond,
			})
			c := newCase(h, "example.com")
			h.waitSteps(c.ID, 1)
			setZone(tc.zone)
			run := h.startRun(c.ID, "mx_check", "example.com")
			got := h.waitRun(c.ID, run)
			r := got.Runs[len(got.Runs)-1]
			if r.Status != "done" || len(r.Skipped) != 1 || r.Skipped[0].Entry != "mx_ports" || !strings.Contains(r.Skipped[0].Reason, tc.reason) {
				t.Fatalf("run = %+v", r)
			}
			if steps := runSteps(got, run); len(steps) != 1 {
				t.Fatalf("skipped entry still ran: %v", checksOf(steps))
			}
		})
	}
}

func TestInvalidPlaybooksAreRejectedAtStart(t *testing.T) {
	for name, yaml := range map[string]string{
		"unknown check":     "name: x\nlabel: X\nkinds: [domain]\nentries:\n  - check: no_such_check\n",
		"unknown depends":   "name: x\nlabel: X\nkinds: [domain]\nentries:\n  - check: dns_lookup\n    depends_on: nope\n",
		"cycle":             "name: x\nlabel: X\nkinds: [domain]\nentries:\n  - id: a\n    check: dns_lookup\n    depends_on: b\n  - id: b\n    check: dns_lookup\n    depends_on: a\n",
		"unknown resolver":  "name: x\nlabel: X\nkinds: [domain]\nentries:\n  - id: a\n    check: dns_lookup\n  - check: blacklist\n    depends_on: a\n    target: the_moon\n",
		"kind not accepted": "name: x\nlabel: X\nkinds: [ip]\nentries:\n  - check: registration\n",
		"bad option":        "name: x\nlabel: X\nkinds: [domain]\nentries:\n  - check: hosting_reachability\n    options: {depth: enormous}\n",
		"not yaml":          "name: [unclosed\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := app.New(app.Config{DataDir: t.TempDir(), PlaybookDir: writePlaybook(t, yaml)})
			if err == nil {
				t.Fatal("invalid Playbook accepted")
			}
		})
	}
}

func TestAPlaybookWithoutBoundaryNotesHasAnEmptyList(t *testing.T) {
	h := start(t, app.Config{
		Net:         app.Net{Resolver: fakeDNS(t, exampleZone, false)},
		PlaybookDir: writePlaybook(t, "name: bare\nlabel: Bare\nkinds: [domain]\nentries:\n  - check: dns_lookup\n"),
	})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	run := h.startRun(c.ID, "bare", "example.com")
	h.waitRun(c.ID, run)
	var raw struct {
		Runs []map[string]any `json:"runs"`
	}
	h.do("GET", "/api/cases/"+itoa(c.ID), nil, &raw)
	if b, ok := raw.Runs[0]["boundary"].([]any); !ok || len(b) != 0 {
		t.Fatalf("boundary = %#v, want []", raw.Runs[0]["boundary"])
	}
}
