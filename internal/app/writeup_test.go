package app_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

func (h *harness) writeup(caseID int64, format string) string {
	h.t.Helper()
	var w struct{ Text string }
	if code := h.do("GET", "/api/cases/"+itoa(caseID)+"/writeup?format="+format, nil, &w); code != http.StatusOK {
		h.t.Fatalf("writeup: %d", code)
	}
	return w.Text
}

const notesPlaybook = `
name: dns_check
label: DNS check
kinds: [domain]
entries:
  - check: dns_lookup
boundary:
  - The registrar account isn't visible from outside.
`

var clock = regexp.MustCompile(`\d{2}:\d{2}`)

// realisticCase: a Case with a ticket, a problem that a re-run shows fixed, a
// Playbook run, rep notes, and a saved secret that must never leak.
func realisticCase(t *testing.T) (*harness, int64) {
	resolver, setZone := mutableDNS(t, `
example.com. 300 IN NS ns.example.net.
example.com. 300 IN A 192.0.2.1`, false)
	h := start(t, app.Config{ConfigDir: t.TempDir(), Net: app.Net{Resolver: resolver}, PlaybookDir: writePlaybook(t, notesPlaybook)})
	h.do("PUT", "/api/settings/secrets/ipinfo_token", map[string]string{"value": "SECRET-ipinfo-0123456789"}, nil)

	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1) // no MX yet
	h.do("PATCH", "/api/cases/"+itoa(c.ID), map[string]string{
		"title": "Mail not arriving", "ticket_ref": "#48213",
		"notes": "Customer moved mail to NewHost on Monday.\nAsked them to confirm the MX change.",
	}, nil)
	setZone(`
example.com. 300 IN NS ns.example.net.
example.com. 300 IN A 192.0.2.1
example.com. 300 IN MX 10 mx1.newhost.net.`)
	run := h.startRun(c.ID, "dns_check", "example.com") // re-runs DNS Lookup: MX now there
	h.waitRun(c.ID, run)
	return h, c.ID
}

func TestTheWriteUpTellsTheWholeStory(t *testing.T) {
	h, id := realisticCase(t)
	md := h.writeup(id, "markdown")

	for _, want := range []string{
		"# Mail not arriving",
		"**Ticket:** #48213",
		"**Targets:** example.com (domain)",
		"## Findings",
		"## Changes",
		"MX: added `10 mx1.newhost.net.`",
		"Resolved: No MX records (example.com, ",
		"## Not visible from here",
		"- The registrar account isn't visible from outside.",
		"## Notes",
		"Customer moved mail to NewHost on Monday.\nAsked them to confirm the MX change.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("write-up lacks %q\n---\n%s", want, md)
		}
	}
	if !clock.MatchString(md[strings.Index(md, "## Changes"):]) {
		t.Errorf("changes have no times:\n%s", md)
	}
	if strings.Contains(md, "No MX records") && !strings.Contains(md, "Resolved: No MX records") {
		t.Errorf("a fixed problem is still listed as current:\n%s", md)
	}
	// Problems come before fine things, critical before warning.
	if i, j := strings.Index(md, "## Findings"), strings.Index(md, "Looks fine"); i == -1 || j < i {
		t.Errorf("ok Findings aren't after the problems:\n%s", md)
	}
}

func TestPlainTextWriteUpHasNoMarkup(t *testing.T) {
	h, id := realisticCase(t)
	txt := h.writeup(id, "text")
	for _, markup := range []string{"# ", "**", "`", "## "} {
		if strings.Contains(txt, markup) {
			t.Errorf("plain text contains %q:\n%s", markup, txt)
		}
	}
	for _, want := range []string{"Mail not arriving", "Ticket: #48213", "FINDINGS", "Resolved: No MX records (example.com, ", "Customer moved mail to NewHost"} {
		if !strings.Contains(txt, want) {
			t.Errorf("plain text lacks %q:\n%s", want, txt)
		}
	}
}

func TestNoSecretEverAppearsInAWriteUp(t *testing.T) {
	h, id := realisticCase(t)
	for _, f := range []string{"markdown", "text"} {
		if strings.Contains(h.writeup(id, f), "SECRET-ipinfo") {
			t.Fatalf("%s write-up contains a secret", f)
		}
	}
}

func TestRepNotesAreSavedOnTheCase(t *testing.T) {
	h, id := realisticCase(t)
	var c struct{ Notes string }
	h.do("GET", "/api/cases/"+itoa(id), nil, &c)
	if !strings.HasPrefix(c.Notes, "Customer moved mail") {
		t.Fatalf("notes = %q", c.Notes)
	}
}

func TestASingleStepCanBeCopiedOnItsOwn(t *testing.T) {
	h, id := realisticCase(t)
	steps := h.waitSteps(id, 2)
	var out struct{ Text string }
	if code := h.do("GET", "/api/cases/"+itoa(id)+"/steps/"+itoa(steps[1].ID)+"/text", nil, &out); code != http.StatusOK {
		t.Fatalf("step text: %d", code)
	}
	for _, want := range []string{"DNS Lookup on example.com", "MX: 10 mx1.newhost.net.", "A: 192.0.2.1"} {
		if !strings.Contains(out.Text, want) {
			t.Errorf("step text lacks %q:\n%s", want, out.Text)
		}
	}
	if code := h.do("GET", "/api/cases/"+itoa(id)+"/steps/99999/text", nil, nil); code != http.StatusNotFound {
		t.Errorf("unknown step: %d", code)
	}
}

func TestAnUnknownFormatIsRejected(t *testing.T) {
	h, id := realisticCase(t)
	if code := h.do("GET", "/api/cases/"+itoa(id)+"/writeup?format=pdf", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("format=pdf: %d", code)
	}
}
