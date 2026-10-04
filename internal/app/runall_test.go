package app_test

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

func TestACheckRunsOnEveryTargetItAppliesTo(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	for _, tg := range []string{"www.example.com", "203.0.113.7"} {
		h.do("POST", "/api/cases/"+itoa(c.ID)+"/targets", map[string]string{"target": tg}, nil)
	}
	before := len(h.waitSteps(c.ID, 2)) // auto DNS Lookups for the two names

	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps/all", map[string]string{"check": "dns_lookup"}, nil); code != http.StatusOK {
		t.Fatalf("run all: %d", code)
	}
	var got runCase
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got = h.runCase(c.ID)
		if len(got.Steps) == before+2 && !slices.ContainsFunc(got.Steps, func(s runStepView) bool { return s.Status == "running" }) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if want := []string{"dns_lookup@example.com", "dns_lookup@www.example.com"}; !slices.Equal(checksOf(got.Steps[before:]), want) {
		t.Fatalf("new steps = %v, want %v (none for the IP)", checksOf(got.Steps[before:]), want)
	}

	// Registration applies only to the domain here: still one Step, still fine.
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps/all", map[string]string{"check": "registration"}, nil); code != http.StatusOK {
		t.Errorf("a Check that applies to one Target: %d", code)
	}
	other := newCase(h, "203.0.113.9")
	if code := h.do("POST", "/api/cases/"+itoa(other.ID)+"/steps/all", map[string]string{"check": "dns_lookup"}, nil); code != http.StatusBadRequest {
		t.Errorf("a Check that applies to no Target: %d", code)
	}
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps/all", map[string]string{"check": "no_such_check"}, nil); code != http.StatusBadRequest {
		t.Errorf("unknown check: %d", code)
	}
}

func TestARunningStepCanBeCancelled(t *testing.T) {
	resolver, setZone := mutableDNS(t, exampleZone, false)
	h := start(t, app.Config{Net: app.Net{Resolver: resolver}, CheckTimeout: 10 * time.Second})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1) // a good run first
	setZone(noAnswer)
	h.rerun(c.ID, "dns_lookup", "example.com")
	running := h.runCase(c.ID).Steps[1]
	if running.Status != "running" {
		t.Fatalf("step = %+v", running)
	}

	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps/"+itoa(running.ID)+"/cancel", nil, nil); code != http.StatusOK {
		t.Fatalf("cancel: %d", code)
	}
	steps := h.waitSteps(c.ID, 2)
	if steps[1].Status != "cancelled" {
		t.Fatalf("after cancel: %+v", steps[1])
	}
	fs := codes(h.findings(c.ID).Findings)
	if slices.Contains(fs, "check_failed") || !slices.Contains(fs, "dns_resolves") {
		t.Fatalf("a cancelled Step changed the Findings: %v", fs)
	}

	// Cancelling a finished Step is harmless; unknown or foreign Steps are 404.
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps/"+itoa(running.ID)+"/cancel", nil, nil); code != http.StatusOK {
		t.Errorf("second cancel: %d", code)
	}
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps/99999/cancel", nil, nil); code != http.StatusNotFound {
		t.Errorf("unknown step: %d", code)
	}
	other := newCase(h, "example.com")
	if code := h.do("POST", "/api/cases/"+itoa(other.ID)+"/steps/"+itoa(running.ID)+"/cancel", nil, nil); code != http.StatusNotFound {
		t.Errorf("another Case's step: %d", code)
	}
}

func TestATimedOutStepIsFailedNotCancelled(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, "", true)}, CheckTimeout: 200 * time.Millisecond})
	c := newCase(h, "example.com")
	if s := h.waitSteps(c.ID, 1)[0]; s.Status != "failed" {
		t.Fatalf("timed-out step = %+v", s)
	}
}
