package app_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type suggestion struct {
	Value  string `json:"value"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	From   int64  `json:"from"`
}

type suggestCase struct {
	Targets     []targetView `json:"targets"`
	Steps       []diffedStep `json:"steps"`
	Suggestions []suggestion `json:"suggestions"`
}

func (h *harness) suggestions(caseID int64) suggestCase {
	h.t.Helper()
	var c suggestCase
	h.do("GET", "/api/cases/"+itoa(caseID), nil, &c)
	return c
}

func values(ss []suggestion) []string {
	var out []string
	for _, s := range ss {
		out = append(out, s.Value)
	}
	return out
}

func suggestionFor(ss []suggestion, value string) *suggestion {
	if i := slices.IndexFunc(ss, func(s suggestion) bool { return s.Value == value }); i != -1 {
		return &ss[i]
	}
	return nil
}

func TestDNSLookupSuggestsMailServersAndAddresses(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	step := h.waitSteps(c.ID, 1)[0]
	got := h.suggestions(c.ID)

	for value, reason := range map[string]string{
		"mail.example.com":                   "Mail server",
		"93.184.216.34":                      "Address",
		"2606:2800:220:1:248:1893:25c8:1946": "Address",
	} {
		s := suggestionFor(got.Suggestions, value)
		if s == nil {
			t.Errorf("no suggestion %s; got %v", value, values(got.Suggestions))
			continue
		}
		if !strings.Contains(s.Reason, reason) || s.From != step.ID || s.Kind == "" {
			t.Errorf("suggestion %+v", s)
		}
	}
	if suggestionFor(got.Suggestions, "example.com") != nil {
		t.Error("a Case's own Target was suggested")
	}
	if len(got.Targets) != 1 {
		t.Errorf("suggestions were added on their own: %+v", got.Targets)
	}
}

func TestACNAMEsTargetIsSuggested(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "www.example.com")
	h.waitSteps(c.ID, 1)
	if s := suggestionFor(h.suggestions(c.ID).Suggestions, "example.com"); s == nil || !strings.Contains(s.Reason, "Alias") {
		t.Fatalf("suggestions = %+v", h.suggestions(c.ID).Suggestions)
	}
}

func TestAcceptingASuggestionAddsItAsATarget(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)

	// Accepting is adding the Target.
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/targets", map[string]string{"target": "mail.example.com"}, nil)
	got := h.suggestions(c.ID)
	if suggestionFor(got.Suggestions, "mail.example.com") != nil {
		t.Fatalf("accepted suggestion still suggested: %v", values(got.Suggestions))
	}
	if !slices.ContainsFunc(got.Targets, func(t targetView) bool { return t.Value == "mail.example.com" }) {
		t.Fatalf("targets = %+v", got.Targets)
	}
}

func TestADismissedSuggestionStaysDismissed(t *testing.T) {
	dir := t.TempDir()
	resolver := fakeDNS(t, exampleZone, false)
	h := start(t, app.Config{DataDir: dir, Net: app.Net{Resolver: resolver}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)

	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/suggestions/dismiss", map[string]string{"value": "93.184.216.34"}, nil); code != http.StatusOK {
		t.Fatalf("dismiss: %d", code)
	}
	if suggestionFor(h.suggestions(c.ID).Suggestions, "93.184.216.34") != nil {
		t.Fatal("dismissed suggestion still shown")
	}

	// A re-run finds the same address again; it must not come back.
	h.rerun(c.ID, "dns_lookup", "example.com")
	h.waitSteps(c.ID, 2)
	h.stop()
	h2 := start(t, app.Config{DataDir: dir, Net: app.Net{Resolver: resolver}})
	if suggestionFor(h2.suggestions(c.ID).Suggestions, "93.184.216.34") != nil {
		t.Fatal("dismissed suggestion came back after a re-run and restart")
	}
	if suggestionFor(h2.suggestions(c.ID).Suggestions, "mail.example.com") == nil {
		t.Fatal("dismissing one suggestion hid the others")
	}

	// Dismissal is per Case.
	other := newCase(h2, "example.com")
	h2.waitSteps(other.ID, 1)
	if suggestionFor(h2.suggestions(other.ID).Suggestions, "93.184.216.34") == nil {
		t.Fatal("a dismissal in one Case hid the suggestion in another")
	}
	if code := h2.do("POST", "/api/cases/999/suggestions/dismiss", map[string]string{"value": "x.com"}, nil); code != http.StatusNotFound {
		t.Fatalf("unknown case: %d", code)
	}
}

func TestWebsiteRedirectDestinationsAreSuggested(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://shop.example.net/welcome", http.StatusMovedPermanently)
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	h := start(t, app.Config{Net: app.Net{
		Resolver: fakeDNS(t, exampleZone, false),
		TLS:      &tls.Config{RootCAs: roots},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "example.com:443" {
				var d net.Dialer
				return d.DialContext(ctx, network, srv.Listener.Addr().String())
			}
			return nil, errors.New("connection refused")
		},
	}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "website_inspection", "target": "example.com"}, nil)
	h.waitSteps(c.ID, 2)
	s := suggestionFor(h.suggestions(c.ID).Suggestions, "shop.example.net")
	if s == nil || !strings.Contains(s.Reason, "Redirect") {
		t.Fatalf("suggestions = %+v", h.suggestions(c.ID).Suggestions)
	}
}

func TestDismissalsAreNormalisedLikeTargets(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/suggestions/dismiss", map[string]string{"value": " Mail.Example.COM. "}, nil)
	if suggestionFor(h.suggestions(c.ID).Suggestions, "mail.example.com") != nil {
		t.Fatal("a differently written dismissal didn't take effect")
	}
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/suggestions/dismiss", map[string]string{"value": "not a host"}, nil); code != http.StatusBadRequest {
		t.Fatalf("invalid value: %d", code)
	}
}
