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
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

func TestEmailDeliveryRunsEndToEnd(t *testing.T) {
	zone := exampleZone + "mail.example.com. 300 IN A 192.0.2.25\n"
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, zone, false), Dial: refuseDial}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)

	run := h.startRun(c.ID, "email_delivery", "example.com")
	got := h.waitRun(c.ID, run)
	r := got.Runs[len(got.Runs)-1]
	if r.Status != "done" || r.Label != "Email Delivery" || r.Total != 4 || len(r.Boundary) == 0 || len(r.Skipped) != 0 {
		t.Fatalf("run = %+v", r)
	}
	want := []string{
		"blacklist@example.com",
		"dns_lookup@example.com",
		"email_auth@example.com",
		"hosting_reachability@mail.example.com",
	}
	if got := checksOf(runSteps(got, run)); !slices.Equal(got, want) {
		t.Fatalf("run steps = %v, want %v", got, want)
	}
	for _, s := range runSteps(got, run) {
		if s.Status != "ok" {
			t.Errorf("%s on %s = %s", s.Check, s.Target, s.Status)
		}
	}
	if !slices.ContainsFunc(got.Targets, func(t targetView) bool { return t.Value == "mail.example.com" }) {
		t.Fatalf("primary MX host not added as a Target: %+v", got.Targets)
	}
}

func TestHostingAndWebsiteRunsEndToEnd(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>hello</html>")) })
	https := httptest.NewTLSServer(ok) // its certificate covers example.com
	t.Cleanup(https.Close)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
	}))
	t.Cleanup(plain.Close)
	roots := x509.NewCertPool()
	roots.AddCert(https.Certificate())
	sites := map[string]string{"example.com:443": https.Listener.Addr().String(), "example.com:80": plain.Listener.Addr().String()}

	h := start(t, app.Config{Net: app.Net{
		Resolver: fakeDNS(t, exampleZone, false),
		TLS:      &tls.Config{RootCAs: roots},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if a, ok := sites[addr]; ok {
				var d net.Dialer
				return d.DialContext(ctx, network, a)
			}
			return nil, errors.New("connection refused")
		},
	}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)

	run := h.startRun(c.ID, "hosting_website", "example.com")
	got := h.waitRun(c.ID, run)
	r := got.Runs[len(got.Runs)-1]
	if r.Status != "done" || r.Label != "Hosting & Website" || r.Total != 4 || len(r.Boundary) == 0 {
		t.Fatalf("run = %+v", r)
	}
	want := []string{"dns_lookup@example.com", "hosting_reachability@example.com", "ssl_inspection@example.com", "website_inspection@example.com"}
	if got := checksOf(runSteps(got, run)); !slices.Equal(got, want) {
		t.Fatalf("run steps = %v, want %v", got, want)
	}
	for _, s := range runSteps(got, run) {
		if s.Status != "ok" {
			t.Errorf("%s = %s", s.Check, s.Status)
		}
	}
	for _, code := range []string{"website_inspection_healthy", "ssl_inspection_valid"} {
		if !slices.Contains(codes(got.Findings), code) {
			t.Errorf("missing %s in %v", code, codes(got.Findings))
		}
	}
}

func TestHostingAndWebsiteAlsoRunsOnHostnames(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false), Dial: refuseDial}})
	c := newCase(h, "www.example.com")
	h.waitSteps(c.ID, 1)
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/runs", map[string]string{"playbook": "hosting_website", "target": "www.example.com"}, nil); code != http.StatusOK {
		t.Fatalf("hosting_website on a hostname: %d", code)
	}
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/runs", map[string]string{"playbook": "email_delivery", "target": "www.example.com"}, nil); code != http.StatusBadRequest {
		t.Fatalf("email_delivery on a hostname: %d, want 400", code)
	}
}
