package app_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

// Some options choose a different thing to examine (SSL Inspection's port is
// another service); others only choose how much to look at (a scope). A run
// on another subject must not hide the Findings of the first.
func TestARunOnAnotherSubjectKeepsTheFirstsFindings(t *testing.T) {
	p := newPKI(t)
	expired := serveTLS(t, tlsCert(mint(t, "example.com", []string{"example.com"}, days(-3), p.inter), p.inter), nil)
	valid := serveTLS(t, tlsCert(mint(t, "example.com", []string{"example.com"}, days(200), p.inter), p.inter), nil)
	servers := map[string]string{"example.com:443": expired, "example.com:993": valid}
	h := start(t, app.Config{Net: app.Net{
		Resolver: fakeDNS(t, exampleZone, false),
		TLS:      &tls.Config{RootCAs: p.roots},
		Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			addr, ok := servers[a]
			if !ok {
				return nil, errors.New("unexpected dial to " + a)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	for i, port := range []string{"443", "993"} {
		h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{
			"check": "ssl_inspection", "target": "example.com", "options": map[string]string{"port": port}}, nil)
		h.waitSteps(c.ID, 2+i)
	}
	got := codes(h.findings(c.ID).Findings)
	if !slices.Contains(got, "ssl_inspection_expired") || !slices.Contains(got, "ssl_inspection_valid") {
		t.Fatalf("want the 443 expiry and the 993 valid Findings side by side, got %v", got)
	}
}
