package app_test

import (
	"bufio"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

// DENIC's real port-43 replies (2026-10), header comments included.
const denicHeader = `% Restricted rights.
%
% Terms and Conditions of Use
%
% The DENIC whois service on port 43 doesn't disclose any information concerning
% the domain holder, general request and abuse contact.
%

`

const (
	denicPlain    = "Domain: example.de\nStatus: connect\n"
	denicDetailed = denicHeader + `Domain: example.de
Nserver: ns1.denic.de 77.67.63.106 2001:668:1f:11:0:0:0:106
Nserver: ns2.denic.de 81.91.164.6 2a02:568:0:2:0:0:0:54
Nserver: ns3.denic.de 195.243.137.27 2003:8:14:0:0:0:0:106
Nserver: ns4.denic.net
Status: connect
Changed: 2024-12-19T13:33:43+01:00
`
	denicFree = "Domain: example.de\nStatus: free\n"
)

// fakeDENIC answers like whois.denic.de: the detailed reply for "-T dn <name>",
// the plain one otherwise, and records every query it receives.
type fakeDENIC struct {
	addr    string
	mu      sync.Mutex
	queries []string
}

func newFakeDENIC(t *testing.T, detailed, plain string) *fakeDENIC {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeDENIC{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			q, _ := bufio.NewReader(c).ReadString('\n')
			q = strings.TrimSpace(q)
			f.mu.Lock()
			f.queries = append(f.queries, q)
			f.mu.Unlock()
			if strings.HasPrefix(q, "-T dn,ace ") {
				c.Write([]byte(detailed))
			} else {
				c.Write([]byte(plain))
			}
			c.Close()
		}
	}()
	return f
}

func registerDE(t *testing.T, whois string) (registrationResult, []finding) {
	t.Helper()
	_, r, fs := runRegistration(t, app.Net{WHOIS: map[string]string{"de": whois}}, "example.de")
	return r, fs
}

func TestARegisteredDEDomainIsRegistered(t *testing.T) {
	f := newFakeDENIC(t, denicDetailed, denicPlain)
	r, fs := registerDE(t, f.addr)
	if !slices.Equal(f.queries, []string{"-T dn,ace example.de"}) {
		t.Fatalf("queries sent = %q, want DENIC's -T dn,ace form", f.queries)
	}
	if !r.Registered || len(r.Nameservers) != 4 || r.Nameservers[0] != "ns1.denic.de" {
		t.Fatalf("result = %+v", r)
	}
	for _, f := range fs {
		if f.Severity == "critical" || f.Severity == "warning" {
			t.Errorf("unexpected %s Finding %s: %s", f.Severity, f.Code, f.Message)
		}
	}
	ok := findingWith(fs, "registration_ok")
	if ok == nil || strings.Contains(ok.Message, " with ") || strings.Contains(ok.Message, " until ") {
		t.Fatalf("the ok Finding claims a registrar or expiry DENIC never gave: %+v", ok)
	}
}

func TestStatusConnectAloneMeansRegistered(t *testing.T) {
	// A server answering only the plain form still says "connect": active.
	f := newFakeDENIC(t, denicPlain, denicPlain)
	if r, fs := registerDE(t, f.addr); !r.Registered || findingWith(fs, "registration_not_registered") != nil {
		t.Fatalf("result = %+v, findings %v", r, codes(fs))
	}
}

func TestAFreeDEDomainIsStillNotRegistered(t *testing.T) {
	f := newFakeDENIC(t, denicFree, denicFree)
	if r, fs := registerDE(t, f.addr); r.Registered || findingWith(fs, "registration_not_registered") == nil {
		t.Fatalf("result = %+v, findings %v", r, codes(fs))
	}
}

func TestAnInternationalisedDEDomainIsQueriedInACEForm(t *testing.T) {
	// DENIC answers "Status: invalid" to "-T dn xn--…"; "-T dn,ace" is the form
	// that works for IDNs (and for every other .de name).
	f := newFakeDENIC(t, strings.Replace(denicDetailed, "Domain: example.de", "Domain: bücher.de\nDomain-Ace: xn--bcher-kva.de", 1), "Domain: xn--bcher-kva.de\nStatus: invalid\n")
	_, r, fs := runRegistration(t, app.Net{WHOIS: map[string]string{"de": f.addr}}, "xn--bcher-kva.de") // bücher.de, as the Case stores it
	if !slices.Equal(f.queries, []string{"-T dn,ace xn--bcher-kva.de"}) {
		t.Fatalf("queries sent = %q", f.queries)
	}
	if !r.Registered || findingWith(fs, "registration_not_registered") != nil {
		t.Fatalf("result = %+v, findings %v", r, codes(fs))
	}
}

func TestAnInvalidAnswerFailsTheStepRatherThanSayingNotRegistered(t *testing.T) {
	f := newFakeDENIC(t, "Domain: example.de\nStatus: invalid\n", "Domain: example.de\nStatus: invalid\n")
	step, _, fs := runRegistration(t, app.Net{WHOIS: map[string]string{"de": f.addr}}, "example.de")
	if step.Status != "failed" || findingWith(fs, "registration_not_registered") != nil {
		t.Fatalf("step = %+v, findings %v", step, codes(fs))
	}
}
