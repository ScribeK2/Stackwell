package app_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type registrationResult struct {
	Domain      string   `json:"domain"`
	Source      string   `json:"source"`
	Registered  bool     `json:"registered"`
	Registrar   string   `json:"registrar"`
	Statuses    []string `json:"statuses"`
	Created     string   `json:"created"`
	Updated     string   `json:"updated"`
	Expires     string   `json:"expires"`
	Nameservers []string `json:"nameservers"`
	DNSSEC      *bool    `json:"dnssec"`
	RDAPError   string   `json:"rdap_error"`
}

// rdapDomain is an RDAP domain object, as a registry serves it, expiring at expires.
func rdapDomain(expires time.Time, statuses ...string) string {
	if statuses == nil {
		statuses = []string{"client transfer prohibited"}
	}
	st, _ := json.Marshal(statuses)
	return fmt.Sprintf(`{
  "objectClassName": "domain", "ldhName": "EXAMPLE.COM",
  "status": %s,
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration", "eventDate": %q},
    {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:34Z"},
    {"eventAction": "last update of RDAP database", "eventDate": "2026-01-01T00:00:00Z"}
  ],
  "nameservers": [{"ldhName": "B.IANA-SERVERS.NET"}, {"ldhName": "A.IANA-SERVERS.NET"}],
  "secureDNS": {"delegationSigned": true},
  "entities": [{
    "objectClassName": "entity", "roles": ["registrar"],
    "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]]
  }]
}`, st, expires.UTC().Format(time.RFC3339))
}

// fakeRDAP serves body (or status, when non-zero) for /domain/*, counting requests.
func fakeRDAP(t *testing.T, status int, body string) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/domain/") {
			http.NotFound(w, r)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/", &hits
}

// fakeWHOIS answers every port-43 query with reply, counting connections.
func fakeWHOIS(t *testing.T, reply string) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			bufio.NewReader(c).ReadString('\n')
			c.Write([]byte(reply))
			c.Close()
		}
	}()
	return ln.Addr().String(), &hits
}

func runRegistration(t *testing.T, n app.Net, target string) (step diffedStep, res registrationResult, fs []finding) {
	t.Helper()
	n.Resolver = fakeDNS(t, exampleZone, false)
	h := start(t, app.Config{Net: n, CheckTimeout: 2 * time.Second})
	c := newCase(h, target)
	h.waitSteps(c.ID, 1)
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "registration", "target": target}, nil); code != http.StatusOK {
		t.Fatalf("run registration: %d", code)
	}
	h.waitSteps(c.ID, 2)
	var raw struct {
		Steps []struct {
			diffedStep
			Error  string          `json:"error"`
			Result json.RawMessage `json:"result"`
		} `json:"steps"`
		Findings []finding `json:"findings"`
	}
	h.do("GET", "/api/cases/"+itoa(c.ID), nil, &raw)
	s := raw.Steps[1]
	if s.Status == "ok" {
		if err := json.Unmarshal(s.Result, &res); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range raw.Findings {
		if strings.HasPrefix(f.Code, "registration_") || f.Code == "check_failed" {
			fs = append(fs, f)
		}
	}
	return s.diffedStep, res, fs
}

func TestRegistrationReadsTheRegistryOverRDAP(t *testing.T) {
	expires := time.Now().AddDate(1, 0, 0)
	rdap, _ := fakeRDAP(t, 0, rdapDomain(expires))
	whois, whoisHits := fakeWHOIS(t, "should not be asked")
	_, r, fs := runRegistration(t, app.Net{RDAP: map[string]string{"com": rdap}, WHOIS: map[string]string{"com": whois}}, "example.com")

	if r.Source != "rdap" || !r.Registered || r.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Fatalf("result = %+v", r)
	}
	if !slices.Equal(r.Statuses, []string{"clientTransferProhibited"}) {
		t.Errorf("statuses = %v", r.Statuses)
	}
	if !slices.Equal(r.Nameservers, []string{"a.iana-servers.net", "b.iana-servers.net"}) {
		t.Errorf("nameservers = %v", r.Nameservers)
	}
	if r.Created != "1995-08-14T04:00:00Z" || r.Updated != "2024-08-14T07:01:34Z" || r.Expires != expires.UTC().Format(time.RFC3339) {
		t.Errorf("dates = %s / %s / %s", r.Created, r.Updated, r.Expires)
	}
	if r.DNSSEC == nil || !*r.DNSSEC {
		t.Errorf("dnssec = %v", r.DNSSEC)
	}
	if whoisHits.Load() != 0 {
		t.Error("WHOIS was queried although RDAP answered")
	}
	if len(fs) != 1 || fs[0].Code != "registration_ok" || !strings.Contains(fs[0].Message, "RESERVED-Internet Assigned Numbers Authority") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestRegistrationFindings(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		name     string
		expires  time.Duration
		statuses []string
		code     string
		severity string
	}{
		{"expired", -5 * day, nil, "registration_expired", "critical"},
		{"expiring in 20 days", 20 * day, nil, "registration_expiring_soon", "warning"},
		{"expiring in 45 days", 45 * day, nil, "registration_expiring", "info"},
		{"client hold", 300 * day, []string{"client hold"}, "registration_on_hold", "critical"},
		{"server hold", 300 * day, []string{"server hold", "active"}, "registration_on_hold", "critical"},
		{"redemption", -40 * day, []string{"redemption period"}, "registration_pending_delete", "critical"},
		{"pending delete", -70 * day, []string{"pending delete"}, "registration_pending_delete", "critical"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rdap, _ := fakeRDAP(t, 0, rdapDomain(time.Now().Add(tc.expires), tc.statuses...))
			_, _, fs := runRegistration(t, app.Net{RDAP: map[string]string{"com": rdap}}, "example.com")
			if got := severityOf(fs, tc.code); got != tc.severity {
				t.Fatalf("%s severity = %q, findings %+v", tc.code, got, fs)
			}
			if tc.severity != "info" && slices.Contains(codes(fs), "registration_ok") {
				t.Fatalf("a problem was also called healthy: %v", codes(fs))
			}
		})
	}
}

func TestRDAPNotFoundMeansNotRegisteredWithoutAskingWHOIS(t *testing.T) {
	rdap, _ := fakeRDAP(t, http.StatusNotFound, "")
	whois, whoisHits := fakeWHOIS(t, "should not be asked")
	_, r, fs := runRegistration(t, app.Net{RDAP: map[string]string{"com": rdap}, WHOIS: map[string]string{"com": whois}}, "example.com")
	if r.Registered || r.Source != "rdap" {
		t.Fatalf("result = %+v", r)
	}
	if whoisHits.Load() != 0 {
		t.Error("WHOIS was queried after an authoritative RDAP 404")
	}
	if len(fs) != 1 || fs[0].Code != "registration_not_registered" || fs[0].Severity != "critical" {
		t.Fatalf("findings = %+v", fs)
	}
}

func whoisReply(expires time.Time) string {
	return `   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.iana.org
   Registrar URL: http://res-dom.iana.org
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: ` + expires.UTC().Format("2006-01-02T15:04:05Z") + `
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Registrar IANA ID: 376
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientHold https://icann.org/epp#clientHold
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
>>> Last update of whois database: 2026-01-01T00:00:00Z <<<
`
}

func TestRegistrationFallsBackToWHOISWhenRDAPFails(t *testing.T) {
	expires := time.Now().AddDate(0, 0, 20).Truncate(time.Second)
	rdap, rdapHits := fakeRDAP(t, http.StatusInternalServerError, "")
	whois, _ := fakeWHOIS(t, whoisReply(expires))
	_, r, fs := runRegistration(t, app.Net{RDAP: map[string]string{"com": rdap}, WHOIS: map[string]string{"com": whois}}, "example.com")

	if rdapHits.Load() == 0 || r.RDAPError == "" {
		t.Fatalf("RDAP was not tried first: %+v", r)
	}
	if r.Source != "whois" || !r.Registered || r.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Fatalf("result = %+v", r)
	}
	if r.Expires != expires.UTC().Format(time.RFC3339) || r.Created != "1995-08-14T04:00:00Z" || r.Updated != "2024-08-14T07:01:34Z" {
		t.Errorf("dates = %s / %s / %s", r.Created, r.Updated, r.Expires)
	}
	if !slices.Equal(r.Statuses, []string{"clientDeleteProhibited", "clientHold"}) {
		t.Errorf("statuses = %v", r.Statuses)
	}
	if !slices.Equal(r.Nameservers, []string{"a.iana-servers.net", "b.iana-servers.net"}) {
		t.Errorf("nameservers = %v", r.Nameservers)
	}
	if r.DNSSEC == nil || !*r.DNSSEC {
		t.Errorf("dnssec = %v", r.DNSSEC)
	}
	// Findings apply to WHOIS-sourced results just the same.
	if severityOf(fs, "registration_on_hold") != "critical" || severityOf(fs, "registration_expiring_soon") != "warning" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestRegistrationUsesWHOISForATLDWithoutRDAP(t *testing.T) {
	// .test is in no RDAP bootstrap.
	whois, _ := fakeWHOIS(t, whoisReply(time.Now().AddDate(2, 0, 0)))
	_, r, fs := runRegistration(t, app.Net{WHOIS: map[string]string{"test": whois}}, "nope.test")
	if r.Source != "whois" || !r.Registered || r.Domain != "nope.test" || !strings.Contains(r.RDAPError, "no RDAP") {
		t.Fatalf("result = %+v", r)
	}
	if slices.Contains(codes(fs), "registration_ok") {
		t.Fatalf("clientHold domain called healthy: %v", codes(fs))
	}
}

func TestRegistrationFollowsIANAsWHOISReferral(t *testing.T) {
	iana, _ := fakeWHOIS(t, "domain:       TEST\r\nrefer:        whois.nic.test\r\n")
	registry, _ := fakeWHOIS(t, whoisReply(time.Now().AddDate(2, 0, 0)))
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch addr {
		case "whois.iana.org:43":
			addr = iana
		case "whois.nic.test:43":
			addr = registry
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	_, r, _ := runRegistration(t, app.Net{Dial: dial}, "nope.test")
	if r.Source != "whois" || r.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Fatalf("result = %+v", r)
	}
}

func TestAnEmptyLookingWHOISReplyMeansNotRegistered(t *testing.T) {
	whois, _ := fakeWHOIS(t, "No match for \"NOPE.TEST\".\r\n>>> Last update of whois database: 2026-01-01T00:00:00Z <<<\r\n")
	_, r, fs := runRegistration(t, app.Net{WHOIS: map[string]string{"test": whois}}, "nope.test")
	if r.Source != "whois" || r.Registered {
		t.Fatalf("result = %+v", r)
	}
	if severityOf(fs, "registration_not_registered") != "critical" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestRegistryWHOISFormatsWithoutRegistrarDates(t *testing.T) {
	for _, tc := range []struct {
		name, reply, registrar string
		registered             bool
	}{
		// DENIC gives no registrar or dates for a registered .de name.
		{"denic connect", "Domain: nope.test\nNserver: ns1.example.net\nNserver: ns2.example.net\nStatus: connect\nChanged: 2024-01-11T10:00:00+01:00\n", "", true},
		{"denic free", "Domain: nope.test\nStatus: free\n", "", false},
		// EURid puts the registrar on the next line.
		{"eurid block", "Domain: nope.test\n\nRegistrar:\n        Name: Example Registrar SA\n        Website: https://registrar.example\n", "Example Registrar SA", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			whois, _ := fakeWHOIS(t, tc.reply)
			_, r, fs := runRegistration(t, app.Net{WHOIS: map[string]string{"test": whois}}, "nope.test")
			if r.Registered != tc.registered || r.Registrar != tc.registrar {
				t.Fatalf("result = %+v", r)
			}
			if slices.Contains(codes(fs), "registration_not_registered") == tc.registered {
				t.Fatalf("findings = %v", codes(fs))
			}
		})
	}
}

func TestASparseRDAPRecordIsStillRegistered(t *testing.T) {
	// The empty-looking heuristic is for WHOIS only: thin RDAP data is a real registration.
	rdap, _ := fakeRDAP(t, 0, `{"objectClassName": "domain", "ldhName": "example.com"}`)
	_, r, fs := runRegistration(t, app.Net{RDAP: map[string]string{"com": rdap}}, "example.com")
	if !r.Registered || slices.Contains(codes(fs), "registration_not_registered") {
		t.Fatalf("result = %+v, findings %v", r, codes(fs))
	}
}

func TestRegistrationFailsWhenNeitherRDAPNorWHOISAnswers(t *testing.T) {
	rdap, _ := fakeRDAP(t, http.StatusBadGateway, "")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	s, _, fs := runRegistration(t, app.Net{RDAP: map[string]string{"com": rdap}, WHOIS: map[string]string{"com": closed}}, "example.com")
	if s.Status != "failed" || !slices.Contains(codes(fs), "check_failed") {
		t.Fatalf("step = %+v, findings %v", s, codes(fs))
	}
}

func TestRegistrationLooksUpTheRegisteredNameOfAPrivateSuffixSite(t *testing.T) {
	// foo.github.io is a site of its own, but it is registered as github.io.
	var asked atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.URL.Path)
		w.Write([]byte(rdapDomain(time.Now().AddDate(1, 0, 0))))
	}))
	t.Cleanup(srv.Close)
	_, r, _ := runRegistration(t, app.Net{RDAP: map[string]string{"io": srv.URL + "/"}}, "foo.github.io")
	if r.Domain != "github.io" || asked.Load() != "/domain/github.io" {
		t.Fatalf("result = %+v, asked %v", r, asked.Load())
	}
}

func TestRegistrationDoesNotApplyToHostnames(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "www.example.com")
	h.waitSteps(c.ID, 1)
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "registration", "target": "www.example.com"}, nil); code != http.StatusBadRequest {
		t.Fatalf("registration on a hostname: %d", code)
	}
}
