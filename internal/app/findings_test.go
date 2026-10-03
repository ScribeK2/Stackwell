package app_test

import (
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type finding struct {
	Code           string  `json:"code"`
	Severity       string  `json:"severity"`
	Title          string  `json:"title"`
	Message        string  `json:"message"`
	Recommendation string  `json:"recommendation"`
	Target         string  `json:"target"`
	Citations      []int64 `json:"citations"`
}

type findingsCase struct {
	Steps    []diffedStep `json:"steps"`
	Findings []finding    `json:"findings"`
}

func (h *harness) findings(caseID int64) findingsCase {
	h.t.Helper()
	var c findingsCase
	h.do("GET", "/api/cases/"+itoa(caseID), nil, &c)
	return c
}

func codes(fs []finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Code)
	}
	return out
}

// findingsFor runs DNS Lookup for target against zone and returns the Case's Findings.
func findingsFor(t *testing.T, zone, target string) findingsCase {
	t.Helper()
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, zone, false)}})
	c := newCase(h, target)
	h.waitSteps(c.ID, 1)
	return h.findings(c.ID)
}

func TestHealthyDomainHasOnlyOKFindings(t *testing.T) {
	c := findingsFor(t, exampleZone, "example.com")
	if len(c.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range c.Findings {
		if f.Severity != "ok" {
			t.Errorf("unexpected %s finding %q: %s", f.Severity, f.Code, f.Message)
		}
		if f.Title == "" || f.Message == "" || f.Target != "example.com" || !slices.Equal(f.Citations, []int64{c.Steps[0].ID}) {
			t.Errorf("incomplete finding %+v", f)
		}
	}
}

func TestDNSFindings(t *testing.T) {
	for _, tc := range []struct {
		name, zone, target, code, severity string
	}{
		{"nxdomain", exampleZone, "nope.test", "dns_nxdomain", "critical"},
		{"no address", `
example.com. 300 IN NS ns.example.net.
example.com. 300 IN MX 10 mail.example.net.`, "example.com", "dns_no_address", "warning"},
		{"no mx", `
example.com. 300 IN NS ns.example.net.
example.com. 300 IN A 192.0.2.1`, "example.com", "dns_no_mx", "warning"},
		{"null mx", `
example.com. 300 IN NS ns.example.net.
example.com. 300 IN A 192.0.2.1
example.com. 300 IN MX 0 .`, "example.com", "dns_null_mx", "info"},
		{"no ns", `
example.com. 300 IN A 192.0.2.1
example.com. 300 IN MX 10 mail.example.net.`, "example.com", "dns_no_ns", "critical"},
		{"cname at apex", `
example.com. 300 IN CNAME other.example.net.`, "example.com", "dns_cname_at_apex", "critical"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := findingsFor(t, tc.zone, tc.target)
			i := slices.IndexFunc(c.Findings, func(f finding) bool { return f.Code == tc.code })
			if i == -1 {
				t.Fatalf("no %s finding; got %v", tc.code, codes(c.Findings))
			}
			if f := c.Findings[i]; f.Severity != tc.severity || f.Recommendation == "" && f.Severity != "info" {
				t.Fatalf("finding = %+v", f)
			}
		})
	}
}

func TestHostnamesAreNotHeldToApexRules(t *testing.T) {
	// www has no MX or NS of its own, and a CNAME is normal there.
	c := findingsFor(t, exampleZone, "www.example.com")
	for _, f := range c.Findings {
		if slices.Contains([]string{"dns_no_mx", "dns_no_ns", "dns_cname_at_apex"}, f.Code) {
			t.Errorf("apex rule applied to a hostname: %+v", f)
		}
	}
}

func TestFindingsAreSortedBySeverity(t *testing.T) {
	c := findingsFor(t, `
example.com. 300 IN TXT "v=spf1 -all"`, "example.com") // no address, no MX, no NS
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2, "ok": 3}
	if !slices.IsSortedFunc(c.Findings, func(a, b finding) int { return rank[a.Severity] - rank[b.Severity] }) {
		t.Fatalf("not sorted: %+v", c.Findings)
	}
	if c.Findings[0].Severity != "critical" {
		t.Fatalf("first = %+v", c.Findings[0])
	}
}

func TestAFixedProblemDisappearsAfterRerun(t *testing.T) {
	resolver, setZone := mutableDNS(t, `
example.com. 300 IN NS ns.example.net.
example.com. 300 IN A 192.0.2.1`, false)
	h := start(t, app.Config{Net: app.Net{Resolver: resolver}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	if !slices.Contains(codes(h.findings(c.ID).Findings), "dns_no_mx") {
		t.Fatal("expected dns_no_mx before the fix")
	}

	setZone(exampleZone) // the customer adds MX records
	h.rerun(c.ID, "dns_lookup", "example.com")
	steps := h.waitSteps(c.ID, 2)
	after := h.findings(c.ID)
	if slices.Contains(codes(after.Findings), "dns_no_mx") {
		t.Fatalf("dns_no_mx survived the fix: %v", codes(after.Findings))
	}
	for _, f := range after.Findings {
		if !slices.Equal(f.Citations, []int64{steps[1].ID}) {
			t.Errorf("finding %s cites %v, want only the latest Step %d", f.Code, f.Citations, steps[1].ID)
		}
	}
}

func TestAFailedLatestRunIsReportedNotIgnored(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, "", true)}, CheckTimeout: 200 * time.Millisecond})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	fs := h.findings(c.ID).Findings
	if len(fs) != 1 || fs[0].Code != "check_failed" || fs[0].Severity != "warning" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestFailedQueriesAreNotReportedAsMissingRecords(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, `
example.com. 300 IN TXT "v=spf1 -all"`, false, dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	got := codes(h.findings(c.ID).Findings)
	for _, wrong := range []string{"dns_no_address", "dns_no_mx", "dns_no_ns"} {
		if slices.Contains(got, wrong) {
			t.Errorf("%s reported although that query failed; findings %v", wrong, got)
		}
	}
	if !slices.Contains(got, "dns_query_errors") {
		t.Errorf("missing dns_query_errors; findings %v", got)
	}
}
