package app_test

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

// Connected Findings: conclusions drawn from several Steps at once.

// providerZone: example.com's mail is on Microsoft 365, but its SPF record
// only includes Zendesk. Tests swap lines to vary the case.
const providerZone = `
example.com. 300 IN A 93.184.216.34
example.com. 300 IN MX 0 example-com.mail.protection.outlook.com.
example.com. 300 IN NS a.iana-servers.net.
example.com. 300 IN TXT "v=spf1 include:mail.zendesk.com -all"
mail.zendesk.com. 300 IN TXT "v=spf1 ip4:192.161.144.0/20 -all"
spf.protection.outlook.com. 300 IN TXT "v=spf1 ip4:40.92.0.0/15 -all"
_spf.example.com. 300 IN TXT "v=spf1 include:spf.protection.outlook.com -all"
`

// spfCase runs DNS Lookup (automatically) and Email Authentication on
// example.com, returning the harness, the Case's id and its Steps and Findings.
func spfCase(t *testing.T, resolver string) (*harness, int64, findingsCase) {
	t.Helper()
	h := start(t, app.Config{Net: app.Net{Resolver: resolver}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	h.rerun(c.ID, "email_auth", "example.com")
	h.waitSteps(c.ID, 2)
	var fc findingsCase
	h.do("GET", "/api/cases/"+itoa(c.ID), nil, &fc)
	return h, c.ID, fc
}

func TestSPFMissingTheMailProviderIsFlagged(t *testing.T) {
	for _, tc := range []struct{ name, mx, include, provider string }{
		{"Microsoft 365", "0 example-com.mail.protection.outlook.com.", "spf.protection.outlook.com", "Microsoft 365"},
		{"Google Workspace", "1 aspmx.l.google.com.", "_spf.google.com", "Google Workspace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zone := strings.Replace(providerZone, "0 example-com.mail.protection.outlook.com.", tc.mx, 1)
			h, id, fc := spfCase(t, fakeDNS(t, zone, false))
			f := findingWith(fc.Findings, "spf_missing_provider")
			if f == nil {
				t.Fatalf("no spf_missing_provider Finding: %v", codes(fc.Findings))
			}
			if f.Severity != "warning" || f.Target != "example.com" ||
				!strings.Contains(f.Title+f.Message, tc.provider) || !strings.Contains(f.Recommendation, "include:"+tc.include) {
				t.Fatalf("finding = %+v", f)
			}
			var stepIDs []int64
			for _, s := range fc.Steps {
				stepIDs = append(stepIDs, s.ID)
			}
			if got := slices.Sorted(slices.Values(f.Citations)); !slices.Equal(got, stepIDs) {
				t.Fatalf("citations %v, want both Steps %v", f.Citations, stepIDs)
			}
			// It reaches the Write-up and History search like any Finding.
			if md := h.writeup(id, "markdown"); !strings.Contains(md, f.Title) {
				t.Errorf("Write-up lacks %q:\n%s", f.Title, md)
			}
			if got := h.list("?q=" + url.QueryEscape(f.Title)); len(got) != 1 || !strings.HasPrefix(got[0].MatchedBy, "Finding") {
				t.Errorf("search for %q = %+v", f.Title, got)
			}
		})
	}
}

func TestFixingSPFClearsTheProviderFinding(t *testing.T) {
	resolver, setZone := mutableDNS(t, providerZone, false)
	h, id, fc := spfCase(t, resolver)
	if findingWith(fc.Findings, "spf_missing_provider") == nil {
		t.Fatalf("no Finding before the fix: %v", codes(fc.Findings))
	}
	setZone(strings.Replace(providerZone, `"v=spf1 include:mail.zendesk.com -all"`, `"v=spf1 include:mail.zendesk.com include:spf.protection.outlook.com -all"`, 1))
	h.rerun(id, "email_auth", "example.com")
	h.waitSteps(id, 3)
	h.do("GET", "/api/cases/"+itoa(id), nil, &fc)
	if f := findingWith(fc.Findings, "spf_missing_provider"); f != nil {
		t.Fatalf("Finding survived the fix: %+v", f)
	}
}

func TestProviderFindingStaysSilentWhenItDoesNotApply(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"nested include", `"v=spf1 include:mail.zendesk.com -all"`, `"v=spf1 include:_spf.example.com -all"`},
		{"redirect", `"v=spf1 include:mail.zendesk.com -all"`, `"v=spf1 redirect=_spf.example.com"`},
		{"direct redirect", `"v=spf1 include:mail.zendesk.com -all"`, `"v=spf1 redirect=spf.protection.outlook.com"`},
		{"no SPF record", `example.com. 300 IN TXT "v=spf1 include:mail.zendesk.com -all"`, ``},
		{"two SPF records", `example.com. 300 IN TXT "v=spf1 include:mail.zendesk.com -all"`,
			"example.com. 300 IN TXT \"v=spf1 -all\"\nexample.com. 300 IN TXT \"v=spf1 ~all\""},
		{"unknown provider", "0 example-com.mail.protection.outlook.com.", "10 mx.example.net."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, fc := spfCase(t, fakeDNS(t, strings.Replace(providerZone, tc.from, tc.to, 1), false))
			if f := findingWith(fc.Findings, "spf_missing_provider"); f != nil {
				t.Fatalf("unexpected Finding: %+v", f)
			}
		})
	}
}

func TestProviderFindingNeedsBothSteps(t *testing.T) {
	// Only the automatic DNS Lookup: no Email Authentication Step yet.
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, providerZone, false)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	var fc findingsCase
	h.do("GET", "/api/cases/"+itoa(c.ID), nil, &fc)
	if f := findingWith(fc.Findings, "spf_missing_provider"); f != nil {
		t.Fatalf("Finding without Email Authentication: %+v", f)
	}

	// Email Authentication whose latest run failed: the earlier, successful
	// run no longer speaks for the domain.
	h2, id, fc2 := spfCase(t, fakeDNS(t, providerZone, false))
	if findingWith(fc2.Findings, "spf_missing_provider") == nil {
		t.Fatalf("no Finding to begin with: %v", codes(fc2.Findings))
	}
	h2.do("POST", "/api/cases/"+itoa(id)+"/steps", map[string]any{"check": "email_auth", "target": "example.com",
		"options": map[string]string{"selectors": "not/valid"}}, nil)
	if steps := h2.waitSteps(id, 3); steps[2].Status != "failed" {
		t.Fatalf("latest Email Authentication = %+v, want failed", steps[2])
	}
	h2.do("GET", "/api/cases/"+itoa(id), nil, &fc2)
	if f := findingWith(fc2.Findings, "spf_missing_provider"); f != nil {
		t.Fatalf("Finding from a failed Email Authentication run: %+v", f)
	}
}
