package app_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type blacklistResult struct {
	Subjects map[string]struct {
		Kind   string `json:"kind"`
		Source string `json:"source"`
		Lists  map[string]struct {
			State  string   `json:"state"`
			Codes  []string `json:"codes"`
			Reason string   `json:"reason"`
			Delist string   `json:"delist"`
		} `json:"lists"`
	} `json:"subjects"`
	IPv6 bool `json:"ipv6"`
}

// runBlacklist runs the Blacklist Check on target with zone as the only DNS
// resolver, so every bundled list resolves through the fake.
func runBlacklist(t *testing.T, zone string, silent bool, target string) (blacklistResult, []finding) {
	t.Helper()
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, zone, silent)}, CheckTimeout: 500 * time.Millisecond})
	c := newCase(h, target)
	n := len(c.Steps) // a domain gets an automatic DNS Lookup
	if n > 0 {
		h.waitSteps(c.ID, n)
	}
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "blacklist", "target": target}, nil); code != http.StatusOK {
		t.Fatalf("run blacklist: %d", code)
	}
	h.waitSteps(c.ID, n+1)
	var raw struct {
		Steps []struct {
			Check  string          `json:"check"`
			Status string          `json:"status"`
			Error  string          `json:"error"`
			Result json.RawMessage `json:"result"`
		} `json:"steps"`
		Findings []finding `json:"findings"`
	}
	h.do("GET", "/api/cases/"+itoa(c.ID), nil, &raw)
	var res blacklistResult
	if s := raw.Steps[n]; s.Check != "blacklist" || s.Status != "ok" || json.Unmarshal(s.Result, &res) != nil {
		t.Fatalf("step = %+v", s)
	}
	var fs []finding
	for _, f := range raw.Findings {
		if strings.HasPrefix(f.Code, "blacklist_") {
			fs = append(fs, f)
		}
	}
	return res, fs
}

const zenListing = `
7.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.2
7.113.0.203.zen.spamhaus.org. 300 IN TXT "Listed by SBL, see https://check.spamhaus.org/sbl/query/SBL1"
`

func TestBlacklistReportsAListingWithItsReasonAndDelistLink(t *testing.T) {
	res, fs := runBlacklist(t, zenListing, false, "203.0.113.7")
	lists := res.Subjects["203.0.113.7"].Lists
	if zen := lists["Spamhaus ZEN"]; zen.State != "listed" || zen.Codes[0] != "127.0.0.2" || !strings.Contains(zen.Reason, "SBL1") {
		t.Fatalf("zen = %+v", zen)
	}
	if lists["SpamCop"].State != "clean" || len(lists) != 8 {
		t.Fatalf("lists = %+v", lists)
	}
	if _, ok := lists["Spamhaus DBL"]; ok {
		t.Fatal("an IP was checked against a domain list")
	}
	f := findingWith(fs, "blacklist_listed")
	if f == nil || f.Severity != "critical" || !strings.Contains(f.Message, "Spamhaus ZEN") || !strings.Contains(f.Message, "SBL1") ||
		!strings.Contains(f.Recommendation, "https://check.spamhaus.org/") {
		t.Fatalf("findings = %+v", fs)
	}
	if findingWith(fs, "blacklist_clean") != nil {
		t.Fatalf("listed address also called clean: %v", codes(fs))
	}
}

func TestBlacklistSeverityFollowsTheList(t *testing.T) {
	_, fs := runBlacklist(t, `
7.113.0.203.psbl.surriel.com. 300 IN A 127.0.0.2
7.113.0.203.dnsbl-1.uceprotect.net. 300 IN A 127.0.0.2`, false, "203.0.113.7")
	sev := map[string]string{}
	for _, f := range fs {
		if f.Code == "blacklist_listed" {
			sev[f.Title] = f.Severity
		}
	}
	if sev["203.0.113.7 listed on PSBL"] != "warning" || sev["203.0.113.7 listed on UCEPROTECT Level 1"] != "info" {
		t.Fatalf("severities = %v", sev)
	}
}

func TestBlacklistTreatsARefusedQueryAsNeitherListedNorClean(t *testing.T) {
	res, fs := runBlacklist(t, `7.113.0.203.zen.spamhaus.org. 300 IN A 127.255.255.254`, false, "203.0.113.7")
	if s := res.Subjects["203.0.113.7"].Lists["Spamhaus ZEN"].State; s != "refused" {
		t.Fatalf("zen state = %s", s)
	}
	if findingWith(fs, "blacklist_listed") != nil {
		t.Fatalf("refusal reported as a listing: %+v", fs)
	}
	f := findingWith(fs, "blacklist_refused")
	if f == nil || f.Severity != "info" || !strings.Contains(f.Message, "public resolvers") {
		t.Fatalf("findings = %+v", fs)
	}
	ok := findingWith(fs, "blacklist_clean")
	if ok == nil || !strings.Contains(ok.Message, "7 lists") {
		t.Fatalf("clean finding should count only the lists that answered: %+v", ok)
	}
}

func TestBlacklistChecksADomainsMailHostsAndTheDomain(t *testing.T) {
	res, fs := runBlacklist(t, exampleZone+`
mail.example.com. 300 IN A 203.0.113.7
`+zenListing+`
example.com.dbl.spamhaus.org. 300 IN A 127.0.1.2`, false, "example.com")
	ip, ok := res.Subjects["203.0.113.7"]
	if !ok || ip.Source != "MX mail.example.com" || ip.Lists["Spamhaus ZEN"].State != "listed" {
		t.Fatalf("subjects = %+v", res.Subjects)
	}
	if _, apex := res.Subjects["93.184.216.34"]; apex {
		t.Fatal("the domain's own A record was checked although it has MX hosts")
	}
	dom := res.Subjects["example.com"]
	if dom.Kind != "domain" || dom.Lists["Spamhaus DBL"].State != "listed" || dom.Lists["SURBL"].State != "clean" || len(dom.Lists) != 2 {
		t.Fatalf("domain = %+v", dom)
	}
	n := 0
	for _, f := range fs {
		if f.Code == "blacklist_listed" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want one finding per listing, got %+v", fs)
	}
}

func TestBlacklistFallsBackToTheDomainsAddressWithoutMX(t *testing.T) {
	res, _ := runBlacklist(t, `example.com. 300 IN A 198.51.100.1`, false, "example.com")
	if s, ok := res.Subjects["198.51.100.1"]; !ok || s.Source != "A record of example.com" {
		t.Fatalf("subjects = %+v", res.Subjects)
	}
}

func TestBlacklistCapsTheAddressesItChecks(t *testing.T) {
	zone := "example.com. 300 IN MX 10 mail.example.com.\n"
	for _, last := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		zone += "mail.example.com. 300 IN A 198.51.100." + last + "\n"
	}
	res, _ := runBlacklist(t, zone, false, "example.com")
	if len(res.Subjects) != 6 { // 5 addresses plus the domain
		t.Fatalf("subjects = %d", len(res.Subjects))
	}
}

func TestBlacklistWarnsWhenADomainHasNoAddresses(t *testing.T) {
	res, fs := runBlacklist(t, `example.com. 300 IN TXT "v=spf1 -all"`, false, "example.com")
	if len(res.Subjects["example.com"].Lists) != 2 {
		t.Fatalf("domain lists still have to be checked: %+v", res.Subjects)
	}
	if f := findingWith(fs, "blacklist_no_addresses"); f == nil || f.Severity != "warning" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestBlacklistTreatsSURBLs127001AsARefusal(t *testing.T) {
	res, fs := runBlacklist(t, `example.com.multi.surbl.org. 300 IN A 127.0.0.1`, false, "example.com")
	if s := res.Subjects["example.com"].Lists["SURBL"].State; s != "refused" || findingWith(fs, "blacklist_listed") != nil {
		t.Fatalf("SURBL state = %s, findings %v", s, codes(fs))
	}
}

func TestBlacklistDoesNotCheckTheWebsiteOfADomainThatTakesNoMail(t *testing.T) {
	res, fs := runBlacklist(t, `
example.com. 300 IN MX 0 .
example.com. 300 IN A 198.51.100.1`, false, "example.com")
	if _, ok := res.Subjects["198.51.100.1"]; ok {
		t.Fatalf("null MX fell back to the A record: %+v", res.Subjects)
	}
	if f := findingWith(fs, "blacklist_no_addresses"); f == nil || !strings.Contains(f.Message, "null MX") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestBlacklistSkipsIPv6WithoutCallingItClean(t *testing.T) {
	res, fs := runBlacklist(t, "", false, "2001:db8::1")
	if !res.IPv6 || len(res.Subjects) != 0 {
		t.Fatalf("result = %+v", res)
	}
	if !slices.Equal(codes(fs), []string{"blacklist_ipv6"}) {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestBlacklistTimeoutsAreUnknownNotClean(t *testing.T) {
	res, fs := runBlacklist(t, "", true, "203.0.113.7")
	if s := res.Subjects["203.0.113.7"].Lists["Spamhaus ZEN"].State; s != "unknown" {
		t.Fatalf("zen state = %s", s)
	}
	if findingWith(fs, "blacklist_clean") != nil {
		t.Fatalf("timeouts called clean: %v", codes(fs))
	}
	if f := findingWith(fs, "blacklist_unknown"); f == nil || f.Severity != "warning" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestBlacklistIsOfferedForIPsAndDomains(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	for _, target := range []string{"203.0.113.7", "example.com"} {
		if c := newCase(h, target); !slices.Contains(c.Targets[0].Checks, "blacklist") {
			t.Errorf("%s: checks %v", target, c.Targets[0].Checks)
		}
	}
}

func TestBlacklistPBLIsAPolicyWarningNotCritical(t *testing.T) {
	_, fs := runBlacklist(t, `
7.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.10`, false, "203.0.113.7")
	f := findingWith(fs, "blacklist_listed")
	if f == nil || f.Severity != "warning" || !strings.Contains(f.Message, "not an abuse listing") {
		t.Fatalf("findings = %+v", fs)
	}
}
