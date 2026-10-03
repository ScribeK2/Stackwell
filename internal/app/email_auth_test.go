package app_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type emailAuthResult struct {
	Scope string `json:"scope"`
	SPF   *struct {
		Records     []string `json:"records"`
		All         string   `json:"all"`
		Lookups     int      `json:"lookups"`
		VoidLookups int      `json:"void_lookups"`
		Errors      []string `json:"errors"`
		Tree        *struct {
			Terms []struct {
				Name   string `json:"name"`
				Target *struct {
					Domain string `json:"domain"`
					Record string `json:"record"`
				} `json:"target"`
			} `json:"terms"`
		} `json:"tree"`
	} `json:"spf"`
	DKIM *struct {
		Checked []string `json:"checked"`
		Keys    []struct {
			Selector string `json:"selector"`
			CNAME    string `json:"cname"`
			KeyType  string `json:"key_type"`
			Bits     int    `json:"bits"`
			Revoked  bool   `json:"revoked"`
		} `json:"keys"`
	} `json:"dkim"`
	DMARC *struct {
		Policy string   `json:"policy"`
		SubPol string   `json:"subdomain_policy"`
		Pct    int      `json:"pct"`
		RUA    []string `json:"rua"`
		ADKIM  string   `json:"adkim"`
		ASPF   string   `json:"aspf"`
	} `json:"dmarc"`
}

// runEmailAuth runs Email Authentication on example.com against zone.
func runEmailAuth(t *testing.T, zone string, opts map[string]string) (emailAuthResult, []finding) {
	t.Helper()
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, zone, false)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{"check": "email_auth", "target": "example.com", "options": opts}, nil)
	h.waitSteps(c.ID, 2)
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
	var res emailAuthResult
	if s := raw.Steps[1]; s.Check != "email_auth" || s.Status != "ok" || json.Unmarshal(s.Result, &res) != nil {
		t.Fatalf("step = %+v", s)
	}
	var fs []finding
	for _, f := range raw.Findings {
		if !strings.HasPrefix(f.Code, "dns_") { // drop the auto DNS Lookup's
			fs = append(fs, f)
		}
	}
	return res, fs
}

func severityOf(fs []finding, code string) string {
	if i := slices.IndexFunc(fs, func(f finding) bool { return f.Code == code }); i != -1 {
		return fs[i].Severity
	}
	return ""
}

func wantFindings(t *testing.T, fs []finding, want map[string]string) {
	t.Helper()
	for code, sev := range want {
		if got := severityOf(fs, code); got != sev {
			t.Errorf("%s: severity %q, want %q (findings %v)", code, got, sev, codes(fs))
		}
	}
}

// dkimTXT is a zone TXT rdata for an RSA key of the given size, split into
// 255-byte strings like a real zone.
func dkimTXT(t *testing.T, bits int) string {
	t.Helper()
	n := new(big.Int).SetBit(big.NewInt(1), bits-1, 1) // only the modulus size matters
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	rec := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	var parts []string
	for len(rec) > 255 {
		parts, rec = append(parts, `"`+rec[:255]+`"`), rec[255:]
	}
	return strings.Join(append(parts, `"`+rec+`"`), " ")
}

const healthyMail = `
example.com. 300 IN TXT "v=spf1 include:_spf.provider.test ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"
example.com. 300 IN TXT "google-site-verification=abc"
_spf.provider.test. 300 IN TXT "v=spf1 ip4:198.51.100.0/24 ~all"
_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject; sp=quarantine; adkim=s; rua=mailto:dmarc@example.com"
`

func TestEmailAuthHealthyDomain(t *testing.T) {
	zone := healthyMail + `
selector1._domainkey.example.com. 300 IN CNAME selector1-example._domainkey.provider.test.
selector1-example._domainkey.provider.test. 300 IN TXT ` + dkimTXT(t, 2048)
	res, fs := runEmailAuth(t, zone, nil)

	spf := res.SPF
	if spf == nil || spf.All != "-all" || spf.Lookups != 1 || len(spf.Errors) != 0 || spf.Tree == nil {
		t.Fatalf("spf = %+v", spf)
	}
	if inc := spf.Tree.Terms[0]; inc.Name != "include" || inc.Target == nil || inc.Target.Record != "v=spf1 ip4:198.51.100.0/24 ~all" {
		t.Fatalf("include not resolved: %+v", spf.Tree.Terms[0])
	}
	if k := res.DKIM.Keys; len(k) != 1 || k[0].Selector != "selector1" || k[0].Bits != 2048 || k[0].KeyType != "rsa" ||
		k[0].CNAME != "selector1-example._domainkey.provider.test" {
		t.Fatalf("dkim = %+v", res.DKIM.Keys)
	}
	if d := res.DMARC; d.Policy != "reject" || d.SubPol != "quarantine" || d.Pct != 100 || d.ADKIM != "s" || d.ASPF != "r" || d.RUA[0] != "mailto:dmarc@example.com" {
		t.Fatalf("dmarc = %+v", d)
	}
	wantFindings(t, fs, map[string]string{"spf_fail_all": "ok", "dkim_found": "ok", "dmarc_enforced": "ok"})
	for _, f := range fs {
		if f.Severity != "ok" {
			t.Errorf("unexpected finding %+v", f)
		}
	}
}

func TestEmailAuthMissingRecords(t *testing.T) {
	res, fs := runEmailAuth(t, `example.com. 300 IN A 192.0.2.1`, nil)
	if len(res.SPF.Records) != 0 || len(res.DKIM.Keys) != 0 || !slices.Contains(res.DKIM.Checked, "google") {
		t.Fatalf("result = %+v", res)
	}
	wantFindings(t, fs, map[string]string{"spf_missing": "warning", "dkim_missing": "warning", "dmarc_missing": "warning"})
	i := slices.IndexFunc(fs, func(f finding) bool { return f.Code == "dkim_missing" })
	if !strings.Contains(fs[i].Recommendation, "Check more DKIM selectors") {
		t.Errorf("dkim_missing doesn't say custom selectors can be added: %+v", fs[i])
	}
}

func TestSPFMultipleRecordsIsCritical(t *testing.T) {
	_, fs := runEmailAuth(t, `
example.com. 300 IN TXT "v=spf1 -all"
example.com. 300 IN TXT "v=spf1 include:_spf.provider.test ~all"`, map[string]string{"scope": "spf"})
	wantFindings(t, fs, map[string]string{"spf_multiple": "critical"})
	if len(fs) != 1 {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestSPFLookupsAreCountedThroughIncludes(t *testing.T) {
	// 2 at the top + 3 in one + 4 in two + 2 in three + 2 in four = 13.
	res, fs := runEmailAuth(t, `
example.com. 300 IN TXT "v=spf1 include:one.test include:two.test -all"
one.test. 300 IN TXT "v=spf1 a mx include:three.test ?all"
one.test. 300 IN A 192.0.2.1
one.test. 300 IN MX 10 one.test.
two.test. 300 IN TXT "v=spf1 a:x.test mx:x.test/24 ptr exists:x.test -all"
x.test. 300 IN A 192.0.2.2
x.test. 300 IN MX 10 x.test.
three.test. 300 IN TXT "v=spf1 include:four.test a"
three.test. 300 IN A 192.0.2.3
four.test. 300 IN TXT "v=spf1 mx a"
four.test. 300 IN A 192.0.2.4
four.test. 300 IN MX 10 four.test.`, map[string]string{"scope": "spf"})
	if res.SPF.Lookups != 13 || res.SPF.VoidLookups != 0 || res.SPF.All != "-all" {
		t.Fatalf("spf = %+v", res.SPF)
	}
	wantFindings(t, fs, map[string]string{"spf_too_many_lookups": "critical", "spf_fail_all": "ok"})
	if severityOf(fs, "spf_permerror") != "" {
		t.Errorf("findings = %v", codes(fs))
	}
}

func TestSPFPermerrors(t *testing.T) {
	res, fs := runEmailAuth(t, `
example.com. 300 IN TXT "v=spf1 include:gone.test include:loop.test ip4:300.1.1.1 bogus ~all"
loop.test. 300 IN TXT "v=spf1 include:example.com"`, map[string]string{"scope": "spf"})
	errs := strings.Join(res.SPF.Errors, "\n")
	for _, want := range []string{"gone.test has no SPF record", "loops back to example.com", `bad address "ip4:300.1.1.1"`, `unknown mechanism "bogus"`} {
		if !strings.Contains(errs, want) {
			t.Errorf("errors missing %q: %v", want, res.SPF.Errors)
		}
	}
	wantFindings(t, fs, map[string]string{"spf_permerror": "critical", "spf_softfail_all": "info"})
}

func TestSPFVoidLookups(t *testing.T) {
	res, fs := runEmailAuth(t, `example.com. 300 IN TXT "v=spf1 a:nx1.test mx:nx2.test exists:nx3.test -all"`, map[string]string{"scope": "spf"})
	if res.SPF.VoidLookups != 3 {
		t.Fatalf("spf = %+v", res.SPF)
	}
	wantFindings(t, fs, map[string]string{"spf_permerror": "critical"})
}

func TestSPFAllQualifiers(t *testing.T) {
	for rec, want := range map[string][2]string{
		"v=spf1 +all":                          {"spf_pass_all", "critical"},
		"v=spf1 all":                           {"spf_pass_all", "critical"},
		"v=spf1 ?all":                          {"spf_neutral_all", "warning"},
		"v=spf1 ip4:192.0.2.1":                 {"spf_no_all", "warning"},
		"v=spf1 ~all":                          {"spf_softfail_all", "info"},
		"v=spf1 redirect=_spf.provider.test":   {"spf_softfail_all", "info"}, // the redirect's all applies
		"V=SPF1 ip4:192.0.2.1 -ALL":            {"spf_fail_all", "ok"},
		"v=spf1 -all redirect=nowhere.invalid": {"spf_fail_all", "ok"}, // redirect ignored next to all
	} {
		t.Run(rec, func(t *testing.T) {
			_, fs := runEmailAuth(t, `example.com. 300 IN TXT "`+rec+`"
_spf.provider.test. 300 IN TXT "v=spf1 ~all"`, map[string]string{"scope": "spf"})
			wantFindings(t, fs, map[string]string{want[0]: want[1]})
			if severityOf(fs, "spf_permerror") != "" {
				t.Errorf("findings = %v", codes(fs))
			}
		})
	}
}

func TestDKIMKeyStrength(t *testing.T) {
	res, fs := runEmailAuth(t, `
google._domainkey.example.com. 300 IN TXT `+dkimTXT(t, 512)+`
k1._domainkey.example.com. 300 IN TXT `+dkimTXT(t, 1024)+`
s1._domainkey.example.com. 300 IN TXT "v=DKIM1; k=rsa; p="
s2._domainkey.example.com. 300 IN TXT "not a dkim record"
dkim._domainkey.example.com. 300 IN TXT "v=DKIM1; p=!!notbase64"
selector1._domainkey.example.com. 300 IN TXT `+dkimTXT(t, 1024)+`
selector2._domainkey.example.com. 300 IN TXT `+dkimTXT(t, 1024), map[string]string{"scope": "dkim"})
	bits := map[string]int{}
	for _, k := range res.DKIM.Keys {
		bits[k.Selector] = k.Bits
		if k.Selector == "s1" && !k.Revoked {
			t.Errorf("s1 not revoked: %+v", k)
		}
	}
	if len(bits) != 6 || bits["google"] != 512 || bits["k1"] != 1024 || bits["dkim"] != 0 {
		t.Fatalf("keys = %+v", res.DKIM.Keys)
	}
	wantFindings(t, fs, map[string]string{"dkim_weak_key": "critical", "dkim_short_key": "warning", "dkim_revoked": "info",
		"dkim_invalid_key": "warning", "dkim_found": "ok"})
	seen := map[string]bool{}
	for _, f := range fs {
		if seen[f.Code] {
			t.Errorf("two %s Findings for one Step", f.Code)
		}
		seen[f.Code] = true
	}
	if i := slices.IndexFunc(fs, func(f finding) bool { return f.Code == "dkim_found" }); strings.Contains(fs[i].Message, "dkim,") {
		t.Errorf("unusable key counted as published: %s", fs[i].Message)
	}
}

func TestSPFUnresolvedRedirectIsNotMissingAll(t *testing.T) {
	_, fs := runEmailAuth(t, `example.com. 300 IN TXT "v=spf1 redirect=_spf.%{d}"`, map[string]string{"scope": "spf"})
	if severityOf(fs, "spf_no_all") != "" {
		t.Errorf("findings = %v", codes(fs))
	}
}

func TestDKIMRevokedOnlyIsMissing(t *testing.T) {
	_, fs := runEmailAuth(t, `s1._domainkey.example.com. 300 IN TXT "v=DKIM1; p="`, map[string]string{"scope": "dkim"})
	wantFindings(t, fs, map[string]string{"dkim_revoked": "info", "dkim_missing": "warning"})
}

func TestDKIMCustomSelectors(t *testing.T) {
	zone := `acme2024._domainkey.example.com. 300 IN TXT ` + dkimTXT(t, 2048)
	res, fs := runEmailAuth(t, zone, map[string]string{"scope": "dkim"})
	wantFindings(t, fs, map[string]string{"dkim_missing": "warning"})
	if slices.Contains(res.DKIM.Checked, "acme2024") {
		t.Fatalf("checked = %v", res.DKIM.Checked)
	}

	res, fs = runEmailAuth(t, zone, map[string]string{"scope": "dkim", "selectors": "Acme2024, other  google"})
	if !slices.Contains(res.DKIM.Checked, "acme2024") || !slices.Contains(res.DKIM.Checked, "other") ||
		len(res.DKIM.Keys) != 1 || res.DKIM.Keys[0].Selector != "acme2024" {
		t.Fatalf("dkim = %+v", res.DKIM)
	}
	wantFindings(t, fs, map[string]string{"dkim_found": "ok"})
}

func TestDKIMInvalidSelectorFailsTheStep(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, healthyMail, false)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{"check": "email_auth", "target": "example.com",
		"options": map[string]string{"selectors": "ok, bad..name"}}, nil)
	if s := h.waitSteps(c.ID, 2)[1]; s.Status != "failed" {
		t.Fatalf("step = %+v", s)
	}
}

func TestDMARCMonitoringOnly(t *testing.T) {
	res, fs := runEmailAuth(t, `_dmarc.example.com. 300 IN TXT "v=DMARC1; p=none; pct=50; aspf=s"`, map[string]string{"scope": "dmarc"})
	if d := res.DMARC; d.Policy != "none" || d.Pct != 50 || d.ASPF != "s" || len(d.RUA) != 0 {
		t.Fatalf("dmarc = %+v", d)
	}
	wantFindings(t, fs, map[string]string{"dmarc_policy_none": "warning", "dmarc_partial": "info", "dmarc_no_rua": "info"})
}

func TestEmailAuthScopeLimitsWorkAndFindings(t *testing.T) {
	res, fs := runEmailAuth(t, `example.com. 300 IN A 192.0.2.1`, map[string]string{"scope": "dmarc"})
	if res.Scope != "dmarc" || res.SPF != nil || res.DKIM != nil || res.DMARC == nil {
		t.Fatalf("result = %+v", res)
	}
	for _, f := range fs {
		if !strings.HasPrefix(f.Code, "dmarc_") {
			t.Errorf("out-of-scope finding %s", f.Code)
		}
	}
	wantFindings(t, fs, map[string]string{"dmarc_missing": "warning"})
}

func TestEmailAuthFailsWhenResolverIsSilent(t *testing.T) {
	resolver, set := mutableDNS(t, exampleZone, false)
	h := start(t, app.Config{Net: app.Net{Resolver: resolver}, CheckTimeout: 500 * time.Millisecond})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	set(noAnswer)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{"check": "email_auth", "target": "example.com",
		"options": map[string]string{"scope": "spf"}}, nil)
	if s := h.waitSteps(c.ID, 2)[1]; s.Status != "failed" {
		t.Fatalf("step = %+v", s)
	}
}
