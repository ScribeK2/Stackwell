package app_test

import (
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type headerAnalysis struct {
	Headers struct {
		From, Subject, ReturnPath string
	} `json:"headers"`
	Hops []struct {
		FromHost string   `json:"from_host"`
		FromIP   string   `json:"from_ip"`
		With     string   `json:"with"`
		DelayS   *float64 `json:"delay_s"`
	} `json:"hops"`
	TotalTransitS *float64 `json:"total_transit_s"`
	OriginIP      string   `json:"origin_ip"`
	Auth          struct {
		SPF, DKIM, DMARC string
	} `json:"auth"`
	Alignment struct {
		FromDomain            string `json:"from_domain"`
		ReturnPathDomain      string `json:"return_path_domain"`
		FromReturnPathAligned *bool  `json:"from_return_path_aligned"`
		MessageIDAligned      *bool  `json:"message_id_aligned"`
	} `json:"alignment"`
	Spam struct {
		Score   *float64 `json:"score"`
		Flagged bool     `json:"flagged"`
	} `json:"spam"`
}

type evidenceCase struct {
	Evidence []struct {
		ID       int64          `json:"id"`
		Kind     string         `json:"kind"`
		Raw      string         `json:"raw"`
		Analysis headerAnalysis `json:"analysis"`
	} `json:"evidence"`
	Findings []struct {
		finding
		Evidence []int64 `json:"evidence"`
	} `json:"findings"`
	Suggestions []struct {
		suggestion
		Evidence int64 `json:"evidence"`
	} `json:"suggestions"`
}

func fixture(t *testing.T, name string) string {
	b, err := os.ReadFile("testdata/email_headers/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// pasteHeaders puts raw headers into a fresh Case as Evidence and returns the Case.
func pasteHeaders(t *testing.T, raw string) (*harness, int64, evidenceCase) {
	t.Helper()
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	var got evidenceCase
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/evidence", map[string]string{"kind": "email_headers", "raw": raw}, &got); code != http.StatusOK {
		t.Fatalf("paste: %d", code)
	}
	if len(got.Evidence) != 1 {
		t.Fatalf("evidence = %+v", got.Evidence)
	}
	return h, c.ID, got
}

func evidenceCodes(c evidenceCase) []string {
	var out []string
	for _, f := range c.Findings {
		if len(f.Evidence) > 0 {
			out = append(out, f.Code)
		}
	}
	return out
}

func TestPastedHeadersAreKeptAndAnalysed(t *testing.T) {
	raw := fixture(t, "gmail.txt")
	h, id, c := pasteHeaders(t, raw)
	e := c.Evidence[0]
	if e.Kind != "email_headers" || e.Raw != raw {
		t.Fatalf("evidence = %+v", e)
	}
	a := e.Analysis
	if a.OriginIP != "203.0.113.5" || len(a.Hops) != 2 || a.Auth.DMARC != "pass" {
		t.Fatalf("analysis = %+v", a)
	}

	// Findings cite the Evidence, not a Step.
	i := slices.IndexFunc(c.Findings, func(f struct {
		finding
		Evidence []int64 `json:"evidence"`
	}) bool {
		return f.Code == "email_headers_authenticated"
	})
	if i == -1 || c.Findings[i].Severity != "ok" || !slices.Equal(c.Findings[i].Evidence, []int64{e.ID}) {
		t.Fatalf("findings = %+v", c.Findings)
	}

	// The originating IP is offered as a Suggested target from the Evidence.
	j := slices.IndexFunc(c.Suggestions, func(s struct {
		suggestion
		Evidence int64 `json:"evidence"`
	}) bool {
		return s.Value == "203.0.113.5"
	})
	if j == -1 || c.Suggestions[j].Evidence != e.ID || !strings.Contains(c.Suggestions[j].Reason, "Earliest") {
		t.Fatalf("suggestions = %+v", c.Suggestions)
	}

	// Saved with the Case.
	var again evidenceCase
	h.do("GET", "/api/cases/"+itoa(id), nil, &again)
	if len(again.Evidence) != 1 || again.Evidence[0].Raw != raw {
		t.Fatalf("evidence after reload = %+v", again.Evidence)
	}
}

func TestSpoofedHeadersAreCalledOut(t *testing.T) {
	_, _, c := pasteHeaders(t, fixture(t, "spoofed.txt"))
	a := c.Evidence[0].Analysis
	if a.Auth.DMARC != "fail" || a.Alignment.FromDomain != "yourbank.test" || a.Alignment.ReturnPathDomain != "evil.test" ||
		a.Alignment.FromReturnPathAligned == nil || *a.Alignment.FromReturnPathAligned {
		t.Fatalf("analysis = %+v", a)
	}
	got := evidenceCodes(c)
	for _, want := range []string{"email_headers_dmarc_fail", "email_headers_spf_fail", "email_headers_misaligned"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	for _, f := range c.Findings {
		if f.Code == "email_headers_dmarc_fail" && f.Severity != "critical" {
			t.Errorf("DMARC fail is %s", f.Severity)
		}
	}
	// Domains in the headers are offered too.
	var values []string
	for _, s := range c.Suggestions {
		values = append(values, s.Value)
	}
	for _, want := range []string{"evil.test", "yourbank.test", "198.51.100.66"} {
		if !slices.Contains(values, want) {
			t.Errorf("no suggestion %s in %v", want, values)
		}
	}
}

func TestMinimalHeadersParseWithoutAnAuthenticationVerdict(t *testing.T) {
	_, _, c := pasteHeaders(t, fixture(t, "minimal.txt"))
	a := c.Evidence[0].Analysis
	if len(a.Hops) != 0 || a.Auth.SPF != "" || a.OriginIP != "" {
		t.Fatalf("analysis = %+v", a)
	}
	if !slices.Contains(evidenceCodes(c), "email_headers_no_auth_results") {
		t.Fatalf("findings = %v", evidenceCodes(c))
	}
}

func TestHeaderParsingEdgeCases(t *testing.T) {
	t.Run("quoted, folded, body ignored", func(t *testing.T) {
		_, _, c := pasteHeaders(t, `> From: Alice <alice@ex.com>
> Subject: multi
>  line subject
> X-Body-Should-Be: ignored

This is the body and must be ignored.
Received: should not be parsed from body`)
		a := c.Evidence[0].Analysis
		if a.Headers.From != "Alice <alice@ex.com>" || a.Headers.Subject != "multi line subject" || len(a.Hops) != 0 {
			t.Fatalf("analysis = %+v", a)
		}
	})
	t.Run("hops oldest first with delays", func(t *testing.T) {
		_, _, c := pasteHeaders(t, `Received: from relay.ex.com (relay.ex.com [203.0.113.9]) by mx.dest.com with ESMTPS id Z2; Wed, 14 Jun 2026 10:02:00 -0700
Received: from sender.ex.com (sender.ex.com [203.0.113.5]) by relay.ex.com with ESMTP id Z1 for <u@dest.com>; Wed, 14 Jun 2026 10:00:00 -0700
From: a@ex.com`)
		a := c.Evidence[0].Analysis
		if len(a.Hops) != 2 || a.Hops[0].FromHost != "sender.ex.com" || a.Hops[0].FromIP != "203.0.113.5" || a.Hops[0].With != "ESMTP" {
			t.Fatalf("hops = %+v", a.Hops)
		}
		if a.Hops[0].DelayS != nil || a.Hops[1].DelayS == nil || *a.Hops[1].DelayS != 120 || a.TotalTransitS == nil || *a.TotalTransitS != 120 {
			t.Fatalf("delays = %+v / %v", a.Hops, a.TotalTransitS)
		}
	})
	t.Run("private and IPv6 ULA hops are not the origin", func(t *testing.T) {
		_, _, c := pasteHeaders(t, `Received: from a (a [203.0.113.7]) by mx; Wed, 14 Jun 2026 10:01:00 -0700
Received: from v6 (v6 [IPv6:fd00::1]) by a; Wed, 14 Jun 2026 10:00:30 -0700
Received: from localhost (localhost [127.0.0.1]) by v6; Wed, 14 Jun 2026 10:00:00 -0700
From: a@ex.com`)
		if got := c.Evidence[0].Analysis.OriginIP; got != "203.0.113.7" {
			t.Fatalf("origin = %q", got)
		}
	})
	t.Run("a long delay between hops is flagged", func(t *testing.T) {
		_, _, c := pasteHeaders(t, `Received: from relay (relay [203.0.113.9]) by mx; Wed, 14 Jun 2026 10:45:00 -0700
Received: from sender (sender [203.0.113.5]) by relay; Wed, 14 Jun 2026 10:00:00 -0700
From: a@ex.com`)
		if !slices.Contains(evidenceCodes(c), "email_headers_delayed") {
			t.Fatalf("findings = %v", evidenceCodes(c))
		}
	})
	t.Run("relaxed alignment and a spam score", func(t *testing.T) {
		_, _, c := pasteHeaders(t, `Return-Path: <bounce@mailer.ex.com>
From: "Brand" <noreply@ex.com>
Message-ID: <abc.123@ex.com>
X-Spam-Score: 7.4
Date: Wed, 14 Jun 2026 10:00:00 -0700`)
		a := c.Evidence[0].Analysis
		if a.Alignment.FromReturnPathAligned == nil || !*a.Alignment.FromReturnPathAligned || a.Alignment.MessageIDAligned == nil || !*a.Alignment.MessageIDAligned {
			t.Fatalf("alignment = %+v", a.Alignment)
		}
		if a.Spam.Score == nil || *a.Spam.Score != 7.4 || !a.Spam.Flagged || !slices.Contains(evidenceCodes(c), "email_headers_spam") {
			t.Fatalf("spam = %+v, findings %v", a.Spam, evidenceCodes(c))
		}
	})
	t.Run("Microsoft SCL", func(t *testing.T) {
		_, _, c := pasteHeaders(t, `From: a@ex.com
X-MS-Exchange-Organization-SCL: 6`)
		if !c.Evidence[0].Analysis.Spam.Flagged {
			t.Fatalf("spam = %+v", c.Evidence[0].Analysis.Spam)
		}
	})
}

func TestTextThatIsNotHeadersIsRefused(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	for _, body := range []map[string]string{
		{"kind": "email_headers", "raw": "just some random text\nno colons here"},
		{"kind": "email_headers", "raw": "   "},
		{"kind": "tea_leaves", "raw": "From: a@ex.com"},
	} {
		if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/evidence", body, nil); code != http.StatusBadRequest {
			t.Errorf("%v: %d", body, code)
		}
	}
}

func TestAFailedDKIMSignatureDoesNotCountAsAligned(t *testing.T) {
	_, _, c := pasteHeaders(t, `Received: from sketchy.host (sketchy.host [198.51.100.66]) by mx.dest.com with ESMTP; Wed, 14 Jun 2026 03:00:00 +0000
Authentication-Results: mx.dest.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=yourbank.test; dmarc=fail header.from=yourbank.test
DKIM-Signature: v=1; a=rsa-sha256; d=yourbank.test; s=forged; b=AAAA
Return-Path: <attacker@evil.test>
From: Your Bank <security@yourbank.test>`)
	if al := c.Evidence[0].Analysis.Alignment; al.FromReturnPathAligned == nil || *al.FromReturnPathAligned {
		t.Fatalf("alignment = %+v", al)
	}
	if !slices.Contains(evidenceCodes(c), "email_headers_misaligned") {
		t.Fatalf("a forged, failing DKIM signature hid the misalignment: %v", evidenceCodes(c))
	}
}

func TestTheDeliveringServerIsKnownApartFromTheClaimedOrigin(t *testing.T) {
	// The bottom Received line is the sender's to write; the top one is the
	// recipient's own server recording who connected to it.
	_, _, c := pasteHeaders(t, `Received: from relay.spam.test (relay.spam.test [198.51.100.66]) by mx.dest.com with ESMTP; Wed, 14 Jun 2026 03:00:05 +0000
Received: from innocent (innocent [8.8.8.8]) by relay.spam.test; Wed, 14 Jun 2026 03:00:00 +0000
From: a@spam.test`)
	reasons := map[string]string{}
	for _, s := range c.Suggestions {
		reasons[s.Value] = s.Reason
	}
	if !strings.Contains(reasons["198.51.100.66"], "Delivered") {
		t.Errorf("the delivering server isn't suggested as such: %v", reasons)
	}
	if !strings.Contains(reasons["8.8.8.8"], "can be forged") {
		t.Errorf("the claimed origin isn't marked as forgeable: %v", reasons)
	}
}
