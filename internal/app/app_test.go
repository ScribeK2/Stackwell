package app_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ScribeK2/Stackwell/internal/app"
)

func TestTypingATargetStartsACaseAndRunsDNSLookup(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})

	var c caseView
	if code := h.do("POST", "/api/cases", map[string]string{"target": "example.com"}, &c); code != http.StatusCreated {
		t.Fatalf("status %d", code)
	}
	if len(c.Targets) != 1 || c.Targets[0].Value != "example.com" {
		t.Fatalf("targets = %v", c.Targets)
	}

	s := h.waitStep(c.ID)
	if s.Check != "dns_lookup" || s.Target != "example.com" || s.Status != "ok" {
		t.Fatalf("step = %+v", s)
	}
	want := map[string][]string{
		"A":    {"93.184.216.34"},
		"AAAA": {"2606:2800:220:1:248:1893:25c8:1946"},
		"MX":   {"10 mail.example.com."},
		"NS":   {"a.iana-servers.net."},
		"TXT":  {`"v=spf1 -all"`},
		"SOA":  {"ns.icann.org. noc.dns.icann.org. 2024 7200 3600 1209600 3600"},
		"CAA":  {`0 issue "letsencrypt.org"`},
	}
	for typ, vals := range want {
		got := s.Result.Records[typ]
		if strings.Join(got, "|") != strings.Join(vals, "|") {
			t.Errorf("%s = %v, want %v", typ, got, vals)
		}
	}
	if len(s.Result.Records["CNAME"]) != 0 {
		t.Errorf("apex should have no CNAME, got %v", s.Result.Records["CNAME"])
	}
}

func TestCNAMETargetReportsCNAME(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	var c caseView
	h.do("POST", "/api/cases", map[string]string{"target": "www.example.com"}, &c)
	s := h.waitStep(c.ID)
	if got := s.Result.Records["CNAME"]; len(got) != 1 || got[0] != "example.com." {
		t.Fatalf("CNAME = %v", got)
	}
}

func TestLargeAnswersAreFetchedInFullOverTCP(t *testing.T) {
	var zone strings.Builder
	for i := range 20 {
		fmt.Fprintf(&zone, "big.test. 300 IN TXT \"verification-token-%02d-%s\"\n", i, strings.Repeat("x", 80))
	}
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, zone.String(), false)}})
	var c caseView
	h.do("POST", "/api/cases", map[string]string{"target": "big.test"}, &c)
	s := h.waitStep(c.ID)
	if got := len(s.Result.Records["TXT"]); got != 20 {
		t.Fatalf("got %d TXT records, want 20", got)
	}
}

func TestOneFailingRecordTypeIsReportedWithoutFailingTheLookup(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false, dns.TypeCAA)}})
	var c caseView
	h.do("POST", "/api/cases", map[string]string{"target": "example.com"}, &c)
	s := h.waitStep(c.ID)
	if s.Status != "ok" || s.Result.Rcode != "NOERROR" || s.Result.Records["A"][0] != "93.184.216.34" {
		t.Fatalf("step = %+v", s)
	}
	if s.Result.Errors["CAA"] != "REFUSED" || len(s.Result.Errors) != 1 {
		t.Fatalf("errors = %v, want only CAA: REFUSED", s.Result.Errors)
	}
}

func TestUnknownDomainIsAnOKStepWithNXDOMAIN(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	var c caseView
	h.do("POST", "/api/cases", map[string]string{"target": "nope.test"}, &c)
	s := h.waitStep(c.ID)
	if s.Status != "ok" || s.Result.Rcode != "NXDOMAIN" {
		t.Fatalf("step = %+v", s)
	}
}

func TestCheckTimeoutFailsTheStepInsteadOfHanging(t *testing.T) {
	h := start(t, app.Config{
		Net:          app.Net{Resolver: fakeDNS(t, "", true)},
		CheckTimeout: 300 * time.Millisecond,
	})
	var c caseView
	h.do("POST", "/api/cases", map[string]string{"target": "example.com"}, &c)
	s := h.waitStep(c.ID)
	if s.Status != "failed" || s.Error == "" {
		t.Fatalf("step = %+v", s)
	}
}

func TestEmptyTargetIsRejected(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	if code := h.do("POST", "/api/cases", map[string]string{"target": "  "}, nil); code != http.StatusBadRequest {
		t.Fatalf("status %d", code)
	}
}

func TestCaseSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	resolver := fakeDNS(t, exampleZone, false)
	h := start(t, app.Config{DataDir: dir, Net: app.Net{Resolver: resolver}})
	var c caseView
	h.do("POST", "/api/cases", map[string]string{"target": "example.com"}, &c)
	h.waitStep(c.ID)
	h.stop()

	h2 := start(t, app.Config{DataDir: dir, Net: app.Net{Resolver: resolver}})
	var again caseView
	if code := h2.do("GET", "/api/cases/"+itoa(c.ID), nil, &again); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if len(again.Steps) != 1 || again.Steps[0].Status != "ok" || again.Steps[0].Result.Records["A"][0] != "93.184.216.34" {
		t.Fatalf("after restart: %+v", again)
	}
}

func TestStepUpdatesStreamLive(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})

	resp, err := http.Get(h.web.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type %q", ct)
	}

	var c caseView
	h.do("POST", "/api/cases", map[string]string{"target": "example.com"}, &c)

	done := make(chan step, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			data, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			var ev struct {
				CaseID int64 `json:"case_id"`
				Step   step  `json:"step"`
			}
			json.Unmarshal([]byte(data), &ev)
			if ev.CaseID == c.ID && ev.Step.Status == "ok" {
				done <- ev.Step
				return
			}
		}
	}()
	select {
	case s := <-done:
		if s.Result.Records["A"][0] != "93.184.216.34" {
			t.Fatalf("streamed step = %+v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no finished step event")
	}
}

func TestServesTheUI(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	resp, err := http.Get(h.web.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("GET / = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestHealthReportsVersion(t *testing.T) {
	h := start(t, app.Config{Version: "1.2.3", Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	var body struct{ Status, Version string }
	if code := h.do("GET", "/api/health", nil, &body); code != http.StatusOK || body.Status != "ok" || body.Version != "1.2.3" {
		t.Fatalf("health = %d %+v", code, body)
	}
}
