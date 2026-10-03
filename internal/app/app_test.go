package app_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ScribeK2/Stackwell/internal/app"
)

// fakeDNS serves zone (lines in zone-file presentation format) on 127.0.0.1.
// Queries for anything not in zone get NXDOMAIN; queries for a refused type get REFUSED.
// With silent=true it never answers.
func fakeDNS(t *testing.T, zone string, silent bool, refuse ...uint16) string {
	addr, _ := mutableDNS(t, zone, silent, refuse...)
	return addr
}

// noAnswer, passed to mutableDNS's setter, makes the server stop answering.
const noAnswer = "<no answer>"

// mutableDNS is fakeDNS plus a function that replaces the zone it serves.
func mutableDNS(t *testing.T, zone string, silent bool, refuse ...uint16) (string, func(zone string)) {
	t.Helper()
	parse := func(zone string) []dns.RR {
		var rrs []dns.RR
		for _, line := range strings.Split(strings.TrimSpace(zone), "\n") {
			if line = strings.TrimSpace(line); line == "" {
				continue
			}
			rr, err := dns.NewRR(line)
			if err != nil {
				t.Fatalf("bad zone line %q: %v", line, err)
			}
			rrs = append(rrs, rr)
		}
		return rrs
	}
	var current atomic.Pointer[[]dns.RR]
	var mute atomic.Bool
	initial := parse(zone)
	current.Store(&initial)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Serve TCP on the same port, like a real resolver, for truncated-answer retries.
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if silent || mute.Load() {
			return
		}
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if slices.Contains(refuse, q.Qtype) {
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m)
			return
		}
		known := false
		for _, rr := range *current.Load() {
			if strings.EqualFold(rr.Header().Name, q.Name) {
				known = true
				if rr.Header().Rrtype == q.Qtype {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		if !known {
			m.Rcode = dns.RcodeNameError
		}
		if w.LocalAddr().Network() == "udp" {
			size := dns.MinMsgSize
			if opt := r.IsEdns0(); opt != nil {
				size = int(opt.UDPSize())
			}
			m.Truncate(size)
		}
		w.WriteMsg(m)
	})
	udp := &dns.Server{PacketConn: pc, Handler: h}
	tcp := &dns.Server{Listener: ln, Handler: h}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return pc.LocalAddr().String(), func(zone string) {
		mute.Store(zone == noAnswer)
		if zone == noAnswer {
			return
		}
		rrs := parse(zone)
		current.Store(&rrs)
	}
}

type harness struct {
	t   *testing.T
	srv *app.Server
	web *httptest.Server
}

func start(t *testing.T, cfg app.Config) *harness {
	t.Helper()
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	srv, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, srv: srv, web: httptest.NewServer(srv.Handler())}
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.web.Close()
	h.srv.Close()
}

func (h *harness) do(method, path string, body any, out any) int {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, h.web.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			h.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

type step struct {
	ID     int64  `json:"id"`
	Check  string `json:"check"`
	Target string `json:"target"`
	Status string `json:"status"`
	Error  string `json:"error"`
	Result struct {
		Rcode   string              `json:"rcode"`
		Records map[string][]string `json:"records"`
		Errors  map[string]string   `json:"errors"`
	} `json:"result"`
}

type caseView struct {
	ID      int64        `json:"id"`
	Targets []targetView `json:"targets"`
	Steps   []step       `json:"steps"`
}

// waitStep polls the Case until its first Step leaves "running".
func (h *harness) waitStep(caseID int64) step {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var c caseView
		h.do("GET", "/api/cases/"+itoa(caseID), nil, &c)
		if len(c.Steps) > 0 && c.Steps[0].Status != "running" {
			return c.Steps[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatal("step never finished")
	return step{}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

const exampleZone = `
example.com. 300 IN A 93.184.216.34
example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946
example.com. 300 IN MX 10 mail.example.com.
example.com. 300 IN NS a.iana-servers.net.
example.com. 300 IN TXT "v=spf1 -all"
example.com. 300 IN SOA ns.icann.org. noc.dns.icann.org. 2024 7200 3600 1209600 3600
example.com. 300 IN CAA 0 issue "letsencrypt.org"
www.example.com. 300 IN CNAME example.com.
`

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
