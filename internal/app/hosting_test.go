package app_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ScribeK2/Stackwell/internal/app"
)

const hostingZone = `
example.com. 300 IN A 192.0.2.10
bare.example.com. 300 IN TXT "no address"
dual.example.com. 300 IN A 192.0.2.10
dual.example.com. 300 IN AAAA 2001:db8::10
`

type hostingPort struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	State   string `json:"state"`
	Banner  string `json:"banner"`
}

type hostingResult struct {
	Addresses []string      `json:"addresses"`
	Ports     []hostingPort `json:"ports"`
}

// fakeHost is 192.0.2.10: the open ports are local listeners (sending banner,
// if any, on accept), filtered ports never answer, and every other port refuses.
func fakeHost(t *testing.T, open map[int]string, filtered ...int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	t.Helper()
	listen := func() net.Listener {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	refused := listen()
	refusedAddr := refused.Addr().String()
	refused.Close()

	local := map[int]string{}
	for port, banner := range open {
		l := listen()
		t.Cleanup(func() { l.Close() })
		local[port] = l.Addr().String()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Write([]byte(banner))
				c.Close()
			}
		}()
	}
	var d net.Dialer
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, p, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(p)
		if host != "192.0.2.10" && host != "2001:db8::10" {
			t.Errorf("dialled unexpected host %s", addr)
		}
		if slices.Contains(filtered, port) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if a, ok := local[port]; ok {
			return d.DialContext(ctx, network, a)
		}
		return d.DialContext(ctx, network, refusedAddr)
	}
}

func runHosting(t *testing.T, target string, opts map[string]string, dial func(context.Context, string, string) (net.Conn, error)) (hostingResult, []finding) {
	t.Helper()
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, hostingZone, false), Dial: dial}})
	c := newCase(h, target)
	auto := 0
	if target != "192.0.2.10" {
		auto = 1 // DNS Lookup
		h.waitSteps(c.ID, auto)
	}
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{"check": "hosting_reachability", "target": target, "options": opts}, nil); code != http.StatusOK {
		t.Fatalf("run hosting_reachability: %d", code)
	}
	h.waitSteps(c.ID, auto+1)
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
	var res hostingResult
	if s := raw.Steps[auto]; s.Check != "hosting_reachability" || s.Status != "ok" || json.Unmarshal(s.Result, &res) != nil {
		t.Fatalf("step = %+v", s)
	}
	var fs []finding
	for _, f := range raw.Findings {
		if strings.HasPrefix(f.Code, "hosting_reachability") {
			fs = append(fs, f)
		}
	}
	return res, fs
}

func port(r hostingResult, n int) hostingPort {
	for _, p := range r.Ports {
		if p.Port == n {
			return p
		}
	}
	return hostingPort{}
}

var webAndMail = map[int]string{80: "", 443: "", 25: "220 mx.example.com ESMTP Postfix\r\n250 more\r\n", 22: "SSH-2.0-OpenSSH_9.6\r\n"}

func TestHostingQuickSweepClassifiesEachPort(t *testing.T) {
	res, fs := runHosting(t, "example.com", nil, fakeHost(t, webAndMail))
	if !slices.Equal(res.Addresses, []string{"192.0.2.10"}) || len(res.Ports) != 8 {
		t.Fatalf("result = %+v", res)
	}
	if p := port(res, 443); p.State != "open" || p.Service != "HTTPS" || p.Address != "192.0.2.10" {
		t.Fatalf("443 = %+v", p)
	}
	if p := port(res, 21); p.State != "closed" || p.Service != "FTP" {
		t.Fatalf("21 = %+v", p)
	}
	if p := port(res, 25); p.Banner != "220 mx.example.com ESMTP Postfix" {
		t.Fatalf("smtp banner = %q", p.Banner)
	}
	if p := port(res, 22); p.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("ssh banner = %q", p.Banner)
	}
	if !slices.Equal(codes(fs), []string{"hosting_reachability_reachable"}) {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestHostingFullSweepCoversMorePorts(t *testing.T) {
	res, fs := runHosting(t, "example.com", map[string]string{"depth": "full"}, fakeHost(t, map[int]string{80: "", 443: "", 25: "", 5432: "", 2083: ""}))
	if len(res.Ports) < 25 || port(res, 2083).State != "open" || port(res, 2083).Service != "cPanel SSL" {
		t.Fatalf("full sweep = %d ports, 2083 %+v", len(res.Ports), port(res, 2083))
	}
	if severityOf(fs, "hosting_reachability_database_exposed") != "warning" {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestHostingProbesAnIPDirectly(t *testing.T) {
	res, _ := runHosting(t, "192.0.2.10", nil, fakeHost(t, webAndMail))
	if !slices.Equal(res.Addresses, []string{"192.0.2.10"}) || port(res, 80).State != "open" {
		t.Fatalf("result = %+v", res)
	}
}

func TestHostingFilteredPortsTimeOut(t *testing.T) {
	res, _ := runHosting(t, "example.com", nil, fakeHost(t, webAndMail, 3306))
	if p := port(res, 3306); p.State != "filtered" {
		t.Fatalf("3306 = %+v", p)
	}
}

func TestHostingNothingOpenIsUnreachable(t *testing.T) {
	_, fs := runHosting(t, "example.com", nil, fakeHost(t, nil))
	if !slices.Equal(codes(fs), []string{"hosting_reachability_unreachable"}) || fs[0].Severity != "critical" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestHostingNameWithoutAddress(t *testing.T) {
	res, fs := runHosting(t, "bare.example.com", nil, fakeHost(t, nil))
	if len(res.Ports) != 0 || severityOf(fs, "hosting_reachability_no_address") != "critical" {
		t.Fatalf("result %+v, findings %v", res, codes(fs))
	}
}

func TestHostingWebAndMailFindings(t *testing.T) {
	_, fs := runHosting(t, "example.com", nil, fakeHost(t, map[int]string{22: "", 3306: ""}))
	for code, sev := range map[string]string{
		"hosting_reachability_web_closed":       "warning",
		"hosting_reachability_smtp_closed":      "info",
		"hosting_reachability_database_exposed": "warning",
		"hosting_reachability_reachable":        "ok",
	} {
		if severityOf(fs, code) != sev {
			t.Errorf("%s: want %s, findings %v", code, sev, codes(fs))
		}
	}
	_, fs = runHosting(t, "example.com", nil, fakeHost(t, map[int]string{80: "", 25: ""}))
	if severityOf(fs, "hosting_reachability_no_https") != "warning" || slices.Contains(codes(fs), "hosting_reachability_web_closed") {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestHostingJudgesEachAddressAndNamesNoRoute(t *testing.T) {
	// The IPv6 address is unroutable from here, so it must not be called
	// filtered, and HTTPS on IPv4 alone must not hide that IPv6 lacks it.
	v4 := fakeHost(t, map[int]string{80: "", 443: "", 25: ""})
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, _ := net.SplitHostPort(addr); host == "2001:db8::10" {
			return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
		}
		return v4(ctx, network, addr)
	}
	res, fs := runHosting(t, "dual.example.com", nil, dial)
	if !slices.Equal(res.Addresses, []string{"192.0.2.10", "2001:db8::10"}) || len(res.Ports) != 16 {
		t.Fatalf("result = %+v", res)
	}
	for _, p := range res.Ports {
		if p.Address == "2001:db8::10" && p.State != "no route" {
			t.Fatalf("v6 port = %+v", p)
		}
	}
	i := slices.IndexFunc(fs, func(f finding) bool { return f.Code == "hosting_reachability_web_closed" })
	if i == -1 || !strings.Contains(fs[i].Message, "2001:db8::10") || strings.Contains(fs[i].Message, "192.0.2.10") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestHostingFailsWhenTheAddressLookupFails(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, hostingZone, false, dns.TypeA), Dial: fakeHost(t, nil)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "hosting_reachability", "target": "example.com"}, nil)
	if s := h.waitSteps(c.ID, 2)[1]; s.Status != "failed" {
		t.Fatalf("step = %+v; a lost A answer must not read as no address", s)
	}
}

func TestHostingSweepStaysWithinTheCheckTimeout(t *testing.T) {
	began := time.Now()
	runHosting(t, "example.com", map[string]string{"depth": "full"}, fakeHost(t, webAndMail, 8080, 8443, 8888))
	if d := time.Since(began); d > 5*time.Second {
		t.Fatalf("full sweep with filtered ports took %s", d)
	}
}
