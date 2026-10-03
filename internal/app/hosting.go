package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// servicePort is a TCP port worth probing on a hosting server.
type servicePort struct {
	Port    int
	Service string
}

// Bundled reference data: the ports a hosting, mail or database server
// commonly listens on. Quick covers the services a rep asks about first.
var hostingPorts = map[string][]servicePort{
	"quick": {{80, "HTTP"}, {443, "HTTPS"}, {25, "SMTP"}, {587, "Submission"}, {993, "IMAPS"}, {22, "SSH"}, {21, "FTP"}, {3306, "MySQL"}},
	"full": {
		{20, "FTP data"}, {21, "FTP"}, {22, "SSH"}, {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"},
		{110, "POP3"}, {143, "IMAP"}, {443, "HTTPS"}, {465, "SMTPS"}, {587, "Submission"},
		{993, "IMAPS"}, {995, "POP3S"}, {1433, "MS SQL"}, {2082, "cPanel"}, {2083, "cPanel SSL"},
		{2086, "WHM"}, {2087, "WHM SSL"}, {2095, "Webmail"}, {2096, "Webmail SSL"},
		{2222, "SSH alt / DirectAdmin"}, {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"},
		{6379, "Redis"}, {8080, "HTTP alt"}, {8443, "HTTPS alt / Plesk"}, {8888, "HTTP alt"},
		{10000, "Webmin"}, {27017, "MongoDB"},
	},
}

// Plain-text protocols that greet the client first, so a short read shows the software.
var bannerPorts = []int{21, 22, 25, 110, 143, 587, 2222}

var databasePorts = []int{1433, 3306, 5432, 6379, 27017}

const (
	hostingDialTimeout   = 2 * time.Second
	hostingBannerTimeout = 500 * time.Millisecond
	hostingParallel      = 16
)

func init() {
	registerCheck(check{
		key:      "hosting_reachability",
		label:    "Hosting Reachability",
		kinds:    []string{kindDomain, kindHostname, kindIP},
		options:  []Option{{Key: "depth", Label: "Depth", Choices: []string{"quick", "full"}, Default: "quick"}},
		run:      hostingReachability,
		findings: hostingFindings,
	})
}

type portProbe struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	State   string `json:"state"` // open | closed (refused) | filtered (no answer) | no route (from this network)
	Banner  string `json:"banner,omitempty"`
}

type hostingResult struct {
	Addresses []string    `json:"addresses"` // what was probed: the first IPv4 and first IPv6 address
	Ports     []portProbe `json:"ports"`
}

// hostingReachability dials each service port on the Target's address(es)
// and classifies it as open, closed or filtered.
func hostingReachability(ctx context.Context, n Net, target string, opts map[string]string) (any, error) {
	res := hostingResult{Addresses: []string{}, Ports: []portProbe{}}
	if _, err := netip.ParseAddr(target); err == nil {
		res.Addresses = append(res.Addresses, target)
	} else {
		out, err := dnsLookup(ctx, n, target, nil)
		if err != nil {
			return nil, err
		}
		l := out.(dnsLookupResult)
		for _, t := range []string{"A", "AAAA"} {
			if e, failed := l.Errors[t]; failed {
				// Otherwise a lost query would read as "no address".
				return nil, errors.New("the " + t + " lookup for " + target + " failed: " + e)
			}
			if len(l.Records[t]) > 0 {
				res.Addresses = append(res.Addresses, strings.TrimSpace(l.Records[t][0]))
			}
		}
	}

	sem := make(chan struct{}, hostingParallel)
	var wg sync.WaitGroup
	for _, addr := range res.Addresses {
		for _, sp := range hostingPorts[opts["depth"]] {
			res.Ports = append(res.Ports, portProbe{Address: addr, Port: sp.Port, Service: sp.Service})
		}
	}
	for i := range res.Ports {
		p := &res.Ports[i]
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			p.State, p.Banner = probePort(ctx, n, p.Address, p.Port)
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		// Ports cut off by the Check timeout would wrongly read as filtered.
		return nil, errors.New("timed out before every port answered")
	}
	return res, nil
}

func probePort(ctx context.Context, n Net, addr string, port int) (state, banner string) {
	dctx, cancel := context.WithTimeout(ctx, hostingDialTimeout)
	defer cancel()
	conn, err := n.DialContext(dctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return "closed", ""
		}
		if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
			return "no route", "" // e.g. no IPv6 on the rep's own network
		}
		return "filtered", "" // timed out, or a firewall dropped/rejected it otherwise
	}
	defer conn.Close()
	if !slices.Contains(bannerPorts, port) {
		return "open", ""
	}
	deadline := time.Now().Add(hostingBannerTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 256)
	nr, _ := conn.Read(buf)
	line, _, _ := strings.Cut(strings.ToValidUTF8(string(buf[:nr]), ""), "\n")
	line = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, line)
	return "open", strings.TrimSpace(line)
}

func hostingFindings(target, _ string, _ map[string]string, raw json.RawMessage) []Finding {
	var r hostingResult
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	if len(r.Addresses) == 0 {
		return []Finding{{Code: "hosting_reachability_no_address", Severity: "critical",
			Title:          "No address to probe",
			Message:        target + " has no A or AAAA record, so there is no server to reach.",
			Recommendation: "Add an A record pointing at the hosting server, or check the DNS Lookup for this name."}}
	}
	open := map[int]bool{} // open on at least one address
	openOn := map[string]bool{}
	var services []string
	closed, filtered, noRoute := 0, 0, 0
	for _, p := range r.Ports {
		switch p.State {
		case "open":
			if !open[p.Port] {
				services = append(services, p.Service+" ("+strconv.Itoa(p.Port)+")")
			}
			open[p.Port] = true
			openOn[net.JoinHostPort(p.Address, strconv.Itoa(p.Port))] = true
		case "closed":
			closed++
		case "no route":
			noRoute++
		default:
			filtered++
		}
	}
	// lacking lists the addresses on which none of ports is open: a site open
	// over IPv6 only still fails for most visitors.
	lacking := func(ports ...int) string {
		var out []string
		for _, a := range r.Addresses {
			if !slices.ContainsFunc(ports, func(p int) bool { return openOn[net.JoinHostPort(a, strconv.Itoa(p))] }) {
				out = append(out, a)
			}
		}
		return strings.Join(out, " and ")
	}
	addrs := strings.Join(r.Addresses, " and ")
	if len(open) == 0 {
		msg := "None of the probed ports on " + addrs + " accepted a connection"
		rec := "Check that the server is up and that its firewall allows these services."
		switch {
		case filtered == 0 && noRoute == 0:
			msg += "; every one actively refused, so the server is up but nothing is listening."
			rec = "Check that the web, mail and other services are running on the server."
		case closed == 0 && filtered == 0:
			msg += ": this network has no route to it."
			rec = "Your own connection may lack a route (e.g. no IPv6); re-run from another network."
		default:
			msg += " (" + strconv.Itoa(closed) + " refused, " + strconv.Itoa(filtered) + " got no answer, " + strconv.Itoa(noRoute) + " had no route from this network)."
		}
		return []Finding{{Code: "hosting_reachability_unreachable", Severity: "critical",
			Title: "Host unreachable", Message: msg, Recommendation: rec}}
	}

	var out []Finding
	if noWeb, noTLS := lacking(80, 443), lacking(443); noWeb != "" {
		out = append(out, Finding{Code: "hosting_reachability_web_closed", Severity: "warning",
			Title:          "Web ports closed",
			Message:        "Neither HTTP (80) nor HTTPS (443) is open on " + noWeb + ", so a website there won't load.",
			Recommendation: "If this server should host a site, check the web server is running and the firewall allows 80 and 443."})
	} else if noTLS != "" {
		out = append(out, Finding{Code: "hosting_reachability_no_https", Severity: "warning",
			Title:          "No HTTPS",
			Message:        "HTTP (80) is open but HTTPS (443) is not on " + noTLS + ", so visitors can't load the site securely.",
			Recommendation: "Enable HTTPS on the web server (e.g. a free Let's Encrypt certificate) and open port 443."})
	}
	if noSMTP := lacking(25); noSMTP != "" {
		msg := "SMTP (25) did not accept a connection on " + noSMTP + ", so this server can't receive mail directly. Many ISPs and networks block outbound port 25, so the cause may be your own network rather than the server."
		if open[587] || open[465] {
			msg += " Mail submission is open, so the server does run mail."
		}
		out = append(out, Finding{Code: "hosting_reachability_smtp_closed", Severity: "info",
			Title: "SMTP port closed", Message: msg,
			Recommendation: "If this server should receive mail, re-run from another network before changing anything on the server."})
	}
	var dbs []string
	for _, p := range databasePorts {
		if open[p] {
			i := slices.IndexFunc(r.Ports, func(x portProbe) bool { return x.Port == p })
			dbs = append(dbs, r.Ports[i].Service+" ("+strconv.Itoa(p)+")")
		}
	}
	if len(dbs) > 0 {
		out = append(out, Finding{Code: "hosting_reachability_database_exposed", Severity: "warning",
			Title:          "Database open to the internet",
			Message:        strings.Join(dbs, ", ") + " accepts connections from anywhere, which invites brute-force and exploit attempts.",
			Recommendation: "Firewall database ports to the hosts that need them, or bind the database to localhost."})
	}
	return append(out, Finding{Code: "hosting_reachability_reachable", Severity: "ok",
		Title: "Reachable", Message: addrs + " answers on " + strings.Join(services, ", ") + "."})
}
