package app

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dnsbl is one DNS blocklist: a subject is listed when <subject>.<zone> has an A record.
type dnsbl struct {
	Name     string
	Zone     string
	Kind     string // kindIP: queried by reversed IPv4 octets; kindDomain: by domain name
	Severity string // of a listing
	Delist   string
	Note     string // added to a listing's message
}

// Bundled reference data: widely used blocklists.
var dnsbls = []dnsbl{
	{"Spamhaus ZEN", "zen.spamhaus.org", kindIP, "critical", "https://check.spamhaus.org/", ""},
	{"SpamCop", "bl.spamcop.net", kindIP, "critical", "https://www.spamcop.net/bl.shtml", "SpamCop listings expire 24 hours after the last report."},
	{"Barracuda", "b.barracudacentral.org", kindIP, "critical", "https://www.barracudacentral.org/rbl/removal-request", ""},
	{"SORBS", "dnsbl.sorbs.net", kindIP, "warning", "http://www.sorbs.net/delisting/", ""},
	{"PSBL", "psbl.surriel.com", kindIP, "warning", "https://psbl.org/remove", ""},
	{"Mailspike", "bl.mailspike.net", kindIP, "warning", "https://mailspike.org/iplookup.html", ""},
	{"UCEPROTECT Level 1", "dnsbl-1.uceprotect.net", kindIP, "info",
		"https://www.uceprotect.net/en/rblcheck.php",
		"Few providers block on UCEPROTECT; Level 1 entries expire on their own 7 days after the last spam seen, so the paid express delisting is rarely worth it."},
	{"Manitu IX", "ix.dnsbl.manitu.net", kindIP, "warning", "https://www.dnsbl.manitu.net/", ""},
	{"GBUdb Truncate", "truncate.gbudb.net", kindIP, "warning", "https://www.gbudb.com/truncate/", ""},
	{"Spamhaus DBL", "dbl.spamhaus.org", kindDomain, "warning", "https://check.spamhaus.org/", ""},
	{"SURBL", "multi.surbl.org", kindDomain, "warning", "https://surbl.org/surbl-analysis", ""},
}

// zenCodes names the Spamhaus ZEN return codes, i.e. which of its lists matched.
var zenCodes = map[string]string{
	"127.0.0.2": "SBL", "127.0.0.3": "SBL CSS", "127.0.0.4": "XBL", "127.0.0.5": "XBL", "127.0.0.6": "XBL",
	"127.0.0.7": "XBL", "127.0.0.9": "SBL DROP", "127.0.0.10": "PBL", "127.0.0.11": "PBL",
}

const (
	blacklistMaxAddresses = 5
	blacklistParallel     = 10
	blacklistQueryTimeout = 3 * time.Second // well inside the 15s Check timeout, with MX and A lookups before it
)

func init() {
	registerCheck(check{key: "blacklist", label: "Blacklist", kinds: []string{kindIP, kindDomain}, run: blacklist, findings: blacklistFindings})
}

// blVerdict is one blocklist's answer for one subject.
type blVerdict struct {
	Zone   string   `json:"zone"`
	Delist string   `json:"delist"`
	State  string   `json:"state"` // listed | clean | refused | unknown
	Codes  []string `json:"codes,omitempty"`
	Reason string   `json:"reason,omitempty"` // the list's TXT record, when listed
	Error  string   `json:"error,omitempty"`  // why refused or unknown
}

// blSubject is one IPv4 address or domain checked, with every list's verdict by list name.
type blSubject struct {
	Kind   string               `json:"kind"`   // ip | domain
	Source string               `json:"source"` // where it came from: target, MX host, A record
	Lists  map[string]blVerdict `json:"lists"`
}

type blacklistResult struct {
	// Keyed by address or domain, so a re-run diffs per subject and list.
	Subjects map[string]blSubject `json:"subjects"`
	Resolve  string               `json:"resolve,omitempty"` // why the domain's mail host addresses couldn't be found
	IPv6     bool                 `json:"ipv6,omitempty"`    // an IPv6 target: not checked
}

// blacklist checks an IPv4 address, or a domain's mail hosts and the domain
// itself, against the bundled blocklists concurrently.
func blacklist(ctx context.Context, n Net, target string, _ map[string]string) (any, error) {
	res := blacklistResult{Subjects: map[string]blSubject{}}
	if ip, err := netip.ParseAddr(target); err == nil {
		if ip.Is6() {
			res.IPv6 = true
			return res, nil
		}
		res.Subjects[target] = blSubject{Kind: kindIP, Source: "target"}
	} else {
		res.Subjects[target] = blSubject{Kind: kindDomain, Source: "target"}
		addrs, err := mailAddresses(ctx, n, target)
		if err != nil {
			res.Resolve = err.Error()
		}
		for _, a := range addrs {
			if _, dup := res.Subjects[a[0]]; !dup && len(res.Subjects) <= blacklistMaxAddresses {
				res.Subjects[a[0]] = blSubject{Kind: kindIP, Source: a[1]}
			}
		}
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, blacklistParallel)
	)
	for subject, s := range res.Subjects {
		s.Lists = map[string]blVerdict{}
		res.Subjects[subject] = s
		for _, l := range dnsbls {
			if l.Kind != s.Kind {
				continue
			}
			name := subject + "." + l.Zone
			if s.Kind == kindIP {
				o := netip.MustParseAddr(subject).As4()
				name = strings.Join([]string{strconv.Itoa(int(o[3])), strconv.Itoa(int(o[2])), strconv.Itoa(int(o[1])), strconv.Itoa(int(o[0])), l.Zone}, ".")
			}
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				v := queryDNSBL(ctx, n, name)
				v.Zone, v.Delist = l.Zone, l.Delist
				mu.Lock()
				s.Lists[l.Name] = v
				mu.Unlock()
			})
		}
	}
	wg.Wait()
	return res, nil
}

// mailAddresses resolves a domain's MX hosts (or, with no MX, the domain
// itself) to IPv4 addresses, each paired with where it came from.
func mailAddresses(ctx context.Context, n Net, domain string) ([][2]string, error) {
	r, err := blExchange(ctx, n, domain, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, errors.New("MX lookup answered " + dns.RcodeToString[r.Rcode])
	}
	var mxs []*dns.MX
	for _, rr := range r.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			if mx.Mx == "." {
				return nil, errors.New("it publishes a null MX: it accepts no mail")
			}
			mxs = append(mxs, mx)
		}
	}
	slices.SortFunc(mxs, func(a, b *dns.MX) int {
		return cmp.Or(cmp.Compare(a.Preference, b.Preference), cmp.Compare(a.Mx, b.Mx))
	})
	hosts := []string{}
	for _, mx := range mxs {
		hosts = append(hosts, strings.TrimSuffix(mx.Mx, "."))
	}
	source := "MX "
	if len(hosts) == 0 {
		hosts, source = []string{domain}, "A record of "
	}
	// Resolve the hosts concurrently, keeping MX preference order.
	found := make([][][2]string, len(hosts))
	errs := make([]error, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Go(func() {
			r, err := blExchange(ctx, n, h, dns.TypeA)
			if err != nil {
				errs[i] = errors.New(h + ": " + err.Error())
				return
			}
			for _, rr := range r.Answer {
				if a, ok := rr.(*dns.A); ok {
					found[i] = append(found[i], [2]string{a.A.String(), source + h})
				}
			}
		})
	}
	wg.Wait()
	out := slices.Concat(found...)
	if len(out) == 0 {
		return nil, errors.Join(errs...) // nil when the hosts simply have no A records
	}
	return out, nil
}

// queryDNSBL looks name up on a blocklist. NXDOMAIN (or no A record) is clean;
// a 127.0.0.0/8 answer is a listing, except 127.255.255.0/24 and 127.0.0.1,
// which lists (Spamhaus, SURBL) use to refuse the query. A timeout or any other answer leaves the verdict unknown.
func queryDNSBL(ctx context.Context, n Net, name string) blVerdict {
	r, err := blExchange(ctx, n, name, dns.TypeA)
	switch {
	case err != nil:
		return blVerdict{State: "unknown", Error: err.Error()}
	case r.Rcode == dns.RcodeNameError:
		return blVerdict{State: "clean"}
	case r.Rcode != dns.RcodeSuccess:
		return blVerdict{State: "unknown", Error: dns.RcodeToString[r.Rcode]}
	}
	v := blVerdict{State: "clean"}
	for _, rr := range r.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(a.A.To4())
		switch {
		case netip.MustParsePrefix("127.255.255.0/24").Contains(ip), ip == netip.MustParseAddr("127.0.0.1"):
			return blVerdict{State: "refused", Codes: []string{ip.String()}, Error: "the list refused the query (" + ip.String() + ")"}
		case !netip.MustParsePrefix("127.0.0.0/8").Contains(ip):
			// Some resolvers rewrite NXDOMAIN to an ad or block page.
			return blVerdict{State: "unknown", Error: "unexpected answer " + ip.String() + "; the resolver may be rewriting answers"}
		}
		v.State = "listed"
		v.Codes = append(v.Codes, ip.String())
	}
	if v.State == "listed" {
		slices.Sort(v.Codes)
		if t, err := blExchange(ctx, n, name, dns.TypeTXT); err == nil {
			for _, rr := range t.Answer {
				if txt, ok := rr.(*dns.TXT); ok && v.Reason == "" {
					v.Reason = strings.Join(txt.Txt, "")
				}
			}
		}
	}
	return v
}

// blExchange sends one query to the resolver, retrying over TCP when truncated.
func blExchange(ctx context.Context, n Net, name string, qt uint16) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, blacklistQueryTimeout)
	defer cancel()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	r, _, err := (&dns.Client{}).ExchangeContext(ctx, m, n.Resolver)
	if err == nil && r.Truncated {
		r, _, err = (&dns.Client{Net: "tcp"}).ExchangeContext(ctx, m, n.Resolver)
	}
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return r, err
}

func blacklistFindings(target, _ string, _ map[string]string, raw json.RawMessage) []Finding {
	var r blacklistResult
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	if r.IPv6 {
		return []Finding{{Code: "blacklist_ipv6", Severity: "info",
			Title:          "IPv6 not checked",
			Message:        "DNS blocklist coverage for IPv6 is limited, so " + target + " was not checked. This is not a clean result.",
			Recommendation: "Check the sending IPv4 address instead, or look the address up on the providers' own websites."}}
	}
	var out []Finding
	addresses, answered := 0, 0
	var refused, unknown []string
	clean := map[string]bool{} // lists that answered for at least one subject
	for _, subject := range slices.Sorted(maps.Keys(r.Subjects)) {
		s := r.Subjects[subject]
		if s.Kind == kindIP {
			addresses++
		}
		about := subject
		if s.Source != "target" {
			about += " (" + s.Source + ")"
		}
		for _, l := range dnsbls {
			v, ok := s.Lists[l.Name]
			if !ok {
				continue
			}
			switch v.State {
			case "listed":
				answered++
				msg := about + " is listed on " + l.Name + " (" + l.Zone + ", " + strings.Join(v.Codes, ", ")
				if l.Zone == "zen.spamhaus.org" {
					var parts []string
					for _, c := range v.Codes {
						if p := zenCodes[c]; p != "" && !slices.Contains(parts, p) {
							parts = append(parts, p)
						}
					}
					if len(parts) > 0 {
						msg += ": " + strings.Join(parts, ", ")
					}
				}
				msg += ")."
				if v.Reason != "" {
					msg += " Reason given: " + v.Reason
				}
				if l.Note != "" {
					msg += " " + l.Note
				}
				out = append(out, Finding{Code: "blacklist_listed", Severity: l.Severity,
					Title:          subject + " listed on " + l.Name,
					Message:        msg,
					Recommendation: "Find and stop the cause (a compromised account, open relay or bulk sending), then request removal at " + l.Delist + "."})
			case "clean":
				answered++
				clean[l.Name] = true
			case "refused":
				refused = append(refused, l.Name)
			default:
				unknown = append(unknown, l.Name+" for "+subject)
			}
		}
	}
	if len(r.Subjects) == 1 && addresses == 0 {
		msg := "No IPv4 mail host addresses were found for " + target + ", so only domain blocklists were checked."
		if r.Resolve != "" {
			msg = "Could not look up " + target + "'s mail hosts (" + r.Resolve + "), so only domain blocklists were checked."
		}
		out = append(out, Finding{Code: "blacklist_no_addresses", Severity: "warning",
			Title:          "No addresses to check",
			Message:        msg,
			Recommendation: "Check the domain's MX and A records, or run this Check on the sending IP directly."})
	}
	if len(refused) > 0 {
		slices.Sort(refused)
		refused = slices.Compact(refused)
		out = append(out, Finding{Code: "blacklist_refused", Severity: "info",
			Title:          "Some blocklists refused to answer",
			Message:        strings.Join(refused, ", ") + " refused the query, so those results are unknown, not clean. Spamhaus blocks queries that arrive through public resolvers such as 8.8.8.8 or 1.1.1.1.",
			Recommendation: "Re-run from a network whose DNS resolver is not a public one, or check the address on the list's own website."})
	}
	if len(unknown) > 0 {
		sev := "info"
		if answered == 0 {
			sev = "warning"
		}
		out = append(out, Finding{Code: "blacklist_unknown", Severity: sev,
			Title:          "Some blocklists didn't answer",
			Message:        "No verdict from " + strings.Join(unknown, ", ") + ".",
			Recommendation: "Re-run; if lists keep timing out, outbound DNS may be filtered on this network."})
	}
	if answered > 0 && !slices.ContainsFunc(out, func(f Finding) bool { return f.Code == "blacklist_listed" }) {
		what := plural(addresses, "address", "addresses")
		if addresses < len(r.Subjects) {
			what += " and the domain"
		}
		out = append(out, Finding{Code: "blacklist_clean", Severity: "ok",
			Title:   "Not listed",
			Message: "Checked " + what + " against " + plural(len(clean), "list", "lists") + "; none lists them."})
	}
	return out
}
