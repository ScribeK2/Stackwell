package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

func init() {
	registerCheck(check{key: "dns_lookup", label: "DNS Lookup", kinds: []string{kindDomain, kindHostname}, auto: true, run: dnsLookup, findings: dnsFindings})
}

var dnsLookupTypes = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS, dns.TypeTXT, dns.TypeSOA, dns.TypeCAA}

type dnsLookupResult struct {
	Rcode   string              `json:"rcode"` // NOERROR or NXDOMAIN: whether the name exists
	Records map[string][]string `json:"records"`
	Errors  map[string]string   `json:"errors,omitempty"` // record type → why that query failed
}

// dnsLookup queries every record type concurrently against the injected resolver.
// NXDOMAIN is a valid answer, not a failure. A failed query for one type is
// reported under Errors; the Step fails only if no query got an answer.
func dnsLookup(ctx context.Context, n Net, target string, _ map[string]string) (any, error) {
	name := dns.Fqdn(target)
	res := dnsLookupResult{Rcode: "NOERROR", Records: map[string][]string{}, Errors: map[string]string{}}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		answers int
	)
	udp, tcp := &dns.Client{}, &dns.Client{Net: "tcp"}
	for _, qt := range dnsLookupTypes {
		wg.Go(func() {
			m := new(dns.Msg)
			m.SetQuestion(name, qt)
			m.RecursionDesired = true
			m.SetEdns0(1232, false)
			r, _, err := udp.ExchangeContext(ctx, m, n.Resolver)
			if err == nil && r.Truncated {
				r, _, err = tcp.ExchangeContext(ctx, m, n.Resolver)
			}
			typ := dns.TypeToString[qt]
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Errors[typ] = err.Error()
				return
			}
			answers++
			switch r.Rcode {
			case dns.RcodeSuccess:
			case dns.RcodeNameError:
				res.Rcode = "NXDOMAIN"
			default:
				res.Errors[typ] = dns.RcodeToString[r.Rcode]
			}
			for _, rr := range r.Answer {
				if rr.Header().Rrtype != qt {
					continue // e.g. the CNAME preceding an A answer
				}
				res.Records[typ] = append(res.Records[typ], strings.TrimPrefix(rr.String(), rr.Header().String()))
			}
		})
	}
	wg.Wait()
	if answers == 0 {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("timed out waiting for DNS resolver " + n.Resolver)
		}
		if ctx.Err() != nil {
			return nil, errors.New("cancelled")
		}
		return nil, errors.New("no answer from DNS resolver " + n.Resolver + ": " + res.Errors["A"])
	}
	return res, nil
}

// dnsFindings applies the DNS Lookup rules. Apex rules (MX, NS, CNAME) only
// apply to registrable domains: a hostname such as www needs none of them.
func dnsFindings(target, kind string, _ map[string]string, raw json.RawMessage) []Finding {
	var r dnsLookupResult
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	if r.Rcode == "NXDOMAIN" {
		return []Finding{{Code: "dns_nxdomain", Severity: "critical",
			Title:          "Name does not exist",
			Message:        "The resolver answered NXDOMAIN: " + target + " does not exist in DNS.",
			Recommendation: "Check the spelling, then whether the domain is registered and its nameservers are delegated."}}
	}
	apex := kind == kindDomain
	has := func(t string) bool { return len(r.Records[t]) > 0 }
	// A failed query says nothing about whether records exist.
	known := func(types ...string) bool {
		for _, t := range types {
			if _, failed := r.Errors[t]; failed {
				return false
			}
		}
		return true
	}
	var fs []Finding

	if apex && has("CNAME") {
		fs = append(fs, Finding{Code: "dns_cname_at_apex", Severity: "critical",
			Title:          "CNAME at the zone apex",
			Message:        target + " is a CNAME to " + r.Records["CNAME"][0] + ". A CNAME can't coexist with the NS, SOA and MX records the apex needs.",
			Recommendation: "Replace it with A/AAAA records, or use the DNS host's ALIAS/flattening feature."})
	}
	switch addrs := len(r.Records["A"]) + len(r.Records["AAAA"]); {
	case addrs > 0:
		fs = append(fs, Finding{Code: "dns_resolves", Severity: "ok",
			Title: "Resolves", Message: target + " resolves to " + plural(addrs, "address", "addresses") + "."})
	case !has("CNAME") && known("A", "AAAA", "CNAME"):
		fs = append(fs, Finding{Code: "dns_no_address", Severity: "warning",
			Title:          "No address records",
			Message:        target + " has no A or AAAA records, so websites and other services on it can't be reached.",
			Recommendation: "Add an A (and ideally AAAA) record pointing at the hosting server, if it should serve anything."})
	}
	if apex {
		switch mx := r.Records["MX"]; {
		case len(mx) == 1 && mx[0] == "0 .":
			fs = append(fs, Finding{Code: "dns_null_mx", Severity: "info",
				Title: "Declares no mail", Message: target + " publishes a null MX (RFC 7505): it accepts no email."})
		case len(mx) > 0:
			fs = append(fs, Finding{Code: "dns_mx", Severity: "ok",
				Title: "Mail exchangers set", Message: target + " has " + plural(len(mx), "MX record", "MX records") + "."})
		case known("MX"):
			fs = append(fs, Finding{Code: "dns_no_mx", Severity: "warning",
				Title:          "No MX records",
				Message:        "Mail to " + target + " falls back to its address record, and most senders won't deliver it.",
				Recommendation: "Add MX records for the mail provider, or a null MX (0 .) if the domain sends and receives no mail."})
		}
		if !has("NS") && known("NS") {
			fs = append(fs, Finding{Code: "dns_no_ns", Severity: "critical",
				Title:          "No NS records",
				Message:        "The resolver returned no nameservers for " + target + ".",
				Recommendation: "Check the delegation at the registrar and that the zone exists on the listed nameservers."})
		}
	}
	if len(r.Errors) > 0 {
		var types []string
		for t := range r.Errors {
			types = append(types, t)
		}
		slices.Sort(types)
		fs = append(fs, Finding{Code: "dns_query_errors", Severity: "info",
			Title:   "Some lookups failed",
			Message: "These record types could not be queried, so their absence above is not conclusive: " + strings.Join(types, ", ") + "."})
	}
	return fs
}
