package app

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

var dnsLookupTypes = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS, dns.TypeTXT, dns.TypeSOA, dns.TypeCAA}

type dnsLookupResult struct {
	Rcode   string              `json:"rcode"` // NOERROR or NXDOMAIN: whether the name exists
	Records map[string][]string `json:"records"`
	Errors  map[string]string   `json:"errors,omitempty"` // record type → why that query failed
}

// dnsLookup queries every record type concurrently against the injected resolver.
// NXDOMAIN is a valid answer, not a failure. A failed query for one type is
// reported under Errors; the Step fails only if no query got an answer.
func dnsLookup(ctx context.Context, n Net, target string) (any, error) {
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
		if ctx.Err() != nil {
			return nil, errors.New("timed out waiting for DNS resolver " + n.Resolver)
		}
		return nil, errors.New("no answer from DNS resolver " + n.Resolver + ": " + res.Errors["A"])
	}
	return res, nil
}
