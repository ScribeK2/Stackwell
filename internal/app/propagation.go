package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// PublicResolver is one of the worldwide resolvers DNS Propagation compares.
type PublicResolver struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Address  string `json:"address"` // host:port
}

// Bundled reference data: well-known open resolvers in different regions.
var defaultPublicResolvers = []PublicResolver{
	{"Google", "Global anycast", "8.8.8.8:53"},
	{"Cloudflare", "Global anycast", "1.1.1.1:53"},
	{"Quad9", "Global anycast", "9.9.9.9:53"},
	{"OpenDNS", "United States", "208.67.222.222:53"},
	{"Level3", "United States", "4.2.2.2:53"},
	{"DNS.SB", "Germany", "185.222.222.222:53"},
	{"AdGuard", "Cyprus", "94.140.14.14:53"},
	{"Yandex", "Russia", "77.88.8.8:53"},
	{"114DNS", "China", "114.114.114.114:53"},
	{"CleanBrowsing", "Netherlands", "185.228.168.9:53"},
}

var propagationScopes = map[string][]string{
	"all":  {"A", "AAAA", "CNAME", "MX", "NS", "TXT"},
	"mail": {"MX", "TXT", "NS"},
	"web":  {"A", "AAAA", "CNAME"},
}

func init() {
	registerCheck(check{
		key:      "dns_propagation",
		label:    "DNS Propagation",
		kinds:    []string{kindDomain, kindHostname},
		options:  []Option{{Key: "scope", Label: "Records", Choices: []string{"all", "mail", "web"}, Default: "all"}},
		run:      dnsPropagation,
		findings: propagationFindings,
	})
}

type resolverAnswer struct {
	PublicResolver
	Rcode   string              `json:"rcode,omitempty"` // NOERROR or NXDOMAIN
	Answers map[string][]string `json:"answers"`
	Failed  []string            `json:"failed,omitempty"` // types this resolver couldn't answer
	Error   string              `json:"error,omitempty"`  // it answered nothing at all
}

type propagationResult struct {
	Types     []string         `json:"types"`
	Resolvers []resolverAnswer `json:"resolvers"`
	// Types on which answering resolvers differ, plus "existence" when some
	// say the name exists and others say NXDOMAIN.
	Disagree []string `json:"disagree"`
}

// dnsPropagation asks every public resolver for the same records and reports
// where they disagree, i.e. where a change has not reached everyone yet.
func dnsPropagation(ctx context.Context, n Net, target string, opts map[string]string) (any, error) {
	resolvers := n.PublicResolvers
	if resolvers == nil {
		resolvers = defaultPublicResolvers
	}
	res := propagationResult{Types: propagationScopes[opts["scope"]], Resolvers: make([]resolverAnswer, len(resolvers)), Disagree: []string{}}
	var wg sync.WaitGroup
	for i, r := range resolvers {
		wg.Go(func() {
			// A resolver that answers nothing at all is unreachable, not "no records".
			out, _ := dnsLookup(ctx, Net{Resolver: r.Address}, target, nil)
			ra := resolverAnswer{PublicResolver: r, Answers: map[string][]string{}}
			if l, ok := out.(dnsLookupResult); ok {
				ra.Rcode = l.Rcode
				for _, t := range res.Types {
					if _, failed := l.Errors[t]; failed {
						ra.Failed = append(ra.Failed, t)
					} else if len(l.Records[t]) > 0 {
						vals := slices.Clone(l.Records[t])
						slices.Sort(vals)
						ra.Answers[t] = vals
					}
				}
			} else {
				ra.Error = "no answer"
			}
			res.Resolvers[i] = ra
		})
	}
	wg.Wait()

	answered := slices.DeleteFunc(slices.Clone(res.Resolvers), func(r resolverAnswer) bool { return r.Error != "" })
	if len(answered) == 0 {
		return nil, errors.New("none of the public resolvers answered; outbound DNS may be blocked on this network")
	}
	// differs reports whether the answering resolvers (minus any skipped) disagree on v.
	differs := func(skip func(resolverAnswer) bool, v func(resolverAnswer) string) bool {
		var first *string
		for _, r := range answered {
			if skip(r) {
				continue
			}
			x := v(r)
			if first == nil {
				first = &x
			} else if *first != x {
				return true
			}
		}
		return false
	}
	never := func(resolverAnswer) bool { return false }
	if differs(never, func(r resolverAnswer) string { return r.Rcode }) {
		res.Disagree = append(res.Disagree, "existence")
	}
	for _, t := range res.Types {
		failed := func(r resolverAnswer) bool { return slices.Contains(r.Failed, t) }
		if differs(failed, func(r resolverAnswer) string { return strings.Join(r.Answers[t], "\n") }) {
			res.Disagree = append(res.Disagree, t)
		}
	}
	return res, nil
}

func propagationFindings(target, _ string, _ map[string]string, raw json.RawMessage) []Finding {
	var r propagationResult
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	var down []string
	answered, missing := 0, 0
	for _, a := range r.Resolvers {
		switch {
		case a.Error != "":
			down = append(down, a.Name)
		case a.Rcode == "NXDOMAIN":
			answered++
			missing++
		default:
			answered++
		}
	}
	var out []Finding
	if len(down) > 0 {
		out = append(out, Finding{Code: "dns_propagation_unreachable", Severity: "info",
			Title:   "Some resolvers didn't answer",
			Message: strings.Join(down, ", ") + " did not respond, so they are left out of the comparison."})
	}
	if missing == answered {
		return append(out, Finding{Code: "dns_propagation_nxdomain", Severity: "warning",
			Title:          "Exists on no resolver",
			Message:        "Every resolver that answered says " + target + " does not exist (NXDOMAIN).",
			Recommendation: "Check the spelling and the domain's registration and delegation; there is nothing to propagate yet."})
	}
	var records, addrs []string
	for _, t := range r.Disagree {
		switch t {
		case "A", "AAAA":
			addrs = append(addrs, t)
		case "existence":
			records = append(records, "whether the name exists")
		default:
			records = append(records, t)
		}
	}
	if len(records) > 0 {
		out = append(out, Finding{Code: "dns_propagation_mismatch", Severity: "warning",
			Title:          "Not yet propagated",
			Message:        "Resolvers around the world disagree on " + strings.Join(records, ", ") + ", so some visitors still see old records.",
			Recommendation: "If the records changed recently, wait out the old TTL and re-run; if not, check for a stale or split nameserver."})
	}
	if len(addrs) > 0 {
		out = append(out, Finding{Code: "dns_propagation_addresses_vary", Severity: "info",
			Title:   "Addresses vary by region",
			Message: strings.Join(addrs, " and ") + " answers differ between resolvers. That is normal for CDNs and geo-DNS; otherwise the change is still propagating."})
	}
	switch {
	case answered < 2:
		out = append(out, Finding{Code: "dns_propagation_insufficient", Severity: "warning",
			Title:          "Too few resolvers answered",
			Message:        "Only one resolver answered, so there is nothing to compare it with.",
			Recommendation: "Re-run; if resolvers keep failing, outbound DNS may be filtered on this network."})
	case len(records) == 0 && len(addrs) == 0:
		out = append(out, Finding{Code: "dns_propagation_consistent", Severity: "ok",
			Title: "Propagated", Message: "All " + strconv.Itoa(answered) + " resolvers that answered agree on " + target + "."})
	}
	return out
}
