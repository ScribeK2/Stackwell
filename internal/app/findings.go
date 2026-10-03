package app

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// Finding is a conclusion drawn from a Case's Steps, citing the Steps it came from.
type Finding struct {
	Code           string  `json:"code"`
	Severity       string  `json:"severity"` // critical | warning | info | ok
	Title          string  `json:"title"`
	Message        string  `json:"message"`
	Recommendation string  `json:"recommendation,omitempty"`
	Target         string  `json:"target"`
	Citations      []int64 `json:"citations"`
}

var severityRank = map[string]int{"critical": 0, "warning": 1, "info": 2, "ok": 3}

// caseFindings derives Findings from the latest finished Step of each Check
// per Target; earlier Steps only feed the before/after history.
func caseFindings(steps []Step, targets []Target) []Finding {
	kinds := map[string]string{}
	for _, t := range targets {
		kinds[t.Value] = t.Kind
	}
	latest := map[[2]string]Step{}
	var order [][2]string
	for _, st := range steps { // id order, so later Steps overwrite earlier ones
		if st.Status == "running" {
			continue
		}
		key := [2]string{st.Check, st.Target}
		if _, seen := latest[key]; !seen {
			order = append(order, key)
		}
		latest[key] = st
	}

	findings := []Finding{}
	for _, key := range order {
		st := latest[key]
		var fs []Finding
		if st.Status == "failed" {
			fs = []Finding{{Code: "check_failed", Severity: "warning",
				Title:          checkLabel(st.Check) + " did not complete",
				Message:        st.Error,
				Recommendation: "Re-run it; if it keeps failing, the network path to the service may be blocked."}}
		} else if c := checkByKey(st.Check); c != nil && c.findings != nil {
			fs = c.findings(st.Target, kinds[st.Target], st.Result)
		}
		for _, f := range fs {
			f.Target, f.Citations = st.Target, []int64{st.ID}
			findings = append(findings, f)
		}
	}
	slices.SortStableFunc(findings, func(a, b Finding) int { return severityRank[a.Severity] - severityRank[b.Severity] })
	return findings
}

func checkByKey(key string) *check {
	if i := slices.IndexFunc(checks, func(c check) bool { return c.key == key }); i != -1 {
		return &checks[i]
	}
	return nil
}

func checkLabel(key string) string {
	if c := checkByKey(key); c != nil {
		return c.label
	}
	return key
}

// dnsFindings applies the DNS Lookup rules. Apex rules (MX, NS, CNAME) only
// apply to registrable domains: a hostname such as www needs none of them.
func dnsFindings(target, kind string, raw json.RawMessage) []Finding {
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

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
