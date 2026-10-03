package app

import (
	"slices"
	"strconv"
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
// per Target and subject options (Option.Subject). Other options don't split:
// the most recent run is the current picture, so a narrower run (SPF only)
// replaces a broader one until the broader one is run again. Earlier Steps
// only feed the before/after history.
func caseFindings(steps []Step, targets []Target) []Finding {
	kinds := map[string]string{}
	for _, t := range targets {
		kinds[t.Value] = t.Kind
	}
	latest := map[[3]string]Step{}
	var order [][3]string
	for _, st := range steps { // id order, so later Steps overwrite earlier ones
		if st.Status == "running" {
			continue
		}
		key := [3]string{st.Check, st.Target, subjectKey(st)}
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
			fs = c.findings(st.Target, kinds[st.Target], st.Options, st.Result)
		}
		for _, f := range fs {
			f.Target, f.Citations = st.Target, []int64{st.ID}
			findings = append(findings, f)
		}
	}
	slices.SortStableFunc(findings, func(a, b Finding) int { return severityRank[a.Severity] - severityRank[b.Severity] })
	return findings
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
