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
	Citations      []int64 `json:"citations"`          // Steps it came from
	Evidence       []int64 `json:"evidence,omitempty"` // or Evidence it came from
}

var severityRank = map[string]int{"critical": 0, "warning": 1, "info": 2, "ok": 3}

// caseFindings derives Findings from the latest finished Step of each Check
// per Target and subject options (Option.Subject). Other options don't split:
// the most recent run is the current picture, so a narrower run (SPF only)
// replaces a broader one until the broader one is run again. Earlier Steps
// only feed the before/after history.
func caseFindings(steps []Step, targets []Target, evidence []Evidence) []Finding {
	kinds := map[string]string{}
	for _, t := range targets {
		kinds[t.Value] = t.Kind
	}
	findings := []Finding{}
	latest := latestSteps(steps)
	for _, st := range latest {
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
	findings = append(findings, evidenceFindings(evidence)...)
	p := picture{latest: latest, Targets: targets, Evidence: evidence}
	for _, rule := range connectedRules {
		findings = append(findings, rule(p)...)
	}
	slices.SortStableFunc(findings, func(a, b Finding) int { return severityRank[a.Severity] - severityRank[b.Severity] })
	return findings
}

// A connected rule draws Findings from the Case as a whole: several Steps,
// possibly on different Targets, and Evidence. Each Finding it returns sets
// its own Target and cites everything it used.
type connectedRule func(p picture) []Finding

// connectedRules is the registry; each rule registers itself from its own
// file's init, like Checks.
var connectedRules []connectedRule

func registerRule(r connectedRule) { connectedRules = append(connectedRules, r) }

// picture is the Case's current state as connected rules see it.
type picture struct {
	latest   []Step // latestSteps: the latest finished Step per Check, Target and subject
	Targets  []Target
	Evidence []Evidence
}

// step returns the latest Step of check on target if it succeeded. A failed
// latest run means the Case has no current answer, even if an earlier run
// succeeded.
func (p picture) step(check, target string) *Step {
	for i := len(p.latest) - 1; i >= 0; i-- {
		if s := p.latest[i]; s.Check == check && s.Target == target {
			if s.Status != "ok" {
				return nil
			}
			return &p.latest[i]
		}
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// latestSteps returns, in first-run order, the latest finished Step of each
// Check per Target and subject options (Option.Subject): the current picture
// that Findings and suggestions are drawn from.
func latestSteps(steps []Step) []Step {
	latest := map[[3]string]Step{}
	var order [][3]string
	for _, st := range steps { // id order, so later Steps overwrite earlier ones
		if st.Status == "running" || st.Status == "cancelled" {
			continue // not a result: never replaces the last real run
		}
		key := [3]string{st.Check, st.Target, subjectKey(st)}
		if _, seen := latest[key]; !seen {
			order = append(order, key)
		}
		latest[key] = st
	}
	out := make([]Step, len(order))
	for i, key := range order {
		out[i] = latest[key]
	}
	return out
}
