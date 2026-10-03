package app

import (
	"net/url"
	"slices"
	"strings"
)

// Suggestion is a Target that a Step's result points to (an MX host, an
// address, a redirect destination), offered to the rep but never added to
// the Case until they accept it.
type Suggestion struct {
	Value  string `json:"value"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"` // e.g. "Mail server for example.com"
	From   int64  `json:"from"`   // the Step it came from
}

// caseSuggestions draws suggestions from the same latest runs as Findings,
// minus the Case's own Targets and anything the rep dismissed.
func caseSuggestions(steps []Step, targets []Target, dismissed []string) []Suggestion {
	skip := slices.Clone(dismissed)
	for _, t := range targets {
		skip = append(skip, t.Value)
	}
	out := []Suggestion{}
	for _, st := range latestSteps(steps) {
		c := checkByKey(st.Check)
		if st.Status != "ok" || c == nil || c.suggest == nil {
			continue
		}
		for _, s := range c.suggest(st.Target, st.Options, st.Result) {
			value, kind, err := parseTarget(s.Value)
			if err != nil || slices.Contains(skip, value) {
				continue
			}
			skip = append(skip, value)
			out = append(out, Suggestion{Value: value, Kind: kind, Reason: s.Reason, From: st.ID})
		}
	}
	return out
}

// urlHost is the host of a URL, or "" if it has none.
func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
