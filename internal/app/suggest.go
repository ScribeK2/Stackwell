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
	Value    string `json:"value"`
	Kind     string `json:"kind"`
	Reason   string `json:"reason"`             // e.g. "Mail server for example.com"
	From     int64  `json:"from"`               // the Step it came from
	Evidence int64  `json:"evidence,omitempty"` // or the Evidence it came from
}

// caseSuggestions draws suggestions from the same latest runs as Findings,
// minus the Case's own Targets and anything the rep dismissed.
func caseSuggestions(steps []Step, targets []Target, evidence []Evidence, dismissed []string) []Suggestion {
	skip := slices.Clone(dismissed)
	for _, t := range targets {
		skip = append(skip, t.Value)
	}
	out := []Suggestion{}
	add := func(s Suggestion) {
		value, kind, err := parseTarget(s.Value)
		if err != nil || slices.Contains(skip, value) {
			return
		}
		skip = append(skip, value)
		s.Value, s.Kind = value, kind
		out = append(out, s)
	}
	for _, st := range latestSteps(steps) {
		c := checkByKey(st.Check)
		if st.Status != "ok" || c == nil || c.suggest == nil {
			continue
		}
		for _, s := range c.suggest(st.Target, st.Options, st.Result) {
			s.From = st.ID
			add(s)
		}
	}
	for _, s := range evidenceSuggestions(evidence) {
		add(s)
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
