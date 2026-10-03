package app

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

// Change is one field that differs between a Step and the previous Step of
// the same Check on the same Target.
type Change struct {
	Field   string   `json:"field"` // dotted path into the result, e.g. records.MX
	Removed []string `json:"removed,omitempty"`
	Added   []string `json:"added,omitempty"`
}

// diffResults compares two Check results field by field. Lists are compared
// as sets, so a resolver returning the same answers in another order is not a
// change. It works on any Check's result without Check-specific code.
func diffResults(prev, cur json.RawMessage) []Change {
	before, after := flatten(prev), flatten(cur)
	fields := map[string]bool{}
	for f := range before {
		fields[f] = true
	}
	for f := range after {
		fields[f] = true
	}
	changes := []Change{}
	for f := range fields {
		c := Change{Field: f, Removed: minus(before[f], after[f]), Added: minus(after[f], before[f])}
		if c.Removed != nil || c.Added != nil {
			changes = append(changes, c)
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Field < changes[j].Field })
	return changes
}

// minus returns the values of a not in b, in a's order.
func minus(a, b []string) []string {
	var out []string
	for _, v := range a {
		if !slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

func flatten(raw json.RawMessage) map[string][]string {
	out := map[string][]string{}
	var v any
	if json.Unmarshal(raw, &v) == nil {
		walk(v, "", out)
	}
	return out
}

func walk(v any, path string, out map[string][]string) {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walk(child, p, out)
		}
	case []any:
		for _, item := range v {
			out[path] = append(out[path], scalar(item))
		}
	case nil:
	default:
		out[path] = append(out[path], scalar(v))
	}
}

func scalar(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
