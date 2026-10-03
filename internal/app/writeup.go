package app

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A Write-up is built only from the Case: Targets, Findings, Steps, runs and
// Rep notes. Secrets are never part of a Case, so they can't reach it.

// style renders a Write-up in Markdown or plain text from the same content.
type style struct{ md bool }

func (s style) title(t string) string {
	if s.md {
		return "# " + t
	}
	return t + "\n" + strings.Repeat("=", len([]rune(t)))
}

func (s style) heading(h string) string {
	if s.md {
		return "## " + h
	}
	return strings.ToUpper(h)
}

func (s style) bold(t string) string {
	if s.md {
		return "**" + t + "**"
	}
	return t
}

func (s style) code(t string) string {
	if s.md {
		return "`" + t + "`"
	}
	return t
}

func (s style) italic(t string) string {
	if s.md {
		return "_" + t + "_"
	}
	return t
}

func clockTime(t time.Time) string { return t.Local().Format("15:04") }

func (s *Server) writeup(c Case, st style) string {
	var b strings.Builder
	line := func(parts ...string) { b.WriteString(strings.Join(parts, "") + "\n") }

	line(st.title(caseName(c)))
	line()
	var meta []string
	if c.TicketRef != "" {
		meta = append(meta, st.bold("Ticket:")+" "+c.TicketRef)
	}
	meta = append(meta, st.bold("Status:")+" "+strings.ToUpper(c.Status[:1])+c.Status[1:])
	var targets []string
	for _, t := range c.Targets {
		targets = append(targets, t.Value+" ("+t.Kind+")")
	}
	meta = append(meta, st.bold("Targets:")+" "+strings.Join(targets, ", "))
	if st.md {
		line(strings.Join(meta, " · "))
	} else {
		for _, m := range meta {
			line(m)
		}
	}

	var problems, fine []Finding
	for _, f := range c.Findings {
		if f.Severity == "ok" {
			fine = append(fine, f)
		} else {
			problems = append(problems, f)
		}
	}
	line()
	line(st.heading("Findings"))
	line()
	if len(problems) == 0 {
		line("No problems found.")
	}
	for _, f := range problems {
		entry := "- " + st.bold(strings.ToUpper(f.Severity[:1])+f.Severity[1:]) + " — " + f.Title + " (" + f.Target + "): " + f.Message
		if f.Recommendation != "" {
			entry += " → " + f.Recommendation
		}
		line(entry)
	}
	if len(fine) > 0 {
		var titles []string
		for _, f := range fine {
			titles = append(titles, f.Title+" ("+f.Target+")")
		}
		line()
		line(st.bold("Looks fine:") + " " + strings.Join(titles, ", "))
	}

	if changes := s.changeLines(c, st); len(changes) > 0 {
		line()
		line(st.heading("Changes"))
		line()
		for _, ch := range changes {
			line("- " + ch)
		}
	}

	var boundary []string
	for _, r := range c.Runs {
		for _, n := range r.Boundary {
			if !slices.Contains(boundary, n) {
				boundary = append(boundary, n)
			}
		}
	}
	if len(boundary) > 0 {
		line()
		line(st.heading("Not visible from here"))
		line()
		for _, n := range boundary {
			line("- " + n)
		}
	}

	if strings.TrimSpace(c.Notes) != "" {
		line()
		line(st.heading("Notes"))
		line()
		line(strings.TrimSpace(c.Notes))
	}

	line()
	by := "Stackwell"
	if s.cfg.Version != "" {
		by += " " + s.cfg.Version
	}
	line(st.italic("Checked with " + by + ", " + time.Now().Local().Format("2006-01-02 15:04 MST")))
	return b.String()
}

// changeLines describes, for each Check's latest run that was compared with an
// earlier one, what changed between them and which problems it resolved.
func (s *Server) changeLines(c Case, st style) []string {
	byID := map[int64]Step{}
	for _, step := range c.Steps {
		byID[step.ID] = step
	}
	kinds := map[string]string{}
	for _, t := range c.Targets {
		kinds[t.Value] = t.Kind
	}
	var out []string
	for _, step := range latestSteps(c.Steps) {
		prev, ok := byID[step.ComparedTo]
		if step.Status != "ok" || !ok {
			continue
		}
		span := clockTime(prev.StartedAt) + " → " + clockTime(step.StartedAt)
		when := " (" + span + ")"
		if len(step.Changes) > 0 {
			var parts []string
			for _, ch := range step.Changes {
				parts = append(parts, changeText(ch, st))
			}
			out = append(out, st.bold(checkLabel(step.Check))+" on "+step.Target+when+": "+strings.Join(parts, "; "))
		}
		before := stepFindings(prev, kinds[prev.Target])
		after := stepFindings(step, kinds[step.Target])
		for _, f := range before {
			if f.Severity != "ok" && !slices.ContainsFunc(after, func(a Finding) bool { return a.Code == f.Code }) {
				out = append(out, "Resolved: "+f.Title+" ("+step.Target+", "+span+")")
			}
		}
	}
	return out
}

func changeText(ch Change, st style) string {
	label := ch.Field
	if f, ok := strings.CutPrefix(label, "records."); ok {
		label = f
	}
	quote := func(vs []string) string {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = st.code(v)
		}
		return strings.Join(out, ", ")
	}
	switch {
	case len(ch.Removed) > 0 && len(ch.Added) > 0:
		return label + ": " + quote(ch.Removed) + " → " + quote(ch.Added)
	case len(ch.Added) > 0:
		return label + ": added " + quote(ch.Added)
	default:
		return label + ": removed " + quote(ch.Removed)
	}
}

// stepFindings applies a Check's rules to one Step on its own.
func stepFindings(st Step, kind string) []Finding {
	if c := checkByKey(st.Check); c != nil && c.findings != nil && st.Status == "ok" {
		return c.findings(st.Target, kind, st.Options, st.Result)
	}
	return nil
}

// stepText is one Step on its own, as plain text: what ran, when, and its
// result field by field.
func stepText(st Step) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s on %s at %s: %s\n", checkLabel(st.Check), st.Target, st.StartedAt.Local().Format("2006-01-02 15:04"), st.Status)
	if st.Status == "failed" {
		b.WriteString(st.Error + "\n")
		return b.String()
	}
	fields := flatten(st.Result)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		label, _ := strings.CutPrefix(k, "records.")
		fmt.Fprintf(&b, "%s: %s\n", label, strings.Join(fields[k], ", "))
	}
	return b.String()
}

func (s *Server) getWriteup(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format != "markdown" && format != "text" && format != "" {
		httpError(w, http.StatusBadRequest, "format is markdown or text")
		return
	}
	c, err := s.store.getCase(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": s.writeup(c, style{md: format != "text"})})
}

func (s *Server) getStepText(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	if !ok {
		return
	}
	stepID, _ := strconv.ParseInt(r.PathValue("step"), 10, 64)
	c, err := s.store.getCase(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	i := slices.IndexFunc(c.Steps, func(st Step) bool { return st.ID == stepID })
	if i == -1 {
		httpError(w, http.StatusNotFound, "no such step")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": stepText(c.Steps[i])})
}

// caseName is the Case's title, or its first Target, as the UI names it.
func caseName(c Case) string {
	if c.Title != "" {
		return c.Title
	}
	if len(c.Targets) > 0 {
		return c.Targets[0].Value
	}
	return "Case #" + strconv.FormatInt(c.ID, 10)
}
