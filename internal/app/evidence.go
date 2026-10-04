package app

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// Evidence is material the rep pasted into a Case (email headers, mail
// logs), kept verbatim. Its analysis is derived on every read by a pure
// analyser, like Findings from Steps, so improving an analyser improves old
// Cases too.
type Evidence struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Raw       string    `json:"raw"`
	Analysis  any       `json:"analysis"`
	CreatedAt time.Time `json:"created_at"`
}

// analyser understands one kind of pasted Evidence. It never touches the
// network: anything worth looking up becomes a Suggested target instead.
type analyser struct {
	kind     string
	label    string
	analyse  func(raw string) (any, error) // an error means it isn't this kind of text
	findings func(analysis any) []Finding
	suggest  func(analysis any) []Suggestion
}

var analysers []analyser

func registerAnalyser(a analyser) { analysers = append(analysers, a) }

func analyserFor(kind string) *analyser {
	for i := range analysers {
		if analysers[i].kind == kind {
			return &analysers[i]
		}
	}
	return nil
}

// evidenceFindings draws Findings from every piece of Evidence, each citing it.
func evidenceFindings(evs []Evidence) []Finding {
	var out []Finding
	for _, e := range evs {
		a := analyserFor(e.Kind)
		if a == nil || e.Analysis == nil || a.findings == nil {
			continue
		}
		for _, f := range a.findings(e.Analysis) {
			f.Citations, f.Evidence = []int64{}, []int64{e.ID}
			out = append(out, f)
		}
	}
	return out
}

func evidenceSuggestions(evs []Evidence) []Suggestion {
	var out []Suggestion
	for _, e := range evs {
		if a := analyserFor(e.Kind); a != nil && e.Analysis != nil && a.suggest != nil {
			for _, s := range a.suggest(e.Analysis) {
				s.Evidence = e.ID
				out = append(out, s)
			}
		}
	}
	return out
}

func readEvidence(q querier, caseID int64) ([]Evidence, error) {
	rows, err := q.Query(`SELECT id, kind, raw, created_at FROM evidence WHERE case_id = ? ORDER BY id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Evidence{}
	for rows.Next() {
		var e Evidence
		var created string
		if err := rows.Scan(&e.ID, &e.Kind, &e.Raw, &created); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if a := analyserFor(e.Kind); a != nil {
			// An analyser that no longer understands old text gives no
			// analysis, rather than an empty one that looks real.
			if analysis, err := a.analyse(e.Raw); err == nil {
				e.Analysis = analysis
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *store) addEvidence(caseID int64, kind, raw string) error {
	defer s.touch(caseID)
	_, err := s.db.Exec(`INSERT INTO evidence (case_id, kind, raw, created_at) VALUES (?, ?, ?, ?)`, caseID, kind, raw, now())
	return err
}

// postEvidence keeps pasted text with the Case if its analyser recognises it.
func (s *Server) postEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	var body struct{ Kind, Raw string }
	if !ok || !decode(w, r, &body) {
		return
	}
	a := analyserFor(body.Kind)
	if a == nil {
		httpError(w, http.StatusBadRequest, "unknown kind of Evidence: "+body.Kind)
		return
	}
	if strings.TrimSpace(body.Raw) == "" {
		httpError(w, http.StatusBadRequest, "nothing was pasted")
		return
	}
	if _, err := a.analyse(body.Raw); err != nil {
		httpError(w, http.StatusBadRequest, "this doesn't look like "+a.label+": "+err.Error())
		return
	}
	s.respondCase(w, http.StatusOK, id, s.store.addEvidence(id, body.Kind, body.Raw))
}

var errNotThisKind = errors.New("no recognisable content")

// evidenceKinds tells the UI what can be pasted.
func evidenceKinds(w http.ResponseWriter, r *http.Request) {
	out := []map[string]string{}
	for _, a := range analysers {
		out = append(out, map[string]string{"kind": a.kind, "label": a.label})
	}
	writeJSON(w, http.StatusOK, out)
}
