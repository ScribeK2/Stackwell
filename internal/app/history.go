package app

import (
	"net/http"
	"slices"
	"strings"
	"time"
)

// listCases lists Cases, most recently active first. Resolved Cases are left
// out unless ?resolved=1; a search (?q=) looks through all of them.
func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	includeResolved := r.URL.Query().Get("resolved") == "1" || q != ""
	limit := listLimit
	if q != "" {
		limit = searchLimit
	}
	cs, err := s.store.recentCases(limit, includeResolved)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if q == "" {
		writeJSON(w, http.StatusOK, cs)
		return
	}
	found := []Case{}
	for _, c := range cs {
		if by, err := s.matches(c, strings.ToLower(q)); err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		} else if by != "" {
			c.MatchedBy = by
			found = append(found, c)
		}
	}
	writeJSON(w, http.StatusOK, found)
}

const (
	listLimit = 50
	// ponytail: search reads up to this many Cases, deriving Findings for
	// each; index Findings in the database if histories grow far past it.
	searchLimit = 1000
)

// matches says why a Case matches a lower-cased query: its title, Ticket
// reference, a Target, or one of its current Findings; "" if it doesn't.
func (s *Server) matches(c Case, q string) (string, error) {
	switch {
	case strings.Contains(strings.ToLower(c.TicketRef), q):
		return "Ticket " + c.TicketRef, nil
	case strings.Contains(strings.ToLower(c.Title), q):
		return "Title: " + c.Title, nil
	}
	for _, t := range c.Targets {
		if strings.Contains(t.Value, q) {
			return "Target " + t.Value, nil
		}
	}
	full, err := s.store.getCase(c.ID)
	if err != nil {
		return "", err
	}
	for _, f := range full.Findings {
		if strings.Contains(strings.ToLower(f.Title+" "+f.Message+" "+f.Code), q) {
			return "Finding: " + f.Title + " (" + f.Target + ")", nil
		}
	}
	return "", nil
}

// purgeCases deletes Cases not active for older_than_days, with everything
// they own. Without confirm it only reports how many it would delete.
func (s *Server) purgeCases(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OlderThanDays int    `json:"older_than_days"`
		Confirm       bool   `json:"confirm"`
		Cutoff        string `json:"cutoff"` // from the preview, so confirm deletes what it counted
	}
	if !decode(w, r, &body) {
		return
	}
	if body.OlderThanDays < 1 {
		httpError(w, http.StatusBadRequest, "older_than_days must be at least 1")
		return
	}
	cutoff := time.Now().Add(-time.Duration(body.OlderThanDays) * 24 * time.Hour)
	if body.Confirm && body.Cutoff != "" {
		t, err := time.Parse(time.RFC3339Nano, body.Cutoff)
		if err != nil {
			httpError(w, http.StatusBadRequest, "cutoff must be the one the preview returned")
			return
		}
		cutoff = t
	}
	ids, err := s.store.inactiveSince(cutoff)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Never the Case open on screen, however old.
	if active, err := s.store.activeCase(); err == nil && active != 0 {
		ids = slices.DeleteFunc(ids, func(id int64) bool { return id == active })
	}
	if !body.Confirm {
		writeJSON(w, http.StatusOK, map[string]any{"would_delete": len(ids), "cutoff": cutoff.UTC().Format(time.RFC3339Nano)})
		return
	}
	if err := s.store.deleteCases(ids); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": len(ids)})
}
