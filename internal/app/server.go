package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Net is every network capability a Check may use. Checks never reach the
// network any other way, so tests can point them at local fakes.
type Net struct {
	Resolver string // host:port of the DNS resolver
}

type Config struct {
	Version      string
	DataDir      string
	Net          Net
	CheckTimeout time.Duration // default 15s
	UI           fs.FS         // built frontend; nil serves a placeholder
}

type check struct {
	key   string
	kinds []string // Target kinds it applies to
	auto  bool     // runs when a Target of a matching kind is added
	run   func(ctx context.Context, n Net, target string) (any, error)
}

var checks = []check{
	{key: "dns_lookup", kinds: []string{kindDomain, kindHostname}, auto: true, run: dnsLookup},
}

// checksFor lists the keys of the Checks that apply to a Target kind.
func checksFor(kind string) []string {
	keys := []string{}
	for _, c := range checks {
		if slices.Contains(c.kinds, kind) {
			keys = append(keys, c.key)
		}
	}
	return keys
}

type Server struct {
	cfg    Config
	store  *store
	events *broker
	ctx    context.Context
	cancel context.CancelFunc
	steps  sync.WaitGroup
}

func New(cfg Config) (*Server, error) {
	if cfg.CheckTimeout == 0 {
		cfg.CheckTimeout = 15 * time.Second
	}
	st, err := openStore(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if err := st.failRunning(); err != nil {
		return nil, err
	}
	if err := st.classifyTargets(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, store: st, events: newBroker(), ctx: ctx, cancel: cancel}, nil
}

// Close cancels running Steps, waits for them to be recorded, and closes the store.
func (s *Server) Close() error {
	s.cancel()
	s.steps.Wait()
	return s.store.db.Close()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cases", s.listCases)
	mux.HandleFunc("POST /api/cases", s.createCase)
	mux.HandleFunc("GET /api/cases/{id}", s.getCase)
	mux.HandleFunc("PATCH /api/cases/{id}", s.editCase)
	mux.HandleFunc("POST /api/cases/{id}/targets", s.addTarget)
	mux.HandleFunc("POST /api/cases/{id}/steps", s.runCheck)
	mux.HandleFunc("GET /api/active", s.getActive)
	mux.HandleFunc("PUT /api/active", s.setActive)
	mux.HandleFunc("GET /api/events", s.events.serve)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.cfg.Version})
	})
	if s.cfg.UI != nil {
		mux.Handle("/", http.FileServerFS(s.cfg.UI))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, "<!doctype html><title>Stackwell</title><p>UI not built.</p>")
		})
	}
	return mux
}

// createCase starts a Case from the Target the rep typed and makes it active.
func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
	var body struct{ Target string }
	if !decode(w, r, &body) {
		return
	}
	value, kind, err := parseTarget(body.Target)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.store.createCase(value, kind)
	if err == nil {
		err = s.runAuto(id, value, kind)
	}
	s.respondCase(w, http.StatusCreated, id, err)
}

func (s *Server) addTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	var body struct{ Target string }
	if !ok || !decode(w, r, &body) {
		return
	}
	value, kind, err := parseTarget(body.Target)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	added, err := s.store.addTarget(id, value, kind)
	if err == nil && added {
		err = s.runAuto(id, value, kind)
	}
	s.respondCase(w, http.StatusOK, id, err)
}

// runCheck runs a Check on one of the Case's Targets: the first run, or a
// re-run that adds a new Step beside the earlier ones.
func (s *Server) runCheck(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	var body struct{ Check, Target string }
	if !ok || !decode(w, r, &body) {
		return
	}
	i := slices.IndexFunc(checks, func(c check) bool { return c.key == body.Check })
	if i == -1 {
		httpError(w, http.StatusBadRequest, "no such check: "+body.Check)
		return
	}
	targets, err := s.store.targets(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	t := slices.IndexFunc(targets, func(t Target) bool { return t.Value == body.Target })
	if t == -1 {
		httpError(w, http.StatusBadRequest, body.Target+" is not a Target of this Case")
		return
	}
	if !slices.Contains(targets[t].Checks, body.Check) {
		httpError(w, http.StatusBadRequest, body.Check+" does not apply to "+targets[t].Kind+" Targets")
		return
	}
	s.respondCase(w, http.StatusOK, id, s.runStep(id, checks[i], body.Target))
}

func (s *Server) editCase(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	var e caseEdit
	if !ok || !decode(w, r, &e) {
		return
	}
	for _, f := range []*string{e.Title, e.TicketRef} {
		if f != nil {
			*f = strings.TrimSpace(*f)
		}
	}
	if e.Status != nil && *e.Status != "open" && *e.Status != "resolved" {
		httpError(w, http.StatusBadRequest, `status must be "open" or "resolved"`)
		return
	}
	s.respondCase(w, http.StatusOK, id, s.store.editCase(id, e))
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	if id, ok := s.caseID(w, r); ok {
		s.respondCase(w, http.StatusOK, id, nil)
	}
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.recentCases(50)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cs == nil {
		cs = []Case{}
	}
	writeJSON(w, http.StatusOK, cs)
}

// getActive returns {"case": Case} or {"case": null} when no Case is active.
func (s *Server) getActive(w http.ResponseWriter, r *http.Request) {
	id, err := s.store.activeCase()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if id == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"case": nil})
		return
	}
	c, err := s.store.getCase(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": c})
}

// setActive switches Cases ({"case_id": n}) or clears the active Case
// ({"case_id": null}) so the next Target typed starts a new one.
func (s *Server) setActive(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CaseID *int64 `json:"case_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	var id int64
	if body.CaseID != nil {
		id = *body.CaseID
	}
	if err := s.store.setActive(id); errors.Is(err, sql.ErrNoRows) {
		httpError(w, http.StatusNotFound, "no such case")
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.getActive(w, r)
}

// runAuto runs the automatic Checks that apply to a newly added Target.
func (s *Server) runAuto(caseID int64, value, kind string) error {
	for _, c := range checks {
		if c.auto && slices.Contains(c.kinds, kind) {
			if err := s.runStep(caseID, c, value); err != nil {
				return err
			}
		}
	}
	return nil
}

// caseID reads the {id} path value, answering 404 itself if no such Case exists.
func (s *Server) caseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || !s.store.caseExists(id) {
		httpError(w, http.StatusNotFound, "no such case")
		return 0, false
	}
	return id, true
}

// respondCase answers with the Case as it now stands, or with err.
func (s *Server) respondCase(w http.ResponseWriter, code int, id int64, err error) {
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c, err := s.store.getCase(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, code, c)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

// runStep records a running Step and executes the Check in the background,
// publishing the Step when it starts and when it finishes.
func (s *Server) runStep(caseID int64, c check, target string) error {
	st, err := s.store.startStep(caseID, c.key, target)
	if err != nil {
		return err
	}
	s.events.publish(caseID, st)
	s.steps.Go(func() {
		ctx, cancel := context.WithTimeout(s.ctx, s.cfg.CheckTimeout)
		defer cancel()
		result, runErr := c.run(ctx, s.cfg.Net, target)
		if err := s.store.finishStep(&st, result, runErr); err != nil {
			st.Status, st.Error = "failed", "could not save result: "+err.Error()
		}
		if st.Status == "ok" {
			if prev, ok := s.store.previousOK(caseID, c.key, target, st.ID); ok {
				st.ComparedTo, st.Changes = prev.ID, diffResults(prev.Result, st.Result)
			}
		}
		s.events.publish(caseID, st)
	})
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
