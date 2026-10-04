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

type Config struct {
	Version      string
	DataDir      string
	Net          Net
	CheckTimeout time.Duration // default 15s
	UI           fs.FS         // built frontend; nil serves a placeholder
	// PlaybookDir holds the team's Playbooks (*.yaml), which add to or
	// override the built-in ones by name. Empty: built-ins only.
	PlaybookDir string
	// ConfigDir holds the secrets file when the keyring isn't used.
	ConfigDir string
	// TryKeyring stores secrets in the system keyring when one answers.
	TryKeyring bool
}

type Server struct {
	cfg     Config
	store   *store
	events  *broker
	secrets secretStore

	reloadMu       sync.Mutex // serialises reloadPlaybooks
	pbMu           sync.Mutex // guards the three below, reloaded from disk
	playbooks      []Playbook
	playbookErrors []playbookError
	playbookDir    string
	ctx            context.Context
	cancel         context.CancelFunc
	steps          sync.WaitGroup // every running Step and Playbook run

	runsMu  sync.Mutex
	running map[int64]context.CancelFunc // run id → cancel, while it runs
	stepsOn map[int64]context.CancelFunc // step id → cancel, while it runs
}

func New(cfg Config) (*Server, error) {
	if cfg.CheckTimeout == 0 {
		cfg.CheckTimeout = 15 * time.Second
	}
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = cfg.DataDir
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
	s := &Server{cfg: cfg, store: st, events: newBroker(), ctx: ctx, cancel: cancel,
		secrets: openSecrets(cfg.ConfigDir, cfg.TryKeyring),
		running: map[int64]context.CancelFunc{}, stepsOn: map[int64]context.CancelFunc{}}
	if err := s.reloadPlaybooks(); err != nil {
		cancel()
		st.db.Close()
		return nil, err
	}
	return s, nil
}

// Close cancels running Steps, waits for them to be recorded, and closes the store.
func (s *Server) Close() error {
	s.cancel()
	s.steps.Wait()
	return s.store.db.Close()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/checks", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, checkInfos()) })
	mux.HandleFunc("GET /api/cases", s.listCases)
	mux.HandleFunc("POST /api/cases", s.createCase)
	mux.HandleFunc("GET /api/cases/{id}", s.getCase)
	mux.HandleFunc("PATCH /api/cases/{id}", s.editCase)
	mux.HandleFunc("POST /api/cases/{id}/targets", s.addTarget)
	mux.HandleFunc("POST /api/cases/{id}/steps", s.runCheck)
	mux.HandleFunc("POST /api/cases/{id}/steps/all", s.runCheckOnAll)
	mux.HandleFunc("POST /api/cases/{id}/steps/{step}/cancel", s.cancelStep)
	mux.HandleFunc("GET /api/cases/{id}/writeup", s.getWriteup)
	mux.HandleFunc("POST /api/cases/{id}/evidence", s.postEvidence)
	mux.HandleFunc("GET /api/evidence/kinds", evidenceKinds)
	mux.HandleFunc("GET /api/cases/{id}/steps/{step}/text", s.getStepText)
	mux.HandleFunc("POST /api/cases/{id}/suggestions/dismiss", s.dismissSuggestion)
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings/secrets/{name}", s.putSecret)
	mux.HandleFunc("DELETE /api/settings/secrets/{name}", s.deleteSecret)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	mux.HandleFunc("GET /api/playbooks", s.listPlaybooks)
	mux.HandleFunc("POST /api/cases/{id}/runs", s.startRun)
	mux.HandleFunc("POST /api/cases/{id}/runs/{run}/cancel", s.cancelRun)
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
	var body struct {
		Check, Target string
		Options       map[string]string
	}
	if !ok || !decode(w, r, &body) {
		return
	}
	c := checkByKey(body.Check)
	if c == nil {
		httpError(w, http.StatusBadRequest, "no such check: "+body.Check)
		return
	}
	opts, err := c.resolveOptions(body.Options)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
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
	_, err = s.runStep(s.ctx, id, *c, body.Target, opts, 0)
	s.respondCase(w, http.StatusOK, id, err)
}

// dismissSuggestion hides a suggested Target for this Case for good.
func (s *Server) dismissSuggestion(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	var body struct{ Value string }
	if !ok || !decode(w, r, &body) {
		return
	}
	// Normalised like a Target, so it matches the suggestion however it's written.
	value, _, err := parseTarget(body.Value)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.respondCase(w, http.StatusOK, id, s.store.dismiss(id, value))
}

// runCheckOnAll runs one Check on every Target of the Case it applies to.
func (s *Server) runCheckOnAll(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	var body struct {
		Check   string
		Options map[string]string
	}
	if !ok || !decode(w, r, &body) {
		return
	}
	c := checkByKey(body.Check)
	if c == nil {
		httpError(w, http.StatusBadRequest, "no such check: "+body.Check)
		return
	}
	opts, err := c.resolveOptions(body.Options)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	targets, err := s.store.targets(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	applies, ran := 0, 0
	var lastErr error
	for _, t := range targets {
		if !slices.Contains(t.Checks, c.key) {
			continue
		}
		applies++
		// One Target failing to start doesn't stop the others; the Case
		// returned shows which ran, so a retry needn't duplicate them.
		if _, err := s.runStep(s.ctx, id, *c, t.Value, opts, 0); err != nil {
			lastErr = err
			continue
		}
		ran++
	}
	switch {
	case applies == 0:
		httpError(w, http.StatusBadRequest, c.label+" doesn't apply to any Target of this Case")
		return
	case ran == 0:
		httpError(w, http.StatusInternalServerError, "could not start "+c.label+": "+lastErr.Error())
		return
	}
	s.respondCase(w, http.StatusOK, id, nil)
}

// cancelStep stops one running Step; it ends as cancelled. Cancelling a
// finished Step changes nothing.
func (s *Server) cancelStep(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	if !ok {
		return
	}
	stepID, _ := strconv.ParseInt(r.PathValue("step"), 10, 64)
	if owner, err := s.store.stepCase(stepID); err != nil || owner != id {
		httpError(w, http.StatusNotFound, "no such step")
		return
	}
	s.runsMu.Lock()
	if stop := s.stepsOn[stepID]; stop != nil {
		stop()
	}
	s.runsMu.Unlock()
	s.respondCase(w, http.StatusOK, id, nil)
}

func (s *Server) editCase(w http.ResponseWriter, r *http.Request) {
	id, ok := s.caseID(w, r)
	var e caseEdit
	if !ok || !decode(w, r, &e) {
		return
	}
	for _, f := range []*string{e.Title, e.TicketRef, e.Notes} {
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
			opts, _ := c.resolveOptions(nil) // defaults always validate
			if _, err := s.runStep(s.ctx, caseID, c, value, opts, 0); err != nil {
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

// runStep records a running Step and executes the Check in the background
// under parent (the server, or a Playbook run that can be cancelled),
// publishing the Step when it starts and when it finishes. The channel
// delivers the finished Step.
func (s *Server) runStep(parent context.Context, caseID int64, c check, target string, opts map[string]string, runID int64) (<-chan Step, error) {
	st, err := s.store.startStep(caseID, c.key, target, opts, runID)
	if err != nil {
		return nil, err
	}
	s.events.publish(caseID, st)
	// The Step's own switch: the rep can stop just this Step (cancelStep),
	// and stopping its run or the server stops it too.
	stepCtx, stop := context.WithCancel(parent)
	s.runsMu.Lock()
	s.stepsOn[st.ID] = stop
	s.runsMu.Unlock()
	done := make(chan Step, 1)
	s.steps.Go(func() {
		defer func() {
			s.runsMu.Lock()
			delete(s.stepsOn, st.ID)
			s.runsMu.Unlock()
			stop()
		}()
		ctx, cancel := context.WithTimeout(stepCtx, s.cfg.CheckTimeout)
		defer cancel()
		result, runErr := c.run(ctx, s.cfg.Net, target, opts)
		// Cancelled only if it ended because it was stopped (the rep, its run
		// or shutdown), not because it timed out; a result that arrived just
		// before the cancel is still a result.
		cancelled := runErr != nil && stepCtx.Err() != nil
		if err := s.store.finishStep(&st, result, runErr, cancelled); err != nil {
			st.Status, st.Error = "failed", "could not save result: "+err.Error()
		}
		if st.Status == "ok" {
			if prev, ok := s.store.previousOK(caseID, c.key, target, opts, st.ID); ok {
				st.ComparedTo, st.Changes = prev.ID, diffResults(prev.Result, st.Result)
			}
		}
		s.events.publish(caseID, st)
		done <- st
	})
	return done, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
