package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
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
	key string
	run func(ctx context.Context, n Net, target string) (any, error)
}

var dnsLookupCheck = check{key: "dns_lookup", run: dnsLookup}

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
	mux.HandleFunc("POST /api/cases", s.createCase)
	mux.HandleFunc("GET /api/cases/{id}", s.getCase)
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

func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
	var body struct{ Target string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	target := strings.TrimSpace(body.Target)
	if target == "" {
		httpError(w, http.StatusBadRequest, "target is required")
		return
	}
	id, err := s.store.createCase(target)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.runStep(id, dnsLookupCheck, target); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c, err := s.store.getCase(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusNotFound, "no such case")
		return
	}
	c, err := s.store.getCase(id)
	if errors.Is(err, sql.ErrNoRows) {
		httpError(w, http.StatusNotFound, "no such case")
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
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
