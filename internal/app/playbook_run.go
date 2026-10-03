package app

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// startRun starts a Playbook on one of the Case's Targets.
func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	caseID, ok := s.caseID(w, r)
	var body struct{ Playbook, Target string }
	if !ok || !decode(w, r, &body) {
		return
	}
	if err := s.reloadPlaybooks(); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p := s.playbook(body.Playbook)
	if p == nil {
		httpError(w, http.StatusBadRequest, "no such playbook: "+body.Playbook)
		return
	}
	targets, err := s.store.targets(caseID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	i := slices.IndexFunc(targets, func(t Target) bool { return t.Value == body.Target })
	if i == -1 {
		httpError(w, http.StatusBadRequest, body.Target+" is not a Target of this Case")
		return
	}
	if !slices.Contains(p.Kinds, targets[i].Kind) {
		httpError(w, http.StatusBadRequest, p.Label+" runs on "+strings.Join(p.Kinds, "/")+" Targets, not "+targets[i].Kind)
		return
	}
	runID, err := s.store.createRun(caseID, p, body.Target)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.runsMu.Lock()
	s.running[runID] = cancel
	s.runsMu.Unlock()
	pb := *p // the Playbook as it was when the run started
	wait := s.execute(ctx, caseID, runID, &pb, body.Target)
	s.steps.Go(func() {
		defer cancel()
		skipped := wait()
		status := "done"
		if ctx.Err() != nil {
			status = "cancelled"
		}
		s.store.finishRun(runID, status, skipped)
		s.runsMu.Lock()
		delete(s.running, runID)
		s.runsMu.Unlock()
		if runs, err := s.store.runs(caseID); err == nil {
			for _, r := range runs {
				if r.ID == runID {
					s.events.publishRun(caseID, r)
				}
			}
		}
	})
	s.respondCase(w, http.StatusOK, caseID, nil)
}

// cancelRun stops a running Playbook; its running Steps end as cancelled and
// entries not yet started never start. Cancelling a finished run is a no-op.
func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	caseID, ok := s.caseID(w, r)
	if !ok {
		return
	}
	runID, err := strconv.ParseInt(r.PathValue("run"), 10, 64)
	owner, lookupErr := s.store.runCase(runID)
	if err != nil || errors.Is(lookupErr, sql.ErrNoRows) || owner != caseID {
		httpError(w, http.StatusNotFound, "no such run")
		return
	}
	s.runsMu.Lock()
	if cancel := s.running[runID]; cancel != nil {
		cancel()
	}
	s.runsMu.Unlock()
	s.respondCase(w, http.StatusOK, caseID, lookupErr)
}

// execute runs every entry of a Playbook, each as soon as the entry it
// depends on has finished, so independent entries run concurrently. It
// returns once the independent entries have started; the returned function
// waits for the rest and reports the entries that were skipped and why.
func (s *Server) execute(ctx context.Context, caseID, runID int64, p *Playbook, target string) func() []skip {
	var (
		mu      sync.Mutex
		skipped []skip
		results = map[string]*Step{} // entry id → its finished Step (nil: skipped)
		done    = map[string]chan struct{}{}
		wg      sync.WaitGroup
	)
	for _, e := range p.Entries {
		done[e.ID] = make(chan struct{})
	}
	skipEntry := func(e PlaybookEntry, reason string) {
		mu.Lock()
		skipped = append(skipped, skip{Entry: e.ID, Reason: reason})
		mu.Unlock()
	}
	// Entries with nothing to wait for start right away, before the request
	// that started the run returns; the rest start as their dependency ends.
	started := map[string]<-chan Step{}
	for _, e := range p.Entries {
		if e.DependsOn != "" {
			continue
		}
		finished, err := s.runStep(ctx, caseID, *checkByKey(e.Check), target, e.Options, runID)
		if err != nil {
			skipEntry(e, "could not start: "+err.Error())
			continue
		}
		started[e.ID] = finished
	}
	for _, e := range p.Entries {
		wg.Go(func() {
			defer close(done[e.ID])
			if finished, ok := started[e.ID]; ok {
				st := <-finished
				mu.Lock()
				results[e.ID] = &st
				mu.Unlock()
				return
			}
			if e.DependsOn == "" {
				return // could not start; already recorded as skipped
			}
			on := target
			select {
			case <-done[e.DependsOn]:
			case <-ctx.Done():
				return
			}
			mu.Lock()
			dep := results[e.DependsOn]
			mu.Unlock()
			switch {
			case dep == nil:
				skipEntry(e, e.DependsOn+" didn't run")
				return
			case dep.Status != "ok":
				skipEntry(e, checkLabel(dep.Check)+" did not complete")
				return
			}
			if e.Target != "" {
				derived, why := targetResolvers[e.Target].resolve(dep.Result)
				if derived == "" {
					skipEntry(e, why)
					return
				}
				value, kind, err := parseTarget(derived)
				if err != nil || !slices.Contains(checkByKey(e.Check).kinds, kind) {
					skipEntry(e, checkLabel(e.Check)+" can't run on "+derived)
					return
				}
				// The Playbook adds what it derives, like a rep accepting a
				// suggestion: the new Target's own auto Checks run too, as
				// ordinary Steps outside this run.
				if added, err := s.store.addTarget(caseID, value, kind); err == nil && added {
					s.runAuto(caseID, value, kind)
				}
				on = value
			}
			if ctx.Err() != nil {
				return
			}
			finished, err := s.runStep(ctx, caseID, *checkByKey(e.Check), on, e.Options, runID)
			if err != nil {
				skipEntry(e, "could not start: "+err.Error())
				return
			}
			st := <-finished
			mu.Lock()
			results[e.ID] = &st
			mu.Unlock()
		})
	}
	return func() []skip {
		wg.Wait()
		return skipped
	}
}
