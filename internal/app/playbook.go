package app

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"go.yaml.in/yaml/v3"
)

// Playbook is a named, data-defined sequence of Checks run against one Target
// of a Case, with Boundary notes (ADR-0002). Defaults are embedded; a team's
// folder can add or override them by name.
type Playbook struct {
	Name        string          `yaml:"name" json:"name"`
	Label       string          `yaml:"label" json:"label"`
	Description string          `yaml:"description" json:"description,omitempty"`
	Kinds       []string        `yaml:"kinds" json:"kinds"` // Target kinds it runs on
	Entries     []PlaybookEntry `yaml:"entries" json:"entries"`
	Boundary    []string        `yaml:"boundary" json:"boundary"`
	Source      string          `yaml:"-" json:"source"` // "built-in" or the file it came from
}

// PlaybookEntry is one Check in a Playbook. With depends_on it waits for that
// entry; with target it runs on a Target derived from that entry's result
// (see targetResolvers) instead of the Playbook's Target.
type PlaybookEntry struct {
	ID        string            `yaml:"id" json:"id"` // defaults to the Check key
	Check     string            `yaml:"check" json:"check"`
	Options   map[string]string `yaml:"options" json:"options,omitempty"`
	DependsOn string            `yaml:"depends_on" json:"depends_on,omitempty"`
	Target    string            `yaml:"target" json:"target,omitempty"`
}

// targetResolver derives a Target from one Check's result. It returns the
// value, or "" and the reason there is none.
type targetResolver struct {
	from    string // the Check whose result it reads
	resolve func(raw json.RawMessage) (value, reason string)
}

var targetResolvers = map[string]targetResolver{
	"primary_mx_host": {from: "dns_lookup", resolve: func(raw json.RawMessage) (string, string) {
		var r dnsLookupResult
		json.Unmarshal(raw, &r)
		best, pref := "", -1
		for _, mx := range r.Records["MX"] {
			var p int
			var host string
			if _, err := fmt.Sscanf(mx, "%d %s", &p, &host); err == nil && host != "." && (pref == -1 || p < pref) {
				best, pref = host, p
			}
		}
		if best == "" {
			return "", "no MX records to derive a mail server from"
		}
		return best, ""
	}},
	"a_record_ip": {from: "dns_lookup", resolve: func(raw json.RawMessage) (string, string) {
		var r dnsLookupResult
		json.Unmarshal(raw, &r)
		if len(r.Records["A"]) == 0 {
			return "", "no A record to derive an address from"
		}
		return r.Records["A"][0], ""
	}},
}

//go:embed playbooks/*.yaml
var builtinPlaybooks embed.FS

// playbookError is a team Playbook file that couldn't be used, and why.
type playbookError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// loadPlaybooks reads the built-in Playbooks and then any in dir, which win
// by name. A broken built-in is a bug in Stackwell and an error; a broken
// file in the team's folder is reported and skipped, so one bad file never
// takes the others down.
func loadPlaybooks(dir string) ([]Playbook, []playbookError, error) {
	var out []Playbook
	problems := []playbookError{}
	add := func(p Playbook) {
		if i := slices.IndexFunc(out, func(q Playbook) bool { return q.Name == p.Name }); i != -1 {
			out[i] = p
		} else {
			out = append(out, p)
		}
	}
	builtin, _ := fs.Glob(builtinPlaybooks, "playbooks/*.yaml")
	for _, f := range builtin {
		b, _ := builtinPlaybooks.ReadFile(f)
		p, err := parsePlaybook(b)
		if err != nil {
			return nil, nil, fmt.Errorf("built-in playbook %s: %w", f, err)
		}
		p.Source = "built-in"
		add(p)
	}
	if dir == "" {
		return out, problems, nil
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return out, append(problems, playbookError{File: dir, Error: "folder not found"}), nil
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.y*ml"))
	slices.Sort(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err == nil {
			var p Playbook
			if p, err = parsePlaybook(b); err == nil {
				p.Source = f
				add(p)
				continue
			}
		}
		// If the broken file names a built-in, it was meant to replace it:
		// withdraw the built-in rather than quietly run the stock Checks.
		var named struct{ Name string }
		if yaml.Unmarshal(b, &named) == nil && named.Name != "" {
			if i := slices.IndexFunc(out, func(q Playbook) bool { return q.Name == named.Name && q.Source == "built-in" }); i != -1 {
				out = slices.Delete(out, i, i+1)
				err = fmt.Errorf("%w (the built-in %q is unavailable until this file is fixed)", err, named.Name)
			}
		}
		problems = append(problems, playbookError{File: f, Error: err.Error()})
	}
	return out, problems, nil
}

func parsePlaybook(b []byte) (Playbook, error) {
	var p Playbook
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // a typo'd key is an error, not silently ignored
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	return p, p.validate()
}

func (p *Playbook) validate() error {
	if p.Name == "" || p.Label == "" {
		return errors.New("name and label are required")
	}
	if len(p.Kinds) == 0 || len(p.Entries) == 0 {
		return errors.New("kinds and entries are required")
	}
	if p.Boundary == nil {
		p.Boundary = []string{} // optional, but always a list
	}
	for _, k := range p.Kinds {
		if !slices.Contains([]string{kindDomain, kindHostname, kindIP, kindEmail}, k) {
			return fmt.Errorf("unknown kind %q", k)
		}
	}
	byID := map[string]*PlaybookEntry{}
	for i := range p.Entries {
		e := &p.Entries[i]
		if e.ID == "" {
			e.ID = e.Check
		}
		if byID[e.ID] != nil {
			return fmt.Errorf("duplicate entry id %q (give repeated Checks an id)", e.ID)
		}
		byID[e.ID] = e
	}
	for i := range p.Entries {
		e := &p.Entries[i]
		c := checkByKey(e.Check)
		if c == nil {
			return fmt.Errorf("entry %s: no such check %q", e.ID, e.Check)
		}
		opts, err := c.resolveOptions(e.Options)
		if err != nil {
			return fmt.Errorf("entry %s: %w", e.ID, err)
		}
		e.Options = opts
		if e.DependsOn != "" && byID[e.DependsOn] == nil {
			return fmt.Errorf("entry %s depends on unknown entry %q", e.ID, e.DependsOn)
		}
		if e.Target != "" {
			r, ok := targetResolvers[e.Target]
			if !ok {
				return fmt.Errorf("entry %s: no such target %q", e.ID, e.Target)
			}
			if e.DependsOn == "" || byID[e.DependsOn].Check != r.from {
				return fmt.Errorf("entry %s: target %s needs depends_on an entry running %s", e.ID, e.Target, r.from)
			}
			continue // a derived Target's kind is checked when it is derived
		}
		for _, k := range p.Kinds {
			if !slices.Contains(c.kinds, k) {
				return fmt.Errorf("entry %s: %s doesn't apply to %s Targets", e.ID, c.label, k)
			}
		}
	}
	for _, e := range p.Entries { // no cycles: follow each chain
		seen := map[string]bool{}
		for id := e.ID; id != ""; id = byID[id].DependsOn {
			if seen[id] {
				return fmt.Errorf("entries depend on each other in a cycle through %s", id)
			}
			seen[id] = true
		}
	}
	return nil
}

// reloadPlaybooks re-reads the team's folder (Settings, else Config.PlaybookDir),
// so files a team pulls in take effect without a restart.
func (s *Server) reloadPlaybooks() error {
	// One reload at a time, so an older read of the folder never lands last.
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	dir, err := s.store.setting("playbook_dir")
	if err != nil {
		return err
	}
	if dir == "" {
		dir = s.cfg.PlaybookDir
	}
	playbooks, problems, err := loadPlaybooks(dir)
	if err != nil {
		return err
	}
	s.pbMu.Lock()
	s.playbooks, s.playbookErrors, s.playbookDir = playbooks, problems, dir
	s.pbMu.Unlock()
	return nil
}

// playbook returns a copy of the named Playbook as currently loaded, or nil.
func (s *Server) playbook(name string) *Playbook {
	s.pbMu.Lock()
	defer s.pbMu.Unlock()
	if i := slices.IndexFunc(s.playbooks, func(p Playbook) bool { return p.Name == name }); i != -1 {
		p := s.playbooks[i]
		return &p
	}
	return nil
}

func (s *Server) listPlaybooks(w http.ResponseWriter, r *http.Request) {
	if err := s.reloadPlaybooks(); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.pbMu.Lock()
	defer s.pbMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"folder": s.playbookDir, "playbooks": s.playbooks, "errors": s.playbookErrors})
}

// skip records why a Playbook entry didn't run.
type skip struct {
	Entry  string `json:"entry"`
	Reason string `json:"reason"`
}
