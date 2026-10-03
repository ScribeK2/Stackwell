package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

// secretStore keeps API keys and passwords. The database records only which
// secrets exist and a masked hint; values live here.
type secretStore interface {
	get(name string) (string, error)
	set(name, value string) error
	remove(name string) error
	backend() string  // "keyring" or "file"
	location() string // where the values are, to show the rep
}

// openSecrets prefers the system keyring (Secret Service over D-Bus) when
// tryKeyring is set and one answers; otherwise a file only the rep can read.
func openSecrets(configDir string, tryKeyring bool) secretStore {
	if tryKeyring && keyringWorks() {
		return keyringSecrets{}
	}
	return &fileSecrets{path: filepath.Join(configDir, "secrets.json")}
}

const keyringService = "stackwell"

// keyringWorks looks up a key that doesn't exist: a working keyring answers
// "not found", anything else means it isn't usable. Read-only, so nothing is
// left behind. A missing D-Bus or Secret Service fails fast; a keyring that
// blocks (e.g. on an unlock prompt) gets a few seconds before the file is used.
func keyringWorks() bool {
	ok := make(chan bool, 1)
	go func() {
		_, err := keyring.Get(keyringService, "__stackwell_probe__")
		ok <- errors.Is(err, keyring.ErrNotFound)
	}()
	select {
	case r := <-ok:
		return r
	case <-time.After(3 * time.Second):
		return false
	}
}

type keyringSecrets struct{}

func (keyringSecrets) get(name string) (string, error) { return keyring.Get(keyringService, name) }
func (keyringSecrets) set(name, value string) error    { return keyring.Set(keyringService, name, value) }
func (keyringSecrets) remove(name string) error {
	if err := keyring.Delete(keyringService, name); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}
func (keyringSecrets) backend() string  { return "keyring" }
func (keyringSecrets) location() string { return "System keyring (Secret Service)" }

// fileSecrets is a JSON file with mode 0600 in a 0700 directory: the same
// protection as ~/.ssh. Encrypting it with a key kept beside it would add
// nothing.
type fileSecrets struct {
	path string
	mu   sync.Mutex
}

func (f *fileSecrets) read() (map[string]string, error) {
	m := map[string]string{}
	b, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	return m, json.Unmarshal(b, &m)
}

// write replaces the file atomically, never leaving it readable by others.
func (f *fileSecrets) write(m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".secrets-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.path)
}

func (f *fileSecrets) get(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.read()
	if err != nil {
		return "", err
	}
	v, ok := m[name]
	if !ok {
		return "", errors.New("no such secret: " + name)
	}
	return v, nil
}

func (f *fileSecrets) set(name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.read()
	if err != nil {
		return err
	}
	m[name] = value
	return f.write(m)
}

func (f *fileSecrets) remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.read()
	if err != nil {
		return err
	}
	delete(m, name)
	return f.write(m)
}

func (f *fileSecrets) backend() string  { return "file" }
func (f *fileSecrets) location() string { return f.path }

// secretHint shows the last four characters of a long secret, enough to tell
// keys apart; a short one shows nothing.
func secretHint(v string) string {
	r := []rune(v)
	if len(r) < 12 {
		return "••••"
	}
	return "••••" + string(r[len(r)-4:])
}

var secretName = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

type secretView struct {
	Name    string `json:"name"`
	Hint    string `json:"hint"`
	Backend string `json:"backend"` // where its value was saved
	// Available is false when it was saved in the other backend (the keyring
	// was unavailable at this start, or --no-keyring changed): its value is
	// out of reach until that backend is back, or it is saved again.
	Available bool `json:"available"`
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	names, err := s.store.secrets()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range names {
		names[i].Available = names[i].Backend == s.secrets.backend()
	}
	dir, err := s.store.setting("playbook_dir")
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secrets_backend":  s.secrets.backend(),
		"secrets_location": s.secrets.location(),
		"secrets":          names,
		"playbook_dir":     dir,
	})
}

// putSettings changes plain settings: the team Playbook folder ("" clears it).
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PlaybookDir *string `json:"playbook_dir"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.PlaybookDir != nil {
		dir := strings.TrimSpace(*body.PlaybookDir)
		if dir != "" {
			if !filepath.IsAbs(dir) {
				httpError(w, http.StatusBadRequest, "use the folder's full path")
				return
			}
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				httpError(w, http.StatusBadRequest, dir+" is not a folder")
				return
			}
		}
		if err := s.store.setSetting("playbook_dir", dir); err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.reloadPlaybooks(); err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.getSettings(w, r)
}

// putSecret stores a value; it is never sent back, only its hint.
func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct{ Value string }
	if !secretName.MatchString(name) {
		httpError(w, http.StatusBadRequest, "secret names use a–z, 0–9 and _")
		return
	}
	if !decode(w, r, &body) {
		return
	}
	value := strings.TrimSpace(body.Value)
	if value == "" {
		httpError(w, http.StatusBadRequest, "a secret can't be empty")
		return
	}
	if err := s.secrets.set(name, value); err != nil {
		httpError(w, http.StatusInternalServerError, "could not store the secret: "+err.Error())
		return
	}
	if err := s.store.setSecret(name, secretHint(value), s.secrets.backend()); err != nil {
		s.secrets.remove(name) // never leave a value the app can't list or delete
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.getSettings(w, r)
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	names, err := s.store.secrets()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	known := false
	for _, n := range names {
		known = known || n.Name == name
	}
	if !known {
		httpError(w, http.StatusNotFound, "no such secret")
		return
	}
	if err := s.secrets.remove(name); err != nil {
		httpError(w, http.StatusInternalServerError, "could not remove the secret: "+err.Error())
		return
	}
	if err := s.store.deleteSecret(name); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.getSettings(w, r)
}
