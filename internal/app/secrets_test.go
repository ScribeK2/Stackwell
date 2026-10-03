package app_test

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type settingsView struct {
	SecretsBackend  string `json:"secrets_backend"`
	SecretsLocation string `json:"secrets_location"`
	Secrets         []struct {
		Name      string `json:"name"`
		Hint      string `json:"hint"`
		Backend   string `json:"backend"`
		Available bool   `json:"available"`
	} `json:"secrets"`
}

// rawGET returns a response body as text, to prove what it does not contain.
func (h *harness) rawGET(path string) string {
	h.t.Helper()
	resp, err := http.Get(h.web.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

const apiKey = "ipinfo-live-9f8e7d6c5b4a3210"

func TestSecretsAreKeptInAFileOnlyTheRepCanRead(t *testing.T) {
	data, conf := t.TempDir(), t.TempDir()
	h := start(t, app.Config{DataDir: data, ConfigDir: conf, Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})

	var s settingsView
	h.do("GET", "/api/settings", nil, &s)
	if s.SecretsBackend != "file" || !strings.HasPrefix(s.SecretsLocation, conf) || len(s.Secrets) != 0 {
		t.Fatalf("settings = %+v", s)
	}

	if code := h.do("PUT", "/api/settings/secrets/ipinfo_token", map[string]string{"value": apiKey}, &s); code != http.StatusOK {
		t.Fatalf("put: %d", code)
	}
	if len(s.Secrets) != 1 || s.Secrets[0].Name != "ipinfo_token" || s.Secrets[0].Hint != "••••3210" ||
		s.Secrets[0].Backend != "file" || !s.Secrets[0].Available {
		t.Fatalf("after put: %+v", s.Secrets)
	}
	if body := h.rawGET("/api/settings"); strings.Contains(body, apiKey) {
		t.Fatal("the API returned a secret's value")
	}

	info, err := os.Stat(s.SecretsLocation)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secrets file %s: %v %v", s.SecretsLocation, info, err)
	}
	if b, _ := os.ReadFile(filepath.Join(data, "stackwell.db")); bytes.Contains(b, []byte(apiKey)) {
		t.Fatal("a secret's value was written to the database")
	}

	// It survives a restart, and can be replaced and removed.
	h.stop()
	h2 := start(t, app.Config{DataDir: data, ConfigDir: conf, Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	h2.do("GET", "/api/settings", nil, &s)
	if len(s.Secrets) != 1 || s.Secrets[0].Hint != "••••3210" {
		t.Fatalf("after restart: %+v", s.Secrets)
	}
	h2.do("PUT", "/api/settings/secrets/ipinfo_token", map[string]string{"value": "pässwörd-ünïcödé"}, &s)
	if s.Secrets[0].Hint != "••••cödé" {
		t.Fatalf("a non-ASCII secret's hint was cut mid-character: %q", s.Secrets[0].Hint)
	}
	h2.do("PUT", "/api/settings/secrets/ipinfo_token", map[string]string{"value": "short"}, &s)
	if s.Secrets[0].Hint != "••••" {
		t.Fatalf("a short secret's hint gives too much away: %q", s.Secrets[0].Hint)
	}
	if code := h2.do("DELETE", "/api/settings/secrets/ipinfo_token", nil, &s); code != http.StatusOK || len(s.Secrets) != 0 {
		t.Fatalf("delete: %d %+v", code, s.Secrets)
	}
	if b, _ := os.ReadFile(s.SecretsLocation); bytes.Contains(b, []byte("short")) {
		t.Fatal("a deleted secret is still in the file")
	}
}

func TestBadSecretsAreRejected(t *testing.T) {
	h := start(t, app.Config{ConfigDir: t.TempDir(), Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	for _, tc := range []struct{ name, value string }{
		{"ipinfo_token", "   "},
		{"Bad%20Name", "x"},
	} {
		if code := h.do("PUT", "/api/settings/secrets/"+tc.name, map[string]string{"value": tc.value}, nil); code != http.StatusBadRequest {
			t.Errorf("%q=%q: %d", tc.name, tc.value, code)
		}
	}
	// A path that tries to climb out never reaches the store at all.
	h.do("PUT", "/api/settings/secrets/../escape", map[string]string{"value": "x"}, nil)
	var s settingsView
	h.do("GET", "/api/settings", nil, &s)
	if len(s.Secrets) != 0 {
		t.Errorf("bad requests stored secrets: %+v", s.Secrets)
	}
	if code := h.do("DELETE", "/api/settings/secrets/never_set", nil, nil); code != http.StatusNotFound {
		t.Errorf("deleting an unknown secret: %d", code)
	}
}
