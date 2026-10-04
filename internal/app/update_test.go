package app_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type updateView struct {
	Current     string `json:"current"`
	Latest      string `json:"latest"`
	Available   bool   `json:"available"`
	CanInstall  bool   `json:"can_install"`
	DownloadURL string `json:"download_url"`
	Error       string `json:"error"`
}

// fakeRelease serves a GitHub-style latest-release document and its assets.
type fakeRelease struct {
	URL      string
	apiHits  atomic.Int32
	appimage []byte
	sums     string
}

func newFakeRelease(t *testing.T, version string, appimage []byte, badSum bool) *fakeRelease {
	f := &fakeRelease{appimage: appimage}
	name := "Stackwell-" + version + "-x86_64.AppImage"
	sum := sha256.Sum256(appimage)
	hexSum := hex.EncodeToString(sum[:])
	if badSum {
		hexSum = hex.EncodeToString(make([]byte, 32))
	}
	f.sums = hexSum + "  " + name + "\n"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			f.apiHits.Add(1)
			fmt.Fprintf(w, `{"tag_name": "v%s", "html_url": "%s/releases/tag/v%s", "assets": [
				{"name": %q, "browser_download_url": "%s/download/%s"},
				{"name": "SHA256SUMS", "browser_download_url": "%s/download/SHA256SUMS"}]}`,
				version, srv.URL, version, name, srv.URL, name, srv.URL)
		case "/download/" + name:
			w.Write(f.appimage)
		case "/download/SHA256SUMS":
			w.Write([]byte(f.sums))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	f.URL = srv.URL + "/releases/latest"
	return f
}

// installedAppImage is the "running" AppImage file the updater replaces.
func installedAppImage(t *testing.T) string {
	dir := t.TempDir()
	path := filepath.Join(dir, "Stackwell.AppImage")
	if err := os.WriteFile(path, []byte("old build"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

type restarts struct {
	mu    sync.Mutex
	paths []string
}

func (r *restarts) restart(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, path)
}

func (r *restarts) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

func TestANewerReleaseIsOffered(t *testing.T) {
	rel := newFakeRelease(t, "1.3.0", []byte("new build"), false)
	h := start(t, app.Config{Version: "1.2.0", UpdateURL: rel.URL, AppImagePath: installedAppImage(t)})
	var u updateView
	h.do("GET", "/api/update", nil, &u)
	if !u.Available || u.Current != "1.2.0" || u.Latest != "1.3.0" || !u.CanInstall || u.DownloadURL == "" {
		t.Fatalf("update = %+v", u)
	}
}

func TestNoUpdateWhenAlreadyCurrentOrADevBuild(t *testing.T) {
	rel := newFakeRelease(t, "1.2.0", []byte("x"), false)
	for _, current := range []string{"1.2.0", "1.10.0", "dev"} {
		h := start(t, app.Config{Version: current, UpdateURL: rel.URL})
		var u updateView
		h.do("GET", "/api/update", nil, &u)
		if u.Available {
			t.Errorf("running %s, offered %s", current, u.Latest)
		}
	}
}

func TestTheReleaseIsCheckedAtMostOnceADay(t *testing.T) {
	rel := newFakeRelease(t, "1.3.0", []byte("x"), false)
	dir := t.TempDir()
	h := start(t, app.Config{DataDir: dir, Version: "1.2.0", UpdateURL: rel.URL})
	for range 3 {
		h.do("GET", "/api/update", nil, nil)
	}
	h.stop()
	h2 := start(t, app.Config{DataDir: dir, Version: "1.2.0", UpdateURL: rel.URL})
	var u updateView
	h2.do("GET", "/api/update", nil, &u)
	if n := rel.apiHits.Load(); n != 1 || !u.Available {
		t.Fatalf("release endpoint hit %d times across reads and a restart; update = %+v", n, u)
	}
}

func TestInstallVerifiesSwapsAndRestarts(t *testing.T) {
	newBuild := []byte("the new build, version 1.3.0")
	rel := newFakeRelease(t, "1.3.0", newBuild, false)
	path := installedAppImage(t)
	var r restarts
	h := start(t, app.Config{Version: "1.2.0", UpdateURL: rel.URL, AppImagePath: path, Restart: r.restart})
	h.do("GET", "/api/update", nil, nil)

	if code := h.do("POST", "/api/update/install", nil, nil); code != http.StatusOK {
		t.Fatalf("install: %d", code)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(newBuild) {
		t.Fatalf("AppImage now holds %q", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("new AppImage isn't executable: %v", info.Mode())
	}
	deadline := time.Now().Add(2 * time.Second)
	for r.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.count() != 1 || r.paths[0] != path {
		t.Fatalf("restarted with %v", r.paths)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("leftover files beside the AppImage: %v", entries)
	}
}

func TestABadChecksumReplacesNothing(t *testing.T) {
	rel := newFakeRelease(t, "1.3.0", []byte("tampered"), true)
	path := installedAppImage(t)
	var r restarts
	h := start(t, app.Config{Version: "1.2.0", UpdateURL: rel.URL, AppImagePath: path, Restart: r.restart})
	h.do("GET", "/api/update", nil, nil)
	var body struct{ Error string }
	if code := h.do("POST", "/api/update/install", nil, &body); code != http.StatusBadGateway || body.Error == "" {
		t.Fatalf("install with a bad checksum: %d %q", code, body.Error)
	}
	if got, _ := os.ReadFile(path); string(got) != "old build" {
		t.Fatalf("AppImage was replaced: %q", got)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("leftover download: %v", entries)
	}
	time.Sleep(50 * time.Millisecond)
	if r.count() != 0 {
		t.Fatal("restarted after a refused update")
	}
}

func TestAnAppImageThatCantBeReplacedGetsADownloadLink(t *testing.T) {
	rel := newFakeRelease(t, "1.3.0", []byte("new"), false)
	path := installedAppImage(t)
	os.Chmod(filepath.Dir(path), 0o555)
	t.Cleanup(func() { os.Chmod(filepath.Dir(path), 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	for _, cfg := range []app.Config{
		{Version: "1.2.0", UpdateURL: rel.URL, AppImagePath: path}, // read-only folder
		{Version: "1.2.0", UpdateURL: rel.URL},                     // not running as an AppImage
	} {
		h := start(t, cfg)
		var u updateView
		h.do("GET", "/api/update", nil, &u)
		if !u.Available || u.CanInstall || u.DownloadURL == "" {
			t.Fatalf("update = %+v", u)
		}
		var body struct {
			DownloadURL string `json:"download_url"`
		}
		if code := h.do("POST", "/api/update/install", nil, &body); code != http.StatusConflict || body.DownloadURL == "" {
			t.Fatalf("install: %d %+v", code, body)
		}
	}
	if got, _ := os.ReadFile(path); string(got) != "old build" {
		t.Fatalf("AppImage changed: %q", got)
	}
}

func TestAnUnreachableReleaseServerIsReportedNotFatal(t *testing.T) {
	h := start(t, app.Config{Version: "1.2.0", UpdateURL: "http://127.0.0.1:1/releases/latest"})
	var u updateView
	if code := h.do("GET", "/api/update", nil, &u); code != http.StatusOK || u.Available || u.Error == "" {
		t.Fatalf("update = %d %+v", code, u)
	}
}

func TestAFailedCheckIsRetriedNotKeptForADay(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	good := newFakeRelease(t, "1.3.0", []byte("x"), false)
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "rate limited", http.StatusForbidden)
			return
		}
		http.Redirect(w, r, good.URL, http.StatusFound)
	}))
	t.Cleanup(flaky.Close)
	dir := t.TempDir()
	h := start(t, app.Config{DataDir: dir, Version: "1.2.0", UpdateURL: flaky.URL})
	var u updateView
	h.do("GET", "/api/update", nil, &u)
	if u.Error == "" || u.Available {
		t.Fatalf("first check = %+v", u)
	}
	h.stop()
	fail.Store(false) // e.g. back online
	h2 := start(t, app.Config{DataDir: dir, Version: "1.2.0", UpdateURL: flaky.URL})
	h2.do("GET", "/api/update", nil, &u)
	if !u.Available {
		t.Fatalf("a failed check was kept: %+v", u)
	}
}

func TestAReleaseWithoutChecksumsIsNotOffered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name": "v1.3.0", "html_url": "x", "assets": [{"name": "Stackwell-1.3.0-x86_64.AppImage", "browser_download_url": "x"}]}`)
	}))
	t.Cleanup(srv.Close)
	h := start(t, app.Config{Version: "1.2.0", UpdateURL: srv.URL})
	var u updateView
	h.do("GET", "/api/update", nil, &u)
	if u.Available {
		t.Fatalf("offered an update that can't be verified: %+v", u)
	}
}
