package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The updater: check the latest release at most once a day; on request,
// download it, verify it against SHA256SUMS, swap it in for the running
// AppImage and restart.

const (
	updateEvery = 24 * time.Hour   // after a successful check
	retryAfter  = 10 * time.Minute // after a failed one (offline, rate-limited)
)

type release struct {
	Version     string    `json:"version"`
	PageURL     string    `json:"page_url"` // the release page, the fallback for a manual download
	AppImageURL string    `json:"appimage_url"`
	AppImage    string    `json:"appimage"` // its file name, as listed in SHA256SUMS
	SumsURL     string    `json:"sums_url"`
	Error       string    `json:"error,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

type updater struct {
	mu     sync.Mutex
	latest *release
}

// latestRelease returns the newest release, asking the release endpoint at
// most once a day; the last answer (or error) is kept across restarts.
func (s *Server) latestRelease() release {
	s.upd.mu.Lock()
	defer s.upd.mu.Unlock()
	if s.upd.latest == nil {
		if raw, _ := s.store.setting("update_check"); raw != "" {
			var r release
			if json.Unmarshal([]byte(raw), &r) == nil {
				s.upd.latest = &r
			}
		}
	}
	if l := s.upd.latest; l != nil {
		wait := updateEvery
		if l.Error != "" {
			wait = retryAfter
		}
		if time.Since(l.CheckedAt) < wait {
			return *l
		}
	}
	r := s.fetchRelease()
	r.CheckedAt = time.Now().UTC()
	s.upd.latest = &r
	// Only a successful answer is kept across restarts: a failure (offline,
	// rate-limited) is retried at the next start, or in retryAfter.
	if b, err := json.Marshal(r); err == nil && r.Error == "" {
		s.store.setSetting("update_check", string(b))
	}
	return r
}

// updateClient is Net's client, except it honours HTTPS_PROXY and friends:
// Checks bypass proxies to see the real path, but the updater only needs to
// reach GitHub however this network allows.
func (s *Server) updateClient(timeout time.Duration) *http.Client {
	c := s.cfg.Net.HTTPClient()
	c.Transport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	c.Timeout = timeout
	return c
}

func (s *Server) fetchRelease() release {
	client := s.updateClient(10 * time.Second)
	req, _ := http.NewRequest("GET", s.cfg.UpdateURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Stackwell/"+s.cfg.Version)
	resp, err := client.Do(req)
	if err != nil {
		return release{Error: "could not reach the release server: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return release{Error: "the release server answered " + resp.Status}
	}
	var gh struct {
		Tag    string `json:"tag_name"`
		Page   string `json:"html_url"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&gh); err != nil {
		return release{Error: "unreadable release information: " + err.Error()}
	}
	r := release{Version: strings.TrimPrefix(gh.Tag, "v"), PageURL: gh.Page}
	for _, a := range gh.Assets {
		switch {
		case a.Name == "SHA256SUMS":
			r.SumsURL = a.URL
		case strings.HasSuffix(a.Name, "-x86_64.AppImage"):
			r.AppImage, r.AppImageURL = a.Name, a.URL
		}
	}
	return r
}

// installable: a newer release with both an AppImage and the SHA256SUMS to
// verify it. Without checksums it is never offered.
func installable(r release, current string) bool {
	return r.Error == "" && newer(r.Version, current) && r.AppImageURL != "" && r.SumsURL != ""
}

var semver = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// newer reports whether version a is a release newer than b. A build that
// isn't a release (dev) is never offered an update.
func newer(a, b string) bool {
	ma, mb := semver.FindStringSubmatch(a), semver.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// canReplace reports whether this process is an AppImage whose file it may
// replace: the folder must be writable, since the swap is a rename.
func (s *Server) canReplace() bool {
	p := s.cfg.AppImagePath
	return p != "" && syscall.Access(filepath.Dir(p), 2 /* W_OK */) == nil
}

func (s *Server) getUpdate(w http.ResponseWriter, r *http.Request) {
	view := map[string]any{"current": s.cfg.Version, "available": false}
	if s.cfg.UpdateURL == "" {
		writeJSON(w, http.StatusOK, view)
		return
	}
	rel := s.latestRelease()
	view["latest"] = rel.Version
	view["error"] = rel.Error
	view["checked_at"] = rel.CheckedAt
	view["download_url"] = rel.PageURL
	view["available"] = installable(rel, s.cfg.Version)
	view["can_install"] = s.canReplace()
	writeJSON(w, http.StatusOK, view)
}

// installUpdate downloads the new AppImage beside the running one, verifies
// it against SHA256SUMS, and only then renames it over the running file and
// restarts. On any failure the running AppImage is untouched.
func (s *Server) installUpdate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.UpdateURL == "" {
		httpError(w, http.StatusConflict, "updates are not configured for this build")
		return
	}
	rel := s.latestRelease()
	if !installable(rel, s.cfg.Version) {
		httpError(w, http.StatusConflict, "there is no update to install")
		return
	}
	if !s.canReplace() {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":        "Stackwell can't replace its own file here; download the new version instead",
			"download_url": rel.PageURL,
		})
		return
	}
	if err := s.download(rel); err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restarting": s.cfg.Restart != nil, "version": rel.Version})
	if s.cfg.Restart != nil {
		go func() {
			time.Sleep(200 * time.Millisecond) // let the answer reach the browser
			s.cfg.Restart(s.cfg.AppImagePath)
		}()
	}
}

func (s *Server) download(rel release) error {
	client := s.updateClient(10 * time.Minute)

	sums, err := fetch(client, rel.SumsURL, 1<<20)
	if err != nil {
		return fmt.Errorf("could not download SHA256SUMS: %w", err)
	}
	want := ""
	for line := range strings.SplitSeq(string(sums), "\n") {
		if f := strings.Fields(line); len(f) == 2 && strings.TrimPrefix(f[1], "*") == rel.AppImage {
			want = strings.ToLower(f[0])
		}
	}
	if want == "" {
		return errors.New("SHA256SUMS doesn't list " + rel.AppImage)
	}

	dir := filepath.Dir(s.cfg.AppImagePath)
	tmp, err := os.CreateTemp(dir, ".stackwell-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once it has been renamed into place
	resp, err := client.Get(rel.AppImageURL)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("could not download the new version: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		return errors.New("could not download the new version: " + resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 2<<30)); err != nil {
		tmp.Close()
		return fmt.Errorf("download interrupted: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		tmp.Close()
		return errors.New("the download doesn't match its published checksum; nothing was replaced")
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.cfg.AppImagePath)
}

func fetch(client *http.Client, url string, limit int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
