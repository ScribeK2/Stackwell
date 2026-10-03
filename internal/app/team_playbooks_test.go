package app_test

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type playbookList struct {
	Folder    string `json:"folder"`
	Playbooks []struct {
		Name   string `json:"name"`
		Label  string `json:"label"`
		Source string `json:"source"`
	} `json:"playbooks"`
	Errors []struct {
		File  string `json:"file"`
		Error string `json:"error"`
	} `json:"errors"`
}

func (h *harness) playbookList() playbookList {
	h.t.Helper()
	var l playbookList
	h.do("GET", "/api/playbooks", nil, &l)
	return l
}

func (l playbookList) find(name string) (label, source string, ok bool) {
	for _, p := range l.Playbooks {
		if p.Name == name {
			return p.Label, p.Source, true
		}
	}
	return "", "", false
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setFolder(h *harness, dir string) int {
	return h.do("PUT", "/api/settings", map[string]string{"playbook_dir": dir}, nil)
}

func TestTeamPlaybooksComeFromTheFolderInSettings(t *testing.T) {
	data := t.TempDir()
	folder := t.TempDir()
	team := writeFile(t, folder, "mx.yaml", mxPlaybook)
	h := start(t, app.Config{DataDir: data, Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})

	if _, _, ok := h.playbookList().find("mx_check"); ok {
		t.Fatal("team Playbook listed before a folder was set")
	}
	if code := setFolder(h, folder); code != http.StatusOK {
		t.Fatalf("set folder: %d", code)
	}
	l := h.playbookList()
	if label, source, ok := l.find("mx_check"); !ok || label != "MX check" || source != team || l.Folder != folder {
		t.Fatalf("list = %+v", l)
	}
	if _, source, _ := l.find("orientation"); source != "built-in" {
		t.Fatalf("built-ins should stay listed as built-in, got %q", source)
	}

	// The setting survives a restart.
	h.stop()
	h2 := start(t, app.Config{DataDir: data, Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	if _, _, ok := h2.playbookList().find("mx_check"); !ok {
		t.Fatal("folder setting lost on restart")
	}

	// Clearing it goes back to built-ins only.
	setFolder(h2, "")
	if _, _, ok := h2.playbookList().find("mx_check"); ok {
		t.Fatal("team Playbook still listed after clearing the folder")
	}
}

func TestAFolderPlaybookOverridesABuiltInOfTheSameName(t *testing.T) {
	folder := t.TempDir()
	path := writeFile(t, folder, "orientation.yaml", `
name: orientation
label: Team Orientation
kinds: [domain]
entries:
  - check: dns_lookup
`)
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	setFolder(h, folder)
	l := h.playbookList()
	n := 0
	for _, p := range l.Playbooks {
		if p.Name == "orientation" {
			n++
		}
	}
	if label, source, _ := l.find("orientation"); n != 1 || label != "Team Orientation" || source != path {
		t.Fatalf("orientation ×%d: %+v", n, l.Playbooks)
	}
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	run := h.startRun(c.ID, "orientation", "example.com")
	if got := h.waitRun(c.ID, run); !slices.Equal(checksOf(runSteps(got, run)), []string{"dns_lookup@example.com"}) {
		t.Fatalf("ran the built-in, not the team's: %v", checksOf(runSteps(got, run)))
	}
}

func TestABrokenFileIsReportedWithoutBreakingTheOthers(t *testing.T) {
	folder := t.TempDir()
	writeFile(t, folder, "good.yaml", mxPlaybook)
	broken := map[string]string{
		"unknown_check.yaml": "name: a\nlabel: A\nkinds: [domain]\nentries:\n  - check: no_such_check\n",
		"cycle.yaml":         "name: b\nlabel: B\nkinds: [domain]\nentries:\n  - id: x\n    check: dns_lookup\n    depends_on: y\n  - id: y\n    check: dns_lookup\n    depends_on: x\n",
		"bad_resolver.yaml":  "name: c\nlabel: C\nkinds: [domain]\nentries:\n  - id: x\n    check: dns_lookup\n  - check: blacklist\n    depends_on: x\n    target: the_moon\n",
		"wrong_kind.yaml":    "name: d\nlabel: D\nkinds: [ip]\nentries:\n  - check: registration\n",
		"bad_option.yaml":    "name: e\nlabel: E\nkinds: [domain]\nentries:\n  - check: hosting_reachability\n    options: {depth: enormous}\n",
		"typo_key.yaml":      "name: f\nlabel: F\nkinds: [domain]\nentires:\n  - check: dns_lookup\n",
		"not_yaml.yaml":      "name: [unclosed\n",
	}
	for name, body := range broken {
		writeFile(t, folder, name, body)
	}
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	if code := setFolder(h, folder); code != http.StatusOK {
		t.Fatalf("a folder with broken files was refused: %d", code)
	}
	l := h.playbookList()
	if _, _, ok := l.find("mx_check"); !ok {
		t.Fatal("the good Playbook was dropped because of broken ones")
	}
	if _, _, ok := l.find("orientation"); !ok {
		t.Fatal("built-ins were dropped because of broken team files")
	}
	if len(l.Errors) != len(broken) {
		t.Fatalf("%d errors for %d broken files: %+v", len(l.Errors), len(broken), l.Errors)
	}
	for _, e := range l.Errors {
		if _, ok := broken[filepath.Base(e.File)]; !ok || e.Error == "" {
			t.Errorf("error %+v doesn't name a broken file and its problem", e)
		}
	}
}

func TestTheFolderIsReReadWithoutARestart(t *testing.T) {
	folder := t.TempDir()
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	setFolder(h, folder)
	writeFile(t, folder, "later.yaml", mxPlaybook) // e.g. after a git pull
	if _, _, ok := h.playbookList().find("mx_check"); !ok {
		t.Fatal("a Playbook added to the folder needs a restart to appear")
	}
}

func TestAFolderThatDoesNotExistIsRefused(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	if code := setFolder(h, filepath.Join(t.TempDir(), "nope")); code != http.StatusBadRequest {
		t.Fatalf("missing folder: %d", code)
	}
	file := writeFile(t, t.TempDir(), "x.yaml", mxPlaybook)
	if code := setFolder(h, file); code != http.StatusBadRequest {
		t.Fatalf("a file instead of a folder: %d", code)
	}
}

func TestABrokenOverrideWithdrawsTheBuiltInRatherThanRunningIt(t *testing.T) {
	folder := t.TempDir()
	writeFile(t, folder, "orientation.yaml", "name: orientation\nlabel: Team Orientation\nkinds: [domain]\nentries:\n  - check: dns_lookpu\n") // typo
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	setFolder(h, folder)
	l := h.playbookList()
	if _, _, ok := l.find("orientation"); ok {
		t.Fatal("the built-in still runs in place of the team's broken override")
	}
	if len(l.Errors) != 1 || !strings.Contains(l.Errors[0].Error, "orientation") {
		t.Fatalf("errors = %+v", l.Errors)
	}
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/runs", map[string]string{"playbook": "orientation", "target": "example.com"}, nil); code != http.StatusBadRequest {
		t.Fatalf("run of a withdrawn Playbook: %d", code)
	}
}
