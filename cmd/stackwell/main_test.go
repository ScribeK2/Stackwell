package main_test

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var bin string

func TestMain(m *testing.M) {
	dir, _ := os.MkdirTemp("", "stackwell-bin")
	bin = filepath.Join(dir, "stackwell")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// env is an isolated environment: own runtime/data dirs, a fake display, and a
// PATH holding only fake browser commands that log their arguments to opened.log.
type env struct {
	t    *testing.T
	dir  string
	vars []string
}

func newEnv(t *testing.T, fakes ...string) *env {
	e := &env{t: t, dir: t.TempDir()}
	pathDir := filepath.Join(e.dir, "bin")
	os.Mkdir(pathDir, 0o755)
	for _, name := range fakes {
		e.fake(filepath.Join(pathDir, name))
	}
	e.vars = []string{
		"PATH=" + pathDir,
		"XDG_RUNTIME_DIR=" + e.dir,
		"XDG_DATA_HOME=" + e.dir,
		"DISPLAY=:99",
	}
	return e
}

func (e *env) fake(path string) {
	script := "#!/bin/sh\necho \"${0##*/} $*\" >> " + filepath.Join(e.dir, "opened.log") + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) opened() []string {
	b, _ := os.ReadFile(filepath.Join(e.dir, "opened.log"))
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// openedLines waits until opened.log has n lines and returns them.
func (e *env) openedLines(n int) []string {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(filepath.Join(e.dir, "opened.log"))
		if lines := strings.Split(strings.TrimSpace(string(b)), "\n"); len(b) > 0 && len(lines) >= n {
			return lines
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("browser opened fewer than %d times", n)
	return nil
}

// launch starts Stackwell and returns its URL once it is serving.
func (e *env) launch(args ...string) string {
	e.t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = e.vars
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGINT)
		cmd.Wait()
	})
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		e.t.Fatalf("no URL printed: %v", err)
	}
	go io.Copy(io.Discard, out)
	url := line[strings.Index(line, "http://"):]
	url = strings.TrimSpace(url)
	resp, err := http.Get(url + "/api/health")
	if err != nil || resp.StatusCode != 200 {
		e.t.Fatalf("not healthy at %s: %v", url, err)
	}
	resp.Body.Close()
	return url
}

func TestServesOnLoopbackFreePort(t *testing.T) {
	e := newEnv(t)
	url := e.launch("--no-browser")
	if !strings.HasPrefix(url, "http://127.0.0.1:") || strings.HasSuffix(url, ":0") {
		t.Fatalf("url = %q", url)
	}
}

func TestOpensChromiumInAppMode(t *testing.T) {
	e := newEnv(t, "chromium", "xdg-open")
	url := e.launch()
	if got := e.openedLines(1)[0]; got != "chromium --app="+url {
		t.Fatalf("opened %q", got)
	}
}

func TestFallsBackToDefaultBrowser(t *testing.T) {
	e := newEnv(t, "xdg-open")
	url := e.launch()
	if got := e.openedLines(1)[0]; got != "xdg-open "+url {
		t.Fatalf("opened %q", got)
	}
}

func TestBROWSERWithArgumentsAndPlaceholder(t *testing.T) {
	e := newEnv(t, "chromium")
	e.fake(filepath.Join(e.dir, "bin", "mybrowser"))
	e.vars = append(e.vars, "BROWSER=mybrowser --new-window %s")
	url := e.launch()
	if got := e.openedLines(1)[0]; got != "mybrowser --new-window "+url {
		t.Fatalf("opened %q", got)
	}
}

func TestUnusableBROWSERFallsThrough(t *testing.T) {
	e := newEnv(t, "chromium")
	e.vars = append(e.vars, "BROWSER=does-not-exist:also-missing %s")
	url := e.launch()
	if got := e.openedLines(1)[0]; got != "chromium --app="+url {
		t.Fatalf("opened %q", got)
	}
}

func TestBROWSERWins(t *testing.T) {
	e := newEnv(t, "chromium", "xdg-open")
	mine := filepath.Join(e.dir, "mybrowser")
	e.fake(mine)
	e.vars = append(e.vars, "BROWSER="+mine)
	url := e.launch()
	if got := e.openedLines(1)[0]; got != "mybrowser "+url {
		t.Fatalf("opened %q", got)
	}
}

func TestNoBrowserFlagOpensNothing(t *testing.T) {
	e := newEnv(t, "chromium", "xdg-open")
	e.launch("--no-browser")
	time.Sleep(300 * time.Millisecond)
	if got := e.opened(); len(got) != 0 {
		t.Fatalf("opened %v", got)
	}
}

func TestSecondLaunchResurfacesTheRunningInstance(t *testing.T) {
	e := newEnv(t, "chromium")
	// The first instance was started headless (e.g. over SSH); the second
	// launch, from the desktop, must still get a window.
	url := e.launch("--no-browser")

	// Only the second launch's environment names this browser, so seeing it
	// proves the window was opened with the requester's environment.
	e.fake(filepath.Join(e.dir, "bin", "deskbrowser"))
	second := exec.Command(bin)
	second.Env = append(e.vars, "BROWSER=deskbrowser")
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = second.Output(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		second.Process.Kill()
		t.Fatal("second launch did not exit")
	}
	if err != nil {
		t.Fatalf("second launch: %v", err)
	}
	if !strings.Contains(string(out), url) {
		t.Fatalf("second launch printed %q, want the running URL %s", out, url)
	}
	if lines := e.openedLines(1); len(lines) != 1 || lines[0] != "deskbrowser "+url {
		t.Fatalf("re-surfaced with %q", lines)
	}
}

func TestStaleSocketDoesNotBlockLaunch(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(filepath.Join(e.dir, "stackwell.sock"), nil, 0o600)
	e.launch("--no-browser")
}

func TestSimultaneousLaunchesOverAStaleSocketYieldOneInstance(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(filepath.Join(e.dir, "stackwell.sock"), nil, 0o600)

	outs := make([]chan string, 2)
	for i := range outs {
		outs[i] = make(chan string, 1)
		cmd := exec.Command(bin, "--no-browser")
		cmd.Env = e.vars
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()
		t.Cleanup(func() { cmd.Process.Signal(syscall.SIGINT); cmd.Wait() })
		go func(ch chan string) {
			line, _ := bufio.NewReader(stdout).ReadString('\n')
			ch <- line
		}(outs[i])
	}
	var lines []string
	for _, ch := range outs {
		select {
		case l := <-ch:
			lines = append(lines, l)
		case <-time.After(10 * time.Second):
			t.Fatal("a launch never reported")
		}
	}
	running := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "Stackwell running at") {
			running++
		}
	}
	urlOf := func(l string) string { return strings.TrimSpace(l[strings.Index(l, "http://"):]) }
	if running != 1 || urlOf(lines[0]) != urlOf(lines[1]) {
		t.Fatalf("want one instance and the same URL twice, got %q", lines)
	}
}
