package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Chromium-family browsers that support --app=URL (a window with no tabs or address bar).
var appModeBrowsers = []string{
	"chromium", "chromium-browser", "google-chrome-stable", "google-chrome",
	"brave-browser", "brave", "microsoft-edge-stable", "vivaldi-stable",
}

// browserCommands lists what to try, in order: each $BROWSER entry
// (colon-separated, %s replaced by the URL or the URL appended), then the
// first Chromium-family browser in app mode, then xdg-open.
func browserCommands(url string) [][]string {
	var cmds [][]string
	for entry := range strings.SplitSeq(os.Getenv("BROWSER"), ":") {
		args := strings.Fields(entry)
		if len(args) == 0 {
			continue
		}
		if strings.Contains(entry, "%s") {
			for i := range args {
				args[i] = strings.ReplaceAll(args[i], "%s", url)
			}
		} else {
			args = append(args, url)
		}
		cmds = append(cmds, args)
	}
	for _, name := range appModeBrowsers {
		if _, err := exec.LookPath(name); err == nil {
			cmds = append(cmds, []string{name, "--app=" + url})
			break
		}
	}
	return append(cmds, []string{"xdg-open", url})
}

// openBrowser shows url with the first browser command that starts.
func openBrowser(url string) {
	for _, args := range browserCommands(url) {
		cmd := exec.Command(args[0], args[1:]...)
		// Own session, so Ctrl-C on Stackwell's terminal doesn't take the browser down.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if cmd.Start() == nil {
			go cmd.Wait()
			return
		}
	}
	log.Printf("could not open a browser; open %s yourself", url)
}

func hasDisplay() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

func runtimeDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("stackwell-%d", os.Getuid()))
	os.MkdirAll(dir, 0o700)
	return dir
}

// instance is this process's claim to be the one running Stackwell. The flock
// on the lock file decides ownership (the kernel drops it if we crash); the
// socket only lets later launches ask the owner for its URL.
type instance struct {
	lock *os.File
	ln   net.Listener
}

// claim either makes this process the owner, or returns the running owner's URL.
func claim() (inst *instance, runningURL string, err error) {
	dir := runtimeDir()
	sock := filepath.Join(dir, "stackwell.sock")
	lock, err := os.OpenFile(filepath.Join(dir, "stackwell.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, "", err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			os.Remove(sock) // any socket file left now is from a dead owner
			ln, err := net.Listen("unix", sock)
			if err != nil {
				lock.Close()
				return nil, "", err
			}
			return &instance{lock: lock, ln: ln}, "", nil
		}
		// Someone owns it. They may still be starting up, or may die before
		// answering, so retry until they answer or the lock frees up.
		if url, err := askURL(sock); err == nil {
			lock.Close()
			return nil, url, nil
		}
		if time.Now().After(deadline) {
			lock.Close()
			return nil, "", errors.New("another Stackwell holds the lock but is not answering")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func askURL(sock string) (string, error) {
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	url, err := bufio.NewReader(conn).ReadString('\n')
	if url = strings.TrimSpace(url); url == "" {
		return "", fmt.Errorf("no URL from running instance: %v", err)
	}
	return url, nil
}

// serve answers every later launch with url until Close.
func (i *instance) serve(url string) {
	for {
		conn, err := i.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			fmt.Fprintln(conn, url)
		}()
	}
}

func (i *instance) Close() {
	i.ln.Close() // also removes the socket file
	i.lock.Close()
}
