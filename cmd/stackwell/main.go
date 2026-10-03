package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/miekg/dns"

	"github.com/ScribeK2/Stackwell/internal/app"
	"github.com/ScribeK2/Stackwell/web"
)

// version is set at build time: -ldflags "-X main.version=1.2.3". The git tag is the source of truth.
var version = "dev"

func main() {
	port := flag.Int("port", 0, "port on 127.0.0.1 (0 picks a free one)")
	noBrowser := flag.Bool("no-browser", false, "print the URL instead of opening a browser")
	showVersion := flag.Bool("version", false, "print the version and exit")
	noKeyring := flag.Bool("no-keyring", false, "keep secrets in a file in the config folder, never the system keyring")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	openWindow := !*noBrowser && hasDisplay()

	inst, running, err := claim()
	if err != nil {
		log.Fatal(err)
	}
	if inst == nil {
		// Surface the running instance from here, with this launch's display.
		fmt.Println("Stackwell already running at", running)
		if openWindow {
			openBrowser(running)
		}
		return
	}
	defer inst.Close()

	dataDir, err := xdgDir("XDG_DATA_HOME", ".local/share")
	if err != nil {
		log.Fatal(err)
	}
	configDir, err := xdgDir("XDG_CONFIG_HOME", ".config")
	if err != nil {
		log.Fatal(err)
	}
	ui, _ := fs.Sub(web.Dist, "dist")
	if _, err := fs.Stat(ui, "index.html"); err != nil {
		ui = nil // built without `npm run build`; serve the placeholder
	}
	srv, err := app.New(app.Config{Version: version, DataDir: dataDir, ConfigDir: configDir, TryKeyring: !*noKeyring, Net: app.Net{Resolver: systemResolver()}, UI: ui})
	if err != nil {
		log.Fatal(err)
	}

	// Loopback only, always (ADR-0005).
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		log.Fatal(err)
	}
	url := "http://" + ln.Addr().String()
	fmt.Println("Stackwell running at", url)
	go inst.serve(url)
	if openWindow {
		openBrowser(url)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Request contexts derive from ctx, so open event streams end on shutdown
	// and Shutdown can wait for every handler before the store closes.
	hs := &http.Server{Handler: srv.Handler(), BaseContext: func(net.Listener) context.Context { return ctx }}
	shutdown := make(chan struct{})
	go func() {
		<-ctx.Done()
		hs.Shutdown(context.Background())
		close(shutdown)
	}()
	if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-shutdown
	srv.Close()
}

// xdgDir returns $env/stackwell, or ~/fallback/stackwell, creating it 0700.
func xdgDir(env, fallback string) (string, error) {
	base := os.Getenv(env)
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, fallback)
	}
	dir := filepath.Join(base, "stackwell")
	return dir, os.MkdirAll(dir, 0o700)
}

// systemResolver returns the first nameserver from /etc/resolv.conf.
func systemResolver() string {
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		return net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	return "1.1.1.1:53"
}
