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
	"os/exec"
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
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	dataDir, err := dataDir()
	if err != nil {
		log.Fatal(err)
	}
	ui, _ := fs.Sub(web.Dist, "dist")
	if _, err := fs.Stat(ui, "index.html"); err != nil {
		ui = nil // built without `npm run build`; serve the placeholder
	}
	srv, err := app.New(app.Config{Version: version, DataDir: dataDir, Net: app.Net{Resolver: systemResolver()}, UI: ui})
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
	if !*noBrowser && (os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "") {
		// ponytail: plain xdg-open; app-mode window and single instance come in #4
		if cmd := exec.Command("xdg-open", url); cmd.Start() != nil {
			log.Printf("could not open a browser; open %s yourself", url)
		} else {
			go cmd.Wait()
		}
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

func dataDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
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
