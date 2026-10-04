package app_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

func send(t *testing.T, h *harness, method, path, host, origin string) int {
	t.Helper()
	req, _ := http.NewRequest(method, h.web.URL+path, strings.NewReader(`{"target":"example.com"}`))
	req.Header.Set("Content-Type", "text/plain") // what a cross-site no-cors POST can send
	if host != "" {
		req.Host = host
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestOtherWebsitesCannotDriveStackwell(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	self := strings.TrimPrefix(h.web.URL, "http://")

	if code := send(t, h, "POST", "/api/cases", "", "https://evil.example"); code != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", code)
	}
	// DNS rebinding: a hostile name resolved to 127.0.0.1 is not loopback.
	if code := send(t, h, "GET", "/api/cases", "rebind.evil.example:"+strings.Split(self, ":")[1], ""); code != http.StatusForbidden {
		t.Errorf("rebound Host: %d", code)
	}
	// Stackwell's own page, and local tools without an Origin, still work.
	if code := send(t, h, "POST", "/api/cases", "", "http://"+self); code != http.StatusCreated {
		t.Errorf("same-origin POST: %d", code)
	}
	if code := send(t, h, "GET", "/api/health", "localhost:"+strings.Split(self, ":")[1], ""); code != http.StatusOK {
		t.Errorf("localhost Host: %d", code)
	}
}
