package app_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type websiteResult struct {
	URL         string `json:"url"`
	FinalURL    string `json:"final_url"`
	Status      int    `json:"status"`
	TimeMS      int64  `json:"time_ms"`
	Server      string `json:"server"`
	ContentType string `json:"content_type"`
	Chain       []struct {
		URL      string `json:"url"`
		Status   int    `json:"status"`
		Location string `json:"location"`
	} `json:"chain"`
	RedirectLoop     bool   `json:"redirect_loop"`
	TooManyRedirects bool   `json:"too_many_redirects"`
	HTTPSError       string `json:"https_error"`
	Error            string `json:"error"`
	HTTPToHTTPS      *bool  `json:"http_to_https"`
	Headers          map[string]struct {
		Present bool   `json:"present"`
		Value   string `json:"value"`
		Via     string `json:"via"`
	} `json:"headers"`
	WordPress struct {
		Detected      bool     `json:"detected"`
		Evidence      []string `json:"evidence"`
		Version       string   `json:"version"`
		CriticalError bool     `json:"critical_error"`
		Maintenance   bool     `json:"maintenance"`
	} `json:"wordpress"`
}

// allHeaders is a handler wrapper that sets every security header.
func allHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=()")
		next(w, r)
	}
}

func page(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }
}

func toHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://example.com"+r.URL.Path, http.StatusMovedPermanently)
}

// inspect runs Website Inspection on example.com with https (port 443) and
// plain (port 80) handlers; a nil handler means the port refuses connections.
func inspect(t *testing.T, https, plain http.Handler) (websiteResult, []finding) {
	t.Helper()
	addrs := map[string]string{}
	var roots *x509.CertPool
	if https != nil {
		s := httptest.NewTLSServer(https)
		t.Cleanup(s.Close)
		roots = x509.NewCertPool()
		roots.AddCert(s.Certificate())
		addrs["example.com:443"] = s.Listener.Addr().String()
	}
	if plain != nil {
		s := httptest.NewServer(plain)
		t.Cleanup(s.Close)
		addrs["example.com:80"] = s.Listener.Addr().String()
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if a, ok := addrs[addr]; ok {
			var d net.Dialer
			return d.DialContext(ctx, network, a)
		}
		return nil, errors.New("connection refused")
	}
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false), Dial: dial, TLS: &tls.Config{RootCAs: roots}}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]string{"check": "website_inspection", "target": "example.com"}, nil); code != http.StatusOK {
		t.Fatalf("run website_inspection: %d", code)
	}
	h.waitSteps(c.ID, 2)
	var raw struct {
		Steps []struct {
			Check  string          `json:"check"`
			Status string          `json:"status"`
			Error  string          `json:"error"`
			Result json.RawMessage `json:"result"`
		} `json:"steps"`
		Findings []finding `json:"findings"`
	}
	h.do("GET", "/api/cases/"+itoa(c.ID), nil, &raw)
	var res websiteResult
	if s := raw.Steps[1]; s.Check != "website_inspection" || s.Status != "ok" || json.Unmarshal(s.Result, &res) != nil {
		t.Fatalf("step = %+v", s)
	}
	var own []finding
	for _, f := range raw.Findings {
		if strings.HasPrefix(f.Code, "website_inspection_") {
			own = append(own, f)
		}
	}
	return res, own
}

func TestWebsiteHealthySiteWithEveryHeader(t *testing.T) {
	https := allHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html>hello</html>"))
	})
	res, fs := inspect(t, https, http.HandlerFunc(toHTTPS))
	if res.Status != 200 || res.FinalURL != "https://example.com/" || res.Server != "nginx" || !strings.HasPrefix(res.ContentType, "text/html") {
		t.Fatalf("result = %+v", res)
	}
	if res.HTTPToHTTPS == nil || !*res.HTTPToHTTPS {
		t.Fatalf("http_to_https = %v", res.HTTPToHTTPS)
	}
	for name, hd := range res.Headers {
		if !hd.Present || hd.Value == "" {
			t.Errorf("%s = %+v", name, hd)
		}
	}
	if len(res.Headers) != 6 || res.WordPress.Detected {
		t.Fatalf("headers = %+v, wp = %+v", res.Headers, res.WordPress)
	}
	if got := codes(fs); !slices.Equal(got, []string{"website_inspection_healthy"}) {
		t.Fatalf("findings = %v", got)
	}
	if !strings.Contains(fs[0].Message, "200") {
		t.Fatalf("healthy message = %q", fs[0].Message)
	}
}

func TestWebsiteRecordsTheRedirectChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/en/", http.StatusFound) })
	mux.HandleFunc("/en/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/en/home", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/en/home", allHeaders(page("home")))
	res, fs := inspect(t, mux, http.HandlerFunc(toHTTPS))
	type hop struct {
		url    string
		status int
	}
	var got []hop
	for _, h := range res.Chain {
		got = append(got, hop{h.URL, h.Status})
	}
	want := []hop{{"https://example.com/", 302}, {"https://example.com/en/", 301}, {"https://example.com/en/home", 200}}
	if !slices.Equal(got, want) || res.Chain[0].Location != "/en/" {
		t.Fatalf("chain = %+v", res.Chain)
	}
	if res.FinalURL != "https://example.com/en/home" || severityOf(fs, "website_inspection_healthy") != "ok" {
		t.Fatalf("final = %s, findings = %v", res.FinalURL, codes(fs))
	}
}

func TestWebsiteDetectsARedirectLoop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/a", http.StatusFound) })
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusFound) })
	res, fs := inspect(t, mux, http.HandlerFunc(toHTTPS))
	if !res.RedirectLoop || len(res.Chain) != 2 {
		t.Fatalf("result = %+v", res)
	}
	if severityOf(fs, "website_inspection_redirect_loop") != "critical" || slices.Contains(codes(fs), "website_inspection_healthy") {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestWebsiteStopsAfterTenRedirects(t *testing.T) {
	https := func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		http.Redirect(w, r, "/"+strconv.Itoa(n+1), http.StatusFound)
	}
	res, fs := inspect(t, http.HandlerFunc(https), http.HandlerFunc(toHTTPS))
	if !res.TooManyRedirects || res.RedirectLoop || len(res.Chain) != 10 {
		t.Fatalf("result = %+v", res)
	}
	if severityOf(fs, "website_inspection_too_many_redirects") != "warning" {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestWebsiteFallsBackToHTTPWhenHTTPSFails(t *testing.T) {
	res, fs := inspect(t, nil, allHeaders(page("plain")))
	if res.HTTPSError == "" || res.FinalURL != "http://example.com/" || res.Status != 200 {
		t.Fatalf("result = %+v", res)
	}
	if severityOf(fs, "website_inspection_https_failed") != "warning" {
		t.Fatalf("findings = %v", codes(fs))
	}
	// HSTS means nothing over plain HTTP; the HTTPS warning covers it.
	if slices.Contains(codes(fs), "website_inspection_missing_hsts") {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestWebsiteFlagsHTTPThatDoesNotRedirectToHTTPS(t *testing.T) {
	res, fs := inspect(t, allHeaders(page("secure")), allHeaders(page("insecure")))
	if res.HTTPToHTTPS == nil || *res.HTTPToHTTPS {
		t.Fatalf("http_to_https = %v", res.HTTPToHTTPS)
	}
	if severityOf(fs, "website_inspection_https_not_enforced") != "warning" {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestWebsiteUnreachable(t *testing.T) {
	res, fs := inspect(t, nil, nil)
	if res.Error == "" || res.Status != 0 {
		t.Fatalf("result = %+v", res)
	}
	if got := codes(fs); !slices.Equal(got, []string{"website_inspection_unreachable"}) || fs[0].Severity != "critical" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestWebsiteRedirectToABrokenHTTPSIsUnreachable(t *testing.T) {
	// HTTPS is down, and plain HTTP only redirects to it.
	res, fs := inspect(t, nil, http.HandlerFunc(toHTTPS))
	if res.Error == "" || res.HTTPSError == "" || len(res.Chain) != 1 || res.Chain[0].Status != 301 {
		t.Fatalf("result = %+v", res)
	}
	if severityOf(fs, "website_inspection_unreachable") != "critical" || !strings.Contains(fs[0].Message, "redirects to https://example.com/") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestWebsiteServerAndClientErrors(t *testing.T) {
	_, fs := inspect(t, allHeaders(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }), http.HandlerFunc(toHTTPS))
	if severityOf(fs, "website_inspection_server_error") != "critical" || slices.Contains(codes(fs), "website_inspection_healthy") {
		t.Fatalf("5xx findings = %v", codes(fs))
	}
	_, fs = inspect(t, allHeaders(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }), http.HandlerFunc(toHTTPS))
	if severityOf(fs, "website_inspection_client_error") != "warning" || slices.Contains(codes(fs), "website_inspection_healthy") {
		t.Fatalf("4xx findings = %v", codes(fs))
	}
}

func TestWebsiteMissingHeaders(t *testing.T) {
	https := func(w http.ResponseWriter, r *http.Request) {
		// X-Frame-Options is covered by CSP frame-ancestors.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write([]byte("ok"))
	}
	res, fs := inspect(t, http.HandlerFunc(https), http.HandlerFunc(toHTTPS))
	if xfo := res.Headers["X-Frame-Options"]; !xfo.Present || xfo.Via == "" {
		t.Fatalf("X-Frame-Options = %+v", xfo)
	}
	if res.Headers["Strict-Transport-Security"].Present {
		t.Fatalf("headers = %+v", res.Headers)
	}
	if severityOf(fs, "website_inspection_missing_hsts") != "warning" || severityOf(fs, "website_inspection_missing_headers") != "info" {
		t.Fatalf("findings = %v", codes(fs))
	}
	i := slices.IndexFunc(fs, func(f finding) bool { return f.Code == "website_inspection_missing_headers" })
	if m := fs[i].Message; !strings.Contains(m, "Referrer-Policy") || !strings.Contains(m, "Permissions-Policy") || strings.Contains(m, "X-Frame-Options") {
		t.Fatalf("message = %q", m)
	}
}

func TestWebsiteDetectsWordPress(t *testing.T) {
	body := `<html><head><meta name="generator" content="WordPress 6.5.2" />
<link rel="https://api.w.org/" href="https://example.com/wp-json/" />
<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head></html>`
	res, fs := inspect(t, allHeaders(page(body)), http.HandlerFunc(toHTTPS))
	wp := res.WordPress
	if !wp.Detected || wp.Version != "6.5.2" || wp.CriticalError || wp.Maintenance {
		t.Fatalf("wordpress = %+v", wp)
	}
	for _, e := range []string{"generator", "wp-content", "wp-json"} {
		if !slices.ContainsFunc(wp.Evidence, func(s string) bool { return strings.Contains(s, e) }) {
			t.Errorf("evidence %v lacks %s", wp.Evidence, e)
		}
	}
	if severityOf(fs, "website_inspection_healthy") != "ok" {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestWebsiteWordPressCriticalError(t *testing.T) {
	https := allHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`<p>There has been a critical error on this website.</p>`))
	})
	res, fs := inspect(t, https, http.HandlerFunc(toHTTPS))
	if !res.WordPress.CriticalError || !res.WordPress.Detected {
		t.Fatalf("wordpress = %+v", res.WordPress)
	}
	// The specific WordPress finding replaces the generic 5xx one.
	if got := codes(fs); !slices.Equal(got, []string{"website_inspection_wp_critical_error"}) || fs[0].Severity != "critical" {
		t.Fatalf("findings = %v", got)
	}
}

func TestWebsiteWordPressMaintenanceMode(t *testing.T) {
	https := allHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`<h1>Briefly unavailable for scheduled maintenance. Check back in a minute.</h1>`))
	})
	res, fs := inspect(t, https, http.HandlerFunc(toHTTPS))
	if !res.WordPress.Maintenance {
		t.Fatalf("wordpress = %+v", res.WordPress)
	}
	if got := codes(fs); !slices.Equal(got, []string{"website_inspection_wp_maintenance"}) || fs[0].Severity != "warning" {
		t.Fatalf("findings = %v", got)
	}
}

func TestWebsiteSlowResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("sleeps 3s")
	}
	https := allHeaders(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3100 * time.Millisecond)
		w.Write([]byte("slow"))
	})
	// Plain HTTP doesn't redirect, so the probe doesn't wait out the slow page again.
	res, fs := inspect(t, https, page("insecure"))
	if res.TimeMS < 3000 || severityOf(fs, "website_inspection_slow") != "info" || severityOf(fs, "website_inspection_healthy") != "ok" {
		t.Fatalf("time = %d, findings = %v", res.TimeMS, codes(fs))
	}
}
