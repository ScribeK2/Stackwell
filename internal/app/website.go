package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

func init() {
	registerCheck(check{
		key:      "website_inspection",
		label:    "Website Inspection",
		kinds:    []string{kindDomain, kindHostname},
		run:      websiteInspection,
		findings: websiteFindings,
	})
}

const (
	websiteMaxRedirects = 10
	websiteMaxBody      = 1 << 20
	websiteSlowMS       = 3000
	// Two fetches (HTTPS then the HTTP fallback or probe) must fit in the Check timeout.
	websiteFetchTimeout = 6 * time.Second
	// The default Go agent is often blocked by WAFs, which would read as a false 4xx.
	websiteUserAgent = "Mozilla/5.0 (compatible; Stackwell website inspection)"
)

// securityHeaders are evaluated on the final response, in display order.
var securityHeaders = []string{
	"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
	"X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
}

var (
	wpGenerator     = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([0-9.]*)`)
	wpCriticalError = []string{"There has been a critical error on this website", "There has been a critical error on your website"}
)

const wpMaintenance = "Briefly unavailable for scheduled maintenance"

type websiteHop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

type websiteHeader struct {
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Via     string `json:"via,omitempty"` // the header that satisfied it, when not itself
}

type websiteWordPress struct {
	Detected      bool     `json:"detected"`
	Evidence      []string `json:"evidence"`
	Version       string   `json:"version,omitempty"`
	CriticalError bool     `json:"critical_error"`
	Maintenance   bool     `json:"maintenance"`
}

type websiteResult struct {
	URL              string                   `json:"url"` // the URL inspected (http:// after a fallback)
	FinalURL         string                   `json:"final_url,omitempty"`
	Status           int                      `json:"status,omitempty"`
	TimeMS           int64                    `json:"time_ms"` // total, across every redirect
	Server           string                   `json:"server,omitempty"`
	ContentType      string                   `json:"content_type,omitempty"`
	Chain            []websiteHop             `json:"chain"` // every response, redirects then the final one
	RedirectLoop     bool                     `json:"redirect_loop"`
	TooManyRedirects bool                     `json:"too_many_redirects"`
	HTTPSError       string                   `json:"https_error,omitempty"`   // why HTTPS failed, when it fell back to HTTP
	Error            string                   `json:"error,omitempty"`         // the site could not be loaded at all
	HTTPToHTTPS      *bool                    `json:"http_to_https,omitempty"` // whether http:// redirects to https:// (nil: not probed)
	Headers          map[string]websiteHeader `json:"headers,omitempty"`
	WordPress        websiteWordPress         `json:"wordpress"`
}

type websiteFetch struct {
	chain         []websiteHop
	loop, tooMany bool
	resp          *http.Response
	body          string
	elapsed       time.Duration
	err           error
}

// fetchSite GETs u, following redirects itself so it can record each hop and
// stop on a loop or after websiteMaxRedirects.
func fetchSite(ctx context.Context, n Net, u string) websiteFetch {
	var f websiteFetch
	c := n.HTTPClient()
	c.Timeout = websiteFetchTimeout
	c.Jar, _ = cookiejar.New(nil) // carry cookies across hops like a browser
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		f.chain = append(f.chain, hopOf(req.Response))
		if slices.ContainsFunc(via, func(r *http.Request) bool { return r.URL.String() == req.URL.String() }) {
			f.loop = true
		} else if len(via) >= websiteMaxRedirects {
			f.tooMany = true
		} else {
			return nil
		}
		return http.ErrUseLastResponse
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		f.err = err
		return f
	}
	req.Header.Set("User-Agent", websiteUserAgent)
	start := time.Now()
	resp, err := c.Do(req)
	f.elapsed = time.Since(start)
	if err != nil {
		// On the first hop the URL is shown alongside, so drop the "Get <url>:" prefix.
		if ue, ok := err.(*url.Error); ok && len(f.chain) == 0 {
			err = ue.Err
		}
		f.err = err
		return f
	}
	defer resp.Body.Close()
	if !f.loop && !f.tooMany { // a stopped chain already recorded this response
		f.chain = append(f.chain, hopOf(resp))
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, websiteMaxBody))
	f.resp, f.body = resp, string(b)
	return f
}

func hopOf(r *http.Response) websiteHop {
	return websiteHop{URL: r.Request.URL.String(), Status: r.StatusCode, Location: r.Header.Get("Location")}
}

// websiteInspection loads the homepage over HTTPS (falling back to HTTP when
// HTTPS can't connect), records the redirect chain, timing, security headers
// and WordPress state, and probes whether plain HTTP redirects to HTTPS.
func websiteInspection(ctx context.Context, n Net, target string, _ map[string]string) (any, error) {
	res := websiteResult{URL: "https://" + target + "/"}
	f := fetchSite(ctx, n, res.URL)
	if f.err != nil && len(f.chain) == 0 && ctx.Err() == nil {
		res.HTTPSError = f.err.Error()
		res.URL = "http://" + target + "/"
		f = fetchSite(ctx, n, res.URL)
	} else if f.err == nil {
		if p := fetchSite(ctx, n, "http://"+target+"/"); p.err == nil {
			enforced := slices.ContainsFunc(p.chain, func(h websiteHop) bool { return strings.HasPrefix(h.URL, "https://") })
			res.HTTPToHTTPS = &enforced
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res.Chain, res.RedirectLoop, res.TooManyRedirects, res.TimeMS = f.chain, f.loop, f.tooMany, f.elapsed.Milliseconds()
	if f.err != nil {
		res.Error = f.err.Error()
		return res, nil
	}
	r := f.resp
	res.FinalURL, res.Status = r.Request.URL.String(), r.StatusCode
	res.Server, res.ContentType = r.Header.Get("Server"), r.Header.Get("Content-Type")

	res.Headers = map[string]websiteHeader{}
	for _, name := range securityHeaders {
		h := websiteHeader{Value: r.Header.Get(name)}
		if name == "X-Frame-Options" && h.Value == "" {
			for d := range strings.SplitSeq(r.Header.Get("Content-Security-Policy"), ";") {
				if d = strings.TrimSpace(d); strings.HasPrefix(strings.ToLower(d), "frame-ancestors") {
					h.Value, h.Via = d, "Content-Security-Policy"
				}
			}
		}
		h.Present = h.Value != ""
		res.Headers[name] = h
	}

	wp := websiteWordPress{Evidence: []string{}}
	if m := wpGenerator.FindStringSubmatch(f.body); m != nil {
		wp.Evidence, wp.Version = append(wp.Evidence, "generator meta"), m[1]
	}
	if strings.Contains(f.body, "/wp-content/") || strings.Contains(f.body, "/wp-includes/") {
		wp.Evidence = append(wp.Evidence, "wp-content/wp-includes paths")
	}
	if strings.Contains(f.body, "/wp-json") || strings.Contains(f.body, "api.w.org") {
		wp.Evidence = append(wp.Evidence, "wp-json link")
	}
	if slices.ContainsFunc(wpCriticalError, func(s string) bool { return strings.Contains(f.body, s) }) {
		wp.CriticalError = true
		wp.Evidence = append(wp.Evidence, "critical-error page")
	}
	if strings.Contains(f.body, wpMaintenance) {
		wp.Maintenance = true
		wp.Evidence = append(wp.Evidence, "maintenance page")
	}
	wp.Detected = len(wp.Evidence) > 0
	res.WordPress = wp
	return res, nil
}

func websiteFindings(target, _ string, _ map[string]string, raw json.RawMessage) []Finding {
	var r websiteResult
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	if r.Error != "" {
		msg := r.URL + " could not be loaded: " + r.Error + "."
		switch {
		case len(r.Chain) > 0: // it answered, but a redirect led somewhere that failed
			last := r.Chain[len(r.Chain)-1]
			msg = last.URL + " redirects to " + last.Location + ", which failed: " + r.Error + "."
		case r.HTTPSError != "":
			msg = "Neither HTTPS nor HTTP answered. HTTPS: " + r.HTTPSError + "; HTTP: " + r.Error + "."
		}
		return []Finding{{Code: "website_inspection_unreachable", Severity: "critical",
			Title:          "Site unreachable",
			Message:        msg,
			Recommendation: "Confirm the web server is running and listening on ports 443/80, and that DNS points " + target + " at it."}}
	}
	status := strconv.Itoa(r.Status)
	var out []Finding
	switch {
	case r.RedirectLoop:
		out = append(out, Finding{Code: "website_inspection_redirect_loop", Severity: "critical",
			Title:          "Redirect loop",
			Message:        r.URL + " redirects back to a URL it already visited, so browsers give up with \"too many redirects\".",
			Recommendation: "Check the redirect rules in the server config, .htaccess and CDN (a common cause is HTTPS forced both at the CDN and the origin, or a WordPress siteurl mismatch)."})
	case r.TooManyRedirects:
		out = append(out, Finding{Code: "website_inspection_too_many_redirects", Severity: "warning",
			Title:          "Too many redirects",
			Message:        r.URL + " was still redirecting after " + strconv.Itoa(websiteMaxRedirects) + " hops.",
			Recommendation: "Shorten the redirect chain; each hop adds latency and some clients stop following."})
	case r.WordPress.CriticalError:
		out = append(out, Finding{Code: "website_inspection_wp_critical_error", Severity: "critical",
			Title:          "WordPress critical error",
			Message:        r.FinalURL + " shows WordPress's \"There has been a critical error\" page (HTTP " + status + ").",
			Recommendation: "A plugin or theme is fatally erroring: check wp-content/debug.log or the PHP error log, and deactivate recently changed plugins."})
	case r.WordPress.Maintenance:
		out = append(out, Finding{Code: "website_inspection_wp_maintenance", Severity: "warning",
			Title:          "WordPress maintenance mode",
			Message:        r.FinalURL + " shows \"Briefly unavailable for scheduled maintenance\" (HTTP " + status + ").",
			Recommendation: "If no update is running, an update was interrupted: delete the .maintenance file in the WordPress root."})
	case r.Status >= 500:
		out = append(out, Finding{Code: "website_inspection_server_error", Severity: "critical",
			Title:          "Server error",
			Message:        r.FinalURL + " answered HTTP " + status + ".",
			Recommendation: "Check the web server and application (PHP) error logs."})
	case r.Status >= 400:
		out = append(out, Finding{Code: "website_inspection_client_error", Severity: "warning",
			Title:          "Homepage returns HTTP " + status,
			Message:        r.FinalURL + " answered HTTP " + status + ".",
			Recommendation: "Check the document root, index file, and access or firewall rules (a 403 can be a WAF blocking automated requests)."})
	case r.Status >= 200 && r.Status < 300:
		out = append(out, Finding{Code: "website_inspection_healthy", Severity: "ok",
			Title:   "Site is up",
			Message: r.FinalURL + " answered HTTP " + status + " in " + strconv.FormatInt(r.TimeMS, 10) + " ms."})
	}
	if r.HTTPSError != "" {
		out = append(out, Finding{Code: "website_inspection_https_failed", Severity: "warning",
			Title:          "HTTPS failed; HTTP only",
			Message:        "HTTPS did not work (" + r.HTTPSError + "), so the site was inspected over plain HTTP.",
			Recommendation: "Install a valid certificate and serve the site on port 443."})
	}
	if r.HTTPToHTTPS != nil && !*r.HTTPToHTTPS {
		out = append(out, Finding{Code: "website_inspection_https_not_enforced", Severity: "warning",
			Title:          "HTTPS not enforced",
			Message:        "http://" + target + "/ does not redirect to HTTPS.",
			Recommendation: "Redirect all plain HTTP requests to https:// with a 301."})
	}
	if !r.RedirectLoop && !r.TooManyRedirects {
		https := strings.HasPrefix(r.FinalURL, "https://")
		var missing []string
		for _, name := range securityHeaders {
			if r.Headers[name].Present {
				continue
			}
			if name != "Strict-Transport-Security" {
				missing = append(missing, name)
			} else if https { // HSTS is ignored over plain HTTP
				out = append(out, Finding{Code: "website_inspection_missing_hsts", Severity: "warning",
					Title:          "No HSTS",
					Message:        "The site does not send Strict-Transport-Security, so browsers may still try plain HTTP first.",
					Recommendation: "Add Strict-Transport-Security: max-age=31536000 once HTTPS works everywhere on the site."})
			}
		}
		if len(missing) > 0 {
			out = append(out, Finding{Code: "website_inspection_missing_headers", Severity: "info",
				Title:          "Missing " + plural(len(missing), "security header", "security headers"),
				Message:        "Not set: " + strings.Join(missing, ", ") + ".",
				Recommendation: "Add them in the web server or CDN config (or a security plugin on WordPress)."})
		}
	}
	if r.TimeMS > websiteSlowMS {
		out = append(out, Finding{Code: "website_inspection_slow", Severity: "info",
			Title:          "Slow response",
			Message:        "The homepage took " + strconv.FormatInt(r.TimeMS, 10) + " ms to respond, redirects included.",
			Recommendation: "Check server load, caching and slow plugins or database queries."})
	}
	return out
}
