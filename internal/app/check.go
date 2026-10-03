package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Net is every network capability a Check may use. Checks never reach the
// network any other way, so tests point them at local fakes.
type Net struct {
	Resolver string // host:port of the DNS resolver for ordinary lookups

	// PublicResolvers overrides the bundled worldwide resolvers that
	// DNS Propagation compares (nil: use the bundled list).
	PublicResolvers []PublicResolver

	// Dial opens every TCP connection a Check makes (nil: a plain net.Dialer,
	// which resolves host names with the system resolver). Tests map
	// "host:443" to a local listener here.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// TLS is the base TLS configuration (nil: system roots). Tests add their CA.
	TLS *tls.Config

	// RDAP maps a TLD to its RDAP base URL, overriding the bundled bootstrap.
	RDAP map[string]string
	// WHOIS maps a TLD to its WHOIS server host:port, overriding the defaults.
	WHOIS map[string]string
}

// DialContext dials through n.Dial, or a plain dialer when unset.
func (n Net) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if n.Dial != nil {
		return n.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// TLSConfig returns a copy of the base TLS configuration, safe to modify.
func (n Net) TLSConfig() *tls.Config {
	if n.TLS == nil {
		return &tls.Config{}
	}
	return n.TLS.Clone()
}

// HTTPClient returns a new client that dials through n; each call gets its own,
// so a Check may set CheckRedirect or Timeout without affecting others.
func (n Net) HTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext:         n.DialContext,
		TLSClientConfig:     n.TLSConfig(),
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
		Proxy:               nil, // diagnostics must see the real path, never a proxy
	}}
}

// Option is a setting a Check accepts, e.g. a sweep depth or a lookup scope.
// A Step's options are part of its identity: Steps are only compared with,
// and superseded by, Steps of the same Check, Target and options.
type Option struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Choices []string `json:"choices,omitempty"` // a select; empty means free text
	Default string   `json:"default"`
}

type check struct {
	key     string
	label   string
	kinds   []string // Target kinds it applies to
	auto    bool     // runs when a Target of a matching kind is added
	options []Option
	run     func(ctx context.Context, n Net, target string, opts map[string]string) (any, error)
	// findings applies the Check's rules to one finished, successful Step (nil: no rules yet).
	findings func(target, kind string, opts map[string]string, result json.RawMessage) []Finding
}

// checks is the registry, in registration order. Each Check registers itself
// from its own file's init, so adding a Check touches no shared file.
var checks []check

func registerCheck(c check) {
	if checkByKey(c.key) != nil {
		panic("check registered twice: " + c.key)
	}
	checks = append(checks, c)
}

func checkByKey(key string) *check {
	if i := slices.IndexFunc(checks, func(c check) bool { return c.key == key }); i != -1 {
		return &checks[i]
	}
	return nil
}

func checkLabel(key string) string {
	if c := checkByKey(key); c != nil {
		return c.label
	}
	return key
}

// checksFor lists the keys of the Checks that apply to a Target kind.
func checksFor(kind string) []string {
	keys := []string{}
	for _, c := range checks {
		if slices.Contains(c.kinds, kind) {
			keys = append(keys, c.key)
		}
	}
	return keys
}

// resolveOptions validates the requested options and fills in defaults, so the
// same run always has the same options whether or not defaults were sent.
func (c *check) resolveOptions(req map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k := range req {
		if !slices.ContainsFunc(c.options, func(o Option) bool { return o.Key == k }) {
			return nil, fmt.Errorf("%s has no option %q", c.label, k)
		}
	}
	for _, o := range c.options {
		v, ok := req[o.Key]
		if !ok {
			v = o.Default
		}
		v = strings.TrimSpace(v)
		if len(o.Choices) > 0 && !slices.Contains(o.Choices, v) {
			return nil, fmt.Errorf("%s: %s must be one of %s", c.label, o.Label, strings.Join(o.Choices, ", "))
		}
		out[o.Key] = v
	}
	return out, nil
}

// checkInfo is what GET /api/checks tells the UI about a Check.
type checkInfo struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Kinds   []string `json:"kinds"`
	Options []Option `json:"options"`
}

func checkInfos() []checkInfo {
	out := []checkInfo{}
	for _, c := range checks {
		opts := c.options
		if opts == nil {
			opts = []Option{}
		}
		out = append(out, checkInfo{Key: c.key, Label: c.label, Kinds: c.kinds, Options: opts})
	}
	return out
}
