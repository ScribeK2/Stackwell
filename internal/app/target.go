package app

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Target kinds. A URL is reduced to its host on submit, so it never appears here.
const (
	kindDomain   = "domain"   // a registrable name: example.com, example.co.uk
	kindHostname = "hostname" // a name below one: www.example.com
	kindIP       = "ip"
	kindEmail    = "email"
)

// parseTarget normalises what the rep typed and classifies it. It runs once,
// on submit: scheme, port, path and trailing dot are dropped, case is folded,
// and international names become punycode.
func parseTarget(raw string) (value, kind string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", errors.New("enter a domain, host, IP or email address")
	}
	// URLs first: they may contain @ (user info, /@handle paths).
	if strings.Contains(s, "://") || strings.Contains(s, "/") {
		if !strings.Contains(s, "://") {
			s = "http://" + s
		}
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", "", errors.New(`"` + raw + `" is not a valid URL`)
		}
		s = u.Hostname()
	}
	if strings.Contains(s, "@") {
		local, domain, _ := strings.Cut(s, "@")
		host, err := parseHost(domain)
		if local == "" || strings.ContainsAny(local, "@ \t") || err != nil {
			return "", "", errors.New(`"` + s + `" is not a valid email address`)
		}
		return strings.ToLower(local) + "@" + host, kindEmail, nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().String(), kindIP, nil
	}
	if ip, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return ip.Unmap().String(), kindIP, nil
	}
	host, err := parseHost(s)
	if err != nil {
		return "", "", err
	}
	// A private suffix (github.io) is itself a resolvable site, so it counts as a domain.
	if apex, _ := publicsuffix.EffectiveTLDPlusOne(host); apex == host || isSuffix(host) {
		return host, kindDomain, nil
	}
	return host, kindHostname, nil
}

// Like idna.Lookup, but allows underscores: reps look up names such as
// selector._domainkey.example.com and _dmarc.example.com.
var hostProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.ValidateLabels(true), idna.StrictDomainName(false))

func parseHost(s string) (string, error) {
	invalid := errors.New(`"` + s + `" is not a valid domain or host name`)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	host, err := hostProfile.ToASCII(strings.TrimSuffix(strings.ToLower(s), "."))
	if err != nil || !strings.Contains(host, ".") || len(host) > 253 {
		return "", invalid
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return "", invalid
		}
	}
	// "com" or "co.uk" alone is not a target; privately run suffixes such as
	// github.io or cloudfront.net are real hosts and are allowed.
	if suffix, icann := publicsuffix.PublicSuffix(host); suffix == host && icann {
		return "", invalid
	}
	return host, nil
}

func isSuffix(host string) bool {
	suffix, _ := publicsuffix.PublicSuffix(host)
	return suffix == host
}
