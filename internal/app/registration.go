package app

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

func init() {
	registerCheck(check{
		key:      "registration",
		label:    "Registration",
		kinds:    []string{kindDomain},
		run:      registration,
		findings: registrationFindings,
	})
}

// IANA's RDAP bootstrap for domains (https://data.iana.org/rdap/dns.json).
//
//go:embed rdap_bootstrap.json
var rdapBootstrapJSON []byte

// rdapBases maps a TLD to its RDAP base URL, parsed once from the bundled bootstrap.
var rdapBases = sync.OnceValue(func() map[string]string {
	var b struct{ Services [][][]string }
	if err := json.Unmarshal(rdapBootstrapJSON, &b); err != nil {
		panic("rdap_bootstrap.json: " + err.Error())
	}
	m := map[string]string{}
	for _, s := range b.Services {
		if len(s) < 2 || len(s[1]) == 0 {
			continue
		}
		url := s[1][0]
		for _, u := range s[1] { // prefer https when a registry lists both
			if strings.HasPrefix(u, "https://") {
				url = u
				break
			}
		}
		for _, tld := range s[0] {
			m[strings.ToLower(tld)] = url
		}
	}
	return m
})

// Bundled WHOIS servers for common TLDs; anything else asks whois.iana.org for a referral.
var defaultWHOIS = map[string]string{
	"com": "whois.verisign-grs.com:43", "net": "whois.verisign-grs.com:43",
	"org": "whois.publicinterestregistry.org:43", "info": "whois.nic.info:43",
	"io": "whois.nic.io:43", "co": "whois.nic.co:43", "me": "whois.nic.me:43",
	"us": "whois.nic.us:43", "biz": "whois.nic.biz:43", "uk": "whois.nic.uk:43",
	"de": "whois.denic.de:43", "nl": "whois.domain-registry.nl:43", "eu": "whois.eu:43",
	"ca": "whois.cira.ca:43", "au": "whois.auda.org.au:43", "fr": "whois.nic.fr:43",
}

const whoisIANA = "whois.iana.org:43"

type registrationResult struct {
	Domain      string   `json:"domain"` // the registrable name looked up
	Source      string   `json:"source"` // rdap | whois
	Registered  bool     `json:"registered"`
	Registrar   string   `json:"registrar,omitempty"`
	Statuses    []string `json:"statuses"`          // EPP camelCase, e.g. clientHold
	Created     string   `json:"created,omitempty"` // RFC 3339 when parseable, else as given
	Updated     string   `json:"updated,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	Nameservers []string `json:"nameservers"`
	DNSSEC      *bool    `json:"dnssec,omitempty"`
	RDAPError   string   `json:"rdap_error,omitempty"` // why WHOIS was used instead
}

// registrableDomain is the ICANN registrable name: foo.github.io is registered as github.io.
func registrableDomain(host string) string {
	s, icann := publicsuffix.PublicSuffix(host)
	for !icann {
		i := strings.IndexByte(s, '.')
		if i == -1 {
			break
		}
		s = s[i+1:]
		_, icann = publicsuffix.PublicSuffix(s)
	}
	if s == host {
		return host
	}
	rest := strings.TrimSuffix(host, "."+s)
	return rest[strings.LastIndexByte(rest, '.')+1:] + "." + s
}

// registration asks the registry over RDAP and falls back to WHOIS when the
// TLD has no RDAP service or it fails. An RDAP 404 is authoritative: not registered.
func registration(ctx context.Context, n Net, target string, _ map[string]string) (any, error) {
	name := registrableDomain(target)
	tld := name[strings.LastIndexByte(name, '.')+1:]
	base := n.RDAP[tld]
	if base == "" {
		base = rdapBases()[tld]
	}
	var rdapErr error
	if base == "" {
		rdapErr = errors.New("no RDAP service for ." + tld)
	} else {
		res, err := rdapLookup(ctx, n, base, name)
		if err == nil {
			return res, nil
		}
		rdapErr = err
	}
	if ctx.Err() != nil {
		return nil, errors.New("timed out")
	}
	server := n.WHOIS[tld]
	if server == "" {
		server = defaultWHOIS[tld]
	}
	res, err := whoisLookup(ctx, n, server, name)
	if err != nil {
		return nil, fmt.Errorf("RDAP: %v; WHOIS: %v", rdapErr, err)
	}
	res.RDAPError = rdapErr.Error()
	return res, nil
}

func rdapLookup(ctx context.Context, n Net, base, name string) (registrationResult, error) {
	res := registrationResult{Domain: name, Source: "rdap", Statuses: []string{}, Nameservers: []string{}}
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(base, "/")+"/domain/"+name, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := n.HTTPClient().Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return res, nil // the registry has no such domain
	}
	if resp.StatusCode != http.StatusOK {
		return res, errors.New("RDAP server answered " + resp.Status)
	}
	type vcardEntity struct {
		Roles []string          `json:"roles"`
		VCard []json.RawMessage `json:"vcardArray"`
	}
	var d struct {
		Status []string `json:"status"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
		SecureDNS *struct {
			DelegationSigned *bool `json:"delegationSigned"`
		} `json:"secureDNS"`
		Entities []vcardEntity `json:"entities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&d); err != nil {
		return res, errors.New("unreadable RDAP answer: " + err.Error())
	}
	res.Registered = true
	for _, e := range d.Entities {
		if !slices.Contains(e.Roles, "registrar") || len(e.VCard) < 2 {
			continue
		}
		var rows [][]any
		json.Unmarshal(e.VCard[1], &rows)
		for _, row := range rows {
			if len(row) >= 4 && row[0] == "fn" {
				res.Registrar, _ = row[3].(string)
			}
		}
	}
	for _, s := range d.Status {
		res.Statuses = append(res.Statuses, eppStatus(s))
	}
	for _, e := range d.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			res.Created = normalizeDate(e.Date)
		case "expiration":
			res.Expires = normalizeDate(e.Date)
		case "last changed":
			res.Updated = normalizeDate(e.Date)
		}
	}
	for _, ns := range d.Nameservers {
		res.Nameservers = append(res.Nameservers, strings.ToLower(strings.TrimSuffix(ns.LDHName, ".")))
	}
	if d.SecureDNS != nil {
		res.DNSSEC = d.SecureDNS.DelegationSigned
	}
	slices.Sort(res.Statuses)
	slices.Sort(res.Nameservers)
	return res, nil
}

// eppStatus turns RDAP's "client hold" and WHOIS's "clientHold https://icann.org/epp#clientHold"
// into the same EPP spelling, clientHold.
func eppStatus(s string) string {
	words := strings.Fields(strings.TrimSpace(s))
	if len(words) == 0 {
		return ""
	}
	if len(words) > 1 && strings.HasPrefix(words[len(words)-1], "http") {
		words = words[:len(words)-1] // WHOIS appends the ICANN explainer URL
	}
	if len(words) == 1 && words[0] == strings.ToUpper(words[0]) {
		return strings.ToLower(words[0]) // some ccTLDs shout: ACTIVE
	}
	out := strings.ToLower(words[0][:1]) + words[0][1:]
	for _, w := range words[1:] {
		out += strings.ToUpper(w[:1]) + w[1:]
	}
	return out
}

var whoisDateLayouts = []string{
	time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02 15:04:05 MST",
	"2006-01-02", "02-Jan-2006", "2006.01.02", "02.01.2006", "2006/01/02", "January 2 2006",
}

// normalizeDate returns RFC 3339 when s is a date it knows, else s unchanged.
func normalizeDate(s string) string {
	s = strings.TrimSpace(s)
	for _, l := range whoisDateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

func whoisField(re string) *regexp.Regexp {
	return regexp.MustCompile(`(?im)^\s*(?:` + re + `):[ \t]*(\S.*?)\s*$`)
}

var (
	whoisRegistrar = whoisField(`Registrar|Registrar Name|Registrar Organization`)
	// EURid and others put the registrar in an indented block under "Registrar:".
	whoisRegistrarBlock = regexp.MustCompile(`(?im)^\s*Registrar:\s*\n\s+(?:Name|Organi[sz]ation):[ \t]*(\S.*?)\s*$`)
	whoisExpires        = whoisField(`Registry Expiry Date|Registrar Registration Expiration Date|Expir(?:ation|y) Date|Expires(?: On)?|paid-till`)
	whoisCreated        = whoisField(`Creation Date|Created Date|Created(?: On)?|Registration Date|Registered On`)
	whoisUpdated        = whoisField(`Updated Date|Last Updated|Last Modified|Modified|Changed`)
	whoisNameservers    = whoisField(`Name Server|Nameserver|nserver`)
	whoisStatus         = whoisField(`Domain Status|Status`)
	whoisDNSSEC         = whoisField(`DNSSEC`)
	whoisRefer          = whoisField(`refer|whois`)
)

// whoisLookup queries a port-43 WHOIS server (following one IANA referral) and
// parses the common fields best-effort.
func whoisLookup(ctx context.Context, n Net, server, name string) (registrationResult, error) {
	if server == "" {
		text, err := whoisQuery(ctx, n, whoisIANA, name)
		if err != nil {
			return registrationResult{}, err
		}
		m := whoisRefer.FindStringSubmatch(text)
		if m == nil {
			return registrationResult{}, errors.New("IANA knows no WHOIS server for this TLD")
		}
		server = net.JoinHostPort(m[1], "43")
	}
	text, err := whoisQuery(ctx, n, server, name)
	if err != nil {
		return registrationResult{}, err
	}
	return parseWHOIS(name, text), nil
}

func parseWHOIS(name, text string) registrationResult {
	res := registrationResult{Domain: name, Source: "whois", Statuses: []string{}, Nameservers: []string{}}
	first := func(re *regexp.Regexp) string {
		if m := re.FindStringSubmatch(text); m != nil {
			return m[1]
		}
		return ""
	}
	res.Registrar = first(whoisRegistrar)
	if res.Registrar == "" {
		res.Registrar = first(whoisRegistrarBlock)
	}
	if s := first(whoisExpires); s != "" {
		res.Expires = normalizeDate(s)
	}
	if s := first(whoisCreated); s != "" {
		res.Created = normalizeDate(s)
	}
	if s := first(whoisUpdated); s != "" {
		res.Updated = normalizeDate(s)
	}
	for _, m := range whoisNameservers.FindAllStringSubmatch(text, -1) {
		ns := strings.ToLower(strings.TrimSuffix(strings.Fields(m[1])[0], "."))
		if !slices.Contains(res.Nameservers, ns) {
			res.Nameservers = append(res.Nameservers, ns)
		}
	}
	for _, m := range whoisStatus.FindAllStringSubmatch(text, -1) {
		if s := eppStatus(m[1]); s != "" && !slices.Contains(res.Statuses, s) {
			res.Statuses = append(res.Statuses, s)
		}
	}
	if s := strings.ToLower(first(whoisDNSSEC)); s != "" {
		signed := strings.Contains(s, "signed") && !strings.Contains(s, "unsigned")
		res.DNSSEC = &signed
	}
	slices.Sort(res.Statuses)
	slices.Sort(res.Nameservers)
	// WHOIS has no common "no match" signal; a reply with no registrar,
	// dates or nameservers is the closest proxy (DENIC's "Status: free" is an
	// explicit one). Only applied to WHOIS: a sparse RDAP record is still a
	// registered domain. Nameservers and the updated date count because
	// DENIC gives no registrar or creation/expiry date for registered names.
	// ponytail: a heavily redacted WHOIS record for a registered domain could trip this.
	res.Registered = !slices.Contains(res.Statuses, "free") &&
		(res.Registrar != "" || res.Expires != "" || res.Created != "" || res.Updated != "" || len(res.Nameservers) > 0)
	return res
}

func whoisQuery(ctx context.Context, n Net, server, name string) (string, error) {
	conn, err := n.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err := io.WriteString(conn, name+"\r\n"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(bufio.NewReader(conn), 1<<20))
	if err != nil && len(b) == 0 {
		return "", err
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", errors.New("empty reply from WHOIS server " + server)
	}
	return string(b), nil
}

// Problem statuses and what they mean for the rep.
var registrationHolds = []string{"clientHold", "serverHold"}
var registrationDeletion = []string{"redemptionPeriod", "pendingDelete", "pendingRestore"}

func registrationFindings(target, _ string, _ map[string]string, raw json.RawMessage) []Finding {
	var r registrationResult
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	if !r.Registered {
		via := "The registry's RDAP service has no record of " + r.Domain + "."
		if r.Source == "whois" {
			via = "The WHOIS reply for " + r.Domain + " carries no registrar or dates, which means it is not registered."
		}
		return []Finding{{Code: "registration_not_registered", Severity: "critical",
			Title:          "Not registered",
			Message:        via,
			Recommendation: "Check the spelling; if it is the customer's domain, it has lapsed or was never registered, so register it (or restore it at the registrar) as soon as possible."}}
	}
	var out []Finding
	if exp, err := time.Parse(time.RFC3339, r.Expires); err == nil {
		left := time.Until(exp)
		days := int(left.Hours() / 24)
		when := exp.Format("2 January 2006")
		switch {
		case left < 0:
			out = append(out, Finding{Code: "registration_expired", Severity: "critical",
				Title:          "Domain expired",
				Message:        r.Domain + " expired on " + when + ". Websites and email on it may stop working at any time.",
				Recommendation: "Renew it at the registrar" + registrarSuffix(r) + " now, before it enters redemption and costs more to restore."})
		case days <= 30:
			out = append(out, Finding{Code: "registration_expiring_soon", Severity: "warning",
				Title:          "Expires within 30 days",
				Message:        r.Domain + " expires on " + when + ", in " + plural(days, "day", "days") + ".",
				Recommendation: "Renew it now, or confirm auto-renew is on and the payment card on file is valid."})
		case days <= 60:
			out = append(out, Finding{Code: "registration_expiring", Severity: "info",
				Title:   "Expires within 60 days",
				Message: r.Domain + " expires on " + when + ", in " + strconv.Itoa(days) + " days. Worth confirming auto-renew is on."})
		}
	}
	if s := slices.DeleteFunc(slices.Clone(r.Statuses), func(s string) bool { return !slices.Contains(registrationHolds, s) }); len(s) > 0 {
		out = append(out, Finding{Code: "registration_on_hold", Severity: "critical",
			Title:          "Domain is on hold",
			Message:        r.Domain + " has status " + strings.Join(s, ", ") + ": the registry has removed it from DNS, so its website and email are down. A clientHold is set by the registrar (often an unpaid renewal or unverified contact email); a serverHold by the registry (often a legal or abuse action).",
			Recommendation: "Contact the registrar" + registrarSuffix(r) + " to find out why and get the hold lifted."})
	}
	if s := slices.DeleteFunc(slices.Clone(r.Statuses), func(s string) bool { return !slices.Contains(registrationDeletion, s) }); len(s) > 0 {
		out = append(out, Finding{Code: "registration_pending_delete", Severity: "critical",
			Title:          "Domain is being deleted",
			Message:        r.Domain + " has status " + strings.Join(s, ", ") + ": it expired and is on its way to being released. During the redemption period the registrar can still restore it, for a fee; once pending delete it cannot be saved.",
			Recommendation: "Ask the registrar" + registrarSuffix(r) + " to restore it immediately if it is still in redemption."})
	}
	if !slices.ContainsFunc(out, func(f Finding) bool { return f.Severity == "critical" || f.Severity == "warning" }) {
		msg := r.Domain + " is registered"
		if r.Registrar != "" {
			msg += " with " + r.Registrar
		}
		if exp, err := time.Parse(time.RFC3339, r.Expires); err == nil {
			msg += " until " + exp.Format("2 January 2006")
		}
		out = append(out, Finding{Code: "registration_ok", Severity: "ok", Title: "Registered", Message: msg + "."})
	}
	return out
}

func registrarSuffix(r registrationResult) string {
	if r.Registrar == "" {
		return ""
	}
	return " (" + r.Registrar + ")"
}
