package app

import (
	"cmp"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

func init() {
	registerCheck(check{
		key:   "email_auth",
		label: "Email Authentication",
		kinds: []string{kindDomain},
		options: []Option{
			{Key: "scope", Label: "Scope", Choices: []string{"all", "spf", "dkim", "dmarc"}, Default: "all"},
			{Key: "selectors", Label: "DKIM selectors", Default: ""},
		},
		run:      emailAuth,
		findings: emailAuthFindings,
	})
}

// Bundled reference data: DKIM selectors the common mail providers use.
var dkimCommonSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim", "email", "smtp",
	"mandrill", "mailchimp", "mxvault", "zoho", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3",
	"everlytickey1", "everlytickey2", "mailjet", "sendgrid", "smtpapi", "amazonses", "mailgun", "mg", "pm",
	"zendesk1", "zendesk2", "hs1", "hs2", "mimecast",
}

const (
	spfMaxLookups  = 10 // RFC 7208 4.6.4
	spfMaxVoids    = 2
	spfLookupCap   = 30 // stop resolving past this, so a runaway tree can't eat the Check timeout
	dkimMaxCustom  = 20
	emailMaxCNAMEs = 8
)

type emailAuthResult struct {
	Scope string       `json:"scope"`
	SPF   *spfResult   `json:"spf,omitempty"`
	DKIM  *dkimResult  `json:"dkim,omitempty"`
	DMARC *dmarcResult `json:"dmarc,omitempty"`
}

type spfResult struct {
	Records     []string `json:"records"`         // every v=spf1 record at the domain
	Tree        *spfNode `json:"tree,omitempty"`  // the single record, flattened through includes and redirects
	All         string   `json:"all,omitempty"`   // the effective all: +all, -all, ~all, ?all; empty if none, "unknown" behind an unresolved redirect
	Lookups     int      `json:"lookups"`         // DNS-querying terms, counted across the tree
	VoidLookups int      `json:"void_lookups"`    // lookups that found nothing
	Truncated   bool     `json:"truncated"`       // stopped resolving past spfLookupCap
	Errors      []string `json:"errors"`          // permerror causes other than the lookup limit
	Failed      []string `json:"failed"`          // lookups inside the tree that got no answer
	Error       string   `json:"error,omitempty"` // the domain's own TXT lookup got no answer
}

type spfNode struct {
	Domain string    `json:"domain"`
	Record string    `json:"record,omitempty"`
	Terms  []spfTerm `json:"terms,omitempty"`
	Error  string    `json:"error,omitempty"`
}

type spfTerm struct {
	Qualifier string   `json:"qualifier,omitempty"` // as written: + - ~ ? or empty
	Name      string   `json:"name"`                // mechanism or modifier: include, a, ip4, redirect…
	Value     string   `json:"value,omitempty"`
	Lookup    bool     `json:"lookup,omitempty"` // counts toward the 10-lookup limit
	Void      bool     `json:"void,omitempty"`
	Target    *spfNode `json:"target,omitempty"` // the resolved include or redirect
}

type dkimResult struct {
	Checked []string  `json:"checked"` // every selector queried, bundled then custom
	Custom  []string  `json:"custom"`
	Keys    []dkimKey `json:"keys"`
	Failed  []string  `json:"failed"` // selectors whose lookup got no answer
}

type dkimKey struct {
	Selector string `json:"selector"`
	CNAME    string `json:"cname,omitempty"`
	Record   string `json:"record"`
	KeyType  string `json:"key_type"`
	Bits     int    `json:"bits,omitempty"` // RSA modulus size, when the key parses
	Revoked  bool   `json:"revoked"`
	Error    string `json:"error,omitempty"` // why the key didn't parse
}

type dmarcResult struct {
	Records []string `json:"records"`
	Policy  string   `json:"policy,omitempty"`
	SubPol  string   `json:"subdomain_policy,omitempty"`
	Pct     int      `json:"pct"`
	RUA     []string `json:"rua"`
	RUF     []string `json:"ruf"`
	ADKIM   string   `json:"adkim,omitempty"`
	ASPF    string   `json:"aspf,omitempty"`
	Error   string   `json:"error,omitempty"`
}

var dkimSelectorRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$`)

func emailAuth(ctx context.Context, n Net, target string, opts map[string]string) (any, error) {
	scope := opts["scope"]
	if scope == "" {
		scope = "all"
	}
	in := func(part string) bool { return scope == "all" || scope == part }
	var custom []string
	for _, s := range strings.FieldsFunc(strings.ToLower(opts["selectors"]), func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\t' || r == '\n' }) {
		if !dkimSelectorRe.MatchString(s) {
			return nil, fmt.Errorf("%q is not a valid DKIM selector", s)
		}
		if !slices.Contains(custom, s) {
			custom = append(custom, s)
		}
	}
	if len(custom) > dkimMaxCustom {
		return nil, fmt.Errorf("at most %d custom DKIM selectors", dkimMaxCustom)
	}

	res := emailAuthResult{Scope: scope}
	var wg sync.WaitGroup
	if in("spf") {
		wg.Go(func() { res.SPF = spfAudit(ctx, n, target) })
	}
	if in("dkim") {
		wg.Go(func() { res.DKIM = dkimAudit(ctx, n, target, custom) })
	}
	if in("dmarc") {
		wg.Go(func() { res.DMARC = dmarcAudit(ctx, n, target) })
	}
	wg.Wait()

	// The Step fails only if nothing in scope got an answer.
	if (res.SPF == nil || res.SPF.Error != "") && (res.DMARC == nil || res.DMARC.Error != "") &&
		(res.DKIM == nil || len(res.DKIM.Failed) == len(res.DKIM.Checked)) {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("timed out waiting for DNS resolver " + n.Resolver)
		}
		return nil, errors.New("no answer from DNS resolver " + n.Resolver)
	}
	return res, nil
}

// emailExchange sends one query, retrying over TCP when truncated. Any rcode
// other than NOERROR or NXDOMAIN is an error.
func emailExchange(ctx context.Context, n Net, name string, qt uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	r, _, err := (&dns.Client{}).ExchangeContext(ctx, m, n.Resolver)
	if err == nil && r.Truncated {
		r, _, err = (&dns.Client{Net: "tcp"}).ExchangeContext(ctx, m, n.Resolver)
	}
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, errors.New(dns.RcodeToString[r.Rcode])
	}
	return r, nil
}

// emailTXT returns the TXT records at name, each RR's strings joined, following
// CNAMEs; cname is the last alias followed.
func emailTXT(ctx context.Context, n Net, name string) (txts []string, cname string, err error) {
	for range emailMaxCNAMEs {
		r, err := emailExchange(ctx, n, name, dns.TypeTXT)
		if err != nil {
			return nil, cname, err
		}
		for _, rr := range r.Answer {
			switch v := rr.(type) {
			case *dns.TXT:
				txts = append(txts, strings.Join(v.Txt, ""))
			case *dns.CNAME:
				cname = strings.TrimSuffix(v.Target, ".")
			}
		}
		if len(r.Answer) > 0 || r.Rcode == dns.RcodeNameError {
			return txts, cname, nil
		}
		// A resolver chases CNAMEs itself; a stub or authoritative server may not.
		c, err := emailExchange(ctx, n, name, dns.TypeCNAME)
		if err != nil {
			return nil, cname, err
		}
		i := slices.IndexFunc(c.Answer, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeCNAME })
		if i == -1 {
			return nil, cname, nil
		}
		name = c.Answer[i].(*dns.CNAME).Target
		cname = strings.TrimSuffix(name, ".")
	}
	return nil, cname, errors.New("CNAME chain too long at " + name)
}

// emailCount counts qt records at name (0 for NXDOMAIN).
func emailCount(ctx context.Context, n Net, name string, qt uint16) (int, error) {
	r, err := emailExchange(ctx, n, name, qt)
	if err != nil {
		return 0, err
	}
	return len(slices.DeleteFunc(r.Answer, func(rr dns.RR) bool { return rr.Header().Rrtype != qt })), nil
}

func spfRecords(txts []string) []string {
	return slices.DeleteFunc(slices.Clone(txts), func(t string) bool {
		f := strings.Fields(t)
		return len(f) == 0 || !strings.EqualFold(f[0], "v=spf1")
	})
}

// spfAudit fetches the domain's SPF record and walks it: no IP is evaluated,
// it only counts lookups and finds the errors that make it a permerror.
func spfAudit(ctx context.Context, n Net, domain string) *spfResult {
	res := &spfResult{Records: []string{}, Errors: []string{}, Failed: []string{}}
	txts, _, err := emailTXT(ctx, n, domain)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Records = spfRecords(txts)
	if len(res.Records) != 1 {
		return res
	}
	w := spfWalker{ctx: ctx, n: n, res: res}
	res.Tree = &spfNode{Domain: domain, Record: res.Records[0]}
	w.walk(res.Tree, []string{domain})
	res.All = spfAll(res.Tree)
	if res.VoidLookups > spfMaxVoids {
		res.Errors = append(res.Errors, fmt.Sprintf("%d void lookups (limit %d)", res.VoidLookups, spfMaxVoids))
	}
	return res
}

type spfWalker struct {
	ctx context.Context
	n   Net
	res *spfResult
}

func (w *spfWalker) errorf(format string, a ...any) {
	w.res.Errors = append(w.res.Errors, fmt.Sprintf(format, a...))
}

// walk parses node.Record into terms, resolving includes and redirect.
// path holds the domains above this node, to catch loops.
func (w *spfWalker) walk(node *spfNode, path []string) {
	domain := node.Domain
	var hasAll bool
	redirect := -1
	for _, tok := range strings.Fields(node.Record)[1:] {
		t := spfTerm{}
		if i := strings.IndexAny(tok, "=:/"); i > 0 && tok[i] == '=' {
			t.Name, t.Value = strings.ToLower(tok[:i]), tok[i+1:]
			if (t.Name == "redirect" || t.Name == "exp") && slices.ContainsFunc(node.Terms, func(x spfTerm) bool { return x.Name == t.Name }) {
				w.errorf("%s: more than one %s= modifier", domain, t.Name)
			}
			if t.Name == "redirect" {
				t.Lookup = true
				redirect = len(node.Terms)
			}
			node.Terms = append(node.Terms, t)
			continue
		}
		if strings.ContainsRune("+-~?", rune(tok[0])) {
			t.Qualifier, tok = tok[:1], tok[1:]
		}
		name, rest, _ := strings.Cut(tok, ":")
		if i := strings.IndexByte(name, '/'); i >= 0 && rest == "" {
			name, rest = name[:i], name[i:]
		}
		t.Name, t.Value = strings.ToLower(name), rest
		switch t.Name {
		case "all":
			hasAll = true
			if t.Value != "" {
				w.errorf("%s: bad term %q", domain, tok)
			}
		case "include", "exists":
			t.Lookup = true
			if t.Value == "" {
				w.errorf("%s: %s needs a domain", domain, t.Name)
			}
		case "a", "mx", "ptr":
			t.Lookup = true
		case "ip4", "ip6":
			if !spfValidIP(t.Name, t.Value) {
				w.errorf("%s: bad address %q", domain, tok)
			}
		default:
			w.errorf("%s: unknown mechanism %q", domain, tok)
		}
		node.Terms = append(node.Terms, t)
	}

	for i := range node.Terms {
		t := &node.Terms[i]
		if !t.Lookup || (t.Name == "redirect" && hasAll) { // redirect is ignored when all is present
			continue
		}
		w.res.Lookups++
		if w.res.Lookups > spfLookupCap {
			w.res.Truncated = true
			continue
		}
		if strings.Contains(t.Value, "%") {
			continue // a macro expands per message; nothing to resolve
		}
		switch t.Name {
		case "include", "redirect":
			if t.Value == "" {
				continue
			}
			t.Target = w.resolve(strings.ToLower(strings.TrimSuffix(t.Value, ".")), path, i == redirect)
		case "a", "mx", "exists":
			host, _, _ := strings.Cut(t.Value, "/")
			if host == "" {
				host = domain
			}
			var found int
			var err error
			switch t.Name {
			case "mx":
				found, err = emailCount(w.ctx, w.n, host, dns.TypeMX)
			default: // a, exists
				if found, err = emailCount(w.ctx, w.n, host, dns.TypeA); err == nil && found == 0 && t.Name == "a" {
					found, err = emailCount(w.ctx, w.n, host, dns.TypeAAAA)
				}
			}
			if err != nil {
				w.res.Failed = append(w.res.Failed, t.Name+":"+host+": "+err.Error())
			} else if found == 0 {
				t.Void = true
				w.res.VoidLookups++
			}
		}
	}
}

// resolve fetches and walks the SPF record an include or redirect points at.
func (w *spfWalker) resolve(domain string, path []string, redirect bool) *spfNode {
	node := &spfNode{Domain: domain}
	kind := "include"
	if redirect {
		kind = "redirect"
	}
	if slices.Contains(path, domain) {
		node.Error = "loop"
		w.errorf("%s loops back to %s", kind, domain)
		return node
	}
	txts, _, err := emailTXT(w.ctx, w.n, domain)
	if err != nil {
		node.Error = "lookup failed: " + err.Error()
		w.res.Failed = append(w.res.Failed, kind+":"+domain+": "+err.Error())
		return node
	}
	recs := spfRecords(txts)
	switch len(recs) {
	case 0:
		node.Error = "no SPF record"
		if len(txts) == 0 {
			w.res.VoidLookups++
		}
		w.errorf("%s target %s has no SPF record", kind, domain)
	case 1:
		node.Record = recs[0]
		w.walk(node, append(slices.Clone(path), domain))
	default:
		node.Error = "multiple SPF records"
		w.errorf("%s target %s has %d SPF records", kind, domain, len(recs))
	}
	return node
}

func spfValidIP(kind, v string) bool {
	var a netip.Addr
	var err error
	if strings.Contains(v, "/") {
		var p netip.Prefix
		p, err = netip.ParsePrefix(v)
		a = p.Addr()
	} else {
		a, err = netip.ParseAddr(v)
	}
	return err == nil && (kind == "ip4") == a.Is4()
}

// spfAll is the all that ends evaluation: the record's own, else its redirect's.
func spfAll(node *spfNode) string {
	if node == nil {
		return ""
	}
	for _, t := range node.Terms {
		if t.Name == "all" {
			return cmp.Or(t.Qualifier, "+") + "all"
		}
	}
	for _, t := range node.Terms {
		if t.Name == "redirect" {
			if t.Target == nil || t.Target.Error != "" {
				return "unknown" // unresolved: a macro, the lookup cap, or a failed or broken target
			}
			return spfAll(t.Target)
		}
	}
	return ""
}

// emailTags parses a DKIM or DMARC tag list; whitespace inside values is dropped.
func emailTags(rec string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(k))] = strings.Join(strings.Fields(v), "")
	}
	return tags
}

func dkimAudit(ctx context.Context, n Net, domain string, custom []string) *dkimResult {
	res := &dkimResult{Checked: slices.Clone(dkimCommonSelectors), Custom: []string{}, Keys: []dkimKey{}, Failed: []string{}}
	for _, s := range custom {
		res.Custom = append(res.Custom, s)
		if !slices.Contains(res.Checked, s) {
			res.Checked = append(res.Checked, s)
		}
	}
	keys := make([][]dkimKey, len(res.Checked))
	failed := make([]bool, len(res.Checked))
	var wg sync.WaitGroup
	for i, sel := range res.Checked {
		wg.Go(func() {
			txts, cname, err := emailTXT(ctx, n, sel+"._domainkey."+domain)
			if err != nil {
				failed[i] = true
				return
			}
			for _, t := range txts {
				tags := emailTags(t)
				if _, hasP := tags["p"]; !hasP && !strings.EqualFold(tags["v"], "DKIM1") {
					continue
				}
				keys[i] = append(keys[i], dkimParse(sel, cname, t, tags))
			}
		})
	}
	wg.Wait()
	for i, sel := range res.Checked {
		res.Keys = append(res.Keys, keys[i]...)
		if failed[i] {
			res.Failed = append(res.Failed, sel)
		}
	}
	return res
}

func dkimParse(sel, cname, rec string, tags map[string]string) dkimKey {
	k := dkimKey{Selector: sel, CNAME: cname, Record: rec, KeyType: strings.ToLower(cmp.Or(tags["k"], "rsa"))}
	p, ok := tags["p"]
	switch {
	case !ok:
		k.Error = "no p= tag"
	case p == "":
		k.Revoked = true
	case k.KeyType == "rsa":
		der, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			k.Error = "public key is not valid base64"
			break
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil { // some publish a bare PKCS#1 key
			pub, err = x509.ParsePKCS1PublicKey(der)
		}
		if rsaPub, isRSA := pub.(*rsa.PublicKey); err == nil && isRSA {
			k.Bits = rsaPub.N.BitLen()
		} else {
			k.Error = "public key does not parse as RSA"
		}
	}
	return k
}

func dmarcAudit(ctx context.Context, n Net, domain string) *dmarcResult {
	res := &dmarcResult{Records: []string{}, RUA: []string{}, RUF: []string{}}
	txts, _, err := emailTXT(ctx, n, "_dmarc."+domain)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	for _, t := range txts {
		if v, _, _ := strings.Cut(t, ";"); strings.EqualFold(strings.Join(strings.Fields(v), ""), "v=DMARC1") {
			res.Records = append(res.Records, t)
		}
	}
	if len(res.Records) != 1 {
		return res
	}
	tags := emailTags(res.Records[0])
	res.Policy, res.SubPol = strings.ToLower(tags["p"]), strings.ToLower(tags["sp"])
	res.ADKIM, res.ASPF = strings.ToLower(cmp.Or(tags["adkim"], "r")), strings.ToLower(cmp.Or(tags["aspf"], "r"))
	res.Pct = 100
	if v, err := strconv.Atoi(tags["pct"]); err == nil && v >= 0 && v <= 100 {
		res.Pct = v
	}
	for _, u := range strings.Split(tags["rua"], ",") {
		if u != "" {
			res.RUA = append(res.RUA, u)
		}
	}
	for _, u := range strings.Split(tags["ruf"], ",") {
		if u != "" {
			res.RUF = append(res.RUF, u)
		}
	}
	return res
}

func emailAuthFindings(target, _ string, _ map[string]string, raw json.RawMessage) []Finding {
	var r emailAuthResult
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	var fs []Finding
	if r.SPF != nil {
		fs = append(fs, spfFindings(target, r.SPF)...)
	}
	if r.DKIM != nil {
		fs = append(fs, dkimFindings(target, r.DKIM)...)
	}
	if r.DMARC != nil {
		fs = append(fs, dmarcFindings(target, r.DMARC)...)
	}
	return fs
}

func spfFindings(target string, r *spfResult) []Finding {
	switch {
	case r.Error != "":
		return []Finding{{Code: "spf_lookup_failed", Severity: "warning",
			Title:          "SPF lookup failed",
			Message:        "The TXT lookup for " + target + " got no answer (" + r.Error + "), so its SPF record is unknown.",
			Recommendation: "Re-run; if it keeps failing, check the domain's nameservers."}}
	case len(r.Records) == 0:
		return []Finding{{Code: "spf_missing", Severity: "warning",
			Title:          "No SPF record",
			Message:        target + " publishes no SPF record, so receivers can't tell which servers may send its mail.",
			Recommendation: "Publish one TXT record starting v=spf1 listing the domain's senders, ending in ~all or -all."}}
	case len(r.Records) > 1:
		return []Finding{{Code: "spf_multiple", Severity: "critical",
			Title:          "Multiple SPF records",
			Message:        target + " publishes " + strconv.Itoa(len(r.Records)) + " v=spf1 records. That is a permerror: receivers treat SPF as broken.",
			Recommendation: "Merge them into a single v=spf1 record."}}
	}
	var fs []Finding
	if r.Lookups > spfMaxLookups {
		at := strconv.Itoa(r.Lookups)
		if r.Truncated {
			at = "more than " + strconv.Itoa(spfLookupCap)
		}
		fs = append(fs, Finding{Code: "spf_too_many_lookups", Severity: "critical",
			Title:          "Too many SPF lookups",
			Message:        "Evaluating " + target + "'s SPF record takes " + at + " DNS lookups; the limit is 10, past which receivers return permerror.",
			Recommendation: "Remove unused includes, or replace includes and a/mx terms with ip4/ip6 ranges."})
	}
	if len(r.Errors) > 0 {
		fs = append(fs, Finding{Code: "spf_permerror", Severity: "critical",
			Title:          "SPF record is broken",
			Message:        "Receivers will return permerror for " + target + ": " + strings.Join(r.Errors, "; ") + ".",
			Recommendation: "Fix the listed terms; an include must point at a domain with exactly one SPF record."})
	}
	if len(r.Failed) > 0 {
		fs = append(fs, Finding{Code: "spf_lookup_failed", Severity: "warning",
			Title:   "Some SPF lookups failed",
			Message: "These lookups got no answer, so the counts above may be low: " + strings.Join(r.Failed, "; ") + "."})
	}
	switch r.All {
	case "+all":
		fs = append(fs, Finding{Code: "spf_pass_all", Severity: "critical",
			Title:          "SPF allows any sender (+all)",
			Message:        target + "'s SPF record ends in +all, authorising every server on the internet to send as it.",
			Recommendation: "Change +all to ~all or -all once the real senders are listed."})
	case "?all":
		fs = append(fs, Finding{Code: "spf_neutral_all", Severity: "warning",
			Title:          "SPF is neutral (?all)",
			Message:        target + "'s SPF record ends in ?all, so unlisted senders get no verdict and spoofing isn't discouraged.",
			Recommendation: "Change ?all to ~all or -all."})
	case "":
		fs = append(fs, Finding{Code: "spf_no_all", Severity: "warning",
			Title:          "SPF has no all",
			Message:        target + "'s SPF record has no all term, so mail from unlisted senders gets a neutral result.",
			Recommendation: "End the record with ~all or -all."})
	case "~all":
		fs = append(fs, Finding{Code: "spf_softfail_all", Severity: "info",
			Title:   "SPF softfails unlisted senders (~all)",
			Message: "Mail from servers " + target + "'s SPF record doesn't list is marked suspicious, not rejected. Common, and safe while senders are being audited; -all is stricter."})
	case "-all":
		fs = append(fs, Finding{Code: "spf_fail_all", Severity: "ok",
			Title: "SPF rejects unlisted senders (-all)", Message: target + "'s SPF record ends in -all."})
	}
	return fs
}

func dkimFindings(target string, r *dkimResult) []Finding {
	// One Finding per code, listing selectors: the UI keys Findings on code, Target and Step.
	var active, revoked, invalid, weak, short []string
	add := func(list *[]string, s string) {
		if !slices.Contains(*list, s) {
			*list = append(*list, s)
		}
	}
	for _, k := range r.Keys {
		sized := k.Selector + " (" + strconv.Itoa(k.Bits) + "-bit)"
		switch {
		case k.Revoked:
			add(&revoked, k.Selector)
			continue
		case k.Error != "":
			add(&invalid, k.Selector+" ("+k.Error+")")
			continue
		case k.Bits > 0 && k.Bits < 1024:
			add(&weak, sized)
		case k.Bits > 0 && k.Bits < 2048:
			add(&short, sized)
		}
		add(&active, k.Selector)
	}
	var out []Finding
	if len(revoked) > 0 {
		out = append(out, Finding{Code: "dkim_revoked", Severity: "info",
			Title: "Revoked DKIM key", Message: "An empty key (p=) means revoked; these selectors can't verify mail: " + strings.Join(revoked, ", ") + "."})
	}
	if len(invalid) > 0 {
		out = append(out, Finding{Code: "dkim_invalid_key", Severity: "warning",
			Title:          "Unusable DKIM key",
			Message:        "Receivers can't verify mail signed with these selectors: " + strings.Join(invalid, "; ") + ".",
			Recommendation: "Republish the key exactly as the mail provider gives it; long keys are often truncated or mangled when pasted."})
	}
	if len(weak) > 0 {
		out = append(out, Finding{Code: "dkim_weak_key", Severity: "critical",
			Title:          "DKIM key too short",
			Message:        "RSA keys under 1024 bits are ignored by receivers and can be factored: " + strings.Join(weak, ", ") + ".",
			Recommendation: "Rotate to a 2048-bit key with the mail provider."})
	}
	if len(short) > 0 {
		out = append(out, Finding{Code: "dkim_short_key", Severity: "warning",
			Title:          "DKIM key below 2048 bits",
			Message:        "2048 bits is the current recommendation: " + strings.Join(short, ", ") + ".",
			Recommendation: "Rotate to a 2048-bit key when the provider allows it."})
	}
	if len(active) > 0 {
		return append(out, Finding{Code: "dkim_found", Severity: "ok",
			Title: "DKIM key published", Message: target + " publishes DKIM keys for " + strings.Join(active, ", ") + "."})
	}
	msg := "None of the " + strconv.Itoa(len(r.Checked)) + " selectors checked has an active DKIM key for " + target
	if len(r.Custom) > 0 {
		msg += " (including " + strings.Join(r.Custom, ", ") + ")"
	}
	msg += ". A provider may use a selector not on the list."
	if len(r.Failed) > 0 {
		msg += " " + plural(len(r.Failed), "selector", "selectors") + " could not be queried."
	}
	return append(out, Finding{Code: "dkim_missing", Severity: "warning",
		Title:          "No DKIM key found",
		Message:        msg,
		Recommendation: "Find the selector in the s= tag of a DKIM-Signature header from a real message and add it under \"Check more DKIM selectors\"; if mail isn't signed, enable DKIM with the provider."})
}

func dmarcFindings(target string, r *dmarcResult) []Finding {
	switch {
	case r.Error != "":
		return []Finding{{Code: "dmarc_lookup_failed", Severity: "warning",
			Title:          "DMARC lookup failed",
			Message:        "The TXT lookup for _dmarc." + target + " got no answer (" + r.Error + "), so its DMARC policy is unknown.",
			Recommendation: "Re-run; if it keeps failing, check the domain's nameservers."}}
	case len(r.Records) == 0:
		return []Finding{{Code: "dmarc_missing", Severity: "warning",
			Title:          "No DMARC record",
			Message:        "_dmarc." + target + " has no DMARC record, so receivers apply no policy to mail failing SPF and DKIM, and nobody gets reports.",
			Recommendation: "Publish v=DMARC1; p=none; rua=mailto:… to start collecting reports, then tighten to quarantine or reject."}}
	case len(r.Records) > 1:
		return []Finding{{Code: "dmarc_multiple", Severity: "warning",
			Title:          "Multiple DMARC records",
			Message:        "_dmarc." + target + " has " + strconv.Itoa(len(r.Records)) + " DMARC records, so receivers ignore DMARC for it entirely.",
			Recommendation: "Keep a single v=DMARC1 record."}}
	}
	var fs []Finding
	switch r.Policy {
	case "none":
		fs = append(fs, Finding{Code: "dmarc_policy_none", Severity: "warning",
			Title:          "DMARC is monitoring only (p=none)",
			Message:        target + "'s DMARC policy is none: failing mail is delivered as usual, so spoofing is reported but not stopped.",
			Recommendation: "Once reports show legitimate mail passing, move to p=quarantine, then p=reject."})
	case "quarantine", "reject":
		fs = append(fs, Finding{Code: "dmarc_enforced", Severity: "ok",
			Title: "DMARC enforced (p=" + r.Policy + ")", Message: "Receivers " + map[string]string{"quarantine": "send failing mail to spam", "reject": "reject failing mail"}[r.Policy] + " for " + target + "."})
	default:
		fs = append(fs, Finding{Code: "dmarc_invalid_policy", Severity: "warning",
			Title:          "DMARC record has no valid policy",
			Message:        "_dmarc." + target + " has no valid p= tag (none, quarantine or reject), so receivers may ignore the record.",
			Recommendation: "Add p=none, p=quarantine or p=reject."})
	}
	if r.Pct < 100 {
		fs = append(fs, Finding{Code: "dmarc_partial", Severity: "info",
			Title: "DMARC applies to " + strconv.Itoa(r.Pct) + "% of mail", Message: "pct=" + strconv.Itoa(r.Pct) + ": the policy is applied to only part of failing mail; the rest gets the next weaker treatment."})
	}
	if len(r.RUA) == 0 {
		fs = append(fs, Finding{Code: "dmarc_no_rua", Severity: "info",
			Title:          "No DMARC aggregate reports",
			Message:        "The DMARC record has no rua= address, so nobody sees which servers send as " + target + ".",
			Recommendation: "Add rua=mailto:<mailbox> to receive daily aggregate reports."})
	}
	return fs
}
