package app

import (
	"fmt"
	"net/mail"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

func init() {
	registerAnalyser(analyser{
		kind:     "email_headers",
		label:    "email headers",
		analyse:  func(raw string) (any, error) { return analyseHeaders(raw) },
		findings: func(a any) []Finding { return headerFindings(a.(headerAnalysis)) },
		suggest:  func(a any) []Suggestion { return headerSuggestions(a.(headerAnalysis)) },
	})
}

type headerSummary struct {
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Date       string `json:"date,omitempty"`
	MessageID  string `json:"message_id,omitempty"`
	ReturnPath string `json:"return_path,omitempty"`
	ReplyTo    string `json:"reply_to,omitempty"`
}

type hop struct {
	FromHost string     `json:"from_host,omitempty"`
	FromIP   string     `json:"from_ip,omitempty"`
	ByHost   string     `json:"by_host,omitempty"`
	With     string     `json:"with,omitempty"`
	At       *time.Time `json:"at,omitempty"`
	DelayS   *float64   `json:"delay_s,omitempty"` // since the previous hop
}

type authResults struct {
	SPF        string `json:"spf,omitempty"`
	DKIM       string `json:"dkim,omitempty"`
	DMARC      string `json:"dmarc,omitempty"`
	CompAuth   string `json:"compauth,omitempty"`
	DKIMDomain string `json:"dkim_domain,omitempty"`
}

type alignment struct {
	FromDomain            string `json:"from_domain,omitempty"`
	ReturnPathDomain      string `json:"return_path_domain,omitempty"`
	MessageIDDomain       string `json:"message_id_domain,omitempty"`
	DKIMDomain            string `json:"dkim_domain,omitempty"`
	FromReturnPathAligned *bool  `json:"from_return_path_aligned,omitempty"`
	MessageIDAligned      *bool  `json:"message_id_aligned,omitempty"`
	DKIMAligned           *bool  `json:"dkim_aligned,omitempty"`
}

type spamSignals struct {
	Score    *float64 `json:"score,omitempty"`
	Required *float64 `json:"required,omitempty"`
	SCL      *int     `json:"scl,omitempty"` // Microsoft spam confidence level
	Flagged  bool     `json:"flagged"`
}

type headerAnalysis struct {
	Headers       headerSummary `json:"headers"`
	Hops          []hop         `json:"hops"` // oldest first
	TotalTransitS *float64      `json:"total_transit_s,omitempty"`
	// OriginIP is the earliest public address in the chain. Those lines are
	// the sender's to write, so it can be forged. DeliveringIP is the latest:
	// recorded by the recipient's own server about who connected to it.
	OriginIP     string      `json:"origin_ip,omitempty"`
	DeliveringIP string      `json:"delivering_ip,omitempty"`
	Auth         authResults `json:"auth"`
	Alignment    alignment   `json:"alignment"`
	Spam         spamSignals `json:"spam"`
}

var (
	quoteMarks  = regexp.MustCompile(`^(\s*>\s?)+`)
	headerLine  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]*):\s?(.*)$`)
	knownHeader = []string{"from", "to", "subject", "date", "received", "message-id", "return-path",
		"authentication-results", "delivered-to", "dkim-signature", "reply-to"}
)

// parseHeaderBlock reads a pasted header block the way reps paste it: with
// forward quote marks, folded lines, and the body after the first blank
// line (ignored). Values are kept in order per lower-cased name.
func parseHeaderBlock(raw string) map[string][]string {
	h := map[string][]string{}
	var last string
	seen := false
	for line := range strings.SplitSeq(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = quoteMarks.ReplaceAllString(line, "")
		if strings.TrimSpace(line) == "" {
			if seen {
				break // the body starts here
			}
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && last != "" {
			vs := h[last]
			vs[len(vs)-1] += " " + strings.TrimSpace(line)
			continue
		}
		if m := headerLine.FindStringSubmatch(line); m != nil {
			last = strings.ToLower(m[1])
			h[last] = append(h[last], strings.TrimSpace(m[2]))
			seen = true
		}
	}
	return h
}

func first(h map[string][]string, name string) string {
	if v := h[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

var (
	receivedFrom = regexp.MustCompile(`(?i)\bfrom\s+(\S+)`)
	receivedIP   = regexp.MustCompile(`\[(?:IPv6:)?([0-9a-fA-F:.]+)\]`)
	receivedBy   = regexp.MustCompile(`(?i)\bby\s+(\S+)`)
	receivedWith = regexp.MustCompile(`(?i)\bwith\s+(\S+)`)
	authPart     = regexp.MustCompile(`(?i)^\s*(spf|dkim|dmarc|compauth)\s*=\s*([a-z]+)`)
	authDKIMDom  = regexp.MustCompile(`(?i)header\.d=([^\s;]+)`)
	authDKIMId   = regexp.MustCompile(`(?i)header\.i=[^@\s;]*@([^\s;]+)`)
	sigDomain    = regexp.MustCompile(`(?i)\bd=([^\s;]+)`)
	spamStatus   = regexp.MustCompile(`(?i)^(yes|no)\b.*?score=(-?[0-9.]+).*?required=(-?[0-9.]+)`)
	sclValue     = regexp.MustCompile(`(?i)\bSCL:(-?\d+)`)
)

// analyseHeaders is pure: it reads the text and nothing else.
func analyseHeaders(raw string) (headerAnalysis, error) {
	var a headerAnalysis
	h := parseHeaderBlock(raw)
	if !slices.ContainsFunc(knownHeader, func(k string) bool { return len(h[k]) > 0 }) {
		return a, errNotThisKind
	}
	a.Headers = headerSummary{
		From: first(h, "from"), To: first(h, "to"), Subject: first(h, "subject"), Date: first(h, "date"),
		MessageID: first(h, "message-id"), ReturnPath: first(h, "return-path"), ReplyTo: first(h, "reply-to"),
	}

	// Received headers are added newest first; the story reads oldest first.
	received := h["received"]
	a.Hops = []hop{}
	for i := len(received) - 1; i >= 0; i-- {
		r := received[i]
		route, date := r, "" // the date follows the last ';'
		if i := strings.LastIndex(r, ";"); i != -1 {
			route, date = r[:i], r[i+1:]
		}
		fromPart, _, _ := strings.Cut(route, " by ")
		var x hop
		if m := receivedFrom.FindStringSubmatch(fromPart); m != nil {
			x.FromHost = strings.Trim(m[1], "()")
		}
		if m := receivedIP.FindStringSubmatch(fromPart); m != nil {
			x.FromIP = m[1]
		}
		if m := receivedBy.FindStringSubmatch(route); m != nil {
			x.ByHost = m[1]
		}
		if m := receivedWith.FindStringSubmatch(route); m != nil {
			x.With = m[1]
		}
		if t, err := mail.ParseDate(strings.TrimSpace(date)); err == nil {
			x.At = &t
		}
		a.Hops = append(a.Hops, x)
	}
	for i := 1; i < len(a.Hops); i++ {
		if a.Hops[i].At != nil && a.Hops[i-1].At != nil {
			d := a.Hops[i].At.Sub(*a.Hops[i-1].At).Seconds()
			a.Hops[i].DelayS = &d
		}
	}
	if n := len(a.Hops); n > 1 && a.Hops[0].At != nil && a.Hops[n-1].At != nil {
		d := a.Hops[n-1].At.Sub(*a.Hops[0].At).Seconds()
		a.TotalTransitS = &d
	}
	for _, x := range a.Hops {
		if ip, err := netip.ParseAddr(x.FromIP); err == nil && publicIP(ip) {
			if a.OriginIP == "" {
				a.OriginIP = ip.String()
			}
			a.DeliveringIP = ip.String() // the last one wins
		}
	}

	// The topmost Authentication-Results is the receiving server's verdict.
	if ar := first(h, "authentication-results"); ar != "" {
		for part := range strings.SplitSeq(ar, ";") {
			if m := authPart.FindStringSubmatch(part); m != nil {
				v := strings.ToLower(m[2])
				switch strings.ToLower(m[1]) {
				case "spf":
					a.Auth.SPF = v
				case "dkim":
					if a.Auth.DKIM == "" || v == "pass" {
						a.Auth.DKIM = v
						if d := authDKIMDom.FindStringSubmatch(part); d != nil {
							a.Auth.DKIMDomain = strings.ToLower(d[1])
						} else if d := authDKIMId.FindStringSubmatch(part); d != nil {
							a.Auth.DKIMDomain = strings.ToLower(d[1]) // Gmail reports header.i, not header.d
						}
					}
				case "dmarc":
					a.Auth.DMARC = v
				case "compauth":
					a.Auth.CompAuth = v
				}
			}
		}
	}

	al := &a.Alignment
	al.FromDomain = addressDomain(a.Headers.From)
	al.ReturnPathDomain = addressDomain(a.Headers.ReturnPath)
	al.MessageIDDomain = addressDomain(strings.Trim(a.Headers.MessageID, "<>"))
	// Only a signature the receiving server verified can align the sender:
	// anyone can write a DKIM-Signature header claiming any domain.
	if a.Auth.DKIM == "pass" {
		al.DKIMDomain = a.Auth.DKIMDomain
		if m := sigDomain.FindStringSubmatch(first(h, "dkim-signature")); al.DKIMDomain == "" && m != nil {
			al.DKIMDomain = strings.ToLower(m[1])
		}
	}
	al.FromReturnPathAligned = aligned(al.FromDomain, al.ReturnPathDomain)
	al.MessageIDAligned = aligned(al.FromDomain, al.MessageIDDomain)
	al.DKIMAligned = aligned(al.FromDomain, al.DKIMDomain)

	sp := &a.Spam
	for _, k := range []string{"x-spam-score", "x-spamd-score"} {
		if f, err := strconv.ParseFloat(strings.Fields(first(h, k) + " x")[0], 64); err == nil {
			sp.Score = &f
		}
	}
	if m := spamStatus.FindStringSubmatch(first(h, "x-spam-status")); m != nil {
		score, _ := strconv.ParseFloat(m[2], 64)
		req, _ := strconv.ParseFloat(m[3], 64)
		sp.Score, sp.Required = &score, &req
		sp.Flagged = strings.EqualFold(m[1], "yes")
	}
	if strings.EqualFold(strings.TrimSpace(first(h, "x-spam-flag")), "yes") {
		sp.Flagged = true
	}
	if sp.Score != nil {
		req := 5.0 // SpamAssassin's default threshold
		if sp.Required != nil {
			req = *sp.Required
		}
		sp.Flagged = sp.Flagged || *sp.Score >= req
	}
	scl := first(h, "x-ms-exchange-organization-scl")
	if m := sclValue.FindStringSubmatch(first(h, "x-forefront-antispam-report")); scl == "" && m != nil {
		scl = m[1]
	}
	if n, err := strconv.Atoi(strings.TrimSpace(scl)); err == nil {
		sp.SCL = &n
		sp.Flagged = sp.Flagged || n >= 5
	}
	return a, nil
}

func publicIP(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() // IsPrivate covers RFC 1918 and IPv6 ULA (fc00::/7)
}

// addressDomain is the domain of an address such as "Name <a@b.com>" or "<a@b.com>".
func addressDomain(s string) string {
	if a, err := mail.ParseAddress(s); err == nil {
		s = a.Address
	}
	s = strings.Trim(strings.TrimSpace(s), "<>")
	if i := strings.LastIndex(s, "@"); i != -1 {
		return strings.ToLower(strings.TrimRight(s[i+1:], ">. "))
	}
	return ""
}

// aligned is DMARC-style relaxed alignment: the same organisational domain.
// nil when either side is missing.
func aligned(a, b string) *bool {
	if a == "" || b == "" {
		return nil
	}
	oa, err1 := publicsuffix.EffectiveTLDPlusOne(a)
	ob, err2 := publicsuffix.EffectiveTLDPlusOne(b)
	same := err1 == nil && err2 == nil && oa == ob
	return &same
}

func headerFindings(a headerAnalysis) []Finding {
	target := a.Alignment.FromDomain
	if target == "" {
		target = "pasted headers"
	}
	var out []Finding
	add := func(f Finding) {
		f.Target = target
		out = append(out, f)
	}
	au := a.Auth
	if au.SPF == "" && au.DKIM == "" && au.DMARC == "" {
		add(Finding{Code: "email_headers_no_auth_results", Severity: "info",
			Title:   "No authentication verdict",
			Message: "There is no Authentication-Results header: this copy wasn't checked by a receiving server, or the header was left out of the paste."})
	}
	switch au.SPF {
	case "", "pass":
	case "fail":
		add(Finding{Code: "email_headers_spf_fail", Severity: "critical", Title: "SPF failed",
			Message:        "The receiving server says the sending server isn't allowed to send for " + orUnknown(a.Alignment.ReturnPathDomain) + ".",
			Recommendation: "Add the sending service to the domain's SPF record, or check whether this message is forged."})
	default:
		add(Finding{Code: "email_headers_spf_fail", Severity: "warning", Title: "SPF " + au.SPF,
			Message:        "The receiving server's SPF result was " + au.SPF + ", not pass.",
			Recommendation: "Run Email Authentication on the sending domain to see its SPF record."})
	}
	switch au.DKIM {
	case "", "pass":
	case "none":
		add(Finding{Code: "email_headers_dkim_fail", Severity: "warning", Title: "Not DKIM-signed",
			Message:        "The message carried no DKIM signature the receiving server could check.",
			Recommendation: "Enable DKIM signing at the sending service."})
	default:
		add(Finding{Code: "email_headers_dkim_fail", Severity: "warning", Title: "DKIM " + au.DKIM,
			Message:        "The DKIM signature did not verify (" + au.DKIM + "). Forwarding or a mailing list that rewrites the message can cause this.",
			Recommendation: "Check the signing domain's published key with Email Authentication."})
	}
	switch au.DMARC {
	case "", "pass":
	case "fail":
		add(Finding{Code: "email_headers_dmarc_fail", Severity: "critical", Title: "DMARC failed",
			Message:        "Neither SPF nor DKIM passed in alignment with the From domain " + orUnknown(a.Alignment.FromDomain) + ", so receivers may reject or quarantine it.",
			Recommendation: "If this mail is legitimate, align SPF or DKIM with the From domain; if not, it is spoofed."})
	default:
		add(Finding{Code: "email_headers_dmarc_none", Severity: "info", Title: "No DMARC verdict (" + au.DMARC + ")",
			Message: "The receiving server reported DMARC as " + au.DMARC + "."})
	}
	if au.SPF == "pass" && au.DKIM == "pass" && au.DMARC == "pass" {
		add(Finding{Code: "email_headers_authenticated", Severity: "ok", Title: "Authenticated",
			Message: "SPF, DKIM and DMARC all passed at the receiving server."})
	}
	al := a.Alignment
	if al.FromReturnPathAligned != nil && !*al.FromReturnPathAligned && (al.DKIMAligned == nil || !*al.DKIMAligned) {
		add(Finding{Code: "email_headers_misaligned", Severity: "warning", Title: "Sender identities don't match",
			Message:        fmt.Sprintf("The From domain (%s) and the bounce address domain (%s) belong to different organisations, and no aligned DKIM signature ties them together.", al.FromDomain, al.ReturnPathDomain),
			Recommendation: "For legitimate mail sent through a provider, set a custom bounce domain or DKIM signing for the From domain."})
	}
	for i, x := range a.Hops {
		if x.DelayS != nil && *x.DelayS > 600 {
			add(Finding{Code: "email_headers_delayed", Severity: "warning", Title: "Delayed in transit",
				Message:        fmt.Sprintf("It waited %s between %s and %s.", minutes(*x.DelayS), orUnknown(a.Hops[i-1].ByHost), orUnknown(x.ByHost)),
				Recommendation: "Look for queueing, greylisting or a retry at that server; its logs will say why."})
			break
		}
	}
	if a.Spam.Flagged {
		msg := "The receiving side marked this message as spam"
		if a.Spam.Score != nil {
			msg += fmt.Sprintf(" (score %.1f)", *a.Spam.Score)
		}
		if a.Spam.SCL != nil {
			msg += fmt.Sprintf(" (Microsoft SCL %d)", *a.Spam.SCL)
		}
		add(Finding{Code: "email_headers_spam", Severity: "warning", Title: "Flagged as spam", Message: msg + ".",
			Recommendation: "Fix any authentication problems above first; then check content and sender reputation (Blacklist)."})
	}
	return out
}

func headerSuggestions(a headerAnalysis) []Suggestion {
	var out []Suggestion
	if a.DeliveringIP != "" {
		out = append(out, Suggestion{Value: a.DeliveringIP, Reason: "Delivered the pasted message to the recipient's server"})
	}
	if a.OriginIP != "" && a.OriginIP != a.DeliveringIP {
		out = append(out, Suggestion{Value: a.OriginIP, Reason: "Earliest server in the pasted message's Received chain (can be forged)"})
	}
	al := a.Alignment
	for _, s := range []struct{ v, why string }{
		{al.FromDomain, "Sender (From) domain in the pasted headers"},
		{al.ReturnPathDomain, "Bounce (Return-Path) domain in the pasted headers"},
		{al.DKIMDomain, "DKIM signing domain in the pasted headers"},
	} {
		if s.v != "" {
			out = append(out, Suggestion{Value: s.v, Reason: s.why})
		}
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown server"
	}
	return s
}

func minutes(s float64) string {
	if s >= 3600 {
		return fmt.Sprintf("%.1f hours", s/3600)
	}
	return fmt.Sprintf("%.0f minutes", s/60)
}
