package app

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Mail log analysis: Postfix / Dovecot-LMTP delivery logs as reps copy them
// out of a log viewer (Graylog), regrouped by queue id into messages with a
// delivery verdict and the receiving server's reply in plain English.
// Ported from ToolHarness's MailLogParser, fixtures and edge cases included.

func init() {
	registerAnalyser(analyser{
		kind:     "mail_log",
		label:    "a mail log (Postfix / Dovecot)",
		analyse:  func(raw string) (any, error) { return analyseMailLog(raw) },
		findings: func(a any) []Finding { return mailLogFindings(a.(mailLogAnalysis)) },
		suggest:  func(a any) []Suggestion { return mailLogSuggestions(a.(mailLogAnalysis)) },
	})
}

type mlRecipient struct {
	To        string   `json:"to"`
	RelayHost string   `json:"relay_host,omitempty"`
	RelayIP   string   `json:"relay_ip,omitempty"`
	Local     bool     `json:"local"` // delivered to a local mailbox (LMTP)
	DelayS    *float64 `json:"delay_s,omitempty"`
	DSN       string   `json:"dsn,omitempty"`
	Status    string   `json:"status,omitempty"` // sent | deferred | bounced
	Reply     string   `json:"reply,omitempty"`  // the receiving server's own words
	Reason    string   `json:"reason,omitempty"` // that reply in plain English
	Attempts  int      `json:"attempts"`         // delivery attempts seen; the fields are the latest
}

type mlMessage struct {
	QueueID    string        `json:"queue_id"`
	Time       string        `json:"time,omitempty"`
	ClientHost string        `json:"client_host,omitempty"`
	ClientIP   string        `json:"client_ip,omitempty"`
	From       string        `json:"from,omitempty"`
	MessageID  string        `json:"message_id,omitempty"`
	Size       int           `json:"size,omitempty"`
	Nrcpt      int           `json:"nrcpt,omitempty"`
	Recipients []mlRecipient `json:"recipients"`
	Removed    bool          `json:"removed"`
	Verdict    string        `json:"verdict"` // delivered | deferred | bounced | incomplete
}

// mlRejection is mail our server refused before queueing it (NOQUEUE).
type mlRejection struct {
	ClientHost string `json:"client_host,omitempty"`
	ClientIP   string `json:"client_ip"`
	Code       string `json:"code,omitempty"`
	DSN        string `json:"dsn,omitempty"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	Reply      string `json:"reply"`
	Reason     string `json:"reason,omitempty"`
	Time       string `json:"time,omitempty"`
}

type mailLogAnalysis struct {
	Messages   []mlMessage   `json:"messages"`
	Rejections []mlRejection `json:"rejections"`
	Unparsed   int           `json:"unparsed"` // lines that were neither Postfix nor Dovecot
}

var (
	pfTag = regexp.MustCompile(`postfix(?:/[\w.-]+)*/(smtpd|cleanup|qmgr|smtp|lmtp|local|virtual|pipe|error|discard|bounce|pickup)\[\d+\]:\s*(.*)$`)
	dcTag = regexp.MustCompile(`\bdovecot(?:\[\d+\])?:\s*(.*)$`)
	// A record starts with a timestamp or carries a Postfix/Dovecot tag; a
	// hard-wrapped fragment has neither.
	recordStart = regexp.MustCompile(`^\s*(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|\b(?:postfix|dovecot)(?:/[\w.-]+)*(?:\[\d+\])?:`)
	notQueueID  = regexp.MustCompile(`^(?:[a-z]+|NOQUEUE)$`) // warning:, error:, statistics:, NOQUEUE:
	queueID     = regexp.MustCompile(`^([0-9A-Za-z]{6,}):\s*(.*)$`)
	isoStamp    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)`)
	syslogStamp = regexp.MustCompile(`\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b`)
	mlClient    = regexp.MustCompile(`client=([^\s\[]+)\[(?:IPv6:)?([0-9a-fA-F.:]+)\]`)
	mlMsgID     = regexp.MustCompile(`message-id=(<[^>]*>|\S+)`)
	mlFrom      = regexp.MustCompile(`from=<([^>]*)>`)
	mlTo        = regexp.MustCompile(`to=<([^>]*)>`)
	mlSize      = regexp.MustCompile(`size=(\d+)`)
	mlNrcpt     = regexp.MustCompile(`nrcpt=(\d+)`)
	mlRelay     = regexp.MustCompile(`relay=([^,]+)`)
	mlRelayHost = regexp.MustCompile(`^([^\[\s]+)`)
	mlBracketIP = regexp.MustCompile(`\[(?:IPv6:)?([0-9a-fA-F.:]+)\]`)
	mlDelay     = regexp.MustCompile(`\bdelay=([\d.]+)`)
	mlDSN       = regexp.MustCompile(`\bdsn=([\d.]+)`)
	mlStatus    = regexp.MustCompile(`\bstatus=(\w+)`)
	mlReply     = regexp.MustCompile(`status=\w+\s+\((.*)\)\s*$`)
	mlRejFrom   = regexp.MustCompile(`from\s+([^\s\[]+)\[(?:IPv6:)?([0-9a-fA-F.:]+)\]:\s*(.*)$`)
	mlRejSplit  = regexp.MustCompile(`;\s*from=`)
	smtpCode    = regexp.MustCompile(`\b([245]\d\d)\b`)
	enhancedDSN = regexp.MustCompile(`\b([45]\.\d+\.\d+)\b`)
)

func submatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// logicalLines undoes hard wrapping: a real record starts with a timestamp or
// carries a program tag, a wrapped fragment does neither, so only such a
// fragment is joined onto the previous record. Other log lines stay whole
// (and are counted as unparsed if they aren't Postfix or Dovecot).
func logicalLines(raw string) []string {
	var lines []string
	for line := range strings.SplitSeq(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if recordStart.MatchString(line) || len(lines) == 0 {
			lines = append(lines, line)
		} else {
			lines[len(lines)-1] += " " + strings.TrimSpace(line)
		}
	}
	return lines
}

// analyseMailLog is pure: it reads the text and nothing else.
func analyseMailLog(raw string) (mailLogAnalysis, error) {
	a := mailLogAnalysis{Messages: []mlMessage{}, Rejections: []mlRejection{}}
	index := map[string]int{} // queue id → position in Messages, in first-seen order
	for _, line := range logicalLines(raw) {
		m := pfTag.FindStringSubmatch(line)
		if m == nil {
			if !dcTag.MatchString(line) { // Dovecot's own lines add nothing Postfix's lmtp line doesn't
				a.Unparsed++
			}
			continue
		}
		daemon, payload := m[1], m[2]
		ts := submatch(isoStamp, line)
		if ts == "" {
			ts = submatch(syslogStamp, line)
		}
		if strings.HasPrefix(payload, "NOQUEUE: reject") || strings.HasPrefix(payload, "NOQUEUE: milter-reject") {
			if r, ok := parseRejection(payload, ts); ok {
				a.Rejections = append(a.Rejections, r)
			}
			continue
		}
		q := queueID.FindStringSubmatch(payload)
		if q == nil || notQueueID.MatchString(q[1]) {
			continue
		}
		id, rest := q[1], q[2]
		i, seen := index[id]
		if !seen {
			i = len(a.Messages)
			index[id] = i
			a.Messages = append(a.Messages, mlMessage{QueueID: id, Time: ts, Recipients: []mlRecipient{}})
		}
		msg := &a.Messages[i]
		switch daemon {
		case "smtpd":
			if c := mlClient.FindStringSubmatch(rest); c != nil {
				msg.ClientHost, msg.ClientIP = c[1], c[2]
			}
		case "cleanup":
			if id := submatch(mlMsgID, rest); id != "" {
				msg.MessageID = id
			}
		case "qmgr":
			if strings.TrimSpace(rest) == "removed" {
				msg.Removed = true
			} else if f := mlFrom.FindStringSubmatch(rest); f != nil {
				msg.From = f[1]
				msg.Size, _ = strconv.Atoi(submatch(mlSize, rest))
				msg.Nrcpt, _ = strconv.Atoi(submatch(mlNrcpt, rest))
			}
		case "smtp", "lmtp", "local", "virtual", "pipe", "error", "discard":
			r := parseOutcome(rest, daemon == "lmtp" || daemon == "local" || daemon == "virtual" || daemon == "pipe")
			// A later attempt for the same recipient (a retry after a
			// deferral) is its outcome now; count the attempts.
			if j := slices.IndexFunc(msg.Recipients, func(x mlRecipient) bool { return x.To == r.To }); j != -1 {
				r.Attempts = msg.Recipients[j].Attempts + 1
				msg.Recipients[j] = r
			} else {
				r.Attempts = 1
				msg.Recipients = append(msg.Recipients, r)
			}
		}
	}
	if len(a.Messages) == 0 && len(a.Rejections) == 0 {
		return a, errNotThisKind
	}
	for i := range a.Messages {
		a.Messages[i].Verdict = verdictFor(a.Messages[i])
	}
	return a, nil
}

func parseOutcome(rest string, lmtp bool) mlRecipient {
	relay := strings.TrimSpace(submatch(mlRelay, rest))
	r := mlRecipient{
		To:        submatch(mlTo, rest),
		RelayHost: submatch(mlRelayHost, relay),
		RelayIP:   submatch(mlBracketIP, relay),
		Local:     lmtp || strings.Contains(relay, "dovecot"),
		DSN:       submatch(mlDSN, rest),
		Status:    submatch(mlStatus, rest),
		Reply:     submatch(mlReply, rest),
	}
	if d, err := strconv.ParseFloat(submatch(mlDelay, rest), 64); err == nil {
		r.DelayS = &d
	}
	r.Reason = decodeReason(r.DSN, r.Reply)
	return r
}

func parseRejection(payload, ts string) (mlRejection, bool) {
	m := mlRejFrom.FindStringSubmatch(payload)
	if m == nil {
		return mlRejection{}, false
	}
	body := m[3]
	reply := strings.TrimSpace(mlRejSplit.Split(body, 2)[0])
	dsn := submatch(enhancedDSN, reply)
	host := m[1]
	if host == "unknown" { // Postfix's word for "no reverse DNS"
		host = ""
	}
	return mlRejection{
		ClientHost: host, ClientIP: m[2],
		Code: submatch(smtpCode, reply), DSN: dsn,
		From: submatch(mlFrom, body), To: submatch(mlTo, body),
		Reply: reply, Reason: decodeReason(dsn, reply), Time: ts,
	}, true
}

var (
	// Not "Recipient address rejected": Postfix prefixes many refusals with it
	// (greylisting, access denied), so it says nothing about the mailbox.
	reUserUnknown = regexp.MustCompile(`(?i)user unknown|unknown user|no such user|does not exist`)
	reQuota       = regexp.MustCompile(`(?i)mailbox full|over\s?quota`)
	reGreylist    = regexp.MustCompile(`(?i)greylist|try again|rate`)
	reGreylist2   = regexp.MustCompile(`(?i)greylist|try again later|rate limit`)
	rePolicy      = regexp.MustCompile(`(?i)blocked|spam|blacklist|blocklist|policy|denied|reputation`)
	reConnect     = regexp.MustCompile(`(?i)timed out|timeout|connection refused|no route|unable to connect|conversation timed out`)
)

// decodeReason turns an enhanced status code (X.Y.Z) or SMTP reply into plain
// English. The raw reply is always shown beside it, so a miss hides nothing.
// A permanent (5.x) code is never described as something that will retry.
func decodeReason(dsn, reply string) string {
	code := submatch(smtpCode, reply)
	perm := strings.HasPrefix(dsn, "5") || (dsn == "" && strings.HasPrefix(code, "5"))
	has := func(prefixes ...string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(dsn, p) {
				return true
			}
		}
		return false
	}
	switch {
	case has("5.1.1", "5.1.0") || reUserUnknown.MatchString(reply):
		return "Recipient mailbox doesn't exist at the receiving server"
	case has("5.1.2"):
		return "Recipient domain doesn't exist or has no working MX"
	case dsn == "5.2.2" || dsn == "4.2.2" || reQuota.MatchString(reply):
		return "Recipient mailbox is full (over quota)"
	case has("5.7.25", "5.7.26"):
		return "Rejected by the receiving server's policy on the sender's reverse DNS, DMARC or authentication"
	case !perm && has("5.7", "4.7") && reGreylist.MatchString(reply):
		return "Greylisted or rate-limited; temporary, Postfix will retry"
	case !perm && (code == "421" || reGreylist2.MatchString(reply)):
		return "Greylisted or rate-limited; temporary, Postfix will retry"
	case has("5.7") || rePolicy.MatchString(reply):
		return "Rejected by the receiving server's policy (spam, blocklist or policy)"
	case !perm && (has("4.4") || reConnect.MatchString(reply)):
		return "Could not connect to the recipient's server; temporary, Postfix will retry"
	case has("4.3", "5.3"):
		return "The receiving mail system had an error (a problem on their side)"
	case dsn == "2.0.0" || code == "250":
		return "Accepted by the receiving server"
	case perm:
		return "Permanent failure: the recipient's server refused it (see its reply)"
	case strings.HasPrefix(code, "4") || strings.HasPrefix(dsn, "4"):
		return "Temporary failure; Postfix will retry (see the reply)"
	}
	return ""
}

// verdictFor: bounced beats deferred beats delivered. A message with no
// delivery line is incomplete, so a truncated paste never reads as delivered.
func verdictFor(m mlMessage) string {
	statuses := map[string]bool{}
	for _, r := range m.Recipients {
		if r.Status != "" {
			statuses[r.Status] = true
		}
	}
	switch {
	case len(statuses) == 0:
		return "incomplete"
	case statuses["bounced"]:
		return "bounced"
	case statuses["deferred"]:
		return "deferred"
	case len(statuses) == 1 && statuses["sent"]:
		return "delivered"
	}
	return "incomplete"
}

// mailLogFindingCap keeps a big log from burying the Case in Findings: the
// rest are counted in one summary Finding and stay visible in the Evidence.
const mailLogFindingCap = 10

func mailLogFindings(a mailLogAnalysis) []Finding {
	var out []Finding
	shown := map[string]int{}
	hidden := 0
	add := func(f Finding) {
		if shown[f.Code] >= mailLogFindingCap {
			hidden++
			return
		}
		shown[f.Code]++
		out = append(out, f)
	}
	delivered := 0
	for _, m := range a.Messages {
		from := m.From
		if from == "" {
			from = "an unknown sender"
		}
		switch m.Verdict {
		case "delivered":
			delivered++
		case "bounced":
			var bad []mlRecipient
			for _, r := range m.Recipients {
				if r.Status == "bounced" {
					bad = append(bad, r)
				}
			}
			sev := "warning" // some recipients got it
			if len(bad) == len(m.Recipients) {
				sev = "critical"
			}
			r := bad[0]
			add(Finding{Code: "mail_log_bounced", Severity: sev, Target: r.To, Title: "Bounced: " + r.To,
				Message:        fmt.Sprintf("Message %s from %s was refused by %s: %s. Their reply: %s", m.QueueID, from, orUnknown(r.RelayHost), orDefault(r.Reason, "see the reply"), r.Reply),
				Recommendation: "Tell the sender the reason; fix the address or the cause, then send again."})
		case "deferred":
			r := m.Recipients[0]
			for _, x := range m.Recipients {
				if x.Status == "deferred" {
					r = x
					break
				}
			}
			add(Finding{Code: "mail_log_deferred", Severity: "info", Target: r.To, Title: "Deferred: " + r.To,
				Message: fmt.Sprintf("Message %s from %s is waiting to be retried: %s. Their reply: %s", m.QueueID, from, orDefault(r.Reason, "see the reply"), r.Reply)})
		case "incomplete":
			add(Finding{Code: "mail_log_incomplete", Severity: "info", Target: m.QueueID, Title: "No final status for " + m.QueueID,
				Message: "The pasted lines stop before this message was delivered, deferred or bounced. Paste more of the log to see how it ended."})
		}
	}
	for _, r := range a.Rejections {
		add(Finding{Code: "mail_log_rejected", Severity: "warning", Target: r.ClientIP, Title: "Refused at our server: " + orDefault(r.ClientHost, r.ClientIP),
			Message:        fmt.Sprintf("Mail from %s to %s was refused before it was queued: %s. Our reply: %s", orDefault(r.From, "an unknown sender"), orDefault(r.To, "an unknown recipient"), orDefault(r.Reason, "see the reply"), r.Reply),
			Recommendation: "If this sender is legitimate, check the listing or policy named in the reply."})
	}
	if hidden > 0 {
		out = append(out, Finding{Code: "mail_log_more", Severity: "info", Target: "pasted mail log", Title: "More in the log",
			Message: fmt.Sprintf("%d more problems aren't listed here; every message is in the pasted log's analysis.", hidden)})
	}
	if delivered > 0 {
		out = append(out, Finding{Code: "mail_log_delivered", Severity: "ok", Target: "pasted mail log", Title: "Delivered",
			Message: fmt.Sprintf("%d of %d messages in the log were delivered to every recipient.", delivered, len(a.Messages))})
	}
	return out
}

// mailLogSuggestions offers the servers that refused or held up mail, and
// the senders our server refused.
func mailLogSuggestions(a mailLogAnalysis) []Suggestion {
	var out []Suggestion
	for _, m := range a.Messages {
		for _, r := range m.Recipients {
			if r.Local || r.RelayHost == "" {
				continue
			}
			switch r.Status {
			case "bounced":
				out = append(out, Suggestion{Value: r.RelayHost, Reason: "Refused mail for " + r.To + " in the pasted log"})
			case "deferred":
				out = append(out, Suggestion{Value: r.RelayHost, Reason: "Deferred mail for " + r.To + " in the pasted log"})
			}
		}
	}
	for _, r := range a.Rejections {
		out = append(out, Suggestion{Value: r.ClientIP, Reason: "Sender refused at our server in the pasted log"})
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
