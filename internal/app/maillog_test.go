package app_test

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ScribeK2/Stackwell/internal/app"
)

type mailLogAnalysis struct {
	Messages []struct {
		QueueID    string `json:"queue_id"`
		From       string `json:"from"`
		ClientHost string `json:"client_host"`
		ClientIP   string `json:"client_ip"`
		MessageID  string `json:"message_id"`
		Size       int    `json:"size"`
		Nrcpt      int    `json:"nrcpt"`
		Removed    bool   `json:"removed"`
		Verdict    string `json:"verdict"`
		Recipients []struct {
			To        string `json:"to"`
			RelayHost string `json:"relay_host"`
			RelayIP   string `json:"relay_ip"`
			Local     bool   `json:"local"`
			DSN       string `json:"dsn"`
			Status    string `json:"status"`
			Reply     string `json:"reply"`
			Reason    string `json:"reason"`
		} `json:"recipients"`
	} `json:"messages"`
	Rejections []struct {
		ClientIP string `json:"client_ip"`
		Code     string `json:"code"`
		From     string `json:"from"`
		To       string `json:"to"`
		Reply    string `json:"reply"`
		Reason   string `json:"reason"`
	} `json:"rejections"`
	Unparsed int `json:"unparsed"`
}

type mailLogCase struct {
	Evidence []struct {
		ID       int64           `json:"id"`
		Analysis mailLogAnalysis `json:"analysis"`
	} `json:"evidence"`
	Findings []struct {
		finding
		Evidence []int64 `json:"evidence"`
	} `json:"findings"`
	Suggestions []suggestion `json:"suggestions"`
}

func pasteLog(t *testing.T, raw string) mailLogCase {
	t.Helper()
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	var got mailLogCase
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/evidence", map[string]string{"kind": "mail_log", "raw": raw}, &got); code != http.StatusOK {
		t.Fatalf("paste: %d", code)
	}
	return got
}

func analysed(t *testing.T, raw string) mailLogAnalysis {
	t.Helper()
	return pasteLog(t, raw).Evidence[0].Analysis
}

const sentLog = `2026-06-12T02:26:20.123Z mail01 postfix/smtpd[2811]: A1B2C3D4: client=mail.client.com[203.0.113.10]
2026-06-12T02:26:20.200Z mail01 postfix/cleanup[2815]: A1B2C3D4: message-id=<abc123@client.com>
2026-06-12T02:26:20.250Z mail01 postfix/qmgr[2790]: A1B2C3D4: from=<sender@client.com>, size=4523, nrcpt=1 (queue active)
2026-06-12T02:26:21.500Z mail01 postfix/smtp[2820]: A1B2C3D4: to=<rcpt@example.net>, relay=mx.example.net[198.51.100.5]:25, delay=1.3, dsn=2.0.0, status=sent (250 2.0.0 OK 1A2B3C)
2026-06-12T02:26:21.600Z mail01 postfix/qmgr[2790]: A1B2C3D4: removed`

func TestTextThatIsNotAMailLogIsRefused(t *testing.T) {
	h := start(t, app.Config{Net: app.Net{Resolver: fakeDNS(t, exampleZone, false)}})
	c := newCase(h, "example.com")
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/evidence", map[string]string{"kind": "mail_log", "raw": "not a log at all\n\n"}, nil); code != http.StatusBadRequest {
		t.Fatalf("garbage: %d", code)
	}
}

func TestADeliveredMessageIsReconstructedByQueueID(t *testing.T) {
	a := analysed(t, sentLog)
	if len(a.Messages) != 1 {
		t.Fatalf("messages = %+v", a.Messages)
	}
	m := a.Messages[0]
	if m.QueueID != "A1B2C3D4" || m.From != "sender@client.com" || m.ClientHost != "mail.client.com" || m.ClientIP != "203.0.113.10" ||
		m.MessageID != "<abc123@client.com>" || m.Size != 4523 || m.Nrcpt != 1 || !m.Removed || m.Verdict != "delivered" {
		t.Fatalf("message = %+v", m)
	}
	r := m.Recipients[0]
	if r.To != "rcpt@example.net" || r.RelayHost != "mx.example.net" || r.RelayIP != "198.51.100.5" || r.Status != "sent" ||
		r.DSN != "2.0.0" || r.Local || r.Reply != "250 2.0.0 OK 1A2B3C" || !strings.Contains(r.Reason, "Accepted") {
		t.Fatalf("recipient = %+v", r)
	}
}

func TestVerdicts(t *testing.T) {
	for _, tc := range []struct{ name, log, verdict string }{
		{"bounced", "Jun 12 02:30:00 mail01 postfix/smtp[2820]: B2C3D4E5: to=<nobody@example.net>, relay=mx.example.net[198.51.100.5]:25, delay=0.9, dsn=5.1.1, status=bounced (host mx.example.net[198.51.100.5] said: 550 5.1.1 <nobody@example.net>: Recipient address rejected: User unknown (in reply to RCPT TO command))", "bounced"},
		{"deferred", "2026-06-12T02:40:00Z mail01 postfix/smtp[2820]: C3D4E5F6: to=<user@example.org>, relay=mx.example.org[192.0.2.7]:25, delay=2.1, dsn=4.7.1, status=deferred (host mx.example.org[192.0.2.7] said: 451 4.7.1 Greylisting in effect, please try again later)", "deferred"},
		{"local lmtp", "2026-06-12T02:50:00Z mail01 postfix/lmtp[3001]: D4E5F6A1: to=<local@ourdomain.com>, relay=ourdomain.com[private/dovecot-lmtp], delay=0.1, dsn=2.0.0, status=sent (250 2.0.0 <local@ourdomain.com> Saved)", "delivered"},
		{"mixed recipients", `postfix/qmgr[2790]: AA11BB22: from=<s@client.com>, size=10, nrcpt=2 (queue active)
postfix/smtp[2820]: AA11BB22: to=<ok@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)
postfix/smtp[2820]: AA11BB22: to=<bad@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)`, "bounced"},
		{"truncated", "postfix/qmgr[2790]: TRUNC123: from=<a@client.com>, size=10, nrcpt=1 (queue active)", "incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := analysed(t, tc.log).Messages[0].Verdict; got != tc.verdict {
				t.Fatalf("verdict = %s, want %s", got, tc.verdict)
			}
		})
	}
}

func TestInterleavedQueueIDsRegroup(t *testing.T) {
	a := analysed(t, `postfix/qmgr[2790]: QID0001A: from=<a@client.com>, size=10, nrcpt=1 (queue active)
postfix/qmgr[2790]: QID0002B: from=<b@client.com>, size=20, nrcpt=1 (queue active)
postfix/smtp[2820]: QID0001A: to=<x@example.net>, relay=mx[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)
postfix/smtp[2820]: QID0002B: to=<y@example.net>, relay=mx[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 User unknown)`)
	verdicts := map[string]string{}
	for _, m := range a.Messages {
		verdicts[m.QueueID] = m.Verdict
	}
	if len(a.Messages) != 2 || verdicts["QID0001A"] != "delivered" || verdicts["QID0002B"] != "bounced" {
		t.Fatalf("verdicts = %v", verdicts)
	}
}

func TestRejectionsAtOurServer(t *testing.T) {
	a := analysed(t, "Jun 12 03:00:00 mail01 postfix/smtpd[2811]: NOQUEUE: reject: RCPT from unknown[185.220.101.1]: 554 5.7.1 Service unavailable; Client host [185.220.101.1] blocked using zen.spamhaus.org; from=<spammer@bad.com> to=<victim@ourdomain.com> proto=ESMTP helo=<bad.com>")
	if len(a.Rejections) != 1 {
		t.Fatalf("rejections = %+v", a.Rejections)
	}
	r := a.Rejections[0]
	if r.ClientIP != "185.220.101.1" || r.To != "victim@ourdomain.com" || r.From != "spammer@bad.com" || r.Code != "554" ||
		!strings.Contains(r.Reply, "zen.spamhaus.org") || !regexp.MustCompile(`(?i)policy|spam|blocklist`).MatchString(r.Reason) {
		t.Fatalf("rejection = %+v", r)
	}
}

func TestPastingQuirks(t *testing.T) {
	t.Run("noise before a record is counted, the record still parses", func(t *testing.T) {
		a := analysed(t, "this is noise\npostfix/qmgr[1]: 9F2A1B3C4D: from=<a@b.com>, size=1, nrcpt=1 (queue active)")
		if len(a.Messages) != 1 || a.Unparsed < 1 {
			t.Fatalf("analysis = %+v", a)
		}
	})
	t.Run("hard-wrapped Graylog lines are joined", func(t *testing.T) {
		a := analysed(t, `2026-06-12T02:26:21Z mail01 postfix/smtp[2820]: 7Fk9R2p1Zc7Yb3Na12: to=<ghost@example.net>,
relay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1
<ghost@example.net>: Recipient address rejected: User unknown)`)
		if a.Unparsed != 0 || len(a.Messages) != 1 {
			t.Fatalf("analysis = %+v", a)
		}
		r := a.Messages[0].Recipients[0]
		if r.To != "ghost@example.net" || r.RelayHost != "mx.example.net" || r.RelayIP != "198.51.100.5" || r.Status != "bounced" || r.DSN != "5.1.1" {
			t.Fatalf("recipient = %+v", r)
		}
	})
	t.Run("a wrapped rejection keeps from and to", func(t *testing.T) {
		a := analysed(t, `Jun 12 02:32:00 mail01 postfix/smtpd[2811]: NOQUEUE: reject: RCPT from unknown[185.220.101.1]: 554 5.7.1 blocked using
zen.spamhaus.org; from=<spammer@bad.com> to=<victim@ourdomain.com> proto=ESMTP`)
		r := a.Rejections[0]
		if r.ClientIP != "185.220.101.1" || r.From != "spammer@bad.com" || r.To != "victim@ourdomain.com" {
			t.Fatalf("rejection = %+v", r)
		}
	})
	t.Run("long queue ids", func(t *testing.T) {
		a := analysed(t, `postfix/qmgr[2790]: 4Xk8R2p1Zc7Yb3Na12: from=<a@client.com>, size=10, nrcpt=1 (queue active)
postfix/smtp[2820]: 4Xk8R2p1Zc7Yb3Na12: to=<x@example.net>, relay=mx[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)`)
		if len(a.Messages) != 1 || a.Messages[0].QueueID != "4Xk8R2p1Zc7Yb3Na12" || a.Messages[0].Verdict != "delivered" {
			t.Fatalf("messages = %+v", a.Messages)
		}
	})
	t.Run("IPv6 relay and client", func(t *testing.T) {
		a := analysed(t, `postfix/smtp[2820]: AB12CD34: to=<u@example.net>, relay=mx.example.net[IPv6:2001:db8::25]:25, dsn=2.0.0, status=sent (250 OK)
postfix/smtpd[2811]: NOQUEUE: reject: RCPT from unknown[IPv6:2001:db8::bad]: 554 5.7.1 blocked; from=<s@bad.com> to=<v@ourdomain.com> proto=ESMTP`)
		if r := a.Messages[0].Recipients[0]; r.RelayHost != "mx.example.net" || r.RelayIP != "2001:db8::25" {
			t.Fatalf("recipient = %+v", r)
		}
		if r := a.Rejections[0]; r.ClientIP != "2001:db8::bad" || r.To != "v@ourdomain.com" {
			t.Fatalf("rejection = %+v", r)
		}
	})
}

func TestRepliesAreDecodedIntoPlainEnglish(t *testing.T) {
	for _, tc := range []struct{ dsn, reply, status, want string }{
		{"5.1.1", "550 5.1.1 User unknown", "bounced", `(?i)mailbox doesn't exist`},
		{"5.2.2", "552 5.2.2 Over quota", "bounced", `(?i)full|quota`},
		{"5.7.1", "554 5.7.1 Message rejected as spam", "bounced", `(?i)policy|spam|blocklist`},
		{"4.7.1", "451 4.7.1 Greylisting, try again later", "deferred", `(?i)greylist|rate|temporary|retry`},
		{"4.4.1", "conversation timed out", "deferred", `(?i)connect|retry|temporary`},
		{"2.0.0", "250 2.0.0 OK", "sent", `(?i)accepted`},
		{"5.9.9", "599 weird", "bounced", `(?i)permanent`},
		// A permanent 5.x is never presented as something that will retry.
		{"5.4.4", "550 5.4.4 No route to host", "bounced", `(?i)permanent`},
		{"5.7.0", "550 5.7.0 Too many errors, try again later", "bounced", `(?i)policy|permanent`},
	} {
		t.Run(tc.dsn, func(t *testing.T) {
			a := analysed(t, fmt.Sprintf("postfix/smtp[1]: DEC0DE01: to=<u@example.net>, relay=mx[198.51.100.5]:25, dsn=%s, status=%s (%s)", tc.dsn, tc.status, tc.reply))
			reason := a.Messages[0].Recipients[0].Reason
			if !regexp.MustCompile(tc.want).MatchString(reason) {
				t.Fatalf("%s %q decoded as %q", tc.dsn, tc.reply, reason)
			}
			if strings.HasPrefix(tc.dsn, "5") && regexp.MustCompile(`(?i)temporary|will retry`).MatchString(reason) {
				t.Fatalf("permanent %s presented as temporary: %q", tc.dsn, reason)
			}
		})
	}
}

func TestMailLogFindingsAndSuggestions(t *testing.T) {
	c := pasteLog(t, sentLog+`
Jun 12 02:30:00 mail01 postfix/smtp[2820]: B2C3D4E5: to=<nobody@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)
2026-06-12T02:40:00Z mail01 postfix/smtp[2820]: C3D4E5F6: to=<user@example.org>, relay=mx.example.org[192.0.2.7]:25, dsn=4.7.1, status=deferred (451 4.7.1 Greylisting, try again later)
Jun 12 03:00:00 mail01 postfix/smtpd[2811]: NOQUEUE: reject: RCPT from unknown[185.220.101.1]: 554 5.7.1 blocked using zen.spamhaus.org; from=<spammer@bad.com> to=<victim@ourdomain.com> proto=ESMTP`)
	id := c.Evidence[0].ID
	got := map[string]string{}
	for _, f := range c.Findings {
		if slices.Equal(f.Evidence, []int64{id}) {
			got[f.Code] = f.Severity + " " + f.Target
		}
	}
	for code, want := range map[string]string{
		"mail_log_bounced":   "critical nobody@example.net",
		"mail_log_deferred":  "info user@example.org",
		"mail_log_rejected":  "warning 185.220.101.1",
		"mail_log_delivered": "ok pasted mail log",
	} {
		if got[code] != want {
			t.Errorf("%s = %q, want %q (all: %v)", code, got[code], want, got)
		}
	}
	var values []string
	for _, s := range c.Suggestions {
		values = append(values, s.Value)
	}
	for _, want := range []string{"mx.example.net", "mx.example.org", "185.220.101.1"} {
		if !slices.Contains(values, want) {
			t.Errorf("no suggestion %s in %v", want, values)
		}
	}
}

func TestALargeLogDoesNotFloodTheFindings(t *testing.T) {
	var log strings.Builder
	for i := range 250 {
		fmt.Fprintf(&log, "postfix/smtp[1]: Q%07d: to=<u%d@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)\n", i, i)
	}
	c := pasteLog(t, log.String())
	if n := len(c.Evidence[0].Analysis.Messages); n != 250 {
		t.Fatalf("parsed %d of 250 messages", n)
	}
	bounced, more := 0, false
	for _, f := range c.Findings {
		switch f.Code {
		case "mail_log_bounced":
			bounced++
		case "mail_log_more":
			more = strings.Contains(f.Message, "240")
		}
	}
	if bounced > 10 || !more {
		t.Fatalf("%d bounce Findings, summary of the rest: %v", bounced, more)
	}
}

func TestOtherLogLinesAreNeverGluedOntoARecord(t *testing.T) {
	a := analysed(t, `2026-06-12T02:26:21Z mail01 postfix/smtp[2820]: AAA11111: to=<x@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=2.0.0, status=sent (250 OK)
2026-06-12T02:26:22Z mail01 dovecot[99]: lmtp(u): msgid=<1@x>: saved mail to INBOX
2026-06-12T02:26:23Z mail01 postfix/local[3100]: BBB22222: to=<nobody@ourdomain.com>, relay=local, dsn=5.1.1, status=bounced (unknown user: "nobody")
2026-06-12T02:26:24Z mail01 kernel: something unrelated`)
	if r := a.Messages[0].Recipients[0]; r.Reply != "250 OK" {
		t.Fatalf("a later line was glued onto the first record: %q", r.Reply)
	}
	if len(a.Messages) != 2 || a.Messages[1].Verdict != "bounced" || !a.Messages[1].Recipients[0].Local {
		t.Fatalf("the local delivery bounce went missing: %+v", a.Messages)
	}
	if a.Unparsed != 1 { // the kernel line
		t.Fatalf("unparsed = %d", a.Unparsed)
	}
}

func TestWarningsAreNotMessages(t *testing.T) {
	a := analysed(t, sentLog+`
2026-06-12T02:27:00Z mail01 postfix/smtpd[2811]: warning: hostname bad.example does not resolve to address 203.0.113.99
2026-06-12T02:27:01Z mail01 postfix/cleanup[2815]: NOQUEUE: milter-reject: END-OF-MESSAGE from unknown[203.0.113.99]: 5.7.1 Rejected by spam filter; from=<s@bad.test> to=<v@ourdomain.com> proto=ESMTP`)
	for _, m := range a.Messages {
		if m.QueueID != "A1B2C3D4" {
			t.Errorf("fake message %q", m.QueueID)
		}
	}
	if len(a.Rejections) != 1 || a.Rejections[0].ClientIP != "203.0.113.99" {
		t.Fatalf("milter rejection = %+v", a.Rejections)
	}
}

func TestARetryThatSucceedsIsDelivered(t *testing.T) {
	a := analysed(t, `2026-06-12T02:40:00Z mail01 postfix/smtp[2820]: C3D4E5F6: to=<user@example.org>, relay=mx.example.org[192.0.2.7]:25, dsn=4.7.1, status=deferred (451 4.7.1 Greylisting in effect, please try again later)
2026-06-12T02:55:00Z mail01 postfix/smtp[2820]: C3D4E5F6: to=<user@example.org>, relay=mx.example.org[192.0.2.7]:25, dsn=2.0.0, status=sent (250 2.0.0 OK)`)
	m := a.Messages[0]
	if m.Verdict != "delivered" || len(m.Recipients) != 1 || m.Recipients[0].Status != "sent" {
		t.Fatalf("message = %+v", m)
	}
}

func TestRecipientAddressRejectedIsNotAlwaysAMissingMailbox(t *testing.T) {
	for _, tc := range []struct{ dsn, reply, status, notWant string }{
		{"4.2.0", "450 4.2.0 <u@x.test>: Recipient address rejected: Greylisted, see http://postgrey", "deferred", `(?i)doesn't exist`},
		{"5.7.1", "554 5.7.1 <u@x.test>: Recipient address rejected: Access denied", "bounced", `(?i)doesn't exist`},
	} {
		a := analysed(t, fmt.Sprintf("postfix/smtp[1]: DEC0DE01: to=<u@x.test>, relay=mx[198.51.100.5]:25, dsn=%s, status=%s (%s)", tc.dsn, tc.status, tc.reply))
		if reason := a.Messages[0].Recipients[0].Reason; regexp.MustCompile(tc.notWant).MatchString(reason) {
			t.Errorf("%q decoded as %q", tc.reply, reason)
		}
	}
}
