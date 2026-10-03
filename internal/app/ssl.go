package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

func init() {
	registerCheck(check{
		key:   "ssl_inspection",
		label: "SSL Inspection",
		kinds: []string{kindDomain, kindHostname},
		options: []Option{{Key: "port", Label: "Port",
			Choices: []string{"443", "465", "587", "993", "995", "8443"}, Default: "443"}},
		run:      sslInspection,
		findings: sslFindings,
	})
}

type sslCert struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	SANs       []string  `json:"sans,omitempty"` // leaf only
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	Key        string    `json:"key"` // e.g. "RSA 2048", "ECDSA P-256"
	Signature  string    `json:"signature"`
}

type sslResult struct {
	Version       string    `json:"version"`
	Cipher        string    `json:"cipher"`
	Chain         []sslCert `json:"chain"` // as the server sent it, leaf first
	HostnameMatch bool      `json:"hostname_match"`
	Verified      bool      `json:"verified"` // what a browser or mail client would accept
	// Trust is whether the chain leads to a trusted root, ignoring hostname and
	// expiry: ok, self_signed, missing_intermediate, unknown_authority or invalid.
	Trust       string `json:"trust"`
	VerifyError string `json:"verify_error,omitempty"`
}

// sslInspection handshakes with target:port and reports the certificate chain
// and protocol. It verifies by hand, so a broken chain is still shown in full.
func sslInspection(ctx context.Context, n Net, target string, opts map[string]string) (any, error) {
	port := opts["port"]
	conn, err := n.DialContext(ctx, "tcp", net.JoinHostPort(target, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() }) // unblocks the SMTP exchange on timeout
	defer stop()
	if port == "587" {
		if err := smtpStartTLS(conn); err != nil {
			return nil, err
		}
	}
	cfg := n.TLSConfig()
	cfg.ServerName = target
	cfg.InsecureSkipVerify = true // verified below, so failures can be explained
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS10 // to report old protocols rather than refuse them
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	st := tc.ConnectionState()
	peer := st.PeerCertificates
	if len(peer) == 0 {
		return nil, errors.New("the server sent no certificate")
	}

	res := sslResult{Version: tls.VersionName(st.Version), Cipher: tls.CipherSuiteName(st.CipherSuite), Trust: "ok"}
	for i, c := range peer {
		sc := sslCert{
			Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName,
			NotBefore: c.NotBefore, NotAfter: c.NotAfter,
			SelfSigned: selfSigned(c), Key: keyName(c.PublicKey), Signature: c.SignatureAlgorithm.String(),
		}
		if i == 0 {
			sc.SANs = c.DNSNames
		}
		res.Chain = append(res.Chain, sc)
	}

	leaf := peer[0]
	inter := x509.NewCertPool()
	for _, c := range peer[1:] {
		inter.AddCert(c)
	}
	vo := x509.VerifyOptions{Roots: cfg.RootCAs, Intermediates: inter, DNSName: target}
	if _, err := leaf.Verify(vo); err != nil {
		res.VerifyError = err.Error()
	} else {
		res.Verified = true
	}
	res.HostnameMatch = leaf.VerifyHostname(target) == nil

	// Trust on its own: no hostname, and inside the leaf's validity if it has
	// lapsed, so an expired certificate isn't also reported as untrusted.
	vo.DNSName = ""
	if time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) {
		vo.CurrentTime = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	}
	_, err = leaf.Verify(vo)
	var unknown x509.UnknownAuthorityError
	switch {
	case err == nil:
	case !errors.As(err, &unknown):
		res.Trust = "invalid"
	case selfSigned(leaf):
		res.Trust = "self_signed"
	case !peer[len(peer)-1].IsCA:
		// Only end-entity certificates were sent: the intermediate is missing.
		// (A sent intermediate under an unknown root reads as a private CA.)
		res.Trust = "missing_intermediate"
	default:
		res.Trust = "unknown_authority"
	}
	if err != nil && res.VerifyError == "" {
		res.VerifyError = err.Error()
	}
	return res, nil
}

// smtpStartTLS reads the banner, says EHLO and asks to switch to TLS.
func smtpStartTLS(conn net.Conn) error {
	tp := textproto.NewConn(conn)
	if _, _, err := tp.ReadResponse(220); err != nil {
		return fmt.Errorf("SMTP banner: %w", err)
	}
	if err := tp.PrintfLine("EHLO stackwell.invalid"); err != nil {
		return err
	}
	_, ext, err := tp.ReadResponse(250)
	if err != nil {
		return fmt.Errorf("SMTP EHLO: %w", err)
	}
	if !strings.Contains(strings.ToUpper(ext), "STARTTLS") {
		return errors.New("the mail server does not offer STARTTLS on port 587")
	}
	if err := tp.PrintfLine("STARTTLS"); err != nil {
		return err
	}
	if _, _, err := tp.ReadResponse(220); err != nil {
		return fmt.Errorf("SMTP STARTTLS: %w", err)
	}
	return nil
}

// selfSigned checks the signature directly: CheckSignatureFrom would reject
// the many self-signed leaves that aren't marked as CAs.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func keyName(k any) string {
	switch k := k.(type) {
	case *rsa.PublicKey:
		return "RSA " + strconv.Itoa(k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "unknown"
}

func sslFindings(target, _ string, opts map[string]string, raw json.RawMessage) []Finding {
	var r sslResult
	if json.Unmarshal(raw, &r) != nil || len(r.Chain) == 0 {
		return nil
	}
	where := target + ":" + opts["port"]
	leaf := r.Chain[0]
	var out []Finding

	// Days left is worked out now, not stored, so re-runs don't differ by date alone.
	soonest := leaf
	for _, c := range r.Chain[1:] {
		if c.NotAfter.Before(soonest.NotAfter) {
			soonest = c
		}
	}
	which := "The certificate"
	if soonest.Subject != leaf.Subject || soonest.Issuer != leaf.Issuer {
		which = "The chain certificate " + soonest.Subject
	}
	expiry := soonest.NotAfter.Format("2 Jan 2006")
	renew := "Renew the certificate and install it, with its intermediates, on the server."
	switch d := int(math.Floor(time.Until(soonest.NotAfter).Hours() / 24)); {
	case d < 0:
		out = append(out, Finding{Code: "ssl_inspection_expired", Severity: "critical",
			Title:          "Certificate expired",
			Message:        which + " on " + where + " expired on " + expiry + " (" + plural(-d, "day", "days") + " ago); browsers and mail clients reject it.",
			Recommendation: renew})
	case d <= 14:
		out = append(out, Finding{Code: "ssl_inspection_expiring", Severity: "warning",
			Title:          "Certificate expires within two weeks",
			Message:        which + " on " + where + " expires on " + expiry + " (in " + plural(d, "day", "days") + ").",
			Recommendation: renew + " If renewal is automated, check why it hasn't happened yet."})
	case d <= 30:
		out = append(out, Finding{Code: "ssl_inspection_expiring_soon", Severity: "info",
			Title:   "Certificate expires within a month",
			Message: which + " on " + where + " expires on " + expiry + " (in " + plural(d, "day", "days") + ")."})
	}

	if !r.HostnameMatch {
		names := leaf.SANs
		if len(names) == 0 {
			names = []string{leaf.Subject}
		}
		out = append(out, Finding{Code: "ssl_inspection_hostname_mismatch", Severity: "critical",
			Title:          "Certificate doesn't cover " + target,
			Message:        "The certificate on " + where + " is for " + strings.Join(names, ", ") + ", not " + target + ".",
			Recommendation: "Issue a certificate that includes " + target + ", or point " + target + " at the server that has one."})
	}

	switch r.Trust {
	case "self_signed":
		out = append(out, Finding{Code: "ssl_inspection_self_signed", Severity: "critical",
			Title:          "Self-signed certificate",
			Message:        "The certificate on " + where + " is signed by itself, not by a certificate authority, so no browser or mail client trusts it.",
			Recommendation: "Replace it with a certificate from a public CA (e.g. Let's Encrypt)."})
	case "missing_intermediate":
		last := r.Chain[len(r.Chain)-1]
		out = append(out, Finding{Code: "ssl_inspection_incomplete_chain", Severity: "critical",
			Title:          "Incomplete certificate chain",
			Message:        "The chain on " + where + " stops at " + last.Subject + ", issued by " + last.Issuer + ": the server isn't sending its intermediate certificate. Some browsers paper over this; most mail clients, apps and APIs fail.",
			Recommendation: "Install the full chain (the CA's fullchain or bundle file) on the server, not just the certificate."})
	case "unknown_authority":
		root := r.Chain[len(r.Chain)-1]
		out = append(out, Finding{Code: "ssl_inspection_untrusted", Severity: "critical",
			Title:          "Certificate not trusted",
			Message:        "The chain on " + where + " leads to " + root.Issuer + ", which isn't a trusted root (a private CA, or a CA clients don't recognise).",
			Recommendation: "Use a certificate from a publicly trusted CA, or install this private CA's root on every client that connects."})
	case "invalid":
		out = append(out, Finding{Code: "ssl_inspection_untrusted", Severity: "critical",
			Title:          "Certificate chain doesn't verify",
			Message:        "The chain on " + where + " fails verification: " + r.VerifyError,
			Recommendation: "Reinstall the certificate with its current, complete chain from the CA."})
	}

	if r.Version == "TLS 1.0" || r.Version == "TLS 1.1" {
		out = append(out, Finding{Code: "ssl_inspection_old_protocol", Severity: "warning",
			Title:          r.Version + " negotiated",
			Message:        where + " negotiated " + r.Version + ", which is deprecated; current browsers refuse it.",
			Recommendation: "Enable TLS 1.2 and 1.3 on the server and disable TLS 1.0/1.1."})
	}

	if r.Verified {
		out = append(out, Finding{Code: "ssl_inspection_valid", Severity: "ok",
			Title:   "Certificate valid",
			Message: "The certificate on " + where + " is valid for " + target + ", issued by " + leaf.Issuer + ", expiring " + leaf.NotAfter.Format("2 Jan 2006") + "."})
	}
	return out
}
