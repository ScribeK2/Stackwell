package app_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ScribeK2/Stackwell/internal/app"
)

// testCert is a crafted certificate plus its key.
type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64

// mint signs a certificate for cn (a CA when sans is nil) with parent, or self-signs when parent is nil.
func mint(t *testing.T, cn string, sans []string, notAfter time.Time, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: sans,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if sans == nil {
		tmpl.IsCA, tmpl.KeyUsage, tmpl.ExtKeyUsage = true, x509.KeyUsageCertSign, nil
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCert{c, key}
}

func days(n int) time.Time { return time.Now().Add(time.Duration(n)*24*time.Hour + time.Hour) }

// pki is a test CA with an intermediate, and the pool that trusts the CA.
type pki struct {
	ca, inter *testCert
	roots     *x509.CertPool
}

func newPKI(t *testing.T) pki {
	ca := mint(t, "Test Root CA", nil, days(3650), nil)
	inter := mint(t, "Test Intermediate", nil, days(1825), ca)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	return pki{ca, inter, roots}
}

// tlsCert is the certificate a server presents: leaf first, then whatever chain it sends.
func tlsCert(leaf *testCert, chain ...*testCert) tls.Certificate {
	c := tls.Certificate{Certificate: [][]byte{leaf.cert.Raw}, PrivateKey: leaf.key}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.cert.Raw)
	}
	return c
}

// serveTLS runs an HTTPS server presenting cert and returns its address.
func serveTLS(t *testing.T, cert tls.Certificate, tune func(*tls.Config)) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	if tune != nil {
		tune(srv.TLS)
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

type sslResult struct {
	Version       string `json:"version"`
	Cipher        string `json:"cipher"`
	HostnameMatch bool   `json:"hostname_match"`
	Verified      bool   `json:"verified"`
	Trust         string `json:"trust"`
	VerifyError   string `json:"verify_error"`
	Chain         []struct {
		Subject    string    `json:"subject"`
		Issuer     string    `json:"issuer"`
		SANs       []string  `json:"sans"`
		NotBefore  time.Time `json:"not_before"`
		NotAfter   time.Time `json:"not_after"`
		SelfSigned bool      `json:"self_signed"`
		Key        string    `json:"key"`
		Signature  string    `json:"signature"`
	} `json:"chain"`
}

// runSSL runs SSL Inspection on example.com:port, where that address is the local server at addr.
func runSSL(t *testing.T, addr, port string, roots *x509.CertPool) (sslResult, []finding) {
	t.Helper()
	h := start(t, app.Config{Net: app.Net{
		Resolver: fakeDNS(t, exampleZone, false),
		TLS:      &tls.Config{RootCAs: roots},
		Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			if a != "example.com:"+port {
				return nil, errors.New("unexpected dial to " + a)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}})
	c := newCase(h, "example.com")
	h.waitSteps(c.ID, 1)
	if code := h.do("POST", "/api/cases/"+itoa(c.ID)+"/steps", map[string]any{
		"check": "ssl_inspection", "target": "example.com", "options": map[string]string{"port": port}}, nil); code != http.StatusOK {
		t.Fatalf("run ssl_inspection: %d", code)
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
	var res sslResult
	if s := raw.Steps[1]; s.Check != "ssl_inspection" || s.Status != "ok" || json.Unmarshal(s.Result, &res) != nil {
		t.Fatalf("step = %+v", s)
	}
	var mine []finding
	for _, f := range raw.Findings {
		if strings.HasPrefix(f.Code, "ssl_inspection") {
			mine = append(mine, f)
		}
	}
	return res, mine
}

func findingWith(fs []finding, code string) *finding {
	if i := slices.IndexFunc(fs, func(f finding) bool { return f.Code == code }); i != -1 {
		return &fs[i]
	}
	return nil
}

func TestSSLInspectionShowsAValidChain(t *testing.T) {
	p := newPKI(t)
	leaf := mint(t, "example.com", []string{"example.com", "www.example.com"}, days(90), p.inter)
	res, fs := runSSL(t, serveTLS(t, tlsCert(leaf, p.inter), nil), "443", p.roots)

	if res.Version != "TLS 1.3" || res.Cipher == "" || !res.HostnameMatch || !res.Verified || res.VerifyError != "" {
		t.Fatalf("result = %+v", res)
	}
	if len(res.Chain) != 2 {
		t.Fatalf("chain = %+v", res.Chain)
	}
	l := res.Chain[0]
	if l.Subject != "example.com" || l.Issuer != "Test Intermediate" || !slices.Equal(l.SANs, []string{"example.com", "www.example.com"}) ||
		!l.NotAfter.Equal(leaf.cert.NotAfter) || l.SelfSigned || l.Key != "ECDSA P-256" || l.Signature != "ECDSA-SHA256" || l.NotBefore.IsZero() {
		t.Fatalf("leaf = %+v", l)
	}
	if res.Chain[1].Subject != "Test Intermediate" || res.Chain[1].Issuer != "Test Root CA" {
		t.Fatalf("intermediate = %+v", res.Chain[1])
	}
	f := findingWith(fs, "ssl_inspection_valid")
	if len(fs) != 1 || f == nil || f.Severity != "ok" || !strings.Contains(f.Message, "Test Intermediate") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestSSLInspectionFlagsAnExpiredCertificate(t *testing.T) {
	p := newPKI(t)
	leaf := mint(t, "example.com", []string{"example.com"}, time.Now().Add(-24*time.Hour), p.inter)
	res, fs := runSSL(t, serveTLS(t, tlsCert(leaf, p.inter), nil), "443", p.roots)
	if res.Verified || res.VerifyError == "" || res.Chain[0].NotAfter.After(time.Now()) {
		t.Fatalf("result = %+v", res)
	}
	if f := findingWith(fs, "ssl_inspection_expired"); f == nil || f.Severity != "critical" || f.Recommendation == "" {
		t.Fatalf("findings = %+v", fs)
	}
	// The chain itself is fine; expiry is the only problem.
	if slices.ContainsFunc(codes(fs), func(c string) bool { return c != "ssl_inspection_expired" }) {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestSSLInspectionWarnsBeforeExpiry(t *testing.T) {
	p := newPKI(t)
	for _, tc := range []struct {
		days     int
		code     string
		severity string
	}{{10, "ssl_inspection_expiring", "warning"}, {20, "ssl_inspection_expiring_soon", "info"}} {
		leaf := mint(t, "example.com", []string{"example.com"}, days(tc.days), p.inter)
		_, fs := runSSL(t, serveTLS(t, tlsCert(leaf, p.inter), nil), "443", p.roots)
		if f := findingWith(fs, tc.code); f == nil || f.Severity != tc.severity {
			t.Fatalf("%d days: findings = %+v", tc.days, fs)
		}
		if findingWith(fs, "ssl_inspection_valid") == nil {
			t.Fatalf("%d days: still valid, findings = %v", tc.days, codes(fs))
		}
	}
}

func TestSSLInspectionFlagsAHostnameMismatch(t *testing.T) {
	p := newPKI(t)
	leaf := mint(t, "other.test", []string{"other.test"}, days(90), p.inter)
	res, fs := runSSL(t, serveTLS(t, tlsCert(leaf, p.inter), nil), "443", p.roots)
	if res.HostnameMatch || res.Verified || !strings.Contains(res.VerifyError, "other.test") {
		t.Fatalf("result = %+v", res)
	}
	if f := findingWith(fs, "ssl_inspection_hostname_mismatch"); f == nil || f.Severity != "critical" || !strings.Contains(f.Message, "other.test") {
		t.Fatalf("findings = %+v", fs)
	}
	if findingWith(fs, "ssl_inspection_valid") != nil {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestSSLInspectionFlagsASelfSignedCertificate(t *testing.T) {
	self := mint(t, "example.com", []string{"example.com"}, days(90), nil)
	res, fs := runSSL(t, serveTLS(t, tlsCert(self), nil), "443", newPKI(t).roots)
	if !res.Chain[0].SelfSigned || res.Trust != "self_signed" || res.Verified {
		t.Fatalf("result = %+v", res)
	}
	if f := findingWith(fs, "ssl_inspection_self_signed"); f == nil || f.Severity != "critical" {
		t.Fatalf("findings = %+v", fs)
	}
	if findingWith(fs, "ssl_inspection_untrusted") != nil {
		t.Fatalf("findings = %v", codes(fs))
	}
}

func TestSSLInspectionFlagsAMissingIntermediate(t *testing.T) {
	p := newPKI(t)
	leaf := mint(t, "example.com", []string{"example.com"}, days(90), p.inter)
	res, fs := runSSL(t, serveTLS(t, tlsCert(leaf), nil), "443", p.roots) // intermediate not sent
	if len(res.Chain) != 1 || res.Trust != "missing_intermediate" || res.Verified || res.VerifyError == "" {
		t.Fatalf("result = %+v", res)
	}
	f := findingWith(fs, "ssl_inspection_incomplete_chain")
	if f == nil || f.Severity != "critical" || !strings.Contains(f.Message, "server isn't sending its intermediate certificate") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestSSLInspectionFlagsAnUnknownAuthority(t *testing.T) {
	private := newPKI(t) // a CA the client doesn't trust; the server sends a complete chain
	leaf := mint(t, "example.com", []string{"example.com"}, days(90), private.inter)
	res, fs := runSSL(t, serveTLS(t, tlsCert(leaf, private.inter), nil), "443", newPKI(t).roots)
	if res.Trust != "unknown_authority" {
		t.Fatalf("result = %+v", res)
	}
	if f := findingWith(fs, "ssl_inspection_untrusted"); f == nil || f.Severity != "critical" || !strings.Contains(f.Message, "Test Root CA") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestSSLInspectionWarnsAboutOldProtocols(t *testing.T) {
	p := newPKI(t)
	leaf := mint(t, "example.com", []string{"example.com"}, days(90), p.inter)
	res, fs := runSSL(t, serveTLS(t, tlsCert(leaf, p.inter), func(c *tls.Config) {
		c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	}), "443", p.roots)
	if res.Version != "TLS 1.1" {
		t.Fatalf("result = %+v", res)
	}
	if f := findingWith(fs, "ssl_inspection_old_protocol"); f == nil || f.Severity != "warning" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestSSLInspectionUpgradesSMTPWithSTARTTLS(t *testing.T) {
	p := newPKI(t)
	leaf := mint(t, "example.com", []string{"example.com"}, days(90), p.inter)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		conn.Write([]byte("220-mail.example.com ESMTP\r\n220 ready\r\n"))
		if l, _ := r.ReadString('\n'); !strings.HasPrefix(l, "EHLO ") {
			return
		}
		conn.Write([]byte("250-mail.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n"))
		if l, _ := r.ReadString('\n'); l != "STARTTLS\r\n" {
			return
		}
		conn.Write([]byte("220 go ahead\r\n"))
		tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{tlsCert(leaf, p.inter)}}).Handshake()
	}()
	res, fs := runSSL(t, ln.Addr().String(), "587", p.roots)
	if !res.Verified || len(res.Chain) != 2 || findingWith(fs, "ssl_inspection_valid") == nil {
		t.Fatalf("result = %+v, findings %v", res, codes(fs))
	}
}
