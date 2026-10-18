package supertls

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/qunulabs/supertls/internal/testpki"
)

// serveTLS runs a TLS listener on loopback that completes handshakes and holds
// each connection briefly before closing it, returning "localhost:<port>".
func serveTLS(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })

	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
				time.Sleep(100 * time.Millisecond)
				tc.Close()
			}()
		}
	}()
	return localhostAddr(t, lis.Addr())
}

func localhostAddr(t *testing.T, a net.Addr) string {
	t.Helper()
	_, port, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatalf("split %s: %v", a, err)
	}
	return net.JoinHostPort("localhost", port)
}

// The whole point of the classifier: a peer whose certificate does not chain to
// the trusted roots is an interceptor.
func TestProbeSubstitutedCertificateIsIntercepted(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	addr := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{p.Proxy}, MinVersion: tls.VersionTLS12})

	got, err := Probe(context.Background(), addr, TrustPool(p.Root.Pool))
	if got != VerdictIntercepted {
		t.Fatalf("got %s (%v), want intercepted", got, err)
	}
	if !errors.Is(err, ErrForeignCertificate) {
		t.Fatalf("err = %v, want ErrForeignCertificate", err)
	}
	if !strings.Contains(err.Error(), p.Foreign.Cert.Subject.CommonName) {
		t.Fatalf("err %q does not name the foreign issuer %q", err, p.Foreign.Cert.Subject.CommonName)
	}
}

// The caller's own server, healthy. Nothing is wrong and nothing should tunnel.
func TestProbeOurServerIsGenuine(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	addr := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{p.Server}, MinVersion: tls.VersionTLS12})

	got, err := Probe(context.Background(), addr, TrustPool(p.Root.Pool))
	if got != VerdictGenuine || err != nil {
		t.Fatalf("got %s (%v), want genuine with no error", got, err)
	}
}

// An expired server leaf is the server operator's bug. Tunnelling would
// reproduce it identically, so misreading it as interception would hide a real
// outage behind a silent fallback.
func TestProbeExpiredOurLeafIsGenuineNotIntercepted(t *testing.T) {
	t.Parallel()
	now := time.Now()
	root := testpki.NewRoot(t, "root", now.Add(-72*time.Hour), now.Add(24*time.Hour))
	inter := root.Intermediate(t, "issuing", now.Add(-72*time.Hour), now.Add(24*time.Hour))
	leaf := inter.ServerCert(t, now.Add(-48*time.Hour), now.Add(-time.Hour), "localhost")
	addr := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12})

	got, err := Probe(context.Background(), addr, TrustPool(root.Pool))
	if got != VerdictGenuine {
		t.Fatalf("got %s (%v), want genuine: an expired leaf of ours must not trigger the tunnel", got, err)
	}
}

// A drifted SAN is also the server operator's bug under TrustPool.
func TestProbeWrongSANIsGenuineNotIntercepted(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	now := time.Now()
	leaf := p.Issuing.ServerCert(t, now.Add(-time.Hour), now.Add(time.Hour), "other.example")
	addr := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12})

	got, err := Probe(context.Background(), addr, TrustPool(p.Root.Pool))
	if got != VerdictGenuine {
		t.Fatalf("got %s (%v), want genuine: a SAN mismatch on our own server is not interception", got, err)
	}
}

// Under a hostname-checking Trust the same server is not recognised.
func TestProbeWrongSANIsInterceptedUnderHostnameTrust(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	now := time.Now()
	leaf := p.Issuing.ServerCert(t, now.Add(-time.Hour), now.Add(time.Hour), "other.example")
	addr := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12})

	got, err := Probe(context.Background(), addr, TrustPoolWithHostname(p.Root.Pool))
	if got != VerdictIntercepted || !errors.Is(err, ErrForeignCertificate) {
		t.Fatalf("got %s (%v), want intercepted with ErrForeignCertificate", got, err)
	}
}

// A closed port is a firewall or an outage: no evidence either way.
func TestProbeClosedPortIsInconclusive(t *testing.T) {
	t.Parallel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := localhostAddr(t, lis.Addr())
	lis.Close()

	p := testpki.Standard(t)
	got, err := Probe(context.Background(), addr, TrustPool(p.Root.Pool))
	if got != VerdictInconclusive || err == nil {
		t.Fatalf("got %s (%v), want inconclusive with an error", got, err)
	}
}

// Not parallel: replaces the dialTCP seam.
func TestProbeDNSFailureIsInconclusive(t *testing.T) {
	orig := dialTCP
	t.Cleanup(func() { dialTCP = orig })
	dialTCP = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}
	}

	p := testpki.Standard(t)
	got, err := Probe(context.Background(), "x.invalid:50051", TrustPool(p.Root.Pool))
	if got != VerdictInconclusive {
		t.Fatalf("got %s (%v), want inconclusive", got, err)
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("err = %v, want a *net.DNSError", err)
	}
}

// A peer that accepts TCP and then speaks something other than TLS is a captive
// portal or a mangling middlebox. The caller's server would have completed the
// handshake.
func TestProbeNonTLSResponderIsIntercepted(t *testing.T) {
	t.Parallel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			c.Close()
		}
	}()

	p := testpki.Standard(t)
	got, err := Probe(context.Background(), localhostAddr(t, lis.Addr()), TrustPool(p.Root.Pool))
	if got != VerdictIntercepted || err == nil {
		t.Fatalf("got %s (%v), want intercepted with an error", got, err)
	}
}

// A middlebox that cannot negotiate TLS 1.3 is still an interceptor.
func TestProbeTLS12OnlyPeerWithForeignCertIsIntercepted(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	addr := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{p.Proxy},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})

	got, err := Probe(context.Background(), addr, TrustPool(p.Root.Pool))
	if got != VerdictIntercepted || !errors.Is(err, ErrForeignCertificate) {
		t.Fatalf("got %s (%v), want intercepted with ErrForeignCertificate", got, err)
	}
}

// A peer that accepts TCP and never answers gives no evidence. Running out of
// time is inconclusive, not interception.
func TestProbeSilentPeerIsInconclusive(t *testing.T) {
	t.Parallel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		// Hold every accepted connection open, silent, until the listener
		// closes at cleanup.
		var held []net.Conn
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()

	p := testpki.Standard(t)
	start := time.Now()
	got, err := probe(context.Background(), localhostAddr(t, lis.Addr()), TrustPool(p.Root.Pool), 200*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("probe took %s, want under 2s", elapsed)
	}
	if got != VerdictInconclusive {
		t.Fatalf("got %s (%v), want inconclusive", got, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}

// Not parallel: replaces the proxyFromEnvironment seam.
func TestProbeProxyRefusalIsInconclusive(t *testing.T) {
	proxy := fakeProxy(t, func(c net.Conn, _ *bufio.Reader) {
		_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	})
	orig := proxyFromEnvironment
	t.Cleanup(func() { proxyFromEnvironment = orig })
	proxyFromEnvironment = func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: proxy.addr}, nil
	}

	p := testpki.Standard(t)
	got, err := Probe(context.Background(), "origin.supertls.test:443", TrustPool(p.Root.Pool))
	if got != VerdictInconclusive {
		t.Fatalf("got %s (%v), want inconclusive", got, err)
	}
	if !errors.Is(err, ErrProxyConnect) {
		t.Fatalf("err = %v, want ErrProxyConnect", err)
	}
}

// A Trust no constructor built must not classify anything.
func TestProbeRefusesInvalidTrust(t *testing.T) {
	t.Parallel()
	got, err := Probe(context.Background(), "localhost:1", Trust{})
	if got != VerdictInconclusive || err == nil {
		t.Fatalf("got %s (%v), want inconclusive with an error", got, err)
	}
}

func TestHostPortDefaults(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"example.com":       "example.com:443",
		"example.com:50051": "example.com:50051",
		"[::1]:8443":        "[::1]:8443",
		"::1":               "[::1]:443",
		"[::1]":             "[::1]:443",
		"127.0.0.1":         "127.0.0.1:443",
	} {
		if got := hostPort(in); got != want {
			t.Errorf("hostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerdictString(t *testing.T) {
	t.Parallel()
	for v, want := range map[Verdict]string{
		VerdictInconclusive: "inconclusive",
		VerdictGenuine:      "genuine",
		VerdictIntercepted:  "intercepted",
		Verdict(99):         "unknown",
	} {
		if got := v.String(); got != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", int(v), got, want)
		}
	}
}
