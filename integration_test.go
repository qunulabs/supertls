package supertls_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/qunulabs/supertls"
	"github.com/qunulabs/supertls/internal/testpki"
	"github.com/qunulabs/supertls/server"
)

const sentinelServiceName = "sentinel.tunnel.v1.TunnelService"

func dialCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func assertTunnelled(t *testing.T, c *supertls.Conn, svc *server.Service, hook *hookLog) {
	t.Helper()
	if c.Mode() != supertls.ModeTunnel {
		t.Fatalf("Mode() = %s, want tunnel", c.Mode())
	}
	healthCheck(t, c.ClientConn())
	if n := svc.OpenTunnels(); n != 1 {
		t.Fatalf("OpenTunnels() = %d, want 1", n)
	}
	var saw bool
	for _, ch := range hook.all() {
		if ch.To == supertls.ModeTunnel && ch.Verdict == supertls.VerdictIntercepted {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("hook never saw To=tunnel Verdict=intercepted: %+v", hook.all())
	}
}

func TestTunnelSurvivesInterceptingProxy(t *testing.T) {
	p := testpki.Standard(t)
	backend, svc := startBackend(t, p)
	proxy := startInterceptingProxy(t, backend, p.Proxy, []string{"h2"})

	hook := &hookLog{}
	d := newDialer(t, p, hook)
	c, err := d.Dial(dialCtx(t), "localhost:"+portOf(t, proxy), innerCreds(p))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	assertTunnelled(t, c, svc, hook)
}

func TestTunnelSurvivesProxyThatDropsALPN(t *testing.T) {
	p := testpki.Standard(t)
	backend, svc := startBackend(t, p)
	proxy := startInterceptingProxy(t, backend, p.Proxy, nil)

	hook := &hookLog{}
	d := newDialer(t, p, hook)
	c, err := d.Dial(dialCtx(t), "localhost:"+portOf(t, proxy), innerCreds(p))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	assertTunnelled(t, c, svc, hook)
}

func TestCleanNetworkStaysOnTheDirectPath(t *testing.T) {
	p := testpki.Standard(t)
	backend, svc := startBackend(t, p)

	hook := &hookLog{}
	d := newDialer(t, p, hook)
	c, err := d.Dial(dialCtx(t), "localhost:"+portOf(t, backend), innerCreds(p))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if c.Mode() != supertls.ModeDirect {
		t.Fatalf("Mode() = %s, want direct", c.Mode())
	}
	healthCheck(t, c.ClientConn())
	if n := svc.OpenTunnels(); n != 0 {
		t.Fatalf("OpenTunnels() = %d, want 0", n)
	}
	for _, ch := range hook.all() {
		if ch.To == supertls.ModeTunnel {
			t.Fatalf("hook reported a switch to tunnel on a clean network: %+v", ch)
		}
	}
}

func TestInnerSessionStillVerifiesServerName(t *testing.T) {
	p := testpki.Standard(t)
	backend, _ := startBackend(t, p)
	proxy := startInterceptingProxy(t, backend, p.Proxy, []string{"h2"})

	// The server certificate has no IP SAN, so the inner session, which names
	// the server it dialled, must refuse it even inside a working tunnel.
	d := newDialer(t, p, nil, supertls.WithTunnelDialBudget(2*time.Second))
	c, err := d.Dial(dialCtx(t), "127.0.0.1:"+portOf(t, proxy), innerCreds(p))
	if err == nil {
		_ = c.Close()
		t.Fatal("Dial succeeded; the inner session did not verify the server name")
	}
	var de *supertls.DialError
	if !errors.As(err, &de) {
		t.Fatalf("error %T is not a *DialError: %v", err, err)
	}
	if de.Verdict != supertls.VerdictIntercepted {
		t.Fatalf("Verdict = %s, want intercepted", de.Verdict)
	}
	if de.Tunnel == nil {
		t.Fatal("Tunnel error is nil; the tunnel should have been tried and failed")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("error does not mention the certificate: %v", err)
	}
}

func TestGenuineServerWithBadCertIsReportedNotTunnelled(t *testing.T) {
	// The fixture's issuing CA became valid an hour ago, so a leaf "expired an
	// hour ago" under it would predate its own issuer, which no real CA does
	// and which the probe's pinned time (the chain's latest NotBefore + 1s)
	// would rightly treat as expired for the pin too. This hierarchy is
	// therefore older, with the same shape as the standard one.
	now := time.Now()
	root := testpki.NewRoot(t, "supertls old root", now.Add(-72*time.Hour), now.Add(24*time.Hour))
	issuing := root.Intermediate(t, "supertls old issuing", now.Add(-72*time.Hour), now.Add(24*time.Hour))
	p := &testpki.PKI{
		Root:    root,
		Issuing: issuing,
		Server:  issuing.ServerCert(t, now.Add(-48*time.Hour), now.Add(-time.Hour), "localhost", "origin.supertls.test"),
		Client:  issuing.ClientCert(t, "client-1", nil, now.Add(24*time.Hour)),
	}
	backend, svc := startBackend(t, p)

	d := newDialer(t, p, nil)
	c, err := d.Dial(dialCtx(t), "localhost:"+portOf(t, backend), innerCreds(p))
	if err == nil {
		_ = c.Close()
		t.Fatal("Dial succeeded against an expired server certificate")
	}
	var de *supertls.DialError
	if !errors.As(err, &de) {
		t.Fatalf("error %T is not a *DialError: %v", err, err)
	}
	if de.Verdict != supertls.VerdictGenuine {
		t.Fatalf("Verdict = %s, want genuine", de.Verdict)
	}
	if de.Tunnel != nil {
		t.Fatalf("Tunnel = %v, want nil: a genuine server is never tunnelled", de.Tunnel)
	}
	if n := svc.OpenTunnels(); n != 0 {
		t.Fatalf("OpenTunnels() = %d, want 0", n)
	}
	if d.Mode("localhost:"+portOf(t, backend)) == supertls.ModeTunnel {
		t.Fatal("mode cache switched to tunnel for a genuine server")
	}
}

func TestServiceNameInteropWithSentinelWireName(t *testing.T) {
	p := testpki.Standard(t)
	backend, svc := startBackend(t, p, server.WithServiceName(sentinelServiceName))
	proxy := startInterceptingProxy(t, backend, p.Proxy, []string{"h2"})

	hook := &hookLog{}
	d := newDialer(t, p, hook, supertls.WithServiceName(sentinelServiceName))
	c, err := d.Dial(dialCtx(t), "localhost:"+portOf(t, proxy), innerCreds(p))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	assertTunnelled(t, c, svc, hook)
}

func TestServiceNameMismatchFailsLoudly(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out a dial budget")
	}
	p := testpki.Standard(t)
	backend, svc := startBackend(t, p, server.WithServiceName(sentinelServiceName))
	proxy := startInterceptingProxy(t, backend, p.Proxy, []string{"h2"})

	d := newDialer(t, p, nil, supertls.WithTunnelDialBudget(2*time.Second))
	c, err := d.Dial(dialCtx(t), "localhost:"+portOf(t, proxy), innerCreds(p))
	if err == nil {
		_ = c.Close()
		t.Fatal("Dial succeeded with mismatched service names")
	}
	var de *supertls.DialError
	if !errors.As(err, &de) {
		t.Fatalf("error %T is not a *DialError: %v", err, err)
	}
	if !strings.Contains(err.Error(), "Unimplemented") {
		t.Fatalf("error does not name Unimplemented: %v", err)
	}
	if n := svc.OpenTunnels(); n != 0 {
		t.Fatalf("OpenTunnels() = %d, want 0", n)
	}
}

// watchedCreds wraps the caller's credentials and records every call that
// could alter them. credentials.NewTLS clones its tls.Config, so inspecting the
// config proves nothing; the credentials object is what a Dial could touch.
type watchedCreds struct {
	credentials.TransportCredentials
	overrides  *atomic.Int32
	handshakes *atomic.Int32
}

func newWatchedCreds(inner credentials.TransportCredentials) *watchedCreds {
	return &watchedCreds{TransportCredentials: inner, overrides: new(atomic.Int32), handshakes: new(atomic.Int32)}
}

func (w *watchedCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	w.handshakes.Add(1)
	return w.TransportCredentials.ClientHandshake(ctx, authority, raw)
}

func (w *watchedCreds) Clone() credentials.TransportCredentials {
	return &watchedCreds{TransportCredentials: w.TransportCredentials.Clone(), overrides: w.overrides, handshakes: w.handshakes}
}

//nolint:staticcheck // the method is part of the interface and is what is watched
func (w *watchedCreds) OverrideServerName(name string) error {
	w.overrides.Add(1)
	return w.TransportCredentials.OverrideServerName(name)
}

func TestDialDoesNotModifyCallerTLSConfig(t *testing.T) {
	p := testpki.Standard(t)
	backend, _ := startBackend(t, p)
	proxy := startInterceptingProxy(t, backend, p.Proxy, []string{"h2"})

	creds := newWatchedCreds(credentials.NewTLS(testpki.StrictClientTLS(p)))
	before, beforeClone := creds.Info(), creds.Clone().Info()

	d := newDialer(t, p, nil)
	c, err := d.Dial(dialCtx(t), "localhost:"+portOf(t, proxy), creds)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if c.Mode() != supertls.ModeTunnel {
		t.Fatalf("Mode() = %s, want tunnel", c.Mode())
	}
	healthCheck(t, c.ClientConn())

	// The caller's credentials must have run the inner handshake (so this
	// test sees the real path) and must never have been told another name.
	if creds.handshakes.Load() == 0 {
		t.Fatal("the caller's credentials never ran a handshake; the test is not exercising them")
	}
	if n := creds.overrides.Load(); n != 0 {
		t.Fatalf("OverrideServerName was called %d times on the caller's credentials", n)
	}
	if after := creds.Info(); after != before {
		t.Errorf("Info() changed: %+v -> %+v", before, after)
	}
	if afterClone := creds.Clone().Info(); afterClone != beforeClone {
		t.Errorf("Clone().Info() changed: %+v -> %+v", beforeClone, afterClone)
	}
}
