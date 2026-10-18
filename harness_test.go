package supertls_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/qunulabs/supertls"
	"github.com/qunulabs/supertls/internal/testpki"
	"github.com/qunulabs/supertls/server"
)

// startBackend runs the real server side: an outer gRPC server carrying the
// tunnel service and an inner gRPC server over the service's listener, both
// built from the same strict TLS configuration, with health SERVING on both.
// It returns the outer address and the service, whose OpenTunnels count tells a
// test whether the tunnel was used.
func startBackend(t *testing.T, p *testpki.PKI, opts ...server.Option) (string, *server.Service) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	svc, err := server.New(append([]server.Option{server.WithListenerAddr(lis.Addr())}, opts...)...)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	tlsConfig := testpki.StrictServerTLS(p)
	hs := health.NewServer()
	hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	outer := grpc.NewServer(append(
		[]grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))},
		svc.OuterServerOptions()...)...)
	svc.Register(outer)
	grpc_health_v1.RegisterHealthServer(outer, hs)

	inner := grpc.NewServer(append(
		[]grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))},
		svc.InnerServerOptions()...)...)
	grpc_health_v1.RegisterHealthServer(inner, hs)

	go func() { _ = outer.Serve(lis) }()
	go func() { _ = inner.Serve(svc.Listener()) }()
	t.Cleanup(func() { inner.Stop(); outer.Stop() })

	return lis.Addr().String(), svc
}

// relay pipes bytes between a and b in both directions and closes both as soon
// as either direction ends, as a real proxy does. Skipping that strands the
// upstream connection with nothing ever arriving on it.
func relay(a, b net.Conn) {
	var once sync.Once
	teardown := func() { once.Do(func() { _ = a.Close(); _ = b.Close() }) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer teardown(); _, _ = io.Copy(a, b) }()
	go func() { defer wg.Done(); defer teardown(); _, _ = io.Copy(b, a) }()
	wg.Wait()
}

// interceptConn is what a TLS-inspecting proxy does with one accepted
// connection: terminate TLS with its own certificate, open a separate TLS
// connection to upstream, and relay between them. alpn is what the proxy offers
// the client; nil models a proxy that does not echo h2.
func interceptConn(down net.Conn, upstream string, cert tls.Certificate, alpn []string) {
	defer down.Close()
	downTLS := tls.Server(down, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   alpn,
	})
	if err := downTLS.Handshake(); err != nil {
		return
	}
	defer downTLS.Close()
	upTLS, err := tls.Dial("tcp", upstream, &tls.Config{
		//nolint:gosec // the proxy is the attacker in this test
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		return
	}
	defer upTLS.Close()
	relay(downTLS, upTLS)
}

// startInterceptingProxy is a stand-in for a TLS-inspecting corporate proxy
// listening on a loopback address, with cert as its own certificate.
func startInterceptingProxy(t *testing.T, upstream string, cert tls.Certificate, alpn []string) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			down, err := lis.Accept()
			if err != nil {
				return
			}
			go interceptConn(down, upstream, cert, alpn)
		}
	}()
	return lis.Addr().String()
}

// healthCheck fails the test unless the server behind cc reports SERVING.
func healthCheck(t *testing.T, cc *grpc.ClientConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := grpc_health_v1.NewHealthClient(cc).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check: %v (code %s)", err, status.Code(err))
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("health status = %s, want SERVING", resp.GetStatus())
	}
}

// innerCreds are the caller's own strict credentials for the inner session.
func innerCreds(p *testpki.PKI) credentials.TransportCredentials {
	return credentials.NewTLS(testpki.StrictClientTLS(p))
}

// hookLog collects the mode changes a Dialer reports.
type hookLog struct {
	mu      sync.Mutex
	changes []supertls.ModeChange
}

func (h *hookLog) record(c supertls.ModeChange) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.changes = append(h.changes, c)
}

func (h *hookLog) all() []supertls.ModeChange {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]supertls.ModeChange(nil), h.changes...)
}

// newDialer builds a Dialer trusting the fixture's root, with the hook wired.
func newDialer(t *testing.T, p *testpki.PKI, hook *hookLog, opts ...supertls.Option) *supertls.Dialer {
	t.Helper()
	// A failed direct dial on a clean-looking network waits out its whole
	// budget, so the tests shorten it; a caller's own option still wins.
	opts = append([]supertls.Option{supertls.WithDirectDialBudget(time.Second)}, opts...)
	if hook != nil {
		opts = append(opts, supertls.WithOnModeChange(hook.record))
	}
	d, err := supertls.NewDialer(supertls.TrustPool(p.Root.Pool), opts...)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	return d
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	return port
}
