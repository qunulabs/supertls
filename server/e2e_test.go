package server

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/qunulabs/supertls/conn"
	"github.com/qunulabs/supertls/internal/testpki"
	"github.com/qunulabs/supertls/tunnelpb"
)

// harness stands up the real nesting: an outer gRPC server carrying the tunnel
// service, and an inner gRPC server over the service's listener, both built from
// the SAME tls.Config value.
type harness struct {
	pki      *testpki.PKI
	svc      *Service
	name     string
	port     string
	outerCon *grpc.ClientConn
	outer    *grpc.Server
	inner    *grpc.Server
	// innerPeer receives the peer of every call that reaches the inner server.
	innerPeer chan *peer.Peer
}

// limitsWith returns DefaultLimits with mut applied.
func limitsWith(mut func(*Limits)) Limits {
	l := DefaultLimits()
	mut(&l)
	return l
}

func newHarness(t *testing.T, opts ...Option) *harness {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	svc, err := New(append([]Option{WithListenerAddr(lis.Addr())}, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	name := svc.cfg.name

	p := testpki.Standard(t)
	tlsConfig := testpki.StrictServerTLS(p)

	outer := grpc.NewServer(append(
		[]grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))},
		svc.OuterServerOptions()...)...)
	svc.Register(outer)

	h := &harness{pki: p, svc: svc, name: name, port: port, outer: outer, innerPeer: make(chan *peer.Peer, 16)}

	inner := grpc.NewServer(append(
		[]grpc.ServerOption{
			grpc.Creds(credentials.NewTLS(tlsConfig)),
			grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
				if pr, ok := peer.FromContext(ctx); ok {
					select {
					case h.innerPeer <- pr:
					default:
					}
				}
				return next(ctx, req)
			}),
		},
		svc.InnerServerOptions()...)...)
	// A stand-in for the real services. What is under test is the transport and
	// the identity it carries, not any handler.
	hs := health.NewServer()
	hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(inner, hs)
	h.inner = inner

	go func() { _ = outer.Serve(lis) }()
	go func() { _ = inner.Serve(svc.Listener()) }()
	t.Cleanup(func() { inner.Stop(); outer.Stop() })

	// The outer connection is deliberately permissive: a proxy could terminate
	// it, and nothing about the security of the inner session depends on it.
	outerCon, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // the inner session verifies
			MinVersion:         tls.VersionTLS12,
		})))
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	t.Cleanup(func() { _ = outerCon.Close() })
	h.outerCon = outerCon
	return h
}

// rawStream opens the tunnel stream by hand, under the harness's service name.
func (h *harness) rawStream(ctx context.Context) (grpc.BidiStreamingClient[tunnelpb.Frame, tunnelpb.Frame], error) {
	cs, err := h.outerCon.NewStream(ctx, &tunnelpb.TunnelService_ServiceDesc.Streams[0], "/"+h.name+"/Open")
	if err != nil {
		return nil, err
	}
	return &grpc.GenericClientStream[tunnelpb.Frame, tunnelpb.Frame]{ClientStream: cs}, nil
}

// innerConn dials the inner session through the tunnel, using authority to
// derive the ServerName the inner handshake verifies.
func (h *harness) innerConn(t *testing.T, authority string) *grpc.ClientConn {
	t.Helper()

	cc, err := grpc.NewClient("passthrough:///"+authority,
		grpc.WithTransportCredentials(credentials.NewTLS(testpki.StrictClientTLS(h.pki))),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			// The stream must outlive gRPC's dial context, which is bounded. The
			// connection owns it and cancels it on Close.
			sctx, cancel := context.WithCancel(context.Background())
			stream, err := h.rawStream(sctx)
			if err != nil {
				cancel()
				return nil, err
			}
			return conn.NewConn(stream, conn.Options{Teardown: cancel}), nil
		}),
	)
	if err != nil {
		t.Fatalf("inner dial: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func (h *harness) check(t *testing.T, cc *grpc.ClientConn) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := grpc_health_v1.NewHealthClient(cc).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		return err
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("got %s, want SERVING", resp.GetStatus())
	}
	return nil
}

// waitOpen polls OpenTunnels until pred holds or the timeout passes.
func (h *harness) waitOpen(timeout time.Duration, pred func(int) bool) int {
	deadline := time.Now().Add(timeout)
	for {
		n := h.svc.OpenTunnels()
		if pred(n) || time.Now().After(deadline) {
			return n
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// The integration test the design rests on: a real gRPC call, through a real
// tunnel, over a real nested mutual-TLS session.
func TestTunnelCarriesARealRPC(t *testing.T) {
	h := newHarness(t)
	cc := h.innerConn(t, "localhost:"+h.port)

	if err := h.check(t, cc); err != nil {
		t.Fatalf("RPC through the tunnel failed: %v", err)
	}
	if n := h.svc.OpenTunnels(); n != 1 {
		t.Fatalf("OpenTunnels() = %d, want 1", n)
	}
}

// A deployment that keeps a service name already on the wire must still tunnel.
func TestTunnelCarriesARealRPCUnderACustomServiceName(t *testing.T) {
	h := newHarness(t, WithServiceName("sentinel.tunnel.v1.TunnelService"))
	cc := h.innerConn(t, "localhost:"+h.port)

	if err := h.check(t, cc); err != nil {
		t.Fatalf("RPC through the tunnel failed: %v", err)
	}
}

// Hostname verification must still be live on the inner session.
//
// The passthrough target is what gRPC derives ServerName from, and getting it
// wrong silently disables SAN checking: the tunnel would still work, every test
// above would still pass, and the inner session would have quietly stopped
// checking who it was talking to. The test chain's server leaf has a SAN for
// localhost and none for 127.0.0.1, so dialling by address MUST fail.
func TestInnerSessionStillVerifiesServerName(t *testing.T) {
	h := newHarness(t)
	cc := h.innerConn(t, "127.0.0.1:"+h.port)

	err := h.check(t, cc)
	if err == nil {
		t.Fatal("inner handshake accepted a server certificate with no SAN for the dialled name: " +
			"hostname verification is not in effect through the tunnel")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "SAN") {
		t.Fatalf("failed, but not for a certificate reason: %v", err)
	}
}

// The inner connection must report the OUTER connection's address as its peer,
// or every handler that reads the client address sees a placeholder.
func TestTunnelReportsRealPeerAddress(t *testing.T) {
	h := newHarness(t)
	cc := h.innerConn(t, "localhost:"+h.port)
	if err := h.check(t, cc); err != nil {
		t.Fatalf("RPC through the tunnel failed: %v", err)
	}

	select {
	case pr := <-h.innerPeer:
		tcp, ok := pr.Addr.(*net.TCPAddr)
		if !ok {
			t.Fatalf("peer address is %T (%v), want *net.TCPAddr", pr.Addr, pr.Addr)
		}
		if !tcp.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("peer IP is %v, want 127.0.0.1", tcp.IP)
		}
		if tcp.Port == 0 {
			t.Fatal("peer port is zero")
		}
		if pr.Addr.String() == "tunnel" {
			t.Fatal("peer is the placeholder address")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the inner server saw no call")
	}
}

// A tunnel carrying no RPCs must be reclaimed.
//
// The hole this closes: the inner server verifies a client certificate only if
// one is given and every authorisation decision is made per RPC, so a peer that
// completes the inner handshake and then issues nothing is never authorised and,
// without MaxConnectionIdle, never disconnected either. The handshake timeout
// does not reach it because the handshake succeeded.
//
// What is actually under test is the CHAIN, not gRPC's option: the inner server
// must send GOAWAY, that must close the tunnel's net.Conn, the Open handler must
// notice and return, and the limiter slot must come back. Any break in that
// leaves the slot held for hours with the option set and looking correct.
func TestIdleTunnelIsReclaimed(t *testing.T) {
	const idle = 1500 * time.Millisecond
	h := newHarness(t, WithLimits(limitsWith(func(l *Limits) { l.InnerMaxConnectionIdle = idle })))
	cc := h.innerConn(t, "localhost:"+h.port)

	if err := h.check(t, cc); err != nil {
		t.Fatalf("first RPC through the tunnel: %v", err)
	}
	if n := h.svc.OpenTunnels(); n != 1 {
		t.Fatalf("after one RPC: %d tunnels open, want 1", n)
	}

	if n := h.waitOpen(10*idle, func(n int) bool { return n == 0 }); n != 0 {
		t.Fatalf("tunnel still held %s after its last RPC: %d open. "+
			"An unauthenticated peer can squat a slot for the whole lifetime", 10*idle, n)
	}
}

// A reclaimed tunnel must not break the client, or the fix above trades a
// resource hole for an outage.
//
// The client opens the tunnel inside the inner connection's dialler, so gRPC is
// expected to redial through a FRESH tunnel and re-handshake. This asserts that
// actually happens rather than assuming it: an RPC issued after the reclaim must
// succeed.
func TestClientSurvivesAnIdleReclaim(t *testing.T) {
	const idle = 1500 * time.Millisecond
	h := newHarness(t, WithLimits(limitsWith(func(l *Limits) { l.InnerMaxConnectionIdle = idle })))
	cc := h.innerConn(t, "localhost:"+h.port)

	if err := h.check(t, cc); err != nil {
		t.Fatalf("first RPC: %v", err)
	}
	if n := h.waitOpen(10*idle, func(n int) bool { return n == 0 }); n != 0 {
		t.Fatalf("tunnel was not reclaimed, %d still open", n)
	}

	// grpc.WaitForReady is deliberately NOT used, so this reproduces what a
	// client that does not set it actually experiences.
	var lastErr error
	for range 5 {
		if lastErr = h.check(t, cc); lastErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("client did not recover through a fresh tunnel after the reclaim: %v", lastErr)
	}
	if n := h.svc.OpenTunnels(); n != 1 {
		t.Fatalf("after recovery: %d tunnels open, want 1", n)
	}
}

func TestTunnelLimitRefusalIsResourceExhausted(t *testing.T) {
	h := newHarness(t, WithLimits(limitsWith(func(l *Limits) { l.MaxConcurrent, l.MaxPerAddress = 1, 1 })))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first, err := h.rawStream(ctx)
	if err != nil {
		t.Fatalf("first stream: %v", err)
	}
	if n := h.waitOpen(5*time.Second, func(n int) bool { return n == 1 }); n != 1 {
		t.Fatalf("first tunnel never opened: %d open", n)
	}
	_ = first

	second, err := h.rawStream(ctx)
	if err != nil {
		t.Fatalf("second stream: %v", err)
	}
	_, err = second.Recv()
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second tunnel: got %v, want ResourceExhausted", err)
	}
	if n := h.svc.OpenTunnels(); n != 1 {
		t.Fatalf("%d tunnels open after a refusal, want 1", n)
	}
}

func TestMaxLifetimeEndsTunnel(t *testing.T) {
	h := newHarness(t, WithLimits(limitsWith(func(l *Limits) { l.MaxLifetime = 500 * time.Millisecond })))
	cc := h.innerConn(t, "localhost:"+h.port)

	if err := h.check(t, cc); err != nil {
		t.Fatalf("RPC through the tunnel: %v", err)
	}
	if n := h.waitOpen(5*time.Second, func(n int) bool { return n == 0 }); n != 0 {
		t.Fatalf("tunnel still open %d after exceeding its maximum lifetime", n)
	}
}

// A peer that sends more than one frame may legally carry ends the tunnel
// rather than being buffered.
func TestOversizedFrameEndsTunnel(t *testing.T) {
	h := newHarness(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := h.rawStream(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if n := h.waitOpen(5*time.Second, func(n int) bool { return n == 1 }); n != 1 {
		t.Fatalf("tunnel never opened: %d open", n)
	}
	if err := s.Send(&tunnelpb.Frame{Data: make([]byte, conn.MaxFrameBytes+1)}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if n := h.waitOpen(5*time.Second, func(n int) bool { return n == 0 }); n != 0 {
		t.Fatalf("tunnel still open after an oversized frame: %d open", n)
	}
}

// Opening a tunnel while the inner listener is closed, which is what draining
// does, answers Unavailable. It must not hang and must not be Internal.
func TestOpenDuringDrainIsUnavailable(t *testing.T) {
	h := newHarness(t)
	_ = h.svc.Listener().Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := h.rawStream(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	_, err = s.Recv()
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
	if n := h.waitOpen(5*time.Second, func(n int) bool { return n == 0 }); n != 0 {
		t.Fatalf("%d tunnels still open after a refused tunnel, want 0", n)
	}
}

// Stopping the inner server first must release every tunnel handler, so the
// whole stop finishes inside its budget.
func TestGracefulStopInnerFirstDoesNotHang(t *testing.T) {
	h := newHarness(t)
	cc := h.innerConn(t, "localhost:"+h.port)
	if err := h.check(t, cc); err != nil {
		t.Fatalf("RPC through the tunnel: %v", err)
	}
	if n := h.svc.OpenTunnels(); n != 1 {
		t.Fatalf("OpenTunnels() = %d, want 1", n)
	}

	done := make(chan struct{})
	go func() {
		h.svc.GracefulStop(h.inner, h.outer, 4*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("GracefulStop did not return within 3s with a live tunnel")
	}
	if n := h.svc.OpenTunnels(); n != 0 {
		t.Fatalf("%d tunnels still open after the stop, want 0", n)
	}
}

// Documents the trap GracefulStop exists to avoid: stopping the outer server
// first waits on tunnel handlers that wait on an inner server nobody stopped.
func TestOuterFirstStopBlocksOnLiveTunnel(t *testing.T) {
	h := newHarness(t)
	cc := h.innerConn(t, "localhost:"+h.port)
	if err := h.check(t, cc); err != nil {
		t.Fatalf("RPC through the tunnel: %v", err)
	}

	done := make(chan struct{})
	go func() {
		h.outer.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("outer GracefulStop returned with a live tunnel: the ordering trap no longer holds, " +
			"so the stop order in GracefulStop may no longer be needed")
	case <-time.After(time.Second):
	}

	h.inner.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("outer GracefulStop still blocked after the inner server stopped")
	}
}
