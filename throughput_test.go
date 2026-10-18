package supertls

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/qunulabs/supertls/internal/testpki"
	"github.com/qunulabs/supertls/server"
	"github.com/qunulabs/supertls/tunnelpb"
)

// The measurement this file exists for.
//
// The flow-control constants in windows.go were chosen from arithmetic, and the
// arithmetic makes a claim that arithmetic cannot settle: that nesting two
// HTTP/2 connections costs a few percent of throughput, and that a small RPC
// queued behind a bulk transfer waits seconds rather than minutes. Both depend
// on how two windows in series actually behave, which is exactly what an
// estimate is worst at.
//
// PACKET LOSS IS NOT SIMULATED, and cannot be honestly simulated here: loss is a
// property of the IP layer, and dropping bytes from a net.Conn does not model it,
// it corrupts the TLS stream. Reproducing loss needs a real network emulator
// (`tc qdisc add dev lo root netem loss 1% delay 30ms`, which needs root). What
// is modelled is one-way delay and link bandwidth, which is what the window
// sizes were chosen against.
const (
	linkRTT       = 60 * time.Millisecond
	linkBandwidth = 10 << 17 // bytes/sec, about 10 Mbit/s
	bulkPayload   = 4 << 20  // 4 MiB, a small dataset artifact
	bulkFrame     = 64 << 10
)

// bulkServiceName is the service the bulk faucet is registered under, so that
// it never collides with the tunnel service on the outer server of the tunnel
// arm.
const bulkServiceName = "supertls.test.Bulk"

func TestTunnelThroughputVersusDirect(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput measurement moves real bytes over a shaped link; slow by construction")
	}
	p := testpki.Standard(t)

	direct := startBulkBackend(t, p)
	tunnelled := startBackendWithBulkInner(t, p)

	directAddr := startShaper(t, direct)
	pinnedAddr := startShaper(t, direct)
	tunnelAddr := startShaper(t, tunnelled)

	// The server certificate names localhost only, and the shapers listen on
	// 127.0.0.1, so every inner session names the server explicitly.
	innerTLS := func() credentials.TransportCredentials {
		cfg := testpki.StrictClientTLS(p)
		cfg.ServerName = "localhost"
		return credentials.NewTLS(cfg)
	}

	dc, err := grpc.NewClient(directAddr, grpc.WithTransportCredentials(innerTLS()))
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	t.Cleanup(func() { dc.Close() })

	// The like-for-like arm. Without it the comparison is not tunnel versus no
	// tunnel, it is pinned windows versus gRPC's bandwidth-delay estimator, and
	// those are different questions with different answers.
	pinned, err := grpc.NewClient(pinnedAddr,
		grpc.WithTransportCredentials(innerTLS()),
		grpc.WithInitialWindowSize(DefaultInnerStreamWindow),
		grpc.WithInitialConnWindowSize(DefaultInnerConnWindow),
	)
	if err != nil {
		t.Fatalf("pinned-window dial: %v", err)
	}
	t.Cleanup(func() { pinned.Close() })

	d, err := NewDialer(TrustPool(p.Root.Pool), WithTunnelDialBudget(30*time.Second))
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tc, err := d.tunnelFn(dialCtx, tunnelAddr, innerTLS(), nil)
	if err != nil {
		t.Fatalf("tunnelled dial: %v", err)
	}
	t.Cleanup(func() { _ = tc.Close() })

	directResult := measure(t, dc)
	pinnedResult := measure(t, pinned)
	tunnelResult := measure(t, tc.ClientConn())

	t.Logf("link: %v RTT, %.1f Mbit/s, %d MiB payload",
		linkRTT, float64(linkBandwidth)*8/1e6, bulkPayload>>20)
	t.Logf("%-10s %10s %12s %14s", "path", "elapsed", "throughput", "worst RPC")
	for _, r := range []struct {
		name string
		res  result
	}{
		{"direct", directResult},
		{"direct+win", pinnedResult},
		{"tunnelled", tunnelResult},
	} {
		t.Logf("%-10s %10s %9.0f KiB/s %14s", r.name,
			r.res.elapsed.Round(time.Millisecond),
			float64(bulkPayload)/1024/r.res.elapsed.Seconds(),
			r.res.worstRPC.Round(time.Millisecond))
	}
	t.Logf("cost of nesting, like for like: %+.1f%% against direct with the same windows",
		(tunnelResult.elapsed.Seconds()/pinnedResult.elapsed.Seconds()-1)*100)
	t.Logf("effect against direct as it currently dials: %+.1f%%",
		(tunnelResult.elapsed.Seconds()/directResult.elapsed.Seconds()-1)*100)

	// A control RPC that waits longer than a few seconds behind bulk data means
	// the window sizing is wrong, which is the failure the pinned values exist
	// to prevent.
	if tunnelResult.worstRPC > 10*time.Second {
		t.Errorf("a control RPC waited %v behind bulk data on the tunnel; "+
			"head-of-line blocking is out of budget, revisit the outer stream window",
			tunnelResult.worstRPC)
	}
	// Catches a framing regression, such as a frame per small write, which
	// would multiply the per-byte cost of the tunnel without moving the worst
	// control RPC.
	if tunnelResult.elapsed > 2*pinnedResult.elapsed {
		t.Errorf("tunnelled transfer took %v, more than twice the %v of direct with the same windows",
			tunnelResult.elapsed, pinnedResult.elapsed)
	}
}

type result struct {
	elapsed  time.Duration
	worstRPC time.Duration
}

// measure streams bulkPayload while probing with small RPCs on the same
// connection, because the number that matters is not throughput alone: it is
// whether a small control RPC can still get through while a large transfer is
// in flight.
func measure(t *testing.T, conn *grpc.ClientConn) result {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stop := make(chan struct{})
	worst := make(chan time.Duration, 1)
	go func() {
		hc := grpc_health_v1.NewHealthClient(conn)
		var max time.Duration
		for {
			select {
			case <-stop:
				worst <- max
				return
			default:
			}
			start := time.Now()
			if _, err := hc.Check(ctx, &grpc_health_v1.HealthCheckRequest{}); err != nil {
				worst <- max
				return
			}
			if d := time.Since(start); d > max {
				max = d
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	start := time.Now()
	stream, err := openStream(ctx, conn, bulkServiceName)
	if err != nil {
		t.Fatalf("open bulk stream: %v", err)
	}
	if err := stream.Send(&tunnelpb.Frame{Data: []byte("go")}); err != nil {
		t.Fatalf("start bulk: %v", err)
	}
	got := 0
	for got < bulkPayload {
		f, err := stream.Recv()
		if err != nil {
			t.Fatalf("bulk recv after %d bytes: %v", got, err)
		}
		got += len(f.GetData())
	}
	elapsed := time.Since(start)
	close(stop)

	return result{elapsed: elapsed, worstRPC: <-worst}
}

// bulkSource is a data faucet. Reusing the tunnel proto rather than inventing
// one keeps the benchmark free of generated test-only code; nothing here
// tunnels anything.
type bulkSource struct {
	tunnelpb.UnimplementedTunnelServiceServer
}

func (bulkSource) Open(stream grpc.BidiStreamingServer[tunnelpb.Frame, tunnelpb.Frame]) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	payload := make([]byte, bulkFrame)
	for sent := 0; sent < bulkPayload; sent += bulkFrame {
		if err := stream.Send(&tunnelpb.Frame{Data: payload}); err != nil {
			return err
		}
	}
	return nil
}

// registerBulk registers the faucet under bulkServiceName by copying the tunnel
// service descriptor with another name.
func registerBulk(s grpc.ServiceRegistrar) {
	desc := tunnelpb.TunnelService_ServiceDesc
	desc.ServiceName = bulkServiceName
	s.RegisterService(&desc, bulkSource{})
}

func healthServer() *health.Server {
	hs := health.NewServer()
	hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	return hs
}

// startBulkBackend is the direct-path control: one server, strict TLS, no tunnel.
func startBulkBackend(t *testing.T, p *testpki.PKI) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(testpki.StrictServerTLS(p))))
	registerBulk(gs)
	grpc_health_v1.RegisterHealthServer(gs, healthServer())
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

// startBackendWithBulkInner mirrors production: the real tunnel service on the
// outer server, and the bulk source on the inner one.
func startBackendWithBulkInner(t *testing.T, p *testpki.PKI) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	svc, err := server.New(server.WithListenerAddr(lis.Addr()))
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	cfg := testpki.StrictServerTLS(p)

	outer := grpc.NewServer(append(
		[]grpc.ServerOption{grpc.Creds(credentials.NewTLS(cfg))},
		svc.OuterServerOptions()...)...)
	svc.Register(outer)

	inner := grpc.NewServer(append(
		[]grpc.ServerOption{grpc.Creds(credentials.NewTLS(cfg))},
		svc.InnerServerOptions()...)...)
	registerBulk(inner)
	grpc_health_v1.RegisterHealthServer(inner, healthServer())

	go func() { _ = outer.Serve(lis) }()
	go func() { _ = inner.Serve(svc.Listener()) }()
	t.Cleanup(func() { inner.Stop(); outer.Stop() })
	return lis.Addr().String()
}

// startShaper interposes a delay-and-bandwidth model between the client and
// upstream, and returns the address to dial instead.
//
// Each direction keeps a virtual clock: a chunk of n bytes arriving at t is
// released at max(lastRelease, t) + n/bandwidth + rtt/2. That is a link with a
// serialisation delay and a propagation delay, which is what the window sizes
// were chosen against. It is not a congestion-controlled path.
func startShaper(t *testing.T, upstream string) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("shaper listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })

	go func() {
		for {
			down, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					down.Close()
					return
				}
				var once sync.Once
				teardown := func() { once.Do(func() { up.Close(); down.Close() }) }
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); defer teardown(); shape(up, down) }()
				go func() { defer wg.Done(); defer teardown(); shape(down, up) }()
				wg.Wait()
			}()
		}
	}()
	return lis.Addr().String()
}

func shape(dst io.Writer, src io.Reader) {
	buf := make([]byte, 32<<10)
	release := time.Now()
	for {
		n, err := src.Read(buf)
		if n > 0 {
			now := time.Now()
			if release.Before(now) {
				release = now
			}
			release = release.Add(time.Duration(float64(n) / linkBandwidth * float64(time.Second)))
			if d := time.Until(release.Add(linkRTT / 2)); d > 0 {
				time.Sleep(d)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
