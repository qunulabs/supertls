package server

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

// A client may ping every 60 seconds with PermitWithoutStream, and between calls
// it holds no open stream. Under gRPC's DEFAULT enforcement policy that is
// abuse: an idle connection scores a strike for every ping, and the third strike
// sends GOAWAY ENHANCE_YOUR_CALM and closes the connection.
//
// The masking is that the strike counter clears whenever the server writes a
// frame, so calls arriving faster than three pings keep clearing it. That is a
// property of the client's call rate, not a guarantee, which is why this is
// tested rather than reasoned about.
//
// The test pings far faster than production so it finishes in seconds. What it
// asserts is the thing that matters: that a silent, pinging connection is not
// torn down by the server.
func TestKeepalivePolicyToleratesIdlePinging(t *testing.T) {
	t.Parallel()

	// This test cannot be made fast, which is why it is skipped under -short.
	// gRPC clamps client keepalive to a 10s floor (internal.KeepaliveMinPingTime),
	// and the server needs FOUR pings to react: the first is never a strike
	// (lastPingAt is still the zero time), then three strikes exceed
	// maxPingStrikes. So the earliest a default-policy server sends its GOAWAY is
	// 40 seconds in.
	const (
		clientPingEvery = 10 * time.Second
		observeFor      = 50 * time.Second
	)
	if testing.Short() {
		t.Skip("needs ~50s: gRPC clamps client pings to 10s and the server reacts on the fourth")
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// The production policy, not a copy of it.
	srv := grpc.NewServer(KeepalivePolicy())
	hs := health.NewServer()
	grpc_health_v1.RegisterHealthServer(srv, hs)
	hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                clientPingEvery,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Must outlast observeFor: watch derives from this, and a shorter parent
	// would end the observation early and pass regardless of the server policy.
	ctx, cancel := context.WithTimeout(context.Background(), observeFor+30*time.Second)
	defer cancel()

	conn.Connect()
	for conn.GetState() != connectivity.Ready {
		if !conn.WaitForStateChange(ctx, conn.GetState()) {
			t.Fatalf("connection never became ready (last state %s)", conn.GetState())
		}
	}

	// Deliberately issue no calls: a call makes the server write a frame, which
	// resets the strike counter and hides exactly the bug under test.
	watch, watchCancel := context.WithTimeout(ctx, observeFor)
	defer watchCancel()

	if conn.WaitForStateChange(watch, connectivity.Ready) {
		t.Fatalf("server dropped a silent, pinging connection after %s (state %s); "+
			"the keepalive enforcement policy is not in effect", observeFor, conn.GetState())
	}
}

// KeepaliveMinTime must stay below gRPC's client-side ping floor.
//
// A client may request any ping interval; gRPC silently clamps it up to
// internal.KeepaliveMinPingTime and no further. So a server threshold at or
// above that floor strikes a client that is behaving exactly as the library
// allows, and the symptom is the same GOAWAY the policy exists to prevent.
//
// This runs in microseconds, unlike the behavioural test above, so a regression
// here is caught on every run rather than only when the slow test is enabled.
func TestKeepaliveMinTimeIsBelowGRPCClientPingFloor(t *testing.T) {
	t.Parallel()

	// google.golang.org/grpc/internal.KeepaliveMinPingTime, which is not
	// importable from here; it is asserted rather than referenced.
	const grpcClientPingFloor = 10 * time.Second

	if KeepaliveMinTime >= grpcClientPingFloor {
		t.Fatalf("KeepaliveMinTime is %s, which is not below gRPC's %s client ping floor: "+
			"a client at the floor would be struck by the very policy meant to tolerate it",
			KeepaliveMinTime, grpcClientPingFloor)
	}
}
