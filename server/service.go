package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/qunulabs/supertls/conn"
	"github.com/qunulabs/supertls/tunnelpb"
)

var errTunnelExpired = errors.New("tunnel exceeded its maximum lifetime")

// Service is the tunnel service: it accepts the outer streams clients open and
// hands each to the inner gRPC server as a net.Conn. Build one with New.
type Service struct {
	tunnelpb.UnimplementedTunnelServiceServer

	cfg      config
	limiter  *limiter
	listener *conn.Listener
}

// New returns a Service. Every option is validated here; an unusable one is an
// error wrapping ErrInvalidOption or ErrWindowInvariant.
func New(opts ...Option) (*Service, error) {
	cfg := config{
		name:   DefaultServiceName,
		log:    slog.Default(),
		limits: DefaultLimits(),
	}
	for _, o := range opts {
		if o == nil {
			return nil, fmt.Errorf("%w: nil option", ErrInvalidOption)
		}
		if err := o(&cfg); err != nil {
			return nil, err
		}
	}
	return &Service{
		cfg:      cfg,
		limiter:  newLimiter(cfg.limits, time.Now),
		listener: conn.NewListener(cfg.addr, cfg.limits.AcceptTimeout),
	}, nil
}

// Register registers the tunnel service on the OUTER server only, under the
// configured service name. Registering it on the inner server would let a tunnel
// nest inside a tunnel.
func (s *Service) Register(outer grpc.ServiceRegistrar) {
	// The generated descriptor is shared package state, so it is copied, and its
	// stream slice with it, before the name is changed.
	desc := tunnelpb.TunnelService_ServiceDesc
	desc.Streams = append([]grpc.StreamDesc(nil), desc.Streams...)
	desc.ServiceName = s.cfg.name
	outer.RegisterService(&desc, s)
}

// Listener returns the listener the INNER gRPC server must serve. Closing it
// makes that server's Serve return, and makes Open refuse new tunnels with
// Unavailable.
func (s *Service) Listener() net.Listener { return s.listener }

// OpenTunnels reports how many tunnel slots are currently held: every Open
// call that has passed the limits and not yet returned. That includes tunnels
// the inner server has not accepted yet (still waiting in the listener's
// Deliver), so it can exceed the number of connections the inner server is
// serving. It is the count MaxConcurrent and MaxPerAddress are checked against.
func (s *Service) OpenTunnels() int { return s.limiter.open() }

// Open implements tunnelpb.TunnelServiceServer. Register is what exposes it;
// call it directly only in tests.
//
// It carries one inner connection and understands nothing about what is inside
// it. The bytes are a complete TLS session terminated by the inner gRPC server,
// so this handler cannot read or alter them, and neither can anything between
// here and the client.
//
// The handler blocks for the connection's whole life. That is load-bearing:
// returning would end the stream and kill the connection underneath the inner
// server. It is also why shutdown must stop the inner server FIRST (see
// GracefulStop).
func (s *Service) Open(stream grpc.BidiStreamingServer[tunnelpb.Frame, tunnelpb.Frame]) error {
	ctx := stream.Context()

	local, remote := peerAddrs(ctx)
	if remote == nil {
		// Cannot happen on a served stream, but a nil address would reach the
		// caller's own peer-address handling and gRPC's error formatting, so the
		// handler refuses rather than improvises.
		return status.Error(codes.Internal, "tunnel: no peer address on stream")
	}
	ip := addrHost(remote)

	release, err := s.limiter.acquire(ip)
	if err != nil {
		return err
	}
	defer release()

	c := conn.NewConn(stream, conn.Options{
		Local:  local,
		Remote: remote,
	})
	defer c.Close()

	if err := s.listener.Deliver(ctx, c); err != nil {
		if errors.Is(err, conn.ErrDeliverTimeout) {
			return status.Error(codes.ResourceExhausted, "tunnel accept backlog")
		}
		if errors.Is(err, net.ErrClosed) {
			return status.Error(codes.Unavailable, "server draining")
		}
		return status.FromContextError(err).Err()
	}

	started := time.Now()
	s.cfg.log.InfoContext(ctx, "supertls: tunnel opened", "peer", ip)

	timer := time.NewTimer(s.cfg.limits.MaxLifetime)
	defer timer.Stop()

	// Two nested TLS layers make packet capture useless for diagnosis, so this
	// log line is the only external evidence a tunnel existed. Keep it.
	var reason string
	select {
	case <-c.Done():
		reason = "inner connection closed"
	case <-ctx.Done():
		reason = "outer stream ended"
	case <-timer.C:
		reason = errTunnelExpired.Error()
	}
	s.cfg.log.InfoContext(ctx, "supertls: tunnel closed",
		"peer", ip, "duration", time.Since(started).Round(time.Second), "reason", reason)
	return nil
}

// peerAddrs returns the OUTER connection's addresses.
//
// The inner connection reports these as its own, which is what keeps handlers
// that read the peer address working unchanged and unaware that they are behind
// a tunnel. A synthetic address here would break anything that stores or parses
// the client address.
func peerAddrs(ctx context.Context) (local, remote net.Addr) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, nil
	}
	return p.LocalAddr, p.Addr
}

// addrHost renders an address as a bare host.
func addrHost(a net.Addr) string {
	s := a.String()
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

var _ tunnelpb.TunnelServiceServer = (*Service)(nil)
