package server

import (
	"fmt"
	"log/slog"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/qunulabs/supertls/internal/servicename"
)

// config is what the options build.
type config struct {
	name    string
	log     *slog.Logger
	limits  Limits
	windows Windows
	addr    net.Addr
}

// Option configures New.
type Option func(*config) error

// WithServiceName registers the tunnel service under name instead of
// DefaultServiceName, so a deployment can keep a service name already on the
// wire. The client must be given the same name. The name must be a dotted
// sequence of identifiers such as pkg.v1.Service, the same rule the client's
// supertls.WithServiceName applies.
func WithServiceName(name string) Option {
	return func(c *config) error {
		if !servicename.Valid(name) {
			return fmt.Errorf("%w: service name %q is not a dotted identifier such as pkg.v1.Service", ErrInvalidOption, name)
		}
		c.name = name
		return nil
	}
}

// WithLogger sets the logger. The default is slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(c *config) error {
		if l == nil {
			return fmt.Errorf("%w: logger is nil", ErrInvalidOption)
		}
		c.log = l
		return nil
	}
}

// WithLimits replaces ALL the limits, so start from DefaultLimits.
func WithLimits(l Limits) Option {
	return func(c *config) error {
		if err := l.Validate(); err != nil {
			return err
		}
		c.limits = l
		return nil
	}
}

// WithWindows sets the server-side flow-control windows used by
// OuterServerOptions and InnerServerOptions. The zero value leaves gRPC's
// defaults.
func WithWindows(w Windows) Option {
	return func(c *config) error {
		if err := w.Validate(); err != nil {
			return err
		}
		c.windows = w
		return nil
	}
}

// WithListenerAddr sets the address the inner listener reports, which should be
// the address of the real listener the outer server serves. gRPC keys its
// connection map by it and the inner server's logs show it. When it is not set
// the listener reports a placeholder.
func WithListenerAddr(a net.Addr) Option {
	return func(c *config) error {
		c.addr = a
		return nil
	}
}

// KeepalivePolicy is the server's policy for client keepalive pings, as a gRPC
// option. Both servers need it, and OuterServerOptions and InnerServerOptions
// include it.
//
// Under gRPC's DEFAULT enforcement policy a client that pings an idle
// connection, which is exactly what PermitWithoutStream clients do between
// calls, scores a strike for every ping, and the third strike sends GOAWAY
// ENHANCE_YOUR_CALM and closes the connection. The strike counter clears
// whenever the server writes a frame, so a chatty client masks this; that is a
// property of the client's call rate, not a guarantee.
//
// The VALUE must sit below gRPC's own client-side ping floor of 10 seconds
// (internal.KeepaliveMinPingTime), not above it. A threshold above that floor is
// a trap: a client configured at the floor, which gRPC permits and silently
// clamps to, would be struck by a server that was supposedly tolerating it. Five
// seconds tolerates anything a gRPC client can emit while still rejecting a
// flood from a hand-rolled one.
//
// This is a pure relaxation of a policy, and a policy is not a SETTINGS frame,
// so it changes nothing on the wire for any existing client.
//
// It is a function rather than an inline literal so that a test can assert the
// production value keeps a silent, pinging connection alive. Asserting the
// constant proves nothing: the failure this guards against lives in gRPC's
// defaults, not in our arithmetic.
func KeepalivePolicy() grpc.ServerOption {
	return grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             KeepaliveMinTime,
		PermitWithoutStream: true,
	})
}

// OuterServerOptions returns the options for the OUTER gRPC server: the
// keepalive policy and, when set in WithWindows, its flow-control windows.
//
// They apply to every connection of that server, so they also apply to any
// direct-path client of it, not only to tunnelling ones. Append your own options
// after these, and pass your own credentials separately.
func (s *Service) OuterServerOptions() []grpc.ServerOption {
	opts := []grpc.ServerOption{KeepalivePolicy()}
	if w := s.cfg.windows.OuterStream; w != 0 {
		opts = append(opts, grpc.InitialWindowSize(w))
	}
	if w := s.cfg.windows.OuterConn; w != 0 {
		opts = append(opts, grpc.InitialConnWindowSize(w))
	}
	return opts
}

// InnerServerOptions returns the options for the INNER gRPC server: the
// keepalive policy, the handshake timeout, MaxConnectionIdle and, when set in
// WithWindows, its flow-control windows.
//
// Never give these to the outer server: MaxConnectionIdle would close direct
// clients that are legitimately idle between calls. Note that a
// grpc.KeepaliveParams option appended after these REPLACES the whole value,
// MaxConnectionIdle included, silently; set the idle bound through
// Limits.InnerMaxConnectionIdle instead, or repeat it.
func (s *Service) InnerServerOptions() []grpc.ServerOption {
	opts := []grpc.ServerOption{
		KeepalivePolicy(),
		// ConnectionTimeout bounds a peer that opens a tunnel and then never
		// speaks HTTP/2. It works only because the tunnel connection implements
		// SetDeadline.
		grpc.ConnectionTimeout(s.cfg.limits.InnerHandshakeTimeout),
		// The only thing that reclaims a tunnel held open by a peer that never
		// authenticates. See DefaultInnerMaxConnectionIdle.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: s.cfg.limits.InnerMaxConnectionIdle,
		}),
	}
	if w := s.cfg.windows.InnerStream; w != 0 {
		opts = append(opts, grpc.InitialWindowSize(w))
	}
	if w := s.cfg.windows.InnerConn; w != 0 {
		opts = append(opts, grpc.InitialConnWindowSize(w))
	}
	return opts
}
