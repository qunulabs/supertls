package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qunulabs/supertls/tunnelpb"
)

// noPeerStream is a tunnel stream whose context carries no gRPC peer. The
// embedded nil ServerStream is never touched: the handler rejects the stream
// before it reads or writes anything.
type noPeerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *noPeerStream) Context() context.Context       { return s.ctx }
func (s *noPeerStream) Send(*tunnelpb.Frame) error     { return nil }
func (s *noPeerStream) Recv() (*tunnelpb.Frame, error) { return nil, io.EOF }

func TestOpenRejectsStreamWithoutPeer(t *testing.T) {
	t.Parallel()

	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A stream whose context carries no peer cannot happen in gRPC, but a nil
	// address would reach the caller's own peer handling and gRPC's error
	// formatting, so the handler refuses rather than improvises.
	err = s.Open(&noPeerStream{ctx: context.Background()})
	if status.Code(err) != codes.Internal {
		t.Fatalf("got %v, want Internal", err)
	}
	if n := s.OpenTunnels(); n != 0 {
		t.Fatalf("%d tunnels open after a refused stream, want 0", n)
	}
}

func TestRegisterUsesServiceName(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		t.Parallel()
		s, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		g := grpc.NewServer()
		s.Register(g)
		info, ok := g.GetServiceInfo()[DefaultServiceName]
		if !ok {
			t.Fatalf("service %s is not registered: %v", DefaultServiceName, g.GetServiceInfo())
		}
		if len(info.Methods) != 1 || info.Methods[0].Name != "Open" {
			t.Fatalf("methods = %+v, want exactly Open", info.Methods)
		}
	})

	t.Run("custom", func(t *testing.T) {
		t.Parallel()
		const name = "sentinel.tunnel.v1.TunnelService"
		s, err := New(WithServiceName(name))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		g := grpc.NewServer()
		s.Register(g)
		infos := g.GetServiceInfo()
		info, ok := infos[name]
		if !ok {
			t.Fatalf("service %s is not registered: %v", name, infos)
		}
		if len(info.Methods) != 1 || info.Methods[0].Name != "Open" {
			t.Fatalf("methods = %+v, want exactly Open", info.Methods)
		}
		if _, ok := infos[DefaultServiceName]; ok {
			t.Fatalf("the default name %s is registered beside the custom one", DefaultServiceName)
		}
	})
}

// Registering under a custom name must not rename the generated descriptor the
// rest of the process, and every other Service, shares.
func TestRegisterDoesNotMutateGeneratedDescriptor(t *testing.T) {
	t.Parallel()

	s, err := New(WithServiceName("custom.v1.Tunnel"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Register(grpc.NewServer())
	if got := tunnelpb.TunnelService_ServiceDesc.ServiceName; got != DefaultServiceName {
		t.Fatalf("generated descriptor renamed to %q", got)
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	badLimits := DefaultLimits()
	badLimits.MaxConcurrent = 0
	cases := []struct {
		name string
		opt  Option
		want error
	}{
		{"empty service name", WithServiceName(""), ErrInvalidOption},
		{"slashed service name", WithServiceName("a/b"), ErrInvalidOption},
		{"nil logger", WithLogger(nil), ErrInvalidOption},
		{"invalid limits", WithLimits(badLimits), ErrInvalidOption},
		{"window below floor", WithWindows(Windows{OuterConn: 1}), ErrInvalidOption},
		{"window invariant", WithWindows(Windows{OuterStream: 128 << 10, InnerConn: 256 << 10}), ErrWindowInvariant},
		{"nil option", nil, ErrInvalidOption},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := New(tc.opt)
			if !errors.Is(err, tc.want) {
				t.Fatalf("New() = (%v, %v), want %v", s, err, tc.want)
			}
			if s != nil {
				t.Fatal("New returned a Service beside an error")
			}
		})
	}
}

func TestNewAcceptsValidOptions(t *testing.T) {
	t.Parallel()

	s, err := New(
		WithServiceName("x.v1.T"),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithLimits(DefaultLimits()),
		WithWindows(Windows{OuterStream: 1 << 20, OuterConn: 2 << 20, InnerStream: 512 << 10, InnerConn: 1 << 20}),
		WithListenerAddr(nil),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.Listener().Addr() == nil {
		t.Fatal("Listener().Addr() is nil")
	}
}

func TestServerOptionsCarryWindowsOnlyWhenSet(t *testing.T) {
	t.Parallel()

	plain, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// keepalive policy only on the outer side; plus handshake timeout and idle
	// bound on the inner side.
	if n := len(plain.OuterServerOptions()); n != 1 {
		t.Fatalf("outer options without windows: %d, want 1", n)
	}
	if n := len(plain.InnerServerOptions()); n != 3 {
		t.Fatalf("inner options without windows: %d, want 3", n)
	}

	sized, err := New(WithWindows(Windows{
		OuterStream: 1 << 20, OuterConn: 2 << 20, InnerStream: 512 << 10, InnerConn: 1 << 20,
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if n := len(sized.OuterServerOptions()); n != 3 {
		t.Fatalf("outer options with windows: %d, want 3", n)
	}
	if n := len(sized.InnerServerOptions()); n != 5 {
		t.Fatalf("inner options with windows: %d, want 5", n)
	}
	// The options must be accepted by a real server.
	grpc.NewServer(sized.OuterServerOptions()...).Stop()
	grpc.NewServer(sized.InnerServerOptions()...).Stop()
}
