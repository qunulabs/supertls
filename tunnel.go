package supertls

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/qunulabs/supertls/conn"
	"github.com/qunulabs/supertls/tunnelpb"
)

// dialTunnel establishes a tunnelled connection to host and returns it once
// the INNER connection is ready.
//
// The structure is what makes this cheap. The tunnel is opened inside the inner
// connection's DIALLER, so gRPC's own reconnect machinery re-establishes it: a
// tunnel killed by a proxy's idle timeout simply causes the dialler to run
// again, a fresh stream to open, and the inner session to re-handshake.
// Nothing above this function has to know. To the caller it looks like one
// transient Unavailable.
//
// inner is the caller's one and only transport credential source for the inner
// connection. It is the LAST WithTransportCredentials in the list, after extra,
// so nothing the caller passes can silently replace it; likewise the tunnel
// dialler comes after extra, so a stray WithContextDialer cannot route the inner
// connection around the tunnel.
func (d *Dialer) dialTunnel(ctx context.Context, host string, inner credentials.TransportCredentials, extra []grpc.DialOption) (*Conn, error) {
	outer, err := d.newOuterConn(host)
	if err != nil {
		return nil, fmt.Errorf("supertls: outer connection to %s: %w", host, err)
	}

	// One recorder per dial, never shared: a concurrent dial to another host
	// must not be able to explain this one's failure.
	rec := &recorder{}
	w := d.cfg.windows
	serviceName := d.cfg.serviceName

	opts := []grpc.DialOption{
		grpc.WithIdleTimeout(0),
		grpc.WithInitialWindowSize(w.InnerStream),
		grpc.WithInitialConnWindowSize(w.InnerConn),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: d.cfg.innerBackoff,
			// Must exceed opening the outer stream plus a nested TLS 1.3 hybrid
			// handshake, or a merely slow setup is scored as a failure.
			MinConnectTimeout: d.cfg.tunnelBudget,
		}),
	}
	opts = append(opts, extra...)
	opts = append(opts,
		// THE CALLER'S OWN CONFIGURATION, VERBATIM AND UNCHANGED. This is the
		// whole security argument: the inner session is the same credentials,
		// the same roots and the same identity that run on the direct path.
		grpc.WithTransportCredentials(recording(inner, rec)),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			// The stream must OUTLIVE gRPC's dial context, which is bounded by
			// MinConnectTimeout. The connection owns the cancel and fires it on
			// Close.
			streamCtx, cancel := context.WithCancel(context.Background())
			stream, err := openStream(streamCtx, outer, serviceName)
			if err != nil {
				cancel()
				rec.note(err)
				return nil, err
			}
			return conn.NewConn(stream, conn.Options{Teardown: cancel}), nil
		}),
	)
	// passthrough:/// keeps host as the authority, which is what the inner
	// session derives its ServerName from. A resolver here would be pointless:
	// the dialler ignores the address and opens a stream on the outer
	// connection.
	innerCC, err := grpc.NewClient("passthrough:///"+host, opts...)
	if err != nil {
		outer.Close()
		return nil, fmt.Errorf("supertls: inner connection to %s: %w", host, err)
	}

	// Waiting on the INNER connection: the outer reaching READY only means the
	// proxy answered, which says nothing about whether the session inside it
	// came up.
	if err := waitForReady(ctx, host, innerCC, d.cfg.tunnelBudget, rec); err != nil {
		innerCC.Close()
		outer.Close()
		return nil, err
	}
	return &Conn{cc: innerCC, outer: outer, mode: ModeTunnel}, nil
}

// newOuterConn builds (without dialling) the outer connection of a tunnel to
// host. Its credentials are permissive by design (see permissiveCreds). The
// caller's outer options come last and so take precedence; the caller's direct
// options and inner credentials never reach it.
func (d *Dialer) newOuterConn(host string) (*grpc.ClientConn, error) {
	w := d.cfg.windows
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(permissiveCreds{}),
		// gRPC's default idle timeout would tear the outer connection down
		// between calls on a long interval.
		grpc.WithIdleTimeout(0),
		grpc.WithInitialWindowSize(w.OuterStream),
		grpc.WithInitialConnWindowSize(w.OuterConn),
		grpc.WithWriteBufferSize(w.Buffer),
		grpc.WithReadBufferSize(w.Buffer),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           DefaultOuterBackoff,
			MinConnectTimeout: DefaultOuterMinConnectTimeout,
		}),
		grpc.WithKeepaliveParams(DefaultOuterKeepalive),
	}
	return grpc.NewClient(host, append(opts, d.cfg.outerOpts...)...)
}

// openStream opens the tunnel stream on cc under the full service name
// serviceName. There is one code path for every service name: the generated
// client hard-codes the default name, so it is not used.
func openStream(ctx context.Context, cc grpc.ClientConnInterface, serviceName string) (grpc.BidiStreamingClient[tunnelpb.Frame, tunnelpb.Frame], error) {
	s, err := cc.NewStream(ctx, &tunnelpb.TunnelService_ServiceDesc.Streams[0], "/"+serviceName+"/Open", grpc.StaticMethod())
	if err != nil {
		return nil, err
	}
	return &grpc.GenericClientStream[tunnelpb.Frame, tunnelpb.Frame]{ClientStream: s}, nil
}
