package conn

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// DefaultAcceptTimeout bounds how long a tunnel handler waits to hand its
// connection to the inner server, when NewListener is given no timeout. A
// connection that cannot be handed over promptly is one whose peer is already
// waiting on a TLS handshake that has not started, so it is better rejected
// than queued.
const DefaultAcceptTimeout = 5 * time.Second

// ErrDeliverTimeout is returned by Deliver when the inner server did not accept
// within the listener's accept timeout.
var ErrDeliverTimeout = errors.New("supertls: inner server did not accept the tunnel in time")

// Listener is a net.Listener fed by tunnel handlers rather than by a socket.
//
// The channel is unbuffered on purpose. gRPC's Serve loop accepts and
// immediately spawns a goroutine per connection, so Accept is never the
// bottleneck in a healthy server; making it unbuffered means a genuinely wedged
// server rejects new tunnels instead of silently accumulating half-open ones.
type Listener struct {
	conns         chan net.Conn
	closed        chan struct{}
	once          sync.Once
	addr          net.Addr
	acceptTimeout time.Duration
}

// NewListener returns a Listener reporting addr. A nil addr is replaced by a
// placeholder address, so Addr never returns nil. An acceptTimeout of zero or
// less selects DefaultAcceptTimeout.
//
// addr should be the real TCP listener's address: gRPC uses it to key its
// connection map, and it is what makes the inner server's logs legible.
func NewListener(addr net.Addr, acceptTimeout time.Duration) *Listener {
	if addr == nil {
		addr = tunnelAddr("tunnel")
	}
	if acceptTimeout <= 0 {
		acceptTimeout = DefaultAcceptTimeout
	}
	return &Listener{
		conns:         make(chan net.Conn),
		closed:        make(chan struct{}),
		addr:          addr,
		acceptTimeout: acceptTimeout,
	}
}

// Accept implements net.Listener.
//
// It returns net.ErrClosed after Close, which gRPC's Serve treats as fatal
// rather than retryable (it retries only errors reporting Temporary), so
// closing the listener is what makes the inner server's Serve return.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener. Safe to call more than once.
func (l *Listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr implements net.Listener.
func (l *Listener) Addr() net.Addr { return l.addr }

// Deliver hands c to the inner server, blocking until it is accepted, the
// listener closes, ctx ends, or the accept timeout elapses.
func (l *Listener) Deliver(ctx context.Context, c net.Conn) error {
	timer := time.NewTimer(l.acceptTimeout)
	defer timer.Stop()
	select {
	case l.conns <- c:
		return nil
	case <-l.closed:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrDeliverTimeout
	}
}

var _ net.Listener = (*Listener)(nil)
