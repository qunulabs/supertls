package conn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestListenerDeliversToAccept(t *testing.T) {
	t.Parallel()
	l := NewListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50051}, 0)
	defer l.Close()

	sa, _ := streamPair()
	want := NewConn(sa, Options{})
	defer want.Close()

	go func() { _ = l.Deliver(context.Background(), want) }()

	got, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got != net.Conn(want) {
		t.Fatal("Accept returned a different connection than Deliver handed over")
	}
}

// gRPC's Serve retries only errors that report Temporary. net.ErrClosed does
// not, which is precisely what makes closing the listener the way to stop the
// inner server. A Temporary error here would spin Serve forever.
func TestListenerAcceptAfterCloseIsNotTemporary(t *testing.T) {
	t.Parallel()
	l := NewListener(nil, 0)
	l.Close()

	_, err := l.Accept()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("got %v, want net.ErrClosed", err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("Accept must not report a timeout after Close, or Serve will retry forever")
	}
	var tmp interface{ Temporary() bool }
	if errors.As(err, &tmp) && tmp.Temporary() {
		t.Fatal("Accept must not report a temporary error after Close, or Serve will retry forever")
	}
}

func TestListenerCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	l := NewListener(nil, 0)
	for range 3 {
		if err := l.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
}

func TestListenerDeliverFailsAfterClose(t *testing.T) {
	t.Parallel()
	l := NewListener(nil, 0)
	l.Close()

	sa, _ := streamPair()
	c := NewConn(sa, Options{})
	defer c.Close()

	if err := l.Deliver(context.Background(), c); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("got %v, want net.ErrClosed", err)
	}
}

func TestListenerDeliverHonoursContext(t *testing.T) {
	t.Parallel()
	l := NewListener(nil, 0) // nothing ever calls Accept
	defer l.Close()

	sa, _ := streamPair()
	c := NewConn(sa, Options{})
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := l.Deliver(ctx, c)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
}

// Addr must be the real TCP address, because gRPC keys its connection map on it
// and it is what makes the inner server's logs point at something real.
func TestListenerReportsSuppliedAddr(t *testing.T) {
	t.Parallel()
	want := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 50051}
	l := NewListener(want, 0)
	defer l.Close()

	if got := l.Addr().String(); got != want.String() {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestListenerDeliverTimesOut(t *testing.T) {
	t.Parallel()
	l := NewListener(nil, 50*time.Millisecond) // nobody accepts
	defer l.Close()

	sa, _ := streamPair()
	c := NewConn(sa, Options{})
	defer c.Close()

	done := make(chan error, 1)
	go func() { done <- l.Deliver(context.Background(), c) }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrDeliverTimeout) {
			t.Fatalf("got %v, want ErrDeliverTimeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Deliver did not time out within 1s")
	}
}

func TestListenerDefaultAcceptTimeout(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{0, -time.Second} {
		l := NewListener(nil, d)
		if l.acceptTimeout != DefaultAcceptTimeout {
			t.Fatalf("timeout %v stored as %v, want DefaultAcceptTimeout", d, l.acceptTimeout)
		}
		l.Close()
	}
	l := NewListener(nil, 7*time.Millisecond)
	defer l.Close()
	if l.acceptTimeout != 7*time.Millisecond {
		t.Fatalf("supplied timeout not kept: %v", l.acceptTimeout)
	}
}

func TestListenerAddrNeverNil(t *testing.T) {
	t.Parallel()
	l := NewListener(nil, 0)
	defer l.Close()
	if l.Addr() == nil {
		t.Fatal("Addr returned nil for a nil supplied address")
	}
	if l.Addr().Network() == "" || l.Addr().String() == "" {
		t.Fatalf("placeholder address is empty: %q %q", l.Addr().Network(), l.Addr().String())
	}
}
