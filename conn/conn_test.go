package conn

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qunulabs/supertls/internal/testpki"
	"github.com/qunulabs/supertls/tunnelpb"
)

// memStream is one end of an in-memory stand-in for a gRPC bidirectional
// stream. It exists so the adapter can be tested with no gRPC and no network in
// the picture, which is the only way to tell an adapter bug apart from a
// transport bug.
//
// Send copies its payload because that is what gRPC does: it serialises the
// message before returning, so the caller is free to reuse the buffer. Without
// the copy this fake would silently tolerate an aliasing bug that production
// would not.
type memStream struct {
	in      <-chan []byte
	out     chan<- []byte
	closed  chan struct{}
	closeFn func()
}

func (m *memStream) Send(f *tunnelpb.Frame) error {
	cp := bytes.Clone(f.GetData())
	select {
	case m.out <- cp:
		return nil
	case <-m.closed:
		return io.ErrClosedPipe
	}
}

func (m *memStream) Recv() (*tunnelpb.Frame, error) {
	select {
	case b, ok := <-m.in:
		if !ok {
			return nil, io.EOF
		}
		return &tunnelpb.Frame{Data: b}, nil
	case <-m.closed:
		return nil, io.EOF
	}
}

// close tears the shared stream down. Both ends may call it concurrently, so
// the sync.Once behind closeFn is shared between them rather than per-end.
func (m *memStream) close() { m.closeFn() }

// streamPair returns two streams wired back to back.
//
// Both ends share one teardown channel, because a gRPC stream is a single
// object: cancelling it at the client ends the server's Recv too. A fake with
// independent per-end closes would let a test hang where production would
// return, which is the opposite of what a fake is for.
func streamPair() (*memStream, *memStream) {
	ab := make(chan []byte)
	ba := make(chan []byte)
	dead := make(chan struct{})
	var once sync.Once
	closeFn := func() { once.Do(func() { close(dead) }) }
	a := &memStream{in: ba, out: ab, closed: dead, closeFn: closeFn}
	b := &memStream{in: ab, out: ba, closed: dead, closeFn: closeFn}
	return a, b
}

// connPair returns two Conns wired back to back, each tearing its stream down
// on Close so a blocked peer does not hang the test.
func connPair(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	sa, sb := streamPair()
	ca := NewConn(sa, Options{Teardown: sa.close})
	cb := NewConn(sb, Options{Teardown: sb.close})
	t.Cleanup(func() { ca.Close(); cb.Close() })
	return ca, cb
}

// writeAsync writes in the background and reports the outcome on a buffered
// channel. Calling t.Errorf from a goroutine that may outlive the test panics
// the whole run, so results come back to the test body instead.
func writeAsync(c *Conn, b []byte) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := c.Write(b)
		ch <- err
	}()
	return ch
}

func mustWrite(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write did not complete")
	}
}

func TestConnRoundTrip(t *testing.T) {
	a, b := connPair(t)

	want := []byte("the inner session is the same one that runs in production")
	wc := writeAsync(a, want)

	got := make([]byte, len(want))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	mustWrite(t, wc)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A short Read must keep the rest of the frame rather than drop it. This is the
// bug that would make a tunnel appear to work and then corrupt a TLS record
// under load, so it is tested directly rather than only through TLS.
func TestConnShortReadKeepsRemainder(t *testing.T) {
	a, b := connPair(t)

	wc := writeAsync(a, []byte("abcdefghij"))

	first := make([]byte, 4)
	n, err := b.Read(first)
	if err != nil || n != 4 {
		t.Fatalf("first read: n=%d err=%v", n, err)
	}
	if string(first) != "abcd" {
		t.Fatalf("first read got %q", first)
	}

	rest := make([]byte, 6)
	if _, err := io.ReadFull(b, rest); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(rest) != "efghij" {
		t.Fatalf("second read got %q", rest)
	}
	mustWrite(t, wc)
}

// Frame boundaries must carry no meaning: a reader reassembles across them the
// way it would across TCP segments.
func TestConnReassemblesAcrossFrames(t *testing.T) {
	a, b := connPair(t)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 40*1024) // 640 KiB, > MaxFrameBytes
	wc := writeAsync(a, payload)

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted across frame boundaries")
	}
	mustWrite(t, wc)
}

func TestConnZeroLengthReadDoesNotConsume(t *testing.T) {
	a, b := connPair(t)

	wc := writeAsync(a, []byte("xy"))

	if n, err := b.Read(nil); n != 0 || err != nil {
		t.Fatalf("zero-length read: n=%d err=%v", n, err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read after zero-length read: %v", err)
	}
	if string(got) != "xy" {
		t.Fatalf("got %q, want %q", got, "xy")
	}
	mustWrite(t, wc)
}

func TestConnReadDeadline(t *testing.T) {
	_, b := connPair(t)

	if err := b.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, err := b.Read(make([]byte, 8))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v, want os.ErrDeadlineExceeded", err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("deadline error must report Timeout() true, got %v", err)
	}
}

// gRPC's server handshake arms a deadline for the connection timeout and then
// clears it with the zero time, so a fired deadline has to be revivable.
func TestConnDeadlineIsRevivable(t *testing.T) {
	a, b := connPair(t)

	if err := b.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("set past deadline: %v", err)
	}
	if _, err := b.Read(make([]byte, 4)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected the past deadline to fire, got %v", err)
	}

	if err := b.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	wc := writeAsync(a, []byte("live"))
	got := make([]byte, 4)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read after clearing the deadline: %v", err)
	}
	if string(got) != "live" {
		t.Fatalf("got %q", got)
	}
	mustWrite(t, wc)
}

// A deadline armed while a Read is already blocked must interrupt it. This is
// how crypto/tls cancels a handshake.
func TestConnDeadlineInterruptsBlockedRead(t *testing.T) {
	_, b := connPair(t)

	errCh := make(chan error, 1)
	go func() {
		_, err := b.Read(make([]byte, 8))
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond) // let the Read block
	if err := b.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a deadline armed during a blocked Read did not interrupt it")
	}
}

func TestConnCloseUnblocksRead(t *testing.T) {
	_, b := connPair(t)

	errCh := make(chan error, 1)
	go func() {
		_, err := b.Read(make([]byte, 8))
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("got %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock a pending Read")
	}
}

func TestConnCloseIsIdempotentAndTearsDownOnce(t *testing.T) {
	sa, _ := streamPair()
	var teardowns int
	var mu sync.Mutex
	c := NewConn(sa, Options{Teardown: func() { mu.Lock(); teardowns++; mu.Unlock() }})

	for range 3 {
		if err := c.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if teardowns != 1 {
		t.Fatalf("teardown ran %d times, want 1", teardowns)
	}
}

// A stream that ends cleanly must surface as io.EOF, because that is how
// crypto/tls and gRPC tell an orderly shutdown from a fault.
func TestConnEndOfStreamIsEOF(t *testing.T) {
	sa, sb := streamPair()
	a := NewConn(sa, Options{Teardown: sa.close})
	b := NewConn(sb, Options{Teardown: sb.close})
	defer b.Close()

	a.Close() // tears the stream down under b

	if _, err := b.Read(make([]byte, 4)); !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want io.EOF", err)
	}
}

func TestConnAddrsAreNeverNil(t *testing.T) {
	sa, _ := streamPair()
	c := NewConn(sa, Options{})
	defer c.Close()

	if c.LocalAddr() == nil || c.RemoteAddr() == nil {
		t.Fatal("a nil Addr panics inside gRPC's own error formatting")
	}
	if c.RemoteAddr().Network() == "" || c.RemoteAddr().String() == "" {
		t.Fatal("Addr must render")
	}
	for _, a := range []net.Addr{c.LocalAddr(), c.RemoteAddr()} {
		if a.Network() != "supertls" || a.String() != "tunnel" {
			t.Fatalf("placeholder address is %s/%s, want supertls/tunnel", a.Network(), a.String())
		}
	}
}

func TestConnReportsSuppliedRemoteAddr(t *testing.T) {
	sa, _ := streamPair()
	want := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44321}
	c := NewConn(sa, Options{Remote: want})
	defer c.Close()

	if got := c.RemoteAddr().String(); got != want.String() {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// The test the whole design rests on: a real, strict, mutually-authenticated
// TLS 1.3 session over a pair of adapters, with no gRPC and no network. If this
// passes, the inner session a caller runs is genuinely unchanged by being
// tunnelled.
func TestRealMutualTLSHandshakeOverTunnel(t *testing.T) {
	p := testpki.Standard(t)

	clientCfg := testpki.StrictClientTLS(p)
	clientCfg.ServerName = "localhost"
	serverCfg := testpki.StrictServerTLS(p)

	rawClient, rawServer := connPair(t)
	tlsClient := tls.Client(rawClient, clientCfg)
	tlsServer := tls.Server(rawServer, serverCfg)

	serverDone := make(chan error, 1)
	go func() { serverDone <- tlsServer.Handshake() }()

	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake over the tunnel: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server handshake over the tunnel: %v", err)
	}

	for name, state := range map[string]tls.ConnectionState{
		"client": tlsClient.ConnectionState(),
		"server": tlsServer.ConnectionState(),
	} {
		if state.Version != tls.VersionTLS13 {
			t.Fatalf("%s: negotiated TLS version %x, want 1.3", name, state.Version)
		}
		if state.CurveID != tls.X25519MLKEM768 {
			t.Fatalf("%s: negotiated group %v, want X25519MLKEM768", name, state.CurveID)
		}
	}

	peers := tlsServer.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		t.Fatal("server saw no client certificate: the tunnel lost the mTLS identity")
	}
	// The identity a server authenticates on must survive the tunnel intact.
	if len(peers[0].URIs) != 1 || peers[0].URIs[0].String() != p.ClientURI.String() {
		t.Fatalf("client identity did not survive the tunnel: %v", peers[0].URIs)
	}
	if peers[0].Subject.CommonName != "client-1" {
		t.Fatalf("client common name %q, want client-1", peers[0].Subject.CommonName)
	}

	// And it carries application data both ways: a 100 KiB echo.
	payload := bytes.Repeat([]byte("supertls echo 0123456789"), 100*1024/24+1)[:100*1024]
	echoErr := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(tlsServer, buf); err != nil {
			echoErr <- err
			return
		}
		_, err := tlsServer.Write(buf)
		echoErr <- err
	}()
	writeErr := make(chan error, 1)
	go func() {
		_, err := tlsClient.Write(payload)
		writeErr <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(tlsClient, got); err != nil {
		t.Fatalf("client read of the echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := <-echoErr; err != nil {
		t.Fatalf("server echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echoed payload differs from what was sent")
	}
}

// A peer that ignores MaxFrameBytes must be refused, not accommodated.
//
// A server sizes its tunnel concurrency cap from a MEASUREMENT of how much
// memory a well-behaved tunnel costs. gRPC's default receive limit is 4 MiB,
// sixty-four times the cap this side writes to, so without this check a hostile
// peer would choose that figure itself and the cap would bound nothing.
func TestReadRejectsAnOversizedFrame(t *testing.T) {
	sa, sb := streamPair()
	c := NewConn(sa, Options{})
	defer c.Close()

	// Bypass the Conn on the far side: only a peer that is not this code can
	// produce a frame this large, which is exactly the case under test.
	go func() { _ = sb.Send(&tunnelpb.Frame{Data: make([]byte, MaxFrameBytes+1)}) }()

	_, err := c.Read(make([]byte, 1024))
	if err == nil {
		t.Fatal("an oversized frame was accepted; a peer can choose how much memory a tunnel costs")
	}
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("failed, but not for the size: %v", err)
	}
	if !strings.Contains(err.Error(), "65537") || !strings.Contains(err.Error(), "65536") {
		t.Fatalf("the error must name the frame size and the limit: %v", err)
	}
}

// The cap must not reject a frame AT the limit, or a full-sized write from the
// other end of a legitimate tunnel would tear the connection down.
func TestReadAcceptsAFrameAtTheLimit(t *testing.T) {
	a, b := connPair(t)
	defer a.Close()
	defer b.Close()

	payload := bytes.Repeat([]byte{0xA5}, MaxFrameBytes)
	go func() { _, _ = a.Write(payload) }()

	got := make([]byte, 0, MaxFrameBytes)
	buf := make([]byte, 32*1024)
	for len(got) < MaxFrameBytes {
		n, err := b.Read(buf)
		if err != nil {
			t.Errorf("read at the limit failed after %d bytes: %v", len(got), err)
			return
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("a frame at exactly MaxFrameBytes did not survive the round trip")
	}
}

// Write splits at the frame cap, so a peer never sees a frame larger than the
// limit it would itself enforce on receive.
func TestConnWriteSplitsAtFrameCap(t *testing.T) {
	sa, sb := streamPair()
	c := NewConn(sa, Options{Teardown: sa.close})
	defer c.Close()

	payload := make([]byte, 200*1024)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	wc := writeAsync(c, payload)

	var got []byte
	for len(got) < len(payload) {
		f, err := sb.Recv()
		if err != nil {
			t.Fatalf("recv after %d bytes: %v", len(got), err)
		}
		if n := len(f.GetData()); n > MaxFrameBytes || n == 0 {
			t.Fatalf("received a frame of %d bytes, want 1..%d", n, MaxFrameBytes)
		}
		got = append(got, f.GetData()...)
	}
	mustWrite(t, wc)
	if !bytes.Equal(got, payload) {
		t.Fatal("the frames do not concatenate to the input")
	}
}

// An empty frame carries no bytes. Read must skip it: returning 0, nil would
// spin a caller, and returning EOF would end a live stream.
func TestConnSkipsEmptyFrames(t *testing.T) {
	sa, sb := streamPair()
	c := NewConn(sa, Options{Teardown: sa.close})
	defer c.Close()

	go func() {
		_ = sb.Send(&tunnelpb.Frame{})
		_ = sb.Send(&tunnelpb.Frame{Data: []byte("x")})
	}()

	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("read: n=%d err=%v data=%q, want one byte x", n, err, buf[:n])
	}
}

// A write deadline must interrupt a Write blocked on a peer that never reads.
func TestConnWriteDeadlineInterruptsBlockedWrite(t *testing.T) {
	sa, _ := streamPair() // nobody reads the far end
	c := NewConn(sa, Options{Teardown: sa.close})
	defer c.Close()

	if err := c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("x"))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a write deadline did not interrupt a blocked Write")
	}
}

func TestConnWriteAfterCloseIsErrClosed(t *testing.T) {
	a, _ := connPair(t)
	a.Close()
	if _, err := a.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("got %v, want net.ErrClosed", err)
	}
}

func TestConnSetDeadlineAfterCloseIsErrClosed(t *testing.T) {
	a, _ := connPair(t)
	a.Close()
	for name, set := range map[string]func(time.Time) error{
		"SetDeadline":      a.SetDeadline,
		"SetReadDeadline":  a.SetReadDeadline,
		"SetWriteDeadline": a.SetWriteDeadline,
	} {
		if err := set(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s: got %v, want net.ErrClosed", name, err)
		}
	}
}

// endedStream is a stream gRPC has already ended: Send reports the bare io.EOF
// it uses for that, and the real status is available only from Recv. Recv
// returns frames first, then blocks until release is closed, then recvErr.
type endedStream struct {
	frames  [][]byte
	recvErr error
	release chan struct{}
	sent    chan struct{} // closed on the first Send
	once    sync.Once
}

func newEndedStream(recvErr error, frames ...[]byte) *endedStream {
	return &endedStream{frames: frames, recvErr: recvErr, release: make(chan struct{}), sent: make(chan struct{})}
}

func (s *endedStream) Send(*tunnelpb.Frame) error {
	s.once.Do(func() { close(s.sent) })
	return io.EOF
}

func (s *endedStream) Recv() (*tunnelpb.Frame, error) {
	if len(s.frames) > 0 {
		f := s.frames[0]
		s.frames = s.frames[1:]
		return &tunnelpb.Frame{Data: f}, nil
	}
	<-s.release
	return nil, s.recvErr
}

func TestConnWriteReportsTheStreamStatusNotBareEOF(t *testing.T) {
	want := status.Error(codes.Unimplemented, "unknown service")
	s := newEndedStream(want)
	close(s.release)
	c := NewConn(s, Options{})
	defer c.Close()

	_, err := c.Write([]byte("hello"))
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Write = %v, want the Unimplemented status Read reports", err)
	}
	if _, rerr := c.Read(make([]byte, 1)); status.Code(rerr) != codes.Unimplemented {
		t.Fatalf("Read = %v, want the same status", rerr)
	}
}

func TestConnWriteAfterCleanEndIsEOF(t *testing.T) {
	s := newEndedStream(io.EOF)
	close(s.release)
	c := NewConn(s, Options{})
	defer c.Close()

	if _, err := c.Write([]byte("hello")); !errors.Is(err, io.EOF) {
		t.Fatalf("Write = %v, want io.EOF", err)
	}
}

// The peer sent data the caller has not read, then ended the stream. The reader
// goroutine is parked on the unread frame and cannot see the status, so Write,
// with no deadline and no concurrent Read, must still return promptly.
func TestConnWriteWithUnreadFrameThenStatusDoesNotBlock(t *testing.T) {
	s := newEndedStream(status.Error(codes.Unavailable, "gone"), []byte("unread"))
	close(s.release)
	c := NewConn(s, Options{})
	defer c.Close()

	errCh := make(chan error, 1)
	go func() { _, err := c.Write([]byte("x")); errCh <- err }()
	select {
	case err := <-errCh:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Write = %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked behind an unread frame")
	}

	// The data and then the status are still delivered to Read, in order.
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "unread" {
		t.Fatalf("Read = %q, %v, want the unread frame", buf[:n], err)
	}
	if _, err := c.Read(buf); status.Code(err) != codes.Unavailable {
		t.Fatalf("Read = %v, want the Unavailable status", err)
	}
}

func TestConnWriteWaitingForStatusHonoursDeadlineAndClose(t *testing.T) {
	// Recv never returns, so the status never arrives.
	s := newEndedStream(io.EOF)
	defer close(s.release)
	c := NewConn(s, Options{})
	defer c.Close()

	if err := c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { _, err := c.Write([]byte("x")); errCh <- err }()
	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked past its deadline waiting for the stream status")
	}

	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	// The first Send already happened; wait for the second, which the next
	// Write makes, so Close lands while Write waits for the status.
	s2 := newEndedStream(io.EOF)
	defer close(s2.release)
	c2 := NewConn(s2, Options{})
	go func() { _, err := c2.Write([]byte("x")); errCh <- err }()
	<-s2.sent
	c2.Close()
	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not release a Write waiting for the stream status")
	}
}
