package conn

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/qunulabs/supertls/tunnelpb"
)

// MaxFrameBytes caps one frame's payload, in both directions: Write never sends
// a larger frame and Read refuses to accept one.
//
// It is above the 16 KiB maximum TLS record so the common case is one record
// per frame with no splitting, and it is a cap rather than a target because the
// overhead that matters here is per-frame: a frame for every small write is
// what turns a fraction of a percent of framing overhead into a large one. The
// inner TLS layer already batches for us, since crypto/tls issues one Write per
// record, so this bound is insurance rather than the mechanism.
const MaxFrameBytes = 64 * 1024

// ErrFrameTooLarge is the error Read returns when the peer sends a frame larger
// than MaxFrameBytes. It is wrapped with the offending size and the limit, so
// match it with errors.Is.
var ErrFrameTooLarge = errors.New("supertls: peer sent a frame larger than MaxFrameBytes")

// Stream is the part of a gRPC bidirectional stream this package needs. The
// generated client and server stream types for TunnelService.Open both satisfy
// it.
//
// gRPC permits one goroutine sending and one receiving concurrently, but not
// two of either. Conn honours that: a single reader goroutine owns Recv for the
// connection's lifetime, and writeMu serialises Send.
type Stream interface {
	Send(*tunnelpb.Frame) error
	Recv() (*tunnelpb.Frame, error)
}

// Conn is a net.Conn carried by a gRPC bidirectional stream.
//
// Frame boundaries carry no meaning. Read reassembles across them exactly as it
// would across TCP segments, which is what lets crypto/tls sit on top
// unmodified.
type Conn struct {
	stream   Stream
	local    net.Addr
	remote   net.Addr
	teardown func()

	// frames carries payloads from the reader goroutine to Read. It is
	// deliberately shallow: a blocked send here stops the goroutine calling
	// Recv, which is what lets gRPC's flow control back-pressure the peer
	// instead of this process buffering an unbounded amount of it.
	frames chan []byte
	// leftover is the tail of a frame a short Read could not take. Guarded by
	// readMu, like all read state.
	leftover []byte

	// recvErr is why the reader goroutine stopped. Written once before frames
	// is closed, so a receive on the closed channel happens-after the write.
	recvErr error
	// recvEnded is closed by the reader goroutine right after it records
	// recvErr, so a writer can wait for the stream's terminal status.
	recvEnded chan struct{}

	// parkMu guards parked and parkWait. parked is true while the reader
	// goroutine holds a received frame that Read has not yet taken, which means
	// it is not inside Recv and cannot observe the stream's terminal status.
	// parkWait, when non-nil, is closed on the next transition to parked, so a
	// writer waiting for the status learns it will not come without a Read.
	parkMu   sync.Mutex
	parked   bool
	parkWait chan struct{}

	// sends carries frames from Write to the writer goroutine that owns Send.
	// Unbuffered, so a caller that abandons a frame on a deadline cannot queue
	// another one behind it until the first has actually gone out.
	sends chan sendReq

	readMu  sync.Mutex
	writeMu sync.Mutex

	rd deadline
	wd deadline

	closeOnce sync.Once
	done      chan struct{}
}

// sendReq is one frame handed to the writer goroutine.
//
// data is a copy rather than a slice of the caller's buffer. That is what makes
// abandoning a frame on a deadline safe: the writer goroutine may still be
// inside Send when Write has already returned, and the caller is entitled to
// reuse its buffer the moment it does.
type sendReq struct {
	data   []byte
	result chan error // buffered, so an abandoned send never blocks the writer
}

// Options configures a Conn.
type Options struct {
	// Local and Remote are reported by LocalAddr and RemoteAddr. Remote should
	// be the real peer address of the OUTER connection, which a server reads
	// from peer.FromContext in the tunnel handler, so that peer authentication
	// and address logging keep seeing the true client rather than a synthetic
	// placeholder.
	Local  net.Addr
	Remote net.Addr

	// Teardown ends the underlying stream. On the client that cancels the
	// stream's context; on the server it releases the handler so it can return.
	// Called at most once, from Close.
	Teardown func()
}

// NewConn wraps s. It starts a goroutine that owns Recv until the stream ends
// or Close is called, so every Conn must be closed.
func NewConn(s Stream, opts Options) *Conn {
	c := &Conn{
		stream:    s,
		local:     opts.Local,
		remote:    opts.Remote,
		teardown:  opts.Teardown,
		frames:    make(chan []byte),
		recvEnded: make(chan struct{}),
		sends:     make(chan sendReq),
		done:      make(chan struct{}),
		rd:        newDeadline(),
		wd:        newDeadline(),
	}
	if c.local == nil {
		c.local = tunnelAddr("tunnel")
	}
	if c.remote == nil {
		c.remote = tunnelAddr("tunnel")
	}
	go c.readLoop()
	go c.writeLoop()
	return c
}

// readLoop is the sole caller of Recv for this connection's lifetime.
func (c *Conn) readLoop() {
	defer close(c.frames)
	// Runs before the close above, and after recvErr is set on every path.
	defer close(c.recvEnded)
	for {
		f, err := c.stream.Recv()
		if err != nil {
			c.recvErr = err
			return
		}
		data := f.GetData()
		if len(data) > MaxFrameBytes {
			// A peer never needs to exceed the cap this side writes to, and
			// letting it would hand the peer the choice of how much memory a
			// tunnel costs: gRPC's own default receive limit is 4 MiB, sixty-four
			// times this bound, and a server's concurrency caps are sized from
			// a MEASUREMENT of well-behaved tunnels. Fail the connection rather
			// than truncate, because a frame that was not delivered whole is a
			// torn byte stream and the TLS session above would fail anyway.
			c.recvErr = fmt.Errorf("%w: %d bytes, limit is %d", ErrFrameTooLarge, len(data), MaxFrameBytes)
			return
		}
		if len(data) == 0 {
			// An empty frame carries no bytes and must not be mistaken for the
			// end of the stream, which is what a zero-byte Read would mean.
			continue
		}
		c.setParked(true)
		select {
		case c.frames <- data:
			c.setParked(false)
		case <-c.done:
			return
		}
	}
}

// setParked records whether the reader goroutine is holding an undelivered
// frame, and wakes a writer waiting on the transition to parked.
func (c *Conn) setParked(v bool) {
	c.parkMu.Lock()
	c.parked = v
	if v && c.parkWait != nil {
		close(c.parkWait)
		c.parkWait = nil
	}
	c.parkMu.Unlock()
}

// parkedOrWaiter reports whether the reader is parked on an undelivered frame;
// if not it returns a channel closed when that next happens.
func (c *Conn) parkedOrWaiter() (bool, <-chan struct{}) {
	c.parkMu.Lock()
	defer c.parkMu.Unlock()
	if c.parked {
		return true, nil
	}
	if c.parkWait == nil {
		c.parkWait = make(chan struct{})
	}
	return false, c.parkWait
}

// Read implements net.Conn.
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Checked before the select below because select picks at random among
	// ready cases: with both a pending frame and an expired deadline, a bare
	// select could return data after the deadline had passed.
	switch {
	case isClosedChan(c.done):
		return 0, net.ErrClosed
	case isClosedChan(c.rd.wait()):
		return 0, os.ErrDeadlineExceeded
	}

	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}
	// A zero-length Read must not consume a frame, or its payload would be lost.
	if len(p) == 0 {
		return 0, nil
	}

	select {
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.rd.wait():
		return 0, os.ErrDeadlineExceeded
	case data, ok := <-c.frames:
		if !ok {
			return 0, c.readError()
		}
		n := copy(p, data)
		if n < len(data) {
			c.leftover = data[n:]
		}
		return n, nil
	}
}

// readError translates why the reader goroutine stopped into what a net.Conn
// reader expects. A stream that ends cleanly is io.EOF, which is how crypto/tls
// and gRPC recognise an orderly shutdown rather than a fault.
func (c *Conn) readError() error {
	switch {
	case c.recvErr == nil, errors.Is(c.recvErr, io.EOF):
		return io.EOF
	default:
		return c.recvErr
	}
}

// writeLoop is the sole caller of Send for this connection's lifetime.
//
// It exists so that a write deadline can interrupt a Write that is blocked on
// flow control. Send itself cannot be interrupted by anything but the stream's
// context, so the only way for Write to honour its deadline is to stop waiting
// on somebody else's Send rather than to abort it.
func (c *Conn) writeLoop() {
	for {
		select {
		case req := <-c.sends:
			req.result <- c.stream.Send(&tunnelpb.Frame{Data: req.data})
		case <-c.done:
			return
		}
	}
}

// Write implements net.Conn.
//
// Frames go to writeLoop rather than to Send directly, so both the wait for a
// turn and the wait for completion are selectable against the write deadline
// and against Close. Without that, a peer that opens a tunnel and then stops
// reading pins a server goroutine for the whole tunnel lifetime: gRPC's own
// handshake timeout is a conn deadline, and a deadline that cannot interrupt a
// write is not a timeout.
//
// An abandoned frame is still delivered, in order, by the writer goroutine. The
// peer therefore receives a complete prefix of the byte stream and never a torn
// one, even though Write reported fewer bytes than eventually went out. That is
// safe for every caller here, because crypto/tls and gRPC both treat a write
// error as permanent and never retry the bytes.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.writable(); err != nil {
		return 0, err
	}

	written := 0
	for len(p) > 0 {
		// Checked before each select because select picks at random among ready
		// cases, so an expired deadline racing a ready writer could otherwise
		// send a frame the caller had already given up on. Deliberately NOT
		// re-checked once the last frame has gone out: a write that delivered
		// every byte succeeded, and failing it because the connection closed
		// immediately afterwards would make every clean shutdown look like a
		// write error.
		if err := c.writable(); err != nil {
			return written, err
		}

		chunk := p
		if len(chunk) > MaxFrameBytes {
			chunk = chunk[:MaxFrameBytes]
		}
		req := sendReq{data: bytes.Clone(chunk), result: make(chan error, 1)}

		select {
		case c.sends <- req:
		case <-c.done:
			return written, net.ErrClosed
		case <-c.wd.wait():
			return written, os.ErrDeadlineExceeded
		}

		select {
		case err := <-req.result:
			if err != nil {
				// A Send that fails because we closed is a close, not a fault.
				if isClosedChan(c.done) {
					return written, net.ErrClosed
				}
				return written, c.sendError(err)
			}
		case <-c.done:
			return written, net.ErrClosed
		case <-c.wd.wait():
			return written, os.ErrDeadlineExceeded
		}

		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// sendError translates an error from Send. gRPC reports a stream that has
// already ended as a bare io.EOF and says the real status must be read from the
// receive side. Passing the io.EOF on would hide why the stream ended (a
// service-name mismatch, for one, is an Unimplemented status), so this waits for
// the reader goroutine to observe the terminal error and returns the same error
// Read would.
//
// The wait ends early in three cases, so Write can never block forever. Close
// or the write deadline fires (Close always yields net.ErrClosed, even when the
// stream status arrives at the same moment, because Close itself ends the
// stream). Or the reader goroutine is parked holding a frame
// the caller has not read: it cannot reach the terminal Recv until Read takes
// that frame, and buffering frames without bound to get past it is not an
// option, so the bare io.EOF is returned and Read will still report the status
// after the data.
//
// Divergence from Sentinel, which always returns the bare io.EOF from Write.
func (c *Conn) sendError(err error) error {
	if !errors.Is(err, io.EOF) {
		return err
	}
	for {
		// Close wins. Close also ends the stream, so the reader goroutine
		// stops with a cancellation (or with no error at all, when it was
		// parked on an undelivered frame); that is the consequence of the
		// Close, not the stream's own status, and must not be reported as one.
		if isClosedChan(c.done) {
			return net.ErrClosed
		}
		select {
		case <-c.recvEnded:
			return c.statusAfterRecvEnded()
		default:
		}
		parked, wake := c.parkedOrWaiter()
		if parked {
			return err
		}
		select {
		case <-c.recvEnded:
			return c.statusAfterRecvEnded()
		case <-wake:
		case <-c.done:
			return net.ErrClosed
		case <-c.wd.wait():
			return os.ErrDeadlineExceeded
		}
	}
}

// statusAfterRecvEnded is what sendError returns once the reader goroutine has
// stopped: net.ErrClosed when Close caused the stop, otherwise what Read would
// return.
func (c *Conn) statusAfterRecvEnded() error {
	if isClosedChan(c.done) {
		return net.ErrClosed
	}
	return c.readError()
}

// writable reports whether a frame may be sent now.
func (c *Conn) writable() error {
	switch {
	case isClosedChan(c.done):
		return net.ErrClosed
	case isClosedChan(c.wd.wait()):
		return os.ErrDeadlineExceeded
	}
	return nil
}

// Close implements net.Conn. It is safe to call more than once and from any
// goroutine, including while a Read or Write is blocked.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.teardown != nil {
			c.teardown()
		}
	})
	return nil
}

// Done returns a channel closed when the connection is closed.
//
// The server's tunnel handler waits on it: the handler must hold the outer
// stream open for as long as the inner server is using this connection, because
// returning would end the stream and cut the connection out from under it.
func (c *Conn) Done() <-chan struct{} { return c.done }

// LocalAddr implements net.Conn.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr implements net.Conn.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline implements net.Conn.
func (c *Conn) SetDeadline(t time.Time) error {
	if isClosedChan(c.done) {
		return net.ErrClosed
	}
	c.rd.set(t)
	c.wd.set(t)
	return nil
}

// SetReadDeadline implements net.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if isClosedChan(c.done) {
		return net.ErrClosed
	}
	c.rd.set(t)
	return nil
}

// SetWriteDeadline implements net.Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if isClosedChan(c.done) {
		return net.ErrClosed
	}
	c.wd.set(t)
	return nil
}

// tunnelAddr is the placeholder address used when a real one is not supplied.
// net.Conn implementations must never return a nil Addr: gRPC and crypto/tls
// both format the peer address on error paths, and a nil there panics inside
// the very failure it was trying to report.
type tunnelAddr string

func (a tunnelAddr) Network() string { return "supertls" }
func (a tunnelAddr) String() string  { return string(a) }

// Compile-time proof that Conn satisfies the interface everything above it
// assumes.
var _ net.Conn = (*Conn)(nil)
