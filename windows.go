package supertls

import (
	"errors"
	"fmt"
)

// Flow-control sizing for the nested connections.
//
// These are pinned rather than left to gRPC's bandwidth-delay estimator, and the
// reason is head-of-line blocking rather than throughput. All inner traffic
// shares ONE outer stream, so a small RPC can queue behind bulk bytes for
// roughly (outer window / bandwidth). At 1 MiB on a 1 Mbit/s link that is about
// eight seconds, comfortably inside a 30-second RPC deadline. Left to
// auto-tune, the estimator would grow the window toward 16 MiB on a fat link,
// and the same arithmetic then gives over two minutes: every small RPC issued
// during a large transfer would time out. Setting any initial window size in
// gRPC also turns the estimator off, which is the point.
//
// The invariant to preserve: outer stream window >= inner connection window,
// or the outer stream silently becomes the binding constraint. Windows.Validate
// enforces it at construction.
const (
	// DefaultOuterStreamWindow is the initial HTTP/2 stream window of the outer
	// connection.
	DefaultOuterStreamWindow = 1 << 20
	// DefaultOuterConnWindow is the initial HTTP/2 connection window of the
	// outer connection.
	DefaultOuterConnWindow = 2 << 20
	// DefaultInnerStreamWindow is the initial HTTP/2 stream window of the inner
	// connection.
	DefaultInnerStreamWindow = 512 << 10
	// DefaultInnerConnWindow is the initial HTTP/2 connection window of the
	// inner connection.
	DefaultInnerConnWindow = 1 << 20
	// DefaultBufferSize is the read and write buffer size of the outer
	// connection.
	DefaultBufferSize = 64 << 10

	// MinWindow is the smallest window gRPC honours: it silently ignores a
	// smaller initial window, which would leave the estimator on.
	MinWindow = 64 << 10
)

// ErrWindowInvariant is returned when the outer stream window is smaller than
// the inner connection window.
var ErrWindowInvariant = errors.New("supertls: outer stream window must be at least the inner connection window")

// ErrInvalidOption is returned when a client option is unusable. Test for it
// with errors.Is.
var ErrInvalidOption = errors.New("supertls: invalid option")

// Windows sizes the flow control of the two nested connections.
type Windows struct {
	// OuterStream and OuterConn are the initial HTTP/2 windows of the outer
	// connection. OuterStream must be at least InnerConn.
	OuterStream, OuterConn int32
	// InnerStream and InnerConn are the initial HTTP/2 windows of the inner
	// connection.
	InnerStream, InnerConn int32
	// Buffer is the read and write buffer size, in bytes, of the outer
	// connection.
	Buffer int
}

// DefaultWindows returns the defaults, which are the values proven in
// production by the transport this library was extracted from.
func DefaultWindows() Windows {
	return Windows{
		OuterStream: DefaultOuterStreamWindow,
		OuterConn:   DefaultOuterConnWindow,
		InnerStream: DefaultInnerStreamWindow,
		InnerConn:   DefaultInnerConnWindow,
		Buffer:      DefaultBufferSize,
	}
}

// Validate refuses windows gRPC would ignore and the one combination that makes
// the outer stream the binding constraint.
func (w Windows) Validate() error {
	for _, f := range []struct {
		name string
		v    int64
	}{
		{"OuterStream", int64(w.OuterStream)},
		{"OuterConn", int64(w.OuterConn)},
		{"InnerStream", int64(w.InnerStream)},
		{"InnerConn", int64(w.InnerConn)},
	} {
		if f.v < MinWindow {
			return fmt.Errorf("%w: window %s is %d, want at least %d (gRPC ignores a smaller window)",
				ErrInvalidOption, f.name, f.v, MinWindow)
		}
	}
	if w.Buffer <= 0 {
		return fmt.Errorf("%w: window Buffer is %d, want a positive size", ErrInvalidOption, w.Buffer)
	}
	if w.OuterStream < w.InnerConn {
		return fmt.Errorf("%w (outer stream %d, inner connection %d)",
			ErrWindowInvariant, w.OuterStream, w.InnerConn)
	}
	return nil
}
