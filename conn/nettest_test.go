package conn

import (
	"net"
	"testing"

	"golang.org/x/net/nettest"
)

// TestConnSatisfiesNetConn runs the standard library's own net.Conn conformance
// suite against the adapter.
//
// This package exists so that crypto/tls and gRPC's HTTP/2 transport can run
// over a gRPC stream unmodified, and both of them assume net.Conn semantics
// rather than merely the interface. Hand-written tests check the behaviours we
// thought of; nettest checks the ones the standard library actually relies on --
// short reads, racy concurrent access, deadlines armed while a call is already
// blocked, and a Close that unblocks everything.
//
// All eleven subtests must pass. Two of them (PresentTimeout and FutureTimeout)
// arm a deadline while a Write is blocked with nobody reading, which is
// precisely the case that pins a goroutine for a whole tunnel lifetime if Write
// cannot be interrupted. Do not skip them.
func TestConnSatisfiesNetConn(t *testing.T) {
	nettest.TestConn(t, func() (net.Conn, net.Conn, func(), error) {
		sa, sb := streamPair()
		a := NewConn(sa, Options{Teardown: sa.close})
		b := NewConn(sb, Options{Teardown: sb.close})
		return a, b, func() { a.Close(); b.Close() }, nil
	})
}
