// Package conn adapts a gRPC bidirectional stream to a net.Conn, so that a
// complete TLS session can be run inside one.
//
// It exists to keep a strict mutual-TLS session working on networks that
// terminate and re-sign TLS for inspection. The client opens a permissive outer
// TLS connection such a proxy can inspect freely, opens one TunnelService.Open
// stream on it, wraps that stream with this package, and runs the UNCHANGED
// strict mTLS session over the result. The server does the mirror image,
// handing the wrapped stream to an in-process gRPC server built from the same
// tls.Config and the same handlers.
//
// A Conn follows gRPC's own stream rules: one goroutine reading and one
// goroutine writing at a time. Internally a single reader goroutine owns Recv
// and a single writer goroutine owns Send for the connection's lifetime, so
// every Conn must be closed. Concurrent calls to Read, or to Write, are
// serialised rather than interleaved.
//
// Nothing in this package knows what it carries, and it must stay that way: the
// security of the tunnelled session lives entirely in the inner session, which
// is byte-for-byte the one that would run without the tunnel.
package conn
