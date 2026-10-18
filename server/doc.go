// Package server is the server half of supertls: the tunnel service, the limits
// that bound it, and the helpers that build the two gRPC servers a tunnel needs.
//
// A deployment runs two gRPC servers. The OUTER server listens on the real
// socket, terminates the outer TLS connection and carries the tunnel service.
// The INNER server has no socket of its own: it serves the Listener of the
// Service, which is fed by the tunnel handler, so every tunnelled connection
// arrives at it as a net.Conn and the inner TLS handshake is performed by gRPC
// itself. Because both servers carry the same handlers, a handler cannot tell
// whether a call came through a tunnel.
//
// Wiring, in prose: build a Service with New; build the outer server with its
// credentials, the outer options and your own options, call Register on it and
// serve it on the real listener; build the inner server with credentials made
// from the SAME tls.Config value, the inner options and your own options,
// register every service on it that the outer server carries, and serve it on
// the Service's Listener. Pass the real listener's address to WithListenerAddr
// so the inner server's logs and gRPC's connection map see a meaningful address.
// On shutdown call GracefulStop with both servers.
//
// Five rules, each of which fails silently when broken:
//
//  1. Register the tunnel service on the outer server ONLY. Registering it on
//     the inner server would let a tunnel nest inside a tunnel.
//  2. Give InnerServerOptions to the inner server ONLY. They set
//     MaxConnectionIdle, which would close direct-path clients of the outer
//     server that are legitimately idle between calls.
//  3. Build both servers' credentials from the same tls.Config value, so the
//     inner session is byte for byte the one that would have run directly.
//  4. Stop the inner server first. Every tunnel handler blocks until its inner
//     connection closes, and only the inner server closes it, so stopping the
//     outer server first waits on handlers that wait on a server nobody asked to
//     stop. GracefulStop does it in the right order.
//  5. The outer server must not REQUIRE a client certificate: the client's
//     outer connection is permissive and presents none. Verify client
//     certificates on the inner session, where the identity lives, for example
//     with tls.VerifyClientCertIfGiven and a per-call check.
//
// The tunnel call is unauthenticated by construction, exactly as the outer
// server's other pre-authentication calls are, so what it exposes is resource
// rather than identity. Limits bounds that exposure.
package server
