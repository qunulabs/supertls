// Package supertls carries one TLS session inside another. The outer TLS
// connection is an ordinary gRPC call to a server that presents a certificate
// from the public web PKI, so a middlebox that terminates and inspects TLS sees
// only the outer session; the inner session runs end to end through it as the
// opaque bytes of a stream.
//
// supertls owns the outer connection, the detection of a middlebox that breaks
// the inner session, the cache of which mode each destination needs, the adapter
// that makes a gRPC stream look like a net.Conn, the tunnel service a server
// registers to accept inner connections, and the limits that bound all of it.
//
// supertls owns none of the inner TLS configuration, no certificate, no
// authorisation decision, and nothing that the inner session carries. The
// caller supplies the inner configuration and decides who may connect; supertls
// moves bytes and reports how the path behaved.
//
// See README.md for how to use it.
package supertls
