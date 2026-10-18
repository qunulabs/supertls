package supertls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"google.golang.org/grpc/credentials"
)

// permissiveCreds are the transport credentials for the OUTER connection of a
// tunnelled dial. They are deliberately, and safely, unverified.
//
// WHY THIS IS NOT A WEAKENING. Everything carried over this connection is the
// caller's complete inner TLS session, verified by the caller's own inner
// credentials exactly as on the direct path. A peer that terminates this outer
// connection receives opaque bytes and cannot complete the inner handshake, so
// there is nothing here for verification to protect. Verifying it would instead
// GUARANTEE failure in the one situation this exists for: a corporate proxy that
// substitutes the server certificate.
//
// WHY NOT credentials.NewTLS. Two reasons, and the second is decisive.
//
//   - It enforces ALPN. Since gRPC 1.67 a handshake that negotiates no protocol
//     is rejected outright (see credentials/tls.go and GRPC_ENFORCE_ALPN_ENABLED).
//     An inspecting proxy that does not echo h2 would therefore kill the outer
//     connection, which is precisely the middlebox this code exists to survive.
//     The only global escape hatch is an environment variable, and this is a
//     library linked into someone else's binary, so setting that is not an option.
//   - It offers no way to drop the post-quantum hybrid group from the outer
//     handshake. Go's CurvePreferences is a FILTER, not an ordering, and the
//     library's fixed order always puts the hybrid first, so a config listing it
//     produces a client hello over 1400 bytes that spans TCP segments. That is a
//     known middlebox tripwire in its own right. The outer connection must be the
//     blandest possible TLS; the inner session keeps the hybrid, where no
//     middlebox can see it.
type permissiveCreds struct{}

func (permissiveCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (
	net.Conn, credentials.AuthInfo, error) {

	host, _, err := net.SplitHostPort(authority)
	if err != nil {
		host = authority
	}

	conn := tls.Client(raw, &tls.Config{
		// Sent as SNI. Both a proxy and the origin route on it, so it must be
		// the real host even though nothing here verifies the answer.
		ServerName: host,
		//nolint:gosec // G402: intentional. See the type comment above: the inner
		// session performs the real verification and this connection protects
		// nothing on its own.
		InsecureSkipVerify: true,
		// As permissive as is still reasonable: an inspection engine that caps
		// at TLS 1.2 must be able to terminate this.
		MinVersion: tls.VersionTLS12,
		// Classical groups only, to keep the client hello small. See above.
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		NextProtos:       []string{"h2"},
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Deliberately NOT checking NegotiatedProtocol, unlike credentials.NewTLS.
	// A proxy may terminate TLS without echoing h2; we speak HTTP/2 regardless,
	// and if it genuinely cannot carry HTTP/2 the connection preface fails with
	// a clearer error than an ALPN rejection would give.
	return conn, credentials.TLSInfo{
		State: conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}, nil
}

func (permissiveCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("supertls: permissive credentials are client-only")
}

// Info must report an EMPTY ServerName. gRPC's initAuthority overrides the
// connection's authority with a non-empty value here, and the authority is what
// the INNER session derives its ServerName from. Filling this in would silently
// redirect the inner hostname check.
func (permissiveCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.2"}
}

func (c permissiveCreds) Clone() credentials.TransportCredentials { return c }

func (permissiveCreds) OverrideServerName(string) error { return nil }

var _ credentials.TransportCredentials = permissiveCreds{}
