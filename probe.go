package supertls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Verdict is what a probe concluded about the peer at a host.
type Verdict int

const (
	// VerdictInconclusive: the probe found no evidence either way. The
	// connection never reached TLS (refused, no route, DNS failure, a proxy that
	// would not CONNECT), or the probe ran out of time during the handshake.
	VerdictInconclusive Verdict = iota

	// VerdictGenuine: the peer presented a certificate the Trust recognises, so
	// it IS the caller's server and any strict-dial failure is the server's own
	// (an expired server leaf, or SANs drifted from the configured hosts). The
	// tunnel would reproduce it identically.
	VerdictGenuine

	// VerdictIntercepted: the peer is not the caller's server, or something
	// between here and it is mangling TLS.
	VerdictIntercepted
)

func (v Verdict) String() string {
	switch v {
	case VerdictInconclusive:
		return "inconclusive"
	case VerdictGenuine:
		return "genuine"
	case VerdictIntercepted:
		return "intercepted"
	default:
		return "unknown"
	}
}

// DefaultProbeTimeout bounds one interception probe. A probe runs only after a
// strict dial has already failed, so it costs nothing on the healthy path.
const DefaultProbeTimeout = 10 * time.Second

// ErrForeignCertificate is returned with VerdictIntercepted when the peer
// completed a handshake but presented a certificate the Trust does not
// recognise.
var ErrForeignCertificate = errors.New("supertls: peer presented a certificate that does not chain to the trusted roots")

// errInvalidTrust is returned when Probe is given a Trust that no constructor
// built.
var errInvalidTrust = errors.New("supertls: invalid Trust: build one with TrustPool, TrustPoolWithHostname or TrustSystemRoots")

// Probe decides whether host is being intercepted, within DefaultProbeTimeout.
// host is the address the caller dials with gRPC; without a port it means 443,
// as it does to gRPC.
func Probe(ctx context.Context, host string, trust Trust) (Verdict, error) {
	return probe(ctx, host, trust, DefaultProbeTimeout)
}

// probe decides whether a host is being intercepted.
//
// It does NOT classify the strict dial's error, which cannot answer the question
// reliably: Go verifies validity dates and the hostname BEFORE it reports a
// chain result, so an expired leaf or a drifted SAN masks whether the peer was
// ours at all. Instead this asks the question directly: perform a maximally
// permissive handshake and look at the certificate the peer actually presented.
//
// That is evidence rather than heuristics. An interceptor cannot produce a chain
// to the trusted roots, and if it could, a proxy would be the least of the
// problems.
func probe(ctx context.Context, host string, trust Trust, timeout time.Duration) (Verdict, error) {
	if !trust.valid() {
		return VerdictInconclusive, errInvalidTrust
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hostport := hostPort(host)
	raw, err := dialLikeGRPC(ctx, hostport)
	if err != nil {
		return VerdictInconclusive, err
	}
	defer raw.Close()

	hostOnly, _, splitErr := net.SplitHostPort(hostport)
	if splitErr != nil {
		hostOnly = hostport
	}

	var presented [][]byte
	conn := tls.Client(raw, &tls.Config{
		ServerName: hostOnly,
		//nolint:gosec // G402: intentional. This probe verifies the chain itself,
		// below, precisely so it can tell "not our server" from "our server, but
		// misconfigured", a distinction stdlib verification collapses.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		// Classical groups only. A post-quantum hybrid hello is over 1400 bytes
		// and is itself a middlebox tripwire, which would make the probe fail for
		// the very reason it is trying to diagnose.
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		NextProtos:       []string{"h2"},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			presented = rawCerts
			return nil
		},
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			// The probe ran out of time (or was cancelled) mid-handshake. A
			// silent or slow peer is no evidence either way.
			return VerdictInconclusive, err
		}
		// TCP succeeded, but even a maximally permissive TLS 1.2 handshake with
		// classical groups failed. The caller's server would have completed
		// this. That covers a protocol_version alert, a handshake_failure alert,
		// a record header error, and a captive portal answering in plaintext
		// HTTP.
		return VerdictIntercepted, err
	}
	defer conn.Close()

	if trust.recognises(presented, hostOnly) {
		return VerdictGenuine, nil
	}
	var issuer, subject string
	if len(presented) > 0 {
		if leaf, err := x509.ParseCertificate(presented[0]); err == nil {
			issuer, subject = leaf.Issuer.CommonName, leaf.Subject.CommonName
		}
	}
	return VerdictIntercepted, fmt.Errorf("%w (issuer %q, subject %q)", ErrForeignCertificate, issuer, subject)
}

// hostPort gives host the port gRPC would dial when it names none: 443. It
// follows gRPC's own target parsing, so a bare IPv6 literal ("::1") and a
// bracketed one without a port ("[::1]") both become "[::1]:443". Anything it
// cannot read is returned unchanged for the dial to reject.
func hostPort(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(host, "443")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if _, _, err := net.SplitHostPort(host + ":443"); err == nil {
		return host + ":443"
	}
	return host
}
