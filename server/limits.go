package server

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/qunulabs/supertls/conn"
)

// DefaultServiceName is the gRPC service name the tunnel service registers
// under unless WithServiceName says otherwise. A client must use the same name.
const DefaultServiceName = "supertls.v1.TunnelService"

// Tunnel resource limits.
//
// The tunnel call is unauthenticated by construction, so the exposure it adds
// is resource rather than identity.
//
// MEASURED, not estimated: holding a hundred live tunnels costs about 134 KiB
// and eleven goroutines per tunnel on the server side. Measure again before
// changing these numbers.
//
// The two failure modes are not symmetric, and that decides the sizing. A cap
// set too low refuses a legitimate customer, whose software then cannot start:
// an outage. A cap set too high risks memory exhaustion, but only under
// deliberate attack, and only on a host where the figure below is a rounding
// error. So the defaults are generous against the fleet and conservative against
// the host.
const (
	// DefaultMaxConcurrent bounds the whole process.
	//
	// Roughly 134 MiB of server-side memory and 11,000 goroutines at the cap. On
	// a 4 GiB host shared with other services that is about three percent of it,
	// and about ten times the fleet this default was sized for, so growth has a
	// long runway. Raise it if the fleet grows or the host does; lowering it is
	// what causes outages.
	DefaultMaxConcurrent = 1024

	// DefaultMaxPerAddress stops one address consuming the whole global budget
	// while still allowing a large customer to run many clients behind a single
	// NAT egress address, which is legitimate and common. A quarter of the global
	// cap, and still well above the entire fleet.
	DefaultMaxPerAddress = 256

	// DefaultOpenBurst is the token bucket depth for tunnel opens per address.
	//
	// It is DOUBLE the per-address concurrency cap so that the concurrency cap is
	// always the binding constraint in steady state and the rate limit bites only
	// on churn. At exactly the cap, a site of that size restarting would spend its
	// whole budget coming up, and the first client to reconnect a moment later
	// would be refused for a reason that has nothing to do with abuse.
	DefaultOpenBurst = 2 * DefaultMaxPerAddress

	// DefaultOpenRefillPerSecond is the sustained open rate per address.
	//
	// The concurrency caps bound how much is held at once; they do not bound
	// CHURN. A peer that opens a tunnel, lets the inner TLS handshake start and
	// drops it, repeatedly, stays far below the per-address cap while costing a
	// handshake and a goroutine every time. This bounds that.
	//
	// The number comes from the worst LEGITIMATE behaviour, not from what an
	// attacker deserves, because getting it wrong breaks a large customer long
	// before it inconveniences anyone. A client whose proxy kills tunnels
	// continuously re-dials on a backoff capped at 15 seconds, so one client
	// sustains at most four opens a minute. With DefaultMaxPerAddress clients
	// behind a single NAT egress address that is about 17 a second.
	//
	// There is deliberately NO global open-rate limit. A fleet-wide churn ceiling
	// cannot be sized from anything this process knows, and one set too low turns
	// a mass reconnect after a service restart into an outage that prevents its
	// own recovery.
	DefaultOpenRefillPerSecond = 17.0

	// DefaultBucketSweep bounds the bookkeeping: without a sweep the bucket map
	// grows by one entry per client address ever seen and never shrinks.
	DefaultBucketSweep = 5 * time.Minute

	// DefaultAcceptTimeout is how long a tunnel handler waits for the inner
	// server to accept a connection before refusing the tunnel.
	DefaultAcceptTimeout = conn.DefaultAcceptTimeout

	// DefaultInnerHandshakeTimeout bounds a peer that opens a tunnel and then
	// never speaks HTTP/2 or TLS. It works only because the tunnel connection
	// implements SetDeadline properly.
	DefaultInnerHandshakeTimeout = 20 * time.Second

	// DefaultInnerMaxConnectionIdle is the ONLY thing that reclaims a tunnel
	// held open by a peer that completes the inner handshake and then issues
	// nothing. When client certificates are verified only if given and every
	// authorisation decision is made per call, such a peer is never authorised
	// and, without this bound, never disconnected either; the handshake timeout
	// does not reach it because the handshake succeeded. A few addresses at the
	// per-address cap could then hold the whole global cap for DefaultMaxLifetime
	// and refuse every genuine client. This is the bound that carries weight.
	DefaultInnerMaxConnectionIdle = 5 * time.Minute

	// DefaultMaxLifetime is a backstop, not a policy. The idle bound retires an
	// unused connection after five minutes and a working one closes when its
	// client does, so nothing legitimate comes near this. It exists so that a
	// tunnel whose inner connection somehow never closes cannot leak forever.
	//
	// It is NOT the defence against an idle squatter: four hours is far too long
	// for that job. See DefaultInnerMaxConnectionIdle.
	DefaultMaxLifetime = 4 * time.Hour

	// KeepaliveMinTime is the shortest interval between client pings the server
	// tolerates. See KeepalivePolicy.
	KeepaliveMinTime = 5 * time.Second
)

// ErrInvalidOption is returned by New, and by the options that validate their
// argument, when a value is unusable. Test for it with errors.Is.
var ErrInvalidOption = errors.New("supertls/server: invalid option")

// ErrWindowInvariant is returned when the outer stream window is smaller than
// the inner connection window, or when only one of the two is set.
var ErrWindowInvariant = errors.New("supertls/server: outer stream window must be at least the inner connection window")

// Limits bounds the resources the tunnel service will spend. Every field must be
// positive; start from DefaultLimits and change what you mean to change.
type Limits struct {
	// MaxConcurrent bounds the open tunnels of the whole process.
	MaxConcurrent int
	// MaxPerAddress bounds the open tunnels from one client address. It must not
	// exceed MaxConcurrent.
	//
	// The address is the IP of the OUTER connection's peer. Behind a TCP load
	// balancer or NAT that hides client addresses every client shares one
	// address, so this limit and the open rate below apply to the whole fleet
	// together. Forwarding headers and PROXY protocol are not read.
	MaxPerAddress int
	// OpenBurst and OpenRefillPerSecond are the token bucket that bounds how fast
	// one address may open tunnels.
	OpenBurst           int
	OpenRefillPerSecond float64
	// BucketSweep is how often idle full buckets are forgotten.
	BucketSweep time.Duration
	// AcceptTimeout is how long a handler waits for the inner server to accept.
	AcceptTimeout time.Duration
	// InnerHandshakeTimeout bounds the inner server's connection setup.
	InnerHandshakeTimeout time.Duration
	// InnerMaxConnectionIdle closes an inner connection that carries no call for
	// this long.
	InnerMaxConnectionIdle time.Duration
	// MaxLifetime is the absolute backstop on one tunnel.
	MaxLifetime time.Duration
}

// DefaultLimits returns the defaults, which are the values proven in production
// by the transport this library was extracted from.
func DefaultLimits() Limits {
	return Limits{
		MaxConcurrent:          DefaultMaxConcurrent,
		MaxPerAddress:          DefaultMaxPerAddress,
		OpenBurst:              DefaultOpenBurst,
		OpenRefillPerSecond:    DefaultOpenRefillPerSecond,
		BucketSweep:            DefaultBucketSweep,
		AcceptTimeout:          DefaultAcceptTimeout,
		InnerHandshakeTimeout:  DefaultInnerHandshakeTimeout,
		InnerMaxConnectionIdle: DefaultInnerMaxConnectionIdle,
		MaxLifetime:            DefaultMaxLifetime,
	}
}

// Validate refuses any non-positive field and a per-address cap above the global
// one. The error wraps ErrInvalidOption.
func (l Limits) Validate() error {
	ints := []struct {
		name string
		v    int
	}{
		{"MaxConcurrent", l.MaxConcurrent},
		{"MaxPerAddress", l.MaxPerAddress},
		{"OpenBurst", l.OpenBurst},
	}
	for _, f := range ints {
		if f.v <= 0 {
			return fmt.Errorf("%w: limit %s is %d, want a positive value", ErrInvalidOption, f.name, f.v)
		}
	}
	// Written as a negated comparison so NaN is refused too.
	if !(l.OpenRefillPerSecond > 0) || math.IsInf(l.OpenRefillPerSecond, 0) {
		return fmt.Errorf("%w: limit OpenRefillPerSecond is %v, want a positive finite value",
			ErrInvalidOption, l.OpenRefillPerSecond)
	}
	durations := []struct {
		name string
		v    time.Duration
	}{
		{"BucketSweep", l.BucketSweep},
		{"AcceptTimeout", l.AcceptTimeout},
		{"InnerHandshakeTimeout", l.InnerHandshakeTimeout},
		{"InnerMaxConnectionIdle", l.InnerMaxConnectionIdle},
		{"MaxLifetime", l.MaxLifetime},
	}
	for _, f := range durations {
		if f.v <= 0 {
			return fmt.Errorf("%w: limit %s is %s, want a positive duration", ErrInvalidOption, f.name, f.v)
		}
	}
	if l.MaxPerAddress > l.MaxConcurrent {
		return fmt.Errorf("%w: MaxPerAddress %d exceeds MaxConcurrent %d",
			ErrInvalidOption, l.MaxPerAddress, l.MaxConcurrent)
	}
	return nil
}

// minWindow is the smallest window gRPC honours: it silently ignores a smaller
// initial window, which would leave its bandwidth estimator on.
const minWindow = 64 << 10

// Windows sizes the server's flow control. A zero field leaves gRPC's default,
// which is its bandwidth-delay estimator.
//
// All inner traffic shares ONE outer stream, so with the estimator on a small
// call can queue behind bulk bytes for roughly (outer window / bandwidth), and
// the estimator grows the window toward 16 MiB on a fat link. Pinning the
// windows bounds that head-of-line delay. Setting any initial window turns the
// estimator off, which is the point.
//
// The client side is sized by the client package; the two sides size their own
// receive windows, so setting them here does not have to match.
type Windows struct {
	// OuterStream and OuterConn are the initial HTTP/2 windows of every
	// connection of the outer server. OuterStream must be at least InnerConn.
	OuterStream, OuterConn int32
	// InnerStream and InnerConn are the initial HTTP/2 windows of every
	// connection of the inner server.
	InnerStream, InnerConn int32
}

// Validate refuses a window gRPC would ignore, a window set on only one of
// OuterStream and InnerConn, and an outer stream window smaller than the inner
// connection window. The first wraps ErrInvalidOption, the others
// ErrWindowInvariant.
func (w Windows) Validate() error {
	for _, f := range []struct {
		name string
		v    int32
	}{
		{"OuterStream", w.OuterStream},
		{"OuterConn", w.OuterConn},
		{"InnerStream", w.InnerStream},
		{"InnerConn", w.InnerConn},
	} {
		if f.v != 0 && f.v < minWindow {
			return fmt.Errorf("%w: window %s is %d, want zero or at least %d (gRPC ignores a smaller window)",
				ErrInvalidOption, f.name, f.v, minWindow)
		}
	}
	// The invariant compares OuterStream with InnerConn, so it only has a meaning
	// when both are set. Setting one alone leaves the other at gRPC's estimator,
	// which can grow past it, so it is refused rather than guessed at.
	if (w.OuterStream == 0) != (w.InnerConn == 0) {
		return fmt.Errorf("%w: OuterStream (%d) and InnerConn (%d) must be set together",
			ErrWindowInvariant, w.OuterStream, w.InnerConn)
	}
	if w.OuterStream < w.InnerConn {
		return fmt.Errorf("%w (outer stream %d, inner connection %d)",
			ErrWindowInvariant, w.OuterStream, w.InnerConn)
	}
	return nil
}
