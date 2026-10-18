package supertls

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

// dialFunc dials one host in one mode and returns the connection once it is
// ready.
type dialFunc func(ctx context.Context, host string, inner credentials.TransportCredentials, extra []grpc.DialOption) (*Conn, error)

// Dialer dials hosts directly, and through a tunnel when the direct path is
// intercepted. It remembers per host which mode works. A Dialer is safe for
// concurrent use.
type Dialer struct {
	cfg   config
	trust Trust
	modes *modeCache

	// logged holds the hosts whose switch to the tunnel has been logged, so the
	// line appears once per host for the life of the Dialer.
	logged sync.Map

	// Test seams. NewDialer sets them; only tests overwrite them, and only
	// before the first Dial.
	directFn dialFunc
	tunnelFn dialFunc
	probeFn  func(ctx context.Context, host string) (Verdict, error)
	now      func() time.Time
}

// NewDialer builds a Dialer. trust says which certificates identify the
// caller's own server; it decides whether a failed direct dial is worth
// tunnelling. A zero or otherwise invalid Trust is refused with
// ErrInvalidOption: the probe could never call a peer genuine, so every failed
// direct dial would silently be tunnelled.
func NewDialer(trust Trust, opts ...Option) (*Dialer, error) {
	if !trust.valid() {
		return nil, invalid("Trust: %v", errInvalidTrust)
	}
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}
	d := &Dialer{cfg: cfg, trust: trust, now: time.Now}
	// Through d.now rather than time.Now, so a test that replaces the clock
	// also moves the cache.
	d.modes = newModeCache(cfg.tunnelTTL, func() time.Time { return d.now() })
	d.directFn = d.dialDirect
	d.tunnelFn = d.dialTunnel
	d.probeFn = func(ctx context.Context, host string) (Verdict, error) {
		return probe(ctx, host, d.trust, d.cfg.probeTimeout)
	}
	return d, nil
}

// Mode reports how host is currently reached. An expired tunnel decision reads
// as ModeUnknown.
func (d *Dialer) Mode(host string) Mode { return d.modes.get(host) }

// Dial connects to host and returns the connection once it is ready.
//
// inner is the caller's transport credentials for the session with its own
// server. They are used unchanged on both paths, and they must verify the
// server: nil, or credentials that verify nothing (grpc's insecure
// credentials), are refused with ErrInvalidOption. extra is applied to the
// direct connection and to the inner connection of a tunnel, never to the
// outer one; it cannot replace inner, nor the dialler that carries the inner
// connection through the tunnel.
//
// A host already known to need the tunnel goes straight to it. Everything else
// tries the direct path first and stays there unless there is evidence of
// interception: a failed direct dial is followed by a probe, and only a peer
// that is not recognised as the caller's server (or a probe that cannot tell)
// is tunnelled. A genuine peer is never tunnelled, because the tunnel dials the
// same host through the same network and would fail identically; its error is
// reported as it is.
func (d *Dialer) Dial(ctx context.Context, host string, inner credentials.TransportCredentials, extra ...grpc.DialOption) (*Conn, error) {
	if err := checkDialArgs(host, inner, extra); err != nil {
		return nil, err
	}
	if d.modes.get(host) == ModeTunnel {
		c, err := d.tunnelFn(ctx, host, inner, extra)
		if err != nil {
			return nil, fmt.Errorf("supertls: tunnelled dial of %s: %w", host, err)
		}
		return c, nil
	}
	c, directErr := d.directFn(ctx, host, inner, extra)
	if directErr == nil {
		d.transition(host, ModeDirect, VerdictGenuine, nil)
		return c, nil
	}
	if ctx.Err() != nil {
		// The caller gave up. That is not the host's fault and not worth a
		// probe.
		return nil, directErr
	}
	v, probeErr := d.probeFn(ctx, host)
	if v == VerdictGenuine {
		return nil, &DialError{Host: host, Direct: directErr, Verdict: v, ProbeErr: probeErr}
	}
	tc, tunnelErr := d.tunnelFn(ctx, host, inner, extra)
	if tunnelErr != nil {
		return nil, &DialError{Host: host, Direct: directErr, Verdict: v, ProbeErr: probeErr, Tunnel: tunnelErr}
	}
	d.transition(host, ModeTunnel, v, probeErr)
	return tc, nil
}

// checkDialArgs refuses the arguments that would otherwise surface as a panic
// inside gRPC, or as a dial that verifies nothing.
func checkDialArgs(host string, inner credentials.TransportCredentials, extra []grpc.DialOption) error {
	if host == "" {
		return invalid("Dial: empty host")
	}
	if inner == nil {
		return invalid("Dial: nil inner credentials")
	}
	// The inner session is the whole security argument of the tunnel: the outer
	// connection verifies nothing, by design. Credentials that do not verify the
	// server would leave the tunnelled path with no verification at all.
	if p := inner.Info().SecurityProtocol; p == "insecure" {
		return invalid("Dial: inner credentials (security protocol %q) do not verify the server", p)
	}
	return checkDialOptions("Dial", extra)
}

// transition records host's new mode, logs the first switch to the tunnel per
// host, and calls the hook when the mode changed.
//
// The cache update and the "did it change" decision are one step under the
// cache's mutex (set returns what it replaced), so of many dials racing to the
// same decision exactly one sees the change and calls the hook.
func (d *Dialer) transition(host string, to Mode, v Verdict, reason error) {
	prev := d.modes.set(host, to)
	if to == ModeTunnel {
		d.logTunnelOnce(host, v, reason)
	}
	if prev != to && d.cfg.onModeChange != nil {
		d.cfg.onModeChange(ModeChange{Host: host, From: prev, To: to, Verdict: v, Reason: reason})
	}
}

// logTunnelOnce reports the switch to tunnelling, once per host.
//
// Two nested TLS layers make packet capture useless for diagnosis, so this line
// is the only external evidence that the mode changed. It is also the honest
// thing to do: a network's security team is entitled to know that traffic to
// this host stopped being inspectable on their network.
func (d *Dialer) logTunnelOnce(host string, v Verdict, reason error) {
	if _, loaded := d.logged.LoadOrStore(host, struct{}{}); loaded {
		return
	}
	msg := "supertls: could not tell whether TLS to this host is intercepted; traffic to it is now carried inside a tunnel"
	if v == VerdictIntercepted {
		msg = "supertls: TLS interception detected; traffic to this host is now carried inside a tunnel"
	}
	d.cfg.logger.Warn(msg, "host", host, "verdict", v.String(), "err", reason)
}

// dialDirect dials host directly and returns the connection once it is READY.
//
// Nothing is added to what the caller would dial itself. The caller's inner
// credentials are the LAST transport credentials in the list, after the
// configured direct options and extra, so a stray WithTransportCredentials in
// either cannot replace them.
func (d *Dialer) dialDirect(ctx context.Context, host string, inner credentials.TransportCredentials, extra []grpc.DialOption) (*Conn, error) {
	rec := &recorder{}
	opts := make([]grpc.DialOption, 0, len(d.cfg.directOpts)+len(extra)+1)
	opts = append(opts, d.cfg.directOpts...)
	opts = append(opts, extra...)
	opts = append(opts, grpc.WithTransportCredentials(recording(inner, rec)))
	cc, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, fmt.Errorf("supertls: direct dial of %s: %w", host, err)
	}
	if err := waitForReady(ctx, host, cc, d.cfg.directBudget, rec); err != nil {
		cc.Close()
		return nil, err
	}
	return &Conn{cc: cc, mode: ModeDirect}, nil
}

// waitForReady forces cc out of IDLE and waits until it is READY, within budget.
//
// grpc.NewClient is lazy: it never dials on its own, so a connection must be
// forced out of IDLE and waited on until it actually reaches READY. gRPC reports
// a handshake failure only as a channel state, so the error of the last
// handshake is read from r and wrapped, to say WHY the connection did not come
// up.
func waitForReady(parent context.Context, host string, cc *grpc.ClientConn, budget time.Duration, r *recorder) error {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	cc.Connect()
	for {
		state := cc.GetState()
		if state == connectivity.Ready {
			return nil
		}
		if !cc.WaitForStateChange(ctx, state) {
			if parent.Err() != nil {
				// The caller gave up, cancelled or out of its own deadline,
				// which is not the host's fault.
				return fmt.Errorf("supertls: dial of %s abandoned: %w", host, context.Cause(parent))
			}
			if last := r.last(); last != nil {
				return fmt.Errorf("%w: %s within %s (last state %s): %w", ErrNotReady, host, budget, state, last)
			}
			return fmt.Errorf("%w: %s within %s (last state %s)", ErrNotReady, host, budget, state)
		}
	}
}

// Conn is a connection returned by Dial: a direct connection, or the inner
// connection of a tunnel together with the outer connection carrying it.
type Conn struct {
	cc    *grpc.ClientConn
	outer *grpc.ClientConn
	mode  Mode

	closeOnce sync.Once
	closeErr  error
}

// ClientConn returns the connection to make calls on. For a tunnel it is the
// inner connection, whose session is verified by the caller's credentials.
func (c *Conn) ClientConn() *grpc.ClientConn { return c.cc }

// Mode reports whether this connection is direct or tunnelled.
func (c *Conn) Mode() Mode { return c.mode }

// Close closes the connection, and for a tunnel then the outer connection. It
// is safe to call more than once; later calls return the first call's result.
// It returns the error of closing the inner (or direct) connection.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		if c.cc != nil {
			c.closeErr = c.cc.Close()
		}
		if c.outer != nil {
			c.outer.Close()
		}
	})
	return c.closeErr
}
