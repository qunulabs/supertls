package supertls

import (
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/keepalive"
)

// Timing defaults.
const (
	// DefaultDirectDialBudget bounds one direct dial. The direct path's timing
	// is deliberately shorter than the tunnel's and must not creep.
	DefaultDirectDialBudget = 5 * time.Second

	// DefaultTunnelDialBudget bounds a tunnelled dial. It is deliberately larger
	// than the direct budget: a tunnelled dial nests a second TLS 1.3 handshake
	// and a second HTTP/2 preface inside the first, so it costs three to four
	// round trips where a direct dial costs two. It is also the inner
	// connection's minimum connect timeout, which must exceed opening the outer
	// stream plus a nested hybrid handshake or a merely slow setup is scored as
	// a failure.
	DefaultTunnelDialBudget = 20 * time.Second

	// DefaultTunnelModeTTL is declared beside Mode: how long a tunnel decision
	// holds before the direct path is tried again.

	// DefaultServiceName is the full name of the tunnel gRPC service. Client and
	// server must agree on it; see WithServiceName.
	DefaultServiceName = "supertls.v1.TunnelService"

	// DefaultOuterMinConnectTimeout is the outer connection's minimum connect
	// timeout.
	DefaultOuterMinConnectTimeout = 20 * time.Second
)

// DefaultInnerBackoff is the inner connection's reconnect backoff. The ceiling
// is short on purpose. If a proxy kills the tunnel every few seconds, gRPC's
// default two-minute backoff would leave the connection down more than up.
var DefaultInnerBackoff = backoff.Config{
	BaseDelay:  500 * time.Millisecond,
	Multiplier: 1.6,
	Jitter:     0.2,
	MaxDelay:   15 * time.Second,
}

// DefaultOuterBackoff is the outer connection's reconnect backoff. The outer
// connection is the one that reaches the network, so it takes a 60-second cap;
// left at gRPC's default of two minutes it would hold a tunnelled client out for
// that long after the server returns, and a fleet would come back together
// rather than spread out. BaseDelay and Multiplier are gRPC's defaults, stated
// so the whole schedule is in one place. The inner connection keeps its own
// shorter cap, which is already inside this one.
var DefaultOuterBackoff = backoff.Config{
	BaseDelay:  time.Second,
	Multiplier: 1.6,
	Jitter:     0.2,
	MaxDelay:   60 * time.Second,
}

// DefaultOuterKeepalive pings every 30 seconds, stream or no stream, and gives
// up on a peer that has not answered in 20. That turns a dead outer connection
// into a transport failure within about a minute, and it keeps the connection
// warm so a proxy never reaps it for idleness between calls. A server whose
// enforcement policy permits pings down to 5 seconds without a stream never
// strikes it.
var DefaultOuterKeepalive = keepalive.ClientParameters{
	Time:                30 * time.Second,
	Timeout:             20 * time.Second,
	PermitWithoutStream: true,
}

// config is the resolved client configuration. It carries only what an Option
// can set: the Trust and the inner credentials are parameters of Dial itself,
// never options, so they cannot be left out.
//
// directOpts and outerOpts are kept apart on purpose. The outer connection is
// permissive and unverified by design, so nothing a caller supplies for the
// direct (verified) channel may ever reach it.
type config struct {
	logger       *slog.Logger
	serviceName  string
	onModeChange func(ModeChange)

	directBudget, tunnelBudget, probeTimeout, tunnelTTL time.Duration

	windows Windows

	directOpts, outerOpts []grpc.DialOption
	innerBackoff          backoff.Config
}

// Option configures a client.
type Option func(*config) error

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOption, fmt.Sprintf(format, args...))
}

// newConfig applies the defaults, then the options in order, then validates the
// windows as a whole.
func newConfig(opts []Option) (config, error) {
	c := config{
		logger:       slog.Default(),
		serviceName:  DefaultServiceName,
		directBudget: DefaultDirectDialBudget,
		tunnelBudget: DefaultTunnelDialBudget,
		probeTimeout: DefaultProbeTimeout,
		tunnelTTL:    DefaultTunnelModeTTL,
		windows:      DefaultWindows(),
		innerBackoff: DefaultInnerBackoff,
	}
	for _, o := range opts {
		if o == nil {
			return config{}, invalid("nil Option")
		}
		if err := o(&c); err != nil {
			return config{}, err
		}
	}
	if err := c.windows.Validate(); err != nil {
		return config{}, err
	}
	return c, nil
}

// WithLogger sets the logger. The default is slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(c *config) error {
		if l == nil {
			return invalid("WithLogger: nil logger")
		}
		c.logger = l
		return nil
	}
}

// serviceNameRE is a dotted sequence of identifiers, the shape of a protobuf
// full service name.
var serviceNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

func validServiceName(name string) bool { return serviceNameRE.MatchString(name) }

// WithServiceName sets the full gRPC service name the tunnel is served under,
// for a deployment that must keep an existing name on the wire. The server must
// be configured with the same name. The default is DefaultServiceName.
func WithServiceName(name string) Option {
	return func(c *config) error {
		if !validServiceName(name) {
			return invalid("WithServiceName: %q is not a dotted identifier such as pkg.v1.Service", name)
		}
		c.serviceName = name
		return nil
	}
}

// WithOnModeChange installs a hook called when a host's mode changes. It runs
// on the dialling goroutine, so it must not block. nil removes the hook.
func WithOnModeChange(f func(ModeChange)) Option {
	return func(c *config) error {
		c.onModeChange = f
		return nil
	}
}

func positive(name string, d time.Duration, dst *time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return invalid("%s: %s is not positive", name, d)
		}
		*dst = d
		return nil
	}
}

// WithDirectDialBudget bounds one direct dial. The default is
// DefaultDirectDialBudget.
func WithDirectDialBudget(d time.Duration) Option {
	return func(c *config) error { return positive("WithDirectDialBudget", d, &c.directBudget)(c) }
}

// WithTunnelDialBudget bounds one tunnelled dial. The default is
// DefaultTunnelDialBudget.
func WithTunnelDialBudget(d time.Duration) Option {
	return func(c *config) error { return positive("WithTunnelDialBudget", d, &c.tunnelBudget)(c) }
}

// WithProbeTimeout bounds one interception probe. The default is
// DefaultProbeTimeout.
func WithProbeTimeout(d time.Duration) Option {
	return func(c *config) error { return positive("WithProbeTimeout", d, &c.probeTimeout)(c) }
}

// WithTunnelModeTTL sets how long a tunnel decision holds before the direct path
// is tried again. The default is DefaultTunnelModeTTL.
func WithTunnelModeTTL(d time.Duration) Option {
	return func(c *config) error { return positive("WithTunnelModeTTL", d, &c.tunnelTTL)(c) }
}

// WithWindows sets the flow-control windows. The windows are validated as a
// whole when the client is built: an outer stream window smaller than the inner
// connection window is refused with ErrWindowInvariant.
func WithWindows(w Windows) Option {
	return func(c *config) error {
		c.windows = w
		return nil
	}
}

func checkDialOptions(name string, opts []grpc.DialOption) error {
	for i, o := range opts {
		if o == nil {
			return invalid("%s: option %d is nil", name, i)
		}
	}
	return nil
}

// WithDirectDialOptions adds gRPC dial options to the DIRECT connection only.
// They are never applied to the outer connection of a tunnel.
func WithDirectDialOptions(opts ...grpc.DialOption) Option {
	return func(c *config) error {
		if err := checkDialOptions("WithDirectDialOptions", opts); err != nil {
			return err
		}
		c.directOpts = append(c.directOpts, opts...)
		return nil
	}
}

// WithOuterDialOptions adds gRPC dial options to the OUTER connection of a
// tunnel only, for example a proxy-aware dialer or a different keepalive. They
// are applied after the library's own and so take precedence. They are never
// applied to the direct connection.
//
// They must NEVER carry per-RPC credentials (grpc.WithPerRPCCredentials, or a
// call option or interceptor that attaches a token). The outer connection
// reports PrivacyAndIntegrity to gRPC while verifying nothing, so gRPC would
// hand the token to whoever terminates it, an inspecting proxy included.
// Per-RPC credentials belong on the inner connection, through the extra options
// of Dial, where the caller's own credentials verify the peer.
func WithOuterDialOptions(opts ...grpc.DialOption) Option {
	return func(c *config) error {
		if err := checkDialOptions("WithOuterDialOptions", opts); err != nil {
			return err
		}
		c.outerOpts = append(c.outerOpts, opts...)
		return nil
	}
}

// WithInnerBackoff sets the inner connection's reconnect backoff. The default
// is DefaultInnerBackoff.
func WithInnerBackoff(b backoff.Config) Option {
	return func(c *config) error {
		if b.MaxDelay <= 0 {
			return invalid("WithInnerBackoff: MaxDelay %s is not positive", b.MaxDelay)
		}
		c.innerBackoff = b
		return nil
	}
}
