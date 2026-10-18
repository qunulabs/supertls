package supertls

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/keepalive"

	"github.com/qunulabs/supertls/tunnelpb"
)

func TestOptionsDefaults(t *testing.T) {
	t.Parallel()
	c, err := newConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.logger != slog.Default() {
		t.Error("logger is not slog.Default()")
	}
	if c.serviceName != DefaultServiceName {
		t.Errorf("serviceName = %q", c.serviceName)
	}
	if c.directBudget != 5*time.Second || c.tunnelBudget != 20*time.Second ||
		c.tunnelTTL != time.Hour || c.probeTimeout != DefaultProbeTimeout {
		t.Errorf("timings drifted: %v %v %v %v", c.directBudget, c.tunnelBudget, c.tunnelTTL, c.probeTimeout)
	}
	if c.windows != DefaultWindows() {
		t.Errorf("windows = %+v", c.windows)
	}
	if c.innerBackoff != DefaultInnerBackoff() || c.outerBackoff != DefaultOuterBackoff() ||
		c.outerKeepalive != DefaultOuterKeepalive() {
		t.Errorf("backoff or keepalive not defaulted: %+v %+v %+v", c.innerBackoff, c.outerBackoff, c.outerKeepalive)
	}
	if c.onModeChange != nil || len(c.directOpts) != 0 || len(c.outerOpts) != 0 {
		t.Error("hook and dial options must default to empty")
	}
	if DefaultOuterMinConnectTimeout != 20*time.Second {
		t.Errorf("DefaultOuterMinConnectTimeout = %v", DefaultOuterMinConnectTimeout)
	}
	wantInner := backoff.Config{BaseDelay: 500 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 15 * time.Second}
	wantOuter := backoff.Config{BaseDelay: time.Second, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 60 * time.Second}
	if DefaultInnerBackoff() != wantInner || DefaultOuterBackoff() != wantOuter {
		t.Errorf("backoff defaults drifted: %+v %+v", DefaultInnerBackoff(), DefaultOuterBackoff())
	}
	k := DefaultOuterKeepalive()
	if k.Time != 30*time.Second || k.Timeout != 20*time.Second || !k.PermitWithoutStream {
		t.Errorf("keepalive drifted: %+v", k)
	}
}

func TestOptionsRejectInvalid(t *testing.T) {
	t.Parallel()
	badWindows := DefaultWindows()
	badWindows.OuterStream, badWindows.InnerConn = MinWindow, 2*MinWindow
	cases := []struct {
		name string
		opt  Option
		want error
	}{
		{"nil logger", WithLogger(nil), ErrInvalidOption},
		{"empty service name", WithServiceName(""), ErrInvalidOption},
		{"slash service name", WithServiceName("a/b"), ErrInvalidOption},
		{"double dot service name", WithServiceName("a..b"), ErrInvalidOption},
		{"leading digit service name", WithServiceName("1a.b"), ErrInvalidOption},
		{"direct budget zero", WithDirectDialBudget(0), ErrInvalidOption},
		{"direct budget negative", WithDirectDialBudget(-time.Second), ErrInvalidOption},
		{"tunnel budget zero", WithTunnelDialBudget(0), ErrInvalidOption},
		{"probe timeout negative", WithProbeTimeout(-1), ErrInvalidOption},
		{"tunnel ttl zero", WithTunnelModeTTL(0), ErrInvalidOption},
		{"backoff max zero", WithInnerBackoff(backoff.Config{BaseDelay: time.Second}), ErrInvalidOption},
		{"backoff max negative", WithInnerBackoff(backoff.Config{MaxDelay: -time.Second}), ErrInvalidOption},
		{"windows invariant", WithWindows(badWindows), ErrWindowInvariant},
		{"windows too small", WithWindows(Windows{}), ErrInvalidOption},
		{"nil direct option", WithDirectDialOptions(nil), ErrInvalidOption},
		{"nil outer option", WithOuterDialOptions(grpc.WithUserAgent("x"), nil), ErrInvalidOption},
		{"nil Option", nil, ErrInvalidOption},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := newConfig([]Option{tc.opt}); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestOptionsAcceptSentinelServiceName(t *testing.T) {
	t.Parallel()
	c, err := newConfig([]Option{WithServiceName("sentinel.tunnel.v1.TunnelService")})
	if err != nil {
		t.Fatal(err)
	}
	if c.serviceName != "sentinel.tunnel.v1.TunnelService" {
		t.Fatalf("serviceName = %q", c.serviceName)
	}
	if _, err := newConfig([]Option{WithServiceName("Single")}); err != nil {
		t.Error("a single identifier is a valid service name")
	}
}

func TestDefaultServiceNameMatchesGenerated(t *testing.T) {
	t.Parallel()
	if DefaultServiceName != tunnelpb.TunnelService_ServiceDesc.ServiceName {
		t.Fatalf("DefaultServiceName = %q, generated = %q", DefaultServiceName, tunnelpb.TunnelService_ServiceDesc.ServiceName)
	}
}

func TestOptionsApplyInOrderAndValidWindowsPass(t *testing.T) {
	t.Parallel()
	w := Windows{OuterStream: 2 << 20, OuterConn: 4 << 20, InnerStream: 1 << 20, InnerConn: 2 << 20, Buffer: 32 << 10}
	hook := func(ModeChange) {}
	c, err := newConfig([]Option{
		WithDirectDialBudget(time.Second),
		WithDirectDialBudget(2 * time.Second),
		WithWindows(w),
		WithOnModeChange(hook),
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.directBudget != 2*time.Second || c.windows != w || c.onModeChange == nil {
		t.Fatalf("options not applied: %+v", c)
	}
}

// The outer channel is permissive by design, so nothing supplied for the direct
// channel may land in its option list, and the reverse.
func TestDialOptionListsStaySeparate(t *testing.T) {
	t.Parallel()
	d := grpc.WithUserAgent("direct")
	o := grpc.WithUserAgent("outer")
	c, err := newConfig([]Option{WithDirectDialOptions(d), WithOuterDialOptions(o)})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.directOpts) != 1 || len(c.outerOpts) != 1 {
		t.Fatalf("directOpts=%d outerOpts=%d, want 1 each", len(c.directOpts), len(c.outerOpts))
	}
}

// The defaults are functions returning a fresh copy, so changing one value a
// caller holds can never move another Dialer.
func TestDefaultsAreCopies(t *testing.T) {
	t.Parallel()
	b := DefaultOuterBackoff()
	b.MaxDelay = time.Millisecond
	k := DefaultOuterKeepalive()
	k.Time = time.Millisecond
	i := DefaultInnerBackoff()
	i.MaxDelay = time.Millisecond
	if DefaultOuterBackoff().MaxDelay != 60*time.Second || DefaultOuterKeepalive().Time != 30*time.Second ||
		DefaultInnerBackoff().MaxDelay != 15*time.Second {
		t.Fatal("a default changed after a returned copy was modified")
	}
}

func TestOuterOptionsApply(t *testing.T) {
	t.Parallel()
	b := backoff.Config{BaseDelay: time.Millisecond, Multiplier: 1, MaxDelay: time.Second}
	k := keepalive.ClientParameters{Time: time.Minute, Timeout: time.Second}
	c, err := newConfig([]Option{WithOuterBackoff(b), WithOuterKeepalive(k)})
	if err != nil {
		t.Fatal(err)
	}
	if c.outerBackoff != b || c.outerKeepalive != k {
		t.Fatalf("outer options not applied: %+v %+v", c.outerBackoff, c.outerKeepalive)
	}
}

func TestBackoffValidation(t *testing.T) {
	t.Parallel()
	good := DefaultInnerBackoff()
	with := func(f func(*backoff.Config)) backoff.Config {
		b := good
		f(&b)
		return b
	}
	cases := []struct {
		name string
		b    backoff.Config
		ok   bool
	}{
		{"default", good, true},
		{"zero base", with(func(b *backoff.Config) { b.BaseDelay = 0 }), true},
		{"multiplier one", with(func(b *backoff.Config) { b.Multiplier = 1 }), true},
		{"jitter zero", with(func(b *backoff.Config) { b.Jitter = 0 }), true},
		{"jitter one", with(func(b *backoff.Config) { b.Jitter = 1 }), true},
		{"max below base", with(func(b *backoff.Config) { b.MaxDelay = time.Millisecond }), true},
		{"negative base", with(func(b *backoff.Config) { b.BaseDelay = -1 }), false},
		{"zero max", with(func(b *backoff.Config) { b.MaxDelay = 0 }), false},
		{"negative max", with(func(b *backoff.Config) { b.MaxDelay = -time.Second }), false},
		{"multiplier below one", with(func(b *backoff.Config) { b.Multiplier = 0.9 }), false},
		{"multiplier zero", with(func(b *backoff.Config) { b.Multiplier = 0 }), false},
		{"multiplier NaN", with(func(b *backoff.Config) { b.Multiplier = math.NaN() }), false},
		{"jitter negative", with(func(b *backoff.Config) { b.Jitter = -0.1 }), false},
		{"jitter above one", with(func(b *backoff.Config) { b.Jitter = 1.1 }), false},
		{"jitter NaN", with(func(b *backoff.Config) { b.Jitter = math.NaN() }), false},
	}
	for _, tc := range cases {
		for name, opt := range map[string]func(backoff.Config) Option{"inner": WithInnerBackoff, "outer": WithOuterBackoff} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				_, err := newConfig([]Option{opt(tc.b)})
				if tc.ok && err != nil {
					t.Fatalf("refused a valid backoff: %v", err)
				}
				if !tc.ok && !errors.Is(err, ErrInvalidOption) {
					t.Fatalf("err = %v, want ErrInvalidOption", err)
				}
			})
		}
	}
}

func TestOuterKeepaliveValidation(t *testing.T) {
	t.Parallel()
	for _, k := range []keepalive.ClientParameters{
		{Time: 0, Timeout: time.Second},
		{Time: time.Minute, Timeout: 0},
		{Time: -time.Second, Timeout: time.Second},
		{Time: time.Minute, Timeout: -time.Second},
	} {
		if _, err := newConfig([]Option{WithOuterKeepalive(k)}); !errors.Is(err, ErrInvalidOption) {
			t.Errorf("WithOuterKeepalive(%+v): err = %v, want ErrInvalidOption", k, err)
		}
	}
}

// Two Dialers with different outer backoffs, dialling at the same time, each
// reconnect on their own schedule. Before the backoff was snapshotted per
// Dialer it was a package variable read on every dial, so one caller's
// assignment moved every Dialer and raced their dials. Run with -race.
func TestOuterBackoffIsPerDialer(t *testing.T) {
	t.Parallel()
	run := func(b backoff.Config) (*Dialer, *atomic.Int32) {
		var n atomic.Int32
		dialer := func(context.Context, string) (net.Conn, error) {
			n.Add(1)
			return nil, errors.New("refused by the test dialer")
		}
		d, err := NewDialer(testTrust(), WithOuterBackoff(b), WithOuterDialOptions(grpc.WithContextDialer(dialer)))
		if err != nil {
			t.Fatal(err)
		}
		return d, &n
	}
	fast := backoff.Config{BaseDelay: 10 * time.Millisecond, Multiplier: 1, MaxDelay: 10 * time.Millisecond}
	slow := backoff.Config{BaseDelay: time.Hour, Multiplier: 1, MaxDelay: time.Hour}
	dFast, nFast := run(fast)
	dSlow, nSlow := run(slow)

	var wg sync.WaitGroup
	for _, d := range []*Dialer{dFast, dSlow} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cc, err := d.newOuterConn("127.0.0.1:1")
			if err != nil {
				t.Error(err)
				return
			}
			defer cc.Close()
			cc.Connect()
			time.Sleep(500 * time.Millisecond)
		}()
	}
	wg.Wait()
	if got := nFast.Load(); got < 5 {
		t.Errorf("fast Dialer made %d outer attempts in 500ms, want at least 5", got)
	}
	if got := nSlow.Load(); got != 1 {
		t.Errorf("slow Dialer made %d outer attempts in 500ms, want exactly 1", got)
	}
	if dFast.cfg.outerBackoff != fast || dSlow.cfg.outerBackoff != slow {
		t.Error("a Dialer's outer backoff changed after construction")
	}
}
