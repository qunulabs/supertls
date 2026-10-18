package supertls

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"

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
	if c.innerBackoff != DefaultInnerBackoff {
		t.Errorf("innerBackoff = %+v", c.innerBackoff)
	}
	if c.onModeChange != nil || len(c.directOpts) != 0 || len(c.outerOpts) != 0 {
		t.Error("hook and dial options must default to empty")
	}
	if DefaultOuterMinConnectTimeout != 20*time.Second {
		t.Errorf("DefaultOuterMinConnectTimeout = %v", DefaultOuterMinConnectTimeout)
	}
	wantInner := backoff.Config{BaseDelay: 500 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 15 * time.Second}
	wantOuter := backoff.Config{BaseDelay: time.Second, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 60 * time.Second}
	if DefaultInnerBackoff != wantInner || DefaultOuterBackoff != wantOuter {
		t.Errorf("backoff defaults drifted: %+v %+v", DefaultInnerBackoff, DefaultOuterBackoff)
	}
	k := DefaultOuterKeepalive
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
	if !validServiceName("Single") {
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
