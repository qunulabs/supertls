package supertls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/local"

	"github.com/qunulabs/supertls/internal/testpki"
)

// captureHandler is an slog.Handler that keeps every record.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r.Clone())
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) warns() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.records {
		if r.Level == slog.LevelWarn {
			out = append(out, r)
		}
	}
	return out
}

func attrs(r slog.Record) map[string]slog.Value {
	m := map[string]slog.Value{}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value
		return true
	})
	return m
}

// hookLog records every ModeChange the hook receives.
type hookLog struct {
	mu      sync.Mutex
	changes []ModeChange
}

func (h *hookLog) hook(c ModeChange) {
	h.mu.Lock()
	h.changes = append(h.changes, c)
	h.mu.Unlock()
}

func (h *hookLog) all() []ModeChange {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]ModeChange(nil), h.changes...)
}

// fakeDial is a seam harness: counters on each seam and a scripted outcome.
type fakeDial struct {
	d     *Dialer
	clock *fakeClock
	logs  *captureHandler
	hooks *hookLog

	directN, probeN, tunnelN atomic.Int32

	mu        sync.Mutex
	directErr error
	verdict   Verdict
	probeErr  error
	tunnelErr error
}

var (
	errDirect = errors.New("direct: tls: failed to verify certificate")
	errTunnel = errors.New("tunnel: rpc error: code = Unimplemented")
)

func testTrust() Trust { return TrustPool(x509.NewCertPool()) }

func testCreds() credentials.TransportCredentials { return credentials.NewTLS(&tls.Config{}) }

func newFakeDial(t *testing.T) *fakeDial {
	t.Helper()
	f := &fakeDial{
		clock: &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		logs:  &captureHandler{},
		hooks: &hookLog{},
	}
	d, err := NewDialer(testTrust(), WithLogger(slog.New(f.logs)), WithOnModeChange(f.hooks.hook))
	if err != nil {
		t.Fatal(err)
	}
	d.now = f.clock.now
	d.directFn = func(context.Context, string, credentials.TransportCredentials, []grpc.DialOption) (*Conn, error) {
		f.directN.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.directErr != nil {
			return nil, f.directErr
		}
		return &Conn{mode: ModeDirect}, nil
	}
	d.probeFn = func(context.Context, string) (Verdict, error) {
		f.probeN.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.verdict, f.probeErr
	}
	d.tunnelFn = func(context.Context, string, credentials.TransportCredentials, []grpc.DialOption) (*Conn, error) {
		f.tunnelN.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.tunnelErr != nil {
			return nil, f.tunnelErr
		}
		return &Conn{mode: ModeTunnel}, nil
	}
	f.d = d
	return f
}

func (f *fakeDial) script(directErr error, v Verdict, probeErr, tunnelErr error) {
	f.mu.Lock()
	f.directErr, f.verdict, f.probeErr, f.tunnelErr = directErr, v, probeErr, tunnelErr
	f.mu.Unlock()
}

func (f *fakeDial) dial(t *testing.T, host string) (*Conn, error) {
	t.Helper()
	return f.d.Dial(context.Background(), host, testCreds())
}

func (f *fakeDial) counts() (direct, probe, tunnel int32) {
	return f.directN.Load(), f.probeN.Load(), f.tunnelN.Load()
}

func TestDialCleanDirectNeverProbes(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	c, err := f.dial(t, "a:1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode() != ModeDirect {
		t.Fatalf("Mode() = %s, want direct", c.Mode())
	}
	if _, p, tu := f.counts(); p != 0 || tu != 0 {
		t.Fatalf("probe=%d tunnel=%d, want 0 and 0", p, tu)
	}
}

func TestDialGenuineNeverTunnels(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictGenuine, nil, nil)
	_, err := f.dial(t, "a:1")
	if _, _, tu := f.counts(); tu != 0 {
		t.Fatalf("tunnel called %d times for a genuine peer", tu)
	}
	var de *DialError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want a *DialError", err)
	}
	if de.Verdict != VerdictGenuine || de.Tunnel != nil {
		t.Fatalf("DialError = %+v, want genuine with no tunnel error", de)
	}
	if !errors.Is(err, errDirect) {
		t.Fatalf("errors.Is(err, errDirect) is false: %v", err)
	}
	if !strings.Contains(err.Error(), "genuine") {
		t.Fatalf("err %q does not name the genuine verdict", err)
	}
	if !strings.Contains(err.Error(), "trusted roots") || !strings.Contains(err.Error(), "not interception") {
		t.Fatalf("err %q does not say the peer was genuine", err)
	}
	if !strings.Contains(err.Error(), errDirect.Error()) {
		t.Fatalf("err %q does not carry the direct error", err)
	}
	if f.d.Mode("a:1") != ModeUnknown {
		t.Fatalf("Mode = %s, want unknown", f.d.Mode("a:1"))
	}
}

func testTunnels(t *testing.T, v Verdict) {
	t.Helper()
	f := newFakeDial(t)
	f.script(errDirect, v, errors.New("evidence"), nil)
	c, err := f.dial(t, "a:1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode() != ModeTunnel {
		t.Fatalf("returned conn is %s, want the tunnel one", c.Mode())
	}
	if f.d.Mode("a:1") != ModeTunnel {
		t.Fatalf("d.Mode = %s, want tunnel", f.d.Mode("a:1"))
	}
}

func TestDialInterceptedTunnels(t *testing.T) {
	t.Parallel()
	testTunnels(t, VerdictIntercepted)
}

func TestDialInconclusiveTunnels(t *testing.T) {
	t.Parallel()
	testTunnels(t, VerdictInconclusive)
}

func TestDialTunnelFailureReturnsOriginalDirectError(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictInconclusive, nil, errTunnel)
	_, err := f.dial(t, "a:1")
	if !errors.Is(err, errDirect) || !errors.Is(err, errTunnel) {
		t.Fatalf("err = %v, want both errDirect and errTunnel to match", err)
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "supertls: direct dial of ") {
		t.Fatalf("err %q does not lead with the direct dial", msg)
	}
	di, ti := strings.Index(msg, errDirect.Error()), strings.Index(msg, errTunnel.Error())
	if di < 0 || ti < 0 || di > ti {
		t.Fatalf("err %q: want the direct error before the tunnel error", msg)
	}
	if f.d.Mode("a:1") != ModeUnknown {
		t.Fatalf("Mode = %s after a failed tunnel, want unknown", f.d.Mode("a:1"))
	}
	if len(f.hooks.all()) != 0 || len(f.logs.warns()) != 0 {
		t.Fatal("a failed tunnel must neither log a switch nor call the hook")
	}
}

func TestDialCachedTunnelSkipsDirectAndProbe(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictIntercepted, nil, nil)
	if _, err := f.dial(t, "a:1"); err != nil {
		t.Fatal(err)
	}
	d0, p0, _ := f.counts()
	c, err := f.dial(t, "a:1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode() != ModeTunnel {
		t.Fatalf("Mode() = %s, want tunnel", c.Mode())
	}
	if d1, p1, _ := f.counts(); d1 != d0 || p1 != p0 {
		t.Fatalf("direct %d->%d, probe %d->%d: a cached tunnel must skip both", d0, d1, p0, p1)
	}
}

func TestDialCachedTunnelFailureIsWrapped(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictIntercepted, nil, nil)
	if _, err := f.dial(t, "a:1"); err != nil {
		t.Fatal(err)
	}
	f.script(errDirect, VerdictIntercepted, nil, errTunnel)
	_, err := f.dial(t, "a:1")
	if !errors.Is(err, errTunnel) || !strings.Contains(err.Error(), "tunnelled dial of a:1") {
		t.Fatalf("err = %v, want the tunnel error wrapped with the host", err)
	}
}

func TestDialExpiredTunnelTriesDirectFirst(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictIntercepted, nil, nil)
	if _, err := f.dial(t, "a:1"); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(DefaultTunnelModeTTL + time.Second)
	f.script(nil, VerdictGenuine, nil, nil)
	d0, _, _ := f.counts()
	c, err := f.dial(t, "a:1")
	if err != nil {
		t.Fatal(err)
	}
	if d1, _, _ := f.counts(); d1 != d0+1 {
		t.Fatalf("direct count %d->%d, want one direct attempt after expiry", d0, d1)
	}
	if c.Mode() != ModeDirect || f.d.Mode("a:1") != ModeDirect {
		t.Fatalf("conn %s, cache %s, want direct", c.Mode(), f.d.Mode("a:1"))
	}
	h := f.hooks.all()
	last := h[len(h)-1]
	if last.From != ModeTunnel || last.To != ModeDirect {
		t.Fatalf("last hook %+v, want tunnel -> direct", last)
	}
}

func TestDialAbandonedSkipsProbe(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictIntercepted, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.d.Dial(ctx, "a:1", testCreds())
	if err != errDirect {
		t.Fatalf("err = %v, want the direct error itself", err)
	}
	if _, p, tu := f.counts(); p != 0 || tu != 0 {
		t.Fatalf("probe=%d tunnel=%d after an abandoned dial, want 0 and 0", p, tu)
	}
}

func TestDialLogsSwitchOncePerHost(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictIntercepted, errors.New("foreign"), nil)
	for round := 0; round < 2; round++ {
		for _, h := range []string{"a:1", "b:1"} {
			if _, err := f.dial(t, h); err != nil {
				t.Fatal(err)
			}
		}
		f.clock.advance(DefaultTunnelModeTTL + time.Second)
	}
	if _, _, tu := f.counts(); tu != 4 {
		t.Fatalf("tunnel count %d, want 4 (two hosts, two decisions each)", tu)
	}
	warns := f.logs.warns()
	if len(warns) != 2 {
		t.Fatalf("%d Warn records, want 2 (one per host)", len(warns))
	}
	seen := map[string]bool{}
	for _, r := range warns {
		a := attrs(r)
		for _, k := range []string{"host", "verdict", "err"} {
			if _, ok := a[k]; !ok {
				t.Fatalf("record %q lacks attr %q", r.Message, k)
			}
		}
		if a["verdict"].String() != "intercepted" {
			t.Fatalf("verdict attr %q, want intercepted", a["verdict"])
		}
		if !strings.Contains(r.Message, "interception detected") {
			t.Fatalf("message %q, want the interception wording", r.Message)
		}
		seen[a["host"].String()] = true
	}
	if !seen["a:1"] || !seen["b:1"] {
		t.Fatalf("logged hosts %v, want a:1 and b:1", seen)
	}
}

func TestDialLogsInconclusiveWording(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictInconclusive, errors.New("refused"), nil)
	if _, err := f.dial(t, "a:1"); err != nil {
		t.Fatal(err)
	}
	w := f.logs.warns()
	if len(w) != 1 || !strings.Contains(w[0].Message, "could not tell") {
		t.Fatalf("records %v, want one with the inconclusive wording", w)
	}
}

func TestConcurrentDialsLogOnce(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictIntercepted, errors.New("foreign"), nil)
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, err := f.d.Dial(context.Background(), "a:1", testCreds())
			if err == nil && c.Mode() != ModeTunnel {
				err = errors.New("returned conn is not the tunnel one")
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.logs.warns()); n != 1 {
		t.Fatalf("%d Warn records, want 1", n)
	}
	h := f.hooks.all()
	if len(h) != 1 || h[0].To != ModeTunnel || h[0].From != ModeUnknown {
		t.Fatalf("hook calls %+v, want exactly one unknown -> tunnel", h)
	}
}

func TestOnModeChangeFiresOnTransitionsOnly(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	for i := 0; i < 2; i++ {
		if _, err := f.dial(t, "a:1"); err != nil {
			t.Fatal(err)
		}
	}
	f.script(errDirect, VerdictIntercepted, nil, nil)
	if _, err := f.dial(t, "a:1"); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(DefaultTunnelModeTTL + time.Second)
	if _, err := f.dial(t, "a:1"); err != nil {
		t.Fatal(err)
	}
	h := f.hooks.all()
	want := [][2]Mode{{ModeUnknown, ModeDirect}, {ModeDirect, ModeTunnel}}
	if len(h) != len(want) {
		t.Fatalf("hook calls %+v, want %v", h, want)
	}
	for i, w := range want {
		if h[i].From != w[0] || h[i].To != w[1] || h[i].Host != "a:1" {
			t.Fatalf("hook call %d = %+v, want %s -> %s", i, h[i], w[0], w[1])
		}
	}
	if h[0].Verdict != VerdictGenuine || h[0].Reason != nil {
		t.Fatalf("direct transition %+v, want genuine with no reason", h[0])
	}
}

// Review Focus 3: bad arguments are refused with ErrInvalidOption before any
// seam runs, never a panic inside gRPC.
func TestDialRejectsNilCredentials(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	cases := []struct {
		name  string
		host  string
		creds credentials.TransportCredentials
		extra []grpc.DialOption
	}{
		{"nil creds", "h:1", nil, nil},
		{"empty host", "", testCreds(), nil},
		// Ruling (b): credentials that verify nothing would leave the tunnelled
		// path with no verification at all.
		{"insecure creds", "h:1", insecure.NewCredentials(), nil},
		{"local creds", "h:1", local.NewCredentials(), nil},
		{"scheme in host", "dns:///h:1", testCreds(), nil},
		{"nil extra option", "h:1", testCreds(), []grpc.DialOption{nil}},
	}
	for _, c := range cases {
		_, err := f.d.Dial(context.Background(), c.host, c.creds, c.extra...)
		if !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("%s: err = %v, want ErrInvalidOption", c.name, err)
		}
	}
	if d, p, tu := f.counts(); d+p+tu != 0 {
		t.Fatalf("seams called (direct=%d probe=%d tunnel=%d), want none", d, p, tu)
	}
}

// Ruling (a): a zero or invalid Trust is refused at construction, before any
// network activity, or every failed direct dial would silently tunnel.
func TestNewDialerRejectsZeroTrust(t *testing.T) {
	t.Parallel()
	for name, tr := range map[string]Trust{"zero": {}, "nil pool": TrustPool(nil), "nil pool hostname": TrustPoolWithHostname(nil)} {
		d, err := NewDialer(tr)
		if !errors.Is(err, ErrInvalidOption) || d != nil {
			t.Fatalf("%s: NewDialer = %v, %v; want nil, ErrInvalidOption", name, d, err)
		}
	}
	if _, err := NewDialer(TrustSystemRoots()); err != nil {
		t.Fatalf("TrustSystemRoots refused: %v", err)
	}
}

func TestNewDialerRejectsBadWindows(t *testing.T) {
	t.Parallel()
	w := DefaultWindows()
	w.OuterStream = w.InnerConn / 2
	_, err := NewDialer(testTrust(), WithWindows(w))
	if !errors.Is(err, ErrWindowInvariant) {
		t.Fatalf("err = %v, want ErrWindowInvariant", err)
	}
}

func TestDialErrorWithoutTunnelError(t *testing.T) {
	t.Parallel()
	e := &DialError{Host: "a:1", Direct: errDirect, Verdict: VerdictIntercepted}
	if len(e.Unwrap()) != 1 || !strings.Contains(e.Error(), errDirect.Error()) {
		t.Fatalf("DialError %q unwraps to %v", e, e.Unwrap())
	}
}

// grpcServer serves s on loopback and returns its address.
func grpcServer(t *testing.T, s *grpc.Server) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

func TestOpenStreamUsesServiceNamePath(t *testing.T) {
	t.Parallel()
	got := make(chan string, 1)
	s := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error {
		m, _ := grpc.MethodFromServerStream(ss)
		got <- m
		return nil
	}))
	addr := grpcServer(t, s)
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := openStream(ctx, cc, "custom.v1.Tunnel")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = st.Recv()
	select {
	case m := <-got:
		if m != "/custom.v1.Tunnel/Open" {
			t.Fatalf("method %q, want /custom.v1.Tunnel/Open", m)
		}
	case <-ctx.Done():
		t.Fatal("server never saw the stream")
	}
}

// Review Focus 5.
func TestConnCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	addr := grpcServer(t, grpc.NewServer())
	mk := func() *grpc.ClientConn {
		cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		cc.Connect()
		return cc
	}
	inner, outer := mk(), mk()
	c := &Conn{cc: inner, outer: outer, mode: ModeTunnel}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if s := outer.GetState(); s != connectivity.Shutdown {
		t.Fatalf("outer state %s after Close, want Shutdown", s)
	}
	if s := inner.GetState(); s != connectivity.Shutdown {
		t.Fatalf("inner state %s after Close, want Shutdown", s)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := (&Conn{}).Close(); err != nil {
		t.Fatalf("Close of an empty Conn: %v", err)
	}
}

func TestWaitForReadyReportsHandshakeError(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	addr := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{p.Proxy}, MinVersion: tls.VersionTLS12})
	rec := &recorder{}
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(recording(strictCreds(p), rec)))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	err = waitForReady(context.Background(), addr, cc, 2*time.Second, rec)
	if !errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want ErrNotReady naming the certificate", err)
	}
}

func TestWaitForReadyAbandoned(t *testing.T) {
	t.Parallel()
	cc, err := grpc.NewClient(closedPort(t), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = waitForReady(ctx, "h:1", cc, time.Second, &recorder{})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "abandoned") {
		t.Fatalf("err = %v, want an abandoned dial", err)
	}
}

func closedPort(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	lis.Close()
	return addr
}

// countingCreds counts client handshakes, so a test can tell whether these
// credentials were the ones gRPC used.
type countingCreds struct {
	credentials.TransportCredentials
	n *atomic.Int32
}

func (c countingCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	c.n.Add(1)
	return c.TransportCredentials.ClientHandshake(ctx, authority, raw)
}

func (c countingCreds) Clone() credentials.TransportCredentials {
	return countingCreds{TransportCredentials: c.TransportCredentials.Clone(), n: c.n}
}

// countingDialer is a context dialer that counts its calls and dials TCP.
func countingDialer(n *atomic.Int32) grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	})
}

// Ruling (c): the caller's inner credentials are applied after the direct
// options and after extra, so a stray WithTransportCredentials in either cannot
// replace them.
func TestDirectOptionsCannotReplaceInnerCredentials(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	addr := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{p.Proxy}, MinVersion: tls.VersionTLS12})
	stray := grpc.WithTransportCredentials(insecure.NewCredentials())
	d, err := NewDialer(testTrust(), WithDirectDialOptions(stray), WithDirectDialBudget(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	inner := countingCreds{TransportCredentials: strictCreds(p), n: &n}
	_, err = d.directFn(context.Background(), addr, inner, []grpc.DialOption{stray})
	if n.Load() == 0 {
		t.Fatal("the inner credentials were never used: a stray option replaced them")
	}
	if !errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want the inner credentials' certificate failure", err)
	}
}

// Ruling (c): direct options reach only the direct connection, outer options
// only the outer one, and extra can neither reach the outer connection nor
// reroute the inner one around the tunnel.
func TestDialOptionsReachOnlyTheirConnection(t *testing.T) {
	t.Parallel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := lis.Addr().String()

	var directN, outerN, extraN atomic.Int32
	d, err := NewDialer(testTrust(),
		WithDirectDialOptions(countingDialer(&directN)),
		WithOuterDialOptions(countingDialer(&outerN)),
		WithDirectDialBudget(time.Second),
		WithTunnelDialBudget(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := d.directFn(context.Background(), addr, testCreds(), nil); err == nil {
		t.Fatal("direct dial to a closing listener succeeded")
	}
	if directN.Load() == 0 || outerN.Load() != 0 {
		t.Fatalf("direct dial: direct dialer %d, outer dialer %d; want >0 and 0", directN.Load(), outerN.Load())
	}

	directN.Store(0)
	extra := []grpc.DialOption{countingDialer(&extraN), grpc.WithTransportCredentials(insecure.NewCredentials())}
	if _, err := d.tunnelFn(context.Background(), addr, testCreds(), extra); err == nil {
		t.Fatal("tunnelled dial to a closing listener succeeded")
	}
	if outerN.Load() == 0 {
		t.Fatal("tunnelled dial: the outer dialer was never used")
	}
	if directN.Load() != 0 {
		t.Fatalf("tunnelled dial used the direct dialer %d times", directN.Load())
	}
	if extraN.Load() != 0 {
		t.Fatalf("extra's dialer ran %d times: the inner connection was routed around the tunnel", extraN.Load())
	}
}

// Ruling (d): each dial has its own handshake recorder, so a concurrent dial to
// another host cannot lend its failure to this one.
func TestRecorderIsPerDial(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	foreign := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{p.Proxy}, MinVersion: tls.VersionTLS12})
	closed := closedPort(t)
	d, err := NewDialer(testTrust(), WithDirectDialBudget(1500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var foreignErr, closedErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, foreignErr = d.directFn(context.Background(), foreign, strictCreds(p), nil)
	}()
	go func() {
		defer wg.Done()
		_, closedErr = d.directFn(context.Background(), closed, strictCreds(p), nil)
	}()
	wg.Wait()
	if foreignErr == nil || !strings.Contains(foreignErr.Error(), "certificate") {
		t.Fatalf("foreign host: err = %v, want a certificate failure", foreignErr)
	}
	if closedErr == nil || strings.Contains(closedErr.Error(), "certificate") {
		t.Fatalf("closed port: err = %v, want a failure that does not borrow the other host's certificate error", closedErr)
	}
}

// Ruling (c), tunnelled side: a WithTransportCredentials in extra is overridden
// on the inner connection of a tunnel too. The outer server accepts the tunnel
// stream and holds it open, so the inner connection reaches its handshake; the
// caller's credentials must be the ones that run it.
func TestExtraCannotReplaceInnerCredentialsInTunnel(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{p.Server}, MinVersion: tls.VersionTLS12}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)),
		grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error {
			<-ss.Context().Done()
			return nil
		}))
	addr := grpcServer(t, s)
	d, err := NewDialer(testTrust(), WithTunnelDialBudget(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	inner := countingCreds{TransportCredentials: strictCreds(p), n: &n}
	extra := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if c, err := d.tunnelFn(context.Background(), addr, inner, extra); err == nil {
		c.Close()
		t.Fatal("tunnelled dial to a server that never answers inside the tunnel succeeded")
	}
	if n.Load() == 0 {
		t.Fatal("the inner credentials were never used: extra replaced them on the tunnelled connection")
	}
}

// "example.com" and "example.com:443" are one host to gRPC, so they must be one
// entry in the mode cache, one log line and one hook call.
func TestModeCacheNormalisesTheDefaultPort(t *testing.T) {
	t.Parallel()
	f := newFakeDial(t)
	f.script(errDirect, VerdictIntercepted, nil, nil)
	if _, err := f.dial(t, "example.com"); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"example.com", "example.com:443"} {
		if m := f.d.Mode(h); m != ModeTunnel {
			t.Fatalf("Mode(%q) = %s, want tunnel", h, m)
		}
	}
	if m := f.d.Mode("example.com:8443"); m != ModeUnknown {
		t.Fatalf("Mode on another port = %s, want unknown", m)
	}
	// The second spelling goes straight to the tunnel: no direct dial, no probe.
	if _, err := f.dial(t, "example.com:443"); err != nil {
		t.Fatal(err)
	}
	if d, p, tu := f.counts(); d != 1 || p != 1 || tu != 2 {
		t.Fatalf("direct=%d probe=%d tunnel=%d, want 1, 1 and 2", d, p, tu)
	}
	h := f.hooks.all()
	if len(h) != 1 || h[0].Host != "example.com:443" {
		t.Fatalf("hook calls = %+v, want one for example.com:443", h)
	}
	if n := len(f.logs.warns()); n != 1 {
		t.Fatalf("%d tunnel log lines, want 1", n)
	}

	// An IPv6 literal without a port is normalised too.
	g := newFakeDial(t)
	if _, err := g.dial(t, "::1"); err != nil {
		t.Fatal(err)
	}
	if m := g.d.Mode("[::1]:443"); m != ModeDirect {
		t.Fatalf("Mode([::1]:443) = %s, want direct", m)
	}
}
