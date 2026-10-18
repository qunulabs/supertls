package supertls_test

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qunulabs/supertls"
	"github.com/qunulabs/supertls/internal/testpki"
)

// net/http reads the proxy environment once per process and never proxies
// loopback names, so each explicit-proxy test runs in a child process and
// targets origin.supertls.test, a name only the fake proxy can resolve.

const proxyChildEnv = "SUPERTLS_PROXY_CHILD"

// runInProxyChild returns true inside the child process, where the test body
// runs. In the parent it runs this very test in a child with every proxy
// variable of the environment removed, fails the parent with the child's output
// if the child fails, and returns false.
func runInProxyChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(proxyChildEnv) == "1" {
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasSuffix(strings.ToUpper(name), "_PROXY") {
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, proxyChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child process failed: %v\n%s", err, out)
	}
	return false
}

// startConnectProxy is a loopback HTTP proxy. It answers CONNECT with 200, 403
// or 407 according to behaviour ("ok", "403", "407"), maps the CONNECT host
// through routes to a loopback address, and records every CONNECT authority.
// When intercept is set it terminates TLS after the 200 the way an inspecting
// proxy does, instead of relaying bytes untouched.
func startConnectProxy(t *testing.T, routes map[string]string, behaviour string, intercept *tls.Certificate) (string, func() []string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })

	var mu sync.Mutex
	var seen []string

	handle := func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		if req.Method != http.MethodConnect {
			_, _ = c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		mu.Lock()
		seen = append(seen, req.Host)
		mu.Unlock()

		switch behaviour {
		case "403":
			_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
			return
		case "407":
			_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: Basic realm=\"supertls-test\"\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		upstream, ok := routes[req.Host]
		if !ok {
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		if br.Buffered() > 0 {
			t.Errorf("proxy: client sent %d bytes before the 200", br.Buffered())
			return
		}
		if intercept != nil {
			interceptConn(c, upstream, *intercept, []string{"h2"})
			return
		}
		up, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		defer up.Close()
		relay(c, up)
	}

	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return lis.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// proxyFixture starts the backend and the proxy, THEN points HTTPS_PROXY at it,
// and only then builds the dialer, before anything has asked for the proxy
// environment. It returns the dial target, which only the proxy can resolve.
func proxyFixture(t *testing.T, p *testpki.PKI, behaviour string, intercept *tls.Certificate) (target string, authorities func() []string) {
	t.Helper()
	backend, _ := startBackend(t, p)
	port := portOf(t, backend)
	target = "origin.supertls.test:" + port
	proxy, authorities := startConnectProxy(t, map[string]string{target: backend}, behaviour, intercept)
	if err := os.Setenv("HTTPS_PROXY", "http://"+proxy); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	return target, authorities
}

func TestHTTPSProxyConnectSuccessStaysDirect(t *testing.T) {
	if !runInProxyChild(t) {
		return
	}
	p := testpki.Standard(t)
	target, authorities := proxyFixture(t, p, "ok", nil)

	d := newDialer(t, p, nil)
	c, err := d.Dial(dialCtx(t), target, innerCreds(p))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if c.Mode() != supertls.ModeDirect {
		t.Fatalf("Mode() = %s, want direct", c.Mode())
	}
	healthCheck(t, c.ClientConn())

	// The name, not an address, must have crossed the proxy.
	var found bool
	for _, a := range authorities() {
		if a == target {
			found = true
		}
	}
	if !found {
		t.Fatalf("no CONNECT carried %q; saw %v", target, authorities())
	}
}

func TestHTTPSProxyInterceptingTunnels(t *testing.T) {
	if !runInProxyChild(t) {
		return
	}
	p := testpki.Standard(t)
	target, _ := proxyFixture(t, p, "ok", &p.Proxy)

	d := newDialer(t, p, nil)
	c, err := d.Dial(dialCtx(t), target, innerCreds(p))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if c.Mode() != supertls.ModeTunnel {
		t.Fatalf("Mode() = %s, want tunnel", c.Mode())
	}
	healthCheck(t, c.ClientConn())
}

func TestHTTPSProxyForbiddenIsInconclusiveAndReportsDirectError(t *testing.T) {
	refusedProxyTest(t, "403")
}

func TestHTTPSProxyAuthRequiredIsInconclusiveAndReportsDirectError(t *testing.T) {
	refusedProxyTest(t, "407")
}

func refusedProxyTest(t *testing.T, behaviour string) {
	t.Helper()
	if testing.Short() {
		t.Skip("waits out two dial budgets")
	}
	if !runInProxyChild(t) {
		return
	}
	p := testpki.Standard(t)
	target, authorities := proxyFixture(t, p, behaviour, nil)

	d := newDialer(t, p, nil,
		supertls.WithDirectDialBudget(2*time.Second),
		supertls.WithTunnelDialBudget(2*time.Second))
	c, err := d.Dial(dialCtx(t), target, innerCreds(p))
	if err == nil {
		_ = c.Close()
		t.Fatal("Dial succeeded through a proxy that refuses CONNECT")
	}
	var de *supertls.DialError
	if !errors.As(err, &de) {
		t.Fatalf("error %T is not a *DialError: %v", err, err)
	}
	if de.Verdict != supertls.VerdictInconclusive {
		t.Fatalf("Verdict = %s, want inconclusive", de.Verdict)
	}
	if de.Tunnel == nil {
		t.Fatal("Tunnel error is nil; an inconclusive verdict must try the tunnel")
	}
	if !errors.Is(err, de.Direct) {
		t.Fatalf("errors.Is(err, de.Direct) is false: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "supertls: direct dial of origin.supertls.test:") {
		t.Fatalf("error text does not begin with the direct dial: %v", err)
	}
	if n := len(authorities()); n < 3 {
		t.Fatalf("recorded %d CONNECTs, want at least 3 (direct, probe, tunnel): %v", n, authorities())
	}
}
