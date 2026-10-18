package supertls

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"strings"
	"testing"
	"time"
)

type recordedRequest struct {
	line   string
	header textproto.MIMEHeader
}

type proxyFixture struct {
	addr string
	reqs chan recordedRequest
}

// fakeProxy runs a loopback "proxy" that records each request line and its
// headers and then hands the connection to answer, which owns it until it
// returns.
func fakeProxy(t *testing.T, answer func(c net.Conn, br *bufio.Reader)) *proxyFixture {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	f := &proxyFixture{addr: lis.Addr().String(), reqs: make(chan recordedRequest, 8)}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				tp := textproto.NewReader(br)
				line, err := tp.ReadLine()
				if err != nil {
					return
				}
				hdr, err := tp.ReadMIMEHeader()
				if err != nil {
					return
				}
				f.reqs <- recordedRequest{line: line, header: hdr}
				answer(c, br)
			}()
		}
	}()
	return f
}

func (f *proxyFixture) url(t *testing.T, userinfo string) *url.URL {
	t.Helper()
	u, err := url.Parse("http://" + userinfo + f.addr)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return u
}

func (f *proxyFixture) next(t *testing.T) recordedRequest {
	t.Helper()
	select {
	case r := <-f.reqs:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy recorded no request")
		return recordedRequest{}
	}
}

// echoServer returns the address of a loopback server that echoes every byte.
func echoServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return lis.Addr().String()
}

func TestDialThroughProxySucceeds(t *testing.T) {
	t.Parallel()
	echo := echoServer(t)
	proxy := fakeProxy(t, func(c net.Conn, br *bufio.Reader) {
		up, err := net.Dial("tcp", echo)
		if err != nil {
			return
		}
		defer up.Close()
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		go func() { _, _ = io.Copy(up, br) }()
		_, _ = io.Copy(c, up)
	})

	conn, err := dialThroughProxy(context.Background(), proxy.url(t, ""), "origin.supertls.test:443")
	if err != nil {
		t.Fatalf("dialThroughProxy: %v", err)
	}
	defer conn.Close()

	if r := proxy.next(t); r.line != "CONNECT origin.supertls.test:443 HTTP/1.1" {
		t.Fatalf("request line %q", r.line)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echoed %q, want ping", buf)
	}
}

func testProxyRefusal(t *testing.T, status string) {
	t.Helper()
	proxy := fakeProxy(t, func(c net.Conn, _ *bufio.Reader) {
		_, _ = c.Write([]byte("HTTP/1.1 " + status + "\r\nContent-Length: 0\r\n\r\n"))
	})
	conn, err := dialThroughProxy(context.Background(), proxy.url(t, ""), "origin.supertls.test:443")
	if err == nil {
		conn.Close()
		t.Fatalf("a %s answer was accepted", status)
	}
	if !errors.Is(err, ErrProxyConnect) {
		t.Fatalf("err = %v, want ErrProxyConnect", err)
	}
	if code := strings.Fields(status)[0]; !strings.Contains(err.Error(), code) {
		t.Fatalf("err %q does not contain the status code %s", err, code)
	}
}

func TestDialThroughProxyForbidden(t *testing.T) {
	t.Parallel()
	testProxyRefusal(t, "403 Forbidden")
}

func TestDialThroughProxyAuthRequired(t *testing.T) {
	t.Parallel()
	testProxyRefusal(t, "407 Proxy Authentication Required")
}

func TestDialThroughProxySendsBasicAuth(t *testing.T) {
	t.Parallel()
	proxy := fakeProxy(t, func(c net.Conn, _ *bufio.Reader) {
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		_, _ = io.Copy(io.Discard, c)
	})
	conn, err := dialThroughProxy(context.Background(), proxy.url(t, "user:pass@"), "origin.supertls.test:443")
	if err != nil {
		t.Fatalf("dialThroughProxy: %v", err)
	}
	defer conn.Close()
	if got := proxy.next(t).header.Get("Proxy-Authorization"); got != "Basic dXNlcjpwYXNz" {
		t.Fatalf("Proxy-Authorization = %q", got)
	}
}

// Bytes after a successful CONNECT mean the proxy is not a plain tunnel, and
// they would be fed to the TLS handshake as if they came from the origin.
func TestDialThroughProxyRefusesEarlyBytes(t *testing.T) {
	t.Parallel()
	proxy := fakeProxy(t, func(c net.Conn, _ *bufio.Reader) {
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\nEXTRA"))
		_, _ = io.Copy(io.Discard, c)
	})
	conn, err := dialThroughProxy(context.Background(), proxy.url(t, ""), "origin.supertls.test:443")
	if err == nil {
		conn.Close()
		t.Fatal("a proxy that sent data before the tunnel was accepted")
	}
}

// A proxy that accepts TCP and never answers CONNECT must not outlive ctx: the
// probe promises to be bounded by its timeout.
func TestDialThroughProxySilentProxyHonoursContext(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	proxy := fakeProxy(t, func(net.Conn, *bufio.Reader) { <-release })

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := dialThroughProxy(ctx, proxy.url(t, ""), "origin.supertls.test:443")
	if err == nil {
		conn.Close()
		t.Fatal("a silent proxy produced a connection")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("dialThroughProxy took %s, want under 2s", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}

func TestProxyAddrDefaultsPort(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"http://p":      "p:80",
		"https://p":     "p:443",
		"http://p:3128": "p:3128",
	} {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		if got := proxyAddr(u); got != want {
			t.Errorf("proxyAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
