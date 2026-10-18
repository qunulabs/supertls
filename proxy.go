package supertls

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrProxyConnect is returned when the HTTP proxy from the environment answers
// CONNECT with anything other than 200.
var ErrProxyConnect = errors.New("supertls: proxy refused CONNECT")

// Test seams. Production code never reassigns these; tests replace them to
// inject a proxy or a dial failure without touching the environment or DNS.
var (
	// proxyFromEnvironment is how the probe finds the proxy gRPC would use.
	proxyFromEnvironment = http.ProxyFromEnvironment
	// dialTCP opens every TCP connection the probe makes.
	dialTCP = (&net.Dialer{}).DialContext
)

// dialLikeGRPC opens a TCP connection the way gRPC does, honouring the same
// proxy environment.
//
// This matters for correctness, not tidiness. gRPC routes through
// http.ProxyFromEnvironment, so on a proxy-mandatory network a probe using a
// bare dialler would die at TCP and report "inconclusive" for a connection gRPC
// actually failed at the TLS layer, diagnosing the opposite of the truth.
func dialLikeGRPC(ctx context.Context, hostport string) (net.Conn, error) {
	proxyURL, err := proxyFromEnvironment(&http.Request{
		URL: &url.URL{Scheme: "https", Host: hostport},
	})
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return dialTCP(ctx, "tcp", hostport)
	}
	return dialThroughProxy(ctx, proxyURL, hostport)
}

// dialThroughProxy opens a CONNECT tunnel to hostport through the HTTP proxy at
// proxyURL. The whole exchange is bounded by ctx: a proxy that accepts TCP and
// never answers is abandoned when ctx ends.
func dialThroughProxy(ctx context.Context, proxyURL *url.URL, hostport string) (net.Conn, error) {
	conn, err := dialTCP(ctx, "tcp", proxyAddr(proxyURL))
	if err != nil {
		return nil, err
	}

	// A blocked read or write does not watch ctx, so ending ctx moves the
	// connection's deadline into the past to release it.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })

	resp, err := connect(conn, proxyURL, hostport)
	if !stop() {
		// ctx ended. Even if CONNECT had just succeeded the connection now
		// carries a past deadline, so it is not handed out.
		conn.Close()
		if err == nil {
			return nil, fmt.Errorf("supertls: proxy CONNECT to %s: %w", hostport, ctx.Err())
		}
		return nil, fmt.Errorf("supertls: proxy CONNECT to %s: %w: %w", hostport, ctx.Err(), err)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("%w: CONNECT %s: %s", ErrProxyConnect, hostport, resp.Status)
	}
	return conn, nil
}

// connect writes the CONNECT request and reads the proxy's answer.
func connect(conn net.Conn, proxyURL *url.URL, hostport string) (*http.Response, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: hostport},
		Header: http.Header{},
	}
	// gRPC supports Basic proxy authentication only. A proxy demanding NTLM or
	// Kerberos fails CONNECT here and on the direct path alike, and no amount of
	// tunnelling changes that; it is correctly reported as inconclusive.
	if ui := proxyURL.User; ui != nil {
		password, _ := ui.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(ui.Username()+":"+password)))
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("supertls: proxy CONNECT write: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("supertls: proxy CONNECT read: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK && br.Buffered() > 0 {
		// Bytes after a successful CONNECT mean the proxy is not a plain tunnel.
		// Continuing would feed them to the TLS handshake as if they came from
		// the origin.
		return nil, errors.New("supertls: proxy sent data before the tunnel was established")
	}
	return resp, nil
}

// proxyAddr renders a proxy URL as a dialable host:port.
func proxyAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}
