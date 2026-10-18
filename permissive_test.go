package supertls

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/qunulabs/supertls/internal/testpki"
)

// permissiveHandshake runs permissiveCreds.ClientHandshake against a tls.Server
// presenting cert with no NextProtos, and returns the captured ClientHello and
// the client's handshake error.
func permissiveHandshake(t *testing.T, authority string, cert tls.Certificate) (*tls.ClientHelloInfo, error) {
	t.Helper()
	// Loopback TCP, not net.Pipe: an unbuffered pipe deadlocks the server's
	// session-ticket write against the client's close_notify.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })

	hellos := make(chan *tls.ClientHelloInfo, 1)
	cfg := &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			hellos <- h
			return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
		},
	}
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		srv, err := lis.Accept()
		if err != nil {
			return
		}
		defer srv.Close()
		_ = tls.Server(srv, cfg).Handshake()
	}()
	cli, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, hsErr := permissiveCreds{}.ClientHandshake(ctx, authority, cli)
	if hsErr == nil {
		conn.Close()
	}
	<-srvDone
	select {
	case h := <-hellos:
		return h, hsErr
	default:
		t.Fatal("the server saw no ClientHello")
		return nil, hsErr
	}
}

// The outer connection is unverified by design, so the thing that MUST hold is
// that it never leaks its ServerName into the authority the inner session
// derives its hostname check from.
func TestPermissiveCredsReportNoServerName(t *testing.T) {
	t.Parallel()
	info := permissiveCreds{}.Info()
	if info.ServerName != "" {
		t.Fatalf("Info().ServerName is %q; a non-empty value overrides the authority "+
			"and silently redirects the inner session's hostname check", info.ServerName)
	}
	if info.SecurityProtocol != "tls" {
		t.Fatalf("SecurityProtocol = %q, want tls", info.SecurityProtocol)
	}
}

func TestPermissiveCredsRejectServerSide(t *testing.T) {
	t.Parallel()
	if _, _, err := (permissiveCreds{}).ServerHandshake(nil); err == nil {
		t.Fatal("permissiveCreds must never be usable as server credentials")
	}
}

func TestPermissiveCredsOfferNoHybridGroup(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	h, err := permissiveHandshake(t, "localhost:1234", p.Proxy)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	if !slices.Contains(h.SupportedCurves, tls.X25519) || !slices.Contains(h.SupportedCurves, tls.CurveP256) {
		t.Fatalf("SupportedCurves %v lack X25519 or P-256", h.SupportedCurves)
	}
	if slices.Contains(h.SupportedCurves, tls.X25519MLKEM768) {
		t.Fatalf("SupportedCurves %v offer the hybrid group", h.SupportedCurves)
	}
	if !slices.Contains(h.SupportedVersions, tls.VersionTLS12) {
		t.Fatalf("SupportedVersions %v lack TLS 1.2", h.SupportedVersions)
	}
}

func TestPermissiveCredsSendSNI(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	h, err := permissiveHandshake(t, "localhost:1234", p.Proxy)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	if h.ServerName != "localhost" {
		t.Fatalf("SNI = %q, want localhost", h.ServerName)
	}
}

// A proxy that terminates TLS without echoing h2, and presents its own
// certificate, must still carry the outer connection.
func TestPermissiveCredsAcceptNoALPN(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	if _, err := permissiveHandshake(t, "localhost:1234", p.Proxy); err != nil {
		t.Fatalf("ClientHandshake against a server negotiating no ALPN with a foreign certificate: %v", err)
	}
}
