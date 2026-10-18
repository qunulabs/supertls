package supertls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/qunulabs/supertls/internal/testpki"
)

// handshakeAgainst runs c.ClientHandshake against a TLS server presenting cert.
func handshakeAgainst(t *testing.T, c credentials.TransportCredentials, cert tls.Certificate) error {
	t.Helper()
	// Loopback TCP, not net.Pipe: an unbuffered pipe deadlocks the server's
	// session-ticket write against the client's close_notify.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		s, err := lis.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		_ = tls.Server(s, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}).Handshake()
	}()
	raw, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, hsErr := c.ClientHandshake(ctx, "localhost:443", raw)
	if hsErr == nil {
		conn.Close()
	}
	<-done
	return hsErr
}

func strictCreds(p *testpki.PKI) credentials.TransportCredentials {
	cfg := testpki.StrictClientTLS(p)
	cfg.ServerName = "localhost"
	return credentials.NewTLS(cfg)
}

func TestRecordingCredsDelegateInfo(t *testing.T) {
	t.Parallel()
	c := recording(credentials.NewTLS(&tls.Config{ServerName: "x"}), &recorder{})
	if got := c.Info().ServerName; got != "x" {
		t.Fatalf("Info().ServerName = %q, want x", got)
	}
}

func TestRecordingCredsNoteHandshakeError(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	r := &recorder{}
	err := handshakeAgainst(t, recording(strictCreds(p), r), p.Proxy)
	if err == nil {
		t.Fatal("a foreign-certificate handshake must fail")
	}
	if r.last() != err {
		t.Fatalf("last() = %v, want the returned error %v", r.last(), err)
	}
}

func TestRecordingCredsClearOnSuccess(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	r := &recorder{}
	r.note(errors.New("stale"))
	if err := handshakeAgainst(t, recording(strictCreds(p), r), p.Server); err != nil {
		t.Fatalf("handshake against the genuine server: %v", err)
	}
	if r.last() != nil {
		t.Fatalf("last() = %v after a successful handshake, want nil", r.last())
	}
}

func TestRecordingCredsCloneSharesRecorder(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	r := &recorder{}
	clone := recording(strictCreds(p), r).Clone()
	if _, ok := clone.(*recordingCreds); !ok {
		t.Fatalf("Clone() returned %T, want the recording wrapper", clone)
	}
	err := handshakeAgainst(t, clone, p.Proxy)
	if err == nil {
		t.Fatal("handshake must fail")
	}
	if r.last() != err {
		t.Fatalf("a clone did not record on the shared recorder: last() = %v", r.last())
	}
}
