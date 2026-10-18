package supertls

import (
	"context"
	"net"
	"sync"

	"google.golang.org/grpc/credentials"
)

// recorder keeps the error of the most recent client handshake. gRPC reports a
// handshake failure to the caller only as a generic Unavailable, so the dial
// layer reads the real cause from here to classify the failure.
type recorder struct {
	mu  sync.Mutex
	err error
}

// note records the outcome of a handshake. A nil err clears the record.
func (r *recorder) note(err error) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
}

// last returns the most recently noted error, or nil.
func (r *recorder) last() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// recordingCreds wraps a TransportCredentials and records its client handshake
// errors. This observes and never changes what is negotiated: it delegates
// everything, and Info passes through untouched because gRPC derives the
// connection's authority from it.
type recordingCreds struct {
	credentials.TransportCredentials
	r *recorder
}

// recording wraps c so that every client handshake outcome is noted on r.
func recording(c credentials.TransportCredentials, r *recorder) credentials.TransportCredentials {
	return &recordingCreds{TransportCredentials: c, r: r}
}

func (c *recordingCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, raw)
	c.r.note(err)
	return conn, info, err
}

// Clone wraps the inner clone with the same recorder: gRPC clones the
// credentials per connection, and the record must survive that.
func (c *recordingCreds) Clone() credentials.TransportCredentials {
	return &recordingCreds{TransportCredentials: c.TransportCredentials.Clone(), r: c.r}
}
