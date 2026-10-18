package tunnelpb

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestServiceDescIsNeutral pins the service name and shape: the library's
// tunnel is one bidirectional stream and nothing else.
func TestServiceDescIsNeutral(t *testing.T) {
	d := TunnelService_ServiceDesc
	if d.ServiceName != "supertls.v1.TunnelService" {
		t.Errorf("ServiceName = %q, want supertls.v1.TunnelService", d.ServiceName)
	}
	if len(d.Methods) != 0 {
		t.Errorf("unary methods = %d, want 0", len(d.Methods))
	}
	if len(d.Streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(d.Streams))
	}
	s := d.Streams[0]
	if s.StreamName != "Open" || !s.ClientStreams || !s.ServerStreams {
		t.Errorf("stream = %+v, want a bidirectional stream named Open", s)
	}
}

// TestFrameWireFormat pins field 1, wire type 2 (bytes). That is what makes a
// Frame here interchangeable on the wire with Sentinel's.
func TestFrameWireFormat(t *testing.T) {
	got, err := proto.Marshal(&Frame{Data: []byte("ab")})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{0x0a, 0x02, 'a', 'b'}
	if !bytes.Equal(got, want) {
		t.Errorf("wire bytes = %x, want %x", got, want)
	}
}
