package supertls

import (
	"errors"
	"fmt"
)

// ErrNotReady is returned when a connection did not become ready within its dial
// budget. When a TLS handshake failed along the way, its error is wrapped too,
// so errors.As can reach it.
var ErrNotReady = errors.New("supertls: connection did not become ready")

// DialError is returned by Dial when the direct dial failed and the tunnel
// either was not tried (the peer is genuine) or failed as well.
//
// Direct is always the ORIGINAL direct-path error. A tunnel failure after a
// failed direct dial is a second-order symptom, and "unimplemented" or a tunnel
// timeout is the least informative thing an operator could be handed for what
// is really a certificate problem. errors.Is matches both Direct and Tunnel.
type DialError struct {
	// Host is the address that was dialled.
	Host string
	// Direct is the error of the direct dial.
	Direct error
	// Verdict is what the interception probe concluded.
	Verdict Verdict
	// ProbeErr is the probe's evidence or failure, nil for a clean genuine
	// verdict.
	ProbeErr error
	// Tunnel is the error of the tunnelled dial, nil when it was not tried.
	Tunnel error
}

func (e *DialError) Error() string {
	switch {
	case e.Verdict == VerdictGenuine:
		return fmt.Sprintf("supertls: direct dial of %s failed and the server presented a certificate "+
			"from the trusted roots, so this is not interception and the tunnel was not tried: %v (probe: %s)",
			e.Host, e.Direct, e.Verdict)
	case e.Tunnel != nil:
		return fmt.Sprintf("supertls: direct dial of %s failed: %v (probe: %s; tunnelled dial also failed: %v)",
			e.Host, e.Direct, e.Verdict, e.Tunnel)
	default:
		return fmt.Sprintf("supertls: direct dial of %s failed: %v (probe: %s)", e.Host, e.Direct, e.Verdict)
	}
}

// Unwrap returns Direct, then Tunnel when it is set.
func (e *DialError) Unwrap() []error {
	errs := []error{e.Direct}
	if e.Tunnel != nil {
		errs = append(errs, e.Tunnel)
	}
	return errs
}
