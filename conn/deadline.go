package conn

import (
	"sync"
	"time"
)

// deadline is the absolute-time deadline net.Conn requires, expressed as a
// channel that closes when the deadline passes.
//
// This is the mechanism the standard library uses for net.Pipe (see
// pipeDeadline in net/pipe.go) and it is reproduced rather than invented
// because the semantics are subtle and load-bearing: a deadline is absolute,
// not a duration; setting it must fail calls that are ALREADY blocked, not just
// future ones; the zero time removes it; a time in the past fires immediately;
// and a deadline that has already fired must be revivable by setting a new one
// in the future. gRPC's server handshake path relies on the last of those, as
// it arms a deadline for the connection timeout and then clears it with the
// zero time.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{} // never nil; closed once the deadline has passed
}

func newDeadline() deadline {
	return deadline{cancel: make(chan struct{})}
}

// set arms the deadline for t, replacing any previous one. A zero t disarms it.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		// The timer has fired and its callback is closing cancel; wait for that to
		// finish so the channel below is not replaced out from under it.
		<-d.cancel
	}
	d.timer = nil

	closed := isClosedChan(d.cancel)

	// No deadline. Revive the channel if a previous deadline had closed it.
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}

	// In the future: arm a timer, reviving the channel first if needed.
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		d.timer = time.AfterFunc(dur, func() { close(d.cancel) })
		return
	}

	// Already past: fire now.
	if !closed {
		close(d.cancel)
	}
}

// wait returns the channel that closes when the deadline passes.
func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
