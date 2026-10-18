package supertls

import (
	"sync"
	"time"
)

// Mode is how a host is currently reached.
type Mode int

const (
	// ModeUnknown means no decision is held for the host, or the tunnel
	// decision has expired and the direct path will be tried again.
	ModeUnknown Mode = iota
	// ModeDirect means the host is reached by a plain strict dial.
	ModeDirect
	// ModeTunnel means the host is reached through the outer connection.
	ModeTunnel
)

func (m Mode) String() string {
	switch m {
	case ModeDirect:
		return "direct"
	case ModeTunnel:
		return "tunnel"
	default:
		return "unknown"
	}
}

// ModeChange describes a host's mode changing. It is handed to the hook
// installed with WithOnModeChange.
//
// Host is the host as the mode cache keys it: host:port, with port 443 made
// explicit when the dialled host had none, so "example.com" and
// "example.com:443" are one host. The hostname is otherwise as dialled; case
// is not folded.
//
// When To is ModeDirect the direct dial succeeded and no probe ran, so Verdict
// is VerdictGenuine. Reason is the probe's error, and is nil for a direct
// success.
type ModeChange struct {
	Host     string
	From, To Mode
	Verdict  Verdict
	Reason   error
}

// DefaultTunnelModeTTL is how long a tunnel decision holds before the direct
// path is tried again, so a machine that leaves the intercepting network stops
// paying for the tunnel. One extra handshake per host per hour costs nothing.
const DefaultTunnelModeTTL = time.Hour

// modeCache remembers, per host, how that host is reached. Its keys are
// normalised by hostPort before they get here.
//
// Per host rather than globally, because a split-tunnel proxy can treat the
// hosts in a failover list differently. In memory only and never persisted: the
// decision is about the network the process is on right now, and mobility is
// the common case.
type modeCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	now   func() time.Time
	modes map[string]modeEntry
}

type modeEntry struct {
	mode      Mode
	decidedAt time.Time
}

func newModeCache(ttl time.Duration, now func() time.Time) *modeCache {
	return &modeCache{ttl: ttl, now: now, modes: make(map[string]modeEntry)}
}

// get returns the mode held for host. Only the tunnel decision expires; an
// expired entry reads as ModeUnknown but is not deleted, so set can still report
// what it replaces.
func (m *modeCache) get(host string) Mode {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.modes[host]
	if !ok {
		return ModeUnknown
	}
	// Only the tunnel decision expires. ModeDirect is re-examined anyway the
	// moment a direct dial fails, so ageing it out would buy nothing.
	if e.mode == ModeTunnel && m.now().Sub(e.decidedAt) > m.ttl {
		return ModeUnknown
	}
	return e.mode
}

// set stores mode for host and returns the mode it replaced, expired or not
// (ModeUnknown when there was none). Returning the stored value even when it
// has expired is what lets a caller tell "this host was tunnelled and is being
// re-decided" from "this host is new".
func (m *modeCache) set(host string, mode Mode) (prev Mode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev = m.modes[host].mode
	m.modes[host] = modeEntry{mode: mode, decidedAt: m.now()}
	return prev
}
