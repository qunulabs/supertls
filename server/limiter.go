package server

import (
	"math"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// limiter caps concurrent tunnels globally and per client address, and bounds
// how fast one address may open them.
//
// It is in-process because it bounds THIS server's memory and goroutines, which
// is a local property.
type limiter struct {
	lim Limits

	mu      sync.Mutex
	total   int
	perIP   map[string]int
	buckets map[string]*openBucket

	// now is time.Now in production and a stub in tests, because a token bucket
	// tested against the wall clock is either slow or flaky.
	now       func() time.Time
	lastSweep time.Time
}

// openBucket is one address's token bucket for tunnel opens.
type openBucket struct {
	tokens float64
	last   time.Time
}

// refill advances the bucket to t. Split out so acquire and the sweep agree on
// what "full" means.
func (b *openBucket) refill(t time.Time, l Limits) {
	if elapsed := t.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(float64(l.OpenBurst), b.tokens+elapsed*l.OpenRefillPerSecond)
		b.last = t
	}
}

// newLimiter returns a limiter for l, which the caller has validated. now is the
// clock.
func newLimiter(l Limits, now func() time.Time) *limiter {
	return &limiter{
		lim:     l,
		perIP:   make(map[string]int),
		buckets: make(map[string]*openBucket),
		now:     now,
	}
}

// open reports how many tunnel slots are held.
func (l *limiter) open() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// acquire reserves a slot for ip, returning the function that releases it. The
// release function is idempotent.
func (l *limiter) acquire(ip string) (release func(), err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweepLocked(now)

	if l.total >= l.lim.MaxConcurrent {
		return nil, status.Error(codes.ResourceExhausted, "too many open tunnels")
	}
	if l.perIP[ip] >= l.lim.MaxPerAddress {
		return nil, status.Error(codes.ResourceExhausted, "too many open tunnels from this address")
	}

	// The rate check comes last, so an address that is merely at its
	// concurrency cap is not also charged a token for being told so.
	b := l.buckets[ip]
	if b == nil {
		b = &openBucket{tokens: float64(l.lim.OpenBurst), last: now}
		l.buckets[ip] = b
	}
	b.refill(now, l.lim)
	if b.tokens < 1 {
		return nil, status.Error(codes.ResourceExhausted, "tunnel open rate exceeded for this address")
	}
	b.tokens--

	l.total++
	l.perIP[ip]++

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if n := l.perIP[ip] - 1; n > 0 {
				l.perIP[ip] = n
			} else {
				// Delete rather than leave a zero, or the map grows without
				// bound across a fleet's worth of client addresses.
				delete(l.perIP, ip)
			}
		})
	}, nil
}

// sweepLocked drops buckets that carry no information: full, and with no tunnel
// currently open from that address. Such a bucket is indistinguishable from the
// one acquire would create on the next open, so keeping it only costs memory.
//
// Amortised into acquire rather than given its own goroutine, because a
// background sweeper would have to be started and stopped in lockstep with a
// Service that tests construct and discard freely.
func (l *limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < l.lim.BucketSweep {
		return
	}
	l.lastSweep = now
	for ip, b := range l.buckets {
		b.refill(now, l.lim)
		if b.tokens >= float64(l.lim.OpenBurst) && l.perIP[ip] == 0 {
			delete(l.buckets, ip)
		}
	}
}
