package server

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLimiterCapsPerAddress(t *testing.T) {
	t.Parallel()

	l := newLimiter(DefaultLimits(), time.Now)
	releases := make([]func(), 0, DefaultMaxPerAddress)
	for i := range DefaultMaxPerAddress {
		rel, err := l.acquire("203.0.113.7")
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		releases = append(releases, rel)
	}

	if _, err := l.acquire("203.0.113.7"); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("got %v, want ResourceExhausted once the per-address cap is reached", err)
	}
	// A different address must be unaffected: one noisy peer must not deny
	// service to everyone else.
	rel, err := l.acquire("198.51.100.4")
	if err != nil {
		t.Fatalf("a different address was refused: %v", err)
	}
	rel()

	releases[0]()
	if rel, err := l.acquire("203.0.113.7"); err != nil {
		t.Fatalf("releasing a slot did not free capacity: %v", err)
	} else {
		rel()
	}
	for _, r := range releases[1:] {
		r()
	}
}

// A leaked map entry per client address is a slow memory leak across a fleet.
func TestLimiterForgetsIdleAddresses(t *testing.T) {
	t.Parallel()

	l := newLimiter(DefaultLimits(), time.Now)
	rel, err := l.acquire("203.0.113.9")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	rel()
	rel() // release must be idempotent

	l.mu.Lock()
	defer l.mu.Unlock()
	if n, ok := l.perIP["203.0.113.9"]; ok {
		t.Fatalf("address still tracked with count %d after release", n)
	}
	if l.total != 0 {
		t.Fatalf("total is %d after releasing everything", l.total)
	}
}

// The concurrency caps bound what is held at once; they do not bound churn. A
// peer that opens a tunnel, starts the inner handshake and drops it costs a
// handshake and a goroutine each time while never approaching the per-address
// cap.
func TestLimiterCapsOpenRatePerAddress(t *testing.T) {
	t.Parallel()

	clock := time.Now()
	l := newLimiter(DefaultLimits(), func() time.Time { return clock })

	const ip = "203.0.113.11"
	// Churn: acquire and release immediately, so concurrency never rises above
	// one and only the rate limit can refuse anything.
	for i := range DefaultOpenBurst {
		rel, err := l.acquire(ip)
		if err != nil {
			t.Fatalf("acquire %d of %d within the burst: %v", i, DefaultOpenBurst, err)
		}
		rel()
	}

	if _, err := l.acquire(ip); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("got %v, want ResourceExhausted once the burst is spent", err)
	}

	// Another address is unaffected: the limit is per address, and one noisy
	// peer must not deny service to a whole fleet.
	if rel, err := l.acquire("198.51.100.11"); err != nil {
		t.Fatalf("a different address was refused: %v", err)
	} else {
		rel()
	}

	// Tokens come back with time, not with luck.
	clock = clock.Add(time.Second)
	for i := range int(DefaultOpenRefillPerSecond) {
		rel, err := l.acquire(ip)
		if err != nil {
			t.Fatalf("acquire %d after a second of refill: %v", i, err)
		}
		rel()
	}
	if _, err := l.acquire(ip); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("got %v, want ResourceExhausted after spending exactly one second of refill", err)
	}
}

// A limit that refuses a client already refused for concurrency would charge it
// twice, and a site sitting at its cap would never recover its rate budget.
func TestLimiterDoesNotChargeRefusedConcurrency(t *testing.T) {
	t.Parallel()

	clock := time.Now()
	l := newLimiter(DefaultLimits(), func() time.Time { return clock })

	const ip = "203.0.113.12"
	releases := make([]func(), 0, DefaultMaxPerAddress)
	for range DefaultMaxPerAddress {
		rel, err := l.acquire(ip)
		if err != nil {
			t.Fatalf("acquire within the concurrency cap: %v", err)
		}
		releases = append(releases, rel)
	}

	spent := DefaultOpenBurst - DefaultMaxPerAddress
	for range 50 {
		if _, err := l.acquire(ip); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("got %v, want ResourceExhausted at the concurrency cap", err)
		}
	}

	for _, r := range releases {
		r()
	}
	// The 50 refusals must have cost nothing, so the whole remaining burst is
	// still available.
	for i := range spent {
		rel, err := l.acquire(ip)
		if err != nil {
			t.Fatalf("acquire %d of %d remaining burst: refusals were charged tokens: %v", i, spent, err)
		}
		rel()
	}
}

// Without a sweep the bucket map grows by one entry per client address ever
// seen and never shrinks.
func TestLimiterSweepsFullIdleBuckets(t *testing.T) {
	t.Parallel()

	clock := time.Now()
	l := newLimiter(DefaultLimits(), func() time.Time { return clock })

	rel, err := l.acquire("203.0.113.13")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	rel()

	// Past the sweep interval, and long enough for the first address's bucket to
	// have refilled to full. The next acquire triggers the sweep.
	clock = clock.Add(DefaultBucketSweep + time.Second)
	rel2, err := l.acquire("198.51.100.13")
	if err != nil {
		t.Fatalf("acquire on a second address: %v", err)
	}
	rel2()

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.buckets["203.0.113.13"]; ok {
		t.Fatal("a full bucket with no open tunnels was not swept")
	}
	if _, ok := l.buckets["198.51.100.13"]; !ok {
		t.Fatal("the bucket for the address that just acquired was swept")
	}
}

func TestLimiterCapsGlobally(t *testing.T) {
	t.Parallel()

	lim := DefaultLimits()
	lim.MaxConcurrent, lim.MaxPerAddress = 3, 3
	l := newLimiter(lim, time.Now)

	var releases []func()
	for i := range 3 {
		rel, err := l.acquire(fmt.Sprintf("203.0.113.%d", i+1))
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		releases = append(releases, rel)
	}
	_, err := l.acquire("198.51.100.1")
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("fourth address: got %v, want ResourceExhausted at the global cap", err)
	}
	if got := status.Convert(err).Message(); got != "too many open tunnels" {
		t.Fatalf("message %q, want the global-cap message", got)
	}
	if n := l.open(); n != 3 {
		t.Fatalf("open() is %d, want 3", n)
	}

	releases[0]()
	rel, err := l.acquire("198.51.100.1")
	if err != nil {
		t.Fatalf("releasing a slot did not free global capacity: %v", err)
	}
	rel()
	for _, r := range releases[1:] {
		r()
	}
}

func TestLimiterReleaseIsIdempotent(t *testing.T) {
	t.Parallel()

	l := newLimiter(DefaultLimits(), time.Now)
	a, err := l.acquire("203.0.113.20")
	if err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	b, err := l.acquire("203.0.113.20")
	if err != nil {
		t.Fatalf("acquire b: %v", err)
	}
	a()
	a()
	a()
	if n := l.open(); n != 1 {
		t.Fatalf("open() is %d after releasing one slot three times, want 1", n)
	}
	l.mu.Lock()
	if n := l.perIP["203.0.113.20"]; n != 1 {
		l.mu.Unlock()
		t.Fatalf("per-address count is %d, want 1", n)
	}
	l.mu.Unlock()
	b()
	if n := l.open(); n != 0 {
		t.Fatalf("open() is %d after releasing everything, want 0", n)
	}
}
