package supertls

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestCache() (*modeCache, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return newModeCache(time.Hour, clk.now), clk
}

func TestModeStrings(t *testing.T) {
	t.Parallel()
	for m, want := range map[Mode]string{ModeUnknown: "unknown", ModeDirect: "direct", ModeTunnel: "tunnel", Mode(9): "unknown"} {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", int(m), got, want)
		}
	}
}

func TestModeCacheUnknownUntilDecided(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache()
	if got := c.get("h"); got != ModeUnknown {
		t.Fatalf("get = %v, want unknown", got)
	}
	if prev := c.set("h", ModeDirect); prev != ModeUnknown {
		t.Fatalf("set prev = %v, want unknown", prev)
	}
	if got := c.get("h"); got != ModeDirect {
		t.Fatalf("get = %v, want direct", got)
	}
}

func TestModeCacheIsPerHost(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache()
	c.set("a", ModeTunnel)
	c.set("b", ModeDirect)
	if c.get("a") != ModeTunnel || c.get("b") != ModeDirect || c.get("c") != ModeUnknown {
		t.Fatalf("hosts leaked into each other: a=%v b=%v c=%v", c.get("a"), c.get("b"), c.get("c"))
	}
}

func TestModeCacheTunnelDecisionExpires(t *testing.T) {
	t.Parallel()
	c, clk := newTestCache()
	c.set("h", ModeTunnel)
	clk.advance(time.Hour)
	if got := c.get("h"); got != ModeTunnel {
		t.Fatalf("at exactly the TTL get = %v, want tunnel", got)
	}
	clk.advance(1)
	if got := c.get("h"); got != ModeUnknown {
		t.Fatalf("TTL + 1ns get = %v, want unknown", got)
	}
}

func TestModeCacheDirectDecisionDoesNotExpire(t *testing.T) {
	t.Parallel()
	c, clk := newTestCache()
	c.set("h", ModeDirect)
	clk.advance(1000 * time.Hour)
	if got := c.get("h"); got != ModeDirect {
		t.Fatalf("get = %v, want direct", got)
	}
}

func TestModeCacheSetReportsPreviousEvenWhenExpired(t *testing.T) {
	t.Parallel()
	c, clk := newTestCache()
	c.set("h", ModeTunnel)
	clk.advance(2 * time.Hour)
	if got := c.get("h"); got != ModeUnknown {
		t.Fatalf("expired get = %v, want unknown", got)
	}
	if prev := c.set("h", ModeTunnel); prev != ModeTunnel {
		t.Fatalf("set prev = %v, want tunnel", prev)
	}
	// Re-deciding restarts the clock.
	if got := c.get("h"); got != ModeTunnel {
		t.Fatalf("get after re-decide = %v, want tunnel", got)
	}
}

func TestModeCacheIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	c, clk := newTestCache()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := fmt.Sprintf("h%d", i%7)
			c.set(h, Mode(1+i%2))
			c.get(h)
			clk.advance(time.Millisecond)
		}()
	}
	wg.Wait()
}
