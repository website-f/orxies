package proxy

import (
	"fmt"
	"sync"
	"testing"
)

func TestPerIPLimitAllowsThenThrottles(t *testing.T) {
	l := NewLimiter(10, 5) // capacity 15
	allowed := 0
	for i := 0; i < 100; i++ {
		if l.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed == 0 || allowed > 20 {
		t.Fatalf("allowed %d of 100; expected roughly the burst capacity (15)", allowed)
	}
	// A different address has its own budget.
	if !l.Allow("5.6.7.8") {
		t.Error("a second IP was throttled by the first IP's usage")
	}
}

func TestNilLimiterAllowsEverything(t *testing.T) {
	var l *Limiter
	if !l.Allow("1.2.3.4") {
		t.Error("nil limiter must allow")
	}
	if rel, ok := l.Acquire(); !ok || rel == nil {
		t.Error("nil limiter must grant an in-flight slot")
	}
	if l.Tracked() != 0 || l.InFlight() != 0 {
		t.Error("nil limiter should report zeroes")
	}
}

// The per-IP map used to grow without bound, which made the limiter a
// memory-exhaustion vector: the edge container is capped at 256MB, so a
// flood from many unique addresses could OOM the proxy and take every
// site down — including sites that weren't under attack.
func TestPerIPMapIsBounded(t *testing.T) {
	l := NewLimiter(1, 0)
	for i := 0; i < maxBuckets+5_000; i++ {
		l.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if got := l.Tracked(); got > maxBuckets {
		t.Fatalf("tracked %d source IPs, cap is %d — the map is unbounded", got, maxBuckets)
	}
}

// Past the cap the limiter must fail CLOSED. Allocating instead would
// mean unbounded memory under exactly the conditions the cap exists for.
func TestBeyondCapFailsClosed(t *testing.T) {
	l := NewLimiter(1, 0)
	for i := 0; i < maxBuckets; i++ {
		l.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if l.Allow("203.0.113.99") {
		t.Error("a brand-new IP was admitted past the bucket cap")
	}
}

// Evicting a refilled bucket is free: a full bucket is indistinguishable
// from a missing one, since new buckets are created full. This checks
// the sweep actually reclaims.
func TestSweepReclaimsIdleBuckets(t *testing.T) {
	l := NewLimiter(10, 5)
	for i := 0; i < 500; i++ {
		l.Allow(fmt.Sprintf("192.0.2.%d", i%256))
	}
	before := l.Tracked()
	if before == 0 {
		t.Fatal("no buckets tracked")
	}

	// Pretend the sweep interval elapsed and every bucket refilled.
	l.mu.Lock()
	past := l.lastSweep.Add(-sweepInterval * 2)
	l.lastSweep = past
	for _, tb := range l.bs {
		tb.last = past
	}
	l.mu.Unlock()

	l.Allow("198.51.100.1") // triggers the sweep
	if after := l.Tracked(); after >= before {
		t.Errorf("sweep reclaimed nothing: %d -> %d", before, after)
	}
}

// The whole point of the global ceiling: a distributed flood keeps every
// individual IP under the per-IP limit, so only a site-wide budget
// stops it.
func TestGlobalCeilingStopsDistributedFlood(t *testing.T) {
	l := NewLimiter(100, 100).WithGlobal(10, 5) // per-IP generous, global tight

	allowed := 0
	for i := 0; i < 500; i++ {
		// A different source every time — each one is well within its
		// own per-IP budget.
		if l.Allow(fmt.Sprintf("172.16.%d.%d", i>>8&0xff, i&0xff)) {
			allowed++
		}
	}
	if allowed > 30 {
		t.Fatalf("global ceiling let %d/500 through; per-IP limits alone don't stop distribution", allowed)
	}
	if allowed == 0 {
		t.Fatal("global ceiling blocked everything, including the initial burst")
	}
}

func TestGlobalDisabledByDefault(t *testing.T) {
	l := NewLimiter(100, 100)
	for i := 0; i < 300; i++ {
		if !l.Allow(fmt.Sprintf("172.20.%d.%d", i>>8&0xff, i&0xff)) {
			t.Fatal("unconfigured global ceiling throttled distinct IPs")
		}
	}
}

func TestMaxInFlightShedsAtCapacity(t *testing.T) {
	l := NewLimiter(1000, 0).WithMaxInFlight(3)

	var releases []func()
	for i := 0; i < 3; i++ {
		rel, ok := l.Acquire()
		if !ok {
			t.Fatalf("slot %d refused below the cap", i)
		}
		releases = append(releases, rel)
	}
	if _, ok := l.Acquire(); ok {
		t.Error("a 4th concurrent request was admitted with the cap at 3")
	}
	if l.InFlight() != 3 {
		t.Errorf("InFlight = %d, want 3", l.InFlight())
	}

	releases[0]()
	if l.InFlight() != 2 {
		t.Errorf("after release InFlight = %d, want 2", l.InFlight())
	}
	if _, ok := l.Acquire(); !ok {
		t.Error("slot not reusable after release")
	}
}

// A double release would corrupt the counter and eventually allow
// unlimited concurrency — the exact failure the cap exists to prevent.
func TestReleaseIsIdempotent(t *testing.T) {
	l := NewLimiter(10, 0).WithMaxInFlight(1)
	rel, ok := l.Acquire()
	if !ok {
		t.Fatal("first acquire refused")
	}
	rel()
	rel()
	rel()
	if got := l.InFlight(); got != 0 {
		t.Fatalf("InFlight = %d after repeated release, want 0", got)
	}
}

func TestConcurrentUseIsRaceFree(t *testing.T) {
	l := NewLimiter(10_000, 1_000).WithGlobal(10_000, 1_000).WithMaxInFlight(64)

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				key := fmt.Sprintf("10.1.%d.%d", n, j%256)
				if l.Allow(key) {
					if rel, ok := l.Acquire(); ok {
						rel()
					}
				}
			}
		}(i)
	}
	wg.Wait()

	if got := l.InFlight(); got != 0 {
		t.Errorf("InFlight leaked: %d", got)
	}
}
