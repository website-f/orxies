package proxy

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// tokenBucket is a per-key leaky bucket with floating-point fill.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// Tuning for the per-IP bucket map. These exist because the map used to
// be unbounded, which made the rate limiter itself a memory-exhaustion
// vector: every unique source address added a permanent entry, and the
// edge container is capped at 256MB. A large distributed flood could
// therefore OOM the proxy and take every site down at once — including
// the sites that weren't being attacked.
const (
	// maxBuckets caps tracked source IPs per site. 50k is far more than
	// a real audience produces concurrently, and bounds worst-case
	// memory to a few megabytes per site.
	maxBuckets = 50_000

	// sweepInterval is how often idle buckets are evicted.
	sweepInterval = 30 * time.Second
)

// Limiter enforces three independent limits for one site:
//
//  1. per-source-IP rate — stops a single host hammering the site;
//  2. a site-wide rate ceiling — the per-IP limit is trivially bypassed
//     by distributing an attack (5,000 hosts each staying politely under
//     the per-IP limit still add up to a flood), so there is also a
//     global budget for the whole site;
//  3. a concurrency cap — the real failure mode isn't requests/second,
//     it's simultaneous requests: these upstreams run ~8 Octane workers
//     against a 151-connection MySQL pool, so a few hundred concurrent
//     expensive requests exhausts them regardless of arrival rate.
//     Shedding past a ceiling keeps the app responsive instead of
//     letting it collapse.
//
// Layout: one Limiter per Site, so configuration can't bleed between
// sites. Safe for concurrent use.
//
// This is origin-side load shedding, NOT DDoS mitigation. A volumetric
// attack saturates the network link before any of this code runs; that
// has to be absorbed upstream of the host.
type Limiter struct {
	rps   float64
	burst float64

	mu        sync.Mutex
	bs        map[string]*tokenBucket
	lastSweep time.Time

	// global is the site-wide budget, nil when unconfigured.
	globalMu    sync.Mutex
	global      *tokenBucket
	globalRPS   float64
	globalBurst float64

	// inFlight counts requests currently being served for this site.
	inFlightMu  sync.Mutex
	inFlight    int
	maxInFlight int
}

// NewLimiter returns a limiter with the given sustained per-IP rate and
// burst capacity. A non-positive rps disables per-IP limiting.
func NewLimiter(rps, burst int) *Limiter {
	if rps <= 0 {
		return nil // disabled
	}
	if burst < 0 {
		burst = 0
	}
	return &Limiter{
		rps:       float64(rps),
		burst:     float64(rps + burst),
		bs:        map[string]*tokenBucket{},
		lastSweep: time.Now(),
	}
}

// WithGlobal adds a site-wide rate ceiling on top of the per-IP limit.
// Zero or negative disables it. Returns l for chaining.
func (l *Limiter) WithGlobal(rps, burst int) *Limiter {
	if l == nil || rps <= 0 {
		return l
	}
	if burst < 0 {
		burst = 0
	}
	l.globalRPS = float64(rps)
	l.globalBurst = float64(rps + burst)
	l.global = &tokenBucket{tokens: l.globalBurst, last: time.Now()}
	return l
}

// WithMaxInFlight caps simultaneous in-flight requests for the site.
// Zero or negative disables it. Returns l for chaining.
func (l *Limiter) WithMaxInFlight(n int) *Limiter {
	if l == nil || n <= 0 {
		return l
	}
	l.maxInFlight = n
	return l
}

// Allow reports whether a request from `key` is within the per-IP and
// site-wide budgets. It does NOT account for concurrency — see Acquire.
func (l *Limiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	// Global budget first: it's the cheaper check, and it's the one
	// that actually holds under a distributed flood.
	if !l.allowGlobal() {
		return false
	}
	return l.allowPerIP(key)
}

func (l *Limiter) allowGlobal() bool {
	if l.global == nil {
		return true
	}
	now := time.Now()
	l.globalMu.Lock()
	defer l.globalMu.Unlock()

	l.global.tokens += now.Sub(l.global.last).Seconds() * l.globalRPS
	if l.global.tokens > l.globalBurst {
		l.global.tokens = l.globalBurst
	}
	l.global.last = now
	if l.global.tokens < 1 {
		return false
	}
	l.global.tokens--
	return true
}

func (l *Limiter) allowPerIP(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) >= sweepInterval {
		l.sweepLocked(now)
		l.lastSweep = now
	}

	tb, ok := l.bs[key]
	if !ok {
		// Refuse to grow past the cap. Failing CLOSED here is
		// deliberate: the alternative is unbounded allocation under a
		// flood, which OOMs the proxy and takes every site down. A
		// throttled new visitor during an active attack is a far better
		// outcome than a dead edge.
		if len(l.bs) >= maxBuckets {
			return false
		}
		// First request from this IP starts with a full burst budget.
		l.bs[key] = &tokenBucket{tokens: l.burst - 1, last: now}
		return true
	}

	// Refill since last visit.
	elapsed := now.Sub(tb.last).Seconds()
	tb.tokens += elapsed * l.rps
	if tb.tokens > l.burst {
		tb.tokens = l.burst
	}
	tb.last = now
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// sweepLocked drops buckets that have refilled to capacity.
//
// The insight that makes this free: a bucket at full capacity is
// indistinguishable from one that doesn't exist, because a new bucket
// is created full. Evicting idle buckets therefore loses no enforcement
// whatsoever — it only reclaims memory. Caller must hold l.mu.
func (l *Limiter) sweepLocked(now time.Time) {
	for k, tb := range l.bs {
		refilled := tb.tokens + now.Sub(tb.last).Seconds()*l.rps
		if refilled >= l.burst {
			delete(l.bs, k)
		}
	}
}

// Acquire reserves an in-flight slot. It returns a release func and
// whether the slot was granted; when false the caller must shed the
// request and must NOT call release.
//
// A nil limiter, or one with no configured cap, always grants.
func (l *Limiter) Acquire() (func(), bool) {
	if l == nil || l.maxInFlight <= 0 {
		return func() {}, true
	}
	l.inFlightMu.Lock()
	if l.inFlight >= l.maxInFlight {
		l.inFlightMu.Unlock()
		return nil, false
	}
	l.inFlight++
	l.inFlightMu.Unlock()

	// once, because a double release would corrupt the counter and
	// eventually let unlimited concurrency through.
	var once sync.Once
	return func() {
		once.Do(func() {
			l.inFlightMu.Lock()
			l.inFlight--
			l.inFlightMu.Unlock()
		})
	}, true
}

// Tracked reports how many source IPs are currently held. Exposed for
// tests and diagnostics.
func (l *Limiter) Tracked() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.bs)
}

// InFlight reports the current in-flight count.
func (l *Limiter) InFlight() int {
	if l == nil {
		return 0
	}
	l.inFlightMu.Lock()
	defer l.inFlightMu.Unlock()
	return l.inFlight
}

// ClientIP returns the best-effort source IP for `r`. If
// trustForwardedHeaders is true, the first hop in X-Forwarded-For is
// used; otherwise the direct peer is used (the safer default).
func ClientIP(r *http.Request, trustForwardedHeaders bool) string {
	if trustForwardedHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
