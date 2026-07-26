package auth

import (
	"sync"
	"time"
)

// Throttle protects the login endpoint from brute force. It counts
// failed attempts per key (the client's peer IP) and enforces a
// temporary lockout once too many failures pile up inside a window.
//
// The map self-prunes: stale entries are dropped once the map grows
// past maxKeys, so a flood of unique source IPs can't exhaust memory
// (the same discipline the request rate-limiter lacked originally).
type Throttle struct {
	mu      sync.Mutex
	m       map[string]*attempt
	max     int           // failures before lockout
	lockout time.Duration // how long a lockout lasts
	window  time.Duration // counter resets after this much quiet
	maxKeys int
}

type attempt struct {
	fails     int
	last      time.Time
	lockUntil time.Time
}

// NewThrottle returns a Throttle with sensible defaults: 5 failures in
// a 15-minute window triggers a 15-minute lockout.
func NewThrottle() *Throttle {
	return &Throttle{
		m:       map[string]*attempt{},
		max:     5,
		lockout: 15 * time.Minute,
		window:  15 * time.Minute,
		maxKeys: 4096,
	}
}

// Blocked reports whether key is currently locked out and, if so, how
// long remains.
func (t *Throttle) Blocked(key string) (bool, time.Duration) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.m[key]
	if a == nil || now.After(a.lockUntil) {
		return false, 0
	}
	return true, time.Until(a.lockUntil)
}

// Fail records one failed attempt for key, promoting it to a lockout
// once the threshold is crossed.
func (t *Throttle) Fail(key string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(now)
	a := t.m[key]
	if a == nil {
		a = &attempt{}
		t.m[key] = a
	}
	if now.Sub(a.last) > t.window {
		a.fails = 0
	}
	a.fails++
	a.last = now
	if a.fails >= t.max {
		a.lockUntil = now.Add(t.lockout)
		a.fails = 0
	}
}

// Reset clears the failure record for key (call on a successful login).
func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	delete(t.m, key)
	t.mu.Unlock()
}

// prune drops entries that are neither locked nor recently active.
// Caller must hold the lock. Only sweeps when the map is large so the
// common path stays O(1).
func (t *Throttle) prune(now time.Time) {
	if len(t.m) < t.maxKeys {
		return
	}
	for k, a := range t.m {
		if now.After(a.lockUntil) && now.Sub(a.last) > t.window {
			delete(t.m, k)
		}
	}
}
