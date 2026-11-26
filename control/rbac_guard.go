// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (R6): the bounded guards behind the management-API role model -
// the per-source brute-force lockout and the single-use nonce cache - plus the
// small bounded utilities both the credential and the step-up verifiers use.

import (
	"errors"
	"sync"
	"time"
)

// ------------------------------------------------------------------ lockout

// attemptLockout is a bounded per-source failure guard. It turns a stream of
// failed credential or step-up verifications into a fixed-window lockout, prunes
// old failures, evicts the least recently seen source instead of failing closed
// for every newcomer, and reports only the transition into the lockout.
type attemptLockout struct {
	mu           sync.Mutex
	entries      map[string]*attackWindow
	failureLimit int
	window       time.Duration
	duration     time.Duration
	maxEntries   int
	now          func() time.Time
}

type attackWindow struct {
	failures    []time.Time
	lockedUntil time.Time
	lastSeen    time.Time
}

func newAttemptLockout(limit int, window, duration time.Duration, now func() time.Time) *attemptLockout {
	if limit <= 0 {
		limit = authLockoutFailureLimit
	}
	if window <= 0 {
		window = authLockoutFailureWindow
	}
	if duration <= 0 {
		duration = authLockoutDuration
	}
	if now == nil {
		now = time.Now
	}
	return &attemptLockout{
		entries: make(map[string]*attackWindow), failureLimit: limit, window: window,
		duration: duration, maxEntries: authLockoutMaxEntries, now: now,
	}
}

// locked reports whether key is currently locked out and for how much longer.
func (l *attemptLockout) locked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	window, ok := l.entries[key]
	if !ok {
		return false, 0
	}
	now := l.now()
	if !window.lockedUntil.IsZero() && now.Before(window.lockedUntil) {
		return true, window.lockedUntil.Sub(now)
	}
	if !window.lockedUntil.IsZero() {
		// The lockout expired: start from a clean slate.
		delete(l.entries, key)
		return false, 0
	}
	return false, 0
}

// fail records one failed verification. It returns the retry-after the source now
// has to observe and whether this call is the transition into the lockout.
func (l *attemptLockout) fail(key string) (bool, time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	window, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.maxEntries {
			l.evictLocked()
		}
		window = &attackWindow{}
		l.entries[key] = window
	}
	window.lastSeen = now
	if !window.lockedUntil.IsZero() && now.Before(window.lockedUntil) {
		return true, window.lockedUntil.Sub(now), false
	}
	cutoff := now.Add(-l.window)
	kept := window.failures[:0]
	for _, stamp := range window.failures {
		if stamp.After(cutoff) {
			kept = append(kept, stamp)
		}
	}
	window.failures = append(kept, now)
	if len(window.failures) < l.failureLimit {
		return false, 0, false
	}
	window.failures = window.failures[:0]
	window.lockedUntil = now.Add(l.duration)
	return true, l.duration, true
}

// success clears the failure history of a source that proved a valid credential,
// so one occasional typo cannot accumulate into a lockout.
func (l *attemptLockout) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// evictLocked removes the least recently active entry. A full table must not
// become a global denial of service (same trade-off as the rate limiter).
func (l *attemptLockout) evictLocked() {
	var oldestKey string
	var oldest time.Time
	for key, window := range l.entries {
		reference := window.lastSeen
		if !window.lockedUntil.IsZero() && window.lockedUntil.After(reference) {
			reference = window.lockedUntil
		}
		if oldestKey == "" || reference.Before(oldest) {
			oldestKey, oldest = key, reference
		}
	}
	if oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}

// -------------------------------------------------------------- nonce replay

// nonceReplayCache enforces one use per nonce inside a bounded TTL. A full cache
// evicts its oldest entry rather than refusing every fresh proof.
type nonceReplayCache struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	max    int
	lastGC time.Time
}

func newNonceReplayCache(max int) *nonceReplayCache {
	if max <= 0 {
		max = nonceReplayCacheMaxEntries
	}
	return &nonceReplayCache{seen: make(map[string]time.Time), max: max}
}

// claim consumes one nonce. It returns false for a value this cache has already
// accepted - the caller must then refuse the request.
func (c *nonceReplayCache) claim(nonce string, expires, now time.Time) bool {
	if nonce == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastGC) > time.Minute {
		for value, at := range c.seen {
			if now.After(at) {
				delete(c.seen, value)
			}
		}
		c.lastGC = now
	}
	if _, replayed := c.seen[nonce]; replayed {
		return false
	}
	if len(c.seen) >= c.max {
		var oldestKey string
		var oldest time.Time
		for value, at := range c.seen {
			if oldestKey == "" || at.Before(oldest) {
				oldestKey, oldest = value, at
			}
		}
		if oldestKey != "" {
			delete(c.seen, oldestKey)
		}
	}
	deadline := expires
	if bound := now.Add(nonceReplayCacheTTL); deadline.After(bound) || deadline.IsZero() {
		deadline = bound
	}
	c.seen[nonce] = deadline
	return true
}

// ---------------------------------------------------------------- utilities

func parseBoundedUnix(value string) (int64, error) {
	if len(value) < 10 || len(value) > 12 {
		return 0, errors.New("timestamp is not bounded")
	}
	var parsed int64
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return 0, errors.New("timestamp is not decimal")
		}
		parsed = parsed*10 + int64(c-'0')
	}
	if parsed < 1_000_000_000 {
		return 0, errors.New("timestamp is implausibly small")
	}
	return parsed, nil
}

// isLowerHex checks the exact lowercase-hex shape of a bounded field.
func isLowerHex(value string, minLen, maxLen int) bool {
	if len(value) < minLen || len(value) > maxLen || len(value)%2 != 0 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
