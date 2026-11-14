package main

import (
	"net"
	"regexp"
	"sync"
	"time"
)

type rateBucket struct {
	tokens float64
	last   time.Time
}

type RateLimiter struct {
	mu          sync.Mutex
	rate        float64
	burst       float64
	maxVisitors int
	visitors    map[string]rateBucket
	lastGC      time.Time
}

func NewRateLimiter(perMinute, burst int) *RateLimiter {
	return &RateLimiter{rate: float64(perMinute) / 60.0, burst: float64(burst), maxVisitors: 65_536, visitors: make(map[string]rateBucket), lastGC: time.Now()}
}

func remoteIdentity(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (l *RateLimiter) Allow(identity string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, exists := l.visitors[identity]
	if !exists && len(l.visitors) >= l.maxVisitors {
		// A full visitor table must not fail closed for every new client (F-08). Evict the
		// least recently seen identity and admit the new one; an attacker who creates many
		// source addresses can only evict other attacker entries, not lock the operator out.
		var oldestKey string
		var oldest time.Time
		for key, visitor := range l.visitors {
			if oldestKey == "" || visitor.last.Before(oldest) {
				oldestKey, oldest = key, visitor.last
			}
		}
		if oldestKey == "" {
			return false
		}
		delete(l.visitors, oldestKey)
	}
	if b.last.IsZero() {
		b.tokens = l.burst
		b.last = now
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	l.visitors[identity] = b
	if now.Sub(l.lastGC) > 5*time.Minute {
		for key, visitor := range l.visitors {
			if now.Sub(visitor.last) > 15*time.Minute {
				delete(l.visitors, key)
			}
		}
		l.lastGC = now
	}
	return allowed
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,96}$`)

// replayEntry is one claimed mutation identifier. scope is the opaque identity
// that claimed it (for example the dashboard operator digest); it is only used
// for the per-scope quota and never leaves the guard.
type replayEntry struct {
	expiry time.Time
	scope  string
}

// ReplayGuard remembers every accepted mutation identifier for one replay
// window and refuses a second claim of the same identifier.
//
// The guard is bounded, and a bounded set has to make a choice when an
// authenticated client floods it: rejecting every further claim turns the
// replay cache into a global mutation lockout (FIND-019), while silently
// forgetting entries re-opens replay. The chosen trade-off is explicit:
//
//   - expired entries are removed first;
//   - the oldest still-valid entry is then moved to a retained table instead of
//     being forgotten, so a replay of a displaced identifier inside the window
//     is still refused; the retained table is bounded by its own limit;
//   - each claiming scope has a hard entry quota, so one credential cannot
//     displace the whole cache on its own.
//
// A determined attacker who spends more than maxEntries+maxRetained distinct
// identifiers inside one window can eventually push the oldest fingerprint out
// of the retained table; that residual is bounded by the window and by the
// per-scope quota, and it is the only way to keep a full cache from becoming a
// global denial of service.
type ReplayGuard struct {
	mu          sync.Mutex
	seen        map[string]replayEntry
	retained    map[string]replayEntry
	scopes      map[string]int
	window      time.Duration
	maxEntries  int
	maxRetained int
	maxPerScope int
	lastPurge   time.Time
}

func NewReplayGuard(window time.Duration) *ReplayGuard {
	if window <= 0 {
		window = 10 * time.Minute
	}
	guard := &ReplayGuard{
		seen:        make(map[string]replayEntry),
		retained:    make(map[string]replayEntry),
		scopes:      make(map[string]int),
		window:      window,
		maxEntries:  65_536,
		maxRetained: 65_536,
		maxPerScope: 1_024,
		lastPurge:   time.Now(),
	}
	return guard
}

// purgeInterval bounds the cost of the periodic expiry sweep. Correctness does
// not depend on it: every claim also compares the stored expiry of the exact
// identifier it is looking at.
func (g *ReplayGuard) purgeInterval() time.Duration {
	interval := g.window / 8
	if interval < time.Second {
		interval = time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	return interval
}

// retainedLimit caps the table of displaced-but-still-valid identifiers. It is
// a full second window of replay memory on top of the active table.
func (g *ReplayGuard) retainedLimit() int {
	if g.maxRetained > 0 {
		return g.maxRetained
	}
	return g.maxEntries
}

func (g *ReplayGuard) perScopeLimit() int {
	if g.maxPerScope > 0 {
		return g.maxPerScope
	}
	return 1_024
}

func (g *ReplayGuard) bumpScopeLocked(scope string, delta int) {
	if scope == "" {
		return
	}
	next := g.scopes[scope] + delta
	if next <= 0 {
		delete(g.scopes, scope)
		return
	}
	g.scopes[scope] = next
}

// purgeLocked drops every entry whose window has passed. It reports whether the
// sweep ran, so the caller can decide whether a quota rejection is worth
// retrying after an expiry sweep.
func (g *ReplayGuard) purgeLocked(now time.Time, force bool) bool {
	if !force && now.Sub(g.lastPurge) < g.purgeInterval() {
		return false
	}
	for id, entry := range g.seen {
		if !entry.expiry.After(now) {
			g.bumpScopeLocked(entry.scope, -1)
			delete(g.seen, id)
		}
	}
	for id, entry := range g.retained {
		if !entry.expiry.After(now) {
			g.bumpScopeLocked(entry.scope, -1)
			delete(g.retained, id)
		}
	}
	g.lastPurge = now
	return true
}

func (g *ReplayGuard) oldestEntryLocked() (string, replayEntry, bool) {
	var oldestID string
	var oldest replayEntry
	for id, entry := range g.seen {
		if oldestID == "" || entry.expiry.Before(oldest.expiry) {
			oldestID, oldest = id, entry
		}
	}
	if oldestID == "" {
		return "", replayEntry{}, false
	}
	return oldestID, oldest, true
}

// evictOldestRetainedLocked drops the retained fingerprint with the earliest
// expiry. Callers invoke it only when the retained table is full, which is the
// documented residual of the bounded design.
func (g *ReplayGuard) evictOldestRetainedLocked() {
	var oldestID string
	var oldest replayEntry
	for id, entry := range g.retained {
		if oldestID == "" || entry.expiry.Before(oldest.expiry) {
			oldestID, oldest = id, entry
		}
	}
	if oldestID == "" {
		return
	}
	g.bumpScopeLocked(oldest.scope, -1)
	delete(g.retained, oldestID)
}

// Claim records a mutation identifier without a scope quota. It is the
// compatibility entry point; callers that know the claiming identity should use
// ClaimFor so a single credential cannot monopolise the bounded cache.
func (g *ReplayGuard) Claim(id string, now time.Time) bool {
	return g.ClaimFor("", id, now)
}

// ClaimFor records a mutation identifier for one opaque claiming scope. scope is
// never logged and never returned; passing an empty scope keeps the historical
// behaviour.
func (g *ReplayGuard) ClaimFor(scope, id string, now time.Time) bool {
	if g == nil || !requestIDPattern.MatchString(id) {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[string]replayEntry)
	}
	if g.retained == nil {
		g.retained = make(map[string]replayEntry)
	}
	if g.scopes == nil {
		g.scopes = make(map[string]int)
	}
	if g.maxEntries < 1 {
		g.maxEntries = 1
	}
	g.purgeLocked(now, len(g.seen) >= g.maxEntries)

	if entry, ok := g.seen[id]; ok {
		if entry.expiry.After(now) {
			return false
		}
		// The window of this identifier has passed: it is released for reuse.
		g.bumpScopeLocked(entry.scope, -1)
		delete(g.seen, id)
	}
	if entry, ok := g.retained[id]; ok {
		if entry.expiry.After(now) {
			return false
		}
		g.bumpScopeLocked(entry.scope, -1)
		delete(g.retained, id)
	}
	if scope != "" && g.scopes[scope] >= g.perScopeLimit() {
		// Expired entries may still count against the quota: one forced sweep,
		// then fail closed for this scope only. Other scopes stay available. The
		// quota is checked before any displacement, so a rejected claim has no
		// side effect on the replay cache.
		g.purgeLocked(now, true)
		if g.scopes[scope] >= g.perScopeLimit() {
			return false
		}
	}
	if len(g.seen) >= g.maxEntries {
		// A full active table must not fail closed for every caller (FIND-019).
		victimID, victim, ok := g.oldestEntryLocked()
		if ok {
			delete(g.seen, victimID)
			if len(g.retained) >= g.retainedLimit() {
				g.evictOldestRetainedLocked()
			}
			// Keep replay protection for the displaced identifier until its
			// original window expires: displacement must not equal forgetting.
			g.retained[victimID] = victim
		}
	}
	g.seen[id] = replayEntry{expiry: now.Add(g.window), scope: scope}
	g.bumpScopeLocked(scope, 1)
	return true
}
