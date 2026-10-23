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

type ReplayGuard struct {
	mu         sync.Mutex
	seen       map[string]time.Time
	window     time.Duration
	maxEntries int
}

func NewReplayGuard(window time.Duration) *ReplayGuard {
	return &ReplayGuard{seen: make(map[string]time.Time), window: window, maxEntries: 65_536}
}

func (g *ReplayGuard) Claim(id string, now time.Time) bool {
	if !requestIDPattern.MatchString(id) {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, expiry := range g.seen {
		if !expiry.After(now) {
			delete(g.seen, key)
		}
	}
	if expiry, ok := g.seen[id]; ok && expiry.After(now) {
		return false
	}
	if len(g.seen) >= g.maxEntries {
		return false
	}
	g.seen[id] = now.Add(g.window)
	return true
}
