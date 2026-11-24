// STATUS: DIAMANT VGT SUPREME
package main

import (
	"sync"
	"time"
)

type attemptWindow struct {
	failures []time.Time
}

type limiter struct {
	mu         sync.Mutex
	entries    map[string]*attemptWindow
	maxEntries int
	// failures is a bounded global ring of recent failed attempts. It does not lock
	// anyone out; it only lets the failure handler slow down a distributed flood.
	failures []time.Time
}

func newLimiter() *limiter {
	return &limiter{entries: make(map[string]*attemptWindow), maxEntries: 4096}
}

// allow enforces the per-source lockout. A full visitor table evicts the least recently
// active source instead of failing closed for every new client (F-08 / G-WEB-04): an
// attacker who floods the map must not be able to lock innocent operators out.
func (l *limiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-15 * time.Minute)
	w := l.entries[ip]
	if w == nil {
		if len(l.entries) >= l.maxEntries {
			var oldestKey string
			var oldest time.Time
			for key, value := range l.entries {
				last := value.lastFailure()
				if oldestKey == "" || last.Before(oldest) {
					oldestKey, oldest = key, last
				}
			}
			if oldestKey != "" {
				delete(l.entries, oldestKey)
			}
		}
		w = &attemptWindow{}
		l.entries[ip] = w
	}
	kept := w.failures[:0]
	for _, t := range w.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	w.failures = kept
	return len(w.failures) < 5
}

func (w *attemptWindow) lastFailure() time.Time {
	if len(w.failures) == 0 {
		return time.Time{}
	}
	return w.failures[len(w.failures)-1]
}

func (l *limiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.entries[ip]
	if w == nil {
		w = &attemptWindow{}
		l.entries[ip] = w
	}
	w.failures = append(w.failures, now)
	l.failures = append(l.failures, now)
	cutoff := now.Add(-5 * time.Minute)
	kept := l.failures[:0]
	for _, stamp := range l.failures {
		if stamp.After(cutoff) {
			kept = append(kept, stamp)
		}
	}
	if len(kept) > 512 {
		kept = kept[len(kept)-512:]
	}
	l.failures = kept
}

// pressure returns the number of failed attempts in the last five minutes. It is used only
// to slow the failure path under a distributed flood, never to refuse a clean sign-in.
func (l *limiter) pressure(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-5 * time.Minute)
	count := 0
	for _, stamp := range l.failures {
		if stamp.After(cutoff) {
			count++
		}
	}
	return count
}

func (l *limiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}
