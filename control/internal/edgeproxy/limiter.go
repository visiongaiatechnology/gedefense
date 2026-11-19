package edgeproxy

import (
	"sync"
	"time"
)

// limiter is a bounded per-peer request budget. Peers are keyed by their
// canonical address; the table evicts the oldest entry instead of growing
// without bound, so a spoofed source flood cannot exhaust memory. A denied
// request is reported to the caller and becomes an edge-blocked event.
type limiter struct {
	mu       sync.Mutex
	capacity int
	limit    float64 // tokens added per second
	burst    float64
	peers    map[string]*tokenBucket
	clock    func() time.Time
}

type tokenBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

func newLimiter(perMinute, capacity int) *limiter {
	if capacity <= 0 {
		capacity = 4096
	}
	limit := float64(perMinute) / 60
	return &limiter{
		capacity: capacity,
		limit:    limit,
		burst:    float64(perMinute),
		peers:    make(map[string]*tokenBucket, capacity),
		clock:    time.Now,
	}
}

func (l *limiter) allow(peer string) bool {
	if l == nil || peer == "" {
		return true
	}
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket, ok := l.peers[peer]
	if !ok {
		if len(l.peers) >= l.capacity {
			l.evictLocked()
		}
		bucket = &tokenBucket{tokens: l.burst, updated: now}
		l.peers[peer] = bucket
	}
	elapsed := now.Sub(bucket.updated).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * l.limit
		if bucket.tokens > l.burst {
			bucket.tokens = l.burst
		}
		bucket.updated = now
	}
	bucket.lastSeen = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

// evictLocked removes the least recently seen peer. The map is bounded, so the
// scan is bounded too; with the default 4096 entries it is a rare slow path.
func (l *limiter) evictLocked() {
	var oldestKey string
	var oldest time.Time
	for key, bucket := range l.peers {
		if oldestKey == "" || bucket.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = bucket.lastSeen
		}
	}
	if oldestKey != "" {
		delete(l.peers, oldestKey)
	}
}
