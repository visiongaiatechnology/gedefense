// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"sync"
	"time"
)

const l7LimiterShards = 64

type l7TokenBucket struct {
	tokens float64
	last   time.Time
}

type l7LimiterShard struct {
	mu       sync.Mutex
	buckets  map[string]l7TokenBucket
	overflow l7TokenBucket
	lastGC   time.Time
}

// l7ShardedLimiter holds only token-bucket state. Rates are supplied per call
// from the published Fabric snapshot, so an operator revision takes effect on
// the next evaluation without rebuilding or draining limiter state.
type l7ShardedLimiter struct {
	maxEntriesPerMap int
	shards           [l7LimiterShards]l7LimiterShard
}

func newL7ShardedLimiter(maxEntries int) *l7ShardedLimiter {
	limiter := &l7ShardedLimiter{maxEntriesPerMap: (maxEntries + l7LimiterShards - 1) / l7LimiterShards}
	if limiter.maxEntriesPerMap < 16 {
		limiter.maxEntriesPerMap = 16
	}
	now := time.Now()
	for i := range limiter.shards {
		limiter.shards[i].buckets = make(map[string]l7TokenBucket, limiter.maxEntriesPerMap)
		limiter.shards[i].lastGC = now
	}
	return limiter
}

func (l *l7ShardedLimiter) Allow(key string, rate, burst float64, now time.Time) bool {
	if l == nil || rate <= 0 || burst <= 0 {
		return false
	}
	shard := &l.shards[l7ShardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	bucket, exists := shard.buckets[key]
	if !exists {
		if len(shard.buckets) >= l.maxEntriesPerMap {
			if now.Sub(shard.lastGC) >= 30*time.Second {
				l7LimiterGCLocked(shard, now, 5*time.Minute)
			}
			if len(shard.buckets) >= l.maxEntriesPerMap {
				return consumeL7Token(&shard.overflow, rate, burst, now)
			}
		}
		bucket = l7TokenBucket{tokens: burst, last: now}
	}
	allowed := consumeL7Token(&bucket, rate, burst, now)
	shard.buckets[key] = bucket
	if now.Sub(shard.lastGC) >= 2*time.Minute {
		l7LimiterGCLocked(shard, now, 15*time.Minute)
	}
	return allowed
}

func consumeL7Token(bucket *l7TokenBucket, rate, burst float64, now time.Time) bool {
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * rate
		if bucket.tokens > burst {
			bucket.tokens = burst
		}
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func l7LimiterGCLocked(shard *l7LimiterShard, now time.Time, maxIdle time.Duration) {
	cutoff := now.Add(-maxIdle)
	for key, bucket := range shard.buckets {
		if bucket.last.Before(cutoff) {
			delete(shard.buckets, key)
		}
	}
	shard.lastGC = now
}

func l7ShardIndex(key string) uint32 {
	const offset32 = uint32(2166136261)
	const prime32 = uint32(16777619)
	hash := offset32
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= prime32
	}
	return hash % l7LimiterShards
}

type L7RateLimiter struct {
	client          *l7ShardedLimiter
	sensitive       *l7ShardedLimiter
	sensitiveGlobal *l7ShardedLimiter
}

func NewL7RateLimiter(cfg L7Config) *L7RateLimiter {
	return newL7RateLimiterWithRuntime(cfg)
}

func newL7RateLimiterWithRuntime(cfg L7Config) *L7RateLimiter {
	return &L7RateLimiter{
		client:          newL7ShardedLimiter(cfg.MaxTrackedClients),
		sensitive:       newL7ShardedLimiter(cfg.MaxTrackedClients),
		sensitiveGlobal: newL7ShardedLimiter(cfg.MaxTrackedClients),
	}
}

func l7Rate(perMinute int) float64 { return float64(perMinute) / 60.0 }

// Evaluate performs one rate decision against exactly the snapshot it is
// handed. The caller passes the same snapshot that governs the rest of the
// inspection, which keeps a single request self-consistent.
func (l *L7RateLimiter) Evaluate(snapshot *l7RuntimeSnapshot, remoteIP, host, path, method string, now time.Time) (bool, string) {
	if l == nil || snapshot == nil {
		return true, ""
	}
	cfg := snapshot.cfg
	clientKey := remoteIP + "|" + strings.ToLower(host)
	if !l.client.Allow(clientKey, l7Rate(cfg.ClientRatePerMinute), float64(cfg.ClientRateBurst), now) {
		return false, "client"
	}
	if snapshot.sensitivePath(path) {
		globalKey := strings.ToLower(host) + "|" + method + "|" + path
		if !l.sensitiveGlobal.Allow(globalKey, l7Rate(cfg.SensitiveGlobalRatePerMinute), float64(cfg.SensitiveGlobalRateBurst), now) {
			return false, "sensitive-route-global"
		}
		key := clientKey + "|" + method + "|" + path
		if !l.sensitive.Allow(key, l7Rate(cfg.SensitiveRatePerMinute), float64(cfg.SensitiveRateBurst), now) {
			return false, "sensitive-route"
		}
	}
	return true, ""
}
