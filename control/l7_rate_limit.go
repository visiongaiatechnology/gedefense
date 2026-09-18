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

type l7ShardedLimiter struct {
	rate             float64
	burst            float64
	maxEntriesPerMap int
	shards           [l7LimiterShards]l7LimiterShard
}

func newL7ShardedLimiter(perMinute, burst, maxEntries int) *l7ShardedLimiter {
	limiter := &l7ShardedLimiter{
		rate: float64(perMinute) / 60.0, burst: float64(burst),
		maxEntriesPerMap: (maxEntries + l7LimiterShards - 1) / l7LimiterShards,
	}
	if limiter.maxEntriesPerMap < 16 {
		limiter.maxEntriesPerMap = 16
	}
	now := time.Now()
	for i := range limiter.shards {
		limiter.shards[i].buckets = make(map[string]l7TokenBucket, limiter.maxEntriesPerMap)
		limiter.shards[i].overflow = l7TokenBucket{tokens: limiter.burst, last: now}
		limiter.shards[i].lastGC = now
	}
	return limiter
}

func (l *l7ShardedLimiter) Allow(key string, now time.Time) bool {
	if l == nil || l.rate <= 0 || l.burst <= 0 {
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
				allowed := consumeL7Token(&shard.overflow, l.rate, l.burst, now)
				return allowed
			}
		}
		bucket = l7TokenBucket{tokens: l.burst, last: now}
	}
	allowed := consumeL7Token(&bucket, l.rate, l.burst, now)
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
	paths           map[string]struct{}
}

func NewL7RateLimiter(cfg L7Config) *L7RateLimiter {
	paths := make(map[string]struct{}, len(cfg.SensitivePaths))
	for _, path := range cfg.SensitivePaths {
		paths[path] = struct{}{}
	}
	return &L7RateLimiter{
		client:          newL7ShardedLimiter(cfg.ClientRatePerMinute, cfg.ClientRateBurst, cfg.MaxTrackedClients),
		sensitive:       newL7ShardedLimiter(cfg.SensitiveRatePerMinute, cfg.SensitiveRateBurst, cfg.MaxTrackedClients),
		sensitiveGlobal: newL7ShardedLimiter(cfg.SensitiveGlobalRatePerMinute, cfg.SensitiveGlobalRateBurst, cfg.MaxTrackedClients),
		paths:           paths,
	}
}

func (l *L7RateLimiter) Evaluate(remoteIP, host, path, method string, now time.Time) (bool, string) {
	if l == nil {
		return true, ""
	}
	clientKey := remoteIP + "|" + strings.ToLower(host)
	if !l.client.Allow(clientKey, now) {
		return false, "client"
	}
	if l.sensitivePath(path) {
		globalKey := strings.ToLower(host) + "|" + method + "|" + path
		if !l.sensitiveGlobal.Allow(globalKey, now) {
			return false, "sensitive-route-global"
		}
		key := clientKey + "|" + method + "|" + path
		if !l.sensitive.Allow(key, now) {
			return false, "sensitive-route"
		}
	}
	return true, ""
}

func (l *L7RateLimiter) sensitivePath(path string) bool {
	if l == nil || path == "" {
		return false
	}
	if _, ok := l.paths[path]; ok {
		return true
	}
	for configured := range l.paths {
		if configured != "/" && strings.HasPrefix(path, configured+"/") {
			return true
		}
	}
	return false
}
