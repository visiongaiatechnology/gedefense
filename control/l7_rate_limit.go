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

// Static-asset budget limits. Static reads are not exempt from rate limiting
// (FIND-021): they draw from a separate, higher but finite per-IP bucket. The
// multiplier keeps a media-heavy admin page working; the absolute ceiling keeps
// "higher" from meaning "unlimited" even with an extreme operator configuration.
const (
	l7StaticAssetBudgetFactor = 8
	l7StaticAssetRateCeiling  = 6_000 // requests per minute, per client
	l7StaticAssetBurstCeiling = 1_000
)

type L7RateLimiter struct {
	client          *l7ShardedLimiter
	static          *l7ShardedLimiter
	sensitive       *l7ShardedLimiter
	sensitiveGlobal *l7ShardedLimiter
}

func NewL7RateLimiter(cfg L7Config) *L7RateLimiter {
	return newL7RateLimiterWithRuntime(cfg)
}

func newL7RateLimiterWithRuntime(cfg L7Config) *L7RateLimiter {
	return &L7RateLimiter{
		client:          newL7ShardedLimiter(cfg.MaxTrackedClients),
		static:          newL7ShardedLimiter(cfg.MaxTrackedClients),
		sensitive:       newL7ShardedLimiter(cfg.MaxTrackedClients),
		sensitiveGlobal: newL7ShardedLimiter(cfg.MaxTrackedClients),
	}
}

func l7Rate(perMinute int) float64 { return float64(perMinute) / 60.0 }

// Evaluate performs one rate decision against exactly the snapshot it is
// handed. The caller passes the same snapshot that governs the rest of the
// inspection, which keeps a single request self-consistent.
func (l *L7RateLimiter) Evaluate(snapshot *l7RuntimeSnapshot, remoteIP, host, path, method string, now time.Time) (bool, string) {
	return l.EvaluatePolicy(snapshot, remoteIP, host, path, method, now, false)
}

// EvaluatePolicy is the single limiter entry point. bypassClient is used only
// for an operator-approved, detected CMS admin surface; sensitive-route limits
// still apply. A verified WordPress master lease is handled by the caller as a
// full short-lived bypass because that session was authenticated out of band.
func (l *L7RateLimiter) EvaluatePolicy(snapshot *l7RuntimeSnapshot, remoteIP, host, path, method string, now time.Time, bypassClient bool) (bool, string) {
	return l.evaluatePolicyWithBudget(snapshot, remoteIP, host, path, method, now, bypassClient, 0, 0)
}

// evaluatePolicyWithBudget applies an optional CMS-specific client bucket.
// A zero rate keeps the snapshot's configured client budget.
func (l *L7RateLimiter) evaluatePolicyWithBudget(snapshot *l7RuntimeSnapshot, remoteIP, host, path, method string, now time.Time, bypassClient bool, clientRatePerMinute, clientRateBurst int) (bool, string) {
	if l == nil || snapshot == nil {
		return true, ""
	}
	cfg := snapshot.cfg
	clientKey := remoteIP + "|" + strings.ToLower(host)
	// Every request consumes a token from exactly one finite bucket. Static reads
	// use a separate, higher per-IP budget instead of the historical blanket
	// exemption; dynamic routes and dynamic-looking suffixes always use the
	// normal client budget.
	if !bypassClient {
		if l7StaticAssetRequest(method, path) {
			staticRate, staticBurst := l7StaticAssetBudget(cfg.ClientRatePerMinute, cfg.ClientRateBurst)
			if !l.static.Allow(clientKey, l7Rate(staticRate), float64(staticBurst), now) {
				return false, "client-static"
			}
		} else {
			rate := cfg.ClientRatePerMinute
			burst := cfg.ClientRateBurst
			if clientRatePerMinute > 0 && clientRateBurst > 0 {
				rate = clientRatePerMinute
				burst = clientRateBurst
			}
			if !l.client.Allow(clientKey, l7Rate(rate), float64(burst), now) {
				return false, "client"
			}
		}
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

// l7StaticAssetBudget turns the dynamic client budget into the higher but
// finite static-asset budget. The result is positive and capped, so no
// configuration can turn it back into an exemption.
func l7StaticAssetBudget(baseRate, baseBurst int) (int, int) {
	rate := baseRate * l7StaticAssetBudgetFactor
	burst := baseBurst * l7StaticAssetBudgetFactor
	if baseRate <= 0 || rate < 1 {
		rate = 1
	}
	if baseBurst <= 0 || burst < 1 {
		burst = 1
	}
	if rate > l7StaticAssetRateCeiling {
		rate = l7StaticAssetRateCeiling
	}
	if burst > l7StaticAssetBurstCeiling {
		burst = l7StaticAssetBurstCeiling
	}
	return rate, burst
}

// l7StaticAssetRequest classifies one request for the bounded static-asset
// budget. The classification is deliberately narrow (FIND-021):
//
//   - only GET/HEAD, because a state-changing method is never a static read;
//   - the path must carry a static file extension, so "/storage/evil" is not a
//     static asset merely because it lives under a storage prefix;
//   - the path must live under a known static content prefix (or be a
//     root-level single-segment file), so an application route such as
//     "/api/user.css" cannot borrow the static budget with a suffix;
//   - dynamic server-side routes (.php/.cgi/...) never qualify even when they
//     look static, because they are executed, not read from disk.
func l7StaticAssetRequest(method, requestURI string) bool {
	switch method {
	case "GET", "HEAD":
	default:
		return false
	}
	path := requestURI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" || path[0] != '/' {
		return false
	}
	lower := strings.ToLower(path)
	if l7DynamicRoutePath(lower) {
		return false
	}
	if !l7StaticFileExtension(lower) {
		return false
	}
	for _, prefix := range []string{"/storage/", "/wp-content/", "/wp-includes/", "/assets/", "/static/", "/media/", "/uploads/"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	// A single path segment with a static extension (for example /favicon.ico or
	// /robots.txt) is a root-level static file. Application routes have at least
	// two segments and therefore never match.
	return strings.Count(strings.TrimPrefix(lower, "/"), "/") == 0
}

// l7DynamicRoutePath reports whether the path is served by an executable route
// rather than read from disk. Such paths never qualify for the static budget.
func l7DynamicRoutePath(lower string) bool {
	for _, suffix := range []string{".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".cgi", ".pl", ".py", ".rb", ".jsp", ".jspx", ".asp", ".aspx", ".do", ".action"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// l7StaticFileExtension lists the file extensions the static budget may cover.
// The list is closed on purpose: an unknown suffix keeps the normal client
// budget.
func l7StaticFileExtension(lower string) bool {
	dot := strings.LastIndexByte(lower, '.')
	if dot < 0 || dot < strings.LastIndexByte(lower, '/') {
		return false
	}
	switch lower[dot+1:] {
	case "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico",
		"woff", "woff2", "ttf", "otf", "eot", "bmp", "txt", "xml", "json", "pdf", "mp4", "webm":
		return true
	default:
		return false
	}
}
