package main

import (
	"testing"
	"time"
)

// TestL7StaticAssetBudgetIsFiniteAndSeparate pins the FIND-021 fix: static reads
// are never exempt from the rate limiter, they draw from their own higher but
// finite per-client bucket. A media-heavy page may still burst above the dynamic
// budget, but the burst ends and dynamic routes keep their normal budget.
func TestL7StaticAssetBudgetIsFiniteAndSeparate(t *testing.T) {
	cfg := l7TestConfig()
	cfg.ClientRatePerMinute = 1
	cfg.ClientRateBurst = 1
	limiter := NewL7RateLimiter(cfg)
	snapshot := &l7RuntimeSnapshot{cfg: cfg}
	now := time.Now().UTC()

	staticRate, staticBurst := l7StaticAssetBudget(cfg.ClientRatePerMinute, cfg.ClientRateBurst)
	if staticRate <= cfg.ClientRatePerMinute || staticBurst <= cfg.ClientRateBurst {
		t.Fatalf("static budget is not higher than the dynamic budget: rate=%d burst=%d", staticRate, staticBurst)
	}
	if staticRate > l7StaticAssetRateCeiling || staticBurst > l7StaticAssetBurstCeiling {
		t.Fatalf("static budget exceeds its hard ceiling: rate=%d burst=%d", staticRate, staticBurst)
	}

	// A legitimate asset spike stays possible inside the static budget.
	for i := 0; i < staticBurst; i++ {
		if allowed, reason := limiter.Evaluate(snapshot, "203.0.113.44", "example.test", "/storage/2025/04/image-300x300.jpg", "GET", now); !allowed {
			t.Fatalf("legitimate asset spike request %d was limited: %s", i, reason)
		}
	}
	// ... but the budget is finite, so the same client cannot read forever.
	allowed, reason := limiter.Evaluate(snapshot, "203.0.113.44", "example.test", "/storage/2025/04/image-300x300.jpg", "GET", now)
	if allowed || reason != "client-static" {
		t.Fatalf("static bucket never ran out: allowed=%t reason=%q", allowed, reason)
	}

	// The dynamic budget was not consumed by the static burst: the first dynamic
	// request passes, the second hits the one-request dynamic burst.
	if allowed, reason := limiter.Evaluate(snapshot, "203.0.113.44", "example.test", "/wp-admin/post.php", "POST", now); !allowed {
		t.Fatalf("normal admin POST was blocked by the static bucket: %s", reason)
	}
	if allowed, reason := limiter.Evaluate(snapshot, "203.0.113.44", "example.test", "/wp-admin/post.php", "POST", now); allowed || reason != "client" {
		t.Fatalf("dynamic client rate limit stopped enforcing: allowed=%t reason=%q", allowed, reason)
	}
}

// TestL7RateLimiterDoesNotExemptBareStorageOrDynamicSuffixes is the negative
// half of FIND-021: the removed blanket exemption used to waive GET requests
// below /storage/, /wp-content/ and /wp-includes/ (even without a static
// extension) and every path with a static-looking suffix such as /api/user.css.
// Both now consume the normal client budget.
func TestL7RateLimiterDoesNotExemptBareStorageOrDynamicSuffixes(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"bare storage path", "GET", "/storage/evil"},
		{"dynamic route with static suffix", "GET", "/api/user.css"},
		{"unknown static prefix", "GET", "/app/theme.css"},
		{"executed php loader", "GET", "/wp-admin/load-styles.php?c=1&dir=ltr"},
		{"storage php file", "GET", "/storage/shell.php"},
		{"state-changing static suffix", "POST", "/storage/upload.jpg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := l7TestConfig()
			cfg.ClientRatePerMinute = 1
			cfg.ClientRateBurst = 1
			limiter := NewL7RateLimiter(cfg)
			snapshot := &l7RuntimeSnapshot{cfg: cfg}
			now := time.Now().UTC()
			if allowed, reason := limiter.Evaluate(snapshot, "198.51.100.7", "example.test", tc.path, tc.method, now); !allowed {
				t.Fatalf("%s %s was not admitted on its first request: %s", tc.method, tc.path, reason)
			}
			allowed, reason := limiter.Evaluate(snapshot, "198.51.100.7", "example.test", tc.path, tc.method, now)
			if allowed {
				t.Fatalf("%s %s bypassed the client rate limit", tc.method, tc.path)
			}
			if reason != "client" {
				t.Fatalf("%s %s was limited by %q, want the normal client bucket", tc.method, tc.path, reason)
			}
		})
	}
}

// TestL7StaticAssetClassificationIsNarrow documents the exact classification
// boundary: only static extensions below known static content prefixes (or a
// root-level single-segment file) qualify. Everything else uses the dynamic
// bucket even when it looks static.
func TestL7StaticAssetClassificationIsNarrow(t *testing.T) {
	static := []string{
		"/storage/2025/04/image-300x300.jpg",
		"/wp-content/plugins/editor/editor.js",
		"/wp-includes/css/dashicons.css",
		"/assets/app.js",
		"/static/site.webmanifest.css",
		"/uploads/photo.webp",
		"/favicon.ico",
		"/robots.txt",
	}
	for _, path := range static {
		if !l7StaticAssetRequest("GET", path) {
			t.Fatalf("%q should use the bounded static bucket", path)
		}
	}
	dynamic := []string{
		"/storage/evil",
		"/api/user.css",
		"/wp-admin/post.php",
		"/wp-admin/load-scripts.php",
		"/storage/shell.php",
		"/api/data.json",
		"/storage/file.unknown",
	}
	for _, path := range dynamic {
		if l7StaticAssetRequest("GET", path) {
			t.Fatalf("%q must not use the static bucket", path)
		}
	}
	if l7StaticAssetRequest("POST", "/storage/image.png") {
		t.Fatal("a state-changing method must never use the static bucket")
	}
}
