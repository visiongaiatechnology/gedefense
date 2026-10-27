package main

import (
	"testing"
	"time"
)

func TestL7ClientRateLimiterDoesNotConsumeStaticOrAdminLoaderRequests(t *testing.T) {
	cfg := l7TestConfig()
	cfg.ClientRatePerMinute = 1
	cfg.ClientRateBurst = 1
	limiter := NewL7RateLimiter(cfg)
	snapshot := &l7RuntimeSnapshot{cfg: cfg}
	now := time.Now().UTC()

	for _, path := range []string{
		"/storage/2025/04/image-300x300.jpg",
		"/wp-content/plugins/editor/editor.js",
		"/wp-includes/css/dashicons.css",
		"/wp-admin/load-styles.php?c=1&dir=ltr",
		"/wp-admin/load-scripts.php?c=1&load=jquery",
	} {
		allowed, reason := limiter.Evaluate(snapshot, "203.0.113.44", "example.test", path, "GET", now)
		if !allowed {
			t.Fatalf("static/admin loader request %q consumed the client budget: %s", path, reason)
		}
	}

	// The limiter still protects dynamic requests: the first dynamic request
	// passes, the second exceeds the one-request burst.
	if allowed, reason := limiter.Evaluate(snapshot, "203.0.113.44", "example.test", "/wp-admin/post.php", "POST", now); !allowed {
		t.Fatalf("normal admin POST was blocked: %s", reason)
	}
	if allowed, reason := limiter.Evaluate(snapshot, "203.0.113.44", "example.test", "/wp-admin/post.php", "POST", now); allowed || reason != "client" {
		t.Fatalf("dynamic client rate limit stopped enforcing: allowed=%t reason=%q", allowed, reason)
	}
}
