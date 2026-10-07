package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestThreatIntelStatusAPIContractMatchesDashboard(t *testing.T) {
	cfg := defaultConfig()
	feeds := NewFeedManager(FeedConfig{MaxEntries: 1000}, t.TempDir())
	feeds.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.7/32"}
	feeds.feedStates["feodo-c2"].LastGoodCount = 1
	feeds.feedStates["feodo-c2"].LastGoodGen = 1
	if _, _, err := feeds.ApplyToKernel(nil, nil); err != nil {
		t.Fatal(err)
	}

	server := NewAPIServer(cfg, NewState("test", cfg), nil, feeds, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/feeds/status", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	server.http.Handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("feed status endpoint returned %d: %s", recorder.Code, recorder.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"overall_status", "last_attempt_at", "last_successful_sync_at", "last_partial_successful_sync_at", "last_fully_successful_sync_at",
		"kernel_apply_status", "kernel_apply_last_at", "kernel_generation", "last_kernel_added", "last_kernel_deleted", "generation", "fingerprint", "block_vectors", "correlate_vectors",
		"annotate_vectors", "total_vectors", "feeds",
	} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("dashboard feed contract field %q missing from top-level response: %v", key, payload)
		}
	}
	if payload["kernel_apply_status"] != kernelApplyApplied {
		t.Fatalf("kernel apply status=%v want=%s", payload["kernel_apply_status"], kernelApplyApplied)
	}
	if Number, ok := payload["kernel_generation"].(float64); !ok || uint64(Number) != feeds.Generation() {
		t.Fatalf("kernel generation=%v want=%d", payload["kernel_generation"], feeds.Generation())
	}
	feedsPayload, ok := payload["feeds"].([]any)
	if !ok || len(feedsPayload) == 0 {
		t.Fatalf("feeds list missing or malformed: %#v", payload["feeds"])
	}
}
