package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReleaseAPIRejectsSkippedPhaseAndAcceptsCanary(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, "0123456789abcdef0123456789abcdef")
	call := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/release/transition", bytes.NewBufferString(body))
		req.Host = "127.0.0.1"
		req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-VGT-Request-ID", randomID()+randomID())
		rec := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := call(`{"target":"enforce","confirmation":"PROMOTE:ENFORCE","reason":"direct promotion must be rejected"}`); rec.Code != http.StatusConflict {
		t.Fatalf("direct enforce status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := call(`{"target":"canary","confirmation":"PROMOTE:CANARY","reason":"start controlled beta canary"}`); rec.Code != http.StatusOK {
		t.Fatalf("canary status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReadinessReflectsEmergencyStop(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, "0123456789abcdef0123456789abcdef")
	if _, err := release.EmergencyStop("test emergency stop blocks readiness"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/readyz", nil)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:45678"
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
