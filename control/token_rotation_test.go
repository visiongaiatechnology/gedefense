// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestRotatingTheTokenEndsEveryExistingSession proves the property that makes a rotation worth
// anything: after the file is replaced, the old token is refused and the new one is accepted - in the
// running process, without a restart. Before the live re-read, the platform kept comparing against the
// copy it loaded at start-up, so a stolen token survived every rotation.
func TestRotatingTheTokenEndsEveryExistingSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.token")
	first, err := loadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	cfg.Dashboard.TokenFile = path
	server := &APIServer{cfg: cfg, token: first}

	called := false
	handler := server.auth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	authorize := func(token string) int {
		called = false
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code
	}

	if code := authorize(first); code != http.StatusOK || !called {
		t.Fatalf("the freshly created token was not accepted: %d", code)
	}

	second, err := RotateDashboardToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("the rotation produced the same token")
	}

	if code := authorize(first); code != http.StatusUnauthorized || called {
		t.Fatalf("the previous token still authenticated after the rotation: %d", code)
	}
	if code := authorize(second); code != http.StatusOK || !called {
		t.Fatalf("the new token was not accepted: %d", code)
	}

	// A token file that becomes unreadable must not lock the operator out: the last known
	// credential stays valid. Deleting the file grants no privilege - whoever can delete it
	// can read it - so this is the deliberate availability half of the trade-off, not a
	// bypass. The rotated credential is the last known one, so the start-up token stays
	// revoked even when the file disappears (strengthening the rotation, F-21).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if code := authorize(first); code != http.StatusUnauthorized {
		t.Fatalf("the revoked start-up token returned after the file was removed: %d", code)
	}
	if code := authorize(second); code != http.StatusOK {
		t.Fatalf("an unreadable token file revoked the last known credential: %d", code)
	}

	// And the rotation is repeatable: writing a fresh file is enough to take effect again.
	third, err := RotateDashboardToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if code := authorize(third); code != http.StatusOK {
		t.Fatalf("a rotation after a lost file did not take effect: %d", code)
	}
	if code := authorize(second); code != http.StatusUnauthorized {
		t.Fatalf("the previously known token survived a rotation: %d", code)
	}
}

// TestRotationBeforeFirstAuthenticatedRequestTakesEffect is F-21 / CHAIN-014: a rotation
// performed in the start-up window must revoke the old token, not be cached away. The
// start-up value used to be returned for the first authenticated request without reading
// the file, so the fresh token was rejected and the compromised old one stayed accepted
// until the next restart.
func TestRotationBeforeFirstAuthenticatedRequestTakesEffect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.token")
	startupToken, err := loadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.Dashboard.TokenFile = path
	server := &APIServer{cfg: cfg, token: startupToken}
	handler := server.auth(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	authorize := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code
	}

	// Rotate before the first authenticated request ever reaches the process.
	rotated, err := RotateDashboardToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == startupToken {
		t.Fatal("rotation produced the same token")
	}
	if code := authorize(startupToken); code != http.StatusUnauthorized {
		t.Fatalf("start-up token accepted after an early rotation: %d", code)
	}
	if code := authorize(rotated); code != http.StatusOK {
		t.Fatalf("freshly rotated token rejected after an early rotation: %d", code)
	}
}
