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

	// A token file that becomes unreadable must not lock the operator out: the credential the process
	// started with stays valid. Deleting the file grants no privilege - whoever can delete it can read
	// it - so this is the deliberate availability half of the trade-off, not a bypass.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if code := authorize(first); code != http.StatusOK {
		t.Fatalf("an unreadable token file locked the operator out: %d", code)
	}
	if code := authorize(second); code != http.StatusUnauthorized {
		t.Fatalf("the rotated token stayed valid after its file was removed: %d", code)
	}

	// And the rotation is repeatable: writing a fresh file is enough to take effect again.
	third, err := RotateDashboardToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if code := authorize(third); code != http.StatusOK {
		t.Fatalf("a rotation after a lost file did not take effect: %d", code)
	}
	if code := authorize(first); code != http.StatusUnauthorized {
		t.Fatalf("the start-up token survived a rotation: %d", code)
	}
}
