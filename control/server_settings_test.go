// STATUS: PLATIN
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func settingsAPIFixture(t *testing.T) (*APIServer, *SettingsStore, *ReleaseController) {
	t.Helper()
	cfg, state, policy, release := betaReleaseFixture(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	settings, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, settings, "0123456789abcdef0123456789abcdef")
	return server, settings, release
}

func putSettings(t *testing.T, server *APIServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1/api/v1/settings", bytes.NewBufferString(body))
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VGT-Request-ID", randomID()+randomID())
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	return rec
}

func TestSettingsAPIRejectsStaleRevision(t *testing.T) {
	server, settings, _ := settingsAPIFixture(t)
	staleRevision := settings.Get().Revision + 1
	body := `{"revision":` + uintString(staleRevision) + `,"alert_score":41}`
	if rec := putSettings(t, server, body); rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSettingsAPIRestrictsRuleWiringToObserveOrDegraded(t *testing.T) {
	server, settings, release := settingsAPIFixture(t)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "verify settings phase boundary"); err != nil {
		t.Fatal(err)
	}
	current := settings.Get()
	body := `{"revision":` + uintString(current.Revision) + `,"enabled_rule_modules":["baseline","command"]}`
	if rec := putSettings(t, server, body); rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func uintString(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	index := len(buf)
	for value > 0 {
		index--
		buf[index] = digits[value%10]
		value /= 10
	}
	return string(buf[index:])
}
