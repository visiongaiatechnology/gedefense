// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAntispywareStatusAndUIBuild(t *testing.T) {
	cfg := isolatedTokenConfig(t, "test-token-123456")
	cfg.Dashboard.AllowedHosts = []string{"127.0.0.1", "localhost"}
	state := NewState(version, cfg)
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "test-token-123456")

	// Unauthenticated /livez must never expose version or ui_build (G-WEB-05).
	recLive := httptest.NewRecorder()
	reqLive := httptest.NewRequest(http.MethodGet, "/livez", nil)
	reqLive.Host = "127.0.0.1:8188"
	server.http.Handler.ServeHTTP(recLive, reqLive)
	if recLive.Code != http.StatusOK {
		t.Fatalf("/livez status=%d", recLive.Code)
	}
	var liveBody map[string]any
	if err := json.Unmarshal(recLive.Body.Bytes(), &liveBody); err != nil {
		t.Fatalf("/livez decode: %v", err)
	}
	if _, exists := liveBody["ui_build"]; exists {
		t.Fatal("/livez leaked ui_build")
	}

	// Authenticated /api/v1/status must carry version and non-empty ui_build.
	recStatus := httptest.NewRecorder()
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	reqStatus.Host = "127.0.0.1:8188"
	reqStatus.Header.Set("Authorization", "Bearer test-token-123456")
	server.http.Handler.ServeHTTP(recStatus, reqStatus)
	if recStatus.Code != http.StatusOK {
		t.Fatalf("/api/v1/status code=%d body=%s", recStatus.Code, recStatus.Body.String())
	}
	var snap Snapshot
	if err := json.Unmarshal(recStatus.Body.Bytes(), &snap); err != nil {
		t.Fatalf("/api/v1/status decode: %v", err)
	}
	if snap.Version != version {
		t.Fatalf("version=%q want %q", snap.Version, version)
	}
	if snap.UIBuild == "" || snap.UIBuild == "---" {
		t.Fatalf("expected real ui_build, got %q", snap.UIBuild)
	}

	// Unauthenticated GET /api/v1/antispyware/status must reject with 401.
	recUnauth := httptest.NewRecorder()
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/v1/antispyware/status", nil)
	reqUnauth.Host = "127.0.0.1:8188"
	server.http.Handler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated antispyware status=%d want 401", recUnauth.Code)
	}

	// Authenticated GET /api/v1/antispyware/status exposes all antispyware planes cleanly.
	recAnti := httptest.NewRecorder()
	reqAnti := httptest.NewRequest(http.MethodGet, "/api/v1/antispyware/status", nil)
	reqAnti.Host = "127.0.0.1:8188"
	reqAnti.Header.Set("Authorization", "Bearer test-token-123456")
	server.http.Handler.ServeHTTP(recAnti, reqAnti)
	if recAnti.Code != http.StatusOK {
		t.Fatalf("antispyware status code=%d body=%s", recAnti.Code, recAnti.Body.String())
	}
	var anti map[string]any
	if err := json.Unmarshal(recAnti.Body.Bytes(), &anti); err != nil {
		t.Fatalf("antispyware decode: %v", err)
	}
	for _, key := range []string{
		"summary", "self_guard", "exec_inode", "bpf_guard", "cross_view",
		"kernel_hooks", "persistence", "dns", "styx_phase2", "sbc_fusion",
		"sec_crit", "credential_guard", "ransom", "titan_exec", "chameleon", "lpe_guard",
	} {
		if _, ok := anti[key]; !ok {
			t.Fatalf("missing key %q in /api/v1/antispyware/status", key)
		}
	}
}
