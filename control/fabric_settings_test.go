package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const fabricTestToken = "0123456789abcdef0123456789abcdef"

func fabricRequest(t *testing.T, server *APIServer, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+path, bytes.NewReader(body))
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+fabricTestToken)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-VGT-Request-ID", randomID()+randomID())
	}
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	return rec
}

func TestFabricSettingsKineticPreviewAndApply(t *testing.T) {
	server, store, _ := settingsAPIFixture(t)
	current := store.Get()
	kinetic := current.Kinetic
	kinetic.VelocityLimit = 23
	kinetic.ServicePortsAdmin = append(kinetic.ServicePortsAdmin, 9443)
	payload, _ := json.Marshal(map[string]interface{}{"expected_revision": current.Revision, "settings": kinetic})

	preview := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/kinetic/preview", payload)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var p FabricSettingsPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Valid || len(p.Diff) == 0 || p.CurrentRevision != current.Revision {
		t.Fatalf("unexpected preview: %+v", p)
	}
	if store.Get().Revision != current.Revision {
		t.Fatal("preview mutated runtime settings")
	}

	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/kinetic", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	updated := store.Get()
	if updated.Revision != current.Revision+1 || updated.Kinetic.VelocityLimit != 23 {
		t.Fatalf("kinetic update not persisted: %+v", updated.Kinetic)
	}
	service, _ := server.kinetic.ClassifyService(9443)
	if service != "admin_panel" {
		t.Fatalf("runtime service-port update not applied to Kinetic engine: %q", service)
	}
}

func TestFabricSettingsRejectsInvalidKineticThreshold(t *testing.T) {
	server, store, _ := settingsAPIFixture(t)
	current := store.Get()
	kinetic := current.Kinetic
	kinetic.VelocityLimit = 0
	payload, _ := json.Marshal(map[string]interface{}{"expected_revision": current.Revision, "settings": kinetic})
	rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/kinetic/preview", payload)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid Kinetic settings accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestFabricSettingsHistoryAndRollback(t *testing.T) {
	server, store, _ := settingsAPIFixture(t)
	original := store.Get()
	kinetic := original.Kinetic
	kinetic.IPThreshold = original.Kinetic.IPThreshold + 9
	payload, _ := json.Marshal(map[string]interface{}{"expected_revision": original.Revision, "settings": kinetic})
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/kinetic", payload); rec.Code != http.StatusOK {
		t.Fatalf("apply failed: %s", rec.Body.String())
	}
	if len(store.History()) == 0 || store.History()[0].Revision != original.Revision {
		t.Fatalf("history missing original revision: %+v", store.History())
	}
	rollbackBody, _ := json.Marshal(map[string]uint64{"revision": original.Revision})
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/rollback", rollbackBody); rec.Code != http.StatusOK {
		t.Fatalf("rollback failed: %d %s", rec.Code, rec.Body.String())
	}
	rolled := store.Get()
	if rolled.Kinetic.IPThreshold != original.Kinetic.IPThreshold || rolled.Revision <= original.Revision+1 {
		t.Fatalf("rollback did not create restored revision: %+v", rolled)
	}
}

func TestReleaseReadinessSerializesEmptyBlockersAsArray(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, fabricTestToken)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/release/readiness?target=canary", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"blockers":null`) {
		t.Fatalf("readiness must serialize empty blockers as []: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"blockers":[]`) {
		t.Fatalf("readiness response missing array blockers contract: %s", rec.Body.String())
	}
}

func TestFabricNetworkSettingsRejectEmptyManagementAllowlist(t *testing.T) {
	server, store, _ := settingsAPIFixture(t)
	current := store.Get()
	payload, _ := json.Marshal(map[string]interface{}{
		"expected_revision": current.Revision,
		"settings":          NetworkModuleSettings{Network: current.Network, ManagementAllowlist: []string{}},
	})
	rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/network/preview", payload)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty management allowlist accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestFabricNetworkAllowlistRemovalRestrictedOutsideObserve(t *testing.T) {
	server, store, release := settingsAPIFixture(t)
	current := store.Get()
	current.ManagementAllowlist = []string{"192.0.2.10/32", "198.51.100.10/32"}
	updated, err := store.Update(current)
	if err != nil {
		t.Fatal(err)
	}
	server.state.SetSettings(updated)
	server.state.SetAllowlistReady(true)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "exercise Fabric allowlist phase gate"); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"expected_revision": updated.Revision,
		"settings":          NetworkModuleSettings{Network: updated.Network, ManagementAllowlist: []string{"192.0.2.10/32"}},
	})
	rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/network", payload)
	if rec.Code != http.StatusConflict {
		t.Fatalf("allowlist removal outside Observe accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func currentXDRModuleSettings(settings RuntimeSettings) XDRModuleSettings {
	return XDRModuleSettings{
		Enabled: settings.XDREnabled, NetworkSensorEnabled: settings.NetworkSensorEnabled, BehaviorEnabled: settings.BehaviorEnabled,
		ScanIntervalMillis: settings.ScanIntervalMillis, NetworkIntervalSeconds: settings.NetworkIntervalSeconds,
		AlertScore: settings.AlertScore, ContainScore: settings.ContainScore, KillScore: settings.KillScore,
		EnabledRuleModules: append([]string(nil), settings.EnabledRuleModules...), CustomRules: append([]CustomRule(nil), settings.CustomRules...),
		Advanced: cloneXDRFabricSettings(settings.XDRFabric),
	}
}

func TestFabricXDRPreviewMarksRestartSettings(t *testing.T) {
	server, store, _ := settingsAPIFixture(t)
	current := store.Get()
	xdr := currentXDRModuleSettings(current)
	xdr.Advanced.WorkerCount++
	payload, _ := json.Marshal(map[string]interface{}{"expected_revision": current.Revision, "settings": xdr})
	preview := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/xdr/preview", payload)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview failed: %d %s", preview.Code, preview.Body.String())
	}
	var parsed FabricSettingsPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.RequiresRestart {
		t.Fatalf("worker-count change was not marked restart-required: %+v", parsed)
	}
	found := false
	for _, diff := range parsed.Diff {
		if diff.Key == "advanced.worker_count" && diff.ApplyClass == "RESTART" {
			found = true
		}
	}
	if !found {
		t.Fatalf("nested restart diff was not flattened correctly: %+v", parsed.Diff)
	}
	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/xdr", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply failed in Observe: %d %s", apply.Code, apply.Body.String())
	}
	var view FabricModuleView
	if err := json.Unmarshal(apply.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.ApplyState != "restart_required" {
		t.Fatalf("restart-class XDR revision reported %q", view.ApplyState)
	}
}

func TestFabricXDRRuleWiringRestrictedOutsideObserve(t *testing.T) {
	server, store, release := settingsAPIFixture(t)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "exercise XDR Fabric rule boundary"); err != nil {
		t.Fatal(err)
	}
	current := store.Get()
	xdr := currentXDRModuleSettings(current)
	xdr.Advanced.RuleOverrides = []XDRRuleOverride{{ID: "KD.LINUX.REVERSE_SHELL", Enabled: false, Score: 105}}
	payload, _ := json.Marshal(map[string]interface{}{"expected_revision": current.Revision, "settings": xdr})
	rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/xdr", payload)
	if rec.Code != http.StatusConflict {
		t.Fatalf("XDR rule wiring changed outside Observe/Degraded: %d %s", rec.Code, rec.Body.String())
	}
}
