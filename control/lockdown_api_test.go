// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3 API tests: authentication, replay, the dedicated trigger
// budget, the status projection bounds and the documented 400/403/409/429/503
// matrix of the four routes. The fake core from lockdown_test.go answers the
// VGT3 wire so the engine path is exercised end to end.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const lockdownTestToken = fabricTestToken

func newLockdownAPIFixture(t *testing.T, enabled bool, mutate func(*LockdownFabricSettings)) (*APIServer, *lockdownFixture) {
	t.Helper()
	fixture := newLockdownFixture(t, enabled, mutate)
	server := NewAPIServer(defaultConfig(), fixture.state, nil, nil, nil, nil, nil, fixture.store, lockdownTestToken)
	server.AttachLockdown(fixture.engine)
	return server, fixture
}

// lockdownAPIRequest is the exact request fabricRequest would send, with a
// caller-chosen request id so replay behaviour is testable.
func lockdownAPIRequest(t *testing.T, server *APIServer, method, path string, body []byte, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+path, bytes.NewReader(body))
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+lockdownTestToken)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if requestID != "" {
		req.Header.Set("X-VGT-Request-ID", requestID)
	}
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	return rec
}

func TestLockdownAPIAuthAndReplayAndTriggerBudget(t *testing.T) {
	server, fixture := newLockdownAPIFixture(t, true, nil)
	body := []byte(`{"confirmation":"TRIGGER LOCKDOWN","reason":"operator pressed the emergency trigger"}`)

	// No bearer credential: the route is closed like every other operator surface.
	anon := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/lockdown/trigger", bytes.NewReader(body))
	anon.Host = "127.0.0.1"
	anon.Header.Set("Content-Type", "application/json")
	anonRecorder := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(anonRecorder, anon)
	if anonRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated trigger answered %d", anonRecorder.Code)
	}
	anonStatus := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/lockdown/status", nil)
	anonStatus.Host = "127.0.0.1"
	anonStatusRecorder := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(anonStatusRecorder, anonStatus)
	if anonStatusRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status answered %d", anonStatusRecorder.Code)
	}

	first := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/trigger", body, "req-lockdown-00000001")
	if first.Code != http.StatusOK {
		t.Fatalf("first trigger answered %d: %s", first.Code, first.Body.String())
	}
	if !fixture.engine.StatusView().Latched {
		t.Fatal("the trigger did not latch the engine")
	}
	// The replay guard is the one s.auth applies to every mutation, with the same
	// request id: a replayed refresh of the request must be refused.
	replay := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/trigger", body, "req-lockdown-00000001")
	if replay.Code != http.StatusConflict {
		t.Fatalf("replayed trigger answered %d", replay.Code)
	}
	// A genuinely new request is refused by the dedicated 1/min budget instead.
	second := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/trigger", body, "req-lockdown-00000002")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("a second trigger within a minute answered %d", second.Code)
	}
}

func TestLockdownAPIStatusIsBoundedAndSecretFree(t *testing.T) {
	duressPath := "/etc/vgt/gedefense/duress.token"
	server, _ := newLockdownAPIFixture(t, true, func(settings *LockdownFabricSettings) {
		settings.DuressTokenPath = duressPath
	})
	rec := lockdownAPIRequest(t, server, http.MethodGet, "/api/v1/lockdown/status", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() > 16<<10 {
		t.Fatalf("status payload is not bounded: %d bytes", rec.Body.Len())
	}
	var view LockdownStatusView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("status is not the documented document: %v", err)
	}
	if !view.Enabled || view.State != lockdownStateDisarmed || view.Settings.CellScope != lockdownCellScopeAll {
		t.Fatalf("unexpected status projection: %+v", view)
	}
	if !view.DuressConfigured {
		t.Fatal("the configured duress path was not reported as a flag")
	}
	if strings.Contains(rec.Body.String(), duressPath) || strings.Contains(rec.Body.String(), "token\":") {
		t.Fatal("the status projection disclosed the duress path or a token")
	}
	// /api/v1/status attaches the projection additively.
	full := lockdownAPIRequest(t, server, http.MethodGet, "/api/v1/status", nil, "")
	var document map[string]json.RawMessage
	if err := json.Unmarshal(full.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if _, ok := document["lockdown"]; !ok {
		t.Fatal("/api/v1/status does not carry the additive lockdown field")
	}
}

func TestLockdownAPIArmTriggerClearFlow(t *testing.T) {
	server, fixture := newLockdownAPIFixture(t, true, nil)

	arm := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/arm", []byte(`{"mode":"locked","reason":"operator arms the kernel policy"}`), "req-arm-00000001")
	if arm.Code != http.StatusOK {
		t.Fatalf("arm answered %d: %s", arm.Code, arm.Body.String())
	}
	if fixture.engine.StatusView().State != lockdownStateArmed {
		t.Fatal("arm did not reach the armed state")
	}
	badMode := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/arm", []byte(`{"mode":"maybe","reason":"operator arms the kernel policy"}`), "req-arm-00000002")
	if badMode.Code != http.StatusBadRequest {
		t.Fatalf("an unknown mode was accepted with %d", badMode.Code)
	}

	// The confirmation phrase proves intent: a wrong one is an authority-shaped
	// mistake and never reaches the engine.
	wrongConfirm := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/trigger", []byte(`{"confirmation":"lockdown","reason":"operator pressed the emergency trigger"}`), "req-trigger-00000001")
	if wrongConfirm.Code != http.StatusForbidden {
		t.Fatalf("a wrong confirmation answered %d", wrongConfirm.Code)
	}
	trigger := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/trigger", []byte(`{"confirmation":"TRIGGER LOCKDOWN","reason":"operator pressed the emergency trigger","source":"manual"}`), "req-trigger-00000002")
	if trigger.Code != http.StatusOK {
		t.Fatalf("trigger answered %d: %s", trigger.Code, trigger.Body.String())
	}
	view := fixture.engine.StatusView()
	if !view.Latched || view.State != lockdownStateActive || !validLockdownEpoch(view.Epoch) {
		t.Fatalf("trigger did not latch with a valid epoch: %+v", view)
	}

	wrongClear := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/clear", []byte(`{"confirmation":"CLEAR LOCKDOWN","reason":"operator releases the lockdown","expected_epoch":"`+view.Epoch+`"}`), "req-clear-00000001")
	if wrongClear.Code != http.StatusForbidden {
		t.Fatalf("a wrong clear confirmation answered %d", wrongClear.Code)
	}
	wrongEpoch := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/clear", []byte(`{"confirmation":"CLEAR:LOCKDOWN","reason":"operator releases the lockdown","expected_epoch":"deadbeef"}`), "req-clear-00000002")
	if wrongEpoch.Code != http.StatusConflict {
		t.Fatalf("a wrong epoch answered %d", wrongEpoch.Code)
	}
	if !fixture.engine.StatusView().Latched {
		t.Fatal("a rejected clear released the latch")
	}
	badEpochShape := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/clear", []byte(`{"confirmation":"CLEAR:LOCKDOWN","reason":"operator releases the lockdown","expected_epoch":"xyz"}`), "req-clear-00000003")
	if badEpochShape.Code != http.StatusBadRequest {
		t.Fatalf("a malformed epoch answered %d", badEpochShape.Code)
	}
	shortReason := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/clear", []byte(`{"confirmation":"CLEAR:LOCKDOWN","reason":"x","expected_epoch":"`+view.Epoch+`"}`), "req-clear-00000004")
	if shortReason.Code != http.StatusBadRequest {
		t.Fatalf("a too-short reason answered %d", shortReason.Code)
	}
	trailing := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/clear", []byte(`{"confirmation":"CLEAR:LOCKDOWN","reason":"operator releases the lockdown","expected_epoch":"`+view.Epoch+`","extra":true}`), "req-clear-00000005")
	if trailing.Code != http.StatusBadRequest {
		t.Fatalf("an unknown JSON field answered %d", trailing.Code)
	}
	clear := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/clear", []byte(`{"confirmation":"CLEAR:LOCKDOWN","reason":"operator releases the lockdown","expected_epoch":"`+view.Epoch+`"}`), "req-clear-00000006")
	if clear.Code != http.StatusOK {
		t.Fatalf("clear answered %d: %s", clear.Code, clear.Body.String())
	}
	if fixture.engine.StatusView().Latched {
		t.Fatal("the clear did not release the latch")
	}
	// The core really received the compare-set clear with the reported epoch.
	if fixture.core.count("LOCKDOWN_CLEAR") != 1 {
		t.Fatalf("core clear was not issued exactly once: %d", fixture.core.count("LOCKDOWN_CLEAR"))
	}
}

func TestLockdownAPICapabilityMissingCore(t *testing.T) {
	server, fixture := newLockdownAPIFixture(t, true, nil)
	fixture.core.setHandler(capabilityMissingCoreHandler)
	// Arming without a kernel that can arm is refused; it is never reported as armed.
	arm := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/arm", []byte(`{"mode":"locked","reason":"operator arms the kernel policy"}`), "req-arm-cm-00000001")
	if arm.Code != http.StatusServiceUnavailable {
		t.Fatalf("arm against a capability-missing core answered %d", arm.Code)
	}
	if fixture.engine.StatusView().State != lockdownStateDisarmed {
		t.Fatal("a refused arm still changed the state")
	}
	// The trigger latches regardless (the Go latch and the cell phase are local
	// capabilities) but the kernel phases are honestly unavailable.
	trigger := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/trigger", []byte(`{"confirmation":"TRIGGER LOCKDOWN","reason":"operator pressed the emergency trigger"}`), "req-trigger-cm-00000001")
	if trigger.Code != http.StatusOK {
		t.Fatalf("trigger against a capability-missing core answered %d: %s", trigger.Code, trigger.Body.String())
	}
	view := fixture.engine.StatusView()
	if !view.Latched || view.Core.Capability != "missing" {
		t.Fatalf("the missing capability was not reported: %+v", view)
	}
	if lockdownPhaseStatus(view.Phases, lockdownPhaseNameNet) != lockdownPhaseUnavailable {
		t.Fatalf("a missing core phase was overclaimed: %+v", view.Phases)
	}
	// A core that holds nothing must not trap the operator in the latch.
	clear := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/clear", []byte(`{"confirmation":"CLEAR:LOCKDOWN","reason":"operator releases the lockdown","expected_epoch":"`+view.Epoch+`"}`), "req-clear-cm-00000001")
	if clear.Code != http.StatusOK {
		t.Fatalf("clear after a capability loss answered %d: %s", clear.Code, clear.Body.String())
	}
}

func TestLockdownAPIDisabledAndUnwired(t *testing.T) {
	server, _ := newLockdownAPIFixture(t, false, nil)
	trigger := lockdownAPIRequest(t, server, http.MethodPost, "/api/v1/lockdown/trigger", []byte(`{"confirmation":"TRIGGER LOCKDOWN","reason":"operator pressed the emergency trigger"}`), "req-disabled-00000001")
	if trigger.Code != http.StatusConflict {
		t.Fatalf("a disabled engine accepted a trigger with %d", trigger.Code)
	}
	status := lockdownAPIRequest(t, server, http.MethodGet, "/api/v1/lockdown/status", nil, "")
	if status.Code != http.StatusOK {
		t.Fatalf("disabled status answered %d", status.Code)
	}
	var view LockdownStatusView
	if err := json.Unmarshal(status.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Enabled || view.Latched {
		t.Fatalf("a disabled engine reported an active state: %+v", view)
	}
	// A server without a wired engine answers honestly instead of dereferencing.
	bare := NewAPIServer(defaultConfig(), NewState("test", defaultConfig()), nil, nil, nil, nil, nil, nil, lockdownTestToken)
	unwired := lockdownAPIRequest(t, bare, http.MethodGet, "/api/v1/lockdown/status", nil, "")
	if unwired.Code != http.StatusOK || !strings.Contains(unwired.Body.String(), "unavailable") {
		t.Fatalf("an unwired server answered %d: %s", unwired.Code, unwired.Body.String())
	}
}

func TestLockdownAPIEvidenceGateExemption(t *testing.T) {
	// The trigger and the clear are the documented way out of a degraded audit
	// condition; the arm is an ordinary mutation and stays gated.
	for _, path := range []string{"/api/v1/lockdown/trigger", "/api/v1/lockdown/clear"} {
		if !evidenceGateExempt(path) {
			t.Errorf("%s is gated behind the condition it may have to resolve", path)
		}
	}
	// Everything else stays gated; the audit guarantee must not have been widened.
	for _, path := range []string{"/api/v1/lockdown/arm", "/api/v1/lockdown/status", "/api/v1/blocks"} {
		if evidenceGateExempt(path) {
			t.Errorf("%s was exempted from the evidence gate", path)
		}
	}
}

// TestLockdownSettingsModuleAPI covers the Fabric settings integration: the
// namespace is readable, an enabling revision is persisted and projected live by
// the engine, and a revision that enables the lockdown without any phase is
// rejected by the same validation the engine relies on.
func TestLockdownSettingsModuleAPI(t *testing.T) {
	// The settings surface needs the release controller (phase guards), so this
	// fixture wires it exactly like settingsAPIFixture does.
	fixture := newLockdownFixture(t, false, nil)
	cfg, _, _, release := betaReleaseFixture(t)
	release.settings = fixture.store
	server := NewAPIServer(cfg, fixture.state, nil, nil, nil, nil, release, fixture.store, lockdownTestToken)
	server.AttachLockdown(fixture.engine)
	get := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/lockdown", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("lockdown settings module answered %d: %s", get.Code, get.Body.String())
	}
	var view FabricModuleView
	if err := json.Unmarshal(get.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	current := fixture.store.Get()
	if view.Module != "lockdown" || view.ApplyState != "disabled" {
		t.Fatalf("unexpected module view: %+v", view)
	}
	if view.Migrations == nil && current.Lockdown == nil {
		t.Fatal("the lockdown namespace is not part of the settings document")
	}

	enabled := *current.Lockdown
	enabled.Enabled = true
	payload, _ := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": enabled})
	put := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/lockdown", payload)
	if put.Code != http.StatusOK {
		t.Fatalf("enabling the lockdown namespace answered %d: %s", put.Code, put.Body.String())
	}
	if !fixture.engine.StatusView().Enabled {
		t.Fatal("the engine did not observe the persisted namespace live")
	}
	if applied := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/lockdown", nil); applied.Code != http.StatusOK {
		t.Fatalf("updated module answered %d", applied.Code)
	} else {
		var updated FabricModuleView
		if err := json.Unmarshal(applied.Body.Bytes(), &updated); err != nil {
			t.Fatal(err)
		}
		if updated.ApplyState != "applied" {
			t.Fatalf("an enabled namespace reported %q", updated.ApplyState)
		}
	}

	// Enabling with every phase disabled is exactly the attrappe §9 forbids.
	noPhases := enabled
	noPhases.NetworkLockdown, noPhases.FreezeProcesses, noPhases.FreezeBrokers = false, false, false
	noPhases.FreezeCells, noPhases.FreezeParserCells, noPhases.HardeningApply = false, false, false
	revision := fixture.store.Get().Revision
	payload, _ = json.Marshal(map[string]any{"expected_revision": revision, "settings": noPhases})
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/lockdown", payload); rec.Code != http.StatusBadRequest {
		t.Fatalf("a phase-less enabling revision answered %d: %s", rec.Code, rec.Body.String())
	}
}
