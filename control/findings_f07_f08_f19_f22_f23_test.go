// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- F-07 / CHAIN-003

func startupSecurityFixture(t *testing.T) (Config, *State, *PolicyStore, *releaseCoreStub, *ReleaseController) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Policy.StorageKeyFile = ""
	cfg.Node.Name = "startup-security-test"
	cfg.Release.MinimumObserveSeconds = 0
	cfg.Release.MinimumCanarySeconds = 0
	cfg.Release.EmergencyStopFile = filepath.Join(dir, "EMERGENCY_STOP")
	cfg.Policy.StateFile = filepath.Join(dir, "policy.json")
	cfg.Policy.SigningKeyFile = filepath.Join(dir, "policy.key")
	cfg.Policy.PublicKeyFile = filepath.Join(dir, "policy.pub")
	state := NewState("test", cfg)
	policy, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	state.SetCore(true, "native")
	core := &releaseCoreStub{}
	release := NewReleaseController(cfg, state, core, policy, nil)
	return cfg, state, policy, core, release
}

// TestStartupWithUnverifiablePolicyRetainsKernelEnforcement is F-07 / CHAIN-003: an
// unverifiable policy is not an observe intent. The kernel blocklist must be retained and the
// platform must report degraded, never "verified empty".
func TestStartupWithUnverifiablePolicyRetainsKernelEnforcement(t *testing.T) {
	_, state, _, core, release := startupSecurityFixture(t)
	target := "203.0.113.7/32"
	if _, err := state.AddBlock(target, "retained enforcement", "manual", time.Hour, false, 1024); err != nil {
		t.Fatal(err)
	}
	if err := release.InitializeStartup("", false); err != nil {
		t.Fatalf("startup with an unverifiable policy failed: %v", err)
	}
	if core.clearCount() != 0 {
		t.Fatal("startup with an unverifiable policy released the kernel blocklist")
	}
	if targets := core.addedTargets(); len(targets) == 0 || !strings.Contains(strings.Join(targets, ","), target) {
		t.Fatalf("retained block was not re-asserted: %v", targets)
	}
	status := release.Status()
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("phase=%q, want degraded", status.Phase)
	}
	if status.KernelPolicyState != "verified-enforce" {
		t.Fatalf("kernel policy state=%q, want verified-enforce", status.KernelPolicyState)
	}
}

// TestCorruptPolicyDoesNotReleaseKernelOnRestart drives the whole sequence: a verified
// enforcement policy on disk, a corrupt state file with no recoverable last-known-good, and
// a restart that must retain rather than release.
func TestCorruptPolicyDoesNotReleaseKernelOnRestart(t *testing.T) {
	cfg, state, policy, core, release := startupSecurityFixture(t)
	if _, err := state.AddBlock("198.51.100.9/32", "restart retention", "manual", time.Hour, false, 1024); err != nil {
		t.Fatal(err)
	}
	if err := persistPolicy(policy, cfg, state); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Policy.StateFile, []byte("{corrupt-policy-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.Policy.StateFile + ".lastgood"); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := policy.Load(); err == nil {
		t.Fatal("corrupt policy state was accepted as verified")
	}
	if err := release.InitializeStartup("", policy.Status().Verified); err != nil {
		t.Fatalf("startup after a corrupt policy failed: %v", err)
	}
	if core.clearCount() != 0 {
		t.Fatal("a corrupt policy allowed the kernel blocklist to be released on restart")
	}
	if status := release.Status(); status.Phase != ReleasePhaseDegraded {
		t.Fatalf("phase=%q, want degraded", status.Phase)
	}
}

func policySecurityFixture(t *testing.T) (Config, *PolicyStore) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Policy.StorageKeyFile = ""
	cfg.Node.Name = "policy-security-test"
	cfg.Policy.StateFile = filepath.Join(dir, "policy.json")
	cfg.Policy.SigningKeyFile = filepath.Join(dir, "policy.key")
	cfg.Policy.PublicKeyFile = filepath.Join(dir, "policy.pub")
	policy, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, policy
}

// TestPolicyGenerationFloorRisesAutomatically is G-STATE-02: persisting a new generation pins
// the floor, so replaying an older signed document is refused even without an administrable
// setting, and the floor survives a restart through its own authenticated anchor.
func TestPolicyGenerationFloorRisesAutomatically(t *testing.T) {
	cfg, policy := policySecurityFixture(t)
	if err := policy.Persist(cfg.Node.Name, "observe", "observe", nil); err != nil {
		t.Fatal(err)
	}
	firstDocument, err := os.ReadFile(cfg.Policy.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(); err != nil {
		t.Fatal(err)
	}
	if err := policy.Persist(cfg.Node.Name, "enforce", "observe", nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := policy.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Generation < 2 {
		t.Fatalf("generation did not advance: %d", loaded.Generation)
	}
	if floor := policy.Status().MinimumGeneration; floor < loaded.Generation {
		t.Fatalf("floor %d did not track the persisted generation %d", floor, loaded.Generation)
	}

	// Replay the older, validly signed generation-1 document.
	if err := os.WriteFile(cfg.Policy.StateFile, firstDocument, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(); err == nil {
		t.Fatal("a replayed older signed policy document was accepted")
	}

	// The floor is persisted independently of the process: a restarted store refuses it too.
	restarted, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Load(); err == nil {
		t.Fatal("a restarted policy store accepted the replayed older document")
	}
}

// TestPolicyLastKnownGoodRecoversEnforcementIntent is the recovery half of F-07: damaging the
// current state file must not turn an enforcement intent into an observe intent.
func TestPolicyLastKnownGoodRecoversEnforcementIntent(t *testing.T) {
	cfg, policy := policySecurityFixture(t)
	if err := policy.Persist(cfg.Node.Name, "enforce", "observe", nil); err != nil {
		t.Fatal(err)
	}
	// Deleting the current file (an availability/targeted-deletion case, not a tampered
	// document) is recovered from the signed last-known-good intent.
	if err := os.Remove(cfg.Policy.StateFile); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := restarted.Load()
	if err != nil {
		t.Fatalf("last-known-good recovery failed: %v", err)
	}
	if envelope.Enforcement != "enforce" {
		t.Fatalf("recovered enforcement=%q, want enforce", envelope.Enforcement)
	}
	if !restarted.LastLoadRecovered() || !restarted.Status().Verified {
		t.Fatal("recovery was not reported as a verified last-known-good load")
	}
}

// TestMissingPolicyStateAboveFloorIsUnverifiable: deleting the state and its recovery copy
// must not look like a fresh install while a generation floor anchor exists.
func TestMissingPolicyStateAboveFloorIsUnverifiable(t *testing.T) {
	cfg, policy := policySecurityFixture(t)
	if err := policy.Persist(cfg.Node.Name, "enforce", "observe", nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{cfg.Policy.StateFile, cfg.Policy.StateFile + ".lastgood"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	restarted, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Load(); err == nil {
		t.Fatal("a deleted policy state above a persisted floor was accepted as a fresh install")
	}
	if restarted.Status().Verified {
		t.Fatal("status reports a verified policy after the state was deleted")
	}
}

// ---------------------------------------------------------------- F-08 / CHAIN-006

func authBudgetServer(t *testing.T) (*APIServer, http.HandlerFunc) {
	t.Helper()
	cfg := isolatedTokenConfig(t, fabricTestToken)
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, fabricTestToken)
	sink := server.auth(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return server, sink
}

func authBudgetRequest(handler http.HandlerFunc, token, sessionHeader string) int {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:40404"
	req.Host = "127.0.0.1"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionHeader != "" {
		req.Header.Set(gatewaySessionHeader, sessionHeader)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec.Code
}

func attestedSessionHeader(token, sessionID string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(gatewaySessionDomain))
	mac.Write([]byte(sessionID))
	return sessionID + "." + hex.EncodeToString(mac.Sum(nil))
}

// TestPreAuthFloodDoesNotConsumeAuthenticatedBudget is G-CORE-03: failed unauthenticated
// attempts and the operator's own requests must not share one bucket.
func TestPreAuthFloodDoesNotConsumeAuthenticatedBudget(t *testing.T) {
	_, handler := authBudgetServer(t)
	for attempt := 0; attempt < preAuthRateBurst+2; attempt++ {
		code := authBudgetRequest(handler, "", "")
		if code != http.StatusUnauthorized && code != http.StatusTooManyRequests {
			t.Fatalf("unauthenticated attempt %d returned %d", attempt, code)
		}
	}
	if code := authBudgetRequest(handler, "", ""); code != http.StatusTooManyRequests {
		t.Fatalf("pre-auth budget did not trip: %d", code)
	}
	if code := authBudgetRequest(handler, fabricTestToken, ""); code != http.StatusNoContent {
		t.Fatalf("authenticated operator was locked out by pre-auth failures: %d", code)
	}
}

// TestGatewayAttestedSessionsHaveSeparateBudgets is G-WEB-01: behind the gateway every
// request has the same loopback peer, so the rate identity must come from the attested
// session. One busy session must not starve another.
func TestGatewayAttestedSessionsHaveSeparateBudgets(t *testing.T) {
	cfg := isolatedTokenConfig(t, fabricTestToken)
	cfg.Dashboard.RateLimitPerMinute = 60
	cfg.Dashboard.RateLimitBurst = 2
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, fabricTestToken)
	handler := server.auth(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	firstSession := "session-aaaaaaaaaaaaaaaaaaaaaaaa"
	secondSession := "session-bbbbbbbbbbbbbbbbbbbbbbbb"
	firstHeader := attestedSessionHeader(fabricTestToken, firstSession)
	if code := authBudgetRequest(handler, fabricTestToken, firstHeader); code != http.StatusNoContent {
		t.Fatalf("first session request=%d", code)
	}
	if code := authBudgetRequest(handler, fabricTestToken, firstHeader); code != http.StatusNoContent {
		t.Fatalf("second session request=%d", code)
	}
	if code := authBudgetRequest(handler, fabricTestToken, firstHeader); code != http.StatusTooManyRequests {
		t.Fatalf("session budget did not trip: %d", code)
	}
	if code := authBudgetRequest(handler, fabricTestToken, attestedSessionHeader(fabricTestToken, secondSession)); code != http.StatusNoContent {
		t.Fatalf("a second attested session was starved by the first: %d", code)
	}
	// A forged binding must not create a fresh per-request identity: every forged value
	// falls back to the shared credential identity, so forging cannot evade the budget.
	forged := firstSession + "." + strings.Repeat("00", sha256.Size)
	if code := authBudgetRequest(handler, fabricTestToken, forged); code != http.StatusNoContent {
		t.Fatalf("first forged-binding request=%d", code)
	}
	otherForged := secondSession + "." + strings.Repeat("11", sha256.Size)
	if code := authBudgetRequest(handler, fabricTestToken, otherForged); code != http.StatusNoContent {
		t.Fatalf("second forged-binding request=%d", code)
	}
	if code := authBudgetRequest(handler, fabricTestToken, forged); code != http.StatusTooManyRequests {
		t.Fatalf("forged session bindings evaded the credential budget: %d", code)
	}
}

// ---------------------------------------------------------------- F-19

func TestAuthenticationDenialsReachTheSignedEvidenceTrail(t *testing.T) {
	cfg := isolatedTokenConfig(t, fabricTestToken)
	state := NewState("test", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, fabricTestToken)
	handler := server.auth(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	if code := authBudgetRequest(handler, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request returned %d", code)
	}
	if code := authBudgetRequest(handler, "wrong-token", ""); code != http.StatusUnauthorized {
		t.Fatalf("invalid credential request returned %d", code)
	}
	found := false
	for _, record := range ledger.Recent(20) {
		if record.Kind == "auth.denial" && record.Source == "access-gateway" {
			found = true
		}
	}
	if !found {
		t.Fatal("authentication denials were not recorded in the signed evidence ledger")
	}
}

// ---------------------------------------------------------------- F-22

func authenticatedRequest(t *testing.T, server *APIServer, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+path, bytes.NewBufferString(body))
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:40505"
	req.Header.Set("Authorization", "Bearer "+fabricTestToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("X-VGT-Request-ID", randomID()+randomID())
	}
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	return rec
}

func TestBlockRemovalRequiresTypedConfirmationAndSupportsUndo(t *testing.T) {
	// The removal path persists the signed policy, so the fixture needs a real policy store.
	cfg, state, policy, _, release := startupSecurityFixture(t)
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, fabricTestToken)
	target := "203.0.113.77/32"
	block, err := state.AddBlock(target, "removal target", "manual", time.Hour, false, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if rec := authenticatedRequest(t, server, http.MethodDelete, "/api/v1/blocks/"+block.ID, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed block removal returned %d, want 400", rec.Code)
	}
	confirmed := `{"confirmation":"REMOVE BLOCK ` + target + `","reason":"operator removes the manual block"}`
	rec := authenticatedRequest(t, server, http.MethodDelete, "/api/v1/blocks/"+block.ID, confirmed)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed block removal returned %d: %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		UndoToken string `json:"undo_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil || payload.UndoToken == "" {
		t.Fatalf("removal response has no undo token: %s", rec.Body.String())
	}
	if _, ok := state.BlockByID(block.ID); ok {
		t.Fatal("block was not removed")
	}
	undo := authenticatedRequest(t, server, http.MethodPost, "/api/v1/blocks/undo", `{"token":"`+payload.UndoToken+`"}`)
	if undo.Code != http.StatusCreated {
		t.Fatalf("block undo returned %d: %s", undo.Code, undo.Body.String())
	}
	found := false
	for _, restored := range state.BlocksSnapshot() {
		if restored.Target == target {
			found = true
		}
	}
	if !found {
		t.Fatal("server-side undo did not restore the removed block")
	}
}

func TestAllowlistRemovalRequiresTypedConfirmationAndSupportsUndo(t *testing.T) {
	server, settings, _ := settingsAPIFixture(t)
	allowlist := settings.Get().ManagementAllowlist
	if len(allowlist) < 2 {
		t.Skip("fixture needs at least two management allowlist entries")
	}
	target := allowlist[len(allowlist)-1]
	unconfirmed := authenticatedRequest(t, server, http.MethodPost, "/api/v1/allowlist/remove", `{"target":"`+target+`"}`)
	if unconfirmed.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed allowlist removal returned %d, want 400", unconfirmed.Code)
	}
	confirmedBody := `{"target":"` + target + `","confirmation":"REMOVE ALLOWLIST ` + target + `","reason":"operator removes management CIDR"}`
	rec := authenticatedRequest(t, server, http.MethodPost, "/api/v1/allowlist/remove", confirmedBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed allowlist removal returned %d: %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		UndoToken string `json:"undo_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil || payload.UndoToken == "" {
		t.Fatalf("removal response has no undo token: %s", rec.Body.String())
	}
	undo := authenticatedRequest(t, server, http.MethodPost, "/api/v1/allowlist/undo", `{"token":"`+payload.UndoToken+`"}`)
	if undo.Code != http.StatusOK {
		t.Fatalf("allowlist undo returned %d: %s", undo.Code, undo.Body.String())
	}
	restored := false
	for _, entry := range settings.Get().ManagementAllowlist {
		if entry == target {
			restored = true
		}
	}
	if !restored {
		t.Fatal("server-side undo did not restore the removed allowlist entry")
	}
}

// ---------------------------------------------------------------- F-23

func TestUnauthenticatedLoopbackSurfacesDoNotDisclosePosture(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, fabricTestToken)
	for _, path := range []string{"/api/v1/status", "/metrics", "/bootz", "/panelz"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.Host = "127.0.0.1"
		req.RemoteAddr = "127.0.0.1:40606"
		server.http.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s answered an unauthenticated request with %d, want 401", path, rec.Code)
		}
	}
	for _, path := range []string{"/livez", "/readyz", "/healthz"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.Host = "127.0.0.1"
		req.RemoteAddr = "127.0.0.1:40606"
		server.http.Handler.ServeHTTP(rec, req)
		payload := map[string]any{}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("%s returned a non-JSON body: %s", path, rec.Body.String())
		}
		if _, ok := payload["version"]; ok {
			t.Fatalf("%s exposes the build version", path)
		}
		for _, forbidden := range []string{"release", "policy", "core", "blockers", "xdr"} {
			if _, ok := payload[forbidden]; ok {
				t.Fatalf("%s exposes posture field %q without authentication", path, forbidden)
			}
		}
		if _, ok := payload["ok"]; !ok {
			t.Fatalf("%s does not report its ok state", path)
		}
	}
}
