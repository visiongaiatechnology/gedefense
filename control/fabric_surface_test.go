// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func surfaceFixture(t *testing.T) (*APIServer, *SettingsStore, *PolicyStore) {
	t.Helper()
	cfg, state, policy, release := betaReleaseFixture(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	cfg.XDR.IncidentLog = filepath.Join(dir, "incidents.jsonl")
	settings, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	release.settings = settings
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, settings, fabricTestToken)
	return server, settings, policy
}

func surfaceRequest(t *testing.T, server *APIServer, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	// httptest.NewRequest fills Host with example.com when the target is a bare path,
	// and the server's host check then rejects every request with 400 "invalid host".
	// The helper has to name the host the operator actually reaches.
	request.Host = "127.0.0.1"
	request.Header.Set("Authorization", "Bearer "+fabricTestToken)
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("X-VGT-Request-ID", randomID())
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.RemoteAddr = "127.0.0.1:40000"
	recorder := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(recorder, request)
	return recorder
}

// TestFabricSearchFindsKeysAndReportsWhy locks the search contract: a query names
// keys across modules, results carry the current effective value, and the reason
// for a hit is reported instead of being guessed by the client.
func TestFabricSearchFindsKeysAndReportsWhy(t *testing.T) {
	server, _, _ := surfaceFixture(t)

	rec := surfaceRequest(t, server, http.MethodGet, "/api/v1/settings/search?q=ttl", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("search status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Query     string            `json:"query"`
		Hits      []FabricSearchHit `json:"hits"`
		Truncated bool              `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Hits) == 0 {
		t.Fatal("searching for a security-relevant term returned nothing")
	}
	modules := map[string]bool{}
	for _, hit := range payload.Hits {
		modules[hit.Module] = true
		if hit.Label == "" || hit.Group == "" || hit.Highlight == "" {
			t.Fatalf("search hit is not addressable: %+v", hit)
		}
		if hit.Value == nil {
			t.Fatalf("search hit carries no effective value: %+v", hit)
		}
	}
	// "TTL" appears in more than one module, which is exactly what the plan's
	// example requires the search to surface.
	if len(modules) < 2 {
		t.Fatalf("search for TTL only covered %v", modules)
	}

	// A key-name match must outrank a description-only match.
	if payload.Hits[0].Highlight != "key" && payload.Hits[0].Highlight != "label" {
		t.Fatalf("strongest hit was a weak match: %+v", payload.Hits[0])
	}

	// Too short a query is refused rather than answered with the whole catalogue.
	if rec := surfaceRequest(t, server, http.MethodGet, "/api/v1/settings/search?q=t", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("a one-character query was accepted: %d", rec.Code)
	}
}

// TestFabricSearchIsDeterministic guards the ordering contract: the same query
// must always produce the same sequence.
func TestFabricSearchIsDeterministic(t *testing.T) {
	server, _, _ := surfaceFixture(t)
	first := surfaceRequest(t, server, http.MethodGet, "/api/v1/settings/search?q=limit", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("search status=%d", first.Code)
	}
	for attempt := 0; attempt < 5; attempt++ {
		next := surfaceRequest(t, server, http.MethodGet, "/api/v1/settings/search?q=limit", nil)
		if next.Body.String() != first.Body.String() {
			t.Fatal("search results are not stable across identical queries")
		}
	}
}

// TestFabricExportIsSignedAndSecretFree proves the two properties the plan
// requires of an export bundle: it is signed, and it carries no key material.
func TestFabricExportIsSignedAndSecretFree(t *testing.T) {
	server, _, policy := surfaceFixture(t)
	rec := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/export", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.Bytes()
	var bundle SettingsBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Schema != settingsBundleSchema || bundle.Signature == "" || bundle.Signer == "" {
		t.Fatalf("bundle is not a signed export: %+v", bundle)
	}
	if len(bundle.Modules) != len(fabricModuleSnapshotOrder) {
		t.Fatalf("bundle carries %d of %d modules", len(bundle.Modules), len(fabricModuleSnapshotOrder))
	}

	// The signature must verify against the policy trust anchor.
	if _, err := verifySettingsBundle(raw, policy.TrustedPublicKey()); err != nil {
		t.Fatalf("exported bundle did not verify: %v", err)
	}

	// Secret material must never appear. This asserts the property rather than
	// trusting that no namespace happens to hold a key today.
	var exported any
	if err := json.Unmarshal(raw, &exported); err != nil {
		t.Fatal(err)
	}
	var inspect func(any)
	inspect = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				switch strings.ToLower(key) {
				case "private_key", "privatekey", "secret", "password", "runtime_token", "bearer":
					t.Fatalf("export bundle contains secret field %q", key)
				}
				inspect(child)
			}
		case []any:
			for _, child := range typed {
				inspect(child)
			}
		case string:
			if strings.Contains(typed, fabricTestToken) {
				t.Fatal("export contains the runtime authentication token")
			}
		}
	}
	inspect(exported)
	for _, secret := range []string{hex.EncodeToString(policy.privateKey), base64.StdEncoding.EncodeToString(policy.privateKey), base64.RawURLEncoding.EncodeToString(policy.privateKey)} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("export contains private signing key material")
		}
	}
}

// TestFabricImportRejectsTamperedBundle covers the integrity gate: a single byte
// change must invalidate the bundle.
func TestFabricImportRejectsTamperedBundle(t *testing.T) {
	server, settings, _ := surfaceFixture(t)
	exported := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/export", nil)
	if exported.Code != http.StatusOK {
		t.Fatalf("export status=%d", exported.Code)
	}
	raw := exported.Body.Bytes()
	before := settings.Get().Revision

	// Flip a value inside the payload without recomputing the digest.
	tampered := bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":false`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("fixture did not contain a value to tamper with")
	}
	rec := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/preview", tampered)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a tampered bundle was accepted: %d %s", rec.Code, rec.Body.String())
	}
	if settings.Get().Revision != before {
		t.Fatal("a rejected preview mutated runtime settings")
	}

	// An unsigned bundle is refused as well.
	var unsigned SettingsBundle
	if err := json.Unmarshal(raw, &unsigned); err != nil {
		t.Fatal(err)
	}
	unsigned.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if rec := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/preview", encoded); rec.Code != http.StatusBadRequest {
		t.Fatalf("an invalidly signed bundle was accepted: %d", rec.Code)
	}
}

// TestFabricImportIsTwoStageAndSingleUse covers the plan's explicit rule that
// there is never an import-to-apply shortcut.
func TestFabricImportIsTwoStageAndSingleUse(t *testing.T) {
	server, settings, _ := surfaceFixture(t)

	// Apply without a preview is impossible.
	blind, err := json.Marshal(map[string]any{"token": strings.Repeat("a", 64), "expected_revision": settings.Get().Revision})
	if err != nil {
		t.Fatal(err)
	}
	if rec := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/apply", blind); rec.Code != http.StatusConflict {
		t.Fatalf("an import applied without a preview: %d", rec.Code)
	}

	// Build a bundle that differs from the running revision.
	current := settings.Get()
	fabric := effectiveIntegritySettings(current)
	fabric.Chronos.MaxFiles = 4321
	candidate := cloneRuntimeSettings(current)
	candidate.Integrity = &fabric
	bundle, err := buildSettingsBundle("source-node", candidate, mustPolicy(t, server), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}

	preview := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/preview", raw)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var previewPayload fabricImportPreviewResponse
	if err := json.Unmarshal(preview.Body.Bytes(), &previewPayload); err != nil {
		t.Fatal(err)
	}
	if !previewPayload.Valid || previewPayload.Token == "" {
		t.Fatalf("preview did not issue a token: %+v", previewPayload)
	}
	if len(previewPayload.Diff) == 0 {
		t.Fatal("preview reported no changes for a differing bundle")
	}
	if settings.Get().Integrity.Chronos.MaxFiles == 4321 {
		t.Fatal("preview mutated runtime settings; an import must never apply during preview")
	}

	applyBody, err := json.Marshal(map[string]any{"token": previewPayload.Token, "expected_revision": settings.Get().Revision})
	if err != nil {
		t.Fatal(err)
	}
	apply := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/apply", applyBody)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	if got := settings.Get().Integrity.Chronos.MaxFiles; got != 4321 {
		t.Fatalf("import did not reach the store: %d", got)
	}

	// The token is single use: replaying the same apply must fail.
	replay := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/apply", applyBody)
	if replay.Code != http.StatusConflict {
		t.Fatalf("an import token was reusable: %d", replay.Code)
	}
}

// TestFabricImportRequiresMatchingRevision proves that a preview cannot be applied
// onto a revision that changed after it was reviewed.
func TestFabricImportRequiresMatchingRevision(t *testing.T) {
	server, settings, _ := surfaceFixture(t)
	current := settings.Get()
	fabric := effectiveIntegritySettings(current)
	fabric.Evidence.MaxBytes = 32 << 20
	candidate := cloneRuntimeSettings(current)
	candidate.Integrity = &fabric
	bundle, err := buildSettingsBundle("source-node", candidate, mustPolicy(t, server), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	preview := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/preview", raw)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var payload fabricImportPreviewResponse
	if err := json.Unmarshal(preview.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Move the stored revision on.
	next := settings.Get()
	next.ScanIntervalMillis++
	if _, err := settings.Update(next); err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(map[string]any{"token": payload.Token, "expected_revision": settings.Get().Revision})
	if err != nil {
		t.Fatal(err)
	}
	if rec := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/apply", body); rec.Code != http.StatusConflict {
		t.Fatalf("a stale preview token was accepted: %d", rec.Code)
	}
}

// TestFabricDriftReportsConfigDrift covers the plan's rule that a stored revision
// which has not reached the engine reports CONFIG_DRIFT and never SYSTEM NOMINAL.
func TestFabricDriftReportsConfigDrift(t *testing.T) {
	server, settings, _ := surfaceFixture(t)
	changed := settings.Get()
	changed.XDRFabric.WorkerCount++
	if _, err := settings.Update(changed); err != nil {
		t.Fatal(err)
	}

	rec := surfaceRequest(t, server, http.MethodGet, "/api/v1/settings/drift", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("drift status=%d body=%s", rec.Code, rec.Body.String())
	}
	var report fabricDriftResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	// No engine is attached in this fixture, either through the XDR engine or the
	// L7 engine, so the report must say so instead of claiming a nominal system.
	if report.Status == "SYSTEM_NOMINAL" {
		t.Fatal("an unattached engine was reported as nominal")
	}
	if report.Status != "CONFIG_DRIFT" {
		t.Fatalf("unexpected drift status %q", report.Status)
	}
	if len(report.Findings) == 0 {
		t.Fatal("CONFIG_DRIFT was reported without any finding")
	}
	for _, finding := range report.Findings {
		if finding.Module == "" || finding.ApplyState == "" || finding.Detail == "" {
			t.Fatalf("drift finding is not actionable: %+v", finding)
		}
	}

	// Restart-class differences are marked as such, because the operator's remedy
	// is different from a stalled reload.
	found := false
	for _, finding := range report.Findings {
		if finding.ApplyState == "restart_required" {
			found = true
			if !finding.Restartable {
				t.Fatal("a restart-class finding was not marked restartable")
			}
		}
	}
	if !found {
		t.Fatal("restart-class drift was not reported")
	}
	_ = settings
}

// TestSettingsBundlePayloadIsOrderIndependent proves the signature covers a
// canonical payload, so a re-serialised bundle with a different key order still
// verifies while any content change does not.
func TestSettingsBundlePayloadIsOrderIndependent(t *testing.T) {
	server, _, policy := surfaceFixture(t)
	exported := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/export", nil)
	if exported.Code != http.StatusOK {
		t.Fatalf("export status=%d", exported.Code)
	}
	var bundle SettingsBundle
	if err := json.Unmarshal(exported.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}

	// Re-marshal through a map, which loses the original field order.
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(exported.Body.Bytes(), &generic); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySettingsBundle(reordered, policy.TrustedPublicKey()); err != nil {
		t.Fatalf("a re-serialised bundle stopped verifying: %v", err)
	}

	// Changing one module payload must break verification.
	bundle.Modules["kinetic"] = json.RawMessage(`{"tampered":true}`)
	payload, err := settingsBundlePayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(policy.TrustedPublicKey(), payload, signature) {
		t.Fatal("a modified bundle still verified against the original signature")
	}
}

func mustPolicy(t *testing.T, server *APIServer) *PolicyStore {
	t.Helper()
	if server.policy == nil {
		t.Fatal("fixture has no policy store")
	}
	return server.policy
}
