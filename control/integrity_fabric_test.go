// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func integrityFixture(t *testing.T) (*APIServer, *SettingsStore) {
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
	return server, settings
}

func integrityPayload(t *testing.T, settings *SettingsStore, mutate func(fabric *IntegrityFabricSettings)) []byte {
	t.Helper()
	current := settings.Get()
	fabric := defaultIntegrityFabricSettings(Config{})
	if current.Integrity != nil {
		fabric = cloneIntegrityFabricSettings(*current.Integrity)
	}
	mutate(&fabric)
	payload, err := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": fabric})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestFabricIntegrityHotRevisionReachesEngines(t *testing.T) {
	server, settings := integrityFixture(t)
	dir := t.TempDir()

	cipher := newTestStorageCipher(t, dir)
	fim, err := NewFIMEngine([]string{dir}, filepath.Join(dir, "fim-baseline.enc"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	chronos, err := NewChronosScanner([]string{dir}, filepath.Join(dir, "chronos.json"), 100, 0, cipher)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := NewEvidenceLedger(filepath.Join(dir, "evidence.jsonl"), filepath.Join(dir, "evidence.ed25519"), filepath.Join(dir, "storage.key"), "integrity-test-node", 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	packages := newPackageIntegrityScanner(filepath.Join(dir, "pacman"), dir)

	payload := integrityPayload(t, settings, func(fabric *IntegrityFabricSettings) {
		fabric.FIM.Roots = []string{dir}
		fabric.FIM.MaxFindings = 42
		fabric.FIM.MaxFileBytes = 2 << 20
		fabric.Chronos.Roots = []string{dir}
		fabric.Chronos.MaxFiles = 77
		fabric.Chronos.BatchSize = 7
		fabric.Evidence.MaxBytes = 8 << 20
		fabric.Evidence.APIRecentDefault = 25
		fabric.Evidence.APIRecentMax = 200
	})
	preview := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/integrity/preview", payload)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/integrity", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}

	live := effectiveIntegritySettings(settings.Get())
	if err := applyIntegrityPolicies(live, fim, chronos, packages, ledger); err != nil {
		t.Fatal(err)
	}
	if policy := fim.policySnapshot(); policy.maxFindings != 42 || policy.maxFileBytes != 2<<20 {
		t.Fatalf("FIM policy not projected: %+v", policy)
	}
	if policy := chronos.policySnapshot(); policy.maxFiles != 77 || policy.batchSize != 7 {
		t.Fatalf("Chronos policy not projected: %+v", policy)
	}
	if policy := ledger.Policy(); policy.MaxBytes != 8<<20 || policy.APIRecentMax != 200 {
		t.Fatalf("evidence policy not projected: %+v", policy)
	}

	// The evidence page ceiling is administrable and enforced.
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/evidence?limit=300", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("evidence page above the administrable ceiling was accepted: %d", rec.Code)
	}
}

// TestFabricIntegrityRootsAreRestartClass proves that a root change is persisted
// and reported, never silently activated against a baseline that is bound to the
// previous root set.
func TestFabricIntegrityRootsAreRestartClass(t *testing.T) {
	server, settings := integrityFixture(t)
	dir := t.TempDir()
	cipher := newTestStorageCipher(t, dir)
	root := filepath.Join(dir, "protected")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fim, err := NewFIMEngine([]string{root}, filepath.Join(dir, "fim-baseline.enc"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	server.AttachFIM(fim)

	payload := integrityPayload(t, settings, func(fabric *IntegrityFabricSettings) {
		fabric.FIM.Roots = []string{dir}
	})
	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/integrity", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	view := decodeFabricView(t, apply.Body.Bytes())
	if view.ApplyState != "restart_required" {
		t.Fatalf("root change reported apply state %q", view.ApplyState)
	}

	// Defence in depth: the engine refuses the same change directly.
	live := effectiveIntegritySettings(settings.Get())
	if err := fim.ApplyPolicy(live.FIM); err == nil {
		t.Fatal("the engine accepted a root change that is bound to the stored baseline")
	}
	if got := fim.Roots(); len(got) != 1 || got[0] != root {
		t.Fatalf("live roots changed: %v", got)
	}
}

func TestFabricIntegrityRejectsUnsafeConfiguration(t *testing.T) {
	server, settings := integrityFixture(t)
	cases := []struct {
		name   string
		mutate func(fabric *IntegrityFabricSettings)
	}{
		{"fim root at filesystem root", func(f *IntegrityFabricSettings) { f.FIM.Roots = []string{"/"} }},
		{"fim root unclean", func(f *IntegrityFabricSettings) { f.FIM.Roots = []string{"/etc/../var"} }},
		{"fim enabled without roots", func(f *IntegrityFabricSettings) { f.FIM.Roots = nil }},
		{"fim interval below floor", func(f *IntegrityFabricSettings) { f.FIM.IntervalSeconds = 5 }},
		{"fim total below per-file", func(f *IntegrityFabricSettings) { f.FIM.MaxTotalBytes = 1 << 20 }},
		{"fim baseline bound too small", func(f *IntegrityFabricSettings) { f.FIM.MaxBaselineBytes = 1024 }},
		{"fim finding budget too small", func(f *IntegrityFabricSettings) { f.FIM.MaxFindings = 1 }},
		{"chronos root at filesystem root", func(f *IntegrityFabricSettings) { f.Chronos.Roots = []string{"/"} }},
		{"chronos enabled without roots", func(f *IntegrityFabricSettings) { f.Chronos.Roots = nil }},
		{"chronos yield out of bounds", func(f *IntegrityFabricSettings) { f.Chronos.YieldMillis = 5000 }},
		{"chronos file budget too small", func(f *IntegrityFabricSettings) { f.Chronos.MaxFiles = 1 }},
		{"package interval out of bounds", func(f *IntegrityFabricSettings) { f.Packages.IntervalHours = 0 }},
		{"evidence budget too small", func(f *IntegrityFabricSettings) { f.Evidence.MaxBytes = 1024 }},
		{"evidence verify interval below floor", func(f *IntegrityFabricSettings) { f.Evidence.VerifyIntervalSeconds = 5 }},
		{"evidence ceiling below default", func(f *IntegrityFabricSettings) {
			f.Evidence.APIRecentDefault = 200
			f.Evidence.APIRecentMax = 100
		}},
		{"evidence page default above ceiling", func(f *IntegrityFabricSettings) { f.Evidence.APIRecentDefault = 600 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := integrityPayload(t, settings, tc.mutate)
			rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/integrity/preview", payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe configuration accepted: %d %s", rec.Code, rec.Body.String())
			}
			if settings.Get().Revision != 1 {
				t.Fatal("rejected preview mutated runtime settings")
			}
		})
	}
}

// TestIntegrityChronosBoundsStopTheWalk covers the traversal budget that did not
// exist before this revision: an unbounded Walk could keep the walker busy
// indefinitely and grow the in-memory digest map without limit.
func TestIntegrityChronosBoundsStopTheWalk(t *testing.T) {
	dir := t.TempDir()
	for index := 0; index < 8; index++ {
		if err := os.WriteFile(filepath.Join(dir, "file"+string(rune('a'+index))+".txt"), []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scanner, err := NewChronosScanner([]string{dir}, filepath.Join(dir, "checkpoint.json"), 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	settings := defaultIntegrityFabricSettings(Config{}).Chronos
	settings.Roots = []string{dir}
	settings.MaxFiles = 3
	if err := scanner.ApplyPolicy(settings); err != nil {
		t.Fatal(err)
	}
	checkpoint, scanErr := scanner.Scan(context.Background(), false)
	if scanErr == nil {
		t.Fatal("the traversal budget was not enforced")
	}
	if checkpoint == nil || checkpoint.Phase != "BOUNDED" {
		t.Fatalf("bounded scan did not report a partial result: %+v", checkpoint)
	}
	if checkpoint.FilesScanned > 3 {
		t.Fatalf("file budget exceeded: %d", checkpoint.FilesScanned)
	}
	if !strings.Contains(scanErr.Error(), "budget exhausted") {
		t.Fatalf("unexpected budget error: %v", scanErr)
	}
}

// TestIntegrityChronosCheckpointIsSealed covers the second finding: the digest
// inventory used to be written as plaintext JSON.
func TestIntegrityChronosCheckpointIsSealed(t *testing.T) {
	dir := t.TempDir()
	secretName := "classified-file-name.txt"
	if err := os.WriteFile(filepath.Join(dir, secretName), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	cipher := newTestStorageCipher(t, dir)
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	scanner, err := NewChronosScanner([]string{dir}, checkpointPath, 10, 0, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if !scanner.Encrypted() {
		t.Fatal("scanner does not report encrypted checkpointing")
	}
	if _, err := scanner.Scan(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secretName) {
		t.Fatal("the sealed checkpoint leaks a protected path in plaintext")
	}
	reopened, err := NewChronosScanner([]string{dir}, checkpointPath, 10, 0, cipher)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.LoadCheckpoint()
	if err != nil {
		t.Fatalf("sealed checkpoint could not be reopened: %v", err)
	}
	if recovered == nil || recovered.FileHashes[filepath.Join(dir, secretName)] == "" {
		t.Fatalf("recovered checkpoint is incomplete: %+v", recovered)
	}
}

func TestIntegrityFIMDisabledRefusesScans(t *testing.T) {
	dir := t.TempDir()
	cipher := newTestStorageCipher(t, dir)
	root := filepath.Join(dir, "protected")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewFIMEngine([]string{root}, filepath.Join(dir, "fim-baseline.enc"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.Enabled() {
		t.Fatal("a freshly constructed engine must be enabled")
	}
	disabled := defaultIntegrityFabricSettings(Config{}).FIM
	disabled.Roots = []string{root}
	disabled.Enabled = false
	if err := engine.ApplyPolicy(disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Scan(); err == nil {
		t.Fatal("a disabled FIM engine still scanned")
	}
	if _, err := engine.CreateBaseline(); err == nil {
		t.Fatal("a disabled FIM engine still created a baseline")
	}
}

// TestIntegrityDocumentWithoutNamespaceStillAuthenticates guards the migration
// path for a settings document written before the Integrity namespace existed.
func TestIntegrityDocumentWithoutNamespaceStillAuthenticates(t *testing.T) {
	cfg := defaultConfig()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	path := filepath.Join(dir, "runtime.json")
	seeded, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	legacy := seeded.Get()
	legacy.FabricVersion = 5
	legacy.Integrity = nil
	legacy.Kinetic.VelocityLimit = 654
	mac, err := seeded.mac(legacy)
	if err != nil {
		t.Fatal(err)
	}
	document := runtimeSettingsEnvelope{Schema: runtimeSettingsSchema, Settings: legacy, MAC: hex.EncodeToString(mac)}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatalf("a pre-Integrity settings document was rejected: %v", err)
	}
	upgraded := reloaded.Get()
	if upgraded.FabricVersion != fabricSettingsVersion {
		t.Fatalf("schema version not upgraded: %d", upgraded.FabricVersion)
	}
	if upgraded.Integrity == nil {
		t.Fatal("Integrity namespace was not seeded during the upgrade")
	}
	if upgraded.Kinetic.VelocityLimit != 654 {
		t.Fatal("existing operator tuning was lost during the upgrade")
	}
	if len(upgraded.Integrity.Chronos.Roots) == 0 {
		t.Fatal("Chronos roots were not seeded from the bootstrap configuration")
	}
}

func TestFabricIntegritySchemaRegistryCoversEveryAdvertisedKey(t *testing.T) {
	server, settings := integrityFixture(t)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/schema", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema status=%d body=%s", rec.Code, rec.Body.String())
	}
	var schema struct {
		Modules  []string                `json:"modules"`
		Settings []FabricSettingMetadata `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &schema); err != nil {
		t.Fatal(err)
	}
	if !containsString(schema.Modules, "integrity") {
		t.Fatalf("schema does not advertise the Integrity module: %v", schema.Modules)
	}
	registered := map[string]FabricSettingMetadata{}
	for _, meta := range schema.Settings {
		if meta.Module == "integrity" {
			registered[meta.Key] = meta
		}
	}
	if len(registered) == 0 {
		t.Fatal("schema carries no Integrity settings")
	}
	payload, err := json.Marshal(effectiveIntegritySettings(settings.Get()))
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(payload, &flat); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"fim", "chronos", "packages", "evidence"} {
		raw, ok := flat[group]
		if !ok {
			t.Fatalf("namespace %q missing from the module snapshot", group)
		}
		nested, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for leaf := range nested {
			documented := group + "." + leaf
			if _, exists := registered[documented]; !exists {
				t.Fatalf("administrable key %q has no schema metadata", documented)
			}
		}
	}
}

func newTestStorageCipher(t *testing.T, dir string) *StorageCipher {
	t.Helper()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x5a}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewStorageCipher(keyPath, "integrity-test-node")
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}
