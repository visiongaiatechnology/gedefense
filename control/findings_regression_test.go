// STATUS: PLATIN
package main

import (
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsAcceptEarlierAuthenticatedEmptyListNormalization(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.Runtime.StorageKeyFile = ""
	settings := defaultRuntimeSettings(cfg)
	settings.Forensics.Quarantine.AllowedRoots = []string{}
	signer := &SettingsStore{key: key}
	wireMAC, err := signer.mac(settings)
	if err != nil {
		t.Fatal(err)
	}
	legacyMAC, err := signer.mac(cloneRuntimeSettings(settings))
	if err != nil {
		t.Fatal(err)
	}
	if hmac.Equal(wireMAC, legacyMAC) {
		t.Fatal("fixture must exercise distinct historical MAC representations")
	}
	path := filepath.Join(dir, "runtime.json")
	write := func(document runtimeSettingsEnvelope) {
		t.Helper()
		data, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	document := runtimeSettingsEnvelope{Schema: runtimeSettingsSchema, Settings: settings, MAC: hex.EncodeToString(legacyMAC)}
	write(document)
	if _, err := NewSettingsStore(path, keyPath, cfg); err != nil {
		t.Fatalf("earlier writer's authenticated document rejected: %v", err)
	}
	document.Settings.Network.DefaultTTLSeconds++
	write(document)
	if _, err := NewSettingsStore(path, keyPath, cfg); err == nil {
		t.Fatal("historical authentication accepted tampered settings")
	}
}

func TestRestorePermissionsCannotWidenAfterTightening(t *testing.T) {
	server, store, _ := surfaceFixture(t)
	original := store.Get().Revision
	narrow := store.Get()
	narrow.Forensics.Quarantine.RestoreFileMode = 0o400
	if _, err := store.Update(narrow); err != nil {
		t.Fatal(err)
	}
	wider := store.Get()
	wider.Forensics.Quarantine.RestoreFileMode = 0o600
	if _, err := store.Update(wider); err == nil {
		t.Fatal("store widened previously tightened permissions")
	}
	if _, err := store.Rollback(original); err == nil {
		t.Fatal("rollback widened previously tightened permissions")
	}
	payload := forensicsFabricPayload(t, store, func(f *ForensicsFabricSettings) { f.Quarantine.RestoreFileMode = 0o600 })
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/forensics/preview", payload); rec.Code != http.StatusBadRequest {
		t.Fatalf("preview accepted widening: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCanaryCreationRefusesSymlinkedRootAncestor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "redirect")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := DeployCanaryFile(filepath.Join(link, "new", "nested", "decoy.env"), CanaryDotEnv); err == nil {
		t.Fatal("canary deployment followed a symlinked ancestor")
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); !os.IsNotExist(err) {
		t.Fatalf("canary directory creation escaped the jail: %v", err)
	}
	existing := filepath.Join(outside, "existing.env")
	if err := os.WriteFile(existing, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DeployCanaryFile(filepath.Join(link, "existing.env"), CanaryDotEnv); err == nil {
		t.Fatal("an existing decoy bypassed ancestor validation")
	}
}

func TestL7PathReorderingProducesNoRevisionDiff(t *testing.T) {
	server, store, _, _ := l7FabricFixture(t)
	payload := l7MutationPayload(t, store, func(f *L7FabricSettings) {
		for left, right := 0, len(f.SensitivePaths)-1; left < right; left, right = left+1, right-1 {
			f.SensitivePaths[left], f.SensitivePaths[right] = f.SensitivePaths[right], f.SensitivePaths[left]
		}
	})
	rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/l7/preview", payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("reordered path preview: %d %s", rec.Code, rec.Body.String())
	}
	var preview FabricSettingsPreview
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if len(preview.Diff) != 0 {
		t.Fatalf("path reordering produced changes: %+v", preview.Diff)
	}
}
