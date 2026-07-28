package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSecret(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x5a}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStorageCipherAADBindingAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	key := testSecret(t, dir, "storage.key")
	cipher, err := NewStorageCipher(key, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	plain := []byte(`{"secret":"process lineage"}`)
	sealed, err := cipher.Encrypt(path, "runtime-settings", 7, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("process lineage")) {
		t.Fatal("plaintext leaked into encrypted envelope")
	}
	seq := uint64(7)
	opened, legacy, err := cipher.Decrypt(path, "runtime-settings", sealed, &seq)
	if err != nil || legacy || !bytes.Equal(opened, plain) {
		t.Fatalf("decrypt failed legacy=%v err=%v", legacy, err)
	}
	if _, _, err := cipher.Decrypt(filepath.Join(dir, "other.json"), "runtime-settings", sealed, &seq); err == nil {
		t.Fatal("path AAD mismatch was accepted")
	}
	if _, _, err := cipher.Decrypt(path, "policy-state", sealed, &seq); err == nil {
		t.Fatal("purpose AAD mismatch was accepted")
	}
	marker := []byte(`"ciphertext":"`)
	idx := bytes.Index(sealed, marker)
	if idx < 0 {
		t.Fatal("ciphertext field missing")
	}
	idx += len(marker)
	if sealed[idx] == 'A' {
		sealed[idx] = 'B'
	} else {
		sealed[idx] = 'A'
	}
	if _, _, err := cipher.Decrypt(path, "runtime-settings", sealed, &seq); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
}

func TestProductionStoresDoNotPersistOperationalPlaintext(t *testing.T) {
	dir := t.TempDir()
	storageKey := testSecret(t, dir, "storage.key")
	runtimeKey := testSecret(t, dir, "runtime.key")
	cfg := defaultConfig()
	cfg.Node.Name = "storage-test-node"
	cfg.Runtime.SettingsFile = filepath.Join(dir, "runtime.json")
	cfg.Runtime.KeyFile = runtimeKey
	cfg.Runtime.StorageKeyFile = storageKey
	cfg.XDR.StorageKeyFile = storageKey
	cfg.Policy.StorageKeyFile = storageKey
	store, err := NewSettingsStore(cfg.Runtime.SettingsFile, runtimeKey, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if store == nil {
		t.Fatal("settings store missing")
	}
	data, err := os.ReadFile(cfg.Runtime.SettingsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(encryptedStorageSchema)) || bytes.Contains(data, []byte("xdr_enabled")) {
		t.Fatal("runtime settings were not encrypted")
	}

	policyCfg := PolicyConfig{StateFile: filepath.Join(dir, "policy.json"), SigningKeyFile: filepath.Join(dir, "policy.key"), PublicKeyFile: filepath.Join(dir, "policy.pub"), StorageKeyFile: storageKey, RequireSigned: true}
	policy, err := NewPolicyStore(policyCfg, cfg.Node.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Persist(cfg.Node.Name, "observe", "observe", []BlockEntry{{ID: "r1", Target: "203.0.113.7/32", Reason: "storage marker", ExpiresAt: time.Now().Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{policyCfg.StateFile, policyCfg.SigningKeyFile} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte(encryptedStorageSchema)) || bytes.Contains(b, []byte("storage marker")) {
			t.Fatalf("policy material not encrypted: %s", path)
		}
	}

	incidentPath := filepath.Join(dir, "incidents.log")
	incidentKey := testSecret(t, dir, "incident.key")
	logger, err := NewIncidentLoggerWithStorage(incidentPath, incidentKey, storageKey, cfg.Node.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Append(XDRIncident{ID: "incident-1", Time: time.Now().UTC(), Severity: "high", Process: "sensitive-process", Summary: "sensitive incident marker", RuleIDs: []string{"rule"}, Categories: []string{"integrity"}}); err != nil {
		t.Fatal(err)
	}
	incidentBytes, err := os.ReadFile(incidentPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(incidentBytes), "sensitive-process") || strings.Contains(string(incidentBytes), "sensitive incident marker") {
		t.Fatal("incident plaintext leaked")
	}
	if err := logger.Verify(); err != nil {
		t.Fatalf("encrypted incident verification failed: %v", err)
	}
}

func TestLegacyRuntimeSettingsMigrateAtomicallyToEncryptedStorage(t *testing.T) {
	dir := t.TempDir()
	runtimeKey := testSecret(t, dir, "runtime.key")
	storageKey := testSecret(t, dir, "storage.key")
	path := filepath.Join(dir, "runtime-settings.json")

	legacyCfg := defaultConfig()
	legacyCfg.Node.Name = "migration-node"
	legacyCfg.Runtime.SettingsFile = path
	legacyCfg.Runtime.KeyFile = runtimeKey
	legacyCfg.Runtime.StorageKeyFile = ""
	legacy, err := NewSettingsStore(path, runtimeKey, legacyCfg)
	if err != nil {
		t.Fatal(err)
	}
	next := legacy.Get()
	next.ScanIntervalMillis = 1350
	if _, err := legacy.Update(next); err != nil {
		t.Fatal(err)
	}
	plain, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte(`"scan_interval_millis": 1350`)) {
		t.Fatal("legacy plaintext fixture was not created")
	}

	encryptedCfg := legacyCfg
	encryptedCfg.Runtime.StorageKeyFile = storageKey
	migrated, err := NewSettingsStore(path, runtimeKey, encryptedCfg)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Get().ScanIntervalMillis != 1350 {
		t.Fatal("migration changed runtime settings")
	}
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sealed, []byte(encryptedStorageSchema)) || bytes.Contains(sealed, []byte("scan_interval_millis")) {
		t.Fatal("legacy runtime settings were not atomically encrypted")
	}
}
