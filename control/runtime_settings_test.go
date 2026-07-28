package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeSettingsPersistAndAuthenticate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "runtime.json")
	cfg := defaultConfig()
	cfg.Runtime.StorageKeyFile = ""
	store, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	next := store.Get()
	next.AutoFeedSync = false
	next.ScanIntervalMillis = 900
	next.ManagementAllowlist = []string{"203.0.113.10", "2001:db8::1/128"}
	updated, err := store.Update(next)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.ScanIntervalMillis != 900 {
		t.Fatalf("unexpected update: %+v", updated)
	}
	reloaded, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Get(); got.Revision != 2 || len(got.ManagementAllowlist) != 2 {
		t.Fatalf("unexpected reload: %+v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSettingsStore(path, keyPath, cfg); err == nil {
		t.Fatal("tampered runtime settings were accepted")
	}
}

func TestRuntimeSettingsRejectInvalidThresholdOrder(t *testing.T) {
	settings := defaultRuntimeSettings(defaultConfig())
	settings.AlertScore = 90
	settings.ContainScore = 80
	if err := validateRuntimeSettings(&settings); err == nil {
		t.Fatal("invalid score order accepted")
	}
}

func TestRuntimeSettingsValidateCustomRulesAndModuleWiring(t *testing.T) {
	settings := defaultRuntimeSettings(defaultConfig())
	settings.EnabledRuleModules = []string{"command", "origin", "command"}
	settings.CustomRules = []CustomRule{{
		ID: "custom.suspicious-tool", Enabled: true, Category: "operator",
		Summary: "Operator-defined suspicious tool", Pattern: `(?i)\bsuspicious-tool\b`, Score: 35,
	}}
	if err := validateRuntimeSettings(&settings); err != nil {
		t.Fatal(err)
	}
	if len(settings.EnabledRuleModules) != 2 || settings.CustomRules[0].ID != "CUSTOM.SUSPICIOUS-TOOL" {
		t.Fatalf("settings were not normalized: %+v", settings)
	}
	settings.CustomRules[0].Pattern = `([unterminated`
	if err := validateRuntimeSettings(&settings); err == nil {
		t.Fatal("invalid RE2 custom rule was accepted")
	}
}

func TestRuntimeSettingsLoadLegacyDocumentWithoutRuleFields(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.Runtime.StorageKeyFile = ""
	legacy := defaultRuntimeSettings(cfg)
	legacy.UpdatedAt = time.Date(2026, time.July, 28, 10, 0, 0, 0, time.UTC)
	legacy.EnabledRuleModules = nil
	legacy.CustomRules = nil
	canonical, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), "enabled_rule_modules") || strings.Contains(string(canonical), "custom_rules") {
		t.Fatalf("legacy MAC input contains post-upgrade fields: %s", canonical)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(runtimeSettingsSchema))
	mac.Write([]byte{0})
	mac.Write(canonical)
	document := runtimeSettingsEnvelope{
		Schema: runtimeSettingsSchema, Settings: legacy, MAC: hex.EncodeToString(mac.Sum(nil)),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatalf("valid legacy runtime document was rejected: %v", err)
	}
	if effective := effectiveRuleModules(store.Get()); len(effective) != len(supportedRuleModules) {
		t.Fatalf("legacy document did not activate safe default modules: %v", effective)
	}
}
