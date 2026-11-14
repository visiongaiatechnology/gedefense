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
	legacy.FabricVersion = 1
	legacy.L7 = nil
	legacy.ThreatIntel = nil
	legacy.Hardening = nil
	legacy.Integrity = nil
	legacy.BootTrust = nil
	legacy.PolicyTrust = nil
	legacy.Forensics = nil
	legacy.System = nil
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
	// The history MAC is mandatory: every writer of this format emits it, and the history is
	// the rollback surface that must not be plantable by a writer without the key.
	historyMAC, err := (&SettingsStore{key: key}).macHistory(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := runtimeSettingsEnvelope{
		Schema: runtimeSettingsSchema, Settings: legacy, MAC: hex.EncodeToString(mac.Sum(nil)),
		HistoryMAC: hex.EncodeToString(historyMAC),
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

// TestRuntimeSettingsRejectsMissingHistoryMAC is the regression for FIND-015: the history MAC
// was verified only when the document happened to carry one ("if document.HistoryMAC != """), so
// a document with an empty field skipped the history authentication entirely. The history is the
// rollback surface - planting entries there makes an operator rollback activate settings the
// attacker chose - and the format has always emitted a MAC for it, so an empty one is an
// integrity failure and never a backward-compatibility case.
func TestRuntimeSettingsRejectsMissingHistoryMAC(t *testing.T) {
	for _, tc := range []struct {
		name    string
		history bool
	}{
		{"empty history", false},
		{"populated history", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "runtime.key")
			if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := defaultConfig()
			cfg.Runtime.StorageKeyFile = ""
			path := filepath.Join(dir, "runtime.json")
			store, err := NewSettingsStore(path, keyPath, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if tc.history {
				next := store.Get()
				next.ScanIntervalMillis = 1337
				if _, err := store.Update(next); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var document runtimeSettingsEnvelope
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if document.HistoryMAC == "" {
				t.Fatal("the fixture was not authenticated under the current format")
			}
			if tc.history && len(document.History) == 0 {
				t.Fatal("the populated-history fixture carries no history")
			}
			document.HistoryMAC = ""
			encoded, err := json.MarshalIndent(document, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewSettingsStore(path, keyPath, cfg); err == nil {
				t.Fatal("runtime settings with an empty history MAC were accepted")
			}
		})
	}
}
