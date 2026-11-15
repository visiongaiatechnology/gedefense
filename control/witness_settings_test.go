package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// POINT 4 / P4-T2: the witness namespace contract (docs/POINT4-WITNESS.md §7).
// Every test here describes one property: the namespace is inert by default, an
// upgrade seeds it disabled and names it, and validation rejects a loose
// configuration instead of repairing it.

func witnessStoreFixture(t *testing.T) (*SettingsStore, Config, string) {
	t.Helper()
	cfg := defaultConfig()
	cfg.Runtime.StorageKeyFile = ""
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return store, cfg, keyPath
}

func witnessUpdate(t *testing.T, store *SettingsStore, mutate func(*WitnessFabricSettings)) (RuntimeSettings, error) {
	t.Helper()
	settings := store.Get()
	witness := effectiveWitnessSettings(settings)
	if mutate != nil {
		mutate(&witness)
	}
	settings.Witness = &witness
	return store.Update(settings)
}

func TestWitnessDefaultsAreInertAndMatchTheContract(t *testing.T) {
	witness := defaultWitnessFabricSettings()
	if witness.Enabled || witness.Mode != witnessModeOff {
		t.Fatalf("the shipped default is not inert: enabled=%v mode=%q", witness.Enabled, witness.Mode)
	}
	if witness.CheckpointIntervalSeconds != 300 || witness.NonceTTLSeconds != 120 || witness.RequestTimeoutSeconds != 10 {
		t.Fatalf("timing defaults drifted: %+v", witness)
	}
	if witness.OutboxMaxBytes != 4<<20 || witness.OutboxMaxEntries != 1024 {
		t.Fatalf("outbox defaults drifted: %+v", witness)
	}
	if witness.RetryAttempts != 3 || witness.RetryBackoffSeconds != 30 || witness.DegradeAfterFailures != 3 {
		t.Fatalf("retry defaults drifted: %+v", witness)
	}
	if !witness.RequireAck || !witness.EquivocationAlarm || witness.TriggerLockdownOnEquivocation {
		t.Fatalf("alarm defaults drifted: %+v", witness)
	}
	if witness.Endpoint != "" || witness.PinnedServerKeyFile != "" || witness.PinnedServerSPKI != "" {
		t.Fatal("the default witness carries a transport anchor")
	}
	// The default document is seeded with the namespace, so it must validate.
	settings := defaultWitnessFabricSettings()
	if err := validateWitnessFabricSettings(&settings); err != nil {
		t.Fatalf("the shipped default does not validate: %v", err)
	}
}

func TestWitnessSettingsValidationRejectsInsteadOfRepairing(t *testing.T) {
	valid := func() WitnessFabricSettings {
		witness := defaultWitnessFabricSettings()
		witness.Enabled = true
		witness.Mode = witnessModeHTTP
		witness.Endpoint = "https://witness.example"
		witness.PinnedServerSPKI = strings.Repeat("ab", 32)
		return witness
	}
	if witness := valid(); validateWitnessFabricSettings(&witness) != nil {
		t.Fatalf("a valid pinned http configuration was rejected: %v", validateWitnessFabricSettings(&witness))
	}
	cases := map[string]func(*WitnessFabricSettings){
		"unknown mode":          func(w *WitnessFabricSettings) { w.Mode = "carrier-pigeon" },
		"enabled but off":       func(w *WitnessFabricSettings) { w.Enabled = true; w.Mode = witnessModeOff },
		"http endpoint missing": func(w *WitnessFabricSettings) { w.Endpoint = "" },
		"http downgrade":        func(w *WitnessFabricSettings) { w.Endpoint = "http://witness.example" },
		"foreign port":          func(w *WitnessFabricSettings) { w.Endpoint = "https://witness.example:8443" },
		"userinfo":              func(w *WitnessFabricSettings) { w.Endpoint = "https://operator:secret@witness.example" },
		"fragment":              func(w *WitnessFabricSettings) { w.Endpoint = "https://witness.example/#x" },
		"query":                 func(w *WitnessFabricSettings) { w.Endpoint = "https://witness.example/?x=1" },
		"relative endpoint":     func(w *WitnessFabricSettings) { w.Endpoint = "/v1/checkpoint" },
		"loopback v4":           func(w *WitnessFabricSettings) { w.Endpoint = "https://127.0.0.1" },
		"loopback v6":           func(w *WitnessFabricSettings) { w.Endpoint = "https://[::1]" },
		"localhost":             func(w *WitnessFabricSettings) { w.Endpoint = "https://localhost" },
		"cloud metadata v4":     func(w *WitnessFabricSettings) { w.Endpoint = "https://169.254.169.254" },
		"cloud metadata host":   func(w *WitnessFabricSettings) { w.Endpoint = "https://metadata.google.internal" },
		"missing pin":           func(w *WitnessFabricSettings) { w.PinnedServerSPKI = "" },
		"short spki":            func(w *WitnessFabricSettings) { w.PinnedServerSPKI = strings.Repeat("ab", 16) },
		"uppercase spki":        func(w *WitnessFabricSettings) { w.PinnedServerSPKI = strings.Repeat("AB", 32) },
		"relative pin path":     func(w *WitnessFabricSettings) { w.PinnedServerKeyFile = "keys/witness.pub" },
		"relative client key":   func(w *WitnessFabricSettings) { w.ClientCertFile = "/etc/witness.crt"; w.ClientKeyFile = "witness.key" },
		"half mtls":             func(w *WitnessFabricSettings) { w.ClientCertFile = "/etc/witness.crt" },
		"interval too small":    func(w *WitnessFabricSettings) { w.CheckpointIntervalSeconds = 1 },
		"interval too large":    func(w *WitnessFabricSettings) { w.CheckpointIntervalSeconds = 100000 },
		"nonce ttl too small":   func(w *WitnessFabricSettings) { w.NonceTTLSeconds = 1 },
		"request timeout zero":  func(w *WitnessFabricSettings) { w.RequestTimeoutSeconds = 0 },
		"outbox too small":      func(w *WitnessFabricSettings) { w.OutboxMaxBytes = 1024 },
		"outbox too large":      func(w *WitnessFabricSettings) { w.OutboxMaxBytes = 1 << 30 },
		"entry bound zero":      func(w *WitnessFabricSettings) { w.OutboxMaxEntries = 0 },
		"retry attempts":        func(w *WitnessFabricSettings) { w.RetryAttempts = 11 },
		"backoff zero":          func(w *WitnessFabricSettings) { w.RetryBackoffSeconds = 0 },
		"degrade threshold":     func(w *WitnessFabricSettings) { w.DegradeAfterFailures = 0 },
	}
	for name, mutate := range cases {
		witness := valid()
		mutate(&witness)
		if err := validateWitnessFabricSettings(&witness); err == nil {
			t.Errorf("%s: an invalid witness configuration was accepted", name)
		}
	}
	export := defaultWitnessFabricSettings()
	export.Enabled = true
	export.Mode = witnessModeExport
	if err := validateWitnessFabricSettings(&export); err != nil {
		t.Fatalf("mode export must not require a transport anchor: %v", err)
	}
	lanWitness := valid()
	lanWitness.Endpoint = "https://10.20.30.40"
	if err := validateWitnessFabricSettings(&lanWitness); err != nil {
		t.Fatalf("explicit LAN RFC1918 witness must remain allowed: %v", err)
	}
}

func TestWitnessMigrationV16ToV17SeedsDisabledNamespace(t *testing.T) {
	bootstrap := defaultRuntimeSettings(defaultConfig())
	document := RuntimeSettings{FabricVersion: 16, Revision: 9}
	if upgraded := upgradeRuntimeSettings(&document, bootstrap); !upgraded {
		t.Fatal("a v16 document must be upgraded")
	}
	if document.FabricVersion != fabricSettingsVersion || fabricSettingsVersion != 17 {
		t.Fatalf("schema version is %d, want 17", document.FabricVersion)
	}
	if document.Witness == nil {
		t.Fatal("the v17 document carries no witness namespace")
	}
	if document.Witness.Enabled || document.Witness.Mode != witnessModeOff {
		t.Fatalf("the upgrade must seed the namespace inert: %+v", document.Witness)
	}
	named := false
	for _, migration := range document.Migrations {
		if strings.Contains(migration, "witness namespace added") && strings.Contains(migration, "enabled=false") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the upgrade did not name the seeded namespace in its migration record: %v", document.Migrations)
	}
	// An existing operator namespace is the authority and must never be re-seeded.
	existing := defaultWitnessFabricSettings()
	existing.Enabled = true
	existing.Mode = witnessModeExport
	custom := RuntimeSettings{FabricVersion: 16, Revision: 10, Witness: &existing}
	upgradeRuntimeSettings(&custom, bootstrap)
	if custom.Witness == nil || !custom.Witness.Enabled || custom.Witness.Mode != witnessModeExport {
		t.Fatalf("the upgrade overwrote the operator's witness namespace: %+v", custom.Witness)
	}
}

func TestWitnessSettingsPersistCloneAndRejectLooseConfiguration(t *testing.T) {
	store, _, keyPath := witnessStoreFixture(t)
	if _, err := witnessUpdate(t, store, func(w *WitnessFabricSettings) {
		w.Enabled = true
		w.Mode = witnessModeHTTP
		w.Endpoint = "https://witness.example"
	}); err == nil {
		t.Fatal("enabling http mode without a pin was accepted")
	}
	updated, err := witnessUpdate(t, store, func(w *WitnessFabricSettings) {
		w.Enabled = true
		w.Mode = witnessModeExport
		w.OutboxMaxEntries = 512
	})
	if err != nil {
		t.Fatalf("a valid export namespace was rejected: %v", err)
	}
	if updated.Witness == nil || !updated.Witness.Enabled || updated.Witness.Mode != witnessModeExport || updated.Witness.OutboxMaxEntries != 512 {
		t.Fatalf("the persisted namespace does not carry the operator values: %+v", updated.Witness)
	}
	// The store must hand out clones: mutating a returned document must not change
	// the persisted one.
	first := store.Get()
	first.Witness.OutboxMaxEntries = 999999
	second := store.Get()
	if second.Witness.OutboxMaxEntries != 512 {
		t.Fatalf("the settings store handed out an aliased namespace: %d", second.Witness.OutboxMaxEntries)
	}
	// The clone helper used on every path must also isolate the pointer.
	clone := cloneRuntimeSettings(second)
	clone.Witness.Enabled = false
	if !store.Get().Witness.Enabled {
		t.Fatal("cloneRuntimeSettings aliased the witness namespace")
	}
	// A reload authenticates the same document and keeps the namespace.
	reloaded, err := NewSettingsStore(store.path, keyPath, defaultConfigWithNoStorage())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Get().Witness == nil || reloaded.Get().Witness.OutboxMaxEntries != 512 {
		t.Fatalf("the witness namespace did not survive a reload: %+v", reloaded.Get().Witness)
	}
}

func defaultConfigWithNoStorage() Config {
	cfg := defaultConfig()
	cfg.Runtime.StorageKeyFile = ""
	return cfg
}

func TestWitnessFabricModuleIsRegistered(t *testing.T) {
	if module, ok := fabricModuleName("witness"); !ok || module != "witness" {
		t.Fatal("the witness module is not registered in the module allowlist")
	}
	settings := defaultRuntimeSettings(defaultConfig())
	view, err := fabricModuleSnapshot(settings, "witness")
	if err != nil {
		t.Fatalf("the witness module has no settings snapshot: %v", err)
	}
	witness, ok := view.(WitnessFabricSettings)
	if !ok || witness.Enabled || witness.Mode != witnessModeOff {
		t.Fatalf("the witness snapshot is not the inert namespace: %+v", view)
	}
	candidate := settings
	if err := decodeModuleSettings(mustMarshal(t, view), "witness", &candidate); err != nil {
		t.Fatalf("the witness module cannot decode its own snapshot: %v", err)
	}
	if candidate.Witness == nil || candidate.Witness.CheckpointIntervalSeconds != 300 {
		t.Fatalf("decoded witness namespace is wrong: %+v", candidate.Witness)
	}
	// Every registered witness key must be present in the schema groups.
	metadata := fabricModuleSettings("witness")
	if len(metadata) != len(witnessSchemaKeys) {
		t.Fatalf("the schema publishes %d witness settings, want %d", len(metadata), len(witnessSchemaKeys))
	}
	seen := map[string]bool{}
	for _, meta := range metadata {
		if meta.Module != "witness" || meta.Group == "" || meta.Label == "" || meta.ApplyClass == "" || meta.Risk == "" || meta.Description == "" || meta.Type == "" {
			t.Fatalf("incomplete witness setting metadata: %+v", meta)
		}
		seen[meta.Key] = true
	}
	for _, key := range witnessSchemaKeys {
		if !seen[key] {
			t.Fatalf("the schema is missing witness.%s", key)
		}
	}
}

// witnessSchemaKeys is the §7 field list as exposed to the dashboard.
var witnessSchemaKeys = []string{
	"enabled", "mode", "endpoint", "pinned_server_key_file", "pinned_server_spki",
	"client_cert_file", "client_key_file", "auth_token_file",
	"checkpoint_interval_seconds", "nonce_ttl_seconds", "request_timeout_seconds",
	"outbox_max_bytes", "outbox_max_entries", "retry_attempts", "retry_backoff_seconds",
	"require_ack", "degrade_after_failures", "equivocation_alarm", "trigger_lockdown_on_equivocation",
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
