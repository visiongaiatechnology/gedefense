// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/rand"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func behaviorIntegrityConfig(t *testing.T) XDRConfig {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig().XDR
	cfg.StorageKeyFile = ""
	cfg.LogKeyFile = filepath.Join(dir, "xdr.key")
	cfg.BehaviorProfileFile = filepath.Join(dir, "behavior.json")
	cfg.BehaviorWarmupSamples = 2
	return cfg
}

func observeSomeBehavior(model *BehaviorModel) {
	process := ProcessSample{Exe: "/usr/bin/example", Comm: "example"}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		model.ObserveNetwork(process, []NetConnection{{RemoteIP: "203.0.113.7", RemotePort: 443}},
			now.Add(time.Duration(i)*time.Second))
	}
}

// TestBehaviorManipulatedProfileIsNeverOverwritten is the FIND-028 regression test.
//
// A profile document that fails authentication only set integrityErr. The periodic Persist then
// overwrote the manipulated file with the in-memory state and cleared integrityErr, so one save
// cycle destroyed the evidence of the manipulation and restored a clean status. Now Persist is
// fail-closed until an operator explicitly resets the model.
func TestBehaviorManipulatedProfileIsNeverOverwritten(t *testing.T) {
	cfg := behaviorIntegrityConfig(t)
	model, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	observeSomeBehavior(model)
	if err := model.Persist(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfg.BehaviorProfileFile)
	if err != nil {
		t.Fatal(err)
	}

	// The operator's profile is manipulated: a learned statistic is changed while the MAC stays
	// the one that authenticated the original payload.
	var document behaviorDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Payload.Profiles) == 0 {
		t.Fatal("the persisted profile has no entries")
	}
	document.Payload.Profiles[0].ConnectionCount.Mean = 999
	tampered, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tampered = append(tampered, '\n')
	if err := os.WriteFile(cfg.BehaviorProfileFile, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Summary().IntegrityOK {
		t.Fatal("the manipulated behavior profile was accepted")
	}

	// Two periodic save cycles must neither overwrite the manipulated document nor clear the
	// integrity failure.
	for cycle := 1; cycle <= 2; cycle++ {
		if err := reloaded.Persist(); err == nil {
			t.Fatalf("Persist cycle %d overwrote a manipulated profile", cycle)
		}
		if summary := reloaded.Summary(); summary.IntegrityOK || summary.Error == "" {
			t.Fatalf("Persist cycle %d cleared the integrity failure: %+v", cycle, summary)
		}
		after, err := os.ReadFile(cfg.BehaviorProfileFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(tampered) {
			t.Fatalf("Persist cycle %d modified the manipulated baseline on disk", cycle)
		}
	}

	// Only the explicit operator reset leaves the fail-closed state. It starts an isolated
	// re-learning phase with a fresh authenticated document.
	resetModel, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := resetModel.ResetAfterIntegrityFailure("operator inspected the profile document"); err != nil {
		t.Fatalf("explicit operator reset failed: %v", err)
	}
	if !resetModel.Summary().IntegrityOK {
		t.Fatal("the operator reset did not restore an authenticated baseline")
	}
	if profiles := resetModel.Snapshot(0); len(profiles) != 0 {
		t.Fatalf("the operator reset carried poisoned profiles into re-learning: %+v", profiles)
	}
	fresh, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Summary().IntegrityOK {
		t.Fatalf("the fresh authenticated baseline does not load: %+v", fresh.Summary())
	}

	// A model without an integrity failure has nothing to reset.
	healthy := &BehaviorModel{enabled: true, path: cfg.BehaviorProfileFile, profiles: map[string]*behaviorProfile{}, maxProfiles: 64, maxPorts: 64}
	if err := healthy.ResetAfterIntegrityFailure("no failure"); err == nil {
		t.Fatal("a healthy model accepted an integrity reset")
	}
}

// TestBehaviorProfileRejectsNegativeVarianceWithAValidMAC reaches the bounds validation through
// a document whose MAC really is current, so the rejection is not just the authentication check.
func TestBehaviorProfileRejectsNegativeVarianceWithAValidMAC(t *testing.T) {
	cfg := behaviorIntegrityConfig(t)
	model, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	model.mu.Lock()
	model.profiles = map[string]*behaviorProfile{
		"/usr/bin/example": {
			Executable:      "/usr/bin/example",
			ConnectionCount: runningStat{Samples: 2, Mean: 1, M2: -1},
			UniqueRemotes:   runningStat{Samples: 2, Mean: 1, M2: 1},
			RemotePorts:     map[uint16]uint64{443: 2},
		},
	}
	model.mu.Unlock()
	if err := model.Persist(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	summary := reloaded.Summary()
	if summary.IntegrityOK {
		t.Fatal("a negatively signed variance loaded successfully")
	}
	if !strings.Contains(summary.Error, "invalid bounds") {
		t.Fatalf("the rejection did not name the bounds violation: %q", summary.Error)
	}
}

// TestBehaviorLegacyPlaintextDocumentIsMigratedToAnEncryptedEnvelope covers the explicit
// migration path introduced with the strict storage decoder. A pre-key plaintext profile is
// only adopted because its payload carries its own HMAC; it is then immediately re-encrypted.
func TestBehaviorLegacyPlaintextDocumentIsMigratedToAnEncryptedEnvelope(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, bytes32(t), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig().XDR
	cfg.StorageKeyFile = ""
	cfg.LogKeyFile = filepath.Join(dir, "xdr.key")
	cfg.BehaviorProfileFile = filepath.Join(dir, "behavior.json")
	cfg.BehaviorWarmupSamples = 2
	plainModel, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	observeSomeBehavior(plainModel)
	if err := plainModel.Persist(); err != nil {
		t.Fatal(err)
	}
	initial, err := os.ReadFile(cfg.BehaviorProfileFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(initial), encryptedStorageSchema) {
		t.Fatal("the pre-migration fixture is already encrypted")
	}

	migratedCfg := cfg
	migratedCfg.StorageKeyFile = keyPath
	migrated, err := NewBehaviorModel(migratedCfg)
	if err != nil {
		t.Fatalf("the legacy document was not migrated: %v", err)
	}
	if !migrated.Summary().IntegrityOK {
		t.Fatalf("the migrated legacy document failed authentication: %+v", migrated.Summary())
	}
	sealed, err := os.ReadFile(cfg.BehaviorProfileFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sealed), encryptedStorageSchema) {
		t.Fatal("the migrated legacy document was not re-encrypted")
	}
	if strings.Contains(string(sealed), "203.0.113.7") {
		t.Fatal("the re-encrypted document still exposes the learned payload")
	}
}

func bytes32(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestBehaviorStatisticValidationRejectsNonFiniteSpread pins the NaN/Inf half of FIND-028.
//
// Every comparison against NaN is false, so "M2 < 0" accepted NaN and +Inf and let a poisoned
// statistic reach the z-score calculation, where it silently disabled anomaly detection.
func TestBehaviorStatisticValidationRejectsNonFiniteSpread(t *testing.T) {
	if !validRunningStat(runningStat{Samples: 3, Mean: 2.5, M2: 4}) {
		t.Fatal("a plausible statistic was rejected")
	}
	invalid := map[string]runningStat{
		"NaN M2":        {Samples: 2, Mean: 1, M2: math.NaN()},
		"+Inf M2":       {Samples: 2, Mean: 1, M2: math.Inf(1)},
		"-Inf M2":       {Samples: 2, Mean: 1, M2: math.Inf(-1)},
		"negative M2":   {Samples: 2, Mean: 1, M2: -0.5},
		"NaN mean":      {Samples: 2, Mean: math.NaN(), M2: 1},
		"+Inf mean":     {Samples: 2, Mean: math.Inf(1), M2: 1},
		"negative mean": {Samples: 2, Mean: -3, M2: 1},
	}
	for name, stat := range invalid {
		if validRunningStat(stat) {
			t.Errorf("%s was accepted as learned state: %+v", name, stat)
		}
	}
}
