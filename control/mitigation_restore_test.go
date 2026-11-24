// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testMitigationStateKey returns the ephemeral HMAC subkey used for a test mitigation state
// file. Production derives it from the runtime settings key.
func testMitigationStateKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestMitigationSurvivesRestart is F-03: the value is written down and re-asserted at the next start,
// both when it is still in force and when it drifted back during downtime.
func TestMitigationSurvivesRestart(t *testing.T) {
	cfg := defaultAdvisoryConfig()
	cfg.AutoMitigate = true
	cfg.MitigationFailures = 2
	statePath := filepath.Join(t.TempDir(), "mitigation.json")
	key := "kernel.unprivileged_userns_clone"
	stateKey := testMitigationStateKey(t)

	core := newFakeMitigationCore(key, "1")
	first := NewMitigationGuard(core, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
	first.AttachStateMACKey(stateKey)
	first.StatePath = statePath
	first.interval = time.Hour
	first.watch = 2 * time.Minute
	if _, err := first.Apply("persist me"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	first.Close()
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("the applied mitigation was not persisted: %v", err)
	}

	// Reboot with a kernel that reverted the value: the guard must set it again and verify.
	driftedCore := newFakeMitigationCore(key, "1")
	second := NewMitigationGuard(driftedCore, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
	second.AttachStateMACKey(stateKey)
	second.StatePath = statePath
	second.interval = time.Hour
	if err := second.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	defer second.Close()
	if got := driftedCore.get(key); got != "0" {
		t.Fatalf("the value was not re-asserted after the restart: %q", got)
	}

	// Reboot with the value still in force: the guard must keep it and report it as held.
	stableCore := newFakeMitigationCore(key, "0")
	third := NewMitigationGuard(stableCore, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
	third.AttachStateMACKey(stateKey)
	third.StatePath = statePath
	third.interval = time.Hour
	if err := third.Restore(); err != nil {
		t.Fatalf("restore in force: %v", err)
	}
	defer third.Close()
	if status := third.Status(); status.State != mitigationStateStable || status.Current != "0" {
		t.Fatalf("restored status = %+v", status)
	}

	// Rollback must remove the record so a reboot does not resurrect a mitigation an operator undid.
	if _, err := third.Rollback("undo"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("the persisted record survived a rollback: %v", err)
	}
}

// TestMitigationStateTamperIsRefused is F-19 / G-STATE-05: an unsigned, tampered or
// non-catalogued persisted mitigation may not cause a privileged sysctl write on restart.
func TestMitigationStateTamperIsRefused(t *testing.T) {
	cfg := defaultAdvisoryConfig()
	cfg.AutoMitigate = true
	cfg.MitigationFailures = 2
	statePath := filepath.Join(t.TempDir(), "mitigation.json")
	catalogueKey := "kernel.unprivileged_userns_clone"
	stateKey := testMitigationStateKey(t)

	guard := NewMitigationGuard(newFakeMitigationCore(catalogueKey, "1"), exposedHostCache(t), cfg, NewState("test", Config{}), nil)
	guard.AttachStateMACKey(stateKey)
	guard.StatePath = statePath
	guard.interval = time.Hour
	guard.watch = 2 * time.Minute
	if _, err := guard.Apply("authenticate this record"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	guard.Close()
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var stored persistedMitigation
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}

	restore := func(value string) (*fakeMitigationCore, error) {
		attempt := newFakeMitigationCore(catalogueKey, "1")
		g := NewMitigationGuard(attempt, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
		g.AttachStateMACKey(stateKey)
		g.StatePath = statePath
		g.interval = time.Hour
		return attempt, g.Restore()
	}

	// Tampered value with the old signature.
	stored.Desired = "1"
	tampered, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	core, restoreErr := restore("1")
	if restoreErr == nil {
		t.Fatal("tampered mitigation state was accepted")
	}
	if core.writes != 0 {
		t.Fatal("tampered mitigation state caused a privileged sysctl write")
	}

	// Correctly signed but outside the compiled catalogue: the state file must not become a
	// route to an arbitrary privileged write even with key access.
	payload, err := mitigationStatePayload(stored)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := guard.mitigationMAC(payload)
	if err != nil {
		t.Fatal(err)
	}
	stored.Signature = hex.EncodeToString(signature)
	signed, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	core, restoreErr = restore("1")
	if restoreErr == nil {
		t.Fatal("authenticated but non-catalogued mitigation state was accepted")
	}
	if core.writes != 0 {
		t.Fatal("non-catalogued mitigation state caused a privileged sysctl write")
	}
}

// readPersistedMitigation decodes the state file a guard wrote.
func readPersistedMitigation(t *testing.T, path string) persistedMitigation {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mitigation state could not be read: %v", err)
	}
	var stored persistedMitigation
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("mitigation state is not valid JSON: %v", err)
	}
	return stored
}

// TestMitigationRestorePreviousAttribution is the FIND-029 regression: the value that was in force
// before the write is measured and persisted, so a rollback restores exactly it; a record whose
// previous value cannot be attributed is marked explicitly as "unattributed" instead of logging the
// undefined literal "unknown", it survives a restart, and a rollback refuses to write a guessed value.
func TestMitigationRestorePreviousAttribution(t *testing.T) {
	const key = "kernel.unprivileged_userns_clone"
	cfg := defaultAdvisoryConfig()
	cfg.AutoMitigate = true
	cfg.MitigationFailures = 2
	stateKey := testMitigationStateKey(t)

	t.Run("measured previous value is persisted, restored and reverted", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "measured.json")
		guard := NewMitigationGuard(newFakeMitigationCore(key, "1"), exposedHostCache(t), cfg, NewState("test", Config{}), nil)
		guard.AttachStateMACKey(stateKey)
		guard.StatePath = statePath
		guard.interval = time.Hour
		guard.watch = 2 * time.Minute
		if _, err := guard.Apply("measure the previous value"); err != nil {
			t.Fatalf("apply: %v", err)
		}
		guard.Close()
		stored := readPersistedMitigation(t, statePath)
		if stored.Previous != "1" || stored.PreviousSource != mitigationPreviousMeasured {
			t.Fatalf("persisted previous = %q (source %q), want measured \"1\"", stored.Previous, stored.PreviousSource)
		}

		drifted := newFakeMitigationCore(key, "1") // the reboot reverted the closed value
		restored := NewMitigationGuard(drifted, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
		restored.AttachStateMACKey(stateKey)
		restored.StatePath = statePath
		restored.interval = time.Hour
		if err := restored.Restore(); err != nil {
			t.Fatalf("restore: %v", err)
		}
		defer restored.Close()
		if status := restored.Status(); status.Previous != "1" || status.PreviousSource != mitigationPreviousMeasured {
			t.Fatalf("restored previous attribution = %q/%q", status.Previous, status.PreviousSource)
		}
		if got := drifted.get(key); got != "0" {
			t.Fatalf("the restored mitigation was not re-asserted: %q", got)
		}
		if _, err := restored.Rollback("operator undo"); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		if got := drifted.get(key); got != "1" {
			t.Fatalf("rollback did not restore the measured previous value: %q", got)
		}
	})

	t.Run("adopted in-force value is explicitly unattributed and a rollback refuses to guess", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "adopted.json")
		core := newFakeMitigationCore(key, "0") // value already closed, state record missing
		guard := NewMitigationGuard(core, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
		guard.AttachStateMACKey(stateKey)
		guard.StatePath = statePath
		guard.interval = time.Hour
		defer guard.Close()
		if err := guard.adoptInForce(); err != nil {
			t.Fatalf("adopt in-force value: %v", err)
		}
		if guard.record == nil {
			t.Fatal("the in-force value was not adopted")
		}
		status := guard.Status()
		if status.Previous != "" || status.PreviousSource != mitigationPreviousUnattributed {
			t.Fatalf("adopted previous attribution = %q/%q, want explicit unattributed", status.Previous, status.PreviousSource)
		}
		stored := readPersistedMitigation(t, statePath)
		if stored.Previous != "" || stored.PreviousSource != mitigationPreviousUnattributed {
			t.Fatalf("persisted adopted previous = %q (source %q), want unattributed", stored.Previous, stored.PreviousSource)
		}
		raw, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"unknown"`) {
			t.Fatal("the adopted record still contains the undefined previous value \"unknown\"")
		}

		// The unattributed record survives a restart, keeps its attribution and keeps
		// asserting; a rollback must refuse to write a guessed value and leave the
		// protection in force (FIND-029 restore policy).
		restartedCore := newFakeMitigationCore(key, "0")
		restarted := NewMitigationGuard(restartedCore, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
		restarted.AttachStateMACKey(stateKey)
		restarted.StatePath = statePath
		restarted.interval = time.Hour
		if err := restarted.Restore(); err != nil {
			t.Fatalf("the unattributed adoption did not survive a restart: %v", err)
		}
		defer restarted.Close()
		if restoredStatus := restarted.Status(); restoredStatus.PreviousSource != mitigationPreviousUnattributed || restoredStatus.Previous != "" {
			t.Fatalf("restored attribution = %q/%q, want unattributed with no invented value",
				restoredStatus.Previous, restoredStatus.PreviousSource)
		}
		if _, err := restarted.Rollback("operator undo"); err == nil {
			t.Fatal("a rollback of an unattributed record wrote a guessed value")
		}
		if strings.Contains(restarted.Status().Reason, "unknown") {
			t.Fatalf("the status still reports an undefined previous state: %q", restarted.Status().Reason)
		}
		if got := restartedCore.get(key); got != "0" {
			t.Fatalf("the refused rollback changed the value: %q", got)
		}
		restartedCore.set(key, "1")
		if stop := restarted.tick(context.Background()); stop {
			t.Fatal("the guard stopped asserting after a refused rollback")
		}
		if got := restartedCore.get(key); got != "0" {
			t.Fatalf("the guard no longer re-asserts the unattributed mitigation: %q", got)
		}
	})

	t.Run("legacy unknown value is migrated to unattributed instead of being refused", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "legacy.json")
		writer := NewMitigationGuard(newFakeMitigationCore(key, "1"), exposedHostCache(t), cfg, NewState("test", Config{}), nil)
		writer.AttachStateMACKey(stateKey)
		writer.StatePath = statePath
		writer.interval = time.Hour
		writer.watch = 2 * time.Minute
		if _, err := writer.Apply("legacy record"); err != nil {
			t.Fatalf("apply: %v", err)
		}
		writer.Close()

		// Re-create the exact record the vulnerable build persisted: a correctly signed
		// record whose previous field carries the undefined non-value "unknown".
		stored := readPersistedMitigation(t, statePath)
		stored.Previous = "unknown"
		stored.PreviousSource = ""
		payload, err := mitigationStatePayload(stored)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := writer.mitigationMAC(payload)
		if err != nil {
			t.Fatal(err)
		}
		stored.Signature = hex.EncodeToString(signature)
		encoded, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}

		core := newFakeMitigationCore(key, "1")
		guard := NewMitigationGuard(core, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
		guard.AttachStateMACKey(stateKey)
		guard.StatePath = statePath
		guard.interval = time.Hour
		if err := guard.Restore(); err != nil {
			t.Fatalf("the legacy record was refused instead of migrated: %v", err)
		}
		defer guard.Close()
		status := guard.Status()
		if status.Previous != "" || status.PreviousSource != mitigationPreviousUnattributed {
			t.Fatalf("legacy previous attribution = %q/%q, want unattributed", status.Previous, status.PreviousSource)
		}
		if got := core.get(key); got != "0" {
			t.Fatalf("the migrated legacy record was not re-asserted: %q", got)
		}
	})
}
