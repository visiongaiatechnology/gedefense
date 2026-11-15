// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3 engine tests: the fail-closed latch, restart recovery, the
// phase aggregation, the evidence-intent gate, the duress/boot-trust paths and
// the authenticated state envelope. The fixtures and the fake core live in
// lockdown_test.go; this file is split out so every test file stays within the
// documented 500-line budget.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockdownTriggerLatchesAndSurvivesRestart(t *testing.T) {
	fixture := newLockdownFixture(t, true, nil)
	view, err := fixture.trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper, Incident: "inc-1", Fingerprint: "fp-1"})
	if err != nil {
		t.Fatalf("trigger failed: %v", err)
	}
	if !view.Latched || view.State != lockdownStateActive {
		t.Fatalf("trigger did not latch: %+v", view)
	}
	if view.Epoch != "0badc0de" {
		t.Fatalf("the core epoch was not adopted: %q", view.Epoch)
	}
	// The kernel phases are adopted from the core answer and never invented.
	if lockdownPhaseStatus(view.Phases, lockdownPhaseNameNet) != lockdownPhaseApplied ||
		lockdownPhaseStatus(view.Phases, lockdownPhaseNameUSB) != lockdownPhaseApplied ||
		lockdownPhaseStatus(view.Phases, lockdownPhaseNameHardening) != lockdownPhaseUnsupported {
		t.Fatalf("core phases were not adopted verbatim: %+v", view.Phases)
	}
	// A restart must recover the latch, not release it.
	restarted, err := NewLockdownEngine(LockdownEngineConfig{Path: fixture.path, Settings: fixture.store, State: fixture.state, Core: fixture.core.client})
	if err != nil {
		t.Fatal(err)
	}
	after := restarted.StatusView()
	if !after.Latched || after.State != lockdownStateActive || after.Epoch != "0badc0de" {
		t.Fatalf("restart released the latch: %+v", after)
	}
	if after.Trigger == nil || after.Trigger.Fingerprint != "fp-1" {
		t.Fatalf("trigger identity did not survive the restart: %+v", after.Trigger)
	}
}

func TestLockdownCorruptStateFailsClosed(t *testing.T) {
	for name, payload := range map[string]string{
		"garbage":          "not-json-at-all",
		"wrong-schema":     `{"schema":"v1","revision":1,"state":"disarmed","updated_at":"2026-01-01T00:00:00Z"}`,
		"unknown-state":    `{"schema":"vgt-gedefense-lockdown-engine-v1","revision":1,"state":"off","mode":"locked","updated_at":"2026-01-01T00:00:00Z"}`,
		"latched-disarmed": `{"schema":"vgt-gedefense-lockdown-engine-v1","revision":1,"state":"disarmed","mode":"locked","latched":true,"updated_at":"2026-01-01T00:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newLockdownFixture(t, true, nil)
			if err := os.WriteFile(fixture.path, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			engine, err := NewLockdownEngine(LockdownEngineConfig{Path: fixture.path, Settings: fixture.store, State: fixture.state, Core: fixture.core.client})
			if err != nil {
				t.Fatal(err)
			}
			view := engine.StatusView()
			if !view.Latched || view.State != lockdownStateActive {
				t.Fatalf("a corrupt document did not fail closed: %+v", view)
			}
			if view.Evidence != "degraded" || view.Degraded == "" || !validLockdownEpoch(view.Epoch) {
				t.Fatalf("the degraded recovery was not reported: %+v", view)
			}
			// The recovery must be persisted so the next start stays latched.
			recovered, err := NewLockdownEngine(LockdownEngineConfig{Path: fixture.path, Settings: fixture.store, State: fixture.state, Core: fixture.core.client})
			if err != nil {
				t.Fatal(err)
			}
			if next := recovered.StatusView(); !next.Latched || next.Epoch != view.Epoch {
				t.Fatalf("the recovered latch was not persisted: %+v", next)
			}
		})
	}
}

// ------------------------------------------------------------- trigger matrix

func TestLockdownIncidentTriggerMatrix(t *testing.T) {
	settings := defaultLockdownFabricSettings()
	settings.Enabled = true
	morpheus := XDRIncident{ID: "m", Severity: "CRITICAL", RuleIDs: []string{"MORPHEUS.RASP.MEM_SCRAPE"}, PID: 42, StartTicks: 7, UID: 1000}
	canary := func(reason string, severity string) XDRIncident {
		return XDRIncident{ID: "c", Severity: severity, PID: 7, RuleIDs: []string{"KD.LINUX.CANARY_ACCESS"}, AttackStory: []AttackStoryNode{{Metadata: map[string]string{"trigger_reason": reason}}}}
	}
	accepted := []struct {
		name     string
		incident XDRIncident
		reason   string
	}{
		{"morpheus-critical", morpheus, lockdownReasonTamper},
		{"canary-unauthorized", canary("CANARY_UNAUTHORIZED_PROBE", "CRITICAL"), lockdownReasonXDRCritical},
	}
	for _, test := range accepted {
		candidate, ok := lockdownIncidentCandidate(settings, test.incident)
		if !ok || candidate.Reason != test.reason || candidate.Source != lockdownSourcePolicy {
			t.Fatalf("%s was not accepted: %+v ok=%t", test.name, candidate, ok)
		}
		if candidate.Fingerprint == "" {
			t.Fatalf("%s produced no bounded fingerprint", test.name)
		}
	}
	rejected := map[string]XDRIncident{
		"morpheus-non-critical": {ID: "r1", Severity: "high", RuleIDs: []string{"MORPHEUS.RASP.MEM_SCRAPE"}},
		"trusted-debugger-rule": {ID: "r2", Severity: "CRITICAL", RuleIDs: []string{"MORPHEUS.DEBUGGER.TRUSTED"}},
		"system-canary":         canary("CANARY_SUSPICIOUS_SYSTEM_ACCESS", "HIGH"),
		"canary-wrong-reason":   canary("CANARY_SUSPICIOUS_SYSTEM_ACCESS", "CRITICAL"),
		"canary-no-reason":      {ID: "r5", Severity: "CRITICAL", RuleIDs: []string{"KD.LINUX.CANARY_ACCESS"}},
		"unrelated-critical":    {ID: "r6", Severity: "CRITICAL", RuleIDs: []string{"XDR.THREAT_INTEL_C2"}},
	}
	for name, incident := range rejected {
		if candidate, ok := lockdownIncidentCandidate(settings, incident); ok {
			t.Fatalf("%s wrongly matched the trigger matrix: %+v", name, candidate)
		}
	}
	// A switch turned off must silence its family.
	off := settings
	off.TriggerMorpheusCritical = false
	if _, ok := lockdownIncidentCandidate(off, morpheus); ok {
		t.Fatal("a disabled Morpheus switch still triggered")
	}
}

func TestLockdownRequireSourcesAndCooldownAndDedupe(t *testing.T) {
	fixture := newLockdownFixture(t, true, func(settings *LockdownFabricSettings) {
		settings.RequireSources = 2
		settings.CooldownSeconds = 0
	})
	first := lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper, Fingerprint: "fp-correlated"}
	if _, err := fixture.trigger(first); !errors.Is(err, errLockdownSourcesPending) {
		t.Fatalf("one source latched despite require_sources=2: %v", err)
	}
	if fixture.engine.StatusView().Latched {
		t.Fatal("the engine latched before the correlation was satisfied")
	}
	// A second candidate from the same reason family does not satisfy the
	// correlation; only a genuinely distinct source does.
	sameFamily := lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper, Fingerprint: "fp-same-family"}
	if _, err := fixture.trigger(sameFamily); !errors.Is(err, errLockdownSourcesPending) {
		t.Fatalf("the same reason family satisfied require_sources=2: %v", err)
	}
	second := lockdownTriggerCandidate{Source: lockdownSourceTimer, Reason: lockdownReasonBootTrust, Fingerprint: "fp-correlated"}
	view, err := fixture.trigger(second)
	if err != nil || !view.Latched {
		t.Fatalf("the second distinct source did not latch: view=%+v err=%v", view, err)
	}
	// Dedupe: after a clear, the very same candidate is suppressed and counted.
	if _, err := fixture.engine.Clear(view.Epoch, lockdownReasonManual, "operator clear request", "req-1"); err != nil {
		t.Fatalf("clear failed: %v", err)
	}
	if _, err := fixture.trigger(first); !errors.Is(err, errLockdownCooldown) {
		t.Fatalf("duplicate fingerprint was not suppressed: %v", err)
	}
	if fixture.engine.StatusView().FalsePositiveGuards == 0 {
		t.Fatal("the suppressed candidate was not counted")
	}
	// Cooldown: a different candidate within cooldown_seconds is suppressed.
	fixture = newLockdownFixture(t, true, func(settings *LockdownFabricSettings) { settings.CooldownSeconds = 300 })
	view, err = fixture.trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper, Fingerprint: "fp-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.engine.Clear(view.Epoch, lockdownReasonManual, "operator clear request", "req-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonXDRCritical, Fingerprint: "fp-b"}); !errors.Is(err, errLockdownCooldown) {
		t.Fatalf("cooldown was not enforced: %v", err)
	}
}

// ------------------------------------------------------------- clear contract

func TestLockdownClearRequiresMatchingEpochAndStaysLatched(t *testing.T) {
	fixture := newLockdownFixture(t, true, nil)
	view, err := fixture.trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.engine.Clear("deadbeef", lockdownReasonManual, "operator clear request", "req-x"); !errors.Is(err, errLockdownEpochMismatch) {
		t.Fatalf("a wrong epoch was accepted: %v", err)
	}
	if !fixture.engine.StatusView().Latched {
		t.Fatal("a wrong epoch released the latch")
	}
	// The core compares the epoch too: an epoch the kernel no longer holds keeps
	// the engine latched.
	fixture.core.setHandler(func(fields []string) (string, string) {
		if fields[3] == "LOCKDOWN_CLEAR" {
			return "ERR", "lockdown epoch mismatch"
		}
		return lockdownDefaultCoreHandler("0badc0de")(fields)
	})
	if _, err := fixture.engine.Clear(view.Epoch, lockdownReasonManual, "operator clear request", "req-y"); !errors.Is(err, errLockdownEpochMismatch) {
		t.Fatalf("a core epoch mismatch was not reported: %v", err)
	}
	if !fixture.engine.StatusView().Latched {
		t.Fatal("a core epoch mismatch released the latch")
	}
	fixture.core.setHandler(lockdownDefaultCoreHandler("0badc0de"))
	cleared, err := fixture.engine.Clear(view.Epoch, lockdownReasonManual, "operator clear request", "req-z")
	if err != nil {
		t.Fatalf("the authenticated clear failed: %v", err)
	}
	if cleared.Latched || cleared.State != lockdownStateDisarmed {
		t.Fatalf("the clear did not release the latch: %+v", cleared)
	}
	restarted, err := NewLockdownEngine(LockdownEngineConfig{Path: fixture.path, Settings: fixture.store, State: fixture.state, Core: fixture.core.client})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.StatusView().Latched {
		t.Fatal("the cleared state was not persisted")
	}
	if _, err := fixture.engine.Clear(view.Epoch, lockdownReasonManual, "operator clear request", "req-w"); !errors.Is(err, errLockdownNotLatched) {
		t.Fatalf("a second clear was accepted: %v", err)
	}
}

// ------------------------------------------------------------ phase results

func TestLockdownPhasesReportPartialAndHonestUnavailable(t *testing.T) {
	fixture := newLockdownFixture(t, true, nil)
	view, err := fixture.trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper})
	if err != nil {
		t.Fatal(err)
	}
	if lockdownPhaseStatus(view.Phases, lockdownPhaseNameNet) != lockdownPhaseApplied {
		t.Fatalf("net was not adopted: %+v", view.Phases)
	}
	// sessions/dm/kernel lockdown are unsupported facts, never fake applies.
	for _, name := range []string{lockdownPhaseNameSessions, lockdownPhaseNameDM, lockdownPhaseNameKernelLockdown} {
		if lockdownPhaseStatus(view.Phases, name) != lockdownPhaseUnsupported {
			t.Fatalf("%s must be honestly unsupported: %+v", name, view.Phases)
		}
	}
	// No cells runtime attached: the cell phase is unavailable, not applied.
	if lockdownPhaseStatus(view.Phases, lockdownPhaseNameCells) != lockdownPhaseUnavailable {
		t.Fatalf("cells overclaimed: %+v", view.Phases)
	}
	if lockdownPhaseStatus(view.Phases, lockdownPhaseNameParserCells) != lockdownPhaseUnavailable {
		t.Fatalf("parser cells overclaimed: %+v", view.Phases)
	}
	if !strings.Contains(lockdownPhaseSummary(view.Phases), "applied=") {
		t.Fatal("the phase summary is not bounded and readable")
	}
}

func TestLockdownEvidenceIntentFailureBlocksPhases(t *testing.T) {
	fixture := newLockdownFixture(t, true, nil)
	// Detach the ledger: §9 says phases without intent evidence must not run.
	fixture.state.mu.Lock()
	fixture.state.evidence = nil
	fixture.state.mu.Unlock()
	view, err := fixture.trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper})
	if err != nil {
		t.Fatalf("the latch itself must be fail-closed even without evidence: %v", err)
	}
	if !view.Latched {
		t.Fatal("the engine did not latch")
	}
	if fixture.core.count("LOCKDOWN_TRIGGER") != 0 {
		t.Fatal("isolation phases ran without an intent evidence record")
	}
	if lockdownPhaseStatus(view.Phases, "evidence") != lockdownPhaseFailed {
		t.Fatalf("the blocked evidence intent was not reported: %+v", view.Phases)
	}
	if view.Evidence != "unavailable" && view.Evidence != "degraded" {
		t.Fatalf("the degraded evidence path was not reported: %+v", view)
	}
}

// -------------------------------------------------- duress and boot-trust

func TestLockdownDuressAndBootTrustTriggers(t *testing.T) {
	duressDir := t.TempDir()
	duressPath := filepath.Join(duressDir, "duress.token")
	fixture := newLockdownFixture(t, true, func(settings *LockdownFabricSettings) {
		settings.DuressTokenPath = duressPath
		settings.CooldownSeconds = 0
	})
	// An absent/empty file must never trigger.
	fixture.engine.pollDuress(time.Now().UTC())
	if fixture.engine.StatusView().Latched {
		t.Fatal("an absent duress token triggered")
	}
	if err := os.WriteFile(duressPath, []byte("panic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.engine.pollDuress(time.Now().UTC())
	view := fixture.engine.StatusView()
	if !view.Latched || view.Trigger == nil || view.Trigger.Reason != lockdownReasonManual {
		t.Fatalf("a duress token did not latch: %+v", view)
	}
	if view.DuressConfigured != true || strings.Contains(lockdownMustJSON(t, view), duressPath) {
		t.Fatal("the duress path leaked into the status projection")
	}

	// Boot-trust: only a VERIFIED -> OBSERVE degradation triggers; NOT_SUPPORTED
	// is a platform fact and must never latch.
	boot := newLockdownFixture(t, true, func(settings *LockdownFabricSettings) { settings.CooldownSeconds = 0 })
	verdict := bootTrustStatusVerified
	boot.engine.AttachBootTrust(func() (string, string) { return verdict, "boot chain verdict" })
	boot.engine.reconcileBootTrust(time.Now().UTC())
	if boot.engine.StatusView().Latched {
		t.Fatal("the first boot-trust sample triggered")
	}
	verdict = bootTrustStatusNotSupported
	boot.engine.reconcileBootTrust(time.Now().UTC())
	if boot.engine.StatusView().Latched {
		t.Fatal("NOT_SUPPORTED triggered a lockdown")
	}
	verdict = bootTrustStatusObserve
	boot.engine.reconcileBootTrust(time.Now().UTC())
	if boot.engine.StatusView().Trigger == nil || boot.engine.StatusView().Trigger.Reason != lockdownReasonBootTrust {
		t.Fatalf("a boot-trust degradation did not trigger: %+v", boot.engine.StatusView())
	}
}

// ------------------------------------------------------------- max targets

func TestLockdownParserCellPhaseRespectsMaxTargets(t *testing.T) {
	fixture := newLockdownFixture(t, true, func(settings *LockdownFabricSettings) { settings.MaxTargets = 2 })
	// A manager with four live cells and no helper: every burn is refused, the
	// phase must report the bound instead of walking the whole inventory.
	manager := &ParserCellManager{
		desired:   ParserCellsFabricSettings{Enabled: true, BurnOnIncident: true, IncidentScore: 80, CooldownSeconds: 0, MaxConcurrent: 4},
		cells:     make(map[string]*ParserCellRuntime, 4),
		staged:    make(map[string]parserCellStagedInput, 1),
		cooldown:  make(map[uint64]time.Time, 4),
		now:       func() time.Time { return time.Now().UTC() },
		evidence:  func(EvidenceRecord) error { return nil },
		addEvent:  func(Event) {},
		clientErr: errors.New("parser helper is not available in this test"),
	}
	for index := 1; index <= 4; index++ {
		manager.cells["cell-"+string(rune('a'+index-1))] = &ParserCellRuntime{
			UUID: "cell-" + string(rune('a'+index-1)), CellClass: parserCellsClassEphemeral,
			CgroupID: uint64(index), State: parserCellStateIsolated, Generation: 1,
		}
	}
	if err := fixture.state.AttachParserCells(manager); err != nil {
		t.Fatal(err)
	}
	settings := effectiveLockdownSettings(fixture.store.Get())
	phase := fixture.engine.runParserCellPhase(settings)
	if phase.Targets != 2 {
		t.Fatalf("max_targets was not enforced: %+v", phase)
	}
	if phase.Status != lockdownPhaseFailed {
		t.Fatalf("refused burns must not be reported as applied: %+v", phase)
	}
}

// ------------------------------------------------------------------- helpers

func lockdownPhaseStatus(phases []LockdownPhaseView, name string) string {
	for _, phase := range phases {
		if phase.Phase == name {
			return phase.Status
		}
	}
	return ""
}

func lockdownMustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestLockdownStateCipherSealsTheDocument proves the persisted latch is an
// authenticated envelope and a tampered document fails closed.
func TestLockdownStateCipherSealsTheDocument(t *testing.T) {
	fixture := newLockdownFixture(t, true, nil)
	keyPath := filepath.Join(fixture.dir, "storage.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewStorageCipher(keyPath, "test-node")
	if err != nil {
		t.Fatal(err)
	}
	enginePath := filepath.Join(fixture.dir, "sealed-lockdown.state")
	engine, err := NewLockdownEngine(LockdownEngineConfig{Path: enginePath, Storage: cipher, Settings: fixture.store, State: fixture.state, Core: fixture.core.client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper, Fingerprint: "sealed"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(enginePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), encryptedStorageSchema) || strings.Contains(string(raw), "vgt-gedefense-lockdown-engine-v1") {
		t.Fatal("the latch document was not sealed with the storage cipher")
	}
	// Flip one ciphertext byte: the envelope must refuse and the engine latch.
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 0x01
	if err := os.WriteFile(enginePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewLockdownEngine(LockdownEngineConfig{Path: enginePath, Storage: cipher, Settings: fixture.store, State: fixture.state, Core: fixture.core.client})
	if err != nil {
		t.Fatal(err)
	}
	if view := recovered.StatusView(); !view.Latched || view.Evidence != "degraded" {
		t.Fatalf("a tampered sealed document did not fail closed: %+v", view)
	}
}

// TestLockdownClearResumesTheFrozenProcess proves the documented reversibility:
// the trigger freezes an incident-bound process through the core, the identity is
// persisted in the latch document, and the authenticated clear (even after a
// restart) resumes exactly that process.
func TestLockdownClearResumesTheFrozenProcess(t *testing.T) {
	fixture := newLockdownFixture(t, true, nil)
	view, err := fixture.trigger(lockdownTriggerCandidate{
		Source: lockdownSourcePolicy, Reason: lockdownReasonTamper, Fingerprint: "process-target",
		PID: 4242, StartTicks: 99, UID: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if lockdownPhaseStatus(view.Phases, lockdownPhaseNameProcesses) != lockdownPhaseApplied {
		t.Fatalf("the incident process was not frozen: %+v", view.Phases)
	}
	if fixture.core.count("XDR_STOP") != 1 {
		t.Fatalf("core XDR_STOP was issued %d times", fixture.core.count("XDR_STOP"))
	}
	// The clear after a restart must still resume the persisted target.
	restarted, err := NewLockdownEngine(LockdownEngineConfig{Path: fixture.path, Settings: fixture.store, State: fixture.state, Core: fixture.core.client})
	if err != nil {
		t.Fatal(err)
	}
	recovered := restarted.StatusView()
	if recovered.Trigger == nil || recovered.Trigger.Fingerprint != "process-target" {
		t.Fatalf("the trigger identity was not recovered: %+v", recovered.Trigger)
	}
	if _, err := restarted.Clear(recovered.Epoch, lockdownReasonManual, "operator clear request", "req-resume-0001"); err != nil {
		t.Fatalf("clear failed: %v", err)
	}
	if fixture.core.count("XDR_CONT") != 1 {
		t.Fatalf("the frozen process was not resumed: %d XDR_CONT", fixture.core.count("XDR_CONT"))
	}
}
