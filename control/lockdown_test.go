// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3 unit tests: settings/migration, the fail-closed latch, the
// trigger matrix (including every documented negative), the automatic guards,
// the phase aggregation, the evidence intent gate and the duress/boot-trust
// paths.

import (
	"bufio"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ------------------------------------------------------------- fake core IPC

// lockdownFakeCore answers authenticated VGT3 requests from the engine. Its
// handler receives the full field slice (protocol, stamp, nonce, command...).
type lockdownFakeCore struct {
	t        *testing.T
	client   *CoreClient
	listener net.Listener
	mu       sync.Mutex
	requests []string
	args     map[string][]string
	handler  func(fields []string) (string, string)
}

func newLockdownFakeCore(t *testing.T) *lockdownFakeCore {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "core.sock")
	client, err := NewCoreClient(socket, filepath.Join(dir, "core.key"), 2*time.Second)
	if err != nil {
		t.Fatalf("fake core client: %v", err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("fake core listener: %v", err)
	}
	fake := &lockdownFakeCore{t: t, client: client, listener: listener, args: make(map[string][]string)}
	fake.handler = lockdownDefaultCoreHandler("0badc0de")
	go fake.acceptLoop()
	t.Cleanup(func() { _ = listener.Close() })
	return fake
}

func (f *lockdownFakeCore) acceptLoop() {
	for {
		connection, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.serve(connection)
	}
}

func (f *lockdownFakeCore) serve(connection net.Conn) {
	defer connection.Close()
	line, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 5 || fields[0] != coreProtocol {
		return
	}
	if fields[len(fields)-1] != coreMAC(f.client.key, fields[:len(fields)-1]...) {
		return
	}
	command := fields[3]
	f.mu.Lock()
	f.requests = append(f.requests, command)
	f.args[command] = append([]string(nil), fields...)
	handler := f.handler
	f.mu.Unlock()
	status, payload := handler(fields)
	tag := coreProtocol + "R"
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := coreMAC(f.client.key, tag, fields[2], status, encoded)
	_, _ = connection.Write([]byte(strings.Join([]string{tag, fields[2], status, encoded, mac}, " ") + "\n"))
}

func (f *lockdownFakeCore) count(command string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, request := range f.requests {
		if request == command {
			count++
		}
	}
	return count
}

func (f *lockdownFakeCore) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *lockdownFakeCore) setHandler(handler func(fields []string) (string, string)) {
	f.mu.Lock()
	f.handler = handler
	f.mu.Unlock()
}

// lockdownDefaultCoreHandler implements the §5 answers of a capability-complete
// core. The epoch is fixed so tests can compare it.
func lockdownDefaultCoreHandler(epoch string) func(fields []string) (string, string) {
	return func(fields []string) (string, string) {
		switch fields[3] {
		case "LOCKDOWN_STATUS":
			return "OK", "state=active;epoch=" + epoch + ";mode=locked;flags=1;phases=net,usb,cells=delegated;unsupported=sessions,dm"
		case "LOCKDOWN_ARM":
			return "OK", "armed:" + epoch
		case "LOCKDOWN_TRIGGER":
			return "OK", "triggered:" + epoch + ";phases=net,usb,tb,brokers;unsupported=hardening"
		case "LOCKDOWN_CLEAR":
			if len(fields) > 4 && fields[4] == epoch {
				return "OK", "cleared"
			}
			return "ERR", "lockdown epoch mismatch"
		case "LOCKDOWN_HEALTH":
			return "OK", "1:2:3:4:5:6"
		case "LOCKDOWN_EVENTS":
			return "OK", "empty"
		case "LOCKDOWN_VERSION":
			return "OK", lockdownCoreVersion
		case "LOCKDOWN_EPOCH":
			return "OK", epoch
		case "XDR_STOP":
			return "OK", "stopped"
		case "XDR_CONT":
			return "OK", "resumed"
		}
		return "ERR", "unknown command"
	}
}

// capabilityMissingCoreHandler is the backwards-compatible old core.
func capabilityMissingCoreHandler(fields []string) (string, string) {
	switch fields[3] {
	case "LOCKDOWN_STATUS", "LOCKDOWN_ARM", "LOCKDOWN_TRIGGER", "LOCKDOWN_CLEAR",
		"LOCKDOWN_HEALTH", "LOCKDOWN_EVENTS", "LOCKDOWN_VERSION", "LOCKDOWN_EPOCH":
		return "ERR", "unknown command"
	}
	return "ERR", "unknown command"
}

// ---------------------------------------------------------------- fixtures

type lockdownFixture struct {
	dir    string
	store  *SettingsStore
	state  *State
	ledger *EvidenceLedger
	core   *lockdownFakeCore
	engine *LockdownEngine
	path   string
}

// newLockdownFixture builds an enabled or inert engine. Evidence is attached so
// the evidence-first contract is exercised by the real ledger, not a stub.
func newLockdownFixture(t *testing.T, enabled bool, mutate func(*LockdownFabricSettings)) *lockdownFixture {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Runtime.StorageKeyFile = ""
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", cfg)
	ledger, err := NewEvidenceLedger(
		filepath.Join(dir, "evidence.jsonl"), filepath.Join(dir, "evidence.ed25519"),
		"", "test-node", 4<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	fixture := &lockdownFixture{dir: dir, store: store, state: state, ledger: ledger, path: filepath.Join(dir, "lockdown-engine.state")}
	if enabled {
		next := store.Get()
		settings := effectiveLockdownSettings(next)
		settings.Enabled = true
		if mutate != nil {
			mutate(&settings)
		}
		next.Lockdown = &settings
		if _, err := store.Update(next); err != nil {
			t.Fatal(err)
		}
	}
	// The fake core is always constructed so a test can prove "no request" by
	// counting, and a disabled engine must never dial it.
	fixture.core = newLockdownFakeCore(t)
	engine, err := NewLockdownEngine(LockdownEngineConfig{
		Path: fixture.path, Settings: store, State: state, Core: fixture.core.client,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.engine = engine
	return fixture
}

func (f *lockdownFixture) trigger(candidate lockdownTriggerCandidate) (LockdownStatusView, error) {
	return f.engine.Trigger(candidate)
}

func (f *lockdownFixture) events() []Event {
	return f.state.Snapshot().Events
}

func (f *lockdownFixture) eventKinds() []string {
	kinds := make([]string, 0)
	for _, event := range f.events() {
		kinds = append(kinds, event.Kind)
	}
	return kinds
}

// -------------------------------------------------------- settings contract

func TestLockdownSettingsDefaultsMatchSpec(t *testing.T) {
	settings := defaultLockdownFabricSettings()
	if settings.Enabled || settings.AutoArm {
		t.Fatal("the shipped lockdown default must be inert")
	}
	checks := map[string]bool{
		"trigger_morpheus_critical":   settings.TriggerMorpheusCritical,
		"trigger_canary_unauthorized": settings.TriggerCanaryUnauthorized,
		"trigger_boot_trust_drift":    settings.TriggerBootTrustDrift,
		"freeze_processes":            settings.FreezeProcesses,
		"freeze_brokers":              settings.FreezeBrokers,
		"network_lockdown":            settings.NetworkLockdown,
		"allow_loopback":              settings.AllowLoopback,
		"freeze_cells":                settings.FreezeCells,
		"freeze_parser_cells":         settings.FreezeParserCells,
		"exclude_uid0":                settings.ExcludeUID0,
	}
	for name, value := range checks {
		if !value {
			t.Errorf("%s default must be true", name)
		}
	}
	if settings.DropLoopback || settings.HardeningApply {
		t.Error("drop_loopback and hardening_apply must default to false")
	}
	if settings.RequireSources != 1 || settings.CooldownSeconds != 300 || settings.MaxTargets != 256 {
		t.Fatalf("unexpected numeric defaults: %+v", settings)
	}
	if settings.CellScope != lockdownCellScopeAll || settings.DuressTokenPath != "" {
		t.Fatalf("unexpected scope/default duress path: %+v", settings)
	}
	// Clone is a value copy and must not share state.
	clone := cloneLockdownFabricSettings(settings)
	clone.Enabled = true
	if settings.Enabled {
		t.Fatal("clone aliased the original")
	}
}

func TestLockdownSettingsValidateRejectsOutOfBounds(t *testing.T) {
	cases := map[string]func(*LockdownFabricSettings){
		"require_sources-low":  func(s *LockdownFabricSettings) { s.RequireSources = 0 },
		"require_sources-high": func(s *LockdownFabricSettings) { s.RequireSources = 9 },
		"cooldown-high":        func(s *LockdownFabricSettings) { s.CooldownSeconds = 86401 },
		"max_targets-low":      func(s *LockdownFabricSettings) { s.MaxTargets = 0 },
		"max_targets-high":     func(s *LockdownFabricSettings) { s.MaxTargets = lockdownMaxTargetsCap + 1 },
		"unknown-cell-scope":   func(s *LockdownFabricSettings) { s.CellScope = "everything" },
		"relative-duress-path": func(s *LockdownFabricSettings) { s.DuressTokenPath = "duress.token" },
		"duress-path-with-nul": func(s *LockdownFabricSettings) { s.DuressTokenPath = "/etc/vgt/duress\x00.token" },
		"enabled-without-phases": func(s *LockdownFabricSettings) {
			s.Enabled = true
			s.NetworkLockdown, s.FreezeProcesses, s.FreezeBrokers = false, false, false
			s.FreezeCells, s.FreezeParserCells, s.HardeningApply = false, false, false
		},
	}
	for name, mutate := range cases {
		settings := defaultLockdownFabricSettings()
		mutate(&settings)
		if err := validateLockdownFabricSettings(&settings); err == nil {
			t.Errorf("%s: out-of-bounds settings were accepted", name)
		}
	}
	valid := defaultLockdownFabricSettings()
	valid.DuressTokenPath = "/etc/vgt/gedefense/duress.token"
	if err := validateLockdownFabricSettings(&valid); err != nil {
		t.Fatalf("a documented value was rejected: %v", err)
	}
}

func TestLockdownSettingsMigrationFromV15NamesTheNamespace(t *testing.T) {
	defaults := defaultRuntimeSettings(Config{})
	legacy := cloneRuntimeSettings(defaults)
	legacy.FabricVersion = 15
	legacy.Lockdown = nil
	upgraded := upgradeRuntimeSettings(&legacy, defaults)
	if !upgraded || legacy.FabricVersion != fabricSettingsVersion {
		t.Fatalf("v15 document was not upgraded: upgraded=%t version=%d", upgraded, legacy.FabricVersion)
	}
	if legacy.Lockdown == nil {
		t.Fatal("v16 did not seed the lockdown namespace")
	}
	if legacy.Lockdown.Enabled {
		t.Fatal("the migrated default must stay disabled")
	}
	named := false
	for _, note := range legacy.Migrations {
		if note == lockdownMigrationNote {
			named = true
		}
	}
	if !named {
		t.Fatal("the v15->v16 migration was not named in the migration record")
	}
}

// ------------------------------------------------------------ default inert

func TestLockdownDefaultOffIsInert(t *testing.T) {
	fixture := newLockdownFixture(t, false, nil)
	// Every entry point must be refused and must not touch the core or publish an
	// event. This is the upgrade contract: zero requests, zero events.
	if _, err := fixture.trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper}); !errors.Is(err, errLockdownDisabled) {
		t.Fatalf("trigger was not refused while disabled: %v", err)
	}
	fixture.engine.ObserveIncident(XDRIncident{ID: "inc-1", Severity: "CRITICAL", RuleIDs: []string{"MORPHEUS.RASP.MEM_SCRAPE"}})
	if len(fixture.events()) != 0 {
		t.Fatalf("a disabled engine published %d events", len(fixture.events()))
	}
	if fixture.core.total() != 0 {
		t.Fatalf("a disabled engine issued %d core commands", fixture.core.total())
	}
	if _, err := os.Stat(fixture.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a disabled engine wrote a latch document")
	}
	view := fixture.engine.StatusView()
	if view.Enabled || view.State != lockdownStateDisarmed || view.Latched {
		t.Fatalf("unexpected disabled status: %+v", view)
	}
}

// --------------------------------------------------------- latch persistence

// TestCoreLockdownWireRejectsHostileAnswers covers the response limits of the
// §5 text wire: an oversized or malformed answer from a buggy or hostile core is
// rejected as a whole instead of being projected into the status document.
func TestCoreLockdownWireRejectsHostileAnswers(t *testing.T) {
	oversized := strings.Repeat("A", maxLockdownPayloadBytes+1)
	status := []string{
		oversized,
		"state=off;epoch=0badc0de;mode=unlocked;flags=0;phases=;unsupported=" + ";extra=1",
		"state=off;epoch=0BADCODE;mode=unlocked;flags=0;phases=;unsupported=",
		"state=off;epoch=0badc0de;mode=unknown;flags=0;phases=;unsupported=",
		"state=off;epoch=0badc0de;mode=unlocked;flags=999;phases=;unsupported=",
		"state=off;epoch=0badc0de;mode=unlocked;flags=0;phases=net,net;unsupported=",
		"state=off;epoch=0badc0de;mode=unlocked;flags=0;phases=rules;unsupported=",
		"state=;epoch=0badc0de;mode=unlocked;flags=0;phases=;unsupported=",
		"",
	}
	for _, payload := range status {
		if _, err := parseCoreLockdownStatus(payload); err == nil {
			t.Fatalf("hostile status was accepted: %.40q", payload)
		}
	}
	triggers := []string{oversized, "triggered:0badc0de;phases=net", "triggered:zz;phases=;unsupported=", "triggered:0badc0de;phases=net;unsupported=net,extra", ""}
	for _, payload := range triggers {
		if _, err := parseCoreLockdownTrigger(payload); err == nil {
			t.Fatalf("hostile trigger answer was accepted: %.40q", payload)
		}
	}
	if _, err := parseCoreLockdownHealth("1:2:3:4:5"); err == nil {
		t.Fatal("a short health payload was accepted")
	}
	if _, err := parseCoreLockdownHealth("1:2:3:4:5:18446744073709551616"); err == nil {
		t.Fatal("an overflowing health counter was accepted")
	}
	// All-or-nothing: one bad lifecycle record rejects the whole batch.
	if events, dropped, err := parseCoreLockdownEvents("0|1:1700000000000:1:5:1:1,2:1700000000001:9:7:6:5"); err == nil || events != nil || dropped != 0 {
		t.Fatalf("a partially invalid event batch was accepted: events=%d dropped=%d err=%v", len(events), dropped, err)
	}
	if _, _, err := parseCoreLockdownEvents("0|" + strings.Repeat("1:2:3:4:5:6,", maxLockdownEventsPerResponse+1)); err == nil {
		t.Fatal("an over-ceiling event batch was accepted")
	}
}

// argsFor returns the full field slice of the most recent request for a command.
func (f *lockdownFakeCore) argsFor(command string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.args[command]...)
}

// TestLockdownCoreWireUsesFinalizedTokens pins the exact P5-T2 wire contract:
// lowercase mode/source/reason tokens, decimal flags and the "-" empty list.
func TestLockdownCoreWireUsesFinalizedTokens(t *testing.T) {
	fixture := newLockdownFixture(t, true, nil)
	if _, err := fixture.trigger(lockdownTriggerCandidate{Source: lockdownSourcePolicy, Reason: lockdownReasonTamper, Fingerprint: "wire"}); err != nil {
		t.Fatal(err)
	}
	trigger := fixture.core.argsFor("LOCKDOWN_TRIGGER")
	if len(trigger) != 8 || trigger[3] != "LOCKDOWN_TRIGGER" || trigger[4] != "policy" || trigger[5] != "tamper" {
		t.Fatalf("LOCKDOWN_TRIGGER wire fields are not the finalized tokens: %v", trigger)
	}
	if trigger[6] != "7" {
		t.Fatalf("expected flags 7 (network+loopback+brokers), got %q", trigger[6])
	}
	// The status answer from the finalized core is parsed as-is.
	view := fixture.engine.StatusView()
	if view.Core.State != "active" || !validLockdownEpoch(view.Core.Epoch) {
		t.Fatalf("the finalized status was not parsed: %+v", view.Core)
	}

	// A separate fixture: the first one is latched, and arming a latched engine is
	// correctly refused.
	armFixture := newLockdownFixture(t, true, nil)
	if _, err := armFixture.engine.Arm(lockdownModeLocked, lockdownReasonManual, "operator arms the kernel policy", "req-wire-arm-1"); err != nil {
		t.Fatal(err)
	}
	arm := armFixture.core.argsFor("LOCKDOWN_ARM")
	if len(arm) != 8 || arm[3] != "LOCKDOWN_ARM" || arm[4] != "locked" || arm[5] != "manual" {
		t.Fatalf("LOCKDOWN_ARM wire fields are not the finalized tokens: %v", arm)
	}

	// The finalized list encodings: "-" is the empty list and the delegated cells
	// token is normalised, the unsupported list carries sessions/dm.
	status, err := parseCoreLockdownStatus("state=degraded;epoch=0badc0de;mode=unlocked;flags=15;phases=net,usb,tb,hardening,brokers,cells=delegated;unsupported=sessions,dm")
	if err != nil {
		t.Fatalf("the finalized status format was rejected: %v", err)
	}
	if status.State != "degraded" || status.Flags != 15 || len(status.Applied) != 6 ||
		status.Applied[5] != lockdownPhaseNameCells || len(status.Unsupported) != 2 {
		t.Fatalf("unexpected finalized status decode: %+v", status)
	}
	result, err := parseCoreLockdownTrigger("triggered:0badc0de;phases=-;unsupported=-")
	if err != nil || result.Epoch != "0badc0de" || len(result.Applied) != 0 || len(result.Unsupported) != 0 {
		t.Fatalf("the finalized empty-list encoding was rejected: %+v err=%v", result, err)
	}
	// The old uppercase reason spellings are not part of the contract any more.
	for _, reason := range []string{"MANUAL", "TAMPER", "XDR_CRITICAL", "BOOT_TRUST_DRIFT"} {
		if lockdownReasonValid(reason) {
			t.Fatalf("legacy reason token %q is still accepted", reason)
		}
	}
}
