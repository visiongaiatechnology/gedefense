// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMitigationCore is the privileged surface the guard writes to, without a kernel in the loop.
type fakeMitigationCore struct {
	mu       sync.Mutex
	values   map[string]string
	reads    int
	writes   int
	writeErr error
}

func newFakeMitigationCore(key, value string) *fakeMitigationCore {
	return &fakeMitigationCore{values: map[string]string{key: value}}
}

func (f *fakeMitigationCore) SysctlGet(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	value, ok := f.values[key]
	if !ok {
		return "", errors.New("unknown sysctl key")
	}
	return value, nil
}

func (f *fakeMitigationCore) SysctlCompareSet(key, expected, desired string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	if f.values[key] != expected {
		return errors.New("compare-set precondition failed")
	}
	f.values[key] = desired
	f.writes++
	return nil
}

func (f *fakeMitigationCore) set(key, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[key] = value
}

func (f *fakeMitigationCore) get(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[key]
}

// exposedHostCache is the measurement of a host where the namespace door is open.
func exposedHostCache(t *testing.T) *kernelExposureCache {
	t.Helper()
	source := newFakeExposureSource()
	source.files["/proc/sys/kernel/osrelease"] = "7.0.0-31-generic\n"
	source.files["/etc/os-release"] = "ID=ubuntu\nVERSION_CODENAME=noble\n"
	source.files["/usr/bin/docker"] = ""
	source.files["/proc/sys/kernel/unprivileged_userns_clone"] = "1\n"
	source.modes["/dev/net/tun"] = 0o600
	source.dirs["/sys/bus/virtio/devices"] = []string{"virtio0"}
	return newKernelExposureCache(func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
		func() kernelExposureSource { return source })
}

type guardFixture struct {
	guard *MitigationGuard
	core  *fakeMitigationCore
	state *State
	now   time.Time
}

func newGuardFixture(t *testing.T, autoMitigate bool, probes ...MitigationProbe) *guardFixture {
	t.Helper()
	cfg := defaultAdvisoryConfig()
	cfg.AutoMitigate = autoMitigate
	cfg.MitigationFailures = 2
	cfg.MitigationWatchSeconds = 120
	cfg.MitigationIntervalSeconds = 60
	core := newFakeMitigationCore("kernel.unprivileged_userns_clone", "1")
	state := NewState("test", Config{})
	fixture := &guardFixture{core: core, state: state, now: time.Unix(1_800_000_000, 0).UTC()}
	fixture.guard = NewMitigationGuard(core, exposedHostCache(t), cfg, state, probes)
	fixture.guard.now = func() time.Time { return fixture.now }
	// The watch interval is raised so the test drives every assertion cycle itself; the ticker from
	// Apply must never fire while a test is asserting.
	fixture.guard.interval = time.Hour
	fixture.guard.watch = 2 * time.Minute
	return fixture
}

func (f *guardFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

// TestMitigationGuardRefusesInReportMode is the safety rail: the default configuration must never
// change a kernel value, and the refusal must name the setting that enables it.
func TestMitigationGuardRefusesInReportMode(t *testing.T) {
	fixture := newGuardFixture(t, false)
	// The automatic path stays refused in report mode ...
	if _, err := fixture.guard.ApplyAutomatic("startup"); err == nil {
		t.Fatal("report mode allowed an automatic kernel change")
	} else if !strings.Contains(err.Error(), "auto_mitigate") {
		t.Fatalf("refusal does not name the setting: %v", err)
	}
	if got := fixture.core.get("kernel.unprivileged_userns_clone"); got != "1" {
		t.Fatalf("the value changed without an operator: %q", got)
	}
	// ... while the operator's explicit intervention is exactly what the switch does not govern.
	status, err := fixture.guard.Apply("operator decided to close the door")
	if err != nil {
		t.Fatalf("the operator's explicit intervention was refused: %v", err)
	}
	if fixture.core.get("kernel.unprivileged_userns_clone") != "0" || status.State != mitigationStateWatching {
		t.Fatalf("manual intervention did not apply: status=%+v value=%q", status, fixture.core.get("kernel.unprivileged_userns_clone"))
	}
	fixture.guard.Close()
	plan := fixture.guard.Plan()
	if !plan.Applicable || plan.Key != "kernel.unprivileged_userns_clone" || plan.Desired != "0" {
		t.Fatalf("plan = %+v", plan)
	}
}

// TestMitigationGuardClosesAndHolds is the positive path: the value is closed, the probation window
// passes, and the guard reports the verified state.
func TestMitigationGuardClosesAndHolds(t *testing.T) {
	fixture := newGuardFixture(t, true, MitigationProbe{Name: "ok", Check: func(context.Context) error { return nil }})
	status, err := fixture.guard.Apply("test")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if status.State != mitigationStateWatching || fixture.core.get("kernel.unprivileged_userns_clone") != "0" {
		t.Fatalf("status=%+v value=%q", status, fixture.core.get("kernel.unprivileged_userns_clone"))
	}
	defer fixture.guard.Close()
	fixture.advance(3 * time.Minute)
	if stop := fixture.guard.tick(context.Background()); !stop {
		t.Fatal("the guard kept watching after the probation window")
	}
	status = fixture.guard.Status()
	if status.State != mitigationStateStable || status.Current != "0" {
		t.Fatalf("status after probation = %+v", status)
	}
}

// TestMitigationGuardRevertsOnRegression is the feature the operator asked for: a change that breaks
// the host is undone automatically, and the revert is verified rather than announced.
func TestMitigationGuardRevertsOnRegression(t *testing.T) {
	breaking := true
	probe := MitigationProbe{Name: "web", Check: func(context.Context) error {
		if breaking {
			return errors.New("the local web stack is down")
		}
		return nil
	}}
	fixture := newGuardFixture(t, true, probe)
	if _, err := fixture.guard.Apply("test"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	defer fixture.guard.Close()
	if fixture.core.get("kernel.unprivileged_userns_clone") != "0" {
		t.Fatal("the value was not applied before the probe")
	}
	// First failure is tolerated (a transient hiccup must not make the mitigation flap) ...
	fixture.guard.tick(context.Background())
	if got := fixture.core.get("kernel.unprivileged_userns_clone"); got != "0" {
		t.Fatalf("reverted on the first failure: %q", got)
	}
	// ... the second consecutive failure reverts, and the revert is read back from the core.
	fixture.guard.tick(context.Background())
	if got := fixture.core.get("kernel.unprivileged_userns_clone"); got != "1" {
		t.Fatalf("the regression did not restore the previous value: %q", got)
	}
	status := fixture.guard.Status()
	if status.State != mitigationStateReverted {
		t.Fatalf("status after revert = %+v", status)
	}
}

// TestMitigationGuardReassertsTamperedValue is "manipulationssicher": a value changed behind the
// platform's back is put back and recorded, not silently accepted.
func TestMitigationGuardReassertsTamperedValue(t *testing.T) {
	fixture := newGuardFixture(t, true, MitigationProbe{Name: "ok", Check: func(context.Context) error { return nil }})
	if _, err := fixture.guard.Apply("test"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	defer fixture.guard.Close()
	fixture.core.set("kernel.unprivileged_userns_clone", "1") // an outside actor opens the door again
	fixture.advance(30 * time.Second)
	fixture.guard.tick(context.Background())
	if got := fixture.core.get("kernel.unprivileged_userns_clone"); got != "0" {
		t.Fatalf("the tampered value was not re-asserted: %q", got)
	}
	status := fixture.guard.Status()
	if status.Drift != 1 {
		t.Fatalf("drift counter = %d, want 1", status.Drift)
	}
	if status.State != mitigationStateWatching && status.State != mitigationStateStable {
		t.Fatalf("state after re-assertion = %q", status.State)
	}
}

// TestMitigationGuardRollbackRestoresPrevious proves the operator's undo works outside the probation
// window and restores exactly the value that was there before, including a value that is not the
// hardening default.
func TestMitigationGuardRollbackRestoresPrevious(t *testing.T) {
	fixture := newGuardFixture(t, true, MitigationProbe{Name: "ok", Check: func(context.Context) error { return nil }})
	if _, err := fixture.guard.Apply("test"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	defer fixture.guard.Close()
	fixture.advance(5 * time.Minute)
	fixture.guard.tick(context.Background()) // probation passes
	status, err := fixture.guard.Rollback("operator undo")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if fixture.core.get("kernel.unprivileged_userns_clone") != "1" {
		t.Fatal("rollback did not restore the previous value")
	}
	if status.State != mitigationStateReverted {
		t.Fatalf("status = %+v", status)
	}
	if _, err := fixture.guard.Rollback("again"); err == nil {
		t.Fatal("a second rollback was accepted with no mitigation in force")
	}
}

// TestMitigationGuardRefusesWhenNothingIsReachable keeps the guard from acting on a host where the
// advisory does not apply or no door is open.
func TestMitigationGuardRefusesWhenNothingIsReachable(t *testing.T) {
	closed := newFakeExposureSource()
	closed.files["/proc/sys/kernel/osrelease"] = "6.1.190-1\n"
	closed.files["/etc/os-release"] = "ID=debian\nVERSION_CODENAME=bookworm\n"
	closed.files["/proc/sys/kernel/unprivileged_userns_clone"] = "0\n"
	cfg := defaultAdvisoryConfig()
	cfg.AutoMitigate = true
	core := newFakeMitigationCore("kernel.unprivileged_userns_clone", "0")
	cache := newKernelExposureCache(func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
		func() kernelExposureSource { return closed })
	guard := NewMitigationGuard(core, cache, cfg, NewState("test", Config{}), nil)
	if _, err := guard.Apply("test"); err == nil {
		t.Fatal("the guard applied a mitigation on a host with no reachable entry point")
	}
	if core.writes != 0 {
		t.Fatalf("the guard wrote %d times without a reason", core.writes)
	}
}

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

// TestMitigationProbeUnavailableIsNotARegression pins the distinction the live host exposed: an
// unprivileged control plane cannot connect to the root-owned Docker socket, but that is a visibility
// limit, not a broken runtime. The mitigation must survive the probation instead of being reverted.
func TestMitigationProbeUnavailableIsNotARegression(t *testing.T) {
	fixture := newGuardFixture(t, true, MitigationProbe{
		Name: "container-runtime",
		Check: func(context.Context) error {
			return errMitigationProbeUnavailable
		},
	})
	if _, err := fixture.guard.Apply("test"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	defer fixture.guard.Close()
	// Run one probe while the probation window is still open, so the visibility limit is
	// actually observed and surfaced; then close the window and confirm it is not a failure.
	fixture.advance(30 * time.Second)
	fixture.guard.tick(context.Background())
	status := fixture.guard.Status()
	if len(status.Warnings) == 0 || !strings.Contains(status.Warnings[0], "UNOBSERVED") {
		t.Fatalf("unobservable probe was not surfaced in status warnings: %+v", status)
	}
	fixture.advance(2 * time.Minute)
	fixture.guard.tick(context.Background())
	status = fixture.guard.Status()
	if status.Failures != 0 {
		t.Fatalf("probe visibility limit was counted as a failure: %+v", status)
	}
	if status.State != mitigationStateStable {
		t.Fatalf("mitigation state = %q, want %q: %+v", status.State, mitigationStateStable, status)
	}
	if got := fixture.core.get("kernel.unprivileged_userns_clone"); got != "0" {
		t.Fatalf("mitigation was reverted by an unobservable probe: %q", got)
	}
}

// TestMitigationGuardHoldsAuxiliaryControls pins the multi-CVE gap: the primary probation record
// owns the user-namespace switch, while MPTCP is adopted as an actively re-asserted auxiliary
// control instead of being left to a static sysctl.d file.
func TestMitigationGuardHoldsAuxiliaryControls(t *testing.T) {
	fixture := newGuardFixture(t, false)
	fixture.core.set("net.mptcp.enabled", "1")
	target, ok := mitigationTargetFor("mptcp-enabled")
	if !ok {
		t.Fatal("mptcp target missing")
	}
	fixture.guard.mu.Lock()
	err := fixture.guard.adoptAuxiliaryTargetLocked(target, "test auxiliary")
	fixture.guard.mu.Unlock()
	if err != nil {
		t.Fatalf("adopt auxiliary: %v", err)
	}
	if got := fixture.core.get("net.mptcp.enabled"); got != "0" {
		t.Fatalf("auxiliary MPTCP value = %q, want 0", got)
	}
	status := fixture.guard.Status()
	if len(status.Auxiliary) != 1 || status.Auxiliary[0].Key != "net.mptcp.enabled" || status.Auxiliary[0].Current != "0" {
		t.Fatalf("auxiliary status = %+v", status.Auxiliary)
	}
	fixture.core.set("net.mptcp.enabled", "1")
	fixture.guard.assertAuxiliary()
	if got := fixture.core.get("net.mptcp.enabled"); got != "0" {
		t.Fatalf("auxiliary drift was not re-asserted: %q", got)
	}
}

// TestMitigationTargetIncludesMPTCP keeps the CVE-2026-98432 entry point actionable instead of
// leaving MPTCP as advice that no operator path can execute.
func TestMitigationTargetIncludesMPTCP(t *testing.T) {
	target, ok := mitigationTargetFor("mptcp-enabled")
	if !ok {
		t.Fatal("mptcp-enabled has no managed mitigation target")
	}
	if target.key != "net.mptcp.enabled" || target.desired != "0" || target.control != "network.mptcp" {
		t.Fatalf("mptcp target = %+v", target)
	}
}

// TestMitigationConfirmationIsDerivedFromTheTarget pins the intent proof used by the API.
func TestMitigationConfirmationIsDerivedFromTheTarget(t *testing.T) {
	if got := expectedMitigationConfirmation("APPLY", "kernel.userns"); got != "APPLY kernel.userns" {
		t.Fatalf("confirmation = %q", got)
	}
	if got := expectedMitigationConfirmation("ROLLBACK", "kernel.userns"); got != "ROLLBACK kernel.userns" {
		t.Fatalf("confirmation = %q", got)
	}
}
