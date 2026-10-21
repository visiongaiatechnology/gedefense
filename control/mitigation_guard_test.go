// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
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

// TestMitigationSurvivesRestart is F-03: the value is written down and re-asserted at the next start,
// both when it is still in force and when it drifted back during downtime.
func TestMitigationSurvivesRestart(t *testing.T) {
	cfg := defaultAdvisoryConfig()
	cfg.AutoMitigate = true
	cfg.MitigationFailures = 2
	statePath := filepath.Join(t.TempDir(), "mitigation.json")
	key := "kernel.unprivileged_userns_clone"

	core := newFakeMitigationCore(key, "1")
	first := NewMitigationGuard(core, exposedHostCache(t), cfg, NewState("test", Config{}), nil)
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

// TestMitigationConfirmationIsDerivedFromTheTarget pins the intent proof used by the API.
func TestMitigationConfirmationIsDerivedFromTheTarget(t *testing.T) {
	if got := expectedMitigationConfirmation("APPLY", "kernel.userns"); got != "APPLY kernel.userns" {
		t.Fatalf("confirmation = %q", got)
	}
	if got := expectedMitigationConfirmation("ROLLBACK", "kernel.userns"); got != "ROLLBACK kernel.userns" {
		t.Fatalf("confirmation = %q", got)
	}
}
