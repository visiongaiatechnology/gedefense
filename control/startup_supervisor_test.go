// STATUS: DIAMANT VGT SUPREME
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

// TestStartupReArmDecision is the safety question of the whole feature in one table. Every row is a
// reason an operator has had to click "activate protection"; the test states which of them the
// platform may now answer itself, and which it may not.
func TestStartupReArmDecision(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	const host = "kernel=7.0.0; node=n; interface=ens6"
	current := startupIdentity{Host: host, Release: "4.2.4"}
	qualified := startupQualification{
		Fingerprint: current.String(), Host: host, Release: "4.2.4",
		QualifiedAt: now.Add(-time.Hour),
	}
	verified := ReleaseStatus{Phase: ReleasePhaseDegraded, KernelPolicyState: "verified-enforce", FailSafeVerified: true}

	cases := []struct {
		name       string
		status     ReleaseStatus
		current    startupIdentity
		qualified  startupQualification
		known      bool
		lastArm    time.Time
		want       string
		wantReason string
	}{
		{"emergency stop is never overridden", func() ReleaseStatus {
			s := verified
			s.EmergencyStop = true
			return s
		}(), current, qualified, true, time.Time{}, startupReArmEmergencyStop, "emergency stop"},
		{"an enforcing platform needs nothing", func() ReleaseStatus {
			s := verified
			s.Phase = ReleasePhaseEnforce
			return s
		}(), current, qualified, true, time.Time{}, startupReArmArmed, "already"},
		{"unverified kernel enforcement blocks", func() ReleaseStatus {
			s := verified
			s.KernelPolicyState = "unverified"
			return s
		}(), current, qualified, true, time.Time{}, startupReArmBlocked, "not verified"},
		{"a failed gate blocks", func() ReleaseStatus {
			s := verified
			s.Blockers = []string{"mandatory evidence ledger is unavailable"}
			return s
		}(), current, qualified, true, time.Time{}, startupReArmBlocked, "gates"},
		{"an unknown host goes through the ladder", verified, current, startupQualification{}, false, time.Time{}, startupReArmLadder, "qualified"},
		{"a changed kernel goes through the ladder", verified, current,
			startupQualification{Fingerprint: "kernel=6.9.0; node=n; interface=ens6; release=4.2.4", Host: "kernel=6.9.0; node=n; interface=ens6", Release: "4.2.4"},
			true, time.Time{}, startupReArmLadder, "changed"},
		{"a changed interface goes through the ladder", verified, current,
			startupQualification{Host: "kernel=7.0.0; node=n; interface=ens3", Release: "4.2.4"},
			true, time.Time{}, startupReArmLadder, "changed"},
		{"a missing identity goes through the ladder", verified, startupIdentity{}, qualified, true, time.Time{}, startupReArmLadder, "unavailable"},
		{"the rate limit prevents flapping", verified, current, qualified, true, now.Add(-30 * time.Second), startupReArmBlocked, "ago"},
		{"the qualified host is re-armed at once", verified, current, qualified, true, now.Add(-time.Hour), startupReArmArmed, "unchanged"},
		// The case this split exists for: an update installs a new release on the host that was
		// already qualified. The self-check has just verified every module, so there is nothing left
		// for a twenty-minute soak to prove.
		{"an updated release on the qualified host re-arms at once", verified,
			startupIdentity{Host: host, Release: "4.2.5"},
			startupQualification{Host: host, Release: "4.2.4"}, true, now.Add(-time.Hour), startupReArmArmed, "release"},
		// The upgrade path: the stored file was written before host and release were separated, so
		// the release has to be lifted out of the combined string. The host part matches, therefore
		// this is an update on a qualified host - not a changed host.
		{"a qualification written by an earlier release is understood", verified,
			startupIdentity{Host: host, Release: "4.2.4"},
			startupQualification{Fingerprint: "kernel=7.0.0; release=4.2.3; node=n; interface=ens6"},
			true, now.Add(-time.Hour), startupReArmArmed, "release"},
		{"a legacy qualification of the same release is still the same host", verified,
			startupIdentity{Host: host, Release: "4.2.4"},
			startupQualification{Fingerprint: "kernel=7.0.0; release=4.2.4; node=n; interface=ens6"},
			true, now.Add(-time.Hour), startupReArmArmed, "unchanged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, reason := decideStartupReArm(tc.status, tc.current, tc.qualified, tc.known, tc.lastArm, now, 5*time.Minute)
			if decision != tc.want {
				t.Fatalf("decision = %q, want %q (reason %q)", decision, tc.want, reason)
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reason %q does not name %q", reason, tc.wantReason)
			}
		})
	}
}

// TestStartupIdentitySeparatesHostFromRelease pins the classification itself, because every decision
// above rests on it: an update must not move the host part.
func TestStartupIdentitySeparatesHostFromRelease(t *testing.T) {
	const host = "kernel=7.0.0; node=n; interface=ens6"
	before := startupIdentity{Host: host, Release: "4.2.3"}
	after := startupIdentity{Host: host, Release: "4.2.4"}
	if before.Host != after.Host {
		t.Fatalf("the host part moved on a release change: %q vs %q", before.Host, after.Host)
	}
	if before.Release == after.Release {
		t.Fatal("the release part did not change")
	}
	if !strings.Contains(after.String(), "release=4.2.4") || !strings.Contains(after.String(), "interface=ens6") {
		t.Fatalf("the rendered identity lost a component: %q", after.String())
	}
	legacy := parseStartupIdentity("", "", "kernel=7.0.0; release=4.2.3; node=n; interface=ens6")
	if legacy.Host != host || legacy.Release != "4.2.3" {
		t.Fatalf("legacy record parsed as host=%q release=%q", legacy.Host, legacy.Release)
	}
	if empty := parseStartupIdentity("", "", ""); empty.known() {
		t.Fatal("an empty record claimed a known host")
	}
}

// TestStartupSelfCheckClassifiesModules proves the three outcomes the operator sees: repaired,
// still broken and blocking, or an operator decision that does not block the protection.
func TestStartupSelfCheckClassifiesModules(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	broken := errors.New("module is down")
	var (
		healedMu   sync.Mutex
		healedCall int
	)
	supervisor := &StartupSupervisor{
		now:          func() time.Time { return now },
		healAttempts: 1,
		modules: []startupModule{
			{name: "blocking_repairable", blocking: true,
				probe: func(context.Context) error { return broken },
				heal: func(context.Context) error {
					healedMu.Lock()
					healedCall++
					healedMu.Unlock()
					return nil
				},
			},
			{name: "operator_only", blocking: false,
				probe: func(context.Context) error { return broken },
			},
		},
	}
	// The repairable module stays broken on the probe after its heal, so it must be reported as
	// failed: an attempted repair that changed nothing is not a success.
	report := supervisor.checkOnce(context.Background(), map[string]int{})
	if report.BlockingIssues != 1 {
		t.Fatalf("blocking issues = %d, want 1 (%+v)", report.BlockingIssues, report.Modules)
	}
	states := map[string]string{}
	for _, module := range report.Modules {
		states[module.Name] = module.State
	}
	if states["blocking_repairable"] != startupModuleFailed {
		t.Fatalf("a module that stayed broken was reported as %q", states["blocking_repairable"])
	}
	if states["operator_only"] != startupModuleOperator {
		t.Fatalf("a non-blocking module was reported as %q", states["operator_only"])
	}

	// A module that becomes healthy after its repair is reported as repaired.
	healthy := false
	supervisor = &StartupSupervisor{
		now:          func() time.Time { return now },
		healAttempts: 2,
		modules: []startupModule{
			{name: "repairable", blocking: true,
				probe: func(context.Context) error {
					if healthy {
						return nil
					}
					return broken
				},
				heal: func(context.Context) error { healthy = true; return nil },
			},
		},
	}
	report = supervisor.checkOnce(context.Background(), map[string]int{})
	if report.BlockingIssues != 0 || report.Healed != 1 {
		t.Fatalf("a repaired module was not reported as repaired: %+v", report)
	}
	if report.Modules[0].State != startupModuleHealed {
		t.Fatalf("state = %q, want %q", report.Modules[0].State, startupModuleHealed)
	}

	// Healing is bounded: once the attempts are used, the module is left as failed.
	heals := map[string]int{"blocking_repairable": 1}
	supervisor = &StartupSupervisor{
		now:          func() time.Time { return now },
		healAttempts: 1,
		modules: []startupModule{
			{name: "blocking_repairable", blocking: true,
				probe: func(context.Context) error { return broken },
				heal:  func(context.Context) error { return nil },
			},
		},
	}
	report = supervisor.checkOnce(context.Background(), heals)
	if report.Modules[0].Detail != "healing attempts exhausted" {
		t.Fatalf("the bound was not enforced: %q", report.Modules[0].Detail)
	}
}

// TestStartupModulesKeepTheTrustDecisions pins the two repairs that must never be automatic:
// accepting a changed system file, and rewriting forensic case history. Both are checked and
// reported, neither blocks the platform from protecting, and neither has a repair function.
func TestStartupModulesKeepTheTrustDecisions(t *testing.T) {
	// The checklist is dependency-driven: a module whose dependencies are not wired is not checked
	// at all, so the test provides the real release controller and settings store from the fixture
	// and an unwired core client - it never calls a probe, it inspects the contract.
	_, store, release := settingsAPIFixture(t)
	modules := newStartupModules(StartupDeps{
		Release: release, State: NewState("test-node", defaultConfig()),
		Core: &CoreClient{}, Settings: store,
	})
	byName := make(map[string]startupModule, len(modules))
	for _, module := range modules {
		byName[module.name] = module
	}
	for _, name := range []string{"system_integrity", "host_keyring", "threat_intel"} {
		module, ok := byName[name]
		if !ok {
			t.Fatalf("module %q is missing from the checklist", name)
		}
		if module.heal != nil {
			t.Fatalf("module %q has an automatic repair; it is a trust decision", name)
		}
		if module.blocking {
			t.Fatalf("module %q blocks the protection; it narrows quality, it does not stop enforcement", name)
		}
	}
	for _, name := range []string{"kernel_enforcement", "management_allowlist", "sensor_coverage"} {
		if !byName[name].blocking {
			t.Fatalf("module %q must block: without it the platform is not protecting", name)
		}
	}
}

// TestSensorCoverageModuleRepairsItselfWithTheCanonicalProbe pins the repair that keeps an update from
// leaving the host paused: the traffic-derived sensor is re-verified with the L7 self-test instead of
// waiting for somebody to send a request through the path.
func TestSensorCoverageModuleRepairsItselfWithTheCanonicalProbe(t *testing.T) {
	ctx := context.Background()
	state := NewState("test", Config{})

	// Without an L7 service the module still reports, and says why it cannot repair itself.
	plain := modulesByName(newStartupModules(StartupDeps{State: state}))
	coverage, ok := plain["sensor_coverage"]
	if !ok {
		t.Fatal("sensor_coverage module missing")
	}
	if coverage.heal == nil {
		t.Fatal("sensor_coverage has no canonical repair")
	}
	if err := coverage.heal(ctx); err == nil {
		t.Fatal("a missing L7 service did not fail the repair")
	}

	// With the probe attached, a PASS is the repair and a FAIL is reported as one.
	probe := &fakeL7SelfTest{result: L7SelfTestResult{Outcome: L7SelfTestPass}}
	withProbe := modulesByName(newStartupModules(StartupDeps{State: state, L7: probe}))["sensor_coverage"]
	if err := withProbe.heal(ctx); err != nil {
		t.Fatalf("a passing self-test did not repair the module: %v", err)
	}
	if probe.calls != 1 {
		t.Fatalf("self-test called %d times, want 1", probe.calls)
	}
	probe.result = L7SelfTestResult{Outcome: L7SelfTestFail, Detail: "inspection counter did not move"}
	if err := withProbe.heal(ctx); err == nil || !strings.Contains(err.Error(), "counter did not move") {
		t.Fatalf("a failing self-test was not reported: %v", err)
	}
}

type fakeL7SelfTest struct {
	result L7SelfTestResult
	calls  int
}

func (f *fakeL7SelfTest) RunSelfTest(context.Context) L7SelfTestResult {
	f.calls++
	return f.result
}

func modulesByName(modules []startupModule) map[string]startupModule {
	index := make(map[string]startupModule, len(modules))
	for _, module := range modules {
		index[module.name] = module
	}
	return index
}

// TestStartupQualificationRoundTrip keeps the fingerprint honest across restarts: a corrupt or
// missing file means "not qualified", never "assume it was".
func TestStartupQualificationRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release-qualification.json")
	supervisor := &StartupSupervisor{qualifyPath: path, now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }}
	if _, known := supervisor.readQualification(); known {
		t.Fatal("an absent qualification file reported a qualified host")
	}
	stored := startupIdentity{Host: "kernel=7.0.0; node=n; interface=ens6", Release: "4.2.4"}
	if err := supervisor.writeQualification(stored); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, known := supervisor.readQualification()
	if !known || got.identity() != stored {
		t.Fatalf("round trip = %+v known=%v", got, known)
	}
	// The record is written by hand as well: an older release wrote only the combined fingerprint, and
	// that file has to keep its qualification instead of reading as a changed host.
	if err := os.WriteFile(path, []byte(`{"fingerprint":"kernel=7.0.0; release=4.2.3; node=n; interface=ens6"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, known := supervisor.readQualification()
	if !known || legacy.identity() != (startupIdentity{Host: stored.Host, Release: "4.2.3"}) {
		t.Fatalf("legacy record = %+v known=%v", legacy, known)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, known := supervisor.readQualification(); known {
		t.Fatal("a corrupt qualification file reported a qualified host")
	}
}

// TestStartupRunRearmsAfterTwoCleanPasses is the behaviour the operator asked for: a restart that
// passes its own check no longer waits for a human.
func TestStartupRunRearmsAfterTwoCleanPasses(t *testing.T) {
	const host = "kernel=7.0.0; node=n; interface=ens6"
	identity := startupIdentity{Host: host, Release: "4.2.4"}
	dir := t.TempDir()
	var (
		mu        sync.Mutex
		reArmCall int
	)
	status := ReleaseStatus{Phase: ReleasePhaseDegraded, KernelPolicyState: "verified-enforce", FailSafeVerified: true, Ready: true}
	supervisor := &StartupSupervisor{
		modules: []startupModule{
			{name: "always_ok", blocking: true, probe: func(context.Context) error { return nil }},
		},
		identity: func(context.Context) (startupIdentity, error) { return identity, nil },
		reArm: func(reason string) (ReleaseStatus, error) {
			mu.Lock()
			reArmCall++
			mu.Unlock()
			status.Phase = ReleasePhaseEnforce
			return status, nil
		},
		status:       func() ReleaseStatus { return status },
		now:          func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
		rounds:       4,
		roundGap:     time.Millisecond,
		armInterval:  5 * time.Minute,
		healAttempts: 1,
		qualifyPath:  filepath.Join(dir, "release-qualification.json"),
	}
	if err := supervisor.writeQualification(identity); err != nil {
		t.Fatal(err)
	}
	var last StartupReport
	supervisor.reportSink = func(report StartupReport) { last = report }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		supervisor.Run(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		called := reArmCall
		mu.Unlock()
		if called > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor did not stop with its context")
	}

	mu.Lock()
	defer mu.Unlock()
	if reArmCall != 1 {
		t.Fatalf("re-arm called %d times, want 1", reArmCall)
	}
	if last.ReArm != startupReArmArmed {
		t.Fatalf("report re-arm = %q (%s)", last.ReArm, last.ReArmReason)
	}
}

// TestStartupRunKeepsEnforcingWhenAModuleStaysBroken is the fail-closed half: the self-check never
// invents success, and the platform is left in the state it was in - enforcing, responses paused -
// with the module named.
func TestStartupRunKeepsEnforcingWhenAModuleStaysBroken(t *testing.T) {
	reArmed := false
	supervisor := &StartupSupervisor{
		modules: []startupModule{
			{name: "never_ok", blocking: true, probe: func(context.Context) error { return errors.New("sensor offline") }},
		},
		identity: func(context.Context) (startupIdentity, error) {
			return startupIdentity{Host: "kernel=7.0.0; node=n; interface=ens6", Release: "4.2.4"}, nil
		},
		reArm: func(string) (ReleaseStatus, error) {
			reArmed = true
			return ReleaseStatus{}, nil
		},
		status: func() ReleaseStatus {
			return ReleaseStatus{Phase: ReleasePhaseDegraded, KernelPolicyState: "verified-enforce", FailSafeVerified: true}
		},
		now:          func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
		rounds:       2,
		roundGap:     time.Millisecond,
		armInterval:  5 * time.Minute,
		healAttempts: 1,
	}
	var lastMu sync.Mutex
	var last StartupReport
	supervisor.reportSink = func(report StartupReport) {
		lastMu.Lock()
		last = report
		lastMu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		supervisor.Run(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		lastMu.Lock()
		reported := last.BlockingIssues
		lastMu.Unlock()
		if reported != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor did not stop with its context")
	}

	if reArmed {
		t.Fatal("the platform re-armed with a broken module")
	}
	if last.BlockingIssues != 1 {
		t.Fatalf("blocking issues = %d, want 1", last.BlockingIssues)
	}
	if len(last.Modules) != 1 || last.Modules[0].Detail == "" {
		t.Fatalf("the broken module was not named: %+v", last.Modules)
	}
}
