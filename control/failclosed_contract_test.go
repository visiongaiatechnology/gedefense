// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The contracts in this file describe one property: the platform never gives up protection
// because something could not be verified. Verification failures pause automatic decisions,
// they do not release the sources that were already blocked - and an operator who wants the
// kernel policy released has to say so explicitly.

// TestAAutomaticDegradationNeverReleasesTheKernelPolicy is the reported defect, at the level
// of the whole controller.
//
// A single malformed kernel sample marked a mandatory sensor degraded. The release gate
// answered by reconciling the kernel to observe, which removes every enforced block, and the
// host stayed unprotected for twenty hours because nothing lifted the phase. An attacker who
// can produce one such sample therefore disarms the platform. Nothing automatic may release
// the policy.
func TestAAutomaticDegradationNeverReleasesTheKernelPolicy(t *testing.T) {
	cfg, state, _, release, core := betaReleaseFixtureWithCore(t)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "enter canary before the fault"); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddBlock("203.0.113.77/32", "blocked before the fault", "test", time.Hour, false, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "arm enforcement before the fault"); err != nil {
		t.Fatal(err)
	}

	// The causes the platform degrades on, including the one that was reported.
	causes := []struct {
		name string
		fire func()
	}{
		{"kinetic sensor unavailable", func() {
			server := &APIServer{cfg: cfg, state: state, release: release}
			server.setKineticSensorState(CoverageOffline, "failed", "synthetic kernel ingress channel loss")
		}},
		{"core heartbeat", func() { release.FailSafe("core heartbeat threshold exceeded") }},
		{"forensic ledger", func() { release.FailSafe("XDR is degraded: incident log verification failed") }},
	}
	for _, cause := range causes {
		t.Run(cause.name, func(t *testing.T) {
			before := core.clearCount()
			cause.fire()
			status := release.Status()
			if status.Phase != ReleasePhaseDegraded {
				t.Fatalf("the cause did not pause the platform: %+v", status)
			}
			if core.clearCount() != before {
				t.Fatalf("%s released the kernel blocklist", cause.name)
			}
			enforcement, xdrMode := state.Modes()
			if enforcement != "enforce" || xdrMode != "observe" {
				t.Fatalf("%s left unsafe modes: %s/%s", cause.name, enforcement, xdrMode)
			}
			if status.KernelPolicyState != "verified-enforce" || !status.FailSafeVerified {
				t.Fatalf("%s did not leave a verified enforcement: %+v", cause.name, status)
			}
			if len(status.FailSafeReason) == 0 {
				t.Fatalf("%s left no cause for the operator", cause.name)
			}
		})
	}
}

// TestAPromotionNeverLowersVerifiedKernelEnforcement covers the same fail-open one step later.
//
// The canary phase applies observe at the kernel. Promoting out of a retained degraded state
// therefore released every blocked source - a phase change silently unblocking an attacker.
// Only the explicit RETURN:OBSERVE instruction may lower a verified enforcement.
func TestAPromotionNeverLowersVerifiedKernelEnforcement(t *testing.T) {
	cfg, state, _, release, core := betaReleaseFixtureWithCore(t)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "enter canary before the fault"); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddBlock("203.0.113.78/32", "blocked before the fault", "test", time.Hour, false, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "arm enforcement before the fault"); err != nil {
		t.Fatal(err)
	}
	release.FailSafe("synthetic fault after verified enforcement")

	// The soak cannot be the reason a test passes, so it is satisfied deliberately.
	release.mu.Lock()
	release.status.Since = time.Now().Add(-24 * time.Hour)
	release.status.NominalSince = nil
	release.mu.Unlock()

	cleared := core.clearCount()
	status, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "re-enter canary after the fault")
	if err != nil {
		t.Fatalf("the canary transition was refused: %v", err)
	}
	if status.Phase != ReleasePhaseCanary {
		t.Fatalf("phase=%s", status.Phase)
	}
	if enforcement, _ := state.Modes(); enforcement != "enforce" {
		t.Fatalf("a promotion released the retained kernel enforcement: %s", enforcement)
	}
	if core.clearCount() != cleared {
		t.Fatal("the promotion released the kernel blocklist")
	}
	if status.KernelPolicyState != "verified-enforce" || !status.FailSafeVerified {
		t.Fatalf("the promoted state does not describe the retained enforcement: %+v", status)
	}

	// The operator's own instruction is still honoured, and it is the only thing that is.
	if _, err := release.Transition(ReleasePhaseObserve, "RETURN:OBSERVE", "operator releases the kernel policy deliberately"); err != nil {
		t.Fatal(err)
	}
	if enforcement, _ := state.Modes(); enforcement != "observe" {
		t.Fatalf("the explicit release did not lower the enforcement: %s", enforcement)
	}
	if core.clearCount() != cleared+1 {
		t.Fatal("the explicit release did not verify the empty kernel")
	}
}

// TestTheDegradedPhaseRecoversOnceTheGatesPassAndTheCalmHolds covers the twenty-hour pause.
//
// The fall-back was a latch on everything: the cause cleared within seconds, and the platform
// stayed paused until a human noticed. The phase now lifts by itself, but only after every
// substantive gate passes again and the calm has held - never merely because time passed.
func TestTheDegradedPhaseRecoversOnceTheGatesPassAndTheCalmHolds(t *testing.T) {
	cfg, state, _, release, core := betaReleaseFixtureWithCore(t)
	// The soak is stated explicitly, so a failure names a behaviour instead of a default.
	runtime := release.runtimeSettingsLocked()
	release.cfg.Release.MinimumObserveSeconds = 3600
	soak := time.Duration(release.effectiveReleaseConfigLocked().MinimumObserveSeconds) * time.Second
	if soak != time.Hour {
		t.Fatalf("the recovery soak is not the configured one: soak=%s configured=%d runtime_fabric=%d fabric_const=%d runtime_protection=%d",
			soak, release.cfg.Release.MinimumObserveSeconds, runtime.FabricVersion, fabricSettingsVersion, runtime.Protection.MinimumObserveSeconds)
	}
	// The promotion ladder has its own soak. It is satisfied deliberately so that this test
	// measures the recovery soak and not the ladder.
	release.mu.Lock()
	release.status.Since = time.Now().Add(-24 * time.Hour)
	release.mu.Unlock()
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "enter canary before the fault"); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "arm enforcement before the fault"); err != nil {
		t.Fatal(err)
	}
	// The promotion ladder legitimately reconciles the kernel on the way up, so the baseline
	// is taken once enforcement is armed: what must not happen is a release from here on.
	cleared := core.clearCount()
	for range cfg.Release.CoreFailureThreshold {
		release.ObserveCore(false)
	}
	if status := release.Status(); status.Phase != ReleasePhaseDegraded {
		t.Fatalf("the fixture did not degrade: %+v", status)
	}

	// The cause clears.
	release.ObserveCore(true)

	// A first evaluation starts the calm, and the soak is not over yet.
	release.Evaluate()
	status := release.Status()
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("the platform recovered before the calm had held (soak=%s, nominal since %v): %+v", soak, status.NominalSince, status)
	}
	if status.NominalSince == nil {
		t.Fatal("the calm was not recorded, so no soak can ever complete")
	}

	// The calm has now held for longer than the configured soak.
	release.mu.Lock()
	at := time.Now().Add(-2 * soak)
	release.status.NominalSince = &at
	release.mu.Unlock()
	release.Evaluate()

	status = release.Status()
	if status.Phase != ReleasePhaseEnforce {
		t.Fatalf("the platform did not recover although every gate passed: %+v", status)
	}
	if !status.FailSafeVerified || status.KernelPolicyState != "verified-enforce" {
		t.Fatalf("the recovered state is not a verified enforcement: %+v", status)
	}
	if status.FailSafeReason != "" || status.FailSafeAt != nil {
		t.Fatalf("the recovered state still carries the old fault: %+v", status)
	}
	if core.clearCount() != cleared {
		t.Fatal("the recovery released the kernel blocklist")
	}
	if enforcement, xdrMode := state.Modes(); enforcement != "enforce" || xdrMode != "enforce" {
		t.Fatalf("the recovery did not restore automatic response: %s/%s", enforcement, xdrMode)
	}
}

// TestRecoveryRequiresAVerifiedEnforcement is the counter-case: recovery must never talk the
// platform into a state it could not confirm.
func TestRecoveryRequiresAVerifiedEnforcement(t *testing.T) {
	cfg, state, policy, _ := betaReleaseFixture(t)
	if _, err := state.AddBlock("198.51.100.90/32", "unconfirmed block", "test", time.Hour, false, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	core := &releaseCoreStub{addErr: errors.New("core unavailable")}
	release := NewReleaseController(cfg, state, core, policy, nil)
	if err := release.InitializeStartup("enforce", true); err == nil {
		t.Fatal("an unverifiable retention reported success")
	}
	// Even after a long calm, an unverified enforcement is not recovered.
	release.mu.Lock()
	at := time.Now().Add(-24 * time.Hour)
	release.status.NominalSince = &at
	release.status.Since = at
	release.mu.Unlock()
	release.Evaluate()
	status := release.Status()
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("recovery claimed a state it could not verify: %+v", status)
	}
	if status.FailSafeVerified {
		t.Fatalf("an unconfirmed kernel state was reported as verified: %+v", status)
	}
}

// TestASingleMalformedSampleDoesNotDegradeTheSensor is the trigger half of the defect.
//
// The health probe answers whether the enforcement path is present. A drain failure answers
// whether one batch of samples arrived intact. The platform treated the second as the first,
// so one rejected sample from a busy host looked like a lost XDP hook.
func TestASingleMalformedSampleDoesNotDegradeTheSensor(t *testing.T) {
	health := &CoreIngressHealth{EventsEmitted: 4242, Mode: "NATIVE_XDP"}
	status, selfTest, reason := evaluateKineticSensorHealth(1, 0, health, health)
	if status != CoverageOnline {
		t.Fatalf("one failed sample drain degraded the sensor: %s (%s)", status, reason)
	}
	if selfTest != "pass" {
		t.Fatalf("self-test=%s", selfTest)
	}
	if !strings.Contains(reason, "recovered sample drain failure") {
		t.Fatalf("the drain failure is not named for the operator: %q", reason)
	}
	if strings.Contains(reason, "enforcement path is") {
		t.Fatalf("a sample problem was reported as an enforcement problem: %q", reason)
	}
}

// TestASustainedSampleDrainFailureDegradesOnlyTheObservation keeps the signal honest: a
// recurring transport failure is a real observation loss, and it still is not an enforcement
// verdict.
func TestASustainedSampleDrainFailureDegradesOnlyTheObservation(t *testing.T) {
	health := &CoreIngressHealth{EventsEmitted: 4242, Mode: "NATIVE_XDP"}
	status, _, reason := evaluateKineticSensorHealth(kineticDrainDegradeAfterFails, 0, health, health)
	if status != CoverageDegraded {
		t.Fatalf("a sustained transport failure stayed %s", status)
	}
	if !strings.Contains(reason, "sample transport") {
		t.Fatalf("the degraded reason does not name the transport: %q", reason)
	}
	if strings.Contains(reason, "enforcement path is") {
		t.Fatalf("the transport failure claims the enforcement path is gone: %q", reason)
	}
}

// TestTheEnforcementPathOutranksSampleNoise pins which signal governs the sensor verdict.
func TestTheEnforcementPathOutranksSampleNoise(t *testing.T) {
	health := &CoreIngressHealth{EventsEmitted: 4242, Mode: "NATIVE_XDP"}
	if status, _, reason := evaluateKineticSensorHealth(0, 1, health, health); status != CoverageDegraded || !strings.Contains(reason, "enforcement path is unstable") {
		t.Fatalf("a failed health probe must degrade the sensor: %s (%s)", status, reason)
	}
	if status, _, reason := evaluateKineticSensorHealth(0, kineticOfflineAfterFails, health, health); status != CoverageOffline || !strings.Contains(reason, "enforcement path is unavailable") {
		t.Fatalf("a sustained health failure must take the sensor offline: %s (%s)", status, reason)
	}
	// A health failure is never excused by a healthy drain.
	if status, _, _ := evaluateKineticSensorHealth(0, kineticOfflineAfterFails, health, health); status == CoverageOnline {
		t.Fatal("a lost enforcement path was reported as online")
	}
}

// TestTheSensorReasonDistinguishesPressureFromTransport keeps the three conditions apart.
func TestTheSensorReasonDistinguishesPressureFromTransport(t *testing.T) {
	previous := &CoreIngressHealth{EventsEmitted: 10, RingDrops: 1, TrackInsertFailures: 0, Mode: "NATIVE_XDP"}
	current := &CoreIngressHealth{EventsEmitted: 20, RingDrops: 2, TrackInsertFailures: 0, Mode: "NATIVE_XDP"}
	status, _, reason := evaluateKineticSensorHealth(0, 0, previous, current)
	if status != CoverageDegraded || !strings.Contains(reason, "kernel ingress pressure") {
		t.Fatalf("ring pressure must be reported as pressure: %s (%s)", status, reason)
	}
}
