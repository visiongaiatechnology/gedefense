// STATUS: DIAMANT VGT SUPREME
package main

import (
	"testing"
	"time"
)

// TestRecentSelfTestClearsAStaleInlineDegradation covers the contradiction the operator
// hit: the self-test reported PASS while the coverage reported INLINE DEGRADED on the
// same screen, and the platform stayed degraded because of it.
//
// InlineHealthy is inferred from events and is sticky. The self-test is a direct
// measurement: it drives a request through the listener and confirms the engine's own
// counter moved. When the two disagree, the measurement is the stronger evidence - and
// before this, the measurement was thrown away, so a passing test could not correct the
// flag it was taken to check.
func TestRecentSelfTestClearsAStaleInlineDegradation(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-2 * time.Minute)

	// The state the operator was in: listener enabled, flag cleared by an earlier error,
	// path measured working moments ago.
	status := L7Status{
		Enabled: true, Healthy: true,
		InlineEnabled: true, InlineHealthy: false,
		SelfTestOutcome: "PASS", SelfTestAt: &recent,
	}
	if got := EvaluateL7Coverage(status, 600); got == "INLINE_DEGRADED" {
		t.Fatalf("a verified path was reported as degraded: %s", got)
	}

	// The flag alone, with no measurement behind it, still degrades. The fix must not
	// have removed the alarm - only the part that fired against the evidence.
	unverified := status
	unverified.SelfTestOutcome = ""
	unverified.SelfTestAt = nil
	if got := EvaluateL7Coverage(unverified, 600); got != "INLINE_DEGRADED" {
		t.Fatalf("an unverified inline path reported %s instead of INLINE_DEGRADED", got)
	}

	// A failing self-test is not evidence of a working path.
	failed := status
	failed.SelfTestOutcome = "FAIL"
	if got := EvaluateL7Coverage(failed, 600); got != "INLINE_DEGRADED" {
		t.Fatalf("a failing self-test cleared the degradation: %s", got)
	}

	// A healthy flag still wins outright; the measurement is a second opinion, not a
	// replacement.
	healthy := status
	healthy.InlineHealthy = true
	if got := EvaluateL7Coverage(healthy, 600); got == "INLINE_DEGRADED" {
		t.Fatalf("a healthy inline flag reported degraded: %s", got)
	}
}

// TestSelfTestEvidenceExpires is the guard in the other direction. A pass speaks for the
// path only while it is recent; otherwise a test run an hour ago would keep a path that
// has since broken reported as verified.
func TestSelfTestEvidenceExpires(t *testing.T) {
	now := time.Now().UTC()

	fresh := now.Add(-l7SelfTestEvidenceWindow + time.Minute)
	if !InlinePathVerifiedBySelfTest(L7Status{SelfTestOutcome: "PASS", SelfTestAt: &fresh}, now) {
		t.Fatal("a pass inside the window was not accepted")
	}

	stale := now.Add(-l7SelfTestEvidenceWindow - time.Minute)
	if InlinePathVerifiedBySelfTest(L7Status{SelfTestOutcome: "PASS", SelfTestAt: &stale}, now) {
		t.Fatal("a pass older than the window was still accepted as evidence")
	}

	// Exactly at the boundary it still counts; the window is inclusive so the behaviour
	// at the edge is defined rather than accidental.
	edge := now.Add(-l7SelfTestEvidenceWindow)
	if !InlinePathVerifiedBySelfTest(L7Status{SelfTestOutcome: "PASS", SelfTestAt: &edge}, now) {
		t.Fatal("a pass exactly at the window boundary was rejected")
	}

	// A clock that moved backwards must not be read as a fresh measurement.
	future := now.Add(10 * time.Minute)
	if InlinePathVerifiedBySelfTest(L7Status{SelfTestOutcome: "PASS", SelfTestAt: &future}, now) {
		t.Fatal("a timestamp in the future was accepted as evidence")
	}

	// No timestamp at all is not evidence, even with a passing outcome recorded.
	if InlinePathVerifiedBySelfTest(L7Status{SelfTestOutcome: "PASS"}, now) {
		t.Fatal("a pass without a timestamp was accepted as evidence")
	}
}

// TestSelfTestRecordsItsVerdict proves the measurement is actually stored. It was
// returned and discarded before, which is why it could never correct anything.
func TestSelfTestRecordsItsVerdict(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	l7cfg := cfg.L7
	l7cfg.Enabled = true
	l7cfg.InlineEnabled = true
	l7cfg.InlineSocket = t.TempDir() + "/edge.sock"
	engine, err := NewL7Engine(l7cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewL7Service(l7cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}

	service.recordSelfTestEvidence(L7SelfTestResult{Outcome: L7SelfTestPass})
	recorded := state.Snapshot().L7
	if recorded.SelfTestOutcome != "PASS" {
		t.Fatalf("the passing verdict was not recorded: %q", recorded.SelfTestOutcome)
	}
	if recorded.SelfTestAt == nil {
		t.Fatal("the verdict was recorded without a time, so it could never expire")
	}

	// A later failure replaces it rather than leaving a stale pass in place.
	service.recordSelfTestEvidence(L7SelfTestResult{Outcome: L7SelfTestFail})
	after := state.Snapshot().L7
	if after.SelfTestOutcome != "FAIL" {
		t.Fatalf("a failing verdict did not replace the passing one: %q", after.SelfTestOutcome)
	}
}

// TestInlineFailureStillBlocksPromotionWithoutEvidence is the counter-case for the
// release gate. The gate must still stop promotion when the inline path is unverified;
// only the case where a recent measurement contradicts the flag is relaxed.
func TestInlineFailureStillBlocksPromotionWithoutEvidence(t *testing.T) {
	cfg := defaultConfig()
	cfg.L7.Enabled = true
	cfg.L7.InlineEnabled = true
	state := NewState("test", cfg)
	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.InlineEnabled = true
		status.InlineHealthy = false
	})
	controller := NewReleaseController(cfg, state, nil, nil, nil)

	readiness, err := controller.Readiness(ReleasePhaseCanary)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(readiness.Blockers, "L7 inline service is unavailable") {
		t.Fatalf("an unverified inline path did not block promotion: %v", readiness.Blockers)
	}

	// With a recent pass the same gate no longer blocks, because the path was measured
	// working more recently than the event that cleared the flag.
	recent := time.Now().UTC().Add(-time.Minute)
	state.UpdateL7Status(func(status *L7Status) {
		status.SelfTestOutcome = "PASS"
		status.SelfTestAt = &recent
	})
	readiness, err = controller.Readiness(ReleasePhaseCanary)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(readiness.Blockers, "L7 inline service is unavailable") {
		t.Fatalf("a verified path still blocked promotion: %v", readiness.Blockers)
	}
}
