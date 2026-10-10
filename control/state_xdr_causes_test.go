package main

import (
	"errors"
	"strings"
	"testing"
)

// TestClearingOneCauseDoesNotSilenceAnother pins the defect that produced repeated fail-safes on
// the production host: recovery used to be one unconditional "degraded = false", so whichever
// component cleared its own reason wiped every other reason with it. The platform reported itself
// healthy while the release gate had already latched, and the next check degraded it again.
func TestClearingOneCauseDoesNotSilenceAnother(t *testing.T) {
	state := NewState("test-node", defaultConfig())

	state.SetXDRDegraded(true, "incident log verification failed: fixture")
	state.markXDRCause(xdrCauseCaseHistory, "case history integrity unavailable: fixture")

	if degraded, reason := state.xdr.Degraded, state.xdr.DegradedReason; !degraded || !strings.Contains(reason, "case history") {
		t.Fatalf("the second cause was not recorded: degraded=%v reason=%q", degraded, reason)
	}

	state.SetXDRDegraded(false, "")

	degraded, reason := state.xdr.Degraded, state.xdr.DegradedReason
	if !degraded {
		t.Fatal("clearing the engine's cause silenced a cause owned by another component")
	}
	if !strings.Contains(reason, "case history") {
		t.Fatalf("the surviving cause is not named: %q", reason)
	}
	if strings.Contains(reason, "incident log") {
		t.Fatalf("the cleared cause is still named: %q", reason)
	}
}

// TestEveryCauseIsNamedInTheReason prevents one reason from hiding behind another one's text.
func TestEveryCauseIsNamedInTheReason(t *testing.T) {
	state := NewState("test-node", defaultConfig())
	state.markXDRCause(xdrCauseEvidence, "mandatory evidence ledger unavailable")
	state.markXDRCause(xdrCauseCaseHistory, "case history integrity unavailable")

	reason := state.xdr.DegradedReason
	for _, want := range []string{"mandatory evidence ledger unavailable", "case history integrity unavailable"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("reason %q missing from %q", want, reason)
		}
	}
}

// TestASingleFailedCaseIngestDoesNotDegrade is the root fix. An incident is ingested on every
// detection, so a store hiccup lasts milliseconds and is retried immediately - it must never pause
// the automatic response, and it must never latch a fail-safe that needs five minutes of calm.
func TestASingleFailedCaseIngestDoesNotDegrade(t *testing.T) {
	state := NewState("test-node", defaultConfig())

	state.noteCaseHistoryFailure(errors.New("fixture ingest failure"))
	if state.xdr.Degraded {
		t.Fatalf("a single failed ingest degraded the platform: %q", state.xdr.DegradedReason)
	}

	state.noteCaseHistoryFailure(errors.New("fixture ingest failure"))
	if !state.xdr.Degraded {
		t.Fatal("a repeatedly failing case history did not degrade the platform")
	}
	if !strings.Contains(state.xdr.DegradedReason, "case history") {
		t.Fatalf("the degradation does not name the case history: %q", state.xdr.DegradedReason)
	}
}

// TestARecoveredCaseHistoryClearsTheCause closes the loop: the condition, not the event, decides
// whether the platform stays paused.
func TestARecoveredCaseHistoryClearsTheCause(t *testing.T) {
	state := NewState("test-node", defaultConfig())
	state.noteCaseHistoryFailure(errors.New("fixture ingest failure"))
	state.noteCaseHistoryFailure(errors.New("fixture ingest failure"))
	if !state.xdr.Degraded {
		t.Fatal("fixture did not degrade the platform")
	}

	state.noteCaseHistorySuccess()

	if state.xdr.Degraded {
		t.Fatalf("a recovered case history left the platform degraded: %q", state.xdr.DegradedReason)
	}
	if state.caseHistoryFailures != 0 {
		t.Fatalf("the failure counter survived recovery: %d", state.caseHistoryFailures)
	}
}

// TestAnOccasionalFailureNeverAccumulates proves the counter is a consecutive-run counter and not a
// lifetime total: failures separated by successes can repeat forever without degrading.
func TestAnOccasionalFailureNeverAccumulates(t *testing.T) {
	state := NewState("test-node", defaultConfig())
	for i := 0; i < 20; i++ {
		state.noteCaseHistoryFailure(errors.New("fixture ingest failure"))
		state.noteCaseHistorySuccess()
	}
	if state.xdr.Degraded {
		t.Fatalf("occasional failures accumulated into a degradation: %q", state.xdr.DegradedReason)
	}
}

// TestTheFlagIsDerivedFromTheCauses is the invariant the whole mechanism rests on: the published
// flag is never assigned directly, it is computed.
func TestTheFlagIsDerivedFromTheCauses(t *testing.T) {
	state := NewState("test-node", defaultConfig())
	if state.xdr.Degraded {
		t.Fatal("a fresh state reports itself degraded")
	}
	state.MarkXDRDegraded("engine: startup verification failed")
	if !state.xdr.Degraded || !strings.Contains(state.xdr.DegradedReason, "startup verification failed") {
		t.Fatalf("MarkXDRDegraded did not publish: degraded=%v reason=%q", state.xdr.Degraded, state.xdr.DegradedReason)
	}
	state.SetXDRDegraded(false, "")
	if state.xdr.Degraded {
		t.Fatalf("the derived flag did not clear: %q", state.xdr.DegradedReason)
	}
}
