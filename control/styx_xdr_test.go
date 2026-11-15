// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5 XDR/beacon integration tests: synthetic kernel flow events,
// exactly one incident, dedupe, evidence before response, degraded/observe,
// overflow series and capability gating. It also carries the small shared
// event/helper predicates (same test package).

import (
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------------- XDR

func newStyxXDRFixture(t *testing.T, cfg StyxBeaconConfig) (*XDREngine, *State, *beaconTestClock) {
	t.Helper()
	state := NewState("test", defaultConfig())
	engine := &XDREngine{
		state: state, correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
	}
	clock := newBeaconTestClock()
	if cfg.Now == nil {
		cfg.Now = clock.Now
	}
	engine.styxBeacon = NewStyxBeaconEngine(cfg, engine.correlator, engine.emitStyxBeaconIncident)
	// The real engine always carries a core client; the response path checks for it
	// before it ever reaches the reversible response engine.
	engine.core = &CoreClient{}
	return engine, state, clock
}

// combinedBeaconEvents produces a flow whose 12th sample satisfies the periodicity
// AND the exfiltration-asymmetry signal at the same evaluation. That is the only
// way a beacon finding reaches the containment-grade score, and it must be exactly
// one incident, not two consecutive escalations.
func combinedBeaconEvents() []CoreStyxFlowEvent {
	events := make([]CoreStyxFlowEvent, 0, 13)
	for index := 0; index < 13; index++ {
		// The exfiltration volume only appears with the 13th event (the 12th counted
		// interval): both signals must become true in the same evaluation, otherwise
		// the detector correctly emits an escalation sequence (alert, then contain)
		// instead of one incident.
		tx := uint64(64)
		if index >= 12 {
			tx = 1_200_000
		}
		events = append(events, beaconEvent(1, 10, 1_000_000_000+uint64(30*time.Second)*uint64(index), tx, 0, 1, "203.0.113.77", 443, 4, 6))
	}
	return events
}

func TestStyxXDRIntegrationEmitsExactlyOneIncidentAndDedupes(t *testing.T) {
	engine, state, clock := newStyxXDRFixture(t, activeBeaconConfig())
	engine.recordStyxFlowBatch(periodicBeaconEvents(30*time.Second, 13, 128, 0), 0, clock.Now())
	snapshot := state.Snapshot()
	if len(snapshot.Incidents) != 1 {
		t.Fatalf("expected exactly one beacon incident, got %d: %+v", len(snapshot.Incidents), snapshot.Incidents)
	}
	incident := snapshot.Incidents[0]
	if incident.CellCgroupID != 1 {
		t.Fatalf("incident carries no cell cgroup, CellGuard could not act on it: %+v", incident)
	}
	if !beaconRuleIDsContain(incident, StyxBeaconRulePeriodicity) {
		t.Fatalf("incident does not carry the periodicity rule: %+v", incident.RuleIDs)
	}
	if incident.Action != "none" {
		t.Fatalf("a single-signal alert must not trigger an active response: %s", incident.Action)
	}
	if !hasStyxEventOfKind(snapshot.Events, "xdr.alert") {
		t.Fatalf("the beacon incident did not reach the XDR event stream: %+v", snapshot.Events)
	}

	// The detector's own dedupe window must survive a second drain of the very same
	// flow: one finding is evidence, thousands of identical rows are noise.
	engine.recordStyxFlowBatch([]CoreStyxFlowEvent{
		beaconEvent(1, 10, 1_000_000_000+uint64(30*time.Second)*13, 128, 0, 1, "203.0.113.77", 443, 4, 6),
	}, 0, clock.Now())
	if got := len(state.Snapshot().Incidents); got != 1 {
		t.Fatalf("dedupe failed, incident count grew to %d", got)
	}
}

func TestStyxXDRIntegrationCombinedSignalsProduceOneContainIncident(t *testing.T) {
	engine, state, clock := newStyxXDRFixture(t, activeBeaconConfig())
	state.SetModes("enforcement", "enforce")
	engine.recordStyxFlowBatch(combinedBeaconEvents(), 0, clock.Now())
	incidents := state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected exactly one containment incident, got %d: %+v", len(incidents), incidents)
	}
	if incidents[0].Decision != "contain" || incidents[0].Score != 250 || incidents[0].Severity != "CRITICAL" {
		t.Fatalf("combined signals did not reach the containment-grade decision: %+v", incidents[0])
	}
	// There is no bypassing response route: without the reversible response engine
	// the existing respond() path refuses an untracked freeze and says so.
	if incidents[0].Action != "none" || !strings.Contains(incidents[0].Outcome, "reversible response engine unavailable") {
		t.Fatalf("beacon containment did not go through the existing respond() path: action=%q outcome=%q",
			incidents[0].Action, incidents[0].Outcome)
	}
}

func TestStyxXDRIntegrationRecordsEvidenceBeforeResponse(t *testing.T) {
	ledger, _ := evidenceFixture(t)
	engine, state, clock := newStyxXDRFixture(t, activeBeaconConfig())
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	state.SetModes("enforcement", "enforce")
	engine.recordStyxFlowBatch(combinedBeaconEvents(), 0, clock.Now())
	if got := len(state.Snapshot().Incidents); got != 1 {
		t.Fatalf("expected one combined incident, got %d", got)
	}
	var evidenceRecorded, responseIntent bool
	for _, record := range ledger.Recent(50) {
		switch record.Kind {
		case "xdr.styx_beacon":
			evidenceRecorded = true
		case "xdr.response.intent":
			responseIntent = true
		}
	}
	if !evidenceRecorded {
		t.Fatal("no mandatory evidence record was written before the response decision")
	}
	if !responseIntent {
		t.Fatal("the containment-grade incident did not reach the existing response engine evidence path")
	}
}

func TestStyxXDRIntegrationDegradedAndObservePauseResponse(t *testing.T) {
	engine, state, clock := newStyxXDRFixture(t, activeBeaconConfig())
	state.SetModes("enforcement", "enforce")
	engine.markDegradedCause("test", "simulated degradation")
	engine.recordStyxFlowBatch(combinedBeaconEvents(), 0, clock.Now())
	incidents := state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("a degraded XDR must still record the beacon evidence, got %d incidents", len(incidents))
	}
	if incidents[0].Action != "none" || !strings.Contains(incidents[0].Outcome, "degraded") {
		t.Fatalf("degraded XDR did not pause the response: action=%q outcome=%q", incidents[0].Action, incidents[0].Outcome)
	}

	// Observe mode: the same evidence is recorded, the response stays paused.
	observeState := NewState("test", defaultConfig())
	observeEngine := &XDREngine{
		state: observeState, correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
	}
	observeClock := newBeaconTestClock()
	cfg := activeBeaconConfig()
	cfg.Now = observeClock.Now
	observeEngine.styxBeacon = NewStyxBeaconEngine(cfg, observeEngine.correlator, observeEngine.emitStyxBeaconIncident)
	observeState.SetModes("enforcement", "observe")
	observeEngine.recordStyxFlowBatch(combinedBeaconEvents(), 0, observeClock.Now())
	observed := observeState.Snapshot().Incidents
	if len(observed) != 1 || observed[0].Action != "none" || observed[0].Outcome != "observe mode" {
		t.Fatalf("observe mode did not pause the response: %+v", observed)
	}
}

func TestStyxXDRFlowOverflowDegradesAndRecovers(t *testing.T) {
	engine, state, clock := newStyxXDRFixture(t, activeBeaconConfig())
	for poll := 0; poll < 3; poll++ {
		engine.recordStyxFlowBatch(nil, 5, clock.Now())
	}
	snapshot := state.Snapshot()
	if events := countStyxEventsOfKind(snapshot.Events, "xdr.styx_flow_overflow"); events != 1 {
		t.Fatalf("overflow event must be reported once per series, got %d", events)
	}
	if events := countStyxEventsOfKind(snapshot.Events, "xdr.styx_flow_sensor_degraded"); events != 1 {
		t.Fatalf("repeated overflow must degrade the sensor once, got %d events", events)
	}
	if got := engine.StyxBeaconSnapshot().SensorState; got != "degraded" {
		t.Fatalf("sensor state after an overflow series is %q, want degraded", got)
	}
	for poll := 0; poll < 3; poll++ {
		engine.recordStyxFlowBatch(nil, 0, clock.Now())
	}
	recovered := state.Snapshot()
	if got := engine.StyxBeaconSnapshot().SensorState; got != "active" {
		t.Fatalf("sensor did not recover after a clean series: %q", got)
	}
	if countStyxEventsOfKind(recovered.Events, "xdr.styx_flow_sensor_recovered") != 1 {
		t.Fatal("sensor recovery was not reported")
	}
	// Overflow is visibility loss, never a claim of absence: the events say so.
	for _, event := range recovered.Events {
		if event.Kind == "xdr.styx_flow_overflow" && !strings.Contains(event.Message, "does not claim the absence of beacons") {
			t.Fatalf("overflow event makes a claim it cannot prove: %q", event.Message)
		}
	}
}

func TestStyxXDRFlowCapabilityGatesDetection(t *testing.T) {
	engine, state, clock := newStyxXDRFixture(t, StyxBeaconConfig{Enabled: true, Mode: StyxModeMonitor, FlowCapabilityKnown: false})
	events := periodicBeaconEvents(30*time.Second, 13, 128, 0)
	engine.recordStyxFlowBatch(events, 0, clock.Now())
	if len(state.Snapshot().Incidents) != 0 {
		t.Fatal("beacon detection fired without the flow capability")
	}
	if got := engine.StyxBeaconSnapshot().SensorState; got != "unavailable" {
		t.Fatalf("sensor without capability reports %q", got)
	}
	engine.setStyxBeaconCapability(true)
	engine.recordStyxFlowBatch(events, 0, clock.Now())
	if len(state.Snapshot().Incidents) != 1 {
		t.Fatalf("detection did not start after the capability was established")
	}
	if got := engine.StyxBeaconSnapshot().SensorState; got != "active" {
		t.Fatalf("sensor state after capability is %q", got)
	}
}

// ------------------------------------------------------------- helpers

func hasStyxEventOfKind(events []Event, kind string) bool {
	for _, event := range events {
		if event.Kind == kind {
			return true
		}
	}
	return false
}

func countStyxEventsOfKind(events []Event, kind string) int {
	count := 0
	for _, event := range events {
		if event.Kind == kind {
			count++
		}
	}
	return count
}

func callIndex(calls []string, want string) int {
	for position, call := range calls {
		if call == want {
			return position
		}
	}
	return -1
}
