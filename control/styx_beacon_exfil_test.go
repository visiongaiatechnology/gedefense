// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"testing"
	"time"
)

// The kernel emits aggregated WINDOW DELTAS: every FlowEvent carries the bytes
// since the previous emit of that flow, not a running total. The matrix feeds
// delta series and checks the cumulative thresholds. It runs with rx telemetry
// available because the tx/rx ratio is only admissible evidence when rx is
// actually observed; the Phase-1 honesty cases are covered separately below.
func TestStyxBeaconExfilAsymmetryCumulativeThresholds(t *testing.T) {
	cases := map[string]struct {
		txDelta, rxDelta uint64
		count            int
		fires            bool
	}{
		"ratio-boundary-8":           {txDelta: 524288, rxDelta: 65536, count: 1, fires: true},
		"ratio-trust-7":              {txDelta: 524288, rxDelta: 65537, count: 1, fires: false},
		"below-half-mib-cumulative":  {txDelta: 120 * 1024, rxDelta: 10 * 1024, count: 4, fires: false},
		"reaches-half-mib-on-fourth": {txDelta: 150 * 1024, rxDelta: 16 * 1024, count: 4, fires: true},
		"rx-zero-edge-8-samples":     {txDelta: 120 * 1024, rxDelta: 0, count: 9, fires: true},
		"rx-zero-edge-just-below":    {txDelta: 110 * 1024, rxDelta: 0, count: 9, fires: false},
		"rx-zero-edge-7-samples":     {txDelta: 140 * 1024, rxDelta: 0, count: 8, fires: false},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			clock := newBeaconTestClock()
			config := activeBeaconConfig()
			config.Now = clock.Now
			engine := newBeaconTestEngine(t, config, clock, nil)
			incidents := feedBeaconEvents(engine, clock, periodicBeaconEvents(time.Second, testCase.count, testCase.txDelta, testCase.rxDelta))
			if !testCase.fires {
				if len(incidents) != 0 {
					t.Fatalf("unexpected incident: %#v", incidents[0])
				}
				return
			}
			if len(incidents) != 1 {
				t.Fatalf("expected one deduped asymmetry incident, got %d", len(incidents))
			}
			incident := incidents[0]
			if incident.Score != 200 || incident.Decision != "alert" || !beaconRuleIDsContain(incident, StyxBeaconRuleAsymmetry) {
				t.Fatalf("unexpected asymmetry incident: %#v", incident)
			}
			if strings.Contains(incident.Summary, "rx telemetry unavailable") {
				t.Fatalf("ratio incident wrongly claims missing rx telemetry: %q", incident.Summary)
			}
			assertBeaconStoryNode(t, incident, StyxBeaconEventAsymmetry)
		})
	}
}

// Phase 1 has no ingress (rx) delta telemetry. High egress volume alone is NOT
// an asymmetry: without a provable ratio the signal must stay "unknown" (no
// score, no combination, no incident) instead of flagging every upload/backup.
func TestStyxBeaconPhase1VolumeOnlyStaysUnknown(t *testing.T) {
	clock := newBeaconTestClock()
	config := activeBeaconConfig()
	config.RxObservationAvailable = false
	config.Now = clock.Now
	engine := newBeaconTestEngine(t, config, clock, nil)
	// 13 x 120 KiB = 1.56 MiB cumulative egress, rx always 0.
	incidents := feedBeaconEvents(engine, clock, periodicBeaconEvents(time.Second, 13, 120*1024, 0))
	if len(incidents) != 0 {
		t.Fatalf("volume-only flow without rx telemetry and without canary fired: %#v", incidents[0])
	}
	if snapshot := engine.Snapshot(); len(snapshot.Top) != 0 {
		t.Fatalf("unknown signal produced a score claim: %#v", snapshot.Top)
	}
	// Real rx deltas do not help either while the capability says unobserved.
	engine = newBeaconTestEngine(t, config, nil, nil)
	incidents = engine.RecordFlows([]CoreStyxFlowEvent{beaconEvent(1, 10, 1_000_000_000, 1<<20, 65536, 64, "198.51.100.70", 443, 4, 6)})
	if len(incidents) != 0 {
		t.Fatalf("unobserved rx was used for a ratio claim: %#v", incidents[0])
	}
}

// The Phase-1 evidence envelope: high egress volume plus a canary/sensitive-path
// correlation. Score 200, but the summary must say there is no ratio claim.
func TestStyxBeaconPhase1CanaryVolumeScore(t *testing.T) {
	clock := newBeaconTestClock()
	config := activeBeaconConfig()
	config.RxObservationAvailable = false
	config.Now = clock.Now
	config.CanaryCorrelation = func(cgroupID uint64, pid int, since time.Time) bool { return cgroupID == 1 && pid == 10 }
	engine := newBeaconTestEngine(t, config, clock, nil)
	// 9 x 150 KiB = 1.35 MiB cumulative, 8 counted intervals: volume + canary.
	incidents := feedBeaconEvents(engine, clock, periodicBeaconEvents(time.Second, 9, 150*1024, 0))
	if len(incidents) != 1 {
		t.Fatalf("expected one volume+canary incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Score != 200 || incident.Severity != "HIGH" || incident.Decision != "alert" {
		t.Fatalf("unexpected volume+canary incident: %#v", incident)
	}
	if !beaconRuleIDsContain(incident, StyxBeaconRuleAsymmetry) {
		t.Fatalf("missing asymmetry evidence bucket: %v", incident.RuleIDs)
	}
	for _, phrase := range []string{"rx telemetry unavailable", "volume+canary correlation", "no ratio claim"} {
		if !strings.Contains(incident.Summary, phrase) {
			t.Fatalf("summary does not state %q: %q", phrase, incident.Summary)
		}
	}
	assertBeaconStoryNode(t, incident, StyxBeaconEventAsymmetry)

	// Below 1 MiB the Phase-1 envelope stays unknown even with a canary hit.
	engine = newBeaconTestEngine(t, config, nil, nil)
	if incidents := feedBeaconEvents(engine, nil, periodicBeaconEvents(time.Second, 9, 100*1024, 0)); len(incidents) != 0 {
		t.Fatalf("volume+canary fired below the 1 MiB evidence floor: %#v", incidents[0])
	}
}

// With real rx telemetry the canary correlation keeps raising 200 -> 250.
func TestStyxBeaconCanaryCorrelationRaisesAsymmetryScore(t *testing.T) {
	config := activeBeaconConfig()
	config.CanaryCorrelation = func(cgroupID uint64, pid int, since time.Time) bool { return cgroupID == 5 && pid == 55 }
	engine := newBeaconTestEngine(t, config, nil, nil)
	event := beaconEvent(5, 55, 1_000_000_000, 1<<20, 65536, 64, "198.51.100.40", 443, 4, 6)
	incidents := engine.RecordFlows([]CoreStyxFlowEvent{event})
	if len(incidents) != 1 || incidents[0].Score != 250 || incidents[0].Severity != "CRITICAL" {
		t.Fatalf("canary correlation did not raise the score: %#v", incidents)
	}
	engine = newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	incidents = engine.RecordFlows([]CoreStyxFlowEvent{event})
	if len(incidents) != 1 || incidents[0].Score != 200 {
		t.Fatalf("baseline asymmetry score changed: %#v", incidents)
	}
}

// Periodicity plus the Phase-1 volume+canary envelope reaches the containment
// grade: two independent signals, score 250, still without a ratio claim.
func TestStyxBeaconPhase1CanaryVolumeCombinationContain(t *testing.T) {
	clock := newBeaconTestClock()
	config := activeBeaconConfig()
	config.RxObservationAvailable = false
	config.Now = clock.Now
	config.CanaryCorrelation = func(cgroupID uint64, pid int, since time.Time) bool { return cgroupID == 1 && pid == 10 }
	engine := newBeaconTestEngine(t, config, clock, nil)
	// 13 x 84 KiB at a 30 s cadence: cumulative volume stays below 1 MiB until the
	// 13th delta, where periodicity (samples=12) and the volume+canary envelope
	// become true in the same evaluation.
	incidents := feedBeaconEvents(engine, clock, periodicBeaconEvents(30*time.Second, 13, 84*1024, 0))
	if len(incidents) != 1 {
		t.Fatalf("expected one combined containment incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Score != 250 || incident.Decision != "contain" || incident.Severity != "CRITICAL" {
		t.Fatalf("combination did not reach containment grade: %#v", incident)
	}
	if !beaconRuleIDsContain(incident, StyxBeaconRulePeriodicity) || !beaconRuleIDsContain(incident, StyxBeaconRuleAsymmetry) {
		t.Fatalf("combined incident lacks signal rules: %v", incident.RuleIDs)
	}
	if !strings.Contains(incident.Summary, "rx telemetry unavailable") {
		t.Fatalf("combined Phase-1 incident hides the missing ratio claim: %q", incident.Summary)
	}
}

// A slow exfiltration whose single emit windows all stay far below the volume
// thresholds must still be found once the cumulative flow total crosses them.
func TestStyxBeaconSlowExfilCumulativeDeltas(t *testing.T) {
	clock := newBeaconTestClock()
	config := activeBeaconConfig()
	config.Now = clock.Now
	engine := newBeaconTestEngine(t, config, clock, nil)
	const txDelta, rxDelta = 60 * 1024, 6 * 1024
	var incidents []XDRIncident
	for index := 0; index < 9; index++ {
		event := beaconEvent(1, 10, 1_000_000_000+uint64(time.Second)*uint64(index), txDelta, rxDelta, 1, "203.0.113.99", 443, 4, 6)
		incidents = append(incidents, engine.RecordFlows([]CoreStyxFlowEvent{event})...)
		// 8 deltas = 480 KiB: below the 512 KiB total, so no signal may fire yet.
		if index < 8 && len(incidents) != 0 {
			t.Fatalf("per-emit window triggered the volume signal after %d deltas", index+1)
		}
		clock.Advance(time.Second)
	}
	if len(incidents) != 1 {
		t.Fatalf("cumulative slow exfiltration not detected: %d incidents", len(incidents))
	}
	snapshot := engine.Snapshot()
	if len(snapshot.Top) != 1 || snapshot.Top[0].TxBytes != 9*txDelta || snapshot.Top[0].RxBytes != 9*rxDelta {
		t.Fatalf("flow volume is not the saturating delta sum: %#v", snapshot.Top)
	}
}

func TestStyxBeaconSaturatingVolumeAccounting(t *testing.T) {
	engine := newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	maxUint := ^uint64(0)
	engine.RecordFlows([]CoreStyxFlowEvent{beaconEvent(1, 10, 1_000_000_000, maxUint-10, 1<<20, 4, "198.51.100.60", 443, 4, 6)})
	engine.RecordFlows([]CoreStyxFlowEvent{beaconEvent(1, 10, 1_001_000_000, 100, 0, 4, "198.51.100.60", 443, 4, 6)})
	snapshot := engine.Snapshot()
	if snapshot.Flows != 1 || len(snapshot.Top) != 1 || snapshot.Top[0].TxBytes != maxUint {
		t.Fatalf("delta sum did not saturate at the u64 ceiling: %#v", snapshot)
	}
}

func TestStyxBeaconSnapshotBoundedTopTen(t *testing.T) {
	engine := newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	for flow := 0; flow < 15; flow++ {
		event := beaconEvent(uint64(flow+1), flow+1, 1_000_000_000, 1<<20, 65536, 64, "198.51.100.50", uint16(5000+flow), 4, 6)
		engine.RecordFlows([]CoreStyxFlowEvent{event})
	}
	snapshot := engine.Snapshot()
	if snapshot.Flows != 15 {
		t.Fatalf("tracked flows = %d, want 15", snapshot.Flows)
	}
	if len(snapshot.Top) != 10 {
		t.Fatalf("top list len = %d, want 10", len(snapshot.Top))
	}
	for index := 1; index < len(snapshot.Top); index++ {
		if snapshot.Top[index-1].Score < snapshot.Top[index].Score {
			t.Fatalf("top list is not score-sorted: %#v", snapshot.Top)
		}
	}
	if snapshot.Top[0].Remote == "" || snapshot.Top[0].Signals == nil {
		t.Fatalf("top row lacks operator context: %#v", snapshot.Top[0])
	}
}
