// STATUS: DIAMANT VGT SUPREME
package main

// M2 tests: the raised flow-batch parser bounds (core: batch 64 / payload 16 KiB)
// and the derived telemetry health (emitted/drop delta, drop ratio, drain lag,
// stale health) with an explicit degradation independent of enforcement.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------- parser batch bounds

func TestStyxFlowParserMatchesRaisedCoreBatchCeiling(t *testing.T) {
	if maxStyxFlowEventsPerResponse != 64 {
		t.Fatalf("flow batch ceiling is %d, the core sends at most 64", maxStyxFlowEventsPerResponse)
	}
	if maxStyxFlowPayloadBytes != 16<<10 {
		t.Fatalf("flow payload ceiling is %d, the core bounds it to 16 KiB", maxStyxFlowPayloadBytes)
	}

	// A full 64-record batch must parse; the old 8-record ceiling would have
	// rejected a perfectly valid core answer and silently dropped telemetry.
	records := make([]string, maxStyxFlowEventsPerResponse)
	for index := range records {
		records[index] = styxValidIPv4Record
	}
	batch := "7|" + strings.Join(records, ",")
	if len(batch) > maxStyxFlowPayloadBytes {
		t.Fatalf("test batch is unexpectedly oversized: %d", len(batch))
	}
	events, dropped, err := parseCoreStyxFlowEvents(batch)
	if err != nil {
		t.Fatalf("a full core batch was rejected: %v", err)
	}
	if len(events) != maxStyxFlowEventsPerResponse || dropped != 7 {
		t.Fatalf("full batch parsed to %d events (dropped %d)", len(events), dropped)
	}

	// One record above the ceiling is rejected instead of silently truncated.
	tooMany := "0|" + strings.Join(append(records, styxValidIPv4Record), ",")
	if _, _, err := parseCoreStyxFlowEvents(tooMany); err == nil {
		t.Fatal("a batch above the core ceiling was accepted")
	}
	// A single oversized record is rejected before field splitting.
	if _, _, err := parseCoreStyxFlowEvents("0|" + strings.Repeat("a", maxStyxFlowRecordBytes+1)); err == nil {
		t.Fatal("an oversized flow record was accepted")
	}
	// A payload above the raised 16 KiB ceiling is rejected before splitting.
	oversized := "0|" + strings.Repeat("a:", maxStyxFlowPayloadBytes/2)
	if len(oversized) <= maxStyxFlowPayloadBytes {
		t.Fatalf("oversized fixture is too small: %d", len(oversized))
	}
	if _, _, err := parseCoreStyxFlowEvents(oversized); err == nil {
		t.Fatal("an oversized flow payload was accepted")
	}
}

// ------------------------------------------------------------ flow metrics

func TestStyxFlowMetricsHealthyWindow(t *testing.T) {
	engine, _, clock := newStyxXDRFixture(t, activeBeaconConfig())
	t0 := clock.Now()
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 100, RingDrops: 0}, t0)
	engine.recordStyxFlowDrain(t0)
	clock.Advance(10 * time.Second)
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 300, RingDrops: 1}, clock.Now())
	engine.recordStyxFlowDrain(clock.Now())

	metrics := engine.styxFlowMetricsAt(clock.Now())
	if metrics.TelemetryState != styxTelemetryHealthy || metrics.TelemetryDegraded {
		t.Fatalf("a healthy window was classified as %q (%s)", metrics.TelemetryState, metrics.Reason)
	}
	if metrics.EmittedDelta != 200 || metrics.RingDropsDelta != 1 {
		t.Fatalf("window deltas are wrong: %+v", metrics)
	}
	if metrics.WindowSeconds != 10 {
		t.Fatalf("window length is wrong: %f", metrics.WindowSeconds)
	}
	if ratio := metrics.DropRatio; ratio <= 0 || ratio > 0.01 {
		t.Fatalf("drop ratio under the documented bound is wrong: %f", ratio)
	}
	if !metrics.EnforcementUnaffected {
		t.Fatal("a telemetry sample must never imply an enforcement change")
	}
}

func TestStyxFlowMetricsDegradeOnDropRatioNotOnEnforcement(t *testing.T) {
	engine, state, clock := newStyxXDRFixture(t, activeBeaconConfig())
	t0 := clock.Now()
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 1000, RingDrops: 0, PolicyDrops: 0}, t0)
	engine.recordStyxFlowDrain(t0)
	clock.Advance(10 * time.Second)
	// 50 ring drops vs 100 emitted events in one window: telemetry lost events
	// while the enforcement path (PolicyDrops=0) stayed untouched.
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 1100, RingDrops: 50, PolicyDrops: 0}, clock.Now())
	engine.recordStyxFlowDrain(clock.Now())

	metrics := engine.styxFlowMetricsAt(clock.Now())
	if metrics.TelemetryState != styxTelemetryDegraded || !metrics.TelemetryDegraded {
		t.Fatalf("a 33%% ring-drop ratio was not degraded: %+v", metrics)
	}
	if metrics.PolicyDrops != 0 {
		t.Fatalf("the fixture claims a policy drop: %+v", metrics)
	}
	if !metrics.EnforcementUnaffected {
		t.Fatal("the telemetry degradation claims an enforcement impact")
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "xdr.styx_telemetry_degraded") {
		t.Fatal("the telemetry degradation was not reported as an operator-visible event")
	}

	// A clean window recovers the telemetry state and names the recovery.
	clock.Advance(10 * time.Second)
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 1400, RingDrops: 50, PolicyDrops: 0}, clock.Now())
	engine.recordStyxFlowDrain(clock.Now())
	recovered := engine.styxFlowMetricsAt(clock.Now())
	if recovered.TelemetryState != styxTelemetryHealthy || recovered.TelemetryDegraded {
		t.Fatalf("a clean window did not recover: %+v", recovered)
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "xdr.styx_telemetry_recovered") {
		t.Fatal("the telemetry recovery was not reported")
	}
}

func TestStyxFlowMetricsDegradeOnDrainLagAndStaleHealth(t *testing.T) {
	engine, _, clock := newStyxXDRFixture(t, activeBeaconConfig())
	t0 := clock.Now()
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 10}, t0)
	engine.recordStyxFlowDrain(t0)

	// The drain is 30 s behind while the health sample is fresh enough: the
	// consumer lag is the honest cause.
	clock.Advance(20 * time.Second)
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 20}, clock.Now())
	lagging := engine.styxFlowMetricsAt(clock.Now())
	if lagging.DrainLagSeconds < 19 || lagging.DrainLagSeconds > 21 {
		t.Fatalf("drain lag is wrong: %+v", lagging)
	}
	// The health sample is 0 s old but the last drain is 20 s old.
	if lagging.TelemetryState != styxTelemetryDegraded || !strings.Contains(lagging.Reason, "drain lag") {
		t.Fatalf("drain lag did not degrade the telemetry: %+v", lagging)
	}

	// No fresh sample for longer than the health window: stale, still not an
	// enforcement claim.
	clock.Advance(45 * time.Second)
	stale := engine.styxFlowMetricsAt(clock.Now())
	if stale.TelemetryState != styxTelemetryStale || !stale.TelemetryDegraded {
		t.Fatalf("a stale health sample was not reported as stale: %+v", stale)
	}
	if !strings.Contains(stale.Reason, "old") {
		t.Fatalf("the stale reason does not explain the age: %q", stale.Reason)
	}
}

func TestStyxFlowMetricsOffAndUnavailableAreNotDegraded(t *testing.T) {
	offCfg := activeBeaconConfig()
	offCfg.Mode = StyxModeOff
	offEngine, _, _ := newStyxXDRFixture(t, offCfg)
	if got := offEngine.styxFlowMetricsAt(time.Now().UTC()); got.TelemetryState != styxTelemetryDisabled || got.TelemetryDegraded {
		t.Fatalf("mode=off telemetry is classified as %q", got.TelemetryState)
	}

	missingCfg := activeBeaconConfig()
	missingCfg.FlowCapabilityKnown = false
	missingEngine, _, _ := newStyxXDRFixture(t, missingCfg)
	if got := missingEngine.styxFlowMetricsAt(time.Now().UTC()); got.TelemetryState != styxTelemetryUnavailable || got.TelemetryDegraded {
		t.Fatalf("a missing capability is classified as %q", got.TelemetryState)
	}
}

func TestStyxStatusViewSeparatesEnforcementFromTelemetry(t *testing.T) {
	server, _, engine := styxAPIFixture(t)
	now := time.Now().UTC()
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 500, RingDrops: 3, PolicyDrops: 0}, now)
	engine.recordStyxFlowDrain(now)

	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/styx/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("styX status returned %d", rec.Code)
	}
	var view StyxStatusView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.EnforcementActive {
		t.Fatalf("an applied monitor policy is not reported as enforcing: %+v", view.Sync)
	}
	if view.TelemetryState != styxTelemetryHealthy || view.TelemetryDegraded {
		t.Fatalf("fresh telemetry is not healthy: %+v", view.Flow)
	}
	if view.Flow.TelemetryState != view.TelemetryState {
		t.Fatalf("top-level telemetry state disagrees with the flow block: %+v", view.Flow)
	}

	// Now push a drop window: enforcement stays active, telemetry degrades. The
	// status must not flip "active" to "off".
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 900, RingDrops: 250, PolicyDrops: 0}, now.Add(10*time.Second))
	engine.recordStyxFlowDrain(now.Add(10 * time.Second))
	rec = fabricRequest(t, server, http.MethodGet, "/api/v1/styx/status", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.EnforcementActive {
		t.Fatal("a telemetry rise turned off the enforcement claim")
	}
	if !view.TelemetryDegraded || view.TelemetryState != styxTelemetryDegraded {
		t.Fatalf("a heavy ring-drop window was not reported as telemetry degraded: %+v", view.Flow)
	}
	if view.Flow.DropRatio <= styxFlowDropRatioDegraded {
		t.Fatalf("drop ratio was not exposed: %+v", view.Flow)
	}
}
