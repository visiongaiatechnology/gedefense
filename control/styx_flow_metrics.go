// STATUS: DIAMANT VGT SUPREME
package main

// M2 (Textdokument): StyX flow-telemetry health.
//
// Enforcement and telemetry are two different facts. The kernel can enforce
// perfectly while its aggregated flow ring overflows (FLOW_RING_DROPS rises),
// which silently removes visibility from the beacon detector. This file derives
// the operator-facing telemetry metrics (emitted/ring-drop delta, drop ratio,
// drain lag, health age) and keeps the "degraded" classification independent of
// the enforcement state - a drop alarm must never be reported as a StyX outage.

import (
	"fmt"
	"time"
)

// Telemetry state vocabulary. It is separate from the enforcement state
// (sync state/mode) on purpose.
const (
	styxTelemetryHealthy     = "healthy"
	styxTelemetryDegraded    = "degraded"
	styxTelemetryStale       = "stale"
	styxTelemetryUnavailable = "unavailable"
	styxTelemetryDisabled    = "disabled"
)

const (
	// styxFlowHealthMaxAge bounds how old a kernel health sample may be before the
	// telemetry is reported as stale. Health polls run every 10 s.
	styxFlowHealthMaxAge = 30 * time.Second
	// styxFlowDrainMaxLag bounds the age of the last successful flow drain. The
	// drain runs every second while the namespace is active.
	styxFlowDrainMaxLag = 10 * time.Second
	// styxFlowDropRatioDegraded is the window drop ratio above which the telemetry
	// is classified as degraded. The documented acceptance target is <0.1 %.
	styxFlowDropRatioDegraded = 0.01
)

// StyxFlowMetrics is the derived, bounded telemetry view. It carries only
// counters and durations; no flow content, command line or address ever enters it.
type StyxFlowMetrics struct {
	SampledAt             *time.Time `json:"sampled_at,omitempty"`
	Emitted               uint64     `json:"emitted"`
	RingDrops             uint64     `json:"ring_drops"`
	AggInsertFailures     uint64     `json:"agg_insert_failures"`
	ParseErrors           uint64     `json:"parse_errors"`
	DropsTotal            uint64     `json:"drops_total"`
	PolicyDrops           uint64     `json:"policy_drops"`
	EmittedDelta          uint64     `json:"emitted_delta"`
	RingDropsDelta        uint64     `json:"ring_drops_delta"`
	DropRatio             float64    `json:"drop_ratio"`
	WindowSeconds         float64    `json:"window_seconds"`
	DrainLagSeconds       float64    `json:"drain_lag_seconds"`
	HealthAgeSeconds      float64    `json:"health_age_seconds"`
	TelemetryState        string     `json:"telemetry_state"`
	TelemetryDegraded     bool       `json:"telemetry_degraded"`
	EnforcementUnaffected bool       `json:"enforcement_unaffected"`
	Reason                string     `json:"reason,omitempty"`
}

// recordStyxFlowDrain records one successful drain of the flow ring. A stalled
// drain is itself a telemetry-degradation signal even before the kernel counters
// move, so it is tracked with its own timestamp.
func (e *XDREngine) recordStyxFlowDrain(now time.Time) {
	if e == nil {
		return
	}
	e.styxFlowMu.Lock()
	e.styxFlowLastDrainAt = now
	e.styxFlowMu.Unlock()
	e.noteStyxTelemetryState(now)
}

// StyxFlowMetrics returns the current telemetry view. It is safe to call from a
// status render: it only reads the sampled counters and never blocks on the core.
func (e *XDREngine) StyxFlowMetrics() StyxFlowMetrics {
	return e.styxFlowMetricsAt(time.Now().UTC())
}

func (e *XDREngine) styxFlowMetricsAt(now time.Time) StyxFlowMetrics {
	out := StyxFlowMetrics{TelemetryState: styxTelemetryUnavailable}
	if e == nil {
		return out
	}
	beaconState := "unavailable"
	if e.styxBeacon != nil {
		beaconState = e.styxBeacon.SensorState()
	}
	e.styxFlowMu.Lock()
	out.Emitted = e.styxFlowHealth.Emitted
	out.RingDrops = e.styxFlowHealth.RingDrops
	out.AggInsertFailures = e.styxFlowHealth.AggInsertFailures
	out.ParseErrors = e.styxFlowHealth.ParseErrors
	out.DropsTotal = e.styxFlowHealth.DropsTotal
	out.PolicyDrops = e.styxFlowHealth.PolicyDrops
	healthAt := e.styxFlowHealthAt
	healthErr := e.styxFlowHealthErr
	previous, previousAt := e.styxFlowHealthPrev, e.styxFlowHealthPrevAt
	lastDrain := e.styxFlowLastDrainAt
	e.styxFlowMu.Unlock()

	if !healthAt.IsZero() {
		sampled := healthAt
		out.SampledAt = &sampled
		out.HealthAgeSeconds = now.Sub(healthAt).Seconds()
		if out.HealthAgeSeconds < 0 {
			out.HealthAgeSeconds = 0
		}
	}
	if !lastDrain.IsZero() {
		out.DrainLagSeconds = now.Sub(lastDrain).Seconds()
		if out.DrainLagSeconds < 0 {
			out.DrainLagSeconds = 0
		}
	}
	// Window deltas: counters can only grow; a shrinking counter means the core
	// restarted and its maps were recreated. That is a re-baseline, not negative
	// traffic, so the deltas are zero for this window.
	if !healthAt.IsZero() && !previousAt.IsZero() && out.Emitted >= previous.Emitted && out.RingDrops >= previous.RingDrops {
		out.EmittedDelta = out.Emitted - previous.Emitted
		out.RingDropsDelta = out.RingDrops - previous.RingDrops
		out.WindowSeconds = healthAt.Sub(previousAt).Seconds()
		if out.WindowSeconds < 0 {
			out.WindowSeconds = 0
		}
		total := out.EmittedDelta + out.RingDropsDelta
		if total > 0 {
			out.DropRatio = float64(out.RingDropsDelta) / float64(total)
		}
	}

	switch {
	case beaconState == "off":
		out.TelemetryState = styxTelemetryDisabled
	case beaconState == "unavailable":
		out.TelemetryState = styxTelemetryUnavailable
		if healthErr != "" {
			out.Reason = "kernel flow health query failed: " + healthErr
		}
	case beaconState == "degraded":
		out.TelemetryState = styxTelemetryDegraded
		out.Reason = "the beacon detector degraded after repeated ring/aggregation overflows; flow/beacon visibility is reduced"
	case healthAt.IsZero():
		out.TelemetryState = styxTelemetryUnavailable
		out.Reason = "no kernel flow-health sample has been received yet"
	case out.HealthAgeSeconds > styxFlowHealthMaxAge.Seconds():
		out.TelemetryState = styxTelemetryStale
		out.Reason = fmt.Sprintf("last kernel flow-health sample is %.0f s old", out.HealthAgeSeconds)
	case !lastDrain.IsZero() && out.DrainLagSeconds > styxFlowDrainMaxLag.Seconds():
		out.TelemetryState = styxTelemetryDegraded
		out.Reason = fmt.Sprintf("flow-event drain lag is %.0f s; the userspace consumer is behind the kernel ring", out.DrainLagSeconds)
	case out.RingDropsDelta > 0 && out.DropRatio > styxFlowDropRatioDegraded:
		out.TelemetryState = styxTelemetryDegraded
		out.Reason = fmt.Sprintf("ring drop ratio %.2f %% in the last window (%d dropped / %d emitted)", out.DropRatio*100, out.RingDropsDelta, out.EmittedDelta)
	default:
		out.TelemetryState = styxTelemetryHealthy
	}
	out.TelemetryDegraded = out.TelemetryState == styxTelemetryDegraded || out.TelemetryState == styxTelemetryStale
	// Flow telemetry is an observation path. A drop in it never changes the
	// kernel enforcement decision, which is exactly why it must be reported as its
	// own degradation and not as a StyX outage.
	out.EnforcementUnaffected = true
	return out
}

// noteStyxTelemetryState reports a telemetry-state transition exactly once. It is
// independent of the enforcement state and never triggers a response.
func (e *XDREngine) noteStyxTelemetryState(now time.Time) {
	if e == nil || e.state == nil {
		return
	}
	metrics := e.styxFlowMetricsAt(now)
	state := metrics.TelemetryState
	e.styxFlowMu.Lock()
	previous := e.styxFlowTelemetryState
	changed := previous != state
	if changed {
		e.styxFlowTelemetryState = state
	}
	e.styxFlowMu.Unlock()
	if !changed {
		return
	}
	degraded := state == styxTelemetryDegraded || state == styxTelemetryStale
	switch {
	case degraded && previous != "":
		e.state.AddEvent(Event{Severity: "high", Kind: "xdr.styx_telemetry_degraded", Source: "kernel",
			Message: "StyX flow telemetry degraded (" + state + "): " + metrics.Reason + ". Enforcement is not affected; flow/beacon visibility is reduced and the detector does not claim the absence of beacons."})
	case degraded:
		e.state.AddEvent(Event{Severity: "high", Kind: "xdr.styx_telemetry_degraded", Source: "kernel",
			Message: "StyX flow telemetry degraded (" + state + "): " + metrics.Reason + ". Enforcement is not affected; flow/beacon visibility is reduced."})
	case previous != "" && (previous == styxTelemetryDegraded || previous == styxTelemetryStale):
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.styx_telemetry_recovered", Source: "kernel",
			Message: "StyX flow telemetry recovered: kernel ring drain and drop ratio are inside the documented bounds again"})
	}
}
