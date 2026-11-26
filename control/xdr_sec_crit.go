// STATUS: V6.3.0 AP-9 (S12)
package main

// V6.3.0 AP-9 (S12): XDR integration of the independent high-priority security
// evidence ring and the two-class telemetry backpressure facts.
//
// The kernel contract (`rust/gedefense-ebpf/src/sec_crit.rs`) separates bulk
// telemetry from critical evidence:
//
//   - bulk classes (exec argv, kernel probe, network flow, DNS) pass a
//     per-(class, cgroup, uid) token bucket; a throttled class is counted, never
//     silently blackholed;
//   - critical records (credential deny, attach-time eBPF helper risk, LKM load,
//     critical persistence record) are duplicated into `SEC_CRIT_EVENTS`, which
//     bulk traffic cannot displace.
//
// This engine consumes that channel. It never creates a response:
//
//   - Every accepted critical record becomes bounded, independently deduplicated
//     `xdr.sec_crit_evidence` info evidence (ledger first). It deliberately does
//     not duplicate the dedicated family findings (XDR.BPF_*, credential guard,
//     XDR.LKM_LOAD, persistence): the family sensors remain authoritative for
//     those rule families.
//   - `XDR.SEC_CRIT_DIFFERENTIAL_GAP` is surfaced only when a critical record
//     arrives while its dedicated family reports disarmed/degraded/not
//     advertised. That is the safety-net case: the record proves visibility
//     existed despite the family projection saying otherwise. Evidence-first,
//     `Decision:"alert"`, `Action:"none"`, score 60 (below every response
//     threshold) — never kill-eligible.
//   - `XDR.TELEMETRY_FLOOD_SUPPRESSION` is emitted when the token bucket
//     suppresses bulk telemetry or the high-priority ring drops records.
//     Severity is `high` when critical evidence was at risk (ring drops /
//     unarmed refusals), otherwise `warning`; score 75; observe-only and rate
//     limited to one incident per 5 minutes. The concrete backpressure state is
//     also reported as a degraded capability cause, so a controlled overflow is
//     never a silent fail-open.
//   - `SecCritReport` projects the honest operator view (state/capability/
//     counters/bucket accounting) and a report-only S12 quota review: parser-cell
//     concurrency, review-queue bytes and the quarantine filesystem reserve.
//     The quotas are reported, not enforced here: this work package may not edit
//     the owning modules, so that remains an explicit integration gap.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Cadences and bounds (bounded, never unbounded work per poll/API read).
const (
	secCritDrainInterval      = 2 * time.Second
	secCritStatusInterval     = 10 * time.Second
	secCritDedupeTTL          = 10 * time.Minute
	secCritSeenLimit          = 4096
	secCritFloodMinGap        = 5 * time.Minute
	secCritDifferentialGap    = 5 * time.Minute
	secCritPressureWindow     = 2 * time.Minute
	secCritReasonBytes        = 320
	secCritSummaryBytes       = 512
	secCritQuotaReasonBytes   = 200
	secCritQuotaReasonsShown  = 4
	secCritQuarantineReserve  = 256 << 20 // 256 MiB minimum free reserve
	secCritFloodRuleID        = "XDR.TELEMETRY_FLOOD_SUPPRESSION"
	secCritDifferentialRuleID = "XDR.SEC_CRIT_DIFFERENTIAL_GAP"
	secCritPressureCause      = "sec_crit_backpressure"
	secCritBucketAccounting   = "bucket_capacity"
)

// secCritCore is the subset of the privileged client the S12 contract needs.
type secCritCore interface {
	SecCritSet(enabled bool) error
	SecCritEvents() ([]CoreSecCritEvent, uint64, error)
	SecCritStatus() (CoreSecCritStatus, error)
}

// SecCritEngine holds the bounded arm-once/dedupe/backpressure bookkeeping.
// Every field is guarded by `XDREngine.secCritMu`; the type exists so the
// pre-wired XDREngine field can be constructed inert in tests.
type SecCritEngine struct {
	armedRequested bool
	// Capability-probe state: before the first SEC_CRIT_STATUS attempt the
	// capability is unknown (not "missing"); a core answering unknown-command is
	// a capability fact. Both are honest but not the same claim.
	capabilityProbed bool
	// Monotonic counter baselines from the previous status sample.
	lastSuppressed   uint64
	lastDrops        uint64
	lastRefused      uint64
	lastReadFailures uint64
	counterBaseline  bool
	// Time/flag of the last observed backpressure event (bulk suppression or
	// critical evidence loss). Drives the recovered/degraded transition only.
	lastPressureAt time.Time
	pressureActive bool
	// Bounded per-source rate limit for differential-gap findings.
	differentialAt map[uint8]time.Time
	// Count of critical local integrity/cross-view findings mirrored into SEC_CRIT.
	mirroredEvents uint64
}

// NewSecCritEngine constructs the inert engine.
func NewSecCritEngine() *SecCritEngine {
	return &SecCritEngine{differentialAt: make(map[uint8]time.Time, 8)}
}

// recordLocalSecCritMirror mirrors local self-tamper and cross-view critical
// findings into the SEC_CRIT bookkeeping and telemetry stream (observe-only).
func (e *XDREngine) recordLocalSecCritMirror(source, kind string, now time.Time) {
	if e == nil || e.secCrit == nil {
		return
	}
	e.secCritMu.Lock()
	e.secCrit.mirroredEvents++
	e.secCritMu.Unlock()
	if e.state != nil {
		e.state.AddEvent(Event{
			Time:     now,
			Severity: "high",
			Kind:     "xdr.sec_crit_evidence",
			Source:   "sec-crit",
			Message:  boundedPermitText(fmt.Sprintf("Critical local evidence mirrored to high-priority ring: source=%s kind=%s", source, kind), secCritSummaryBytes),
			Target:   boundedPermitText(source+":"+kind, 120),
		})
	}
}

// pollSecCrit runs one status + drain cycle and returns the next due time. The
// XDR loop ticks every 100 ms; this returns the drain cadence (2 s) and performs
// the status query only when its 10 s cadence is due, so neither can delay
// another ingestion path. A pre-6.3 core (unknown command) is a capability
// fact: ErrSecCritUnavailable is reported as missing, never as an XDR outage.
func (e *XDREngine) pollSecCrit(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.secCrit == nil || e.secCritCore == nil || !runtime.XDREnabled || now.Before(retryAfter) {
		return retryAfter
	}
	if e.secCritStatusDue(now) {
		status, statusErr := e.secCritCore.SecCritStatus()
		e.consumeSecCritStatus(status, statusErr, now)
		if statusErr == nil {
			// Arm the observe-only observer once. The core arms itself at load;
			// this covers a core that was explicitly disarmed and keeps a later
			// operator disarm authoritative (the request latches).
			if !status.Enabled {
				if err := e.secCritArm(); err != nil {
					e.setSecCritArmError(err)
				}
			}
			e.consumeSecCritFlood(status, now)
		}
	}
	events, dropped, drainErr := e.secCritCore.SecCritEvents()
	if drainErr != nil {
		if errors.Is(drainErr, ErrSecCritUnavailable) {
			e.consumeSecCritStatus(CoreSecCritStatus{}, ErrSecCritUnavailable, now)
		} else {
			// Never pretend healthy: the report shows degraded with this reason
			// until the drain succeeds again.
			e.setSecCritDrainError(drainErr)
		}
		return now.Add(secCritDrainInterval)
	}
	e.clearSecCritDrainError()
	e.consumeSecCritEvents(events, dropped, now)
	return now.Add(secCritDrainInterval)
}

func (e *XDREngine) secCritStatusDue(now time.Time) bool {
	e.secCritMu.Lock()
	defer e.secCritMu.Unlock()
	return e.secCritStatusAt.IsZero() || now.Sub(e.secCritStatusAt) >= secCritStatusInterval
}

// secCritArm issues SEC_CRIT_SET 1 at most once per process. A failure keeps the
// latch open so a transient IPC failure is retried on the next status cycle.
func (e *XDREngine) secCritArm() error {
	if e == nil || e.secCrit == nil || e.secCritCore == nil {
		return nil
	}
	e.secCritMu.Lock()
	requested := e.secCrit.armedRequested
	e.secCritMu.Unlock()
	if requested {
		return nil
	}
	if err := e.secCritCore.SecCritSet(true); err != nil {
		return err
	}
	e.secCritMu.Lock()
	e.secCrit.armedRequested = true
	e.secCritMu.Unlock()
	return nil
}

func (e *XDREngine) setSecCritStatusError(err error) {
	if e == nil || err == nil {
		return
	}
	e.secCritMu.Lock()
	e.secCritStatusErr = "status query failed: " + boundedStyxText(err)
	e.secCritMu.Unlock()
}

func (e *XDREngine) setSecCritDrainError(err error) {
	if e == nil || err == nil {
		return
	}
	e.secCritMu.Lock()
	e.secCritStatusErr = "event drain failed: " + boundedStyxText(err)
	e.secCritMu.Unlock()
}

// setSecCritArmError records a failed SEC_CRIT_SET 1 without pretending the
// status query failed.
func (e *XDREngine) setSecCritArmError(err error) {
	if e == nil || err == nil {
		return
	}
	e.secCritMu.Lock()
	e.secCritStatusErr = "arm request failed: " + boundedStyxText(err)
	e.secCritMu.Unlock()
}

// clearSecCritDrainError forgets only a drain-origin error; a persistent
// status-query failure is cleared by the next successful status query.
func (e *XDREngine) clearSecCritDrainError() {
	if e == nil {
		return
	}
	e.secCritMu.Lock()
	if strings.HasPrefix(e.secCritStatusErr, "event drain failed:") {
		e.secCritStatusErr = ""
	}
	e.secCritMu.Unlock()
}

func (e *XDREngine) consumeSecCritStatus(status CoreSecCritStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.secCritMu.Lock()
	wasKnown := e.secCritCapabilityKnown
	if e.secCrit != nil {
		e.secCrit.capabilityProbed = true
	}
	switch {
	case statusErr == nil:
		e.secCritStatus = status
		e.secCritStatusAt = now
		e.secCritStatusErr = ""
		e.secCritCapabilityKnown = true
	case errors.Is(statusErr, ErrSecCritUnavailable):
		e.secCritCapabilityKnown = false
		e.secCritStatus = CoreSecCritStatus{}
		e.secCritStatusAt = time.Time{}
		e.secCritStatusErr = ""
		if e.secCrit != nil {
			e.secCrit.armedRequested = false
			e.secCrit.counterBaseline = false
		}
	default:
		e.secCritStatusErr = "status query failed: " + boundedStyxText(statusErr)
	}
	known := e.secCritCapabilityKnown
	e.secCritMu.Unlock()
	if e.state == nil {
		return
	}
	switch {
	case !known && wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.sec_crit_capability_missing", Source: "kernel",
			Message: "The privileged core no longer advertises the SEC_CRIT_* command family; the high-priority security evidence ring is unavailable (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.sec_crit_capability_available", Source: "kernel",
			Message: "High-priority security evidence ring is available; critical SEC_CRIT records are ingested as independent safety-net evidence (observe-only)"})
	}
}

// consumeSecCritFlood turns the monotonic kernel counters into the bounded
// backpressure facts. "Bucket exhausted" is exactly the suppression counter
// advancing (the kernel increments it on the refusal); "critical evidence at
// risk" is a ring-drop or an unarmed refusal while the observer is armed.
func (e *XDREngine) consumeSecCritFlood(status CoreSecCritStatus, now time.Time) {
	if e == nil || e.secCrit == nil {
		return
	}
	e.secCritMu.Lock()
	engine := e.secCrit
	counterReset := engine.counterBaseline &&
		(status.Suppressed < engine.lastSuppressed || status.Drops < engine.lastDrops)
	var suppressedDelta, dropsDelta uint64
	if engine.counterBaseline && !counterReset {
		suppressedDelta = status.Suppressed - engine.lastSuppressed
		dropsDelta = status.Drops - engine.lastDrops
	} else {
		suppressedDelta = status.Suppressed
		dropsDelta = status.Drops
	}
	engine.lastSuppressed = status.Suppressed
	engine.lastDrops = status.Drops
	engine.lastRefused = status.RefusedUnarmed
	engine.lastReadFailures = status.ReadFailures
	engine.counterBaseline = true
	pressured := suppressedDelta > 0 || dropsDelta > 0
	if pressured {
		engine.lastPressureAt = now
		engine.pressureActive = true
	}
	recentPressure := engine.pressureActive && !engine.lastPressureAt.IsZero() &&
		now.Sub(engine.lastPressureAt) <= secCritPressureWindow
	if !recentPressure {
		engine.pressureActive = false
	}
	e.secCritMu.Unlock()

	if pressured {
		e.markSecCritPressure(status, suppressedDelta, dropsDelta, now)
	}
	if recentPressure {
		if !e.secCritPressureCauseSet() {
			reason := fmt.Sprintf(
				"S12 telemetry backpressure active: bulk telemetry suppressed by the per-(class,cgroup,uid) token bucket (total=%d), high-priority ring drops=%d, bucket capacity=%d",
				status.Suppressed, status.Drops, status.BucketCapacity)
			e.markDegradedCause(secCritPressureCause, boundedPermitText(reason, secCritReasonBytes))
		}
	} else if e.secCritPressureCauseSet() {
		e.clearDegradedCause(secCritPressureCause)
		if e.state != nil {
			e.state.AddEvent(Event{Severity: "info", Kind: "xdr.sec_crit_backpressure_recovered", Source: "kernel",
				Message: "S12 telemetry backpressure recovered: no bulk suppression or high-priority loss observed in the pressure window; critical evidence channel is healthy"})
		}
	}
}
