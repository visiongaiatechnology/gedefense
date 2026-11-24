// V6.3.0 AP-9 (S12): flood/backpressure findings, the drain-observed critical
// loss path, the bounded dedupe/evidence ingestion and the bounded operator text
// of the S12 channel. Every finding here is observe-only: `Decision:"alert"`,
// `Action:"none"`, never kill-eligible, and each one commits its evidence before
// the incident is appended.
package main

import (
	"fmt"
	"time"
)

// markSecCritPressure records the evidence-first flood finding (rate limited to
// one per 5 minutes) and the concrete degraded cause. It never derives a
// response and never touches the kill gate.
func (e *XDREngine) markSecCritPressure(status CoreSecCritStatus, suppressedDelta, dropsDelta uint64, now time.Time) {
	if e == nil || e.state == nil {
		return
	}
	criticalAtRisk := dropsDelta > 0 || status.Drops > 0
	severity := "warning"
	if criticalAtRisk {
		severity = "high"
	}
	summary := fmt.Sprintf(
		"S12 telemetry backpressure: bulk telemetry throttled by the per-(class,cgroup,uid) token bucket (new suppressions=%d, total=%d, capacity=%d); high-priority SEC_CRIT ring drops=%d (new=%d), refused-unarmed=%d, read failures=%d; critical evidence lost=%s",
		suppressedDelta, status.Suppressed, status.BucketCapacity, status.Drops, dropsDelta,
		status.RefusedUnarmed, status.ReadFailures, yesNo(criticalAtRisk))
	summary = boundedPermitText(summary, secCritSummaryBytes)

	e.secCritMu.Lock()
	last := e.secCritLastOverflow
	due := last.IsZero() || now.Sub(last) >= secCritFloodMinGap
	if due {
		e.secCritLastOverflow = now
	}
	e.secCritMu.Unlock()
	if !due {
		return
	}

	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: severity, Kind: "xdr.telemetry_flood_suppression", Source: "kernel",
		Message: "S12 telemetry flood-suppression evidence recorded before any report: " + summary,
		Target:  "sec-crit:ring", Time: now,
	})
	outcome := "observed only; telemetry backpressure is reported as capability degradation and never changes an enforcement decision"
	if evidenceErr != nil {
		outcome = "observed only; mandatory evidence commit failed, incident recorded without response: " + boundedStyxText(evidenceErr)
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("seccrit-flood-%d", now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-sec-crit",
		Category:   "sensor-health",
		EventType:  "TELEMETRY_FLOOD_SUPPRESSION",
		EntityID:   "sec-crit:ring",
		Actor:      "kernel",
		Severity:   severity,
		Confidence: 90,
		CausalEdge: EdgeRootCause,
		EventUUID:  randomID(),
		Metadata: map[string]string{
			"suppressed_total":    fmt.Sprintf("%d", status.Suppressed),
			"suppressed_new":      fmt.Sprintf("%d", suppressedDelta),
			"ring_drops_total":    fmt.Sprintf("%d", status.Drops),
			"ring_drops_new":      fmt.Sprintf("%d", dropsDelta),
			"refused_unarmed":     fmt.Sprintf("%d", status.RefusedUnarmed),
			"read_failures":       fmt.Sprintf("%d", status.ReadFailures),
			"bucket_capacity":     fmt.Sprintf("%d", status.BucketCapacity),
			"critical_evidence":   "at_risk=" + yesNo(criticalAtRisk),
			"observe_only":        "true",
			"response_derived":    "none",
			"ring_priority_class": "high",
		},
	}
	node.Digest = node.ComputeNodeDigest()
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: now, Severity: severity, Score: 75,
		RuleIDs: []string{secCritFloodRuleID}, Categories: []string{"sensor-health"},
		Summary: summary, Decision: "alert", Action: "none", Outcome: outcome,
		ExecutionChainID: node.NodeID, AttackStory: []AttackStoryNode{node}, EvidenceRoot: node.Digest,
	})
	if e.state != nil {
		e.state.AddEvent(Event{Time: now, Severity: severity, Kind: "xdr.telemetry_flood_suppression", Source: "kernel",
			Message: summary + "; " + outcome, Target: "sec-crit:ring"})
	}
}

// noteSecCritCriticalLoss reports a drain-observed ring-drop delta immediately
// (the drain runs on a 2 s cadence, the status on 10 s) so critical evidence
// loss can never wait for a status sample. It shares the 5 minute flood rate
// limit and always raises the pressure/degraded cause.
func (e *XDREngine) noteSecCritCriticalLoss(dropped uint64, now time.Time) {
	if e == nil || dropped == 0 || e.secCrit == nil {
		return
	}
	e.secCritMu.Lock()
	e.secCrit.lastPressureAt = now
	status := e.secCritStatus
	e.secCritMu.Unlock()
	status.Drops = status.Drops + dropped
	e.markSecCritPressure(status, 0, dropped, now)
	if !e.secCritPressureCauseSet() {
		reason := fmt.Sprintf("S12 high-priority ring dropped %d critical security record(s) in one drain; critical evidence was lost (capability degraded)", dropped)
		e.markDegradedCause(secCritPressureCause, boundedPermitText(reason, secCritReasonBytes))
	}
}

func (e *XDREngine) secCritPressureCauseSet() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.degradeCauses[secCritPressureCause]
	return ok
}

// consumeSecCritEvents turns one bounded drain into independent evidence. It
// never re-creates a dedicated family finding and never derives a response.
func (e *XDREngine) consumeSecCritEvents(events []CoreSecCritEvent, dropped uint64, now time.Time) {
	if e == nil {
		return
	}
	for _, event := range events {
		if !e.claimSecCritRecord(event, now) {
			continue
		}
		e.recordSecCritEvidence(event, now)
		if reason, gap := e.secCritFamilyState(event.Source); gap {
			e.recordSecCritDifferential(event, reason, now)
		}
	}
	if dropped > 0 {
		e.noteSecCritCriticalLoss(dropped, now)
	}
}

// claimSecCritRecord dedupes by the mandated (ts, source, kind, pid, ino) key
// with a bounded, TTL-pruned seen map.
func (e *XDREngine) claimSecCritRecord(event CoreSecCritEvent, now time.Time) bool {
	if e == nil {
		return false
	}
	key := fmt.Sprintf("event:%d|%d|%d|%d|%d", event.TsNS, event.Source, event.Kind, event.PID, event.Ino)
	e.secCritMu.Lock()
	defer e.secCritMu.Unlock()
	if e.secCritSeen == nil {
		e.secCritSeen = make(map[string]time.Time)
	}
	if until, exists := e.secCritSeen[key]; exists && now.Before(until) {
		return false
	}
	e.secCritSeen[key] = now.Add(secCritDedupeTTL)
	if len(e.secCritSeen) > secCritSeenLimit {
		for seenKey, until := range e.secCritSeen {
			if !until.After(now) {
				delete(e.secCritSeen, seenKey)
			}
		}
		// Still over the bound (all entries fresh): evict until bounded. The map
		// is a dedupe cache, so an evicted key can only repeat a record, never
		// hide one.
		for seenKey := range e.secCritSeen {
			if len(e.secCritSeen) <= secCritSeenLimit {
				break
			}
			delete(e.secCritSeen, seenKey)
		}
	}
	return true
}

// recordSecCritEvidence records one critical record as bounded, independent
// safety-net evidence (ledger first) and an info event. No incident is created:
// the dedicated family sensors own their rule families.
func (e *XDREngine) recordSecCritEvidence(event CoreSecCritEvent, now time.Time) {
	if e == nil || e.state == nil {
		return
	}
	summary := secCritEventSummary(event)
	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: "info", Kind: "xdr.sec_crit_evidence", Source: "kernel",
		Message: "Independent high-priority security evidence (safety net): " + summary,
		Target:  fmt.Sprintf("pid:%d", event.PID), Time: now,
	})
	if evidenceErr != nil {
		e.state.AddEvent(Event{Time: now, Severity: "warning", Kind: "xdr.sec_crit_evidence_failed", Source: "kernel",
			Message: "Critical SEC_CRIT evidence could not be committed to the ledger: " + boundedStyxText(evidenceErr),
			Target:  fmt.Sprintf("pid:%d", event.PID)})
		return
	}
	e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.sec_crit_evidence", Source: "kernel",
		Message: summary, Target: fmt.Sprintf("pid:%d", event.PID)})
}

// secCritFamilyState reports whether the dedicated family that normally owns
// this evidence source is disarmed/degraded/not advertised. Only then does a
// safety-net record carry differential information; sources without a wired
// duplicate producer are not compared (no claim is invented).
func (e *XDREngine) secCritFamilyState(source uint8) (string, bool) {
	if e == nil {
		return "", false
	}
	switch source {
	case SecCritSourceCredGuard:
		e.credMu.Lock()
		known, armed, errText := e.credCapabilityKnown, e.credStatus.Armed, e.credStatusErr
		e.credMu.Unlock()
		switch {
		case !known:
			return "credential guard is not reported available (capability missing/unknown)", true
		case errText != "":
			return "credential guard degraded: " + boundedPermitText(errText, secCritReasonBytes), true
		case !armed:
			return "credential guard is disarmed (CRED_GUARD_SET 0)", true
		}
	case SecCritSourceBpfGuard:
		e.bpfGuardMu.Lock()
		known, enabled, errText := e.bpfGuardCapabilityKnown, e.bpfGuardStatus.Enabled, e.bpfGuardStatusErr
		e.bpfGuardMu.Unlock()
		switch {
		case !known:
			return "attach-time eBPF guard is not reported available (capability missing/unknown)", true
		case errText != "":
			return "attach-time eBPF guard degraded: " + boundedPermitText(errText, secCritReasonBytes), true
		case !enabled:
			return "attach-time eBPF guard is disarmed (BPF_GUARD_SET 0)", true
		}
	case SecCritSourceKernelHooks:
		e.kernelHooksMu.Lock()
		known, enabled, errText := e.kernelHooksCapabilityKnown, e.kernelHooksStatus.Enabled, e.kernelHooksStatusErr
		e.kernelHooksMu.Unlock()
		switch {
		case !known:
			return "kernel hook sensor is not reported available (capability missing/unknown)", true
		case errText != "":
			return "kernel hook sensor degraded: " + boundedPermitText(errText, secCritReasonBytes), true
		case !enabled:
			return "kernel hook sensor is disarmed (KERNEL_HOOK_SET 0)", true
		}
	case SecCritSourcePersistence:
		e.persistenceMu.Lock()
		known, enabled, errText := e.persistenceCapabilityKnown, e.persistenceStatus.Enabled, e.persistenceStatusErr
		e.persistenceMu.Unlock()
		switch {
		case !known:
			return "persistence guard is not reported available (capability missing/unknown)", true
		case errText != "":
			return "persistence guard degraded: " + boundedPermitText(errText, secCritReasonBytes), true
		case !enabled:
			return "persistence guard is disarmed (PERSIST_GUARD_SET 0)", true
		}
	}
	return "", false
}

// recordSecCritDifferential surfaces the safety-net differential: a critical
// record exists while its dedicated family claims to be unavailable. It is
// evidence-first, alert-only (no action) and rate limited per source.
func (e *XDREngine) recordSecCritDifferential(event CoreSecCritEvent, reason string, now time.Time) {
	if e == nil || e.secCrit == nil {
		return
	}
	e.secCritMu.Lock()
	if e.secCrit.differentialAt == nil {
		e.secCrit.differentialAt = make(map[uint8]time.Time, 8)
	}
	last := e.secCrit.differentialAt[event.Source]
	due := last.IsZero() || now.Sub(last) >= secCritDifferentialGap
	if due {
		e.secCrit.differentialAt[event.Source] = now
	}
	e.secCritMu.Unlock()
	if !due {
		return
	}
	summary := fmt.Sprintf(
		"S12 safety-net differential: %s record observed while the dedicated family is not active (%s); the independent high-priority record proves visibility exists independently of the family projection",
		secCritSourceName(event.Source), boundedPermitText(reason, secCritReasonBytes))
	summary = boundedPermitText(summary, secCritSummaryBytes)
	if e.state == nil {
		return
	}
	var evidenceErr error
	if e.state != nil {
		evidenceErr = e.state.RecordEvidence(EvidenceRecord{
			Severity: "warning", Kind: "xdr.sec_crit_differential_gap", Source: "kernel",
			Message: "S12 differential evidence recorded before any report: " + summary,
			Target:  fmt.Sprintf("source:%d:pid:%d", event.Source, event.PID), Time: now,
		})
	}
	outcome := "observed only; the safety-net differential never derives a response"
	if evidenceErr != nil {
		outcome = "observed only; mandatory evidence commit failed, incident recorded without response: " + boundedStyxText(evidenceErr)
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("seccrit-gap-%d-%d", event.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-sec-crit",
		Category:   "sensor-health",
		EventType:  "SEC_CRIT_DIFFERENTIAL_GAP",
		EntityID:   fmt.Sprintf("pid:%d", event.PID),
		Actor:      fmt.Sprintf("uid:%d", event.UID),
		Severity:   "warning",
		Confidence: 85,
		CausalEdge: EdgeRootCause,
		EventUUID:  randomID(),
		Metadata: map[string]string{
			"source":           secCritSourceName(event.Source),
			"dedicated_reason": boundedPermitText(reason, secCritReasonBytes),
			"obs_ts_ns":        fmt.Sprintf("%d", event.TsNS),
			"comm":             event.Comm,
			"dev":              fmt.Sprintf("%d", event.Dev),
			"ino":              fmt.Sprintf("%d", event.Ino),
			"observe_only":     "true",
			"response_derived": "none",
		},
	}
	node.Digest = node.ComputeNodeDigest()
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: now, Severity: "warning", Score: 60,
		PID: event.PID, UID: event.UID, Process: event.Comm,
		RuleIDs: []string{secCritDifferentialRuleID}, Categories: []string{"sensor-health"},
		Summary: summary, Decision: "alert", Action: "none", Outcome: outcome,
		ExecutionChainID: node.NodeID, AttackStory: []AttackStoryNode{node}, EvidenceRoot: node.Digest,
	})
	if e.state != nil {
		e.state.AddEvent(Event{Time: now, Severity: "warning", Kind: "xdr.sec_crit_differential_gap", Source: "kernel",
			Message: summary, Target: fmt.Sprintf("pid:%d", event.PID)})
	}
}

// secCritEventSummary renders the bounded operator text of one record.
func secCritEventSummary(event CoreSecCritEvent) string {
	summary := fmt.Sprintf(
		"source=%s kind=%d action=%s detail=0x%x pid=%d tgid=%d uid=%d dev=%d ino=%d comm=%s extra=%s",
		secCritSourceName(event.Source), event.Kind, secCritActionName(event.Action),
		event.DetailCode, event.PID, event.TGID, event.UID, event.Dev, event.Ino,
		boundedPermitText(event.Comm, 32), boundedPermitText(event.Extra, 32))
	return boundedPermitText(summary, secCritSummaryBytes)
}

func secCritSourceName(source uint8) string {
	switch source {
	case SecCritSourceCredGuard:
		return "credential-guard"
	case SecCritSourceBpfGuard:
		return "bpf-guard"
	case SecCritSourceKernelHooks:
		return "kernel-hooks"
	case SecCritSourceCrossView:
		return "cross-view"
	case SecCritSourceSelfTamper:
		return "self-tamper"
	case SecCritSourceRansom:
		return "ransom"
	case SecCritSourcePersistence:
		return "persistence"
	default:
		return fmt.Sprintf("unknown-%d", source)
	}
}

func secCritActionName(action uint8) string {
	switch action {
	case SecCritActionObserve:
		return "observe"
	case SecCritActionEnforce:
		return "enforce"
	default:
		return fmt.Sprintf("unknown-%d", action)
	}
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
