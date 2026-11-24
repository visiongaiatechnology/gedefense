// STATUS: V6.3.0 AP-0
package main

// V6.3.0 AP-0: XDR integration of the kernel sensor self-protection.
//
// Consumes SELF_GUARD_STATUS / SELF_TAMPER_EVENTS and turns an unlinked BPF
// pin, a replaced pin inode, a dead canary sensor chain, a missing bpffs or a
// monotone ring-drop delta into evidence-first XDR.SELF_TAMPER incidents tagged
// SBC-EVID-08. Deliberately alert-only: no active response (Action "none",
// Decision "degrade") is derived from a self-tamper fact, because the kernel
// enforcement plane itself may be degraded. The platform must not answer a
// broken trust boundary by taking a response action it can no longer justify.
//
// Evidence is written before the incident. If the mandatory evidence commit
// fails, that failure is reflected in the incident outcome instead of being
// swallowed: the operator sees a degraded incident, not a healthy one.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// selfGuardStatusInterval is the status-query cadence (AP-0: 10 s).
	selfGuardStatusInterval = 10 * time.Second
	// selfGuardDrainInterval is the bounded self-tamper drain cadence.
	selfGuardDrainInterval = time.Second
	// selfGuardStatusRetry is the backoff for a core that does not advertise the
	// family yet (capability fact) or for a transient status failure.
	selfGuardStatusRetry = 10 * time.Second
	// selfGuardDrainRetry is the backoff after a transient drain failure.
	selfGuardDrainRetry = 2 * time.Second
	// selfGuardSeenTTL bounds cross-sensor duplicate suppression.
	selfGuardSeenTTL = 10 * time.Minute
	// selfGuardSeenCap bounds the dedupe/rate-limit map.
	selfGuardSeenCap = 4096
	// selfGuardOverflowInterval rate-limits "the self-tamper queue itself
	// overflowed" facts.
	selfGuardOverflowInterval = 5 * time.Minute
	// selfGuardDropRateLimit is the per-counter ring-drop incident rate limit.
	selfGuardDropRateLimit = 5 * time.Minute
	// selfGuardRuleID is the closed self-tamper rule token.
	selfGuardRuleID = "XDR.SELF_TAMPER"
	// selfGuardSBCFamily names the self-protection evidence family.
	selfGuardSBCFamily = "SBC-EVID-08"
	// selfGuardDetailMaxBytes bounds the detail copied into evidence metadata.
	selfGuardDetailMaxBytes = 32
)

// selfGuardCore is the subset of the privileged client the self-protection
// contract needs (interface so synthetic-answer tests need no socket).
type selfGuardCore interface {
	SelfGuardSet(enabled bool) error
	SelfGuardStatus() (CoreSelfGuardStatus, error)
	SelfTamperEvents() ([]CoreSelfTamperEvent, uint64, error)
}

// selfTamperFact is one normalized integrity fact from any self-protection
// source: a bounded queue record or a sampled ring-drop delta.
type selfTamperFact struct {
	kind       string
	detailCode uint32
	detail     string
	tsMS       uint64
	edge       string
	counter    string
	delta      uint64
}

// pollSelfGuard runs one status + drain cycle and returns the next due time.
//
// Cadence: the status is queried every 10 s and the bounded self-tamper queue is
// drained every second; the ring-drop watchdog reads drop counters other
// ingestion paths already sampled on the engine, so it issues no extra core
// command for the credential/styx families. Ingress ring drops are sampled with
// the 10 s status cycle only.
func (e *XDREngine) pollSelfGuard(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.selfGuardCore == nil || !runtime.XDREnabled {
		return retryAfter
	}
	if now.Before(retryAfter) {
		return retryAfter
	}

	statusDue := false
	e.selfGuardMu.Lock()
	if e.selfGuardStatusAt.IsZero() || now.Sub(e.selfGuardStatusAt) >= selfGuardStatusInterval {
		statusDue = true
		// Track the attempt, not only the success: a failing status query must
		// not be retried on every 100 ms tick.
		e.selfGuardStatusAt = now
	}
	e.selfGuardMu.Unlock()

	// The watchdog runs before the capability gate: a core without the
	// SELF_GUARD_* family still reports credential/flow ring drops through the
	// already-sampled health structs, and a silent telemetry loss must not
	// depend on a newer command family being present.
	e.watchSelfGuardRingDrops(statusDue, now)

	if statusDue {
		status, statusErr := e.selfGuardCore.SelfGuardStatus()
		e.consumeSelfGuardStatus(status, statusErr, now)
		if statusErr == nil {
			e.armSelfGuardOnce(status)
		} else if errors.Is(statusErr, ErrSelfGuardUnavailable) {
			// A pre-6.3 core is a capability fact, never an XDR degradation.
			return now.Add(selfGuardStatusRetry)
		}
	}

	e.selfGuardMu.Lock()
	known := e.selfGuardCapabilityKnown
	e.selfGuardMu.Unlock()
	if !known {
		return now.Add(selfGuardStatusRetry)
	}

	events, dropped, drainErr := e.selfGuardCore.SelfTamperEvents()
	e.consumeSelfTamperBatch(events, dropped, drainErr, now)
	if drainErr != nil {
		if errors.Is(drainErr, ErrSelfGuardUnavailable) {
			return now.Add(selfGuardStatusRetry)
		}
		return now.Add(selfGuardDrainRetry)
	}
	return now.Add(selfGuardDrainInterval)
}

// consumeSelfGuardStatus stores the honest projection and reports capability
// transitions as info events only (a missing capability is not an attack).
func (e *XDREngine) consumeSelfGuardStatus(status CoreSelfGuardStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.selfGuardMu.Lock()
	wasKnown := e.selfGuardCapabilityKnown
	switch {
	case statusErr == nil:
		e.selfGuardStatus = status
		e.selfGuardStatusAt = now
		e.selfGuardStatusErr = ""
		e.selfGuardCapabilityKnown = true
	case errors.Is(statusErr, ErrSelfGuardUnavailable):
		e.selfGuardCapabilityKnown = false
		e.selfGuardStatus = CoreSelfGuardStatus{}
		e.selfGuardStatusErr = ""
	default:
		e.selfGuardStatusErr = boundedStyxText(statusErr)
	}
	known := e.selfGuardCapabilityKnown
	e.selfGuardMu.Unlock()
	if e.state == nil {
		return
	}
	switch {
	case !known && wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.self_guard_capability_missing", Source: "integrity",
			Message: "The privileged core no longer advertises the SELF_GUARD_* command family; kernel sensor self-protection visibility is unavailable (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.self_guard_capability_available", Source: "integrity",
			Message: "Kernel sensor self-protection is available; pin/canary self-tamper facts are ingested as observe-only evidence"})
	}
}

// armSelfGuardOnce arms the observers exactly once when the family is available.
// A failed arm is retried only after a later successful status query, and never
// turns into a detection fact on its own.
func (e *XDREngine) armSelfGuardOnce(status CoreSelfGuardStatus) {
	if e == nil {
		return
	}
	e.selfGuardMu.Lock()
	if e.selfGuardArmedRequested {
		e.selfGuardMu.Unlock()
		return
	}
	if status.Enabled || status.Armed {
		// Already armed, e.g. by a previous control-plane process or an operator
		// command: do not fight that state.
		e.selfGuardArmedRequested = true
		e.selfGuardMu.Unlock()
		return
	}
	e.selfGuardArmedRequested = true
	e.selfGuardMu.Unlock()
	if err := e.selfGuardCore.SelfGuardSet(true); err != nil {
		e.selfGuardMu.Lock()
		e.selfGuardArmedRequested = false
		e.selfGuardStatusErr = boundedStyxText(err)
		e.selfGuardMu.Unlock()
	}
}

// consumeSelfTamperBatch deduplicates and records one bounded drain.
func (e *XDREngine) consumeSelfTamperBatch(events []CoreSelfTamperEvent, dropped uint64, drainErr error, now time.Time) {
	if e == nil {
		return
	}
	if drainErr != nil {
		if errors.Is(drainErr, ErrSelfGuardUnavailable) {
			e.consumeSelfGuardStatus(CoreSelfGuardStatus{}, drainErr, now)
			return
		}
		e.selfGuardMu.Lock()
		e.selfGuardStatusErr = boundedStyxText(drainErr)
		e.selfGuardMu.Unlock()
		return
	}
	for _, event := range events {
		if !e.claimSelfTamperRecord(event, now) {
			continue
		}
		label, edge := selfTamperKindMapping(event.Kind)
		e.recordSelfTamperFact(selfTamperFact{
			kind:       label,
			detailCode: event.DetailCode,
			detail:     event.Detail,
			tsMS:       event.TsMS,
			edge:       edge,
		}, now)
	}
	if dropped > 0 {
		e.recordSelfGuardQueueOverflow(dropped, now)
	}
}

// claimSelfTamperRecord suppresses a record that the core reported twice (e.g.
// re-read after a restart) using the AP-0 dedupe identity (ts, kind, code).
func (e *XDREngine) claimSelfTamperRecord(event CoreSelfTamperEvent, now time.Time) bool {
	key := fmt.Sprintf("%d|%d|%d", event.TsMS, event.Kind, event.DetailCode)
	e.selfGuardMu.Lock()
	defer e.selfGuardMu.Unlock()
	if e.selfGuardSeen == nil {
		e.selfGuardSeen = make(map[string]time.Time)
	}
	if until, exists := e.selfGuardSeen[key]; exists && now.Before(until) {
		return false
	}
	e.selfGuardSeen[key] = now.Add(selfGuardSeenTTL)
	e.pruneSelfGuardSeenLocked(now)
	return true
}

// pruneSelfGuardSeenLocked drops expired dedupe and rate-limit entries. The map
// is bounded; pruning only removes entries whose hold has already expired, so an
// active rate limit can never be forgotten.
func (e *XDREngine) pruneSelfGuardSeenLocked(now time.Time) {
	if len(e.selfGuardSeen) <= selfGuardSeenCap {
		return
	}
	for key, until := range e.selfGuardSeen {
		if !until.After(now) {
			delete(e.selfGuardSeen, key)
		}
	}
}

// recordSelfGuardQueueOverflow turns records lost by the bounded self-tamper
// queue into the same evidence family. It is rate-limited because a full queue
// persists across many drains.
func (e *XDREngine) recordSelfGuardQueueOverflow(dropped uint64, now time.Time) {
	e.selfGuardMu.Lock()
	last := e.selfGuardLastOverflow
	if !last.IsZero() && now.Sub(last) < selfGuardOverflowInterval {
		e.selfGuardMu.Unlock()
		return
	}
	e.selfGuardLastOverflow = now
	e.selfGuardMu.Unlock()
	e.recordSelfTamperFact(selfTamperFact{
		kind:       "queue_overflow",
		detailCode: 0,
		detail:     "self-guard queue overflow",
		tsMS:       uint64(now.UnixMilli()),
		edge:       EdgeRootCause,
	}, now)
}

// selfTamperKindMapping maps the closed wire kind to the human/operator label
// and the integrity-appropriate causal edge for the attack story.
func selfTamperKindMapping(kind uint8) (string, string) {
	switch kind {
	case SelfGuardKindPinMissing:
		return "pin_missing", EdgeFileModified
	case SelfGuardKindPinReplaced:
		return "pin_replaced", EdgeFileModified
	case SelfGuardKindCanaryDead:
		return "canary_dead", EdgeRootCause
	case SelfGuardKindBpffsUnavailable:
		return "bpffs_unavailable", EdgeFileModified
	case SelfGuardKindPinRestored:
		return "pin_restored", EdgeRootCause
	case SelfGuardKindCanaryRecovered:
		return "canary_recovered", EdgeRootCause
	default:
		return "unknown_tamper", EdgeRootCause
	}
}

// boundedSelfTamperFact copies a fact into its wire/metadata bounds. The wire
// parser already rejects longer details; this is defense in depth for the
// watchdog-created facts that never pass through that parser.
func boundedSelfTamperFact(fact selfTamperFact) selfTamperFact {
	fact.kind = strings.TrimSpace(fact.kind)
	if fact.kind == "" {
		fact.kind = "unknown_tamper"
	}
	if len(fact.kind) > 32 {
		fact.kind = fact.kind[:32]
	}
	fact.detail = strings.TrimSpace(fact.detail)
	if len(fact.detail) > selfGuardDetailMaxBytes {
		fact.detail = fact.detail[:selfGuardDetailMaxBytes]
	}
	if len(fact.counter) > 32 {
		fact.counter = fact.counter[:32]
	}
	if fact.edge == "" {
		fact.edge = EdgeRootCause
	}
	return fact
}

// recordSelfTamperFact is the single evidence-first sink for self-protection
// facts: evidence is committed before the incident exists, and an evidence
// failure is carried into the incident outcome. It never issues a response.
func (e *XDREngine) recordSelfTamperFact(fact selfTamperFact, now time.Time) {
	if e == nil || e.state == nil {
		return
	}
	fact = boundedSelfTamperFact(fact)
	summary, target := selfTamperSummary(fact)
	evidence := EvidenceRecord{
		Severity: "critical",
		Kind:     "xdr.self_tamper",
		Source:   "integrity",
		Message:  "Self-protection fact recorded before any response: " + summary,
		Target:   target,
		Time:     now,
	}
	evidenceErr := e.state.RecordEvidence(evidence)
	incident := buildSelfTamperIncident(fact, evidenceErr, now)
	e.appendIncident(incident)
	e.state.AddEvent(Event{
		Time: now, Severity: "critical", Kind: "xdr.self_tamper", Source: "integrity",
		Message: incident.Summary + "; " + incident.Outcome, Target: target,
	})
}

// selfTamperSummary renders the bounded operator summary and evidence target.
// Neither ever contains a filesystem path from the kernel.
func selfTamperSummary(fact selfTamperFact) (string, string) {
	summary := fmt.Sprintf("Sensor self-protection integrity failure: %s (detail_code=%d)", fact.kind, fact.detailCode)
	if fact.counter != "" {
		summary = fmt.Sprintf("%s counter=%s delta=%d", summary, fact.counter, fact.delta)
	} else if fact.detail != "" {
		summary = fmt.Sprintf("%s detail=%s", summary, fact.detail)
	}
	target := fmt.Sprintf("self-guard:%s:code:%d", fact.kind, fact.detailCode)
	if fact.counter != "" {
		target = fmt.Sprintf("self-guard:%s:counter:%s", fact.kind, fact.counter)
	}
	if len(summary) > 240 {
		summary = summary[:240]
	}
	if len(target) > 120 {
		target = target[:120]
	}
	return summary, target
}

// buildSelfTamperIncident is pure apart from ID minting: it maps a normalized
// fact (and the evidence-commit error, if any) to the observe-only incident with
// one bounded attack-story node. No lineage exists for a sensor-integrity fact,
// but the node carries a chain root so consumers can attach later evidence.
func buildSelfTamperIncident(fact selfTamperFact, evidenceErr error, now time.Time) XDRIncident {
	fact = boundedSelfTamperFact(fact)
	summary, target := selfTamperSummary(fact)
	metadata := map[string]string{
		"kind":                 fact.kind,
		"detail_code":          strconv.FormatUint(uint64(fact.detailCode), 10),
		"sbc_family":           selfGuardSBCFamily,
		"has_lineage_or_chain": "true",
		"target":               target,
	}
	if fact.detail != "" {
		metadata["detail"] = fact.detail
	}
	if fact.tsMS != 0 {
		metadata["ts_ms"] = strconv.FormatUint(fact.tsMS, 10)
	}
	if fact.counter != "" {
		metadata["ring_counter"] = fact.counter
		metadata["delta"] = strconv.FormatUint(fact.delta, 10)
	}
	node := AttackStoryNode{
		NodeID:     "selfguard-" + randomID(),
		Timestamp:  now,
		Sensor:     "self-guard",
		Category:   "integrity",
		EventType:  strings.ToUpper(fact.kind),
		EntityID:   "sensor:self-guard",
		Actor:      "sensor",
		Severity:   "critical",
		Confidence: 90,
		CausalEdge: fact.edge,
		EventUUID:  randomID(),
		Metadata:   metadata,
	}
	node.Digest = node.ComputeNodeDigest()
	outcome := "sensor integrity degraded; observer-only, no active response issued"
	if evidenceErr != nil {
		// Not swallowed: the incident's own outcome states the evidence gap, and
		// the response stays disabled because the forensics are incomplete.
		outcome = "sensor integrity degraded; mandatory evidence commit failed, incident recorded without response: " + boundedStyxText(evidenceErr)
	}
	return XDRIncident{
		ID: randomID(), Time: now, Severity: "critical", Score: 200,
		RuleIDs:          []string{selfGuardRuleID},
		Categories:       []string{"integrity"},
		Summary:          summary,
		Decision:         "degrade",
		Action:           "none",
		Outcome:          outcome,
		ExecutionChainID: node.NodeID,
		EvidenceRoot:     node.Digest,
		AttackStory:      []AttackStoryNode{node},
	}
}

// selfGuardDropSample is one monotone telemetry-loss counter read from state the
// engine already sampled. Enforcement counters (StyX policy drops) are
// deliberately excluded: they count intended blocks, not lost telemetry.
type selfGuardDropSample struct {
	name  string
	value uint64
}

// watchSelfGuardRingDrops reports a monotone delta of a telemetry-loss counter
// as SBC-EVID-08 self-tamper evidence. Rate limit: one incident per counter per
// five minutes. A counter that went backwards is treated as a sensor restart
// (new baseline), never as a negative delta.
func (e *XDREngine) watchSelfGuardRingDrops(includeIngress bool, now time.Time) {
	if e == nil {
		return
	}
	var samples [5]selfGuardDropSample
	sampleCount := 0
	e.credMu.Lock()
	samples[sampleCount] = selfGuardDropSample{name: "cred_guard_drops", value: e.credStatus.Drops}
	e.credMu.Unlock()
	sampleCount++
	e.styxFlowMu.Lock()
	samples[sampleCount] = selfGuardDropSample{name: "styx_ring_drops", value: e.styxFlowHealth.RingDrops}
	sampleCount++
	samples[sampleCount] = selfGuardDropSample{name: "styx_agg_insert_failures", value: e.styxFlowHealth.AggInsertFailures}
	sampleCount++
	samples[sampleCount] = selfGuardDropSample{name: "styx_parse_errors", value: e.styxFlowHealth.ParseErrors}
	sampleCount++
	e.styxFlowMu.Unlock()
	if includeIngress && e.core != nil {
		if health, err := e.core.IngressHealth(); err == nil {
			samples[sampleCount] = selfGuardDropSample{name: "ingress_ring_drops", value: health.RingDrops}
			sampleCount++
		}
	}

	var pending [5]selfGuardDropSample
	pendingCount := 0
	e.selfGuardMu.Lock()
	if e.selfGuardDropBaselines == nil {
		e.selfGuardDropBaselines = make(map[string]uint64, sampleCount)
	}
	if e.selfGuardSeen == nil {
		e.selfGuardSeen = make(map[string]time.Time)
	}
	for index := 0; index < sampleCount; index++ {
		sample := samples[index]
		baseline := e.selfGuardDropBaselines[sample.name]
		if sample.value < baseline {
			// Sensor/core restart: rebase instead of reporting a negative delta.
			e.selfGuardDropBaselines[sample.name] = sample.value
			continue
		}
		delta := sample.value - baseline
		if delta == 0 {
			continue
		}
		e.selfGuardDropBaselines[sample.name] = sample.value
		rateKey := "drop:" + sample.name
		if until, exists := e.selfGuardSeen[rateKey]; exists && now.Before(until) {
			continue
		}
		e.selfGuardSeen[rateKey] = now.Add(selfGuardDropRateLimit)
		if pendingCount < len(pending) {
			pending[pendingCount] = selfGuardDropSample{name: sample.name, value: delta}
			pendingCount++
		}
	}
	e.pruneSelfGuardSeenLocked(now)
	e.selfGuardMu.Unlock()

	for index := 0; index < pendingCount; index++ {
		fact := pending[index]
		e.recordSelfTamperFact(selfTamperFact{
			kind:       "ring_drop",
			detailCode: 0,
			detail:     fact.name,
			tsMS:       uint64(now.UnixMilli()),
			edge:       EdgeRootCause,
			counter:    fact.name,
			delta:      fact.value,
		}, now)
	}
}
