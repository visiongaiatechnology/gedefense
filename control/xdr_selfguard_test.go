// STATUS: V6.3.0 AP-0
package main

// V6.3.0 AP-0 regression tests: polling cadence/arming, evidence-first
// observe-only SELF_TAMPER incidents, dedupe by (ts, kind, detail_code), the
// ring-drop watchdog with its per-counter rate limit and the capability-fact
// handling of a core that does not advertise the SELF_GUARD_* family.

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSelfGuardCore serves synthetic VGT3 answers without a socket. It models
// the core's queue semantics: a drain empties what was enqueued.
type fakeSelfGuardCore struct {
	mu          sync.Mutex
	status      CoreSelfGuardStatus
	statusErr   error
	events      []CoreSelfTamperEvent
	dropped     uint64
	drainErr    error
	setCalls    []bool
	setErr      error
	statusCalls int
	drainCalls  int
}

func (f *fakeSelfGuardCore) SelfGuardSet(enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls = append(f.setCalls, enabled)
	return f.setErr
}

func (f *fakeSelfGuardCore) SelfGuardStatus() (CoreSelfGuardStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusCalls++
	return f.status, f.statusErr
}

func (f *fakeSelfGuardCore) SelfTamperEvents() ([]CoreSelfTamperEvent, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drainCalls++
	if f.drainErr != nil {
		return nil, 0, f.drainErr
	}
	events := f.events
	dropped := f.dropped
	f.events = nil
	f.dropped = 0
	return events, dropped, nil
}

func (f *fakeSelfGuardCore) enqueue(events ...CoreSelfTamperEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, events...)
}

func (f *fakeSelfGuardCore) calls() (statusCalls, drainCalls int, sets []bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statusCalls, f.drainCalls, append([]bool(nil), f.setCalls...)
}

func newSelfGuardTestEngine(fake *fakeSelfGuardCore) *XDREngine {
	return &XDREngine{
		state:                  NewState("test", defaultConfig()),
		correlator:             NewIncidentCorrelator(0),
		dedupe:                 map[string]time.Time{},
		degradeCauses:          map[string]string{},
		forensicFailures:       map[string]int{},
		selfGuardCore:          fake,
		selfGuardSeen:          map[string]time.Time{},
		selfGuardDropBaselines: map[string]uint64{},
	}
}

func selfGuardIncidents(engine *XDREngine) []XDRIncident {
	var found []XDRIncident
	for _, incident := range engine.state.Snapshot().Incidents {
		if containsString(incident.RuleIDs, selfGuardRuleID) {
			found = append(found, incident)
		}
	}
	return found
}

func enabledSelfGuardStatus() CoreSelfGuardStatus {
	return CoreSelfGuardStatus{
		Enabled: true, Armed: true, PinsAvailable: true, PinsExpected: 12,
		CanaryState: "active", CanaryRuns: 1, Events: 0,
	}
}

// unarmedSelfGuardStatus models an available, disarmed core; polling it once
// must arm it exactly once.
func unarmedSelfGuardStatus() CoreSelfGuardStatus {
	status := enabledSelfGuardStatus()
	status.Enabled = false
	status.Armed = false
	return status
}

func syntheticSelfTamper(ts uint64) CoreSelfTamperEvent {
	return CoreSelfTamperEvent{TsMS: ts, Kind: SelfGuardKindPinMissing, DetailCode: 1, Detail: "EXEC_EVENTS"}
}

func TestSelfGuardPollArmsOnceAndDrains(t *testing.T) {
	fake := &fakeSelfGuardCore{status: unarmedSelfGuardStatus()}
	engine := newSelfGuardTestEngine(fake)
	fake.enqueue(syntheticSelfTamper(1_700_000_000_000))
	runtime := RuntimeSettings{XDREnabled: true}
	now := time.Now().UTC()

	next := engine.pollSelfGuard(runtime, now, time.Time{})
	if !next.Equal(now.Add(time.Second)) {
		t.Fatalf("drain cadence is %v, want 1s", next.Sub(now))
	}
	statusCalls, drainCalls, sets := fake.calls()
	if statusCalls != 1 || drainCalls != 1 {
		t.Fatalf("first poll did %d status / %d drain calls", statusCalls, drainCalls)
	}
	if len(sets) != 1 || !sets[0] {
		t.Fatalf("self-guard was not armed once: %v", sets)
	}
	if incidents := selfGuardIncidents(engine); len(incidents) != 1 {
		t.Fatalf("expected one self-tamper incident, got %d", len(incidents))
	}

	// The next second only drains; it must not re-arm and must not duplicate.
	engine.pollSelfGuard(runtime, now.Add(time.Second), next)
	statusCalls, drainCalls, sets = fake.calls()
	if statusCalls != 1 || drainCalls != 2 {
		t.Fatalf("second poll did %d status / %d drain calls", statusCalls, drainCalls)
	}
	if len(sets) != 1 {
		t.Fatalf("self-guard was armed %d times", len(sets))
	}
	// Ten seconds later the status is sampled again, still without re-arming.
	engine.pollSelfGuard(runtime, now.Add(11*time.Second), now.Add(10*time.Second))
	statusCalls, _, sets = fake.calls()
	if statusCalls != 2 {
		t.Fatalf("status cadence is wrong: %d calls", statusCalls)
	}
	if len(sets) != 1 {
		t.Fatalf("self-guard was armed again after the status refresh: %v", sets)
	}
}

func TestSelfGuardAlreadyEnabledDoesNotReArm(t *testing.T) {
	fake := &fakeSelfGuardCore{status: CoreSelfGuardStatus{Enabled: true, Armed: true}}
	engine := newSelfGuardTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	now := time.Now().UTC()
	engine.pollSelfGuard(runtime, now, time.Time{})
	engine.pollSelfGuard(runtime, now.Add(11*time.Second), now.Add(time.Second))
	_, _, sets := fake.calls()
	if len(sets) != 0 {
		t.Fatalf("an already armed core was armed again: %v", sets)
	}
}

func TestSelfGuardIncidentIsEvidenceFirstObserveOnly(t *testing.T) {
	fake := &fakeSelfGuardCore{status: enabledSelfGuardStatus()}
	engine := newSelfGuardTestEngine(fake)
	fake.enqueue(syntheticSelfTamper(1_700_000_000_000))
	now := time.Now().UTC()
	engine.pollSelfGuard(RuntimeSettings{XDREnabled: true}, now, time.Time{})

	incidents := selfGuardIncidents(engine)
	if len(incidents) != 1 {
		t.Fatalf("expected one self-tamper incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Severity != "critical" {
		t.Fatalf("severity is %q", incident.Severity)
	}
	if incident.Decision != "degrade" || incident.Action != "none" {
		t.Fatalf("self-tamper derived a response: decision=%q action=%q", incident.Decision, incident.Action)
	}
	if incident.KillSignals != 0 || incident.ResponseScore != 0 {
		t.Fatalf("self-tamper incident carries kill/response signals: %+v", incident)
	}
	if !containsString(incident.Categories, "integrity") {
		t.Fatalf("categories are %v", incident.Categories)
	}
	if !strings.Contains(incident.Outcome, "no active response") {
		t.Fatalf("outcome does not state the observe-only decision: %q", incident.Outcome)
	}
	if len(incident.AttackStory) != 1 {
		t.Fatalf("attack story has %d nodes", len(incident.AttackStory))
	}
	node := incident.AttackStory[0]
	if node.Sensor != "self-guard" || node.Category != "integrity" || node.CausalEdge != EdgeFileModified {
		t.Fatalf("attack-story node is wrong: %+v", node)
	}
	if node.Metadata["sbc_family"] != "SBC-EVID-08" || node.Metadata["has_lineage_or_chain"] != "true" {
		t.Fatalf("attack-story metadata is incomplete: %v", node.Metadata)
	}
	if node.Metadata["kind"] != "pin_missing" || node.Metadata["detail"] != "EXEC_EVENTS" {
		t.Fatalf("attack-story fact metadata is wrong: %v", node.Metadata)
	}
	if incident.ExecutionChainID != node.NodeID || incident.EvidenceRoot != node.Digest {
		t.Fatalf("incident is not rooted in the attack-story node: %+v", incident)
	}
	// The evidence-first path must also surface the fact on the event stream.
	foundEvent := false
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == "xdr.self_tamper" {
			foundEvent = true
		}
	}
	if !foundEvent {
		t.Fatal("self-tamper fact did not reach the event stream")
	}
}

func TestSelfGuardEvidenceFailureIsReflectedInIncidentOutcome(t *testing.T) {
	now := time.Now().UTC()
	fact := selfTamperFact{kind: "pin_missing", detailCode: 1, detail: "EXEC_EVENTS", tsMS: 1_700_000_000_000, edge: EdgeFileModified}
	incident := buildSelfTamperIncident(fact, errors.New("evidence ledger unavailable"), now)
	if !strings.Contains(incident.Outcome, "evidence commit failed") {
		t.Fatalf("evidence failure was swallowed: %q", incident.Outcome)
	}
	if incident.Action != "none" || incident.Decision != "degrade" {
		t.Fatalf("evidence failure changed the response: %+v", incident)
	}
	if !containsString(incident.RuleIDs, selfGuardRuleID) {
		t.Fatalf("rule ids lost: %v", incident.RuleIDs)
	}
	clean := buildSelfTamperIncident(fact, nil, now)
	if strings.Contains(clean.Outcome, "evidence commit failed") {
		t.Fatalf("healthy incident claims an evidence gap: %q", clean.Outcome)
	}
}

func TestSelfGuardDedupeUsesTimestampKindAndDetailCode(t *testing.T) {
	fake := &fakeSelfGuardCore{status: enabledSelfGuardStatus()}
	engine := newSelfGuardTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	now := time.Now().UTC()
	fake.enqueue(syntheticSelfTamper(1_700_000_000_000), syntheticSelfTamper(1_700_000_000_000))
	engine.pollSelfGuard(runtime, now, time.Time{})
	if incidents := selfGuardIncidents(engine); len(incidents) != 1 {
		t.Fatalf("duplicate record created %d incidents", len(incidents))
	}
	// A different timestamp is a different record.
	fake.enqueue(syntheticSelfTamper(1_700_000_000_001))
	engine.pollSelfGuard(runtime, now.Add(time.Second), now.Add(time.Second))
	if incidents := selfGuardIncidents(engine); len(incidents) != 2 {
		t.Fatalf("distinct record was suppressed: %d incidents", len(incidents))
	}
	// A different kind/code at the same timestamp is also distinct.
	replaced := syntheticSelfTamper(1_700_000_000_001)
	replaced.Kind = SelfGuardKindPinReplaced
	replaced.DetailCode = 2
	fake.enqueue(replaced)
	engine.pollSelfGuard(runtime, now.Add(2*time.Second), now.Add(2*time.Second))
	if incidents := selfGuardIncidents(engine); len(incidents) != 3 {
		t.Fatalf("distinct kind/code was suppressed: %d incidents", len(incidents))
	}
}

func TestSelfGuardRingDropWatchdogRateLimitedPerCounter(t *testing.T) {
	fake := &fakeSelfGuardCore{status: enabledSelfGuardStatus()}
	engine := newSelfGuardTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	now := time.Now().UTC()

	// A counter that already reports drops at first sample is not silently
	// rebased: the first observation of a non-zero process-lifetime counter is
	// the delta from zero.
	engine.credMu.Lock()
	engine.credStatus = CoreCredGuardStatus{Drops: 5}
	engine.credMu.Unlock()
	next := engine.pollSelfGuard(runtime, now, time.Time{})
	if incidents := selfGuardIncidents(engine); len(incidents) != 1 {
		t.Fatalf("initial drop delta did not produce one incident: %d", len(incidents))
	}
	incident := selfGuardIncidents(engine)[0]
	node := incident.AttackStory[0]
	if node.Metadata["ring_counter"] != "cred_guard_drops" || node.Metadata["delta"] != "5" {
		t.Fatalf("drop incident metadata is wrong: %v", node.Metadata)
	}

	// No delta: no incident.
	engine.pollSelfGuard(runtime, now.Add(time.Second), next)
	// A new delta inside the 5 minute window is rate-limited per counter.
	engine.credMu.Lock()
	engine.credStatus.Drops = 8
	engine.credMu.Unlock()
	next = engine.pollSelfGuard(runtime, now.Add(2*time.Second), now.Add(time.Second))
	if incidents := selfGuardIncidents(engine); len(incidents) != 1 {
		t.Fatalf("rate-limited drop created %d incidents", len(incidents))
	}
	// Outside the window the counter reports again.
	engine.credMu.Lock()
	engine.credStatus.Drops = 9
	engine.credMu.Unlock()
	engine.pollSelfGuard(runtime, now.Add(6*time.Minute), next)
	if incidents := selfGuardIncidents(engine); len(incidents) != 2 {
		t.Fatalf("drop after the rate-limit window did not report: %d incidents", len(incidents))
	}
}

func TestSelfGuardStyxRingDropAndQueuedOverflowReport(t *testing.T) {
	fake := &fakeSelfGuardCore{status: enabledSelfGuardStatus()}
	engine := newSelfGuardTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	now := time.Now().UTC()
	engine.styxFlowMu.Lock()
	engine.styxFlowHealth = CoreStyxFlowHealth{RingDrops: 3, DropsTotal: 100, PolicyDrops: 100}
	engine.styxFlowMu.Unlock()
	engine.pollSelfGuard(runtime, now, time.Time{})
	incidents := selfGuardIncidents(engine)
	if len(incidents) != 1 {
		t.Fatalf("styx ring drop produced %d incidents", len(incidents))
	}
	node := incidents[0].AttackStory[0]
	if node.Metadata["ring_counter"] != "styx_ring_drops" || node.Metadata["delta"] != "3" {
		t.Fatalf("styx drop metadata is wrong: %v", node.Metadata)
	}
	// Intentional StyX enforcement drops (DropsTotal/PolicyDrops) must never be
	// classified as lost telemetry.
	engine.pollSelfGuard(runtime, now.Add(time.Second), now.Add(time.Second))
	if got := len(selfGuardIncidents(engine)); got != 1 {
		t.Fatalf("policy drops were classified as self-tamper: %d incidents", got)
	}

	// A queue-overflow delta on the self-tamper queue becomes evidence once and
	// is rate-limited afterwards.
	fake.mu.Lock()
	fake.dropped = 4
	fake.mu.Unlock()
	next := engine.pollSelfGuard(runtime, now.Add(2*time.Second), now.Add(2*time.Second))
	if got := len(selfGuardIncidents(engine)); got != 2 {
		t.Fatalf("queue overflow produced %d incidents", got)
	}
	fake.mu.Lock()
	fake.dropped = 2
	fake.mu.Unlock()
	engine.pollSelfGuard(runtime, now.Add(3*time.Second), next)
	if got := len(selfGuardIncidents(engine)); got != 2 {
		t.Fatalf("repeated queue overflow was not rate-limited: %d incidents", got)
	}
}

func TestSelfGuardCapabilityUnavailableIsFactNotDegradation(t *testing.T) {
	fake := &fakeSelfGuardCore{statusErr: ErrSelfGuardUnavailable}
	engine := newSelfGuardTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	now := time.Now().UTC()
	next := engine.pollSelfGuard(runtime, now, time.Time{})
	if !next.Equal(now.Add(10 * time.Second)) {
		t.Fatalf("capability backoff is %v, want 10s", next.Sub(now))
	}
	if incidents := selfGuardIncidents(engine); len(incidents) != 0 {
		t.Fatalf("missing capability created %d incidents", len(incidents))
	}
	if _, drainCalls, sets := fake.calls(); drainCalls != 0 || len(sets) != 0 {
		t.Fatalf("missing capability still drained/armed: drain=%d arm=%v", drainCalls, sets)
	}

	// Capability loss after a successful sample is an info transition, not an
	// incident.
	fake2 := &fakeSelfGuardCore{status: enabledSelfGuardStatus()}
	engine2 := newSelfGuardTestEngine(fake2)
	engine2.pollSelfGuard(runtime, now, time.Time{})
	fake2.mu.Lock()
	fake2.statusErr = ErrSelfGuardUnavailable
	fake2.mu.Unlock()
	engine2.pollSelfGuard(runtime, now.Add(11*time.Second), now.Add(time.Second))
	if incidents := selfGuardIncidents(engine2); len(incidents) != 0 {
		t.Fatalf("capability loss created %d incidents", len(incidents))
	}
	found := false
	for _, event := range engine2.state.Snapshot().Events {
		if event.Kind == "xdr.self_guard_capability_missing" {
			found = true
		}
	}
	if !found {
		t.Fatal("capability loss was not reported as an info event")
	}
}

func TestPollSelfGuardDisabledDoesNothing(t *testing.T) {
	fake := &fakeSelfGuardCore{status: enabledSelfGuardStatus()}
	engine := newSelfGuardTestEngine(fake)
	now := time.Now().UTC()
	retryAfter := now.Add(30 * time.Second)
	next := engine.pollSelfGuard(RuntimeSettings{XDREnabled: false}, now, retryAfter)
	if !next.Equal(retryAfter) {
		t.Fatalf("disabled XDR changed the retry deadline: %v", next)
	}
	if statusCalls, drainCalls, sets := fake.calls(); statusCalls != 0 || drainCalls != 0 || len(sets) != 0 {
		t.Fatalf("disabled XDR touched the core: status=%d drain=%d arm=%v", statusCalls, drainCalls, sets)
	}
}

func TestSelfGuardKindMappingIsClosed(t *testing.T) {
	expected := map[uint8]string{
		SelfGuardKindPinMissing:       "pin_missing",
		SelfGuardKindPinReplaced:      "pin_replaced",
		SelfGuardKindCanaryDead:       "canary_dead",
		SelfGuardKindBpffsUnavailable: "bpffs_unavailable",
		SelfGuardKindPinRestored:      "pin_restored",
		SelfGuardKindCanaryRecovered:  "canary_recovered",
	}
	for kind, label := range expected {
		got, edge := selfTamperKindMapping(kind)
		if got != label {
			t.Fatalf("kind %d mapped to %q", kind, got)
		}
		if edge == "" {
			t.Fatalf("kind %d has no causal edge", kind)
		}
	}
	if got, _ := selfTamperKindMapping(0); got != "unknown_tamper" {
		t.Fatalf("unknown kind mapped to %q", got)
	}
}
