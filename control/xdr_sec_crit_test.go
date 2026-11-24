// STATUS: V6.3.0 AP-9 (S12)
package main

// V6.3.0 AP-9 (S12) engine tests: arm-once/drain cadence, independent
// safety-net evidence (never a duplicate family incident), the
// XDR.SEC_CRIT_DIFFERENTIAL_GAP rule, the observe-only
// XDR.TELEMETRY_FLOOD_SUPPRESSION fact with its rate limit and severity ladder,
// the honest capability/degradation projection, and the report-only S12 quota
// review. Synthetic core answers only: no socket, no kernel.

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeSecCritCore struct {
	setCalls    []bool
	setErr      error
	status      CoreSecCritStatus
	statusErr   error
	events      []CoreSecCritEvent
	dropped     uint64
	eventsErr   error
	statusCalls int
	eventCalls  int
}

func (f *fakeSecCritCore) SecCritSet(enabled bool) error {
	f.setCalls = append(f.setCalls, enabled)
	if f.setErr != nil {
		return f.setErr
	}
	if enabled {
		f.status.Enabled = true
	}
	return nil
}

func (f *fakeSecCritCore) SecCritStatus() (CoreSecCritStatus, error) {
	f.statusCalls++
	if f.statusErr != nil {
		return CoreSecCritStatus{}, f.statusErr
	}
	return f.status, nil
}

func (f *fakeSecCritCore) SecCritEvents() ([]CoreSecCritEvent, uint64, error) {
	f.eventCalls++
	if f.eventsErr != nil {
		return nil, 0, f.eventsErr
	}
	return f.events, f.dropped, nil
}

func newSecCritTestEngine(fake secCritCore) *XDREngine {
	return &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		secCrit: NewSecCritEngine(), secCritCore: fake,
	}
}

// syntheticSecCritEvent builds a record that satisfies the documented kernel
// producer contract for the given source.
func syntheticSecCritEvent(source uint8, ts uint64, pid int, ino uint64) CoreSecCritEvent {
	event := CoreSecCritEvent{TsNS: ts, Source: source, Kind: 1, PID: pid, TGID: pid, UID: 1000, Ino: ino}
	switch source {
	case SecCritSourceCredGuard:
		event.Action = SecCritActionEnforce
		event.Dev = 8
		event.DetailCode = 0o100644
		event.Comm = "fake_sshd"
		event.Extra = "0000000000000000"
	case SecCritSourceBpfGuard:
		event.Action = SecCritActionObserve
		event.DetailCode = 5
		event.Comm = "rootkit"
		event.Extra = "0000000000000000"
	case SecCritSourceKernelHooks:
		event.Action = SecCritActionObserve
		event.Comm = "insmod"
		event.Extra = "0100000041626364"
	case SecCritSourcePersistence:
		event.Action = SecCritActionObserve
		event.Dev = 8
		event.DetailCode = 3<<8 | 2
		event.Comm = "libx.so"
		event.Extra = "2a00000000000000"
	default:
		event.Action = SecCritActionObserve
		event.Comm = "reserved"
		event.Extra = "0000000000000000"
	}
	return event
}

func secCritIncidentsWithRule(engine *XDREngine, ruleID string) []XDRIncident {
	var out []XDRIncident
	for _, incident := range engine.state.Snapshot().Incidents {
		if containsString(incident.RuleIDs, ruleID) {
			out = append(out, incident)
		}
	}
	return out
}

func secCritStateEventCount(engine *XDREngine, kind string) int {
	seen := 0
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == kind {
			seen++
		}
	}
	return seen
}

func TestSecCritEngineArmsOnceAndDrainsBoundedBatches(t *testing.T) {
	fake := &fakeSecCritCore{
		status: CoreSecCritStatus{Enabled: false, BucketCapacity: 4096},
		events: []CoreSecCritEvent{
			syntheticSecCritEvent(SecCritSourceCredGuard, 1700000000000000000, 4242, 123456),
			syntheticSecCritEvent(SecCritSourceBpfGuard, 1700000000000000001, 5150, 0),
		},
	}
	engine := newSecCritTestEngine(fake)
	// Dedicated families are healthy, so the safety-net records are plain
	// evidence (differential reporting is its own test).
	engine.credCapabilityKnown = true
	engine.credStatus.Armed = true
	engine.bpfGuardCapabilityKnown = true
	engine.bpfGuardStatus.Enabled = true
	runtime := RuntimeSettings{XDREnabled: true}
	t0 := time.Now().UTC()
	next := engine.pollSecCrit(runtime, t0, time.Time{})
	if len(fake.setCalls) != 1 || !fake.setCalls[0] {
		t.Fatalf("engine did not arm the observer once: %v", fake.setCalls)
	}
	if !next.Equal(t0.Add(secCritDrainInterval)) {
		t.Fatalf("poll returned %v, want %v drain cadence", next.Sub(t0), secCritDrainInterval)
	}
	if fake.statusCalls != 1 || fake.eventCalls != 1 {
		t.Fatalf("first poll calls status=%d events=%d", fake.statusCalls, fake.eventCalls)
	}
	// The records are independent evidence, never a duplicate family incident.
	if got := len(engine.state.Snapshot().Incidents); got != 0 {
		t.Fatalf("safety-net records created %d incidents", got)
	}
	if got := secCritStateEventCount(engine, "xdr.sec_crit_evidence"); got != 2 {
		t.Fatalf("safety-net evidence events = %d, want 2", got)
	}
	// A repeated drain of the same records must not duplicate evidence.
	engine.pollSecCrit(runtime, next, time.Time{})
	if got := secCritStateEventCount(engine, "xdr.sec_crit_evidence"); got != 2 {
		t.Fatalf("dedupe failed: evidence events = %d, want 2", got)
	}
	// After the 10 s status cadence the observer is already enabled: no re-arm.
	engine.pollSecCrit(runtime, t0.Add(11*time.Second), time.Time{})
	if len(fake.setCalls) != 1 {
		t.Fatalf("observer was armed more than once: %v", fake.setCalls)
	}
}

func TestSecCritEvidenceIsInfoOnlyAndObserveOnly(t *testing.T) {
	fake := &fakeSecCritCore{status: CoreSecCritStatus{Enabled: true, BucketCapacity: 4096}}
	engine := newSecCritTestEngine(fake)
	// Dedicated families are healthy: no differential claim.
	engine.credCapabilityKnown = true
	engine.credStatus.Armed = true
	engine.bpfGuardCapabilityKnown = true
	engine.bpfGuardStatus.Enabled = true
	engine.kernelHooksCapabilityKnown = true
	engine.kernelHooksStatus.Enabled = true
	engine.persistenceCapabilityKnown = true
	engine.persistenceStatus.Enabled = true
	now := time.Now().UTC()
	engine.consumeSecCritEvents([]CoreSecCritEvent{
		syntheticSecCritEvent(SecCritSourceCredGuard, 1700000000000000000, 4242, 123456),
		syntheticSecCritEvent(SecCritSourceKernelHooks, 1700000000000000001, 616, 0),
	}, 0, now)
	if got := len(engine.state.Snapshot().Incidents); got != 0 {
		t.Fatalf("critical records duplicated family incidents: %d", got)
	}
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == "xdr.sec_crit_evidence" && event.Severity != "info" {
			t.Fatalf("safety-net evidence severity is %q, want info", event.Severity)
		}
	}
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("healthy safety-net evidence degraded the engine: %s", reason)
	}
}

func TestSecCritDifferentialGapOnlyWhenFamilyUnavailable(t *testing.T) {
	fake := &fakeSecCritCore{status: CoreSecCritStatus{Enabled: true, BucketCapacity: 4096}}
	engine := newSecCritTestEngine(fake)
	now := time.Now().UTC()
	// The attach-time guard is not reported available: the safety-net record is
	// differential evidence.
	event := syntheticSecCritEvent(SecCritSourceBpfGuard, 1700000000000000000, 5150, 0)
	engine.consumeSecCritEvents([]CoreSecCritEvent{event}, 0, now)
	incidents := secCritIncidentsWithRule(engine, "XDR.SEC_CRIT_DIFFERENTIAL_GAP")
	if len(incidents) != 1 {
		t.Fatalf("differential-gap incidents = %d, want 1", len(incidents))
	}
	incident := incidents[0]
	if incident.Severity != "warning" || incident.Score != 60 || incident.Decision != "alert" ||
		incident.Action != "none" || incident.KillSignals != 0 || incident.ResponseScore != 0 {
		t.Fatalf("differential incident is not observe-only: %+v", incident)
	}
	if incident.Outcome == "" || incident.EvidenceRoot == "" || incident.ExecutionChainID == "" {
		t.Fatalf("differential incident lacks evidence/outcome: %+v", incident)
	}
	// Same record again is deduplicated; a new record per source is rate limited.
	engine.consumeSecCritEvents([]CoreSecCritEvent{event}, 0, now.Add(time.Second))
	engine.consumeSecCritEvents([]CoreSecCritEvent{
		syntheticSecCritEvent(SecCritSourceBpfGuard, 1700000000000000002, 5151, 0),
	}, 0, now.Add(2*time.Second))
	if got := len(secCritIncidentsWithRule(engine, "XDR.SEC_CRIT_DIFFERENTIAL_GAP")); got != 1 {
		t.Fatalf("differential rate limit failed: incidents = %d, want 1", got)
	}
	// Once the family reports active, a new record produces no differential.
	engine.bpfGuardCapabilityKnown = true
	engine.bpfGuardStatus.Enabled = true
	engine.consumeSecCritEvents([]CoreSecCritEvent{
		syntheticSecCritEvent(SecCritSourceBpfGuard, 1700000000000000003, 5152, 0),
	}, 0, now.Add(6*time.Minute))
	if got := len(secCritIncidentsWithRule(engine, "XDR.SEC_CRIT_DIFFERENTIAL_GAP")); got != 1 {
		t.Fatalf("healthy family still produced a differential: incidents = %d", got)
	}
	// A disarmed credential guard is reported with its concrete reason.
	engine.credCapabilityKnown = true
	engine.credStatus.Armed = false
	if reason, gap := engine.secCritFamilyState(SecCritSourceCredGuard); !gap || !strings.Contains(reason, "disarmed") {
		t.Fatalf("disarmed family not detected: gap=%t reason=%q", gap, reason)
	}
	engine.credStatus.Armed = true
	if _, gap := engine.secCritFamilyState(SecCritSourceCredGuard); gap {
		t.Fatal("active family wrongly reported as differential")
	}
}

func TestSecCritFloodSuppressionIsObserveOnlyAndRateLimited(t *testing.T) {
	fake := &fakeSecCritCore{status: CoreSecCritStatus{
		Enabled: true, Suppressed: 10, BucketCapacity: 4096,
	}}
	engine := newSecCritTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	t0 := time.Now().UTC()
	engine.pollSecCrit(runtime, t0, time.Time{})
	incidents := secCritIncidentsWithRule(engine, "XDR.TELEMETRY_FLOOD_SUPPRESSION")
	if len(incidents) != 1 {
		t.Fatalf("flood-suppression incidents = %d, want 1", len(incidents))
	}
	incident := incidents[0]
	if incident.Severity != "warning" || incident.Score != 75 || incident.Decision != "alert" ||
		incident.Action != "none" || incident.KillSignals != 0 || incident.ResponseScore != 0 {
		t.Fatalf("flood incident is not observe-only: %+v", incident)
	}
	if len(incident.AttackStory) != 1 || incident.AttackStory[0].Sensor != "kernel-sec-crit" ||
		incident.AttackStory[0].Metadata["observe_only"] != "true" {
		t.Fatalf("flood incident attack-story missing: %+v", incident.AttackStory)
	}
	if !strings.Contains(incident.Summary, "suppressions") || !strings.Contains(incident.Summary, "4096") {
		t.Fatalf("flood summary is not the bounded counter summary: %q", incident.Summary)
	}
	// Concrete capability degradation is reported (no silent fail-open).
	if degraded, reason := engine.degradedState(); !degraded || !strings.Contains(reason, "S12") {
		t.Fatalf("backpressure did not degrade the capability: degraded=%t reason=%q", degraded, reason)
	}
	// A second burst within five minutes stays at one incident.
	engine.pollSecCrit(runtime, t0.Add(11*time.Second), time.Time{})
	if got := len(secCritIncidentsWithRule(engine, "XDR.TELEMETRY_FLOOD_SUPPRESSION")); got != 1 {
		t.Fatalf("flood incident rate limit failed: %d incidents", got)
	}
	// Once critical evidence is at risk (ring drops) the severity is high.
	fake.status = CoreSecCritStatus{Enabled: true, Suppressed: 30, Drops: 2, BucketCapacity: 4096}
	engine.pollSecCrit(runtime, t0.Add(6*time.Minute), time.Time{})
	incidents = secCritIncidentsWithRule(engine, "XDR.TELEMETRY_FLOOD_SUPPRESSION")
	if len(incidents) != 2 {
		t.Fatalf("second flood incident not emitted after the rate limit: %d", len(incidents))
	}
	// The snapshot is newest-first: the critical-at-risk finding must exist and
	// stay observe-only with the high severity.
	highSeen := false
	for _, candidate := range incidents {
		if candidate.Severity == "high" {
			highSeen = true
			if candidate.Score != 75 || candidate.Action != "none" || candidate.Decision != "alert" ||
				candidate.KillSignals != 0 || candidate.ResponseScore != 0 {
				t.Fatalf("critical-at-risk flood incident is not observe-only: %+v", candidate)
			}
			if !strings.Contains(candidate.Summary, "critical evidence lost=yes") {
				t.Fatalf("critical-at-risk summary is not honest: %q", candidate.Summary)
			}
		}
	}
	if !highSeen {
		t.Fatalf("no high-severity critical-at-risk incident in %+v", incidents)
	}
}

func TestSecCritRingDropDrainIsImmediateAndHigh(t *testing.T) {
	fake := &fakeSecCritCore{
		status:  CoreSecCritStatus{Enabled: true, BucketCapacity: 4096},
		dropped: 2,
	}
	engine := newSecCritTestEngine(fake)
	engine.pollSecCrit(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	incidents := secCritIncidentsWithRule(engine, "XDR.TELEMETRY_FLOOD_SUPPRESSION")
	if len(incidents) != 1 {
		t.Fatalf("a drain-observed critical ring drop produced %d incidents, want 1", len(incidents))
	}
	if incidents[0].Severity != "high" || incidents[0].Action != "none" || incidents[0].Decision != "alert" {
		t.Fatalf("critical loss incident is not high/observe-only: %+v", incidents[0])
	}
	if degraded, reason := engine.degradedState(); !degraded || !strings.Contains(reason, "critical") {
		t.Fatalf("critical loss did not degrade the capability: %q", reason)
	}
}

func TestSecCritBackpressureRecoversHonestly(t *testing.T) {
	fake := &fakeSecCritCore{status: CoreSecCritStatus{
		Enabled: true, Suppressed: 4, BucketCapacity: 4096,
	}}
	engine := newSecCritTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	t0 := time.Now().UTC()
	engine.pollSecCrit(runtime, t0, time.Time{})
	if degraded, _ := engine.degradedState(); !degraded {
		t.Fatal("backpressure did not degrade the capability")
	}
	// No counter advance inside the pressure window: still degraded.
	engine.pollSecCrit(runtime, t0.Add(11*time.Second), time.Time{})
	if degraded, _ := engine.degradedState(); !degraded {
		t.Fatal("capability recovered inside the pressure window")
	}
	// Quiet for longer than the window: the cause clears, but history stays in
	// the report (monotonic counters are never hidden).
	engine.pollSecCrit(runtime, t0.Add(secCritPressureWindow+30*time.Second), time.Time{})
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("capability did not recover after the pressure window: %s", reason)
	}
	report := engine.SecCritReport()
	if report.State != "active" || report.Capability != "available" {
		t.Fatalf("recovered ring projected as %+v", report)
	}
	if report.Suppressed != 4 || !strings.Contains(report.Reason, "history") {
		t.Fatalf("recovered report hides the historical backpressure: %+v", report)
	}
}

func TestSecCritReportProjection(t *testing.T) {
	engine := newSecCritTestEngine(&fakeSecCritCore{})
	report := engine.SecCritReport()
	if report.State != "unavailable" || report.Capability != "unknown" {
		t.Fatalf("unknown capability projected as %+v", report)
	}
	if report.BucketAccounting != secCritBucketAccounting {
		t.Fatalf("bucket accounting label is %q, want %q", report.BucketAccounting, secCritBucketAccounting)
	}

	fake := &fakeSecCritCore{status: CoreSecCritStatus{
		Enabled: true, Events: 7, Drops: 0, RefusedUnarmed: 0, ReadFailures: 1,
		Suppressed: 0, BucketCapacity: 4096,
	}}
	engine = newSecCritTestEngine(fake)
	engine.pollSecCrit(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	report = engine.SecCritReport()
	if report.State != "active" || report.Capability != "available" || !report.Enabled {
		t.Fatalf("healthy ring projected as %+v", report)
	}
	if report.Events != 7 || report.BucketCapacity != 4096 || report.ReadFailures != 1 {
		t.Fatalf("report counters mismatch: %+v", report)
	}
	if report.SampledAt == nil {
		t.Fatal("healthy report lacks the sample timestamp")
	}

	// Capability missing: unavailable, never degraded (a capability fact).
	fake = &fakeSecCritCore{statusErr: ErrSecCritUnavailable, eventsErr: ErrSecCritUnavailable}
	engine = newSecCritTestEngine(fake)
	engine.pollSecCrit(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	report = engine.SecCritReport()
	if report.State != "unavailable" || report.Capability != "missing" {
		t.Fatalf("capability-missing ring projected as %+v", report)
	}
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("capability-missing degraded the engine: %s", reason)
	}

	// A drain failure is surfaced as degraded with the concrete reason.
	fake = &fakeSecCritCore{
		status:    CoreSecCritStatus{Enabled: true, BucketCapacity: 4096},
		eventsErr: errors.New("core IPC write failed"),
	}
	engine = newSecCritTestEngine(fake)
	engine.pollSecCrit(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	report = engine.SecCritReport()
	if report.State != "degraded" || !strings.Contains(report.Reason, "event drain failed") {
		t.Fatalf("drain failure projected as %+v", report)
	}

	// A failed arm request is reported honestly, not as a status failure.
	fake = &fakeSecCritCore{
		status: CoreSecCritStatus{Enabled: false, BucketCapacity: 4096},
		setErr: errors.New("arm denied"),
	}
	engine = newSecCritTestEngine(fake)
	engine.pollSecCrit(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	report = engine.SecCritReport()
	if report.State != "degraded" || !strings.Contains(report.Reason, "arm request failed") {
		t.Fatalf("arm failure projected as %+v", report)
	}
}

func TestSecCritPollRespectsRetryAndRuntimeGate(t *testing.T) {
	fake := &fakeSecCritCore{status: CoreSecCritStatus{Enabled: true, BucketCapacity: 4096}}
	engine := newSecCritTestEngine(fake)
	now := time.Now().UTC()
	retry := now.Add(30 * time.Second)
	if got := engine.pollSecCrit(RuntimeSettings{XDREnabled: false}, now, retry); !got.Equal(retry) {
		t.Fatalf("disabled runtime poll moved the retry time: %v", got)
	}
	if fake.statusCalls != 0 || fake.eventCalls != 0 {
		t.Fatal("disabled runtime still polled the core")
	}
	if got := engine.pollSecCrit(RuntimeSettings{XDREnabled: true}, now, retry); !got.Equal(retry) {
		t.Fatalf("early poll moved the retry time: %v", got)
	}
	if fake.statusCalls != 0 || fake.eventCalls != 0 {
		t.Fatal("early poll bypassed the retry window")
	}
}

func TestSecCritQuotaReportIsHonestAndReportOnly(t *testing.T) {
	engine := newSecCritTestEngine(&fakeSecCritCore{})
	// Parser cells: enabled with a configured limit, forced over the limit.
	manager := NewParserCellManager(ParserCellsConfig{}, nil, nil, nil, nil)
	manager.clientErr = nil
	manager.desired.Enabled = true
	manager.desired.MaxConcurrent = 2
	manager.active = 3
	engine.parserCells = manager
	// Review queue: not bound yet -> byte quota honestly unobservable.
	engine.reviewQueue = NewReviewQueue()
	// Quarantine: a real directory (statfs works) then a missing one.
	dir := t.TempDir()
	inspector, err := NewAirlockInspector(dir, 1<<20)
	if err != nil {
		t.Fatalf("airlock constructor: %v", err)
	}
	engine.airlock = inspector

	quotas := engine.SecCritQuotaReport()
	if quotas.Enforced {
		t.Fatal("report-only quotas claim enforcement")
	}
	if quotas.CellHelperConcurrencyLimit != 2 || quotas.CellHelperActive != 3 || quotas.CellHelperOK {
		t.Fatalf("parser cell quota not detected: %+v", quotas)
	}
	if quotas.ReviewQueueOK {
		t.Fatalf("unbound review queue claimed a byte quota: %+v", quotas)
	}
	if !quotas.QuarantineOK || quotas.QuarantineDir != dir || quotas.QuarantineFreeBytes == 0 {
		t.Fatalf("quarantine reserve check wrong: %+v", quotas)
	}
	if len(quotas.Degraded) == 0 || len(quotas.Degraded) > secCritQuotaReasonsShown {
		t.Fatalf("quota degraded reasons are not bounded: %+v", quotas.Degraded)
	}
	for _, reason := range quotas.Degraded {
		if len(reason) > secCritQuotaReasonBytes {
			t.Fatalf("quota reason is not bounded: %d bytes", len(reason))
		}
	}

	// Healthy parser cells and a loaded review queue report OK.
	manager.active = 1
	engine.reviewQueue.mu.Lock()
	engine.reviewQueue.loaded = true
	engine.reviewQueue.maxBytes = 1 << 20
	engine.reviewQueue.mu.Unlock()
	quotas = engine.SecCritQuotaReport()
	if !quotas.CellHelperOK || !quotas.ReviewQueueOK || quotas.CellHelperActive != 1 {
		t.Fatalf("healthy quotas projected degraded: %+v", quotas)
	}

	// A missing quarantine filesystem degrades only the quarantine fact.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove quarantine dir: %v", err)
	}
	quotas = engine.SecCritQuotaReport()
	if quotas.QuarantineOK || !strings.Contains(strings.Join(quotas.Degraded, "; "), "quarantine") {
		t.Fatalf("missing quarantine filesystem not reported: %+v", quotas)
	}
	// Report-only: the projection never touches the owning quota state.
	if !engine.reviewQueue.loaded {
		t.Fatal("quota projection mutated the review queue")
	}
}
