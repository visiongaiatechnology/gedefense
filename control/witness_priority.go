// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (S08/S15): immediate, prioritised out-of-band witness push for
// evidence-category self-tamper findings.
//
// The XDR engine calls pushCriticalWitness for every incident *before* the local
// forensic log record is written, and the finding's evidence record was already
// committed to the authenticated ledger by the evidence-first rule. A push binds a
// signed checkpoint of the ledger head that already covers that evidence, so a
// local log truncation a moment later cannot erase the only copy. The hook is
// bounded and never blocks the ingest path. Residual: S08/S15 are ROBUST only when
// the witness namespace is enabled (docs/V6.3.0-RBAC.md).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	// witnessPriorityQueueCapacity bounds the hand-off queue; overflow is counted
	// and reported, never turned into unbounded memory.
	witnessPriorityQueueCapacity = 64
	// witnessPriorityDedupeCapacity/TTL bound the duplicate suppression table.
	witnessPriorityDedupeCapacity = 4096
	witnessPriorityDedupeTTL      = time.Hour
	// witnessPriorityEventCooldown bounds how often one condition is reported.
	witnessPriorityEventCooldown = 5 * time.Minute
	// witnessPriorityMaxRuleIDs/Categories bound the copied slices.
	witnessPriorityMaxRuleIDs      = 8
	witnessPriorityMaxCategories   = 8
	witnessPriorityRequestTimeout  = 6 * time.Second
	witnessPriorityMaxReportedText = 200
)

// criticalWitnessEvidenceRules is the rule-id half of the SBC-EVID-08 trigger set.
// Severity alone is deliberately not a trigger: a critical network finding is not
// an evidence-integrity finding.
var criticalWitnessEvidenceRules = map[string]struct{}{
	"XDR.SELF_TAMPER":        {},
	"XDR.SELF_ARTIFACT":      {},
	"WITNESS.EQUIVOCATION":   {},
	"BASELINE.HASH_MISMATCH": {},
}

// criticalWitnessEvidenceCategories is the category half. A bare "ransomware",
// "impact" or "sensor-health" category is not pushed; those reach the witness only
// through the GIEF evidence family, so a burst of them cannot become witness
// traffic.
var criticalWitnessEvidenceCategories = map[string]struct{}{
	"integrity":        {},
	"self-tamper":      {},
	"evidence":         {},
	"witness":          {},
	"worker-integrity": {},
}

// criticalWitnessSink is the injection point of the priority push.
type criticalWitnessSink interface {
	pushCriticalWitness(incident XDRIncident)
}

// criticalWitnessSinks late-binds the sink to one engine (XDREngine has no witness field in this edit scope).
var criticalWitnessSinks sync.Map // *XDREngine -> criticalWitnessSink

// criticalWitnessRecord is the bounded fact a push retains; the witness checkpoint
// itself carries only hashes and counters.
type criticalWitnessRecord struct {
	ID           string
	RecordHash   string
	EvidenceRoot string
	RuleIDs      []string
	Categories   []string
	Severity     string
	ObservedAt   time.Time
	EnqueuedAt   time.Time
}

// pushCriticalWitness is the appendIncident seam: it runs synchronously before the
// forensic log append and hands an eligible finding to the bounded pusher.
func (e *XDREngine) pushCriticalWitness(incident XDRIncident) {
	if e == nil {
		return
	}
	// The hook sits on the ingest path; a defect here must never fail XDR.
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("witness priority hook isolated a panic type=%T", recovered)
		}
	}()
	if !criticalWitnessTrigger(incident) {
		return
	}
	sink, _ := criticalWitnessSinks.Load(e)
	if sink != nil {
		if typed, ok := sink.(criticalWitnessSink); ok {
			typed.pushCriticalWitness(incident)
			return
		}
	}
	criticalWitnessPusherFor(e).pushCriticalWitness(incident)
}

// criticalWitnessTrigger is the SBC-EVID-08/self-tamper predicate.
func criticalWitnessTrigger(incident XDRIncident) bool {
	if incident.GIEF != nil && strings.TrimSpace(incident.GIEF.SBCFamily) == SBCFamilyEvidence {
		return true
	}
	for _, ruleID := range incident.RuleIDs {
		if _, ok := criticalWitnessEvidenceRules[strings.TrimSpace(ruleID)]; ok {
			return true
		}
	}
	for _, category := range incident.Categories {
		if _, ok := criticalWitnessEvidenceCategories[strings.ToLower(strings.TrimSpace(category))]; ok {
			return true
		}
	}
	return false
}

// criticalWitnessPusherFor returns the engine's single pusher, creating it lazily.
func criticalWitnessPusherFor(e *XDREngine) *criticalWitnessPusher {
	if existing, ok := criticalWitnessSinks.Load(e); ok {
		if typed, ok := existing.(*criticalWitnessPusher); ok {
			return typed
		}
	}
	created := newCriticalWitnessPusher(e)
	actual, _ := criticalWitnessSinks.LoadOrStore(e, created)
	if typed, ok := actual.(*criticalWitnessPusher); ok {
		return typed
	}
	return created
}

// attachCriticalWitnessSinkForTest replaces the engine's sink for the ordering proof.
func attachCriticalWitnessSinkForTest(e *XDREngine, sink criticalWitnessSink) {
	if e == nil || sink == nil {
		return
	}
	criticalWitnessSinks.Store(e, sink)
}

// detachCriticalWitnessSinkForTest removes the sink and stops its worker.
func detachCriticalWitnessSinkForTest(e *XDREngine) {
	existing, ok := criticalWitnessSinks.LoadAndDelete(e)
	if !ok {
		return
	}
	if pusher, ok := existing.(*criticalWitnessPusher); ok {
		pusher.close()
	}
}

// criticalWitnessPusher owns the queue, the dedupe table and one delivery worker.
type criticalWitnessPusher struct {
	engine           *XDREngine
	now              func() time.Time
	transportFactory func(settings WitnessFabricSettings, now func() time.Time) (witnessTransport, error)
	queue            chan criticalWitnessRecord
	stop             chan struct{}

	mu              sync.Mutex
	started         bool
	closed          bool
	dedupe          map[string]time.Time
	dedupeOrder     []string
	lastDedupeScan  time.Time
	lastDelivered   time.Time
	lastFailure     time.Time
	lastDrop        time.Time
	lastUnavailable time.Time
	dropped         uint64
	delivered       uint64
	failed          uint64
}

func newCriticalWitnessPusher(engine *XDREngine) *criticalWitnessPusher {
	return &criticalWitnessPusher{
		engine: engine, now: func() time.Time { return time.Now().UTC() },
		transportFactory: newCriticalWitnessTransport,
		queue:            make(chan criticalWitnessRecord, witnessPriorityQueueCapacity),
		stop:             make(chan struct{}),
		dedupe:           make(map[string]time.Time),
	}
}

// pushCriticalWitness is the non-blocking hand-off; dedupe and queue are bounded.
func (p *criticalWitnessPusher) pushCriticalWitness(incident XDRIncident) {
	now := p.now()
	record := criticalWitnessRecordFromIncident(incident, now)
	key := criticalWitnessDedupeKey(record)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	if key != "" && !p.rememberLocked(key, now) {
		p.mu.Unlock()
		return
	}
	startWorker := !p.started
	if startWorker {
		p.started = true
	}
	p.mu.Unlock()
	if startWorker {
		go p.run()
	}
	select {
	case p.queue <- record:
	default:
		p.mu.Lock()
		p.dropped++
		p.mu.Unlock()
		p.reportOnce(&p.lastDrop, "xdr.witness_priority_dropped", "warning",
			"The bounded priority-witness queue is full; an evidence-category finding was not handed to the out-of-band witness")
	}
}

// run is the single delivery worker of one engine; close() cancels it.
func (p *criticalWitnessPusher) run() {
	for {
		select {
		case <-p.stop:
			return
		case record := <-p.queue:
			p.deliver(record)
		}
	}
}

// deliver makes one bounded push attempt and reports its outcome honestly.
func (p *criticalWitnessPusher) deliver(record criticalWitnessRecord) {
	defer func() {
		if recovered := recover(); recovered != nil {
			p.mu.Lock()
			p.failed++
			p.mu.Unlock()
			log.Printf("witness priority delivery isolated a panic type=%T", recovered)
		}
	}()
	if err := p.push(record); err != nil {
		if errors.Is(err, errWitnessDisabled) {
			// The capability is unavailable; push() already reported that fact once.
			// It is not a delivery failure of this finding.
			return
		}
		p.mu.Lock()
		p.failed++
		p.mu.Unlock()
		severity := "warning"
		reason := "the out-of-band witness did not acknowledge the priority checkpoint"
		if witnessAuthFailure(err) {
			reason = "the out-of-band witness rejected the priority checkpoint's authorization or pin"
		} else if witnessPermanent(err) {
			reason = "the out-of-band witness permanently rejected the priority checkpoint"
		}
		p.reportOnce(&p.lastFailure, "xdr.witness_priority_failed", severity,
			"Immediate out-of-band witness push for an evidence-category finding failed: "+reason)
		return
	}
	p.mu.Lock()
	p.delivered++
	report := p.delivered <= 1 || p.now().Sub(p.lastDelivered) >= time.Minute
	if report {
		p.lastDelivered = p.now()
	}
	p.mu.Unlock()
	if report {
		p.report("info", "xdr.witness_priority_delivered",
			"The out-of-band witness acknowledged a priority self-tamper/evidence checkpoint")
	}
}

// push sends one signed checkpoint of the current ledger head, which already
// covers the evidence record of the finding (the anti-truncation property).
func (p *criticalWitnessPusher) push(_ criticalWitnessRecord) error {
	settings := p.witnessSettings()
	if !witnessModeActive(settings) || settings.Mode != witnessModeHTTP {
		p.reportUnavailableOnce("the out-of-band witness namespace is disabled or not in http mode")
		return errWitnessDisabled
	}
	engine := p.engine
	if engine == nil {
		return errWitnessDisabled
	}
	var ledger *EvidenceLedger
	if engine.state != nil {
		ledger = engine.state.EvidenceLedger()
	}
	if ledger == nil {
		p.reportUnavailableOnce("no authenticated evidence ledger is attached")
		return errWitnessDisabled
	}
	view, err := ledger.Checkpoint()
	if err != nil {
		return &witnessClientError{reason: "the evidence ledger refused a checkpoint", permanent: true}
	}
	policy := defaultRuntimeSettings(engine.cfg)
	if engine.settings != nil {
		policy = engine.settings.Get()
	}
	policyDigest, err := PolicyDigest(policy)
	if err != nil {
		return &witnessClientError{reason: "the policy digest could not be computed", permanent: true}
	}
	checkpointID, err := NewWitnessCheckpointID()
	if err != nil {
		return &witnessClientError{reason: "the checkpoint id could not be generated", permanent: true}
	}
	postureDigest := BootPostureDigest(BootTrustReport{})
	checkpoint := WitnessCheckpoint{
		Schema: WitnessCheckpointSchema, Version: witnessCheckpointVersion,
		NodeID: witnessNodeID(engine.cfg.Node.Name), CheckpointID: checkpointID,
		CreatedAt:   p.now().UTC().Format(time.RFC3339),
		LedgerEpoch: view.LedgerEpoch, Sequence: view.Sequence, HeadHash: view.HeadHash,
		Records: view.Records, SigningKeyFP: view.PublicKeyFingerprint,
		BootPosture: "NOT_SUPPORTED", BootPostureDigest: postureDigest,
		QuoteKind: witnessQuoteKindNone, PolicyRevision: policy.Revision,
		PolicyDigest: policyDigest, SensorState: criticalWitnessSensorState(engine), Challenge: "",
	}
	transport, err := p.transportFactory(settings, p.now)
	if err != nil {
		return &witnessClientError{reason: "the witness transport could not be configured", permanent: true}
	}
	ctx, cancel := context.WithTimeout(context.Background(), witnessPriorityRequestTimeout)
	defer cancel()
	challenge, err := transport.Challenge(ctx)
	if err != nil {
		return err
	}
	// The challenge is part of the signed payload, so the checkpoint is signed
	// once, after the fresh single-use nonce is known.
	checkpoint.Challenge = challenge
	signed, err := SignWitnessCheckpoint(checkpoint, ledger.WitnessCheckpointSigner())
	if err != nil {
		return &witnessClientError{reason: "the checkpoint could not be signed", permanent: true}
	}
	if _, err := transport.Push(ctx, signed); err != nil {
		return err
	}
	return nil
}

// witnessSettings returns the current witness namespace of the engine.
func (p *criticalWitnessPusher) witnessSettings() WitnessFabricSettings {
	if p.engine != nil && p.engine.settings != nil {
		return effectiveWitnessSettings(p.engine.settings.Get())
	}
	return defaultWitnessFabricSettings()
}

// criticalWitnessSensorState maps the XDR sensor label onto the checkpoint enum,
// exactly like the periodic engine does. It never exports the label itself.
func criticalWitnessSensorState(engine *XDREngine) string {
	if engine == nil || engine.state == nil {
		return "offline"
	}
	label := strings.ToLower(strings.TrimSpace(engine.state.XDRSensorState()))
	switch {
	case label == "" || label == "initializing":
		return "offline"
	case strings.HasPrefix(label, "disabled"):
		return "disabled"
	case strings.Contains(label, "degraded"):
		return "degraded"
	default:
		return "online"
	}
}

// newCriticalWitnessTransport builds the hardened client with a retry-free priority profile.
func newCriticalWitnessTransport(settings WitnessFabricSettings, now func() time.Time) (witnessTransport, error) {
	priority := settings
	if priority.RequestTimeoutSeconds > int(witnessPriorityRequestTimeout/time.Second) {
		priority.RequestTimeoutSeconds = int(witnessPriorityRequestTimeout / time.Second)
	}
	priority.RetryAttempts = 0
	return newWitnessHTTPClient(witnessClientConfig{Settings: priority, Now: now})
}

// reportUnavailableOnce states the honest residual once per cooldown.
func (p *criticalWitnessPusher) reportUnavailableOnce(reason string) {
	if p.claimReport(&p.lastUnavailable) {
		p.report("warning", "xdr.witness_priority_unavailable",
			"Immediate out-of-band witness push is unavailable ("+reason+"); S08/S15 anti-truncation is not ROBUST until the witness is enabled")
	}
}

// claimReport is the single cooldown primitive of every priority event.
func (p *criticalWitnessPusher) claimReport(last *time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if !last.IsZero() && now.Sub(*last) < witnessPriorityEventCooldown {
		return false
	}
	*last = now
	return true
}

// reportOnce bounds one condition to one event per cooldown.
func (p *criticalWitnessPusher) reportOnce(last *time.Time, kind, severity, message string) {
	if p.claimReport(last) {
		p.report(severity, kind, message)
	}
}

// report writes one bounded event (never an incident, so it cannot re-enter the trigger).
func (p *criticalWitnessPusher) report(severity, kind, message string) {
	message = rbacBoundedText(message, witnessPriorityMaxReportedText)
	if p.engine != nil && p.engine.state != nil {
		p.engine.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "witness", Message: message})
		return
	}
	log.Printf("witness priority event kind=%q severity=%q message=%q", kind, severity, message)
}

// close stops the worker; production keeps it for the process lifetime.
func (p *criticalWitnessPusher) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()
	close(p.stop)
}

// rememberLocked records one dedupe key, bounded by eviction of the oldest.
func (p *criticalWitnessPusher) rememberLocked(key string, now time.Time) bool {
	if _, seen := p.dedupe[key]; seen {
		return false
	}
	if now.Sub(p.lastDedupeScan) > time.Minute {
		for remembered, at := range p.dedupe {
			if now.Sub(at) > witnessPriorityDedupeTTL {
				delete(p.dedupe, remembered)
			}
		}
		p.lastDedupeScan = now
	}
	for len(p.dedupe) >= witnessPriorityDedupeCapacity && len(p.dedupeOrder) > 0 {
		oldest := p.dedupeOrder[0]
		p.dedupeOrder = p.dedupeOrder[1:]
		delete(p.dedupe, oldest)
	}
	p.dedupe[key] = now
	p.dedupeOrder = append(p.dedupeOrder, key)
	return true
}

func criticalWitnessRecordFromIncident(incident XDRIncident, now time.Time) criticalWitnessRecord {
	return criticalWitnessRecord{
		ID: incident.ID, RecordHash: incident.RecordHash, EvidenceRoot: incident.EvidenceRoot,
		Severity: incident.Severity, ObservedAt: incident.Time.UTC(), EnqueuedAt: now,
		RuleIDs:    boundedWitnessCopy(incident.RuleIDs, witnessPriorityMaxRuleIDs, 96),
		Categories: boundedWitnessCopy(incident.Categories, witnessPriorityMaxCategories, 64),
	}
}

// boundedWitnessCopy copies at most limit entries, each bounded in bytes, so the
// queued record can never carry unbounded operator-visible text.
func boundedWitnessCopy(values []string, limit, maxBytes int) []string {
	if len(values) > limit {
		values = values[:limit]
	}
	copied := make([]string, 0, len(values))
	for _, value := range values {
		copied = append(copied, rbacBoundedText(value, maxBytes))
	}
	return copied
}

// criticalWitnessDedupeKey prefers the forensic record hash, then the incident id;
// only a finding with neither is hashed from its bounded content.
func criticalWitnessDedupeKey(record criticalWitnessRecord) string {
	if record.RecordHash != "" {
		return "rh:" + record.RecordHash
	}
	if record.ID != "" {
		return "id:" + record.ID
	}
	digest := sha256.Sum256([]byte(strings.Join(record.RuleIDs, ",") + "|" +
		strings.Join(record.Categories, ",") + "|" + record.EvidenceRoot + "|" +
		record.ObservedAt.UTC().Format(time.RFC3339Nano) + "|" + record.Severity))
	return "fp:" + hex.EncodeToString(digest[:16])
}
