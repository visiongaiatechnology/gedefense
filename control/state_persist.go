// STATUS: DIAMANT VGT SUPREME
// State persistence, rotation and restore paths, split out of state.go
// (refactoring wave 1b, structure-only).
package main

import (
	"errors"
	"log"
	"sort"
	"strings"
	"time"
)

func (s *State) AddBlock(target, reason, source string, ttl time.Duration, enforced bool, maxEntries int) (BlockEntry, error) {
	return s.AddBlockAt(target, reason, source, ttl, enforced, maxEntries, time.Now().UTC())
}

// AddBlockAt is the deterministic form used by response engines and tests. The
// supplied timestamp is part of the decision evidence and therefore also owns
// the TTL origin; callers that do not have an evidence timestamp use AddBlock.
func (s *State) AddBlockAt(target, reason, source string, ttl time.Duration, enforced bool, maxEntries int, now time.Time) (BlockEntry, error) {
	target, err := normalizeTarget(target)
	if err != nil {
		return BlockEntry{}, err
	}
	if len(reason) < 3 || len(reason) > 240 {
		return BlockEntry{}, errors.New("reason must contain 3-240 characters")
	}
	if now.IsZero() {
		now = time.Now()
	}
	// Compute the deadline before UTC() strips the monotonic reading: the wall-clock value
	// is what gets persisted, the monotonic value is what decides expiry in this process.
	deadline := now.Add(ttl)
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxEntries <= 0 {
		return BlockEntry{}, errors.New("blocklist capacity must be positive")
	}
	if old, ok := s.blocks[target]; ok {
		old.ExpiresAt = now.Add(ttl)
		old.Reason = reason
		old.Enforced = enforced
		s.blocks[target] = old
		s.blockDeadlines[target] = deadline
		return old, nil
	}
	if len(s.blocks) >= maxEntries {
		return BlockEntry{}, errors.New("blocklist capacity reached")
	}
	b := BlockEntry{ID: randomID(), Target: target, Reason: reason, Source: source, CreatedAt: now, ExpiresAt: now.Add(ttl), Enforced: enforced}
	s.blocks[target] = b
	s.blockDeadlines[target] = deadline
	return b, nil
}

// blockExpiryDeadline returns the monotonic deadline when the entry still carries one.
func (s *State) blockExpiryDeadline(target string, entry BlockEntry) time.Time {
	if deadline, ok := s.blockDeadlines[target]; ok && !deadline.IsZero() {
		return deadline
	}
	return entry.ExpiresAt
}

// blockExpired evaluates expiry against the monotonic reading when both sides carry one.
func blockExpired(deadline, wallNow, monoNow time.Time) bool {
	if deadline.Round(0) != deadline {
		return !deadline.After(monoNow)
	}
	return !deadline.After(wallNow)
}

func (s *State) BlockByID(id string) (BlockEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, block := range s.blocks {
		if block.ID == id {
			return block, true
		}
	}
	return BlockEntry{}, false
}

// BlockByTarget returns the current normalized block entry for a target. It is
// used by transactional response paths that must restore an existing manual or
// automatic rule exactly when a later kernel/policy step fails.
func (s *State) BlockByTarget(target string) (BlockEntry, bool) {
	normalized, err := normalizeTarget(target)
	if err != nil {
		return BlockEntry{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	block, ok := s.blocks[normalized]
	return block, ok
}

func (s *State) RemoveBlockByID(id string) (BlockEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for target, b := range s.blocks {
		if b.ID == id {
			delete(s.blocks, target)
			delete(s.blockDeadlines, target)
			return b, true
		}
	}
	return BlockEntry{}, false
}

func (s *State) Expired(now time.Time) []BlockEntry {
	monoNow := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []BlockEntry
	for k, b := range s.blocks {
		if blockExpired(s.blockExpiryDeadline(k, b), now, monoNow) {
			out = append(out, b)
			delete(s.blocks, k)
			delete(s.blockDeadlines, k)
		}
	}
	return out
}

func (s *State) SetBlockEnforced(target string, enforced bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	block, ok := s.blocks[target]
	if !ok {
		return false
	}
	block.Enforced = enforced
	s.blocks[target] = block
	return true
}

// RestoreIncidents seeds the incident list from the log on disk at startup.
//
// It is separate from AddIncident because the two answer different questions. AddIncident
// records something that has just happened: it counts it as a new incident, feeds the case
// engine, and increases the totals. A restored incident happened in an earlier life of this
// process and must not be counted again, or every restart would inflate the totals and
// re-open cases that were already handled.
func (s *State) RestoreIncidents(incidents []XDRIncident) {
	if len(incidents) == 0 {
		return
	}
	restored := make([]XDRIncident, 0, len(incidents))
	for _, incident := range incidents {
		if incident.ID == "" {
			continue
		}
		restored = append(restored, incident)
	}
	if len(restored) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := make(map[string]struct{}, len(s.incidents))
	for _, incident := range s.incidents {
		existing[incident.ID] = struct{}{}
	}
	for _, incident := range restored {
		if _, seen := existing[incident.ID]; seen {
			continue
		}
		s.incidents = append(s.incidents, incident)
	}
	if len(s.incidents) > s.incidentCap {
		s.incidents = append([]XDRIncident(nil), s.incidents[len(s.incidents)-s.incidentCap:]...)
	}
	// The totals are left alone deliberately. They report what this process has observed,
	// and the restored records are already counted in the log they came from.
}

// incidentFingerprint identifies repeated evidence: the same rule finding the same thing at the same
// place is one event with repetitions, not a new event every few seconds.
func incidentFingerprint(i XDRIncident) string {
	rule := ""
	if len(i.RuleIDs) > 0 {
		rule = i.RuleIDs[0]
	}
	return rule + "|" + i.Severity + "|" + i.Process + "|" + i.Remote + "|" + i.Summary
}

func (s *State) AddIncident(i XDRIncident) {
	// The incident list, the status API, the dashboard badge and the case engine consume
	// one vocabulary. Normalising here keeps a producer that emits the display form
	// ("CRITICAL") from leaking into the store, the dedupe fingerprint or the case gate.
	i.Severity = strings.ToLower(strings.TrimSpace(i.Severity))
	if i.ID == "" {
		i.ID = randomID()
	}
	if i.Time.IsZero() {
		i.Time = time.Now().UTC()
	}
	s.mu.Lock()
	// Repeated identical evidence must not become a flood of rows. Internet background scanners hit the
	// public web endpoint every few seconds with the same probe; without this, one rule produced 218 of
	// 250 incidents in the visible window and pushed every other finding out of sight.
	// Only re-ingested internet background noise is collapsed. An integrity finding is never suppressed:
	// a second modification of a protected object must be visible as a second incident, which is exactly
	// what TestOneReplacedProtectedObjectIsReportedOnce enforces.
	if len(i.RuleIDs) > 0 && strings.HasPrefix(i.RuleIDs[0], "L7.SCANNER") {
		if s.incidentDedupe == nil {
			s.incidentDedupe = make(map[string]time.Time, 256)
		}
		fingerprint := incidentFingerprint(i)
		now := time.Now().UTC()
		if last, seen := s.incidentDedupe[fingerprint]; seen && now.Sub(last) < 60*time.Second {
			s.incidentDedupe[fingerprint] = now
			s.mu.Unlock()
			return
		}
		if len(s.incidentDedupe) > 4096 {
			for key := range s.incidentDedupe {
				delete(s.incidentDedupe, key)
				if len(s.incidentDedupe) <= 2048 {
					break
				}
			}
		}
		s.incidentDedupe[fingerprint] = now
	}
	s.incidents = append(s.incidents, i)
	if len(s.incidents) > s.incidentCap {
		s.incidents = append([]XDRIncident(nil), s.incidents[len(s.incidents)-s.incidentCap:]...)
	}
	s.xdr.IncidentsTotal++
	if i.Action != "" && i.Action != "none" {
		s.xdr.ActionsTotal++
	}
	cases := s.cases
	s.mu.Unlock()
	if cases != nil {
		if err := cases.IngestIncident(i); err != nil {
			// A failed ingest is not an integrity finding: it is retried with the next incident,
			// which arrives within seconds. Degrading the platform on a single failure turned a
			// transient store hiccup into a five-minute pause of the automatic response.
			s.noteCaseHistoryFailure(err)
		} else {
			s.noteCaseHistorySuccess()
		}
	}
}

func (s *State) AcknowledgeIncident(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.incidents {
		if s.incidents[i].ID == id {
			s.incidents[i].Acknowledged = true
			return true
		}
	}
	return false
}

func (s *State) BlocksSnapshot() []BlockEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]BlockEntry, 0, len(s.blocks))
	for _, b := range s.blocks {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

func (s *State) RestoreBlock(b BlockEntry) {
	s.mu.Lock()
	s.blocks[b.Target] = b
	// A restored entry has no live monotonic origin; the persisted wall-clock deadline is
	// the only available authority.
	delete(s.blockDeadlines, b.Target)
	s.mu.Unlock()
}

func (s *State) ImportBlocks(blocks []BlockEntry, now time.Time, maxEntries int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, b := range blocks {
		if count >= maxEntries || blockExpired(b.ExpiresAt, now, time.Now()) {
			continue
		}
		normalized, err := normalizeTarget(b.Target)
		if err != nil || b.ID == "" {
			continue
		}
		b.Target = normalized
		s.blocks[normalized] = b
		delete(s.blockDeadlines, normalized)
		count++
	}
	return count
}

func (s *State) AddEvent(e Event) {
	if e.ID == "" {
		e.ID = randomID()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	_ = s.RecordEvidence(EvidenceRecord{
		ID: e.ID, Time: e.Time, Severity: e.Severity, Kind: e.Kind,
		Source: e.Source, Message: e.Message, Target: e.Target,
	})
	s.mu.Lock()
	s.events = append(s.events, e)
	if len(s.events) > s.eventCap {
		s.events = append([]Event(nil), s.events[len(s.events)-s.eventCap:]...)
	}
	subs := make([]chan Event, 0, len(s.subscribers))
	for ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- e:
		default:
		}
	}
}

func (s *State) AttachEvidenceLedger(ledger *EvidenceLedger) error {
	if ledger == nil {
		return errors.New("evidence ledger is required")
	}
	// The construction already verified the authenticated checkpoint and a bounded tail, and it
	// recorded any failure in the ledger. Re-walking the chain here doubled the startup cost for
	// no additional assurance: at 260 MB that second walk alone took minutes, and it was the
	// difference between a platform that starts and one that never becomes ready.
	if err := ledger.Healthy(); err != nil {
		return err
	}
	s.mu.Lock()
	s.evidence = ledger
	s.evidenceErr = nil
	s.evidenceStatus = ledger.Status()
	s.mu.Unlock()
	return nil
}

func (s *State) RecordEvidence(record EvidenceRecord) error {
	s.mu.RLock()
	ledger := s.evidence
	s.mu.RUnlock()
	if ledger == nil {
		return nil
	}
	_, err := ledger.Append(record)
	s.mu.Lock()
	var line string
	switch {
	case err == nil:
		s.evidenceErr = nil
		s.evidenceStatus = ledger.Status()
		line = s.clearXDRCauseLocked(xdrCauseEvidence)
	case errors.Is(err, errEvidenceBudgetExhausted):
		// A full ledger is a capacity condition. The chain is intact, the signatures are
		// valid and nothing is lost - the retention budget has simply been reached. It
		// must not be reported as an integrity failure, and it must not degrade XDR.
		s.evidenceErr = err
		s.evidenceStatus = ledger.Status()
		s.evidenceStatus.Full = true
		line = s.clearXDRCauseLocked(xdrCauseEvidence)
	default:
		s.evidenceErr = err
		s.evidenceStatus = ledger.Status()
		s.evidenceStatus.Healthy = false
		s.evidenceStatus.Error = "evidence integrity unavailable"
		line = s.markXDRCauseLocked(xdrCauseEvidence, "mandatory evidence ledger unavailable")
	}
	s.mu.Unlock()
	if line != "" {
		log.Print(line)
	}
	return err
}

func (s *State) EvidenceHealthy() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.evidenceErr
}

// EvidenceGateCondition reports why the evidence gate is closed, in terms precise
// enough to act on.
//
// Both conditions used to present the same public string, "mandatory evidence ledger
// unavailable", and the two have nothing in common operationally: a full ledger is
// cleared by raising its retention budget, a corrupt one is not cleared by anything the
// operator can do from the interface. Reporting them identically left an operator with
// every mutation refused and no indication that the remedy was a setting they own. The
// second return value is nil when the gate is open.
func (s *State) EvidenceGateCondition() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.evidenceErr == nil {
		return "", nil
	}
	if errors.Is(s.evidenceErr, errEvidenceBudgetExhausted) {
		return "evidence ledger retention budget reached", s.evidenceErr
	}
	return "mandatory evidence ledger unavailable", s.evidenceErr
}

// SetEvidenceStatus publishes a freshly verified ledger status without recording
// an event. It is used by the periodic verification loop so a healthy ledger
// keeps its status current and a tampered one flips to unhealthy immediately.
func (s *State) SetEvidenceStatus(status EvidenceStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evidenceStatus = status
}

func (s *State) EvidenceLedger() *EvidenceLedger {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.evidence
}
