package main

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"time"
)

// observeEgressLocked adds the outbound delta of one flow record to its entity
// window and refreshes both ingress-attribution indices.
func (p *StyxPhase2Engine) observeEgressLocked(event CoreStyxFlowEvent, address netip.Addr, now time.Time) {
	p.txEvents = saturatingAdd(p.txEvents, 1)
	key := styxPhase2EntityKey{cgroupID: event.CgroupID, pid: event.PID, remote: address, port: event.DstPort}
	entity := p.entityLocked(key, now)
	bucket := entity.bucketLocked(styxPhase2Minute(now))
	bucket.tx = saturatingAdd(bucket.tx, event.TxBytes)
	bucket.txSamples = styxSaturatingAdd32(bucket.txSamples, 1)
	entity.lastSeen = now
	entity.txTotal = saturatingAdd(entity.txTotal, event.TxBytes)
	if entity.uid == 0 && event.UID != 0 {
		entity.uid = event.UID
	}
	entity.family = event.Family
	entity.proto = event.Proto
	if entity.comm == "" {
		entity.comm = sanitizeBeaconComm(event.Comm)
	}
	if _, exists := p.firstSeen[address]; !exists {
		p.recordFirstSeenLocked(address, now)
	}
	p.indexEntityLocked(key, event)
}

// observeIngressLocked attributes the inbound delta of one record to the egress
// entity it answers. A record that cannot be attributed is counted
// (`rxUnattributed`) and NEVER folded into some other entity's rx: the PCR rule
// requires a matched sample, so missing attribution can only soften a finding,
// never create one.
func (p *StyxPhase2Engine) observeIngressLocked(event CoreStyxFlowEvent, address netip.Addr, now time.Time) {
	p.ingressEvents = saturatingAdd(p.ingressEvents, 1)
	entity, ok := p.attributeIngressLocked(event, address)
	if !ok {
		p.rxUnattributed = saturatingAdd(p.rxUnattributed, 1)
		return
	}
	bucket := entity.bucketLocked(styxPhase2Minute(now))
	bucket.rx = saturatingAdd(bucket.rx, event.RxBytes)
	bucket.rxSamples = styxSaturatingAdd32(bucket.rxSamples, 1)
	entity.lastSeen = now
	entity.rxTotal = saturatingAdd(entity.rxTotal, event.RxBytes)
	p.rxAttributed = saturatingAdd(p.rxAttributed, 1)
	if _, exists := p.firstSeen[address]; !exists {
		p.recordFirstSeenLocked(address, now)
	}
}

// attributeIngressLocked resolves an inbound record to its egress entity:
// first by the receiving socket's cgroup + remote tuple, then (when the ingress
// cgroup is unavailable, e.g. no cgroup-v2 socket data) by the exact reverse
// 5-tuple of an observed egress flow.
func (p *StyxPhase2Engine) attributeIngressLocked(event CoreStyxFlowEvent, address netip.Addr) (*styxPhase2Entity, bool) {
	if event.CgroupID != 0 {
		rxKey := styxPhase2RxKey{cgroupID: event.CgroupID, remote: address, port: event.DstPort}
		if owner, ok := p.rxIndex[rxKey]; ok {
			if entity := p.entities[owner]; entity != nil {
				return entity, true
			}
			delete(p.rxIndex, rxKey)
		}
	}
	endpointKey := styxPhase2EndpointKey{
		remote: address, remotePort: event.DstPort, localPort: event.SrcPort, proto: event.Proto,
	}
	if owner, ok := p.endpoints[endpointKey]; ok {
		if entity := p.entities[owner]; entity != nil {
			return entity, true
		}
		delete(p.endpoints, endpointKey)
	}
	return nil, false
}

// indexEntityLocked refreshes the bounded attribution indices for one entity.
func (p *StyxPhase2Engine) indexEntityLocked(key styxPhase2EntityKey, event CoreStyxFlowEvent) {
	rxKey := styxPhase2RxKey{cgroupID: key.cgroupID, remote: key.remote, port: key.port}
	if _, exists := p.rxIndex[rxKey]; exists || len(p.rxIndex) < styxPhase2MaxEntities {
		p.rxIndex[rxKey] = key
	}
	endpointKey := styxPhase2EndpointKey{
		remote: key.remote, remotePort: key.port, localPort: event.SrcPort, proto: event.Proto,
	}
	if _, exists := p.endpoints[endpointKey]; exists || len(p.endpoints) < styxPhase2MaxEntities {
		p.endpoints[endpointKey] = key
	}
}

// entityLocked returns the entity for `key`, creating it with bounded eviction.
func (p *StyxPhase2Engine) entityLocked(key styxPhase2EntityKey, now time.Time) *styxPhase2Entity {
	if entity := p.entities[key]; entity != nil {
		return entity
	}
	if len(p.entities) >= styxPhase2MaxEntities {
		p.evictOldestEntityLocked()
	}
	entity := &styxPhase2Entity{key: key, firstSeen: now, lastSeen: now}
	p.entities[key] = entity
	return entity
}

// evictOldestEntityLocked drops the least recently active entity (the bounded
// stop of the window map). Derived indices still pointing at it are removed by
// the next prune or by the existence check on lookup.
func (p *StyxPhase2Engine) evictOldestEntityLocked() {
	var victimKey styxPhase2EntityKey
	var victim *styxPhase2Entity
	for key, entity := range p.entities {
		if victim == nil || entity.lastSeen.Before(victim.lastSeen) {
			victimKey, victim = key, entity
		}
	}
	if victim != nil {
		delete(p.entities, victimKey)
		p.evictions = saturatingAdd(p.evictions, 1)
	}
}

// recordFirstSeenLocked records a new remote in the bounded First-Seen set. When
// the set is full the oldest entry is dropped; a First-Seen fact is therefore a
// bounded observation, not an unbounded history.
func (p *StyxPhase2Engine) recordFirstSeenLocked(address netip.Addr, now time.Time) {
	if _, exists := p.firstSeen[address]; exists {
		return
	}
	if len(p.firstSeen) >= styxPhase2MaxFirstSeen {
		var oldestAddr netip.Addr
		var oldest time.Time
		for candidate, seen := range p.firstSeen {
			if oldest.IsZero() || seen.Before(oldest) {
				oldestAddr, oldest = candidate, seen
			}
		}
		delete(p.firstSeen, oldestAddr)
	}
	p.firstSeen[address] = now
}

// bucketLocked returns the one-minute bucket for `minute`, resetting the ring
// slot when it belongs to an older minute (bounded window, no slice growth).
func (entity *styxPhase2Entity) bucketLocked(minute int64) *styxPhase2Bucket {
	index := minute % styxPhase2Buckets
	if index < 0 {
		index += styxPhase2Buckets
	}
	bucket := &entity.buckets[index]
	if bucket.minute != minute {
		*bucket = styxPhase2Bucket{minute: minute}
	}
	return bucket
}

// windowLocked sums the five-minute window (the current minute plus the four
// previous ones) with saturating arithmetic.
func (entity *styxPhase2Entity) windowLocked(minute int64) (tx, rx uint64, txSamples, rxSamples uint32) {
	for index := range entity.buckets {
		bucket := &entity.buckets[index]
		if bucket.minute < minute-(styxPhase2Buckets-1) || bucket.minute > minute {
			continue
		}
		tx = saturatingAdd(tx, bucket.tx)
		rx = saturatingAdd(rx, bucket.rx)
		txSamples = styxSaturatingAdd32(txSamples, bucket.txSamples)
		rxSamples = styxSaturatingAdd32(rxSamples, bucket.rxSamples)
	}
	return tx, rx, txSamples, rxSamples
}

// pruneLocked ages out stale entities, stale attribution indices and expired
// dedupe fingerprints. Called on every engine poll, so all maps stay bounded.
func (p *StyxPhase2Engine) pruneLocked(now time.Time) {
	cutoff := now.Add(-styxPhase2Window)
	minute := styxPhase2Minute(now)
	for key, entity := range p.entities {
		if entity.lastSeen.Before(cutoff) {
			delete(p.entities, key)
			continue
		}
		for index := range entity.buckets {
			if entity.buckets[index].minute < minute-(styxPhase2Buckets-1) {
				entity.buckets[index] = styxPhase2Bucket{}
			}
		}
	}
	for key, owner := range p.rxIndex {
		entity := p.entities[owner]
		if entity == nil || entity.lastSeen.Before(cutoff) || !key.remote.IsValid() {
			delete(p.rxIndex, key)
		}
	}
	for key, owner := range p.endpoints {
		entity := p.entities[owner]
		if entity == nil || entity.lastSeen.Before(cutoff) || !key.remote.IsValid() {
			delete(p.endpoints, key)
		}
	}
	for fingerprint, until := range p.dedupe {
		if !now.Before(until) {
			delete(p.dedupe, fingerprint)
		}
	}
}

// evaluatePCR prunes the windows and emits the bounded evidence incidents of
// this cycle. The rule is exactly documented in the module header; there is no
// path that turns a tx-only entity into a PCR claim.
func (p *StyxPhase2Engine) evaluatePCR(now time.Time) []XDRIncident {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	p.pruneLocked(now)
	minute := styxPhase2Minute(now)
	incidents := make([]XDRIncident, 0, 4)
	for _, entity := range p.entities {
		if len(incidents) >= styxPhase2MaxIncidentsPerPoll {
			break
		}
		tx, rx, txSamples, rxSamples := entity.windowLocked(minute)
		windowBytes := saturatingAdd(tx, rx)
		if windowBytes < styxPhase2MinWindowBytes || txSamples == 0 {
			continue
		}
		// A PCR statement needs observed inbound bytes for this entity. rxSamples
		// > 0 only happens when an ingress FlowEvent was attributed to the entity;
		// an unattributed/absent RX flow is never scored as rx=0.
		if !p.rxObservationAvailable || rxSamples == 0 {
			continue
		}
		firstSeenAt, seen := p.firstSeen[entity.key.remote]
		if !seen || now.Sub(firstSeenAt) > styxPhase2FirstSeenTTL || now.Before(firstSeenAt) {
			continue
		}
		if !styxPhase2PCROverThreshold(tx, rx) {
			continue
		}
		p.pcrCandidates = saturatingAdd(p.pcrCandidates, 1)
		if !p.claimIncidentLocked(entity.key, now) {
			continue
		}
		pcr := styxPhase2PCRValue(tx, rx)
		incident := styxPhase2BuildIncident(entity, tx, rx, txSamples, rxSamples, pcr, firstSeenAt, now, p.sessions)
		p.pcrIncidents = saturatingAdd(p.pcrIncidents, 1)
		incidents = append(incidents, incident)
	}
	return incidents
}

// claimIncidentLocked deduplicates one entity's evidence for 30 minutes and
// bounds the dedupe map.
func (p *StyxPhase2Engine) claimIncidentLocked(key styxPhase2EntityKey, now time.Time) bool {
	fingerprint := fmt.Sprintf("styx-pcr:%d:%d:%s:%d", key.cgroupID, key.pid, key.remote.String(), key.port)
	if until, exists := p.dedupe[fingerprint]; exists && now.Before(until) {
		p.suppressed = saturatingAdd(p.suppressed, 1)
		return false
	}
	if len(p.dedupe) >= styxPhase2MaxEntities {
		p.suppressed = saturatingAdd(p.suppressed, 1)
		return false
	}
	p.dedupe[fingerprint] = now.Add(styxPhase2DedupeTTL)
	return true
}

// styxPhase2PCROverThreshold reports the exact integer form of PCR > +0.60:
// (tx-rx)/(tx+rx) > 0.6  <=>  2*tx > 8*rx  <=>  tx > 4*rx. Equality (the
// boundary tx == 4*rx, PCR == 0.60) does not fire. The overflow guard keeps the
// multiplication safe for maximal counter values.
func styxPhase2PCROverThreshold(tx, rx uint64) bool {
	if tx <= rx {
		return false
	}
	if rx > math.MaxUint64/4 {
		return false
	}
	return tx > 4*rx
}

// styxPhase2PCRValue renders the ratio for reports/metadata with saturation-safe
// inputs. The wire counters are bounded window sums; a maximal pair is clamped
// into the representation instead of producing NaN/Inf.
func styxPhase2PCRValue(tx, rx uint64) float64 {
	total := saturatingAdd(tx, rx)
	if total == 0 {
		return 0
	}
	value := (float64(tx) - float64(rx)) / float64(total)
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}

// correlationQualityLocked is the honest quality ladder: OBSERVED needs an
// attached RX observer AND a matched inbound sample; TEMPORAL is a
// session-inactive timing statement only; otherwise NONE.
func (p *StyxPhase2Engine) correlationQualityLocked(rxSamples uint32) string {
	if p.rxObservationAvailable && rxSamples > 0 {
		return "OBSERVED"
	}
	if p.sessions.IdleHint == "inactive" {
		return "TEMPORAL"
	}
	return "NONE"
}

// styxPhase2BuildIncident renders the evidence-first, observe-only incident.
func styxPhase2BuildIncident(entity *styxPhase2Entity, tx, rx uint64, txSamples, rxSamples uint32, pcr float64, firstSeenAt, now time.Time, sessions StyxSessionSummary) XDRIncident {
	remote := netip.AddrPortFrom(entity.key.remote, entity.key.port).String()
	process := entity.comm
	if process == "" {
		process = "unknown"
	}
	actor := fmt.Sprintf("PID:%d|%s", entity.key.pid, process)
	idleHint := sessions.IdleHint
	if idleHint == "" {
		idleHint = "unavailable"
	}
	incidentID := fmt.Sprintf("INC-STYX-PHASE2-%d-%d", now.UnixNano(), styxPhase2Score)
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("node-styx-phase2-%d", now.UnixNano()),
		Timestamp:  now,
		Sensor:     styxPhase2SensorName,
		Category:   "c2",
		EventType:  styxPhase2EventTypes,
		EntityID:   remote,
		Actor:      actor,
		Severity:   styxPhase2Severity,
		Confidence: 85,
		CausalEdge: EdgeEgressAttempted,
		EventUUID:  incidentID,
		Metadata: map[string]string{
			"rule":                styxPhase2RulePCRExfil,
			"target_ip":           entity.key.remote.String(),
			"dst_port":            strconv.FormatUint(uint64(entity.key.port), 10),
			"cgroup_id":           strconv.FormatUint(entity.key.cgroupID, 10),
			"pid":                 strconv.Itoa(entity.key.pid),
			"pcr":                 strconv.FormatFloat(pcr, 'f', 3, 64),
			"tx_bytes":            strconv.FormatUint(tx, 10),
			"rx_bytes":            strconv.FormatUint(rx, 10),
			"window_seconds":      strconv.Itoa(int(styxPhase2Window / time.Second)),
			"window_bytes":        strconv.FormatUint(saturatingAdd(tx, rx), 10),
			"tx_samples":          strconv.FormatUint(uint64(txSamples), 10),
			"rx_samples":          strconv.FormatUint(uint64(rxSamples), 10),
			"first_seen":          firstSeenAt.UTC().Format(time.RFC3339),
			"correlation_quality": "OBSERVED",
			"rx_observation":      "available",
			"idlehint":            idleHint,
			"idlehint_source":     "logind-session-files (logind IdleHint D-Bus property is not readable; no lock state is claimed)",
			"sessions":            fmt.Sprintf("%d/%d/%d", sessions.Total, sessions.Active, sessions.Inactive),
			"remote_addressing":   "ip-literal",
			"dns_attribution":     "unavailable",
			"observe_only":        "true",
		},
	}
	evidenceRoot := node.ComputeNodeDigest()
	summary := fmt.Sprintf(
		"StyX phase-2 PCR exfiltration evidence: pid=%d comm=%s remote=%s pcr=%.3f tx=%d rx=%d window=%d samples=%d rx_samples=%d first_seen=%s correlation_quality=OBSERVED idlehint=%s sessions=%d/%d/%d rule=%s",
		entity.key.pid, process, remote, pcr, tx, rx, saturatingAdd(tx, rx), txSamples, rxSamples,
		firstSeenAt.UTC().Format(time.RFC3339), idleHint, sessions.Total, sessions.Active, sessions.Inactive,
		styxPhase2RulePCRExfil)
	return XDRIncident{
		ID:            incidentID,
		Time:          now,
		Severity:      styxPhase2Severity,
		Score:         styxPhase2Score,
		ResponseScore: styxPhase2Score,
		PID:           entity.key.pid,
		UID:           entity.uid,
		CellCgroupID:  entity.key.cgroupID,
		SocketFamily:  int32(entity.family),
		Process:       process,
		Remote:        remote,
		Summary:       summary,
		RuleIDs:       []string{styxPhase2RulePCRExfil},
		Categories:    []string{"network", "c2"},
		Decision:      "alert",
		Action:        "none",
		Outcome:       "recorded by the StyX phase-2 PCR detector; observe-only, no active response and no containment were derived",
		EvidenceRoot:  evidenceRoot,
		AttackStory:   []AttackStoryNode{node},
	}
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// styxPhase2Minute converts a timestamp to its Unix-minute bucket index.
func styxPhase2Minute(t time.Time) int64 {
	return t.Unix() / int64(styxPhase2BucketDuration/time.Second)
}

// styxSaturatingAdd32 is the uint32 counterpart of saturatingAdd.
func styxSaturatingAdd32(left, right uint32) uint32 {
	if sum := left + right; sum >= left {
		return sum
	}
	return math.MaxUint32
}
