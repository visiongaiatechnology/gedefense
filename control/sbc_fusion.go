// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6: time-weighted SBC-01..08 entity graph.
//
// The engine corroborates findings per entity with an exponentially decayed
// score (default 30 min half-life, configurable between 15 and 60 minutes). It
// is evidence for the operator and metadata for the GIEF envelope; it never adds
// a kill-eligible category, never lowers the kill gate and never triggers an
// active response by itself. `combineMatches` (the kill gate) cannot reach it.
//
// Contract with the integration seam:
//   - `NewSBCFusionEngine()` (no arguments) is called from NewXDREngine,
//   - `attachGIEFEnvelope` calls `observeIncident` with the finding's family and
//     attaches the returned *prior* context (read before the current finding is
//     added) to the envelope,
//   - `SBCFusionReport()` is the bounded projection a future API can expose,
//   - `recordSBCCorroborations` is the evidence-first drain for fusion events.
//     It is deliberately NOT called from appendIncident: the envelope seam must
//     not write evidence, so the call belongs to a future API/poll seam (this is
//     an integration gap, not a hidden behaviour).

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// SBCFusionEngine holds the bounded, thread-safe entity graph.
type SBCFusionEngine struct {
	mu       sync.Mutex
	halfLife time.Duration
	entities map[string]*sbcEntity
	// clock is the default time source when a caller passes a zero time. It is
	// injectable in tests; production never changes it.
	clock func() time.Time

	observations        uint64
	evictions           uint64
	prunings            uint64
	corroborationEvents uint64
	droppedEvents       uint64
	events              []SBCCorroborationEvent
}

// NewSBCFusionEngine constructs the fusion engine with the documented 30 minute
// half-life. The constructor is parameterless by contract with the XDR seam.
func NewSBCFusionEngine() *SBCFusionEngine {
	return &SBCFusionEngine{
		halfLife: time.Duration(SBCDefaultHalfLifeMinutes) * time.Minute,
		entities: make(map[string]*sbcEntity, SBCCapacity),
		clock:    func() time.Time { return time.Now().UTC() },
	}
}

// clockTimeLocked returns the injected clock or wall time. Callers hold f.mu.
func (f *SBCFusionEngine) clockTimeLocked() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now().UTC()
}

// halfLifeMinutesLocked converts the configured half-life to minutes. Callers
// hold f.mu.
func (f *SBCFusionEngine) halfLifeMinutesLocked() float64 {
	if f.halfLife <= 0 {
		return float64(SBCDefaultHalfLifeMinutes)
	}
	return float64(f.halfLife) / float64(time.Minute)
}

// HalfLifeMinutes returns the configured decay half-life in minutes.
func (f *SBCFusionEngine) HalfLifeMinutes() float64 {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.halfLifeMinutesLocked()
}

// SetHalfLife clamps and installs a new decay half-life (15–60 minutes). It
// returns the value that is now active. It exists for future settings wiring; the
// seam constructor keeps the default.
func (f *SBCFusionEngine) SetHalfLife(halfLife time.Duration) time.Duration {
	if f == nil {
		return 0
	}
	minHalfLife := time.Duration(SBCMinHalfLifeMinutes) * time.Minute
	maxHalfLife := time.Duration(SBCMaxHalfLifeMinutes) * time.Minute
	if halfLife <= 0 {
		halfLife = time.Duration(SBCDefaultHalfLifeMinutes) * time.Minute
	}
	if halfLife < minHalfLife {
		halfLife = minHalfLife
	}
	if halfLife > maxHalfLife {
		halfLife = maxHalfLife
	}
	f.mu.Lock()
	f.halfLife = halfLife
	f.mu.Unlock()
	return halfLife
}

// observeIncident reads the entity's decayed context *before* adding the current
// finding, adds the finding, and returns the prior context (nil when the entity
// has no meaningful prior evidence). The returned slice is a copy: the caller may
// hold it inside the GIEF envelope without sharing engine state.
func (f *SBCFusionEngine) observeIncident(incident XDRIncident, family string, now time.Time) *SBCContext {
	if f == nil {
		return nil
	}
	family = sbcBoundedFamily(family)
	key := sbcEntityKey(incident)
	f.mu.Lock()
	defer f.mu.Unlock()
	if now.IsZero() {
		now = f.clockTimeLocked()
	}

	var context *SBCContext
	if entity, ok := f.entities[key]; ok {
		decayed := entity.decayedScore(now, f.halfLife)
		families := entity.decayedFamilies(now, f.halfLife)
		if len(families) > 0 || decayed >= sbcContextEpsilon {
			context = &SBCContext{
				Families:        append([]string(nil), families...),
				DecayedScore:    sbcRoundScore(decayed),
				HalfLifeMinutes: f.halfLifeMinutesLocked(),
				Corroborations:  len(families),
			}
		}
		// Cross-domain corroboration: earlier findings for the same entity came
		// from at least one other SBC family and still carry weight.
		if len(families) > 0 && decayed >= sbcCorroborationMinScore && sbcHasForeignFamily(families, family) {
			f.corroborationEvents++
			f.enqueueCorroborationLocked(SBCCorroborationEvent{
				Time:          now,
				Entity:        key,
				Family:        family,
				PriorFamilies: append([]string(nil), families...),
				PriorScore:    sbcRoundScore(decayed),
			})
		}
	}

	f.observations++
	if len(f.entities) >= SBCCapacity || f.observations%sbcPruneEvery == 0 {
		f.pruneLocked(now)
	}
	entity, ok := f.entities[key]
	if !ok {
		if len(f.entities) >= SBCCapacity {
			f.evictOneLocked(now)
		}
		entity = &sbcEntity{
			key:       key,
			families:  make(map[string]float64, sbcMaxFamiliesPerEntity),
			firstSeen: now,
			lastSeen:  now,
		}
		f.entities[key] = entity
	}
	entity.addObservation(family, sbcObservationWeight(incident.Severity), now, f.halfLife)
	return context
}

// sbcHasForeignFamily reports whether one of the decayed families differs from
// the current finding's family (cross-domain corroboration).
func sbcHasForeignFamily(families []string, current string) bool {
	for _, family := range families {
		if family != current {
			return true
		}
	}
	return false
}

// enqueueCorroborationLocked appends one event to the bounded queue. A full queue
// drops the oldest event and counts the drop; it never grows.
func (f *SBCFusionEngine) enqueueCorroborationLocked(event SBCCorroborationEvent) {
	if len(f.events) >= sbcEventQueueCap {
		copy(f.events, f.events[1:])
		f.events[len(f.events)-1] = event
		f.droppedEvents++
		return
	}
	f.events = append(f.events, event)
}

// DrainCorroborations returns the queued cross-domain corroboration events in
// observation order and empties the bounded queue.
func (f *SBCFusionEngine) DrainCorroborations() []SBCCorroborationEvent {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) == 0 {
		return nil
	}
	drained := append([]SBCCorroborationEvent(nil), f.events...)
	f.events = f.events[:0]
	return drained
}

// EntitySnapshot returns the decayed projection of one entity. It is a read-only
// projection used by the report and by tests; it never mutates the graph.
func (f *SBCFusionEngine) EntitySnapshot(key string, now time.Time) (SBCEntitySummary, bool) {
	if f == nil {
		return SBCEntitySummary{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	entity, ok := f.entities[key]
	if !ok {
		return SBCEntitySummary{}, false
	}
	if now.IsZero() {
		now = f.clockTimeLocked()
	}
	return SBCEntitySummary{
		Entity:       entity.key,
		Families:     entity.decayedFamilies(now, f.halfLife),
		DecayedScore: sbcRoundScore(entity.decayedScore(now, f.halfLife)),
		Observations: entity.observations,
		LastSeen:     entity.lastSeen,
	}, true
}

// Report returns the bounded read-only projection of the graph. Family lists and
// the top entity list are deterministically ordered.
func (f *SBCFusionEngine) Report(now time.Time, top int) SBCFusionReport {
	if f == nil {
		return SBCFusionReport{Version: SBCFusionVersion, State: "unavailable"}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if now.IsZero() {
		now = f.clockTimeLocked()
	}
	if top <= 0 || top > sbcReportTopEntities {
		top = sbcReportTopEntities
	}
	report := SBCFusionReport{
		Version:             SBCFusionVersion,
		State:               "active",
		HalfLifeMinutes:     f.halfLifeMinutesLocked(),
		Capacity:            SBCCapacity,
		Entities:            len(f.entities),
		Observations:        f.observations,
		Evictions:           f.evictions,
		Prunings:            f.prunings,
		CorroborationEvents: f.corroborationEvents,
		DroppedEvents:       f.droppedEvents,
		GeneratedAt:         now,
	}
	summaries := make([]SBCEntitySummary, 0, len(f.entities))
	for _, entity := range f.entities {
		summaries = append(summaries, SBCEntitySummary{
			Entity:       entity.key,
			Families:     entity.decayedFamilies(now, f.halfLife),
			DecayedScore: sbcRoundScore(entity.decayedScore(now, f.halfLife)),
			Observations: entity.observations,
			LastSeen:     entity.lastSeen,
		})
	}
	sort.Slice(summaries, func(left, right int) bool {
		if summaries[left].DecayedScore != summaries[right].DecayedScore {
			return summaries[left].DecayedScore > summaries[right].DecayedScore
		}
		if !summaries[left].LastSeen.Equal(summaries[right].LastSeen) {
			return summaries[left].LastSeen.After(summaries[right].LastSeen)
		}
		return summaries[left].Entity < summaries[right].Entity
	})
	if len(summaries) > top {
		summaries = summaries[:top]
	}
	report.Top = summaries
	return report
}

// SBCFusionReport is the bounded operator projection for future API wiring. It
// returns an honest unavailable state when the seam did not construct the engine.
func (e *XDREngine) SBCFusionReport() SBCFusionReport {
	unavailable := SBCFusionReport{
		Version:         SBCFusionVersion,
		State:           "unavailable",
		Capacity:        SBCCapacity,
		HalfLifeMinutes: float64(SBCDefaultHalfLifeMinutes),
	}
	if e == nil || e.sbc == nil {
		return unavailable
	}
	return e.sbc.Report(time.Now().UTC(), sbcReportTopEntities)
}

// recordSBCCorroborations drains the fusion's own cross-domain corroboration
// events and publishes them evidence-first: the mandatory evidence commit runs
// before the state event. A failed evidence commit is reported honestly in a
// state event of its own instead of being swallowed.
//
// This method is not called from appendIncident on purpose — the GIEF envelope
// seam must not write evidence. Wiring the call belongs to a future API/poll
// seam (documented integration gap in the AP-6 report).
func (e *XDREngine) recordSBCCorroborations(now time.Time) (int, error) {
	if e == nil || e.sbc == nil || e.state == nil {
		return 0, nil
	}
	events := e.sbc.DrainCorroborations()
	if len(events) == 0 {
		return 0, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	recorded := 0
	var firstErr error
	for _, event := range events {
		message := fmt.Sprintf(
			"SBC cross-domain corroboration (%s): entity %s observed again as %s after prior families %s (decayed score %.4f); fusion metadata only, the kill gate is untouched",
			SBCFusionVersion, event.Entity, event.Family, strings.Join(event.PriorFamilies, ","), event.PriorScore)
		message = boundedText(message, 512)
		target := boundedText(event.Entity, sbcEntityTextBytes)
		evidenceErr := e.state.RecordEvidence(EvidenceRecord{
			Severity: "info", Kind: "xdr.sbc_correlated", Source: "sbc-fusion",
			Message: "SBC fusion evidence recorded before the state event: " + message,
			Target:  target, Time: event.Time,
		})
		if evidenceErr != nil {
			if firstErr == nil {
				firstErr = evidenceErr
			}
			e.state.AddEvent(Event{
				Time: now, Severity: "warning", Kind: "xdr.sbc_correlated_evidence_failed", Source: "sbc-fusion",
				Message: "mandatory evidence commit failed; the corroboration is published as an unbacked event: " + evidenceErr.Error(),
				Target:  target,
			})
			continue
		}
		recorded++
		e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.sbc_correlated", Source: "sbc-fusion", Message: message, Target: target})
	}
	return recorded, firstErr
}
