package main

import (
	"sort"
	"time"
)

// StyxPhase2EntityReport is one bounded entity window in the read-only report.
type StyxPhase2EntityReport struct {
	CgroupID           uint64    `json:"cgroup_id"`
	PID                int       `json:"pid"`
	UID                uint32    `json:"uid,omitempty"`
	Remote             string    `json:"remote"`
	Port               uint16    `json:"port"`
	Family             uint8     `json:"family"`
	Proto              uint8     `json:"proto"`
	Comm               string    `json:"comm,omitempty"`
	TxBytes            uint64    `json:"tx_bytes"`
	RxBytes            uint64    `json:"rx_bytes"`
	WindowBytes        uint64    `json:"window_bytes"`
	PCR                float64   `json:"pcr"`
	PCRObserved        bool      `json:"pcr_observed"`
	TxSamples          uint32    `json:"tx_samples"`
	RxSamples          uint32    `json:"rx_samples"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	CorrelationQuality string    `json:"correlation_quality"`
}

// StyxPhase2Report is the bounded read-only projection for future API wiring.
// It carries the RX capability, the PCR entity windows, the idle hint and the
// session summary. It is report-only; nothing in the response engine consumes it.
type StyxPhase2Report struct {
	RxObservation      string                   `json:"rx_observation"` // available|unavailable|unknown
	RxAttached         bool                     `json:"rx_attached"`
	RxEvents           uint64                   `json:"rx_events"`
	RxReadFailures     uint64                   `json:"rx_read_failures"`
	RxStatusAgeMS      int64                    `json:"rx_status_age_ms,omitempty"`
	RxStatusError      string                   `json:"rx_status_error,omitempty"`
	IdleHint           string                   `json:"idlehint"`
	Sessions           StyxSessionSummary       `json:"sessions"`
	Entities           []StyxPhase2EntityReport `json:"entities"`
	EntityCount        int                      `json:"entity_count"`
	TxEvents           uint64                   `json:"tx_events"`
	IngressEvents      uint64                   `json:"ingress_events"`
	RxAttributedEvents uint64                   `json:"rx_attributed_events"`
	RxUnattributed     uint64                   `json:"rx_unattributed_events"`
	PCRCandidates      uint64                   `json:"pcr_candidates"`
	PCRIncidents       uint64                   `json:"pcr_incidents"`
	Suppressed         uint64                   `json:"suppressed"`
	CorrelationQuality string                   `json:"correlation_quality"` // OBSERVED|TEMPORAL|NONE
	Limitation         string                   `json:"limitation,omitempty"`
}

// ---------------------------------------------------------------------------
// Report projection
// ---------------------------------------------------------------------------

// StyxPhase2Report projects the bounded phase-2 state for future API wiring.
// It never mutates detection state and never initiates a response.
func (e *XDREngine) StyxPhase2Report() StyxPhase2Report {
	if e == nil || e.styxPhase2 == nil {
		return StyxPhase2Report{RxObservation: "unknown", IdleHint: "unavailable"}
	}
	return e.styxPhase2.report(time.Now().UTC())
}

// report renders the bounded read-only projection.
func (p *StyxPhase2Engine) report(now time.Time) StyxPhase2Report {
	if p == nil {
		return StyxPhase2Report{RxObservation: "unknown", IdleHint: "unavailable"}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	minute := styxPhase2Minute(now)
	projection := StyxPhase2Report{
		RxObservation:      "unknown",
		RxAttached:         p.rxAttached,
		RxEvents:           p.rxEvents,
		RxReadFailures:     p.rxReadFailures,
		RxStatusError:      p.rxStatusErr,
		IdleHint:           p.sessions.IdleHint,
		Sessions:           p.sessions,
		EntityCount:        len(p.entities),
		TxEvents:           p.txEvents,
		IngressEvents:      p.ingressEvents,
		RxAttributedEvents: p.rxAttributed,
		RxUnattributed:     p.rxUnattributed,
		PCRCandidates:      p.pcrCandidates,
		PCRIncidents:       p.pcrIncidents,
		Suppressed:         p.suppressed,
	}
	if projection.IdleHint == "" {
		projection.IdleHint = "unavailable"
	}
	switch {
	case p.rxObservationAvailable:
		projection.RxObservation = "available"
	case p.rxCapabilityKnown:
		projection.RxObservation = "unavailable"
	default:
		projection.RxObservation = "unknown"
	}
	if !p.rxStatusAt.IsZero() {
		projection.RxStatusAgeMS = now.Sub(p.rxStatusAt).Milliseconds()
		if projection.RxStatusAgeMS < 0 {
			projection.RxStatusAgeMS = 0
		}
	}
	entities := make([]StyxPhase2EntityReport, 0, styxPhase2MaxReportEntities)
	for _, entity := range p.entities {
		tx, rx, txSamples, rxSamples := entity.windowLocked(minute)
		windowBytes := saturatingAdd(tx, rx)
		if windowBytes == 0 {
			continue
		}
		// PCR is computed once the window carries at least 64 KiB (below that a
		// ratio is statistically meaningless); OBSERVED still needs the attached
		// RX capability and a matched inbound sample.
		observed := p.rxObservationAvailable && rxSamples > 0 && windowBytes >= styxPhase2PCRComputeBytes
		entry := StyxPhase2EntityReport{
			CgroupID:           entity.key.cgroupID,
			PID:                entity.key.pid,
			UID:                entity.uid,
			Remote:             entity.key.remote.String(),
			Port:               entity.key.port,
			Family:             entity.family,
			Proto:              entity.proto,
			Comm:               entity.comm,
			TxBytes:            tx,
			RxBytes:            rx,
			WindowBytes:        windowBytes,
			TxSamples:          txSamples,
			RxSamples:          rxSamples,
			FirstSeen:          entity.firstSeen,
			LastSeen:           entity.lastSeen,
			CorrelationQuality: p.correlationQualityLocked(rxSamples),
		}
		if observed {
			entry.PCR = styxPhase2PCRValue(tx, rx)
			entry.PCRObserved = true
		}
		entities = append(entities, entry)
	}
	sort.SliceStable(entities, func(i, j int) bool {
		if entities[i].WindowBytes != entities[j].WindowBytes {
			return entities[i].WindowBytes > entities[j].WindowBytes
		}
		return entities[i].PCR > entities[j].PCR
	})
	if len(entities) > styxPhase2MaxReportEntities {
		entities = entities[:styxPhase2MaxReportEntities]
	}
	projection.Entities = entities
	projection.CorrelationQuality = "NONE"
	if p.rxObservationAvailable && p.rxAttributed > 0 {
		projection.CorrelationQuality = "OBSERVED"
	} else if projection.IdleHint == "inactive" {
		projection.CorrelationQuality = "TEMPORAL"
	}
	switch {
	case !p.rxCapabilityKnown:
		projection.Limitation = "ingress RX capability is missing (capability fact, not degradation); PCR is not computed from tx-only data and no lock state is claimed from logind session files"
	case !p.rxObservationAvailable:
		projection.Limitation = "ingress RX observer is not attached; PCR is not computed from tx-only data and no lock state is claimed from logind session files"
	case p.rxAttributed == 0:
		projection.Limitation = "ingress RX observer is attached but no inbound flow has matched an egress entity yet; PCR needs a matched inbound sample and is not claimed from tx-only data"
	case projection.IdleHint != "inactive":
		projection.Limitation = "logind IdleHint is a D-Bus property and is not readable from /run/systemd/sessions; only a session-inactive timing statement is derived, never a locked-screen claim"
	}
	return projection
}
