// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6: time-weighted SBC-01..08 entity graph types.
//
// The fusion engine corroborates findings per entity with an exponentially
// decayed score. It is operator evidence and GIEF metadata only: it never adds a
// kill-eligible category, never raises a ResponseScore and is never consulted by
// the kill gate (`combineMatches` in xdr_rules.go does not know it exists).
//
// Bounded memory contract:
//   - at most SBCCapacity (2048) entities,
//   - at most 8 families per entity (the closed SBC family set),
//   - at most sbcEventQueueCap (128) queued corroboration events,
//   - report projections carry at most sbcReportTopEntities (16) entities.

import "time"

const (
	// SBCFusionVersion is the version token of the report projection.
	SBCFusionVersion = "sbc/fusion/v1"

	// SBCCapacity is the hard entity-graph bound.
	SBCCapacity = 2048

	// Half-life bounds from the V6.3.0 plan: configurable between 15 and 60
	// minutes, default 30 minutes.
	SBCDefaultHalfLifeMinutes = 30
	SBCMinHalfLifeMinutes     = 15
	SBCMaxHalfLifeMinutes     = 60

	// sbcDecayEpsilon is the decayed weight below which an entity family (and an
	// entity with no families left) is pruned. It is far below a single
	// observation weight, so only genuinely stale state is removed.
	sbcDecayEpsilon = 0.01
	// sbcContextEpsilon is the decayed score below which an existing entity is no
	// longer exposed as corroboration in the envelope.
	sbcContextEpsilon = 0.0001
	// sbcCorroborationMinScore is the minimum decayed score of prior observations
	// before a fusion event is produced (one full default-weight observation).
	sbcCorroborationMinScore = 0.5
	// sbcPruneEvery triggers a full sweep every N observations in addition to the
	// capacity-triggered sweep, so idle entities do not linger indefinitely.
	sbcPruneEvery = 256
	// sbcMaxFamiliesPerEntity bounds the per-entity family map; the closed SBC
	// family set has exactly eight members.
	sbcMaxFamiliesPerEntity = 8
	// sbcEventQueueCap bounds the queued corroboration events.
	sbcEventQueueCap = 128
	// sbcReportTopEntities bounds the report projection.
	sbcReportTopEntities = 16
	// sbcEntityTextBytes bounds identity text taken from incident metadata.
	sbcEntityTextBytes = 96
)

// SBCContext is the corroboration context attached to a GIEF envelope. It
// describes evidence that existed for the same entity *before* the current
// finding was observed; the current observation is added afterwards.
type SBCContext struct {
	// Families are the decayed family names observed for the entity before this
	// finding, sorted; never more than the eight closed SBC families.
	Families []string `json:"families,omitempty"`
	// DecayedScore is the summed, exponentially decayed observation weight.
	DecayedScore float64 `json:"decayed_score"`
	// HalfLifeMinutes is the decay half-life used by the graph.
	HalfLifeMinutes float64 `json:"half_life_minutes"`
	// Corroborations is the number of distinct decayed families in Families.
	Corroborations int `json:"corroborations"`
}

// SBCEntitySummary is one bounded entity projection inside SBCFusionReport.
type SBCEntitySummary struct {
	Entity       string    `json:"entity"`
	Families     []string  `json:"families,omitempty"`
	DecayedScore float64   `json:"decayed_score"`
	Observations uint64    `json:"observations"`
	LastSeen     time.Time `json:"last_seen"`
}

// SBCFusionReport is the bounded read-only projection of the fusion graph for
// future API wiring. It is a report, not an enforcement input.
type SBCFusionReport struct {
	Version             string             `json:"version"`
	State               string             `json:"state"`
	HalfLifeMinutes     float64            `json:"half_life_minutes"`
	Capacity            int                `json:"capacity"`
	Entities            int                `json:"entities"`
	Observations        uint64             `json:"observations"`
	Evictions           uint64             `json:"evictions"`
	Prunings            uint64             `json:"prunings"`
	CorroborationEvents uint64             `json:"corroboration_events"`
	DroppedEvents       uint64             `json:"dropped_events"`
	Top                 []SBCEntitySummary `json:"top,omitempty"`
	GeneratedAt         time.Time          `json:"generated_at"`
}

// SBCCorroborationEvent is one cross-domain corroboration fact produced by the
// fusion graph. It is queued (bounded) by the graph and drained by
// XDREngine.recordSBCCorroborations, which records evidence before it publishes
// the matching state event.
type SBCCorroborationEvent struct {
	Time          time.Time `json:"time"`
	Entity        string    `json:"entity"`
	Family        string    `json:"family"`
	PriorFamilies []string  `json:"prior_families,omitempty"`
	PriorScore    float64   `json:"prior_score"`
}

// sbcEntity is one graph node. All stored scores are normalised to lastSeen, so
// the decayed value at any later instant is score * 2^(-(t-lastSeen)/halfLife).
type sbcEntity struct {
	key          string
	families     map[string]float64
	score        float64
	observations uint64
	firstSeen    time.Time
	lastSeen     time.Time
}
