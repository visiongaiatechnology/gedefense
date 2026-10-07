package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DefenseLayer represents a verified security boundary in GeDefense.
type DefenseLayer string

const (
	LayerIngressNetwork DefenseLayer = "ingress_network"
	LayerHostXDR        DefenseLayer = "host_xdr"
	LayerEgress         DefenseLayer = "egress"
	LayerApplicationL7  DefenseLayer = "application_l7"
	LayerThreatIntel    DefenseLayer = "threat_intel"
	LayerFIM            DefenseLayer = "fim"
	LayerBootTrust      DefenseLayer = "boot_trust"
	LayerPolicyTrust    DefenseLayer = "policy_trust"
)

// EnforcementMode defines how active reactions are applied.
type EnforcementMode string

const (
	EnforcementObserve EnforcementMode = "observe"
	EnforcementContain EnforcementMode = "contain"
	EnforcementBlock   EnforcementMode = "block"
)

// SensorCoverageStatus represents the operational coverage of an individual sensor.
type SensorCoverageStatus string

const (
	CoverageOnline        SensorCoverageStatus = "online"
	CoverageDegraded      SensorCoverageStatus = "degraded"
	CoverageOffline       SensorCoverageStatus = "offline"
	CoverageDisabled      SensorCoverageStatus = "disabled"
	CoverageNotApplicable SensorCoverageStatus = "not_applicable"
)

// SensorCoverage represents the telemetry and self-test state of a specific sensor.
type SensorCoverage struct {
	Name           string               `json:"name"`
	Layer          DefenseLayer         `json:"layer"`
	Status         SensorCoverageStatus `json:"status"`
	Required       bool                 `json:"required"`
	LastOK         *time.Time           `json:"last_ok,omitempty"`
	LastError      string               `json:"last_error,omitempty"`
	SelfTest       string               `json:"self_test,omitempty"`
	CoverageReason string               `json:"coverage_reason,omitempty"`
}

// SystemCoverage aggregates coverage across all sensors deterministically.
type SystemCoverage struct {
	OverallStatus SensorCoverageStatus      `json:"overall_status"`
	Nominal       bool                      `json:"nominal"`
	Sensors       map[string]SensorCoverage `json:"sensors"`
	Summary       string                    `json:"summary"`
}

// EvaluateCoverage determines system nominal status deterministically (Rule 5).
func EvaluateCoverage(sensors map[string]SensorCoverage) SystemCoverage {
	out := SystemCoverage{
		OverallStatus: CoverageOnline,
		Nominal:       true,
		Sensors:       make(map[string]SensorCoverage, len(sensors)),
	}

	hasDegradedRequired := false
	hasOfflineRequired := false
	var offlineNames []string
	var degradedNames []string

	for k, v := range sensors {
		out.Sensors[k] = v
		if !v.Required {
			continue
		}
		switch v.Status {
		case CoverageOffline, CoverageDisabled:
			hasOfflineRequired = true
			offlineNames = append(offlineNames, v.Name)
		case CoverageDegraded:
			hasDegradedRequired = true
			degradedNames = append(degradedNames, v.Name)
		}
	}

	if hasOfflineRequired {
		out.OverallStatus = CoverageOffline
		out.Nominal = false
		out.Summary = fmt.Sprintf("Critical mandatory sensors offline: %s", strings.Join(offlineNames, ", "))
	} else if hasDegradedRequired {
		out.OverallStatus = CoverageDegraded
		out.Nominal = false
		out.Summary = fmt.Sprintf("Mandatory sensors degraded: %s", strings.Join(degradedNames, ", "))
	} else {
		out.OverallStatus = CoverageOnline
		out.Nominal = true
		out.Summary = "All mandatory sensors operational"
	}

	return out
}

// DefenseLayerState models separated detection and enforcement state (Point 6).
type DefenseLayerState struct {
	Layer              DefenseLayer         `json:"layer"`
	DetectionEnabled   bool                 `json:"detection_enabled"`
	DetectionHealthy   bool                 `json:"detection_healthy"`
	EnforcementMode    EnforcementMode      `json:"enforcement_mode"`
	EnforcementHealthy bool                 `json:"enforcement_healthy"`
	ModeReason         string               `json:"mode_reason,omitempty"`
	Coverage           SensorCoverageStatus `json:"coverage"`
}

// KineticEvent provides the unified security event schema across all layers (Point 4).
type KineticEvent struct {
	ID               string                 `json:"id"`
	Time             time.Time              `json:"time"`
	Layer            DefenseLayer           `json:"layer"`
	Sensor           string                 `json:"sensor"`
	RuleID           string                 `json:"rule_id"`
	Category         string                 `json:"category"`
	Severity         string                 `json:"severity"` // "info", "low", "medium", "high", "critical"
	Score            int                    `json:"score"`
	Confidence       float64                `json:"confidence"` // 0.0 to 1.0
	SourceIP         string                 `json:"source_ip,omitempty"`
	DestinationIP    string                 `json:"destination_ip,omitempty"`
	Port             uint16                 `json:"port,omitempty"`
	Protocol         string                 `json:"protocol,omitempty"` // "tcp", "udp", "icmp"
	Interface        string                 `json:"interface,omitempty"`
	Process          string                 `json:"process,omitempty"`
	PID              int                    `json:"pid,omitempty"`
	Domain           string                 `json:"domain,omitempty"`
	JA3Fingerprint   string                 `json:"ja3_fingerprint,omitempty"`
	Subnet           string                 `json:"subnet,omitempty"` // e.g. /24, /16, /64
	Hits             int                    `json:"hits,omitempty"`
	RatePerSec       float64                `json:"rate_per_sec,omitempty"`
	Action           string                 `json:"action"` // "track", "warn", "contain", "block", "drop"
	Decision         string                 `json:"decision"`
	EvidenceID       string                 `json:"evidence_id,omitempty"`
	PolicyGeneration uint64                 `json:"policy_generation,omitempty"`
	Fingerprint      string                 `json:"fingerprint"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// ComputeFingerprint generates a deterministic SHA-256 deduplication key.
func (e *KineticEvent) ComputeFingerprint() string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s|%s",
		e.Layer, e.RuleID, e.SourceIP, e.DestinationIP, e.Subnet, e.Port, e.Protocol, e.Domain)
	sum := sha256.Sum256([]byte(raw))
	e.Fingerprint = hex.EncodeToString(sum[:16])
	return e.Fingerprint
}

// KineticTelemetry captures the aggregate performance and incident metrics.
type KineticTelemetry struct {
	HitsTotal                 uint64 `json:"hits_total"`
	VelocityBurstsTotal       uint64 `json:"velocity_bursts_total"`
	PortscansTotal            uint64 `json:"portscans_total"`
	SubnetStrikesTotal        uint64 `json:"subnet_strikes_total"`
	L7StrikesTotal            uint64 `json:"l7_strikes_total"`
	BansEnforcedTotal         uint64 `json:"bans_enforced_total"`
	BansExpiredTotal          uint64 `json:"bans_expired_total"`
	ResponseAppliedTotal      uint64 `json:"response_applied_total"`
	ResponseSuppressedTotal   uint64 `json:"response_suppressed_total"`
	ResponseRollbackTotal     uint64 `json:"response_rollback_total"`
	ResponseFailedTotal       uint64 `json:"response_failed_total"`
	ActiveTrackingIPs         int    `json:"active_tracking_ips"`
	ActiveSubnetsV4           int    `json:"active_subnets_v4"`
	ActiveSubnetsV6           int    `json:"active_subnets_v6"`
	ActiveWideV4              int    `json:"active_wide_v4"`
	TrackingCapacity          int    `json:"tracking_capacity"`
	TrackingDropsTotal        uint64 `json:"tracking_drops_total"`
	TrackingEvictionsTotal    uint64 `json:"tracking_evictions_total"`
	AggregateEvictionsTotal   uint64 `json:"aggregate_evictions_total"`
	KernelEventsEmitted       uint64 `json:"kernel_events_emitted"`
	KernelRingDrops           uint64 `json:"kernel_ring_drops"`
	KernelTrackInsertFailures uint64 `json:"kernel_track_insert_failures"`
	// IngressMode names the hook that is actually enforcing ingress on this host:
	// NATIVE_XDP in the driver path, GENERIC_XDP in the generic path, TC_INGRESS when
	// neither was available. It is reported because "the kernel producer is verified"
	// was previously true for all three, and they perform very differently under load -
	// an operator could not tell whether their hardware was doing the work.
	IngressMode  string                             `json:"ingress_mode,omitempty"`
	LastStrikeAt *time.Time                         `json:"last_strike_at,omitempty"`
	Layers       map[DefenseLayer]DefenseLayerState `json:"layers"`
	Coverage     SystemCoverage                     `json:"coverage"`
}

// DefaultKineticTelemetry initializes a fail-safe baseline. No sensor is
// considered healthy until a real producer has verified its data path.
func DefaultKineticTelemetry() KineticTelemetry {
	layers := map[DefenseLayer]DefenseLayerState{
		LayerIngressNetwork: {
			Layer:              LayerIngressNetwork,
			DetectionEnabled:   true,
			DetectionHealthy:   false,
			EnforcementMode:    EnforcementObserve,
			EnforcementHealthy: false,
			Coverage:           CoverageOffline,
			ModeReason:         "awaiting verified kernel ingress telemetry",
		},
		LayerHostXDR: {
			Layer:              LayerHostXDR,
			DetectionEnabled:   false,
			DetectionHealthy:   false,
			EnforcementMode:    EnforcementObserve,
			EnforcementHealthy: false,
			Coverage:           CoverageNotApplicable,
			ModeReason:         "reported by the XDR subsystem, not inferred by Kinetic Defense",
		},
		LayerEgress: {
			Layer:              LayerEgress,
			DetectionEnabled:   false,
			DetectionHealthy:   false,
			EnforcementMode:    EnforcementObserve,
			EnforcementHealthy: false,
			Coverage:           CoverageNotApplicable,
			ModeReason:         "reported by the egress subsystem, not inferred by Kinetic Defense",
		},
		LayerApplicationL7: {
			Layer:              LayerApplicationL7,
			DetectionEnabled:   false,
			DetectionHealthy:   false,
			EnforcementMode:    EnforcementObserve,
			EnforcementHealthy: false,
			Coverage:           CoverageNotApplicable,
			ModeReason:         "reported by the L7 subsystem, not inferred by Kinetic Defense",
		},
		LayerThreatIntel: {
			Layer:              LayerThreatIntel,
			DetectionEnabled:   false,
			DetectionHealthy:   false,
			EnforcementMode:    EnforcementObserve,
			EnforcementHealthy: false,
			Coverage:           CoverageNotApplicable,
			ModeReason:         "reported by the threat-intelligence subsystem",
		},
		LayerFIM: {
			Layer:              LayerFIM,
			DetectionEnabled:   false,
			DetectionHealthy:   false,
			EnforcementMode:    EnforcementObserve,
			EnforcementHealthy: false,
			Coverage:           CoverageNotApplicable,
			ModeReason:         "reported by the integrity subsystem",
		},
		LayerBootTrust: {
			Layer:              LayerBootTrust,
			DetectionEnabled:   false,
			DetectionHealthy:   false,
			EnforcementMode:    EnforcementObserve,
			EnforcementHealthy: false,
			Coverage:           CoverageNotApplicable,
			ModeReason:         "reported by the boot-trust subsystem",
		},
		LayerPolicyTrust: {
			Layer:              LayerPolicyTrust,
			DetectionEnabled:   false,
			DetectionHealthy:   false,
			EnforcementMode:    EnforcementObserve,
			EnforcementHealthy: false,
			Coverage:           CoverageNotApplicable,
			ModeReason:         "reported by the policy/evidence subsystem",
		},
	}

	sensors := map[string]SensorCoverage{
		"xdp_ingress": {
			Name:           "xdp_ingress",
			Layer:          LayerIngressNetwork,
			Status:         CoverageOffline,
			Required:       true,
			SelfTest:       "unverified",
			CoverageReason: "no verified kernel ingress producer has reported yet",
		},
	}

	return KineticTelemetry{
		TrackingCapacity: 65536,
		Layers:           layers,
		Coverage:         EvaluateCoverage(sensors),
	}
}

// BoundedEventQueue implements a ring buffer for realtime SSE stream and backpressure.
type BoundedEventQueue struct {
	mu       sync.Mutex
	capacity int
	events   []KineticEvent
	drops    uint64
}

// NewBoundedEventQueue creates an event queue with fixed capacity.
func NewBoundedEventQueue(capacity int) *BoundedEventQueue {
	if capacity <= 0 {
		capacity = 250
	}
	return &BoundedEventQueue{
		capacity: capacity,
		events:   make([]KineticEvent, 0, capacity),
	}
}

// Push adds an event, dropping the oldest if capacity is exceeded.
func (q *BoundedEventQueue) Push(event KineticEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.events) >= q.capacity {
		q.events = q.events[1:]
		q.drops++
	}
	q.events = append(q.events, event)
}

// Snapshot returns a copy of current events and drop count.
func (q *BoundedEventQueue) Snapshot() ([]KineticEvent, uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	out := make([]KineticEvent, len(q.events))
	copy(out, q.events)
	return out, q.drops
}

// Capacity returns the fixed event buffer capacity.
func (q *BoundedEventQueue) Capacity() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.capacity
}
