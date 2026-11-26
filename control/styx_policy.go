// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5: the StyX bridge into the XDR/beacon engine and the bounded
// read-only API view types. This file never decides enforcement: the detector's
// incidents go through the existing XDR appendIncident/respond path.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// ----------------------------------------------------- XDR / beacon integration
//
// The XDR engine owns the detector and the syncer; these helpers are the only
// bridge. The detector configuration is adjusted under its own mutex (the flow
// state stays private to styx_beacon.go), so this file never touches the detected
// evidence itself.

// applyStyxBeaconSettings projects the operator namespace onto the detector. It is
// called at construction and from ApplyRuntimeSettings; it does not start or stop
// any collection by itself.
func (e *XDREngine) applyStyxBeaconSettings(settings RuntimeSettings) {
	if e == nil || e.styxBeacon == nil {
		return
	}
	plan, err := buildStyxPolicyPlan(effectiveStyxFabricSettings(settings))
	if err != nil {
		// The store validates before persisting; a defensive failure keeps the
		// detector passive and mode off instead of inventing a policy.
		e.styxBeacon.mu.Lock()
		e.styxBeacon.cfg.Enabled = false
		e.styxBeacon.cfg.Mode = StyxModeOff
		e.styxBeacon.mu.Unlock()
		return
	}
	resolverPrefixes := make([]netip.Prefix, 0, len(plan.Resolvers))
	for _, resolver := range plan.Resolvers {
		if prefix, parseErr := netip.ParsePrefix(resolver.CIDR); parseErr == nil {
			resolverPrefixes = append(resolverPrefixes, prefix)
		}
	}
	allowPrefixes := parseAllowlistPrefixes(append(append([]string(nil), settings.ManagementAllowlist...), e.cfg.Defense.Allowlist...))
	localPrefixes := localHostInterfacePrefixes()
	now := time.Now().UTC()
	e.styxBeacon.mu.Lock()
	e.styxBeacon.cfg.Enabled = plan.Enabled
	// The detector must mirror the effective global mode: mode=off means the
	// kernel logs no flows (§6.1), so SensorState has to report "off" instead of
	// claiming an active sensor over empty telemetry.
	e.styxBeacon.cfg.Mode = plan.ModeName
	e.styxBeacon.cfg.ResolverPrefixes = resolverPrefixes
	e.styxBeacon.cfg.AllowPrefixes = allowPrefixes
	e.styxBeacon.cfg.LocalPrefixSource = localHostInterfacePrefixes
	e.styxBeacon.cfg.KernelSoftirqCheck = linuxIsKernelThread
	e.styxBeacon.localPrefixes = localPrefixes
	e.styxBeacon.localPrefixRefreshedAt = now
	// DNSObservationAvailable mirrors the real runtime DNS_CAPTURE_* channel
	// (false until armed + tracepoints attached, then enables real STYX.EGRESS.DIRECT_IP).
	e.styxBeacon.cfg.DNSObservationAvailable = e.DNSObservationAvailable()
	e.styxBeacon.cfg.RxObservationAvailable = false
	e.styxBeacon.mu.Unlock()
}

// localHostInterfacePrefixes returns single-host (/32 or /128) prefixes for
// every non-loopback unicast address currently bound to a local network
// interface on this machine. Using exact host masks avoids suppressing sibling
// peers in the same subnet while eliminating DIRECT_IP_NO_DNS false positives
// on daemon self-traffic across arbitrary servers and devices.
func localHostInterfacePrefixes() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil || len(addrs) == 0 {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, raw := range addrs {
		ipNet, ok := raw.(*net.IPNet)
		if !ok || ipNet == nil || ipNet.IP == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() {
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes
}

// linuxIsKernelThread verifies via procfs that pid is an authentic Linux kernel
// thread (PPID 2 and no userspace /proc/<pid>/exe), preventing unprivileged
// tasks from spoofing ksoftirqd/* via prctl(PR_SET_NAME).
func linuxIsKernelThread(pid int) bool {
	if pid <= 2 {
		return false
	}
	if _, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		return false
	} else if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	line := string(statBytes)
	closeParen := strings.LastIndexByte(line, ')')
	if closeParen < 0 || closeParen+2 >= len(line) {
		return false
	}
	fields := strings.Fields(line[closeParen+2:])
	if len(fields) < 2 {
		return false
	}
	ppid, err := strconv.Atoi(fields[1])
	return err == nil && ppid == 2
}

func parseAllowlistPrefixes(entries []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, raw := range entries {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(trimmed); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		} else if addr, addrErr := netip.ParseAddr(trimmed); addrErr == nil {
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return prefixes
}

// setStyxBeaconCapability records the negotiated core capability on the detector.
// A missing capability leaves the sensor `unavailable`; it never suppresses events
// that were already recorded.
func (e *XDREngine) setStyxBeaconCapability(known bool) {
	if e == nil || e.styxBeacon == nil {
		return
	}
	e.styxBeacon.mu.Lock()
	knownBefore := e.styxBeacon.cfg.FlowCapabilityKnown
	e.styxBeacon.cfg.FlowCapabilityKnown = known
	e.styxBeacon.mu.Unlock()
	if knownBefore != known && e.state != nil {
		if known {
			e.state.AddEvent(Event{Severity: "info", Kind: "styx.flow_capability_available", Source: "kernel", Message: "Kernel StyX flow telemetry is available; the beacon sensor reports its own state from here on"})
		} else {
			e.state.AddEvent(Event{Severity: "warning", Kind: "styx.flow_capability_missing", Source: "kernel", Message: "Kernel StyX flow telemetry is unavailable (old core or command rejected); the beacon sensor is unavailable and does not claim the absence of beacons"})
		}
	}
}

// styxCanaryCorrelation answers §8.2 signal 2's contextual question from the
// existing incident stream: was a deception canary accessed by this process or in
// this cgroup inside the lookback window?
func (e *XDREngine) styxCanaryCorrelation(cgroupID uint64, pid int, since time.Time) bool {
	if e == nil || e.state == nil {
		return false
	}
	snapshot := e.state.Snapshot()
	for index := range snapshot.Incidents {
		incident := snapshot.Incidents[index]
		if incident.Time.Before(since) {
			continue
		}
		if !containsString(incident.RuleIDs, "KD.LINUX.CANARY_ACCESS") {
			continue
		}
		if pid > 0 && incident.PID == pid {
			return true
		}
		if cgroupID != 0 && incident.CellCgroupID == cgroupID {
			return true
		}
	}
	return false
}

// emitStyxBeaconIncident is the detector's sink. It is the ONLY path from a beacon
// finding into XDR: evidence first, then the existing response decision, then the
// existing incident log. It never invents a new enforcement route.
func (e *XDREngine) emitStyxBeaconIncident(incident XDRIncident) error {
	if e == nil || e.state == nil {
		return nil
	}
	// The mandatory evidence record is written before the incident and must carry the
	// same vocabulary as the log, the state and the case store; the beacon engine emits
	// the display form ("CRITICAL"/"HIGH").
	incident.Severity = strings.ToLower(strings.TrimSpace(incident.Severity))
	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: incident.Severity, Kind: "xdr.styx_beacon", Source: "styx-beacon",
		Message: "Styx beacon/exfiltration detection evidence recorded before any active response: " + incident.Summary,
		Target:  incident.Remote, Time: incident.Time,
	})
	if evidenceErr != nil {
		// No evidence, no response (§1.5). The incident is still recorded, with an
		// outcome that says why nothing happened.
		incident.Action, incident.Outcome = "none", "mandatory evidence commit failed; active response disabled"
		e.appendIncident(incident)
		e.addStyxBeaconEvent(incident)
		return evidenceErr
	}
	incident.Action, incident.Outcome = e.respond(incident)
	e.appendIncident(incident)
	e.addStyxBeaconEvent(incident)
	// The incident carries CellCgroupID, so the existing CellGuard auto-confine
	// scanner can isolate the cell when the operator enabled cells.auto_confine and
	// the score crosses the threshold. No new silent path is opened here.
	return nil
}

func (e *XDREngine) addStyxBeaconEvent(incident XDRIncident) {
	if e == nil || e.state == nil {
		return
	}
	e.state.AddEvent(Event{
		Severity: incident.Severity, Kind: "xdr." + incident.Decision, Source: "styx-beacon",
		Message: incident.Summary, Target: incident.Remote,
	})
}

// recordStyxFlowBatch feeds one drained batch plus its ring-drop delta into the
// detector and reports visibility loss honestly (§3.3, §9): an overflow series
// degrades the sensor; it never becomes a claim that no beacons exist.
func (e *XDREngine) recordStyxFlowBatch(events []CoreStyxFlowEvent, dropped uint64, now time.Time) {
	// V6.3.0 AP-6: phase-2 analytics (bidirectional PCR / DNS correlation
	// context) observe every batch before the beacon detector prunes it. The
	// phase-2 engines never change an enforcement decision.
	e.phase2ObserveFlowBatch(events, now)
	beacon := e.styxBeacon
	if beacon == nil {
		return
	}
	e.recordStyxFlowDrain(now)
	sensorBefore := beacon.SensorState()
	beacon.RecordFlowPoll(dropped)
	if len(events) > 0 {
		beacon.RecordFlows(events)
	}
	sensorAfter := beacon.SensorState()
	if dropped > 0 && e.state != nil {
		e.styxFlowMu.Lock()
		lastOverflow := e.styxLastOverflowEvent
		if lastOverflow.IsZero() || now.Sub(lastOverflow) >= 5*time.Minute {
			e.styxLastOverflowEvent = now
			e.styxFlowMu.Unlock()
			e.state.AddEvent(Event{
				Severity: "high", Kind: "xdr.styx_flow_overflow", Source: "kernel",
				Message: fmt.Sprintf("Styx flow telemetry reported %d dropped aggregated flows; the beacon detector's visibility is reduced and it does not claim the absence of beacons", dropped),
			})
		} else {
			e.styxFlowMu.Unlock()
		}
	}
	if e.state != nil {
		switch {
		case sensorBefore != "degraded" && sensorAfter == "degraded":
			e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.styx_flow_sensor_degraded", Source: "kernel",
				Message: "Styx flow sensor degraded after repeated ring/aggregation drops; beacon incidents are suppressed until a clean poll series restores visibility"})
		case sensorBefore == "degraded" && sensorAfter == "active":
			e.state.AddEvent(Event{Severity: "info", Kind: "xdr.styx_flow_sensor_recovered", Source: "kernel",
				Message: "Styx flow sensor recovered after a clean poll series"})
		}
	}
	e.styxFlowMu.Lock()
	if now.Sub(e.styxLastPrune) >= 5*time.Second {
		beacon.Prune(now)
		e.styxLastPrune = now
	}
	e.styxFlowMu.Unlock()
}

// recordStyxFlowHealth stores the kernel flow counters for the operator status.
// The previous sample is kept so the status can expose a real window delta (and
// not just cumulative counters that never show a rate).
func (e *XDREngine) recordStyxFlowHealth(health CoreStyxFlowHealth, now time.Time) {
	if e == nil {
		return
	}
	e.styxFlowMu.Lock()
	if !e.styxFlowHealthAt.IsZero() {
		e.styxFlowHealthPrev = e.styxFlowHealth
		e.styxFlowHealthPrevAt = e.styxFlowHealthAt
	}
	e.styxFlowHealth = health
	e.styxFlowHealthAt = now
	e.styxFlowHealthErr = ""
	e.styxFlowMu.Unlock()
	e.noteStyxTelemetryState(now)
}

func (e *XDREngine) recordStyxFlowHealthFailure(err error) {
	if e == nil || err == nil {
		return
	}
	e.styxFlowMu.Lock()
	e.styxFlowHealthErr = boundedStyxText(err)
	e.styxFlowMu.Unlock()
	e.noteStyxTelemetryState(time.Now().UTC())
}

// styxFlowPollEnabled reports whether the detector is armed for flow ingestion. It
// is false for the upgrade default and for a disabled operator revision.
func (e *XDREngine) styxFlowPollEnabled() bool {
	if e == nil || e.styxBeacon == nil {
		return false
	}
	e.styxBeacon.mu.Lock()
	defer e.styxBeacon.mu.Unlock()
	return e.styxBeacon.cfg.Enabled
}

func (e *XDREngine) styxFlowCapabilityKnown() bool {
	if e == nil || e.styxBeacon == nil {
		return false
	}
	e.styxBeacon.mu.Lock()
	defer e.styxBeacon.mu.Unlock()
	return e.styxBeacon.cfg.FlowCapabilityKnown
}

// StyxFlowHealthStatus returns the last kernel flow counters the engine observed.
func (e *XDREngine) StyxFlowHealthStatus() (CoreStyxFlowHealth, time.Time, string) {
	if e == nil {
		return CoreStyxFlowHealth{}, time.Time{}, ""
	}
	e.styxFlowMu.Lock()
	defer e.styxFlowMu.Unlock()
	return e.styxFlowHealth, e.styxFlowHealthAt, e.styxFlowHealthErr
}

// ---------------------------------------------------------------- API views

// StyxBeaconView is the bounded operator view of the detector. Top is capped at
// ten by the detector itself; no secret, command line or credential ever enters it.
type StyxBeaconView struct {
	SensorState    string                   `json:"sensor_state"`
	DNSObservation string                   `json:"dns_observation"`
	TrackedFlows   int                      `json:"tracked_flows"`
	Top            []StyxBeaconFlowSnapshot `json:"top"`
	Events         uint64                   `json:"events_total"`
	Incidents      uint64                   `json:"incident_total"`
	Suppressed     uint64                   `json:"suppressed_total"`
	Dropped        uint64                   `json:"rejected_total"`
	Overflows      uint64                   `json:"overflow_total"`
}

func styxBeaconView(snapshot StyxBeaconSnapshot) StyxBeaconView {
	top := snapshot.Top
	if top == nil {
		top = []StyxBeaconFlowSnapshot{}
	}
	if len(top) > 10 {
		top = top[:10]
	}
	return StyxBeaconView{
		SensorState: snapshot.SensorState, DNSObservation: snapshot.DNSObservation,
		TrackedFlows: snapshot.Flows, Top: top,
		Events: snapshot.Events, Incidents: snapshot.Incidents, Suppressed: snapshot.Suppressed,
		Dropped: snapshot.Dropped, Overflows: snapshot.Overflows,
	}
}

// StyxStatus is the small, bounded StyX projection on GET /api/v1/status.
// Enforcement (enabled/mode/sync) and telemetry health are separate fields: a
// drop-driven telemetry degradation must never read as "StyX is not active".
type StyxStatus struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	SensorState   string `json:"sensor_state"`
	Capability    string `json:"capability"`
	SyncState     string `json:"sync_state"`
	Epoch         string `json:"epoch,omitempty"`
	TrackedFlows  int    `json:"tracked_flows"`
	EventsTotal   uint64 `json:"events_total"`
	IncidentTotal uint64 `json:"incident_total"`
	Suppressed    uint64 `json:"suppressed_total"`
	OverflowTotal uint64 `json:"overflow_total"`
	Degraded      bool   `json:"degraded"`
	// V6.3.0 AP-6: the cgroup_skb/ingress RX capability fact
	// ("available" / "unavailable"). Reporting metadata only; it never changes a
	// score, an enforcement decision or the Phase-1 asymmetry gate.
	RxObservation string `json:"rx_observation"`

	EnforcementActive   bool    `json:"enforcement_active"`
	TelemetryState      string  `json:"telemetry_state"`
	TelemetryDegraded   bool    `json:"telemetry_degraded"`
	FlowDropRatio       float64 `json:"flow_drop_ratio"`
	FlowRingDropsDelta  uint64  `json:"flow_ring_drops_delta"`
	FlowEmittedDelta    uint64  `json:"flow_emitted_delta"`
	FlowDrainLagSeconds float64 `json:"flow_drain_lag_seconds"`
}

// StyxStatusSnapshot builds the bounded status field for /api/v1/status. It is nil
// for an engine without any StyX wiring, so the existing snapshot JSON stays
// byte-identical unless the feature is compiled in and attached.
func (e *XDREngine) StyxStatusSnapshot() *StyxStatus {
	if e == nil || (e.styxBeacon == nil && e.styxPolicy == nil) {
		return nil
	}
	sync := e.StyxPolicyStatus()
	beacon := e.StyxBeaconSnapshot()
	flow := e.StyxFlowMetrics()
	return &StyxStatus{
		Enabled: sync.Enabled, Mode: sync.Mode, SensorState: beacon.SensorState,
		Capability: sync.Capability, SyncState: sync.State, Epoch: sync.Epoch,
		TrackedFlows: beacon.Flows, EventsTotal: beacon.Events, IncidentTotal: beacon.Incidents,
		Suppressed: beacon.Suppressed, OverflowTotal: beacon.Overflows,
		Degraded:          beacon.SensorState == "degraded" || flow.TelemetryDegraded,
		RxObservation:     beacon.RxObservation,
		EnforcementActive: styxEnforcementActive(sync),
		TelemetryState:    flow.TelemetryState, TelemetryDegraded: flow.TelemetryDegraded,
		FlowDropRatio: flow.DropRatio, FlowRingDropsDelta: flow.RingDropsDelta,
		FlowEmittedDelta: flow.EmittedDelta, FlowDrainLagSeconds: flow.DrainLagSeconds,
	}
}

// styxEnforcementActive reports only what the kernel sync actually applied: an
// applied (or partially applied/degraded) revision with a non-off global mode.
func styxEnforcementActive(sync StyxSyncStatus) bool {
	if !sync.Enabled || sync.Mode == StyxModeOff || sync.Mode == "" {
		return false
	}
	switch sync.State {
	case StyxSyncStateApplied, StyxSyncStateDegraded:
		return true
	default:
		return false
	}
}

// StyxPolicyStatus returns the structured sync status, or an honest unavailable
// state when no syncer is attached.
func (e *XDREngine) StyxPolicyStatus() StyxSyncStatus {
	if e == nil || e.styxPolicy == nil {
		return StyxSyncStatus{State: StyxSyncStateUnavailable, Capability: styxCapabilityUnknown}
	}
	return e.styxPolicy.Snapshot()
}

// StyxBeaconSnapshot returns the detector's bounded snapshot. The detector handles
// a nil receiver, so an engine without a detector simply reports unavailable.
func (e *XDREngine) StyxBeaconSnapshot() StyxBeaconSnapshot {
	if e == nil || e.styxBeacon == nil {
		return StyxBeaconSnapshot{SensorState: "unavailable", DNSObservation: "unknown", RxObservation: "unavailable"}
	}
	return e.styxBeacon.Snapshot()
}

// StyxStatusView is the GET /api/v1/styx/status payload: the sync state, the
// kernel flow health and the detector's bounded sensor state in one read-only view.
type StyxStatusView struct {
	State             string             `json:"state"`
	SensorState       string             `json:"sensor_state"`
	Capability        string             `json:"capability"`
	EnforcementActive bool               `json:"enforcement_active"`
	TelemetryState    string             `json:"telemetry_state"`
	TelemetryDegraded bool               `json:"telemetry_degraded"`
	Sync              StyxSyncStatus     `json:"sync"`
	Flow              StyxFlowMetrics    `json:"flow"`
	KernelHealth      CoreStyxFlowHealth `json:"kernel_health"`
	KernelHealthAt    *time.Time         `json:"kernel_health_at,omitempty"`
	KernelHealthError string             `json:"kernel_health_error,omitempty"`
	Beacon            StyxBeaconView     `json:"beacon"`
	GoRuleCount       int                `json:"go_rule_count"`
	GoRuleDrops       uint64             `json:"go_rule_drops"`
	GoRuleMetadata    uint64             `json:"go_rule_metadata_hits"`
}

// StyxBeaconsView is the GET /api/v1/styx/beacons payload. It carries the same
// bounded detector projection and no per-flow history beyond the detector's Top 10.
type StyxBeaconsView struct {
	State             string             `json:"state"`
	SensorState       string             `json:"sensor_state"`
	Capability        string             `json:"capability"`
	EnforcementActive bool               `json:"enforcement_active"`
	TelemetryState    string             `json:"telemetry_state"`
	TelemetryDegraded bool               `json:"telemetry_degraded"`
	SyncState         string             `json:"sync_state"`
	Epoch             string             `json:"epoch,omitempty"`
	Beacon            StyxBeaconView     `json:"beacon"`
	Flow              StyxFlowMetrics    `json:"flow"`
	KernelHealth      CoreStyxFlowHealth `json:"kernel_health"`
	KernelHealthAt    *time.Time         `json:"kernel_health_at,omitempty"`
	KernelHealthError string             `json:"kernel_health_error,omitempty"`
}
