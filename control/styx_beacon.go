// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T2: STYX_BEACON detector (docs/POINT3-EGRESS-BEACON.md §8.2).
// Passive Phase-1 sensor: no response, no fake DNS/rx claims, mode=off reports off.
import (
	"container/list"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxTrackedBeaconFlows = 8192
	MaxFlowsPerCgroup     = 64
	FlowTTLSeconds        = 900
	MaxIncidentsPerMinute = 6
	DedupeSeconds         = 300
)
const (
	StyxBeaconEventPeriodicity = "BEACON_PERIODICITY"
	StyxBeaconEventAsymmetry   = "EXFIL_ASYMMETRY"
	StyxBeaconEventDirectIP    = "DIRECT_IP_NO_DNS"
	StyxBeaconRulePeriodicity  = "STYX.BEACON.PERIODIC"
	StyxBeaconRuleAsymmetry    = "STYX.EXFIL.ASYMMETRY"
	StyxBeaconRuleDirectIP     = "STYX.EGRESS.DIRECT_IP"
	styxBeaconSensorName       = "STYX_BEACON"
)

type StyxBeaconConfig struct {
	Enabled             bool
	Mode                string
	FlowCapabilityKnown bool
	// RxObservationAvailable=false in Phase 1: no ingress deltas => no ratio claim.
	// Phase 2 keeps this Phase-1 gate untouched: the beacon detector still does
	// not pair ingress deltas into its egress aggregates, so the asymmetry rule
	// must not claim a ratio. The *capability* fact (the AP-6 cgroup_skb/ingress
	// observer is attached and is the source of the phase-2 PCR telemetry) is
	// reported separately through RxObservationCapability; it only enriches
	// incident metadata/reporting and never changes a score or a decision.
	RxObservationAvailable, DNSObservationAvailable bool
	RxObservationCapability                         bool
	ResolverPrefixes                                []netip.Prefix
	CanaryCorrelation                               func(cgroupID uint64, pid int, since time.Time) bool
	Now                                             func() time.Time
	PruneInterval                                   time.Duration
}
type beaconFlowKey struct {
	cgroupID uint64
	pid      int
	uid      uint32
	family   uint8
	proto    uint8
	dstIP    netip.Addr
	dstPort  uint16
}
type beaconAggregate struct {
	key                      beaconFlowKey
	comm                     string
	lastSeen                 time.Time
	lastTSNS                 uint64
	samples                  int64
	intervalMean, intervalM2 float64
	txBytes, rxBytes         uint64
	lastDNSSeen              bool
	lastScore                int
	lastSignals, lastRules   []string
	lastEvent, lastCategory  string
	lastDecision             string
}
type StyxBeaconEngine struct {
	mu                                                                      sync.Mutex
	cfg                                                                     StyxBeaconConfig
	correlator                                                              *IncidentCorrelator
	sink                                                                    func(XDRIncident) error
	flows                                                                   map[beaconFlowKey]*list.Element
	order                                                                   *list.List // front = most recent, back = LRU victim
	perCgroup                                                               map[uint64]int
	dedupe                                                                  map[string]time.Time
	incidents                                                               []time.Time
	degraded                                                                bool
	overflowPolls, cleanPolls                                               int
	events, emittedIncidents, suppressed, dropped, overflowRecords, evicted uint64
}
type StyxBeaconFlowSnapshot struct {
	CgroupID uint64   `json:"cgroup_id"`
	PID      int      `json:"pid"`
	Remote   string   `json:"remote"`
	TxBytes  uint64   `json:"tx_bytes"`
	RxBytes  uint64   `json:"rx_bytes"`
	Score    int      `json:"score"`
	Signals  []string `json:"signals,omitempty"`
	Comm     string   `json:"comm,omitempty"`
}
type StyxBeaconSnapshot struct {
	SensorState, DNSObservation                       string
	Flows                                             int
	Top                                               []StyxBeaconFlowSnapshot
	Events, Incidents, Suppressed, Dropped, Overflows uint64
	// RxObservation is the AP-6 ingress RX capability fact ("available" /
	// "unavailable"); it is reporting metadata only and does not change the
	// Phase-1 asymmetry gate.
	RxObservation string
}

func NewStyxBeaconEngine(cfg StyxBeaconConfig, correlator *IncidentCorrelator, sink func(XDRIncident) error) *StyxBeaconEngine {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.PruneInterval <= 0 {
		cfg.PruneInterval = 5 * time.Second
	}
	return &StyxBeaconEngine{
		cfg: cfg, correlator: correlator, sink: sink,
		flows:     make(map[beaconFlowKey]*list.Element),
		order:     list.New(),
		perCgroup: make(map[uint64]int),
		dedupe:    make(map[string]time.Time),
	}
}

func (b *StyxBeaconEngine) SensorState() string {
	if b == nil {
		return "unavailable"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sensorStateLocked()
}

// SetRxObservationCapability records the AP-6 ingress RX capability fact
// (additive, V6.3.0). It is reporting metadata only: the Phase-1
// `RxObservationAvailable` asymmetry gate is intentionally NOT changed by it,
// because the beacon detector still does not pair inbound deltas into its
// egress aggregates. The phase-2 PCR engine is the consumer of real RX data.
func (b *StyxBeaconEngine) SetRxObservationCapability(available bool) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.cfg.RxObservationCapability = available
	b.mu.Unlock()
}

// styxRxObservationText renders the capability fact for incident metadata and
// snapshots.
func styxRxObservationText(available bool) string {
	if available {
		return "available"
	}
	return "unavailable"
}

func (b *StyxBeaconEngine) sensorStateLocked() string {
	if !b.cfg.Enabled || !b.cfg.FlowCapabilityKnown {
		return "unavailable"
	}
	if !(b.cfg.Mode == StyxModeMonitor || b.cfg.Mode == StyxModeEnforce) {
		// §6.1: mode=off short-circuits the kernel hook before flow logging.
		return "off"
	}
	if b.degraded {
		return "degraded"
	}
	return "active"
}

func (b *StyxBeaconEngine) RecordFlows(events []CoreStyxFlowEvent) []XDRIncident {
	if b == nil || len(events) == 0 {
		return nil
	}
	now := b.cfg.Now().UTC()
	b.mu.Lock()
	if !b.cfg.Enabled || !b.cfg.FlowCapabilityKnown || !(b.cfg.Mode == StyxModeMonitor || b.cfg.Mode == StyxModeEnforce) {
		b.mu.Unlock()
		return nil
	}
	b.events += uint64(len(events))
	incidents := make([]XDRIncident, 0, 1)
	for i := range events {
		if incident, ok := b.observeLocked(events[i], now); ok {
			incidents = append(incidents, incident)
		}
	}
	b.pruneLocked(now)
	b.mu.Unlock()
	for _, incident := range incidents {
		if b.sink != nil {
			_ = b.sink(incident)
		}
	}
	return incidents
}
func (b *StyxBeaconEngine) observeLocked(event CoreStyxFlowEvent, now time.Time) (XDRIncident, bool) {
	address, addressOK := netip.AddrFromSlice(event.DstIP)
	if (event.Family != 4 && event.Family != 6) || (event.Proto != 0 && event.Proto != 6 && event.Proto != 17) ||
		(event.Direction != 1 && event.Direction != 2) || event.Verdict > 5 || event.Packets == 0 || event.PID < 0 {
		b.dropped++
		return XDRIncident{}, false
	}
	address = address.Unmap()
	if !addressOK || !address.IsValid() || address.IsUnspecified() || (event.Family == 4) != address.Is4() {
		b.dropped++
		return XDRIncident{}, false
	}
	if isIgnoredNonExternalFlow(event, address) {
		return XDRIncident{}, false
	}
	key := beaconFlowKey{cgroupID: event.CgroupID, pid: event.PID, uid: event.UID,
		family: event.Family, proto: event.Proto, dstIP: address, dstPort: event.DstPort}
	element, exists := b.flows[key]
	if !exists {
		if b.perCgroup[key.cgroupID] >= MaxFlowsPerCgroup {
			b.dropped++
			return XDRIncident{}, false
		}
		if b.order.Len() >= MaxTrackedBeaconFlows {
			if victim := b.order.Back(); victim != nil {
				b.removeLocked(victim)
				b.evicted++
			}
		}
		element = b.order.PushFront(&beaconAggregate{key: key, lastSeen: now})
		b.flows[key] = element
		b.perCgroup[key.cgroupID]++
	}
	aggregate := element.Value.(*beaconAggregate)
	b.order.MoveToFront(element)
	b.updateLocked(aggregate, event, now)
	if !b.evaluateLocked(aggregate, now) {
		return XDRIncident{}, false
	}
	return b.buildIncidentLocked(aggregate, now), true
}
func (b *StyxBeaconEngine) updateLocked(aggregate *beaconAggregate, event CoreStyxFlowEvent, now time.Time) {
	aggregate.lastSeen = now
	if aggregate.comm == "" {
		aggregate.comm = sanitizeBeaconComm(event.Comm)
	}
	if event.TimestampNS > 0 {
		if aggregate.lastTSNS > 0 && event.TimestampNS > aggregate.lastTSNS {
			if deltaNS := event.TimestampNS - aggregate.lastTSNS; deltaNS <= uint64(24*time.Hour) {
				aggregate.addInterval(float64(deltaNS) / float64(time.Second))
			}
		}
		aggregate.lastTSNS = event.TimestampNS
	}
	// The kernel emits WINDOW DELTAS (FLOW_AGG_TX/RX reset after every emit), so
	// the flow volume is the saturating delta sum - never a per-emit maximum.
	aggregate.txBytes = saturatingAdd(aggregate.txBytes, event.TxBytes)
	aggregate.rxBytes = saturatingAdd(aggregate.rxBytes, event.RxBytes)
	if b.cfg.DNSObservationAvailable && slices.ContainsFunc(b.cfg.ResolverPrefixes, func(prefix netip.Prefix) bool { return prefix.Contains(aggregate.key.dstIP) }) {
		aggregate.lastDNSSeen = true
	}
}
func saturatingAdd(left, right uint64) uint64 {
	if sum := left + right; sum >= left {
		return sum
	}
	return ^uint64(0) // true overflow: the sum wrapped below the left operand
}

func (aggregate *beaconAggregate) addInterval(seconds float64) {
	if seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return
	}
	aggregate.samples++
	delta := seconds - aggregate.intervalMean
	aggregate.intervalMean += delta / float64(aggregate.samples)
	aggregate.intervalM2 += delta * (seconds - aggregate.intervalMean)
}
func (aggregate *beaconAggregate) cv() float64 {
	if aggregate.samples < 2 || aggregate.intervalMean <= 0 {
		return math.Inf(1)
	}
	variance := aggregate.intervalM2 / float64(aggregate.samples)
	if variance <= 0 {
		return 0
	}
	return math.Sqrt(variance) / aggregate.intervalMean
}

func (b *StyxBeaconEngine) evaluateLocked(aggregate *beaconAggregate, now time.Time) bool {
	signals := make([]string, 0, 3)
	rules := make([]string, 0, 3)
	category, eventType := "COMMAND_AND_CONTROL", ""
	bestScore := 0
	if aggregate.samples >= 12 && aggregate.cv() <= 0.30 && aggregate.intervalMean >= 10 && aggregate.intervalMean <= 3600 {
		signals = append(signals, StyxBeaconEventPeriodicity)
		rules = append(rules, StyxBeaconRulePeriodicity)
		bestScore, eventType = 120, StyxBeaconEventPeriodicity
	}
	// Signal 2 is fail-closed without rx telemetry (Phase 1): a tx/rx ratio is
	// not proveable, so high egress volume only counts WITH a canary correlation.
	asymmetry, asymmetryScore := false, 200
	if b.cfg.RxObservationAvailable {
		if aggregate.txBytes >= 524288 {
			if aggregate.rxBytes == 0 {
				asymmetry = aggregate.samples >= 8 && aggregate.txBytes >= 1<<20
			} else {
				asymmetry = aggregate.txBytes/aggregate.rxBytes >= 8
			}
		}
		if asymmetry && b.cfg.CanaryCorrelation != nil && b.cfg.CanaryCorrelation(aggregate.key.cgroupID, aggregate.key.pid, now.Add(-FlowTTLSeconds*time.Second)) {
			asymmetryScore = 250
		}
	} else if aggregate.txBytes >= 1<<20 && aggregate.samples >= 8 && b.cfg.CanaryCorrelation != nil && b.cfg.CanaryCorrelation(aggregate.key.cgroupID, aggregate.key.pid, now.Add(-FlowTTLSeconds*time.Second)) {
		asymmetry = true
	}
	if asymmetry {
		signals = append(signals, StyxBeaconEventAsymmetry)
		rules = append(rules, StyxBeaconRuleAsymmetry)
		category = "EXFILTRATION"
		if asymmetryScore > bestScore {
			bestScore, eventType = asymmetryScore, StyxBeaconEventAsymmetry
		}
	}
	// Signal 3 is dead in Phase 1: no DNS attribution exists, so it may never fire.
	if b.cfg.DNSObservationAvailable && !aggregate.lastDNSSeen && !slices.ContainsFunc(b.cfg.ResolverPrefixes, func(prefix netip.Prefix) bool { return prefix.Contains(aggregate.key.dstIP) }) && aggregate.txBytes >= 65536 {
		signals = append(signals, StyxBeaconEventDirectIP)
		rules = append(rules, StyxBeaconRuleDirectIP)
		if 80 > bestScore {
			bestScore, eventType = 80, StyxBeaconEventDirectIP
		}
	}
	aggregate.lastSignals = append(aggregate.lastSignals[:0], signals...)
	aggregate.lastScore = 0
	if len(signals) == 0 {
		return false
	}
	score, decision := bestScore, "alert"
	if len(signals) >= 2 {
		score, decision = 250, "contain"
	}
	aggregate.lastScore, aggregate.lastRules = score, rules
	aggregate.lastEvent, aggregate.lastCategory, aggregate.lastDecision = eventType, category, decision
	if b.degraded {
		b.suppressed++
		return false
	}
	if !b.claimIncidentLocked(now, aggregate.key, rules) {
		b.suppressed++
		return false
	}
	b.emittedIncidents++
	return true
}

func (b *StyxBeaconEngine) claimIncidentLocked(now time.Time, key beaconFlowKey, rules []string) bool {
	fingerprint := fmt.Sprintf("styx-beacon:%d:%d:%d:%d:%s:%d:%s",
		key.cgroupID, key.pid, key.family, key.proto, key.dstIP.String(), key.dstPort, strings.Join(rules, ","))
	if until, exists := b.dedupe[fingerprint]; exists && now.Before(until) {
		return false
	}
	kept := b.incidents[:0]
	for _, stamp := range b.incidents {
		if stamp.After(now.Add(-time.Minute)) {
			kept = append(kept, stamp)
		}
	}
	b.incidents = kept
	if len(b.incidents) >= MaxIncidentsPerMinute {
		return false
	}
	b.incidents = append(b.incidents, now)
	b.dedupe[fingerprint] = now.Add(DedupeSeconds * time.Second)
	return true
}

func (b *StyxBeaconEngine) buildIncidentLocked(aggregate *beaconAggregate, now time.Time) XDRIncident {
	key := aggregate.key
	remote := netip.AddrPortFrom(key.dstIP, key.dstPort).String()
	process := aggregate.comm
	if process == "" {
		process = "unknown"
	}
	actor := fmt.Sprintf("PID:%d|%s", key.pid, process)
	severity := "high"
	if aggregate.lastScore >= 250 {
		severity = "critical"
	}
	incidentID := fmt.Sprintf("INC-STYX-BEACON-%d-%d", now.UnixNano(), aggregate.lastScore)
	node := AttackStoryNode{
		NodeID: fmt.Sprintf("node-styx-beacon-%d", now.UnixNano()), Timestamp: now,
		Sensor: styxBeaconSensorName, Category: aggregate.lastCategory, EventType: aggregate.lastEvent,
		EntityID: remote, Actor: actor, Severity: severity, Confidence: 90,
		CausalEdge: EdgeEgressAttempted, EventUUID: incidentID,
		Metadata: map[string]string{
			"target_ip": key.dstIP.String(), "cgroup_id": strconv.FormatUint(key.cgroupID, 10),
			"signals":        strings.Join(aggregate.lastSignals, ","),
			"rx_observation": styxRxObservationText(b.cfg.RxObservationCapability),
		},
	}
	var storyNodes []AttackStoryNode
	var evidenceRoot string
	if b.correlator != nil {
		if graph, _, err := b.correlator.IngestEvent(now, actor, styxBeaconSensorName, aggregate.lastCategory, node); err == nil && graph != nil {
			storyNodes = graph.CloneNodes()
			evidenceRoot = graph.EvidenceRoot()
		}
	}
	if len(storyNodes) == 0 {
		storyNodes = []AttackStoryNode{node}
		evidenceRoot = node.ComputeNodeDigest()
	}
	summary := fmt.Sprintf("Styx beacon/exfiltration evidence: pid=%d comm=%s remote=%s signals=%s tx=%d rx=%d samples=%d score=%d",
		key.pid, process, remote, strings.Join(aggregate.lastSignals, "+"),
		aggregate.txBytes, aggregate.rxBytes, aggregate.samples, aggregate.lastScore)
	if !b.cfg.RxObservationAvailable && slices.Contains(aggregate.lastRules, StyxBeaconRuleAsymmetry) {
		summary += " (rx telemetry unavailable; volume+canary correlation, no ratio claim)"
	}
	return XDRIncident{
		ID: incidentID, Time: now, Severity: severity, Score: aggregate.lastScore, ResponseScore: aggregate.lastScore,
		PID: key.pid, UID: key.uid, CellCgroupID: key.cgroupID, SocketFamily: int32(key.family),
		Process: process, Remote: remote, Summary: summary,
		RuleIDs: aggregate.lastRules, Categories: []string{"command_and_control", "exfiltration"},
		Decision: aggregate.lastDecision, Action: "none",
		Outcome:     "recorded by the StyX beacon detector; no active response from this sensor",
		AttackStory: storyNodes, EvidenceRoot: evidenceRoot,
	}
}

func (b *StyxBeaconEngine) RecordFlowPoll(dropped uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.overflowRecords += dropped
	if dropped == 0 {
		b.overflowPolls = 0
		b.cleanPolls++
		if b.degraded && b.cleanPolls >= 3 {
			b.degraded = false
		}
		return
	}
	b.cleanPolls = 0
	b.overflowPolls++
	if b.overflowPolls >= 3 {
		b.degraded = true
	}
}

func (b *StyxBeaconEngine) Prune(now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(now.UTC())
}
func (b *StyxBeaconEngine) pruneLocked(now time.Time) {
	cutoff := now.Add(-FlowTTLSeconds * time.Second)
	for element := b.order.Back(); element != nil; {
		previous := element.Prev()
		if aggregate := element.Value.(*beaconAggregate); aggregate.lastSeen.Before(cutoff) {
			b.removeLocked(element)
		}
		element = previous
	}
	for fingerprint, until := range b.dedupe {
		if !now.Before(until) {
			delete(b.dedupe, fingerprint)
		}
	}
	kept := b.incidents[:0]
	for _, stamp := range b.incidents {
		if stamp.After(now.Add(-time.Minute)) {
			kept = append(kept, stamp)
		}
	}
	b.incidents = kept
}
func (b *StyxBeaconEngine) removeLocked(element *list.Element) {
	aggregate := element.Value.(*beaconAggregate)
	b.order.Remove(element)
	delete(b.flows, aggregate.key)
	if count := b.perCgroup[aggregate.key.cgroupID]; count > 1 {
		b.perCgroup[aggregate.key.cgroupID] = count - 1
	} else {
		delete(b.perCgroup, aggregate.key.cgroupID)
	}
}

func (b *StyxBeaconEngine) Snapshot() StyxBeaconSnapshot {
	if b == nil {
		return StyxBeaconSnapshot{SensorState: "unavailable", DNSObservation: "unknown", RxObservation: "unavailable"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	snapshot := StyxBeaconSnapshot{
		SensorState: b.sensorStateLocked(), DNSObservation: "unknown",
		RxObservation: styxRxObservationText(b.cfg.RxObservationCapability),
		Flows:         len(b.flows),
		Events:        b.events, Incidents: b.emittedIncidents, Suppressed: b.suppressed, Dropped: b.dropped,
		Overflows: b.overflowRecords,
	}
	if b.cfg.DNSObservationAvailable {
		snapshot.DNSObservation = "known"
	}
	top := make([]StyxBeaconFlowSnapshot, 0, 10)
	for element := b.order.Front(); element != nil; element = element.Next() {
		aggregate := element.Value.(*beaconAggregate)
		if aggregate.lastScore <= 0 {
			continue
		}
		top = append(top, StyxBeaconFlowSnapshot{
			CgroupID: aggregate.key.cgroupID, PID: aggregate.key.pid,
			Remote:  netip.AddrPortFrom(aggregate.key.dstIP, aggregate.key.dstPort).String(),
			TxBytes: aggregate.txBytes, RxBytes: aggregate.rxBytes, Score: aggregate.lastScore,
			Signals: append([]string(nil), aggregate.lastSignals...), Comm: sanitizeBeaconComm(aggregate.comm),
		})
	}
	sort.SliceStable(top, func(i, j int) bool {
		if top[i].Score != top[j].Score {
			return top[i].Score > top[j].Score
		}
		return top[i].TxBytes > top[j].TxBytes
	})
	if len(top) > 10 {
		top = top[:10]
	}
	snapshot.Top = top
	return snapshot
}

// isIgnoredNonExternalFlow suppresses local IPC (loopback), link-local/multicast,
// and unattributable kernel softirq/timer retransmits (`pid=0` / `swapper/*` / port 0)
// that otherwise aggregate unrelated timer packets into false BEACON_PERIODICITY hits.
func isIgnoredNonExternalFlow(event CoreStyxFlowEvent, address netip.Addr) bool {
	if address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return true
	}
	if event.PID == 0 || event.Proto == 0 || event.DstPort == 0 {
		return true
	}
	return strings.HasPrefix(sanitizeBeaconComm(event.Comm), "swapper/")
}

func sanitizeBeaconComm(comm string) string {
	if comm == "" || len(comm) > 16 || strings.IndexFunc(comm, func(character rune) bool {
		return character < 0x20 || character == 0x7f || character == ' '
	}) >= 0 {
		return ""
	}
	return comm
}
