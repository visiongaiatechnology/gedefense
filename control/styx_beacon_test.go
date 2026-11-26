// STATUS: DIAMANT VGT SUPREME
package main

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type beaconTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *beaconTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *beaconTestClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

func newBeaconTestClock() *beaconTestClock {
	return &beaconTestClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// activeBeaconConfig models a fully instrumented sensor: flow telemetry plus
// observed rx bytes, so the ratio branch of signal 2 is admissible. Production
// projection (applyStyxBeaconSettings) keeps the Phase-1 capabilities false;
// the honesty tests override RxObservationAvailable instead of weakening this.
func activeBeaconConfig() StyxBeaconConfig {
	return StyxBeaconConfig{Enabled: true, Mode: StyxModeMonitor, FlowCapabilityKnown: true, RxObservationAvailable: true}
}

func newBeaconTestEngine(t *testing.T, cfg StyxBeaconConfig, clock *beaconTestClock, sink func(XDRIncident) error) *StyxBeaconEngine {
	t.Helper()
	if clock != nil {
		cfg.Now = clock.Now
	}
	return NewStyxBeaconEngine(cfg, NewIncidentCorrelator(0), sink)
}

func beaconEvent(cgroup uint64, pid int, tsNS, tx, rx uint64, packets uint32, dst string, port uint16, family, proto uint8) CoreStyxFlowEvent {
	ip := net.ParseIP(dst)
	if family == 4 && ip != nil {
		ip = ip.To4()
	}
	return CoreStyxFlowEvent{
		CgroupID: cgroup, TimestampNS: tsNS, TxBytes: tx, RxBytes: rx, PID: pid, UID: 1000,
		DstIP: ip, DstPort: port, SrcPort: 40000, Packets: packets,
		Family: family, Proto: proto, Direction: 1, Comm: "curl",
	}
}

func feedBeaconEvents(engine *StyxBeaconEngine, clock *beaconTestClock, events []CoreStyxFlowEvent) []XDRIncident {
	var incidents []XDRIncident
	for _, event := range events {
		incidents = append(incidents, engine.RecordFlows([]CoreStyxFlowEvent{event})...)
		if clock != nil {
			clock.Advance(time.Second)
		}
	}
	return incidents
}

func periodicBeaconEvents(interval time.Duration, count int, tx, rx uint64) []CoreStyxFlowEvent {
	events := make([]CoreStyxFlowEvent, 0, count)
	for i := 0; i < count; i++ {
		events = append(events, beaconEvent(1, 10, 1_000_000_000+uint64(interval)*uint64(i), tx, rx, 1, "203.0.113.77", 443, 4, 6))
	}
	return events
}

func beaconRuleIDsContain(incident XDRIncident, want string) bool {
	for _, ruleID := range incident.RuleIDs {
		if ruleID == want {
			return true
		}
	}
	return false
}

func TestStyxBeaconPeriodicityCVBoundaries(t *testing.T) {
	cases := map[string]struct {
		events []CoreStyxFlowEvent
		fires  bool
	}{
		"periodic-30s":       {events: periodicBeaconEvents(30*time.Second, 13, 128, 0), fires: true},
		"boundary-min-10s":   {events: periodicBeaconEvents(10*time.Second, 13, 128, 0), fires: true},
		"below-min-9.5s":     {events: periodicBeaconEvents(9_500*time.Millisecond, 13, 128, 0), fires: false},
		"boundary-max-3600s": {events: periodicBeaconEvents(3600*time.Second, 13, 128, 0), fires: true},
		"above-max-3601s":    {events: periodicBeaconEvents(3601*time.Second, 13, 128, 0), fires: false},
		"too-few-samples":    {events: periodicBeaconEvents(30*time.Second, 12, 128, 0), fires: false},
		"high-cv-jitter":     {events: jitteredBeaconEvents(), fires: false},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			engine := newBeaconTestEngine(t, activeBeaconConfig(), newBeaconTestClock(), nil)
			incidents := feedBeaconEvents(engine, newBeaconTestClock(), testCase.events)
			if !testCase.fires {
				if len(incidents) != 0 {
					t.Fatalf("unexpected incident: %#v", incidents[0])
				}
				return
			}
			if len(incidents) != 1 {
				t.Fatalf("expected exactly one deduped periodicity incident, got %d", len(incidents))
			}
			incident := incidents[0]
			if incident.Score != 120 || incident.Decision != "alert" || incident.Severity != "high" {
				t.Fatalf("unexpected periodicity incident: score=%d decision=%s severity=%s", incident.Score, incident.Decision, incident.Severity)
			}
			if !beaconRuleIDsContain(incident, StyxBeaconRulePeriodicity) {
				t.Fatalf("missing periodicity rule: %v", incident.RuleIDs)
			}
			assertBeaconStoryNode(t, incident, StyxBeaconEventPeriodicity)
		})
	}
}

func jitteredBeaconEvents() []CoreStyxFlowEvent {
	events := make([]CoreStyxFlowEvent, 0, 14)
	ts := uint64(1_000_000_000)
	for i := 0; i < 13; i++ {
		events = append(events, beaconEvent(1, 10, ts, 128, 0, 1, "203.0.113.77", 443, 4, 6))
		if i%2 == 0 {
			ts += uint64(10 * time.Second)
		} else {
			ts += uint64(300 * time.Second)
		}
	}
	return events
}

func TestStyxBeaconModeOffIsNotActive(t *testing.T) {
	event := beaconEvent(1, 10, 1_000_000_000, 1<<20, 65536, 64, "198.51.100.61", 443, 4, 6)
	cases := map[string]struct {
		mode     string
		want     string
		incident bool
	}{
		"off":     {mode: StyxModeOff, want: "off", incident: false},
		"empty":   {mode: "", want: "off", incident: false},
		"monitor": {mode: StyxModeMonitor, want: "active", incident: true},
		"enforce": {mode: StyxModeEnforce, want: "active", incident: true},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			config := activeBeaconConfig()
			config.Mode = testCase.mode
			engine := newBeaconTestEngine(t, config, nil, nil)
			if state := engine.SensorState(); state != testCase.want {
				t.Fatalf("mode %q reports sensor state %q, want %q", testCase.mode, state, testCase.want)
			}
			incidents := engine.RecordFlows([]CoreStyxFlowEvent{event})
			if testCase.incident && len(incidents) != 1 {
				t.Fatalf("mode %q did not process flows: %d incidents", testCase.mode, len(incidents))
			}
			if !testCase.incident && len(incidents) != 0 {
				t.Fatalf("mode %q processed flows although the kernel logs none", testCase.mode)
			}
		})
	}
}

func assertBeaconStoryNode(t *testing.T, incident XDRIncident, wantEventType string) {
	t.Helper()
	if len(incident.AttackStory) == 0 {
		t.Fatal("incident carries no attack story node")
	}
	if incident.EvidenceRoot == "" {
		t.Fatal("incident evidence root is empty")
	}
	node := incident.AttackStory[len(incident.AttackStory)-1]
	if node.Sensor != styxBeaconSensorName || node.EventType != wantEventType {
		t.Fatalf("unexpected story node sensor/event: %q/%q", node.Sensor, node.EventType)
	}
	if node.CausalEdge != EdgeEgressAttempted {
		t.Fatalf("story node causal edge = %q, want %q", node.CausalEdge, EdgeEgressAttempted)
	}
	if node.Digest == "" && len(incident.AttackStory) == 1 {
		t.Fatal("story node digest is empty")
	}
}

func TestStyxBeaconDirectIPRequiresKnownDNS(t *testing.T) {
	event := beaconEvent(1, 10, 1_000_000_000, 1<<20, 1<<20, 64, "203.0.113.88", 443, 4, 6)

	engine := newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{event}); len(incidents) != 0 {
		t.Fatalf("direct-IP signal fired while DNS telemetry is unknown: %#v", incidents[0])
	}
	if engine.Snapshot().DNSObservation != "unknown" {
		t.Fatal("snapshot claims DNS observation without a capability")
	}

	knownConfig := activeBeaconConfig()
	knownConfig.DNSObservationAvailable = true
	engine = newBeaconTestEngine(t, knownConfig, nil, nil)
	incidents := engine.RecordFlows([]CoreStyxFlowEvent{event})
	if len(incidents) != 1 || incidents[0].Score != 80 || !beaconRuleIDsContain(incidents[0], StyxBeaconRuleDirectIP) {
		t.Fatalf("direct-IP signal did not fire with known DNS telemetry: %#v", incidents)
	}
	if engine.Snapshot().DNSObservation != "known" {
		t.Fatal("snapshot hides the injected DNS capability")
	}

	allowlistedConfig := knownConfig
	allowlistedConfig.ResolverPrefixes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	engine = newBeaconTestEngine(t, allowlistedConfig, nil, nil)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{event}); len(incidents) != 0 {
		t.Fatalf("resolver-allowlisted destination was flagged as direct-IP: %#v", incidents[0])
	}
}

func TestStyxBeaconCombinationEmitsContainIncident(t *testing.T) {
	var captured []XDRIncident
	var capturedMu sync.Mutex
	config := activeBeaconConfig()
	config.DNSObservationAvailable = true
	engine := newBeaconTestEngine(t, config, nil, func(incident XDRIncident) error {
		capturedMu.Lock()
		captured = append(captured, incident)
		capturedMu.Unlock()
		return nil
	})
	clock := newBeaconTestClock()
	event := beaconEvent(42, 4711, 1_000_000_000, 1<<20, 65536, 512, "198.51.100.66", 8443, 4, 6)
	incidents := engine.RecordFlows([]CoreStyxFlowEvent{event})
	if len(incidents) != 1 {
		t.Fatalf("expected one combined incident, got %d", len(incidents))
	}
	_ = clock
	incident := incidents[0]
	if incident.Score != 250 || incident.ResponseScore != 250 || incident.Decision != "contain" || incident.Severity != "critical" {
		t.Fatalf("unexpected combined incident: score=%d response=%d decision=%s severity=%s",
			incident.Score, incident.ResponseScore, incident.Decision, incident.Severity)
	}
	if incident.CellCgroupID != 42 || incident.PID != 4711 || incident.Process != "curl" || incident.Remote != "198.51.100.66:8443" {
		t.Fatalf("unexpected identity fields: %#v", incident)
	}
	if !beaconRuleIDsContain(incident, StyxBeaconRuleAsymmetry) || !beaconRuleIDsContain(incident, StyxBeaconRuleDirectIP) {
		t.Fatalf("combined incident lacks signal rules: %v", incident.RuleIDs)
	}
	categories := map[string]bool{}
	for _, category := range incident.Categories {
		categories[category] = true
	}
	if !categories["command_and_control"] || !categories["exfiltration"] {
		t.Fatalf("combined incident lacks §8.2 categories: %v", incident.Categories)
	}
	assertBeaconStoryNode(t, incident, StyxBeaconEventAsymmetry)
	capturedMu.Lock()
	defer capturedMu.Unlock()
	if len(captured) != 1 || captured[0].ID != incident.ID {
		t.Fatalf("sink did not receive exactly the emitted incident: %d", len(captured))
	}
}

func TestStyxBeaconDedupeWindow(t *testing.T) {
	clock := newBeaconTestClock()
	engine := newBeaconTestEngine(t, activeBeaconConfig(), clock, nil)
	first := beaconEvent(1, 10, 1_000_000_000, 1<<20, 65536, 100, "203.0.113.9", 443, 4, 6)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{first}); len(incidents) != 1 {
		t.Fatalf("first asymmetry incident missing: %d", len(incidents))
	}
	clock.Advance(time.Second)
	second := first
	second.TimestampNS += uint64(time.Second)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{second}); len(incidents) != 0 {
		t.Fatalf("dedupe window did not suppress a repeat: %#v", incidents[0])
	}
	if engine.Snapshot().Suppressed == 0 {
		t.Fatal("suppressed repeat was not counted")
	}
	clock.Advance(301 * time.Second)
	third := second
	third.TimestampNS += uint64(301 * time.Second)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{third}); len(incidents) != 1 {
		t.Fatalf("dedupe window did not expire: %d", len(incidents))
	}
}

func TestStyxBeaconEscalationEmitsNewIncident(t *testing.T) {
	config := activeBeaconConfig()
	config.DNSObservationAvailable = true
	clock := newBeaconTestClock()
	engine := newBeaconTestEngine(t, config, clock, nil)
	base := beaconEvent(7, 77, 1_000_000_000, 65536, 65536, 32, "198.51.100.10", 443, 4, 6)
	first := engine.RecordFlows([]CoreStyxFlowEvent{base})
	if len(first) != 1 || first[0].Decision != "alert" {
		t.Fatalf("direct-only incident missing: %#v", first)
	}
	clock.Advance(time.Second)
	escalated := base
	escalated.TimestampNS += uint64(time.Second)
	escalated.TxBytes = 1 << 20
	second := engine.RecordFlows([]CoreStyxFlowEvent{escalated})
	if len(second) != 1 || second[0].Decision != "contain" || second[0].Score != 250 {
		t.Fatalf("escalated combined incident missing inside dedupe window: %#v", second)
	}
}

func TestStyxBeaconTTLPrune(t *testing.T) {
	clock := newBeaconTestClock()
	engine := newBeaconTestEngine(t, activeBeaconConfig(), clock, nil)
	engine.RecordFlows([]CoreStyxFlowEvent{beaconEvent(1, 10, 1_000_000_000, 100, 100, 1, "203.0.113.5", 443, 4, 6)})
	if engine.Snapshot().Flows != 1 {
		t.Fatalf("flow not tracked: %d", engine.Snapshot().Flows)
	}
	clock.Advance(899 * time.Second)
	engine.Prune(clock.Now())
	if engine.Snapshot().Flows != 1 {
		t.Fatal("flow pruned before the 900 s TTL")
	}
	clock.Advance(2 * time.Second)
	engine.Prune(clock.Now())
	if engine.Snapshot().Flows != 0 {
		t.Fatal("expired flow survived the TTL prune")
	}
}

func TestStyxBeaconCardinalityBoundsUnderConcurrency(t *testing.T) {
	engine := newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	const writers, perWriter = 8, 1250
	var waitGroup sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		waitGroup.Add(1)
		go func(writer int) {
			defer waitGroup.Done()
			for index := 0; index < perWriter; index += 25 {
				events := make([]CoreStyxFlowEvent, 0, 25)
				for offset := 0; offset < 25 && index+offset < perWriter; offset++ {
					flowID := writer*perWriter + index + offset
					events = append(events, beaconEvent(uint64(flowID+1), flowID+1, 1_000_000_000,
						1, 1, 1, "198.51.100.7", uint16(1024+flowID%60000), 4, 6))
				}
				engine.RecordFlows(events)
				_ = engine.Snapshot()
			}
		}(writer)
	}
	waitGroup.Wait()
	snapshot := engine.Snapshot()
	if snapshot.Flows > MaxTrackedBeaconFlows {
		t.Fatalf("flow cardinality unbounded: %d > %d", snapshot.Flows, MaxTrackedBeaconFlows)
	}
	if len(snapshot.Top) > 10 {
		t.Fatalf("snapshot top list unbounded: %d", len(snapshot.Top))
	}
}

func TestStyxBeaconPerCgroupCap(t *testing.T) {
	engine := newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	for port := 0; port < MaxFlowsPerCgroup+1; port++ {
		engine.RecordFlows([]CoreStyxFlowEvent{beaconEvent(9, 10, uint64(1_000_000_000+port), 1, 1, 1, "198.51.100.8", uint16(2000+port), 4, 6)})
	}
	snapshot := engine.Snapshot()
	if snapshot.Flows != MaxFlowsPerCgroup {
		t.Fatalf("per-cgroup cap violated: flows=%d want=%d", snapshot.Flows, MaxFlowsPerCgroup)
	}
	if snapshot.Dropped == 0 {
		t.Fatal("dropped observation was not counted")
	}
}

func TestStyxBeaconIncidentRateLimit(t *testing.T) {
	engine := newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	emitted := 0
	for flow := 0; flow < MaxIncidentsPerMinute+1; flow++ {
		event := beaconEvent(uint64(flow+1), flow+1, 1_000_000_000, 1<<20, 65536, 64, "198.51.100.20", uint16(4000+flow), 4, 6)
		emitted += len(engine.RecordFlows([]CoreStyxFlowEvent{event}))
	}
	if emitted != MaxIncidentsPerMinute {
		t.Fatalf("incident budget violated: emitted=%d want=%d", emitted, MaxIncidentsPerMinute)
	}
	if engine.Snapshot().Suppressed == 0 {
		t.Fatal("rate-limited incident was not counted as suppressed")
	}
}

func TestStyxBeaconDegradedSensorSuppressesEmission(t *testing.T) {
	engine := newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	for poll := 0; poll < 3; poll++ {
		engine.RecordFlowPoll(5)
	}
	if state := engine.SensorState(); state != "degraded" {
		t.Fatalf("sensor state after overflow series = %q, want degraded", state)
	}
	event := beaconEvent(1, 10, 1_000_000_000, 1<<20, 65536, 64, "198.51.100.30", 443, 4, 6)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{event}); len(incidents) != 0 {
		t.Fatalf("degraded detector emitted an incident: %#v", incidents[0])
	}
	if engine.Snapshot().Overflows != 15 {
		t.Fatal("overflow records were not counted")
	}
	for poll := 0; poll < 3; poll++ {
		engine.RecordFlowPoll(0)
	}
	if state := engine.SensorState(); state != "active" {
		t.Fatalf("sensor did not recover after clean polls: %q", state)
	}
	event.TimestampNS += uint64(time.Second)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{event}); len(incidents) != 1 {
		t.Fatal("recovered detector did not resume emission")
	}
}

func TestStyxBeaconUnavailableWithoutCapability(t *testing.T) {
	engine := newBeaconTestEngine(t, StyxBeaconConfig{}, nil, nil)
	if state := engine.SensorState(); state != "unavailable" {
		t.Fatalf("unconfigured sensor state = %q", state)
	}
	event := beaconEvent(1, 10, 1_000_000_000, 1<<20, 65536, 64, "198.51.100.31", 443, 4, 6)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{event}); len(incidents) != 0 {
		t.Fatal("unavailable detector emitted an incident")
	}
	engine = newBeaconTestEngine(t, StyxBeaconConfig{Enabled: true, FlowCapabilityKnown: false}, nil, nil)
	if state := engine.SensorState(); state != "unavailable" {
		t.Fatalf("capability-missing sensor state = %q", state)
	}
	var nilEngine *StyxBeaconEngine
	if state := nilEngine.SensorState(); state != "unavailable" {
		t.Fatalf("nil sensor state = %q", state)
	}
	if incidents := nilEngine.RecordFlows([]CoreStyxFlowEvent{event}); incidents != nil {
		t.Fatal("nil detector emitted an incident")
	}
	nilEngine.RecordFlowPoll(1)
	nilEngine.Prune(time.Now())
	_ = nilEngine.Snapshot()
}

func TestStyxBeaconMalformedEventsAreDroppedNotCrashed(t *testing.T) {
	engine := newBeaconTestEngine(t, activeBeaconConfig(), nil, nil)
	badEvents := []CoreStyxFlowEvent{
		beaconEvent(1, 10, 1_000_000_000, 100, 0, 1, "203.0.113.5", 443, 5, 6),
		beaconEvent(1, 10, 1_000_000_000, 100, 0, 1, "203.0.113.5", 443, 4, 1),
		beaconEvent(1, 10, 1_000_000_000, 100, 0, 0, "203.0.113.5", 443, 4, 6),
		beaconEvent(1, -1, 1_000_000_000, 100, 0, 1, "203.0.113.5", 443, 4, 6),
		{CgroupID: 1, TimestampNS: 1, TxBytes: 1, Packets: 1, Family: 4, Proto: 6, Direction: 1},
	}
	for _, event := range badEvents {
		engine.RecordFlows([]CoreStyxFlowEvent{event})
	}
	snapshot := engine.Snapshot()
	if snapshot.Dropped != uint64(len(badEvents)) {
		t.Fatalf("malformed events not counted: dropped=%d want=%d", snapshot.Dropped, len(badEvents))
	}
	if snapshot.Flows != 0 {
		t.Fatalf("malformed events created flows: %d", snapshot.Flows)
	}
}

// The operator projection is the only place the detector learns about settings;
// it must keep the Phase-1 capabilities false so signal 2 never claims a ratio.
func TestStyxBeaconProductionSettingsKeepPhase1CapabilitiesOff(t *testing.T) {
	engine := &XDREngine{styxBeacon: NewStyxBeaconEngine(activeBeaconConfig(), NewIncidentCorrelator(0), nil)}
	engine.setStyxBeaconCapability(true)
	runtime := defaultRuntimeSettings(defaultConfig())
	monitor := StyxFabricSettings{Enabled: true, Mode: StyxModeMonitor, LogFlows: true}
	runtime.Styx = &monitor
	engine.applyStyxBeaconSettings(runtime)
	engine.styxBeacon.mu.Lock()
	rxAvailable := engine.styxBeacon.cfg.RxObservationAvailable
	dnsAvailable := engine.styxBeacon.cfg.DNSObservationAvailable
	engine.styxBeacon.mu.Unlock()
	if rxAvailable || dnsAvailable {
		t.Fatalf("phase-1 projection claims telemetry it does not have: rx=%t dns=%t", rxAvailable, dnsAvailable)
	}
	// The integrated path therefore keeps a volume-only flow "unknown".
	engine.recordStyxFlowBatch(periodicBeaconEvents(time.Second, 13, 120*1024, 0), 0, time.Now().UTC())
	if got := engine.styxBeacon.Snapshot().Incidents; got != 0 {
		t.Fatalf("phase-1 volume-only flow produced %d incidents", got)
	}
}

func TestStyxBeaconIgnoresLoopbackLinkLocalAndKernelSwapperFlows(t *testing.T) {
	clock := newBeaconTestClock()
	engine := newBeaconTestEngine(t, activeBeaconConfig(), clock, nil)
	noiseTemplates := []struct {
		pid  int
		comm string
		ip   string
		port uint16
	}{
		{pid: 0, comm: "swapper/1", ip: "127.0.0.1", port: 20198},
		{pid: 43428, comm: "gedefense-contr", ip: "127.0.0.1", port: 443},
		{pid: 0, comm: "swapper/6", ip: "169.254.0.2", port: 0},
		{pid: 0, comm: "swapper/6", ip: "51.169.45.190", port: 0},
		{pid: 1200, comm: "systemd", ip: "51.169.45.190", port: 0},
	}
	for _, tpl := range noiseTemplates {
		for i := 0; i < 15; i++ {
			ev := beaconEvent(1, tpl.pid, 1_000_000_000+uint64(30*time.Second)*uint64(i), 1024, 0, 1, tpl.ip, tpl.port, 4, 6)
			ev.Comm = tpl.comm
			if inc := engine.RecordFlows([]CoreStyxFlowEvent{ev}); len(inc) != 0 {
				t.Fatalf("ignored noise flow %+v emitted unexpected beacon incident: %+v", tpl, inc[0])
			}
			clock.Advance(time.Second)
		}
	}
	snap := engine.Snapshot()
	if snap.Flows != 0 || snap.Incidents != 0 || len(snap.Top) != 0 || snap.Dropped != 0 {
		t.Fatalf("expected zero tracked/flagged/dropped for non-external noise, got %+v", snap)
	}
}

func TestStyxBeaconIgnoresManagementAndDefenseAllowlistFlows(t *testing.T) {
	engine := &XDREngine{
		cfg:        Config{Defense: DefenseConfig{Allowlist: []string{"198.51.100.42"}}},
		styxBeacon: NewStyxBeaconEngine(activeBeaconConfig(), NewIncidentCorrelator(0), nil),
	}
	engine.setStyxBeaconCapability(true)
	runtime := defaultRuntimeSettings(engine.cfg)
	runtime.ManagementAllowlist = []string{"10.0.2.2/32"}
	monitor := StyxFabricSettings{Enabled: true, Mode: StyxModeMonitor, LogFlows: true}
	runtime.Styx = &monitor
	engine.applyStyxBeaconSettings(runtime)
	engine.styxBeacon.mu.Lock()
	engine.styxBeacon.cfg.DNSObservationAvailable = true
	engine.styxBeacon.mu.Unlock()

	for _, ip := range []string{"10.0.2.2", "198.51.100.42"} {
		for i := 0; i < 15; i++ {
			ev := beaconEvent(1, 797, 1_000_000_000+uint64(30*time.Second)*uint64(i), 1024, 0, 1, ip, 64723, 4, 6)
			ev.Comm = "gedefense-contr"
			if inc := engine.styxBeacon.RecordFlows([]CoreStyxFlowEvent{ev}); len(inc) != 0 {
				t.Fatalf("allowlisted peer %s emitted unexpected beacon incident: %+v", ip, inc[0])
			}
		}
	}
	snap := engine.styxBeacon.Snapshot()
	if snap.Flows != 0 || snap.Incidents != 0 {
		t.Fatalf("expected allowlisted flows to be ignored, got %+v", snap)
	}
}

func TestStyxBeaconLocalHostAddressSuppressesDirectIPWithoutDisablingOtherSignals(t *testing.T) {
	config := activeBeaconConfig()
	config.DNSObservationAvailable = true
	config.LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.10/32")}
	engine := newBeaconTestEngine(t, config, newBeaconTestClock(), nil)

	// Normal volume (<1 MiB) to host's own interface IP must NOT fire DIRECT_IP_NO_DNS.
	selfEvent := beaconEvent(5753, 2609, 1_000_000_000, 190_000, 0, 12, "198.51.100.10", 8333, 4, 6)
	selfEvent.Comm = "node_daemon"
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{selfEvent}); len(incidents) != 0 {
		t.Fatalf("host-local self flow should not fire DIRECT_IP_NO_DNS: %+v", incidents[0])
	}
	if top := engine.Snapshot().Top; len(top) != 0 {
		t.Fatalf("expected zero flagged top flows for host self-traffic, got %+v", top)
	}

	// Sibling IP in the same /24 MUST still trigger DIRECT_IP_NO_DNS (host-only mask).
	siblingEvent := beaconEvent(5753, 2609, 1_000_000_000, 190_000, 0, 12, "198.51.100.11", 8333, 4, 6)
	siblingEvent.Comm = "node_daemon"
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{siblingEvent}); len(incidents) != 1 || !beaconRuleIDsContain(incidents[0], StyxBeaconRuleDirectIP) {
		t.Fatalf("sibling peer in same /24 lost DIRECT_IP_NO_DNS coverage: %+v", incidents)
	}

	// Other signals (asymmetry/periodicity) stay active even for host-local targets.
	highVolSelf := beaconEvent(5753, 2609, 2_000_000_000, 2<<20, 1024, 64, "198.51.100.10", 9000, 4, 6)
	for i := 0; i < 8; i++ {
		highVolSelf.TimestampNS += uint64(time.Second)
		_ = engine.RecordFlows([]CoreStyxFlowEvent{highVolSelf})
	}
	var sawAsymmetry bool
	for _, flow := range engine.Snapshot().Top {
		if flow.Remote == "198.51.100.10:9000" {
			sawAsymmetry = len(flow.Signals) == 1 && flow.Signals[0] == StyxBeaconEventAsymmetry
		}
	}
	if !sawAsymmetry {
		t.Fatalf("expected non-DNS asymmetry signal to remain active for host target, got top=%+v", engine.Snapshot().Top)
	}
}

func TestStyxBeaconDynamicLocalPrefixRefreshAndKernelSoftirqAntiSpoof(t *testing.T) {
	clock := newBeaconTestClock()
	hostIP := "198.51.100.50"
	config := activeBeaconConfig()
	config.DNSObservationAvailable = true
	config.LocalPrefixSource = func() []netip.Prefix {
		addr := netip.MustParseAddr(hostIP)
		return []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}
	}
	config.KernelSoftirqCheck = func(pid int) bool {
		return pid == 44
	}
	engine := newBeaconTestEngine(t, config, clock, nil)

	// Genuine ksoftirqd kernel thread (uid=0, pid=44 verified via procfs check) is ignored.
	ksoftirq := beaconEvent(5753, 44, 1_000_000_000, 80_000, 0, 8, "203.0.113.99", 20302, 4, 6)
	ksoftirq.UID = 0
	ksoftirq.Comm = "ksoftirqd/1"
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{ksoftirq}); len(incidents) != 0 {
		t.Fatalf("verified ksoftirqd thread triggered unexpected incident: %+v", incidents[0])
	}

	// Userspace process spoofing ksoftirqd/* via prctl(PR_SET_NAME) MUST NOT bypass detection.
	spoofed := beaconEvent(5753, 9999, 1_000_000_000, 80_000, 0, 8, "203.0.113.99", 20302, 4, 6)
	spoofed.UID = 0
	spoofed.Comm = "ksoftirqd/1"
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{spoofed}); len(incidents) != 1 || !beaconRuleIDsContain(incidents[0], StyxBeaconRuleDirectIP) {
		t.Fatalf("spoofed userspace ksoftirqd bypassed DIRECT_IP_NO_DNS: %+v", incidents)
	}

	// Dynamic interface change (host gains new IP after refresh interval) suppresses DIRECT_IP_NO_DNS on the new IP.
	hostIP = "198.51.100.51"
	clock.Advance(localPrefixRefreshInterval + time.Second)
	newHostEvent := beaconEvent(5753, 2609, 2_000_000_000, 120_000, 0, 8, hostIP, 8333, 4, 6)
	if incidents := engine.RecordFlows([]CoreStyxFlowEvent{newHostEvent}); len(incidents) != 0 {
		t.Fatalf("dynamic local IP refresh did not suppress DIRECT_IP_NO_DNS: %+v", incidents[0])
	}
}

func TestLocalHostInterfacePrefixesProduceHostOnlyMasks(t *testing.T) {
	prefixes := localHostInterfacePrefixes()
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.IsSingleIP() {
			t.Fatalf("local interface prefix must be a single-host mask, got %s", prefix)
		}
		if prefix.Addr().IsLoopback() || prefix.Addr().IsUnspecified() {
			t.Fatalf("unexpected loopback/unspecified address in local prefixes: %s", prefix)
		}
	}
}
