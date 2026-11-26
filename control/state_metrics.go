// STATUS: DIAMANT VGT SUPREME
// XDR status metrics, derived aggregates and stream/kinetic telemetry,
// split out of state.go (refactoring wave 1b, structure-only).
package main

import (
	"log"
	"sort"
	"strings"
	"time"
)

// SetXDREnabled publishes the operator's enablement switch.
//
// It must not write the sensor label while XDR is enabled. That label is composed by the engine from
// the individual sensors (xdrSensorMode: fanotify, eBPF exec, cgroup egress, BPF-LSM cell) and it is
// the only signal the interface has to decide whether the fanotify execution channel is flowing -
// the malware card and the integrity badge are both derived from it. This function used to overwrite
// it with a coarse "procfs+network-bounded" on every status tick; because the engine composes the
// precise label on the line before the tick calls this function, the coarse one always won. The
// integrity view then reported HANDLUNGSBEDARF and the malware card "not verified" while the Rust
// core was running with on_access=fanotify-exec. A switch is not a sensor report.
func (s *State) SetXDREnabled(enabled, networkSensor bool) {
	s.mu.Lock()
	s.xdr.Enabled = enabled
	switch {
	case !enabled:
		// Off is a definite statement about the sensor, and only this function knows it.
		s.xdr.Sensor = "disabled-by-operator"
	case s.xdr.Sensor == "" || s.xdr.Sensor == "initializing":
		// Nothing precise has been reported yet: name the fallback that the engine will refine.
		if networkSensor {
			s.xdr.Sensor = "procfs+network-bounded"
		} else {
			s.xdr.Sensor = "procfs-bounded"
		}
	}
	s.mu.Unlock()
}

func (s *State) SetXDRStatus(x XDRStatus) {
	s.mu.Lock()
	if x.IncidentsTotal == 0 {
		x.IncidentsTotal = s.xdr.IncidentsTotal
	}
	if x.ActionsTotal == 0 {
		x.ActionsTotal = s.xdr.ActionsTotal
	}
	// A fail-closed degraded state must never be erased by a routine sensor
	// status refresh. Recovery is explicit through SetXDRDegraded(false, "").
	if s.xdr.Degraded && !x.Degraded {
		x.Degraded = true
		x.DegradedReason = s.xdr.DegradedReason
	}
	s.xdr = x
	s.mu.Unlock()
}

// SetXDRRansomSensor projects the M2.2 kernel ransomware sensor without replacing
// the rest of the XDR status (other sensor refreshes only own their own fields).
func (s *State) SetXDRRansomSensor(status RansomSensorStatus) {
	s.mu.Lock()
	s.xdr.RansomSensor = status
	s.mu.Unlock()
}

// SetXDRCredentialGuard projects the M2.4 kernel credential guard.
func (s *State) SetXDRCredentialGuard(status CredentialGuardStatus) {
	s.mu.Lock()
	s.xdr.CredentialGuard = status
	s.mu.Unlock()
}

func (s *State) UpdateXDRScan(processes, connections int, at time.Time, degraded bool, reason string, protected int) {
	s.mu.Lock()
	s.xdr.Enabled = true
	s.xdr.Processes = processes
	if connections >= 0 {
		s.xdr.OpenConnections = connections
	}
	u := at.UTC()
	s.xdr.LastScan = &u
	s.xdr.Degraded = degraded
	s.xdr.DegradedReason = reason
	s.xdr.ProtectedObjects = protected
	if s.xdr.Sensor == "" || s.xdr.Sensor == "initializing" {
		s.xdr.Sensor = "procfs-fallback"
	}
	s.mu.Unlock()
}

func (s *State) UpdateXDRRuntime(queueDepth, queueCapacity int, drops, evaluations, anomalies uint64, behavior BehaviorSummary) {
	s.mu.Lock()
	s.xdr.QueueDepth = queueDepth
	s.xdr.QueueCapacity = queueCapacity
	s.xdr.EvaluationDrops = drops
	s.xdr.EvaluationsTotal = evaluations
	s.xdr.AnomaliesTotal = anomalies
	s.xdr.Behavior = behavior
	s.mu.Unlock()
}

// XDRSensorState returns the current XDR sensor label under the state lock. The
// witness engine maps it onto the checkpoint enum; the label itself never leaves
// the host.
func (s *State) XDRSensorState() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.xdr.Sensor
}

// The degradation state has exactly one owner: this map.
//
// It used to have four writers, each assigning s.xdr.Degraded and s.xdr.DegradedReason directly -
// the engine's cause map, a case-history ingest failure, an evidence-ledger failure and a startup
// remark. Whichever wrote last won, and because recovery was a single unconditional
// SetXDRDegraded(false, ...) from the engine, the next engine tick wiped a cause that belonged to
// somebody else. That is how a platform could report itself healthy while the release gate had
// already latched a fail-safe, and how a degradation of the case history became a visible pause of
// the automatic response that nobody could name.
const (
	xdrCauseEngine      = "engine"
	xdrCauseCaseHistory = "case_history"
	xdrCauseEvidence    = "evidence_ledger"
)

// caseHistoryFailureThreshold is how many consecutive failed case-history ingests are treated as a
// condition rather than a hiccup. One failed ingest is not an integrity finding: the store keeps
// its own status.Error for the operator, and the ingest is retried with the next incident, which
// arrives within seconds on a host under load.
const caseHistoryFailureThreshold = 2

// MarkXDRDegraded records a degradation that belongs to the engine. It is the startup path, where
// no cause map exists yet.
func (s *State) MarkXDRDegraded(reason string) {
	s.markXDRCause(xdrCauseEngine, reason)
}

// SetXDRDegraded sets or clears the engine's contribution. It no longer touches causes that other
// components own: clearing the engine's reason must not silence the case history or the ledger.
func (s *State) SetXDRDegraded(degraded bool, reason string) {
	if degraded {
		s.markXDRCause(xdrCauseEngine, reason)
		return
	}
	s.clearXDRCause(xdrCauseEngine)
}

// markXDRCause adds or replaces one cause and reports the transition in the journal. The log line
// is written outside the lock: I/O under a global state mutex is what the engine does not do, and
// this mutex is held on every status refresh.
func (s *State) markXDRCause(cause, reason string) {
	s.mu.Lock()
	line := s.markXDRCauseLocked(cause, reason)
	s.mu.Unlock()
	if line != "" {
		log.Print(line)
	}
}

func (s *State) clearXDRCause(cause string) {
	s.mu.Lock()
	line := s.clearXDRCauseLocked(cause)
	s.mu.Unlock()
	if line != "" {
		log.Print(line)
	}
}

func (s *State) markXDRCauseLocked(cause, reason string) string {
	if s.xdrCauses == nil {
		s.xdrCauses = make(map[string]string, 4)
	}
	if previous, ok := s.xdrCauses[cause]; ok && previous == reason {
		return ""
	}
	s.xdrCauses[cause] = reason
	return s.recomputeXDRDegradedLocked()
}

func (s *State) clearXDRCauseLocked(cause string) string {
	if _, ok := s.xdrCauses[cause]; !ok {
		return ""
	}
	delete(s.xdrCauses, cause)
	return s.recomputeXDRDegradedLocked()
}

// recomputeXDRDegradedLocked derives the published flag from the causes and returns the journal
// line for a transition, or an empty string when nothing changed. Every cause is named in the
// reason, so no cause can be hidden behind another one's text. The published reason stays prose -
// the interface shows it verbatim - while the journal line carries the owning keys.
func (s *State) recomputeXDRDegradedLocked() string {
	degraded := len(s.xdrCauses) > 0
	keys := make([]string, 0, len(s.xdrCauses))
	for key := range s.xdrCauses {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	reasons := make([]string, 0, len(keys))
	detail := make([]string, 0, len(keys))
	for _, key := range keys {
		reasons = append(reasons, s.xdrCauses[key])
		detail = append(detail, key+"="+s.xdrCauses[key])
	}
	reason := strings.Join(reasons, "; ")
	if s.xdr.Degraded == degraded && s.xdr.DegradedReason == reason {
		return ""
	}
	s.xdr.Degraded = degraded
	s.xdr.DegradedReason = reason
	if degraded {
		return "xdr degraded: " + strings.Join(detail, "; ")
	}
	return "xdr recovered: no degradation causes remain"
}

// noteCaseHistoryFailure treats a failed case-history ingest as a condition only once it repeats.
// The first failure is named in the journal and changes nothing else.
func (s *State) noteCaseHistoryFailure(err error) {
	s.mu.Lock()
	s.caseHistoryFailures++
	attempts := s.caseHistoryFailures
	var line string
	if attempts >= caseHistoryFailureThreshold {
		line = s.markXDRCauseLocked(xdrCauseCaseHistory, "case history integrity unavailable: "+err.Error())
	}
	s.mu.Unlock()
	switch {
	case line != "":
		log.Print(line)
	case attempts == 1:
		log.Printf("case history ingest failed (%d/%d, not degrading yet): %v", attempts, caseHistoryFailureThreshold, err)
	}
}

// noteCaseHistorySuccess clears the cause as soon as an ingest succeeds, so an occasional failure
// can never accumulate into a degradation.
func (s *State) noteCaseHistorySuccess() {
	s.mu.Lock()
	s.caseHistoryFailures = 0
	line := s.clearXDRCauseLocked(xdrCauseCaseHistory)
	s.mu.Unlock()
	if line != "" {
		log.Print(line)
	}
}

func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	blocks := make([]BlockEntry, 0, len(s.blocks))
	for _, b := range s.blocks {
		blocks = append(blocks, b)
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].ExpiresAt.Before(blocks[j].ExpiresAt) })
	events := append([]Event(nil), s.events...)
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	incidents := append([]XDRIncident(nil), s.incidents...)
	for i, j := 0, len(incidents)-1; i < j; i, j = i+1, j-1 {
		incidents[i], incidents[j] = incidents[j], incidents[i]
	}
	fimStatus := FIMStatus{Enabled: false, Health: "DISABLED"}
	if s.fim != nil {
		fimStatus = s.fim.Status()
	}
	cases := s.cases
	cells := s.cells
	parserCells := s.parserCells
	titan := s.titan
	snapshot := Snapshot{Version: s.version, NodeName: s.nodeName, NodeMode: s.nodeMode, Enforcement: s.enforcement, StartedAt: s.started,
		UptimeSeconds: int64(time.Since(s.started).Seconds()), CoreConnected: s.coreConnected, CoreMode: s.coreMode, AllowlistReady: s.allowlistReady,
		FeedVectors: s.feedVectors, FeedStatus: s.feedStatus, LastFeedSync: s.lastFeedSync,
		LastFeedAttempt: s.lastFeedAttempt, LastFeedFullSync: s.lastFeedFullSync,
		FeedGeneration: s.feedGeneration, FeedFingerprint: s.feedFingerprint,
		FeedBlockVectors: s.feedBlockVectors, FeedCorrelateVectors: s.feedCorrelateVectors, FeedAnnotateVectors: s.feedAnnotateVectors,
		Blocks: blocks, Events: events, Telemetry: s.telemetry,
		XDR: s.xdr, L7: s.l7, Incidents: incidents, Policy: s.policy, Release: cloneReleaseStatus(s.release), Settings: cloneRuntimeSettings(s.settings),
		Evidence: s.evidenceStatus, FIM: fimStatus,
		Cases:    CaseStatus{Healthy: false, Cases: []SecurityCase{}},
		Cells:    GaiaCellsStatus{Enabled: false, Healthy: false, Availability: "disabled", Cells: []GaiaCell{}},
		Kinetic:  s.kinetic,
		Coverage: s.kinetic.Coverage,
		Stream:   s.streamDiagnostics}
	// The L7 verdict and the platform coverage are derived here, never served from the
	// stored copies. Both are functions of fields that more than one component publishes
	// into, so a stored copy records whichever of them wrote last. The derivation lives in
	// one place because two callers need it: this snapshot and the telemetry accessor that
	// answers /api/v1/kinetic/live, the endpoint the Kinetic page reads.
	if s.releaseXDRMode != "" && snapshot.XDR.Enabled {
		snapshot.XDR.Mode = s.releaseXDRMode
	}
	snapshot.L7, snapshot.Kinetic.Coverage = s.derivedCoverageLocked()

	// The top-level coverage is the same verdict under a second name, and it was built
	// into the struct literal above from the stored value before any of this ran. Leaving
	// it alone meant the derivation reached one field and not the other: the platform
	// served a corrected Kinetic summary and a stale overall verdict in the same response,
	// and the interface reads this one for the state it shows the operator. There is one
	// summary, and both names have to carry it.
	snapshot.Coverage = snapshot.Kinetic.Coverage
	snapshot.Stream.ActiveClients = len(s.subscribers)
	customCount := 0
	for _, cr := range s.settings.CustomRules {
		if cr.Enabled {
			customCount++
		}
	}
	builtinXDR := 0
	if s.xdr.Enabled {
		builtinXDR = 8
	}
	behaviorRules := 0
	if s.settings.BehaviorEnabled {
		behaviorRules = 1
	}
	kineticRules := 0
	if s.kinetic.Coverage.OverallStatus != "disabled" {
		kineticRules = 7
	}
	l7Rules := 0
	if s.l7.Enabled {
		l7Rules = 3
	}
	threatFeeds := 0
	if s.settings.FeedsEnabled {
		threatFeeds = s.feedVectors
	}
	snapshot.Protection = deriveProtectionStatus(snapshot, s.releaseXDRMode)
	snapshot.DetectionRules = DetectionRulesCount{
		BuiltinXDR:  builtinXDR,
		Custom:      customCount,
		Behavior:    behaviorRules,
		Kinetic:     kineticRules,
		L7:          l7Rules,
		ThreatFeeds: threatFeeds,
		Total:       builtinXDR + customCount + behaviorRules + kineticRules + l7Rules + threatFeeds,
	}
	s.mu.RUnlock()
	if cases != nil {
		snapshot.Cases = cases.Status(100)
	}
	if cells != nil {
		snapshot.Cells = cells.Status(false)
	}
	if parserCells != nil {
		// Local snapshot only: Status never contacts the helper, and a disabled
		// namespace reports itself without any request.
		status := parserCells.Status()
		snapshot.ParserCells = &status
	}
	if titan != nil {
		snapshot.Titan = titan.Status()
	} else {
		snapshot.Titan = TitanStatus{Version: snapshot.Version, Mode: TitanModeObserve, Sensor: TitanSensorStatus{State: "disabled"}}
	}
	return snapshot
}

// deriveProtectionStatus answers whether every layer the "full protection" claim
// depends on is actually enforcing. The release phase alone was not sufficient:
// it said enforce while the XDR layer still reported observe, and the dashboard
// printed "VOLLSCHUTZ AKTIV" over a paused active response.
func deriveProtectionStatus(snap Snapshot, releaseXDRMode string) ProtectionStatus {
	status := ProtectionStatus{Domains: make([]ProtectionDomain, 0, 6), Gaps: make([]string, 0, 8)}
	phase := strings.ToLower(strings.TrimSpace(snap.Release.Phase))
	emergency := snap.Release.EmergencyStop

	kernelActive := snap.Enforcement == "enforce" && snap.Release.KernelPolicyState == "verified-enforce"
	status.Domains = append(status.Domains, ProtectionDomain{Name: "kernel", Active: kernelActive, Mode: snap.Enforcement, Detail: snap.Release.KernelPolicyState})
	if !kernelActive {
		status.Gaps = append(status.Gaps, "kernel_not_enforcing")
	}

	xdrMode := strings.TrimSpace(releaseXDRMode)
	if xdrMode == "" {
		xdrMode = strings.TrimSpace(snap.XDR.Mode)
	}
	xdrDegraded := isXDROperationallyDegraded(snap.XDR)
	xdrActive := snap.XDR.Enabled && xdrMode == "enforce" && !xdrDegraded
	status.Domains = append(status.Domains, ProtectionDomain{Name: "xdr", Active: xdrActive, Mode: xdrMode})
	if !snap.XDR.Enabled {
		status.Gaps = append(status.Gaps, "xdr_disabled")
	} else if xdrDegraded {
		status.Gaps = append(status.Gaps, "xdr_degraded")
	} else if xdrMode != "enforce" {
		switch xdrMode {
		case "observe":
			status.Gaps = append(status.Gaps, "xdr_observe")
		case "contain":
			status.Gaps = append(status.Gaps, "xdr_contain")
		default:
			status.Gaps = append(status.Gaps, "xdr_disabled")
		}
	}

	coreActive := snap.CoreConnected
	status.Domains = append(status.Domains, ProtectionDomain{Name: "core", Active: coreActive, Mode: snap.CoreMode})
	if !coreActive {
		status.Gaps = append(status.Gaps, "core_disconnected")
	}

	kineticMode := strings.TrimSpace(snap.Settings.Kinetic.EnforcementMode)
	// Full protection is about the configured enforcement posture of the layer. A
	// degraded auxiliary sensor is reported in the domain detail and the coverage
	// panel, but it does not silently turn an enforcing Kinetic layer into "off".
	kineticActive := snap.Settings.Kinetic.Enabled && kineticMode == "block"
	status.Domains = append(status.Domains, ProtectionDomain{Name: "kinetic", Active: kineticActive, Mode: kineticMode, Detail: snap.Coverage.Summary})
	if !snap.Settings.Kinetic.Enabled || kineticMode != "block" {
		status.Gaps = append(status.Gaps, "kinetic_not_block")
	}

	l7Active := snap.L7.Enabled && snap.L7.Mode == "block"
	status.Domains = append(status.Domains, ProtectionDomain{Name: "l7", Active: l7Active, Mode: snap.L7.Mode, Detail: snap.L7.CoverageReason})
	if !l7Active {
		status.Gaps = append(status.Gaps, "l7_not_block")
	}

	evidenceActive := snap.Evidence.Enabled && snap.Evidence.Healthy
	status.Domains = append(status.Domains, ProtectionDomain{Name: "evidence", Active: evidenceActive, Mode: snap.Evidence.VerifyScope})
	if !evidenceActive {
		status.Gaps = append(status.Gaps, "evidence_unhealthy")
	}

	if emergency {
		status.Gaps = append(status.Gaps, "emergency_stop")
	}
	if phase != "enforce" {
		status.Gaps = append(status.Gaps, "release_not_enforce")
	}

	status.Effective = phase == "enforce" && !emergency && kernelActive && xdrActive && coreActive && kineticActive && l7Active && evidenceActive
	switch {
	case emergency:
		status.Level = "emergency"
	case status.Effective:
		status.Level = "full"
	case phase == "observe":
		status.Level = "observe"
	case phase == "canary":
		status.Level = "canary"
	case phase == "degraded":
		status.Level = "degraded"
	default:
		status.Level = "restricted"
	}
	if status.Effective {
		status.Summary = "every protection layer enforces"
	} else if len(status.Gaps) > 0 {
		status.Summary = strings.Join(status.Gaps, ",")
	}
	return status
}

func (s *State) RecordStreamConnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamDiagnostics.TotalConnects++
	s.streamDiagnostics.ActiveClients = len(s.subscribers)
}

func (s *State) RecordStreamDisconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamDiagnostics.TotalDisconnects++
	s.streamDiagnostics.ActiveClients = len(s.subscribers)
}

func (s *State) RecordStreamHeartbeat() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.streamDiagnostics.LastHeartbeatAt = &now
}

func (s *State) RecordStreamWriteError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamDiagnostics.WriteErrors++
}

func (s *State) StreamDiagnostics() StreamDiagnostics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := s.streamDiagnostics
	res.ActiveClients = len(s.subscribers)
	return res
}

func (s *State) KineticTelemetry() KineticTelemetry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.kinetic
	// The coverage is derived, not the stored copy.
	//
	// This accessor answers /api/v1/kinetic/live, which is the endpoint the Kinetic page
	// reads, and it returned the stored map. The L7 verdict is a function of fields that
	// two components publish into, so the stored copy recorded whichever of them wrote
	// last: the same process answered "All mandatory sensors operational" on
	// /api/v1/status and "Mandatory sensors degraded: l7_application" on this endpoint in
	// the same second, and the operator saw the second one on the page that matters.
	_, t.Coverage = s.derivedCoverageLocked()
	return t
}

// derivedCoverageLocked returns the L7 status and the platform coverage, both derived from
// the fields the components publish.
//
// Neither may be served from the stored copies. The L7 verdict depends on fields that two
// components write: the inspection service recomputes it on its own events, and the inline
// edge sets InlineHealthy when a request or a self-test proves the path - events the service
// never sees. The coverage is then summarised from the sensor map, whose L7 entry was
// written by one publisher on the service's events alone, so it kept whatever it recorded
// the last time.
//
// Deriving it where it is read makes the two impossible to disagree. The web surface probe
// is deliberately not re-run here: it reads /proc and this is a hot path, so only the parts
// of the verdict that depend on already-published fields are recomputed.
//
// The caller holds s.mu.
func (s *State) derivedCoverageLocked() (L7Status, SystemCoverage) {
	l7 := s.l7
	l7.Coverage = EvaluateL7Coverage(l7, int64(time.Since(s.started).Seconds()))
	l7.TrafficPathVerified = l7.Coverage == "TRAFFIC_ACTIVE"
	l7.CoverageReason = describeL7Coverage(l7.Coverage)
	if l7.Miswired && l7.Coverage != "OFFLINE" {
		l7.CoverageReason = l7.WebSurfaceNote
	}
	sensors := make(map[string]SensorCoverage, len(s.sensors)+1)
	for name, cov := range s.sensors {
		sensors[name] = cov
	}
	sensors["l7_application"] = deriveL7SensorCoverage(l7, l7.Healthy)
	return l7, EvaluateCoverage(sensors)
}

func (s *State) SetKineticTelemetry(t KineticTelemetry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kinetic = t
}

func (s *State) UpdateKineticTelemetry(fn func(*KineticTelemetry)) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.kinetic)
}

func (s *State) SetSensorCoverage(cov SensorCoverage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sensors == nil {
		s.sensors = make(map[string]SensorCoverage)
	}
	s.sensors[cov.Name] = cov
	s.kinetic.Coverage = EvaluateCoverage(s.sensors)
}

func (s *State) SensorCoverage(name string) (SensorCoverage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sensors == nil {
		return SensorCoverage{}, false
	}
	cov, ok := s.sensors[name]
	return cov, ok
}

func (s *State) SystemCoverage() SystemCoverage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kinetic.Coverage
}
