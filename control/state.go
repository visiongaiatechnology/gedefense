package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

type Event struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Severity string    `json:"severity"`
	Kind     string    `json:"kind"`
	Source   string    `json:"source"`
	Message  string    `json:"message"`
	Target   string    `json:"target,omitempty"`
}

type BlockEntry struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Enforced  bool      `json:"enforced"`
}

type Telemetry struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryUsed    uint64  `json:"memory_used"`
	MemoryTotal   uint64  `json:"memory_total"`
	RXBytes       uint64  `json:"rx_bytes"`
	TXBytes       uint64  `json:"tx_bytes"`
	RXRate        float64 `json:"rx_rate"`
	TXRate        float64 `json:"tx_rate"`
	Interface     string  `json:"interface"`
}

type Snapshot struct {
	Version              string              `json:"version"`
	NodeName             string              `json:"node_name"`
	NodeMode             string              `json:"node_mode"`
	Enforcement          string              `json:"enforcement"`
	StartedAt            time.Time           `json:"started_at"`
	UptimeSeconds        int64               `json:"uptime_seconds"`
	CoreConnected        bool                `json:"core_connected"`
	CoreMode             string              `json:"core_mode"`
	AllowlistReady       bool                `json:"allowlist_ready"`
	FeedVectors          int                 `json:"feed_vectors"`
	FeedStatus           string              `json:"feed_status,omitempty"`
	LastFeedSync         *time.Time          `json:"last_feed_sync,omitempty"`
	LastFeedAttempt      *time.Time          `json:"last_feed_attempt,omitempty"`
	LastFeedFullSync     *time.Time          `json:"last_feed_full_sync,omitempty"`
	FeedGeneration       uint64              `json:"feed_generation,omitempty"`
	FeedFingerprint      string              `json:"feed_fingerprint,omitempty"`
	FeedBlockVectors     int                 `json:"feed_block_vectors,omitempty"`
	FeedCorrelateVectors int                 `json:"feed_correlate_vectors,omitempty"`
	FeedAnnotateVectors  int                 `json:"feed_annotate_vectors,omitempty"`
	Blocks               []BlockEntry        `json:"blocks"`
	Events               []Event             `json:"events"`
	Telemetry            Telemetry           `json:"telemetry"`
	XDR                  XDRStatus           `json:"xdr"`
	L7                   L7Status            `json:"l7"`
	Incidents            []XDRIncident       `json:"incidents"`
	Policy               PolicyStatus        `json:"policy"`
	Release              ReleaseStatus       `json:"release"`
	Settings             RuntimeSettings     `json:"settings"`
	Evidence             EvidenceStatus      `json:"evidence"`
	FIM                  FIMStatus           `json:"fim"`
	Cases                CaseStatus          `json:"cases"`
	Cells                GaiaCellsStatus     `json:"cells"`
	Kinetic              KineticTelemetry    `json:"kinetic"`
	Coverage             SystemCoverage      `json:"coverage"`
	Stream               StreamDiagnostics   `json:"stream"`
	DetectionRules       DetectionRulesCount `json:"detection_rules"`
}

type DetectionRulesCount struct {
	BuiltinXDR  int `json:"builtin_xdr"`
	Custom      int `json:"custom"`
	Behavior    int `json:"behavior"`
	Kinetic     int `json:"kinetic"`
	L7          int `json:"l7"`
	ThreatFeeds int `json:"threat_feeds"`
	Total       int `json:"total"`
}

type StreamDiagnostics struct {
	ActiveClients    int        `json:"active_clients"`
	TotalConnects    int64      `json:"total_connects"`
	TotalDisconnects int64      `json:"total_disconnects"`
	LastHeartbeatAt  *time.Time `json:"last_heartbeat_at,omitempty"`
	WriteErrors      int64      `json:"write_errors"`
}

type State struct {
	mu                                       sync.RWMutex
	version, nodeName, nodeMode, enforcement string
	started                                  time.Time
	coreConnected                            bool
	coreMode                                 string
	allowlistReady                           bool
	feedVectors                              int
	feedStatus                               string
	lastFeedSync                             *time.Time
	lastFeedAttempt                          *time.Time
	lastFeedFullSync                         *time.Time
	feedGeneration                           uint64
	feedFingerprint                          string
	feedBlockVectors                         int
	feedCorrelateVectors                     int
	feedAnnotateVectors                      int
	telemetry                                Telemetry
	blocks                                   map[string]BlockEntry
	events                                   []Event
	eventCap                                 int
	subscribers                              map[chan Event]struct{}
	xdr                                      XDRStatus
	l7                                       L7Status
	incidents                                []XDRIncident
	incidentCap                              int
	policy                                   PolicyStatus
	release                                  ReleaseStatus
	settings                                 RuntimeSettings
	evidence                                 *EvidenceLedger
	evidenceStatus                           EvidenceStatus
	evidenceErr                              error
	fim                                      *FIMEngine
	transactions                             *TransactionEngine
	cases                                    *CaseEngine
	cells                                    *GaiaCellsAdapter
	kinetic                                  KineticTelemetry
	sensors                                  map[string]SensorCoverage
	streamDiagnostics                        StreamDiagnostics
}

func NewState(version string, cfg Config) *State {
	s := &State{version: version, nodeName: cfg.Node.Name, nodeMode: cfg.Node.Mode, enforcement: cfg.Defense.Enforcement,
		started: time.Now().UTC(), coreMode: "offline", blocks: make(map[string]BlockEntry), eventCap: 250,
		subscribers: make(map[chan Event]struct{}), incidentCap: 250,
		xdr: XDRStatus{Enabled: cfg.XDR.Enabled, Mode: cfg.XDR.Mode, Sensor: "initializing", QueueCapacity: cfg.XDR.QueueCapacity},
		l7: L7Status{
			Enabled: cfg.L7.Enabled, Mode: cfg.L7.Mode, Socket: cfg.L7.Socket, Healthy: !cfg.L7.Enabled,
			InlineEnabled: cfg.L7.InlineEnabled, InlineHealthy: !cfg.L7.InlineEnabled, InlineSocket: cfg.L7.InlineSocket,
		},
		release: ReleaseStatus{Channel: cfg.Release.Channel, Phase: ReleasePhaseObserve, Since: time.Now().UTC()}}
	s.kinetic = DefaultKineticTelemetry()
	s.sensors = make(map[string]SensorCoverage)
	for k, v := range s.kinetic.Coverage.Sensors {
		s.sensors[k] = v
	}
	return s
}

// randomID returns the identifier carried by evidence records: block entries,
// incidents, quarantine objects, transactions and cases.
//
// A failure of the system random source is fatal on purpose. The previous clock
// fallback made every subsequent identifier predictable, and an identifier an
// attacker can pre-compute is exactly what is needed to collide or forge audit
// records. There is no safe degraded mode for a value that must be unguessable,
// so the process stops instead of continuing with weak identifiers.
//
// The width is eight bytes because the identifier format is a contract: the
// CS-, TX- and QV- prefixes are validated at exactly nineteen characters.
//
// Entropy boundary: eight bytes is 64 bits. That is ample for correlation - the
// chance of a collision stays negligible far beyond any realistic number of
// records - and it is NOT adequate for a value an attacker could profit from
// guessing. These identifiers are not secrets and must never become one: no
// endpoint may authorise an action on an identifier alone, and no identifier may
// be accepted as a capability. Authorisation is carried by the bearer token
// compared in constant time in tokenEqual. A future feature that needs an
// unguessable handle must mint its own value from crypto/rand with at least 128
// bits rather than reuse this function.
func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("system random source unavailable, refusing to mint evidence identifiers: %v", err)
	}
	return hex.EncodeToString(b)
}

func normalizeTarget(target string) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		if ip.IsUnspecified() {
			return "", errors.New("blocking the unspecified address is not allowed")
		}
		if ip.To4() != nil {
			return ip.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}
	_, network, err := net.ParseCIDR(target)
	if err != nil {
		return "", errors.New("target must be an IPv4/IPv6 address or CIDR")
	}
	if network.IP.IsUnspecified() {
		return "", errors.New("blocking the unspecified address is not allowed")
	}
	return network.String(), nil
}

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
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
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
		return old, nil
	}
	if len(s.blocks) >= maxEntries {
		return BlockEntry{}, errors.New("blocklist capacity reached")
	}
	b := BlockEntry{ID: randomID(), Target: target, Reason: reason, Source: source, CreatedAt: now, ExpiresAt: now.Add(ttl), Enforced: enforced}
	s.blocks[target] = b
	return b, nil
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
			return b, true
		}
	}
	return BlockEntry{}, false
}

func (s *State) Expired(now time.Time) []BlockEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []BlockEntry
	for k, b := range s.blocks {
		if !b.ExpiresAt.After(now) {
			out = append(out, b)
			delete(s.blocks, k)
		}
	}
	return out
}

func (s *State) SetModes(enforcement, xdrMode string) {
	s.mu.Lock()
	s.enforcement = enforcement
	s.xdr.Mode = xdrMode
	s.mu.Unlock()
}

func (s *State) Modes() (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enforcement, s.xdr.Mode
}

func (s *State) SetSettings(settings RuntimeSettings) {
	s.mu.Lock()
	s.settings = cloneRuntimeSettings(settings)
	s.mu.Unlock()
}

func (s *State) SetReleaseStatus(status ReleaseStatus) {
	s.mu.Lock()
	status.Blockers = append([]string(nil), status.Blockers...)
	s.release = status
	s.mu.Unlock()
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

func (s *State) SetCore(connected bool, mode string) {
	s.mu.Lock()
	s.coreConnected = connected
	s.coreMode = mode
	s.mu.Unlock()
}

func (s *State) SetAllowlistReady(ready bool) {
	s.mu.Lock()
	s.allowlistReady = ready
	s.mu.Unlock()
}

func (s *State) SetTelemetry(t Telemetry) {
	s.mu.Lock()
	s.telemetry = t
	s.mu.Unlock()
}

func (s *State) SetFeedVectors(n int, at time.Time) {
	s.mu.Lock()
	s.feedVectors = n
	u := at.UTC()
	s.lastFeedSync = &u
	s.mu.Unlock()
}

func (s *State) SetFeedState(blockCount, correlateCount, annotateCount int, gen uint64, fingerprint, status string, lastAttempt, lastSuccess, lastFullSuccess time.Time) {
	s.mu.Lock()
	s.feedVectors = blockCount + correlateCount + annotateCount
	s.feedBlockVectors = blockCount
	s.feedCorrelateVectors = correlateCount
	s.feedAnnotateVectors = annotateCount
	s.feedGeneration = gen
	s.feedFingerprint = fingerprint
	s.feedStatus = status
	if !lastAttempt.IsZero() {
		u := lastAttempt.UTC()
		s.lastFeedAttempt = &u
	}
	if !lastSuccess.IsZero() {
		u := lastSuccess.UTC()
		s.lastFeedSync = &u
	}
	if !lastFullSuccess.IsZero() {
		u := lastFullSuccess.UTC()
		s.lastFeedFullSync = &u
	}
	s.mu.Unlock()
}

func (s *State) SetXDREnabled(enabled, networkSensor bool) {
	s.mu.Lock()
	s.xdr.Enabled = enabled
	if !enabled {
		s.xdr.Sensor = "disabled-by-operator"
	} else if networkSensor {
		s.xdr.Sensor = "procfs+network-bounded"
	} else {
		s.xdr.Sensor = "procfs-bounded"
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

func (s *State) MarkXDRDegraded(reason string) {
	s.mu.Lock()
	s.xdr.Degraded = true
	s.xdr.DegradedReason = reason
	s.mu.Unlock()
}

func (s *State) SetXDRDegraded(degraded bool, reason string) {
	s.mu.Lock()
	s.xdr.Degraded = degraded
	if degraded {
		s.xdr.DegradedReason = reason
	} else {
		s.xdr.DegradedReason = ""
	}
	s.mu.Unlock()
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

func (s *State) AddIncident(i XDRIncident) {
	if i.ID == "" {
		i.ID = randomID()
	}
	if i.Time.IsZero() {
		i.Time = time.Now().UTC()
	}
	s.mu.Lock()
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
			s.mu.Lock()
			s.xdr.Degraded = true
			s.xdr.DegradedReason = "case history integrity unavailable"
			s.mu.Unlock()
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

func (s *State) SetPolicyStatus(p PolicyStatus) {
	s.mu.Lock()
	s.policy = p
	s.mu.Unlock()
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
	s.mu.Unlock()
}

func (s *State) ImportBlocks(blocks []BlockEntry, now time.Time, maxEntries int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, b := range blocks {
		if count >= maxEntries || !b.ExpiresAt.After(now) {
			continue
		}
		normalized, err := normalizeTarget(b.Target)
		if err != nil || b.ID == "" {
			continue
		}
		b.Target = normalized
		s.blocks[normalized] = b
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
	if err := ledger.Verify(); err != nil {
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
	switch {
	case err == nil:
		s.evidenceErr = nil
		s.evidenceStatus = ledger.Status()
	case errors.Is(err, errEvidenceBudgetExhausted):
		// A full ledger is a capacity condition. The chain is intact, the signatures are
		// valid and nothing is lost - the retention budget has simply been reached. It
		// must not be reported as an integrity failure, and it must not degrade XDR.
		s.evidenceErr = err
		s.evidenceStatus = ledger.Status()
		s.evidenceStatus.Full = true
	default:
		s.evidenceErr = err
		s.evidenceStatus = ledger.Status()
		s.evidenceStatus.Healthy = false
		s.evidenceStatus.Error = "evidence integrity unavailable"
		s.xdr.Degraded = true
		s.xdr.DegradedReason = "mandatory evidence ledger unavailable"
	}
	s.mu.Unlock()
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

func (s *State) AttachFIM(engine *FIMEngine) error {
	if engine == nil {
		return errors.New("FIM engine is required")
	}
	s.mu.Lock()
	s.fim = engine
	s.mu.Unlock()
	return nil
}

func (s *State) FIM() *FIMEngine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fim
}

func (s *State) AttachTransactions(engine *TransactionEngine) error {
	if engine == nil {
		return errors.New("transaction engine is required")
	}
	s.mu.Lock()
	s.transactions = engine
	s.mu.Unlock()
	return nil
}

func (s *State) Transactions() *TransactionEngine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.transactions
}

func (s *State) AttachCases(engine *CaseEngine) error {
	if engine == nil {
		return errors.New("case engine is required")
	}
	s.mu.Lock()
	s.cases = engine
	s.mu.Unlock()
	return nil
}

func (s *State) Cases() *CaseEngine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cases
}

func (s *State) AttachCells(adapter *GaiaCellsAdapter) error {
	if adapter == nil {
		return errors.New("Gaia Cells adapter is required")
	}
	s.mu.Lock()
	s.cells = adapter
	s.mu.Unlock()
	return nil
}

func (s *State) Cells() *GaiaCellsAdapter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cells
}

func (s *State) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		if _, ok := s.subscribers[ch]; ok {
			delete(s.subscribers, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
}

func (s *State) SetL7Status(status L7Status) {
	s.mu.Lock()
	s.l7 = status
	s.mu.Unlock()
}

func (s *State) UpdateL7Status(update func(*L7Status)) {
	if update == nil {
		return
	}
	s.mu.Lock()
	update(&s.l7)
	s.mu.Unlock()
}

func (s *State) L7Status() L7Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.l7
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
	return snapshot
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
