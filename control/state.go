package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
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
	Version        string          `json:"version"`
	NodeName       string          `json:"node_name"`
	NodeMode       string          `json:"node_mode"`
	Enforcement    string          `json:"enforcement"`
	StartedAt      time.Time       `json:"started_at"`
	UptimeSeconds  int64           `json:"uptime_seconds"`
	CoreConnected  bool            `json:"core_connected"`
	CoreMode       string          `json:"core_mode"`
	AllowlistReady bool            `json:"allowlist_ready"`
	FeedVectors    int             `json:"feed_vectors"`
	LastFeedSync   *time.Time      `json:"last_feed_sync,omitempty"`
	Blocks         []BlockEntry    `json:"blocks"`
	Events         []Event         `json:"events"`
	Telemetry      Telemetry       `json:"telemetry"`
	XDR            XDRStatus       `json:"xdr"`
	Incidents      []XDRIncident   `json:"incidents"`
	Policy         PolicyStatus    `json:"policy"`
	Release        ReleaseStatus   `json:"release"`
	Settings       RuntimeSettings `json:"settings"`
	Evidence       EvidenceStatus  `json:"evidence"`
	FIM            FIMStatus       `json:"fim"`
	Cases          CaseStatus      `json:"cases"`
	Cells          GaiaCellsStatus `json:"cells"`
}

type State struct {
	mu                                       sync.RWMutex
	version, nodeName, nodeMode, enforcement string
	started                                  time.Time
	coreConnected                            bool
	coreMode                                 string
	allowlistReady                           bool
	feedVectors                              int
	lastFeedSync                             *time.Time
	telemetry                                Telemetry
	blocks                                   map[string]BlockEntry
	events                                   []Event
	eventCap                                 int
	subscribers                              map[chan Event]struct{}
	xdr                                      XDRStatus
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
}

func NewState(version string, cfg Config) *State {
	return &State{version: version, nodeName: cfg.Node.Name, nodeMode: cfg.Node.Mode, enforcement: cfg.Defense.Enforcement,
		started: time.Now().UTC(), coreMode: "offline", blocks: make(map[string]BlockEntry), eventCap: 250,
		subscribers: make(map[chan Event]struct{}), incidentCap: 250,
		xdr:     XDRStatus{Enabled: cfg.XDR.Enabled, Mode: cfg.XDR.Mode, Sensor: "initializing", QueueCapacity: cfg.XDR.QueueCapacity},
		release: ReleaseStatus{Channel: cfg.Release.Channel, Phase: ReleasePhaseObserve, Since: time.Now().UTC()}}
}

func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
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
	target, err := normalizeTarget(target)
	if err != nil {
		return BlockEntry{}, err
	}
	if len(reason) < 3 || len(reason) > 240 {
		return BlockEntry{}, errors.New("reason must contain 3-240 characters")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.blocks) >= maxEntries {
		return BlockEntry{}, errors.New("blocklist capacity reached")
	}
	if old, ok := s.blocks[target]; ok {
		old.ExpiresAt = now.Add(ttl)
		old.Reason = reason
		old.Enforced = enforced
		s.blocks[target] = old
		return old, nil
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
	if err != nil {
		s.evidenceErr = err
		s.evidenceStatus = ledger.Status()
		s.evidenceStatus.Healthy = false
		s.evidenceStatus.Error = "evidence integrity unavailable"
		s.xdr.Degraded = true
		s.xdr.DegradedReason = "mandatory evidence ledger unavailable"
	} else {
		s.evidenceStatus = ledger.Status()
	}
	s.mu.Unlock()
	return err
}

func (s *State) EvidenceHealthy() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.evidenceErr
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
		FeedVectors: s.feedVectors, LastFeedSync: s.lastFeedSync, Blocks: blocks, Events: events, Telemetry: s.telemetry,
		XDR: s.xdr, Incidents: incidents, Policy: s.policy, Release: cloneReleaseStatus(s.release), Settings: cloneRuntimeSettings(s.settings),
		Evidence: s.evidenceStatus, FIM: fimStatus,
		Cases: CaseStatus{Healthy: false, Cases: []SecurityCase{}},
		Cells: GaiaCellsStatus{Enabled: false, Healthy: false, Availability: "disabled", Cells: []GaiaCell{}}}
	s.mu.RUnlock()
	if cases != nil {
		snapshot.Cases = cases.Status(100)
	}
	if cells != nil {
		snapshot.Cells = cells.Status(false)
	}
	return snapshot
}
