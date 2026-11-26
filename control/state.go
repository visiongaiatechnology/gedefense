// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net"
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

// ProtectionDomain is one layer whose enforcement the operator relies on when
// the product claims "full protection".
type ProtectionDomain struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Mode   string `json:"mode"`
	Detail string `json:"detail,omitempty"`
}

// ProtectionStatus is the single honest answer to "is full protection active?".
//
// It is derived from the effective enforcement state, never from a single release
// phase flag: a release in enforce whose XDR layer is still in observe (or whose
// core/censor/evidence layer is down) is restricted, and the gaps name exactly why.
type ProtectionStatus struct {
	Effective bool               `json:"effective"`
	Level     string             `json:"level"`
	Summary   string             `json:"summary"`
	Domains   []ProtectionDomain `json:"domains"`
	Gaps      []string           `json:"gaps"`
}

type Snapshot struct {
	Version              string        `json:"version"`
	UIBuild              string        `json:"ui_build,omitempty"`
	NodeName             string        `json:"node_name"`
	NodeMode             string        `json:"node_mode"`
	Enforcement          string        `json:"enforcement"`
	StartedAt            time.Time     `json:"started_at"`
	UptimeSeconds        int64         `json:"uptime_seconds"`
	CoreConnected        bool          `json:"core_connected"`
	CoreMode             string        `json:"core_mode"`
	AllowlistReady       bool          `json:"allowlist_ready"`
	FeedVectors          int           `json:"feed_vectors"`
	FeedStatus           string        `json:"feed_status,omitempty"`
	LastFeedSync         *time.Time    `json:"last_feed_sync,omitempty"`
	LastFeedAttempt      *time.Time    `json:"last_feed_attempt,omitempty"`
	LastFeedFullSync     *time.Time    `json:"last_feed_full_sync,omitempty"`
	FeedGeneration       uint64        `json:"feed_generation,omitempty"`
	FeedFingerprint      string        `json:"feed_fingerprint,omitempty"`
	FeedBlockVectors     int           `json:"feed_block_vectors,omitempty"`
	FeedCorrelateVectors int           `json:"feed_correlate_vectors,omitempty"`
	FeedAnnotateVectors  int           `json:"feed_annotate_vectors,omitempty"`
	Blocks               []BlockEntry  `json:"blocks"`
	Events               []Event       `json:"events"`
	Telemetry            Telemetry     `json:"telemetry"`
	XDR                  XDRStatus     `json:"xdr"`
	L7                   L7Status      `json:"l7"`
	Incidents            []XDRIncident `json:"incidents"`
	Policy               PolicyStatus  `json:"policy"`
	Release              ReleaseStatus `json:"release"`
	// Readiness is only attached to the dashboard-facing snapshot (APIServer.clientSnapshot).
	// The release controller owns it, not the state; nil means this snapshot came straight from the
	// state and does not carry the readiness projection.
	Readiness *ReleaseReadinessSet `json:"readiness,omitempty"`
	Settings  RuntimeSettings      `json:"settings"`
	Evidence  EvidenceStatus       `json:"evidence"`
	FIM       FIMStatus            `json:"fim"`
	Titan     TitanStatus          `json:"titan"`
	// TitanExec is the bounded kernel exec-gate projection (POINT 1 / P1-T5). It
	// stays nil when the engine carries no exec-gate wiring, so the status payload
	// of an installation that never enabled the gate stays unchanged.
	TitanExec *TitanExecStatus `json:"titan_exec,omitempty"`
	// ParserCells is the bounded ephemeral parser-cell projection (POINT 2 / P2-T3).
	// It stays nil when the control plane carries no parser-cell manager, so the
	// status payload of an installation that never enabled the namespace is
	// unchanged and no helper is ever contacted for it.
	ParserCells *ParserCellsStatus `json:"parser_cells,omitempty"`
	// Lockdown is the bounded Emergency Lockdown projection (POINT 5 / P5-T3). It
	// stays nil when the control plane carries no lockdown engine, so the status
	// payload of an installation that never enabled the namespace is unchanged.
	Lockdown       *LockdownStatusView `json:"lockdown,omitempty"`
	Cases          CaseStatus          `json:"cases"`
	Cells          GaiaCellsStatus     `json:"cells"`
	Kinetic        KineticTelemetry    `json:"kinetic"`
	Coverage       SystemCoverage      `json:"coverage"`
	Stream         StreamDiagnostics   `json:"stream"`
	DetectionRules DetectionRulesCount `json:"detection_rules"`
	Protection     ProtectionStatus    `json:"protection"`
	// Witness is the bounded Out-of-Band Witness projection (POINT 4 / P4-T2). It
	// stays nil when the control plane carries no witness engine, so the status
	// payload of an installation that never enabled the namespace is unchanged.
	Witness *WitnessStatus `json:"witness,omitempty"`
	// Startup is the bounded startup self-check view published by
	// StartupSupervisor.publish via startup_supervisor.go. Nil until the
	// supervisor has produced its first report.
	Startup *StartupStatus `json:"startup,omitempty"`
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
	// releaseXDRMode is owned by the release controller (SetModes). The XDR
	// engine publishes its own sensor status continuously; without a separate
	// release-owned field that refresh overwrote the promotion state, so an
	// enforced release silently kept reporting (and acting as) observe.
	releaseXDRMode       string
	started              time.Time
	coreConnected        bool
	coreMode             string
	allowlistReady       bool
	feedVectors          int
	feedStatus           string
	lastFeedSync         *time.Time
	lastFeedAttempt      *time.Time
	lastFeedFullSync     *time.Time
	feedGeneration       uint64
	feedFingerprint      string
	feedBlockVectors     int
	feedCorrelateVectors int
	feedAnnotateVectors  int
	telemetry            Telemetry
	blocks               map[string]BlockEntry
	// blockDeadlines keeps the monotonic TTL origin of in-memory block entries next to
	// the serializable wall-clock ExpiresAt. A forward wall-clock step must not expire a
	// security block early (F-26 / G-STATE-06); entries restored from disk fall back to
	// the wall clock because the monotonic reading is not serializable.
	blockDeadlines      map[string]time.Time
	events              []Event
	eventCap            int
	subscribers         map[chan Event]struct{}
	xdr                 XDRStatus
	xdrCauses           map[string]string
	caseHistoryFailures int
	l7                  L7Status
	incidents           []XDRIncident
	incidentDedupe      map[string]time.Time
	incidentCap         int
	policy              PolicyStatus
	release             ReleaseStatus
	settings            RuntimeSettings
	evidence            *EvidenceLedger
	evidenceStatus      EvidenceStatus
	evidenceErr         error
	fim                 *FIMEngine
	titan               *TitanEngine
	transactions        *TransactionEngine
	cases               *CaseEngine
	cells               *GaiaCellsAdapter
	parserCells         *ParserCellManager
	kinetic             KineticTelemetry
	sensors             map[string]SensorCoverage
	streamDiagnostics   StreamDiagnostics
}

func NewState(version string, cfg Config) *State {
	s := &State{version: version, nodeName: cfg.Node.Name, nodeMode: cfg.Node.Mode, enforcement: cfg.Defense.Enforcement,
		started: time.Now().UTC(), coreMode: "offline", blocks: make(map[string]BlockEntry), blockDeadlines: make(map[string]time.Time), eventCap: 250,
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

func (s *State) SetModes(enforcement, xdrMode string) {
	s.mu.Lock()
	s.enforcement = enforcement
	s.releaseXDRMode = xdrMode
	s.xdr.Mode = xdrMode
	s.mu.Unlock()
}

func (s *State) Modes() (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mode := s.releaseXDRMode
	if mode == "" {
		mode = s.xdr.Mode
	}
	return s.enforcement, mode
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

func (s *State) SetPolicyStatus(p PolicyStatus) {
	s.mu.Lock()
	s.policy = p
	s.mu.Unlock()
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

func (s *State) AttachTitan(engine *TitanEngine) error {
	if engine == nil {
		return errors.New("Titan engine is required")
	}
	s.mu.Lock()
	s.titan = engine
	s.mu.Unlock()
	return nil
}

// Titan returns the attached Titan engine, or nil when the module is not part of
// this composition. Callers must render the explicit unavailable state.
func (s *State) Titan() *TitanEngine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.titan
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

// AttachParserCells binds the ephemeral parser-cell manager. It is additive next
// to the legacy Gaia Cells adapter: both report separately, neither can claim the
// other's cells.
func (s *State) AttachParserCells(manager *ParserCellManager) error {
	if manager == nil {
		return errors.New("parser cell manager is required")
	}
	s.mu.Lock()
	s.parserCells = manager
	s.mu.Unlock()
	return nil
}

func (s *State) ParserCells() *ParserCellManager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.parserCells
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
