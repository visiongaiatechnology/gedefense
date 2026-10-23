// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// GeDefense Titan - trust-aware integrity / ingress observation core (Linux).
//
// Titan observes file creation and modification inside operator-configured roots,
// evaluates every observation against owner authorization evidence and records
// what it genuinely observed. It does not attribute an actor: the trust state is
// a statement about authorization and system integrity, never about a person,
// organization or state. Missing evidence always lowers trust.
//
// Modes:
//   OBSERVE - record and evidence everything, never act.
//   CONTAIN - record; when armed and auto-containment is enabled, unexpected or
//             compromised changes are handed to the existing quarantine
//             transaction applier (never a delete, never an invented success).
//   STRICT  - record and contain as CONTAIN, and additionally surface changes
//             that are not explicitly AUTHORIZED as needing operator review.
//
// Persistence is two bounded, atomically written documents under the control
// plane state directory: the owner policy and the observation journal. The
// signed evidence ledger is the tamper-evident record; the journal is the
// bounded working set the interface reads.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	titanPolicySchema   = "vgt-gedefense-titan-policy-v1"
	titanJournalSchema  = "vgt-gedefense-titan-journal-v1"
	titanJournalVersion = 1

	titanMaxPolicyBytes      = 64 << 10
	titanMaxJournalReadBytes = 8 << 20

	titanMinJournalEvents = 50
	titanMaxJournalEvents = 2000
	titanMinJournalBytes  = 256 << 10
	titanMaxJournalBytes  = 8 << 20
	titanMinFileBytes     = 1 << 10
	titanMaxFileBytes     = 64 << 20
	titanMaxRoots         = 32
	titanMaxAllowlist     = 256
	titanMaxPathBytes     = 4096
	titanMaxEventIDBytes  = 64
	titanMinReasonBytes   = 8
	titanMaxReasonBytes   = 512
	titanDefaultLimit     = 20
	titanMaxLimit         = 50
	titanMaxSensorEvents  = 256
	titanMaxQuarantine    = 200
)

type TitanMode string

const (
	TitanModeObserve TitanMode = "OBSERVE"
	TitanModeContain TitanMode = "CONTAIN"
	TitanModeStrict  TitanMode = "STRICT"
)

func validTitanMode(mode TitanMode) bool {
	return mode == TitanModeObserve || mode == TitanModeContain || mode == TitanModeStrict
}

type TitanTrustState string

const (
	TitanTrustAuthorized  TitanTrustState = "AUTHORIZED"
	TitanTrustTolerated   TitanTrustState = "TOLERATED"
	TitanTrustUnexpected  TitanTrustState = "UNEXPECTED"
	TitanTrustCompromised TitanTrustState = "COMPROMISED"
)

type TitanCorrelation string

const (
	TitanCorrelationObserved TitanCorrelation = "OBSERVED"
	TitanCorrelationTemporal TitanCorrelation = "TEMPORAL"
	TitanCorrelationNone     TitanCorrelation = "NONE"
)

type TitanChangeType string

const (
	TitanChangeCreated    TitanChangeType = "CREATED"
	TitanChangeModified   TitanChangeType = "MODIFIED"
	TitanChangeRemoved    TitanChangeType = "REMOVED"
	TitanChangeAttributes TitanChangeType = "ATTRIBUTES"
	// TitanChangeUnavailable marks a change whose type could not be determined
	// from the sensor event. It is deliberately visible instead of guessed.
	TitanChangeUnavailable TitanChangeType = "UNKNOWN"
)

func validTitanChangeType(change TitanChangeType) bool {
	switch change {
	case TitanChangeCreated, TitanChangeModified, TitanChangeRemoved, TitanChangeAttributes, TitanChangeUnavailable:
		return true
	default:
		return false
	}
}

// Engine response values. Only CONTAINED states that a transaction verified the
// moved object; every other value says explicitly that no containment succeeded.
const (
	TitanResponseObserved           = "OBSERVED"
	TitanResponseContained          = "CONTAINED"
	TitanResponseContainUnavailable = "CONTAIN_UNAVAILABLE"
	TitanResponseContainFailed      = "CONTAIN_FAILED"
	TitanResponseNoAction           = "NO_ACTION"
	TitanResponseReviewRequired     = "REVIEW_REQUIRED"
)

type TitanSensorStatus struct {
	State              string     `json:"state"`
	LastObservationUTC *time.Time `json:"last_observation_utc"`
	Error              string     `json:"error"`
}

type TitanTrustCounts struct {
	Authorized  int `json:"AUTHORIZED"`
	Tolerated   int `json:"TOLERATED"`
	Unexpected  int `json:"UNEXPECTED"`
	Compromised int `json:"COMPROMISED"`
}

type TitanCorrelationCounts struct {
	Observed int `json:"OBSERVED"`
	Temporal int `json:"TEMPORAL"`
	None     int `json:"NONE"`
}

// TitanStatus is the contract of GET /api/v1/titan/status and Snapshot.Titan.
type TitanStatus struct {
	Version         string                 `json:"version"`
	Mode            TitanMode              `json:"mode"`
	Armed           bool                   `json:"armed"`
	AutoContain     bool                   `json:"auto_contain"`
	Trust           TitanTrustCounts       `json:"trust"`
	Correlation     TitanCorrelationCounts `json:"correlation"`
	EventsTotal     uint64                 `json:"events_total"`
	OpenFindings    int                    `json:"open_findings"`
	QuarantineCount int                    `json:"quarantine_count"`
	Sensor          TitanSensorStatus      `json:"sensor"`
	UpdatedUTC      time.Time              `json:"updated_utc"`
}

// TitanEvent is one observed change. The contract fields are the first block;
// the remaining fields are additive forensic context for the operator surface.
type TitanEvent struct {
	ID                  string           `json:"id"`
	ObservedUTC         time.Time        `json:"observed_utc"`
	Path                string           `json:"path"`
	ChangeType          TitanChangeType  `json:"change_type"`
	TrustState          TitanTrustState  `json:"trust_state"`
	AuthorizationReason string           `json:"authorization_reason"`
	Response            string           `json:"response"`
	CorrelationQuality  TitanCorrelation `json:"correlation_quality"`
	Severity            string           `json:"severity"`
	Sensor              string           `json:"sensor"`
	SHA256              string           `json:"sha256"`
	Size                int64            `json:"size"`

	Mode              TitanMode  `json:"mode,omitempty"`
	FileMode          string     `json:"file_mode,omitempty"`
	Review            string     `json:"review,omitempty"`
	ReviewReason      string     `json:"review_reason,omitempty"`
	ReviewUTC         *time.Time `json:"review_utc,omitempty"`
	Containment       string     `json:"containment,omitempty"`
	ContainmentDetail string     `json:"containment_detail,omitempty"`
	QuarantineID      string     `json:"quarantine_id,omitempty"`
	EvidenceID        string     `json:"evidence_id,omitempty"`
	JournalSequence   uint64     `json:"journal_sequence"`
}

type titanQuarantineItem struct {
	ID           string    `json:"id"`
	EventID      string    `json:"event_id"`
	Path         string    `json:"path"`
	SampleSHA256 string    `json:"sample_sha256"`
	CreatedUTC   time.Time `json:"created_utc"`
	State        string    `json:"state"`
}

type TitanQuarantineStatus struct {
	Items []titanQuarantineItem `json:"items"`
	Count int                   `json:"count"`
}

type titanPolicyDocument struct {
	Schema   string      `json:"schema"`
	Version  int         `json:"version"`
	Policy   titanPolicy `json:"policy"`
	SavedUTC time.Time   `json:"saved_utc"`
}

type titanPolicy struct {
	Mode             TitanMode `json:"mode"`
	Armed            bool      `json:"armed"`
	AutoContain      bool      `json:"auto_contain"`
	Roots            []string  `json:"roots"`
	Allowlist        []string  `json:"allowlist"`
	DevelopmentRoots []string  `json:"development_roots"`
	ProtectedPaths   []string  `json:"protected_paths"`
	MaxFileBytes     int64     `json:"max_file_bytes"`
	MaxEvents        int       `json:"max_events"`
	JournalMaxBytes  int64     `json:"journal_max_bytes"`
	UpdatedUTC       time.Time `json:"updated_utc"`
	Revision         uint64    `json:"revision"`
}

type titanJournalDocument struct {
	Schema      string                `json:"schema"`
	Version     int                   `json:"version"`
	SavedUTC    time.Time             `json:"saved_utc"`
	TotalEvents uint64                `json:"total_events"`
	Events      []TitanEvent          `json:"events"`
	Quarantine  []titanQuarantineItem `json:"quarantine"`
}

// titanObservation is the normalized sensor report handed to the engine.
type titanObservation struct {
	Path        string
	ChangeType  TitanChangeType
	ObservedUTC time.Time
	Sensor      string
	// Live is true when the sensor observed the change directly instead of a
	// periodic reconciliation reconstructing it from a scan diff.
	Live bool
}

// titanObserver is the platform sensor. Implementations are bounded and must
// stop when the context is cancelled.
type titanObserver interface {
	Run(ctx context.Context, roots []string, out chan<- titanObservation) error
}

// titanFIMLookup exposes the already verified FIM baseline to the trust engine.
type titanFIMLookup interface {
	TitanBaselineRecord(path string) (FIMRecord, uint64, bool)
}

// titanPackageOwner is package-manager ownership evidence for one path.
type titanPackageOwner struct {
	Manager string
	Package string
}

// titanPackageVerifier resolves package ownership with a bounded, fixed-argument
// local query. A missing verifier or a missing manager is missing evidence and
// must lower trust, never raise it.
type titanPackageVerifier interface {
	Owner(ctx context.Context, path string) (titanPackageOwner, bool, error)
}

// titanContextProvider exposes time-correlated XDR context. Titan never turns
// this into actor attribution: a temporal correlation is labelled TEMPORAL and
// nothing more.
type titanContextProvider interface {
	RecentIncidents(ctx context.Context, since time.Time) (int, error)
}

type titanContainmentResult struct {
	TransactionID string
	ObjectID      string
	SHA256        string
}

// titanContainment is the existing quarantine transaction applier. Titan must
// never delete and must never report containment it did not verify.
type titanContainment interface {
	RequestContain(ctx context.Context, path, reason string) (titanContainmentResult, error)
	Items() []titanQuarantineItem
}

// TitanDeps are the real host integrations handed in by the composition root.
type TitanDeps struct {
	Version     string
	DataRoot    string
	FIM         titanFIMLookup
	Packages    titanPackageVerifier
	Context     titanContextProvider
	Containment titanContainment
	Observer    titanObserver
	Evidence    func(EvidenceRecord) error
	Events      func(Event)
	Now         func() time.Time
}

type TitanEngine struct {
	mu sync.RWMutex

	version     string
	deps        TitanDeps
	policy      titanPolicy
	policyPath  string
	journalPath string

	events       []TitanEvent
	quarantine   []titanQuarantineItem
	totalEvents  uint64
	sequence     uint64
	openFindings int
	trustCounts  TitanTrustCounts
	corrCounts   TitanCorrelationCounts

	sensor      TitanSensorStatus
	loadWarning string
	enabled     bool

	rootsChanged chan struct{}
	running      bool
}

// NewTitanEngine validates the configuration, restores the bounded policy and
// journal, and returns the engine. A corrupt persisted document never stops the
// control plane: it starts from safe defaults, keeps the corrupt file untouched
// for forensics and reports the condition through the sensor/status error.
func NewTitanEngine(cfg TitanConfig, deps TitanDeps) (*TitanEngine, error) {
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	if deps.DataRoot == "" || !filepath.IsAbs(deps.DataRoot) {
		return nil, errors.New("Titan data root must be absolute")
	}
	if deps.Version == "" {
		return nil, errors.New("Titan version is required")
	}
	policyPath := cfg.PolicyFile
	if policyPath == "" {
		policyPath = filepath.Join(deps.DataRoot, "titan-policy.json")
	}
	journalPath := cfg.JournalFile
	if journalPath == "" {
		journalPath = filepath.Join(deps.DataRoot, "titan-journal.json")
	}
	if !filepath.IsAbs(policyPath) || !filepath.IsAbs(journalPath) {
		return nil, errors.New("Titan policy and journal paths must be absolute")
	}
	policy, err := titanPolicyFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	engine := &TitanEngine{
		version: deps.Version, deps: deps, enabled: cfg.Enabled,
		policy: policy, policyPath: policyPath, journalPath: journalPath,
		rootsChanged: make(chan struct{}, 1),
		sensor:       TitanSensorStatus{State: "disabled"},
	}
	if cfg.Enabled {
		engine.sensor = TitanSensorStatus{State: "degraded", Error: "sensor not started"}
	}
	if err := engine.loadPolicy(); err != nil {
		engine.loadWarning = "persisted Titan policy rejected; configured safe defaults are active"
	}
	if err := engine.loadJournal(); err != nil {
		if engine.loadWarning != "" {
			engine.loadWarning += "; "
		}
		engine.loadWarning += "persisted Titan journal rejected; starting with an empty bounded journal"
	}
	engine.recountLocked()
	return engine, nil
}

func titanPolicyFromConfig(cfg TitanConfig) (titanPolicy, error) {
	mode := TitanMode(strings.ToUpper(strings.TrimSpace(cfg.Mode)))
	if mode == "" {
		mode = TitanModeObserve
	}
	policy := titanPolicy{
		Mode: mode, Armed: cfg.Armed, AutoContain: cfg.AutoContain,
		Roots: append([]string(nil), cfg.Roots...), Allowlist: append([]string(nil), cfg.Allowlist...),
		DevelopmentRoots: append([]string(nil), cfg.DevelopmentRoots...), ProtectedPaths: append([]string(nil), cfg.ProtectedPaths...),
		MaxFileBytes: cfg.MaxFileBytes, MaxEvents: cfg.MaxEvents, JournalMaxBytes: cfg.JournalMaxBytes,
	}
	if err := normalizeTitanPolicy(&policy); err != nil {
		return titanPolicy{}, err
	}
	return policy, nil
}

// normalizeTitanPolicy canonicalizes and validates every policy field. It is
// used for configuration, for the persisted document and for the API request,
// so all three paths share one validator.
func normalizeTitanPolicy(policy *titanPolicy) error {
	if policy == nil {
		return errors.New("Titan policy is nil")
	}
	if !validTitanMode(policy.Mode) {
		return errors.New("Titan mode must be OBSERVE, CONTAIN or STRICT")
	}
	roots, err := normalizeTitanPaths(policy.Roots, titanMaxRoots)
	if err != nil {
		return fmt.Errorf("Titan roots: %w", err)
	}
	if len(roots) == 0 {
		return errors.New("Titan requires at least one configured root")
	}
	allowlist, err := normalizeTitanPaths(policy.Allowlist, titanMaxAllowlist)
	if err != nil {
		return fmt.Errorf("Titan allowlist: %w", err)
	}
	devRoots, err := normalizeTitanPaths(policy.DevelopmentRoots, titanMaxRoots)
	if err != nil {
		return fmt.Errorf("Titan development roots: %w", err)
	}
	protected, err := normalizeTitanPaths(policy.ProtectedPaths, titanMaxRoots*2)
	if err != nil {
		return fmt.Errorf("Titan protected paths: %w", err)
	}
	if policy.MaxFileBytes == 0 {
		policy.MaxFileBytes = 16 << 20
	}
	if policy.MaxFileBytes < titanMinFileBytes || policy.MaxFileBytes > titanMaxFileBytes {
		return fmt.Errorf("Titan max file bytes must be between %d and %d", titanMinFileBytes, titanMaxFileBytes)
	}
	if policy.MaxEvents == 0 {
		policy.MaxEvents = 500
	}
	if policy.MaxEvents < titanMinJournalEvents || policy.MaxEvents > titanMaxJournalEvents {
		return fmt.Errorf("Titan max journal events must be between %d and %d", titanMinJournalEvents, titanMaxJournalEvents)
	}
	if policy.JournalMaxBytes == 0 {
		policy.JournalMaxBytes = 4 << 20
	}
	if policy.JournalMaxBytes < titanMinJournalBytes || policy.JournalMaxBytes > titanMaxJournalBytes {
		return fmt.Errorf("Titan journal bytes must be between %d and %d", titanMinJournalBytes, titanMaxJournalBytes)
	}
	policy.Roots, policy.Allowlist, policy.DevelopmentRoots, policy.ProtectedPaths = roots, allowlist, devRoots, protected
	return nil
}

func normalizeTitanPaths(values []string, limit int) ([]string, error) {
	if len(values) > limit {
		return nil, fmt.Errorf("list exceeds %d entries", limit)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if len(value) > titanMaxPathBytes || strings.ContainsRune(value, '\x00') {
			return nil, errors.New("path contains NUL or is too long")
		}
		if !filepath.IsAbs(value) {
			return nil, fmt.Errorf("path %q is not absolute", value)
		}
		clean := filepath.Clean(value)
		if clean != value {
			return nil, fmt.Errorf("path %q is not canonical", value)
		}
		if clean == string(filepath.Separator) {
			return nil, errors.New("the filesystem root is not a bounded Titan target")
		}
		if _, duplicate := seen[clean]; duplicate {
			continue
		}
		seen[clean] = struct{}{}
		result = append(result, clean)
	}
	sort.Strings(result)
	return result, nil
}

func (e *TitanEngine) loadPolicy() error {
	raw, err := readBoundedPrivateFile(e.policyPath, titanMaxPolicyBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document titanPolicyDocument
	if err := decoder.Decode(&document); err != nil {
		return errors.New("Titan policy document is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Titan policy document contains trailing data")
	}
	if document.Schema != titanPolicySchema || document.Version != 1 {
		return errors.New("Titan policy schema is unsupported")
	}
	policy := document.Policy
	if err := normalizeTitanPolicy(&policy); err != nil {
		return err
	}
	e.policy = policy
	return nil
}

func (e *TitanEngine) loadJournal() error {
	raw, err := readBoundedPrivateFile(e.journalPath, titanMaxJournalReadBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document titanJournalDocument
	if err := decoder.Decode(&document); err != nil {
		return errors.New("Titan journal document is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Titan journal document contains trailing data")
	}
	if document.Schema != titanJournalSchema || document.Version != titanJournalVersion {
		return errors.New("Titan journal schema is unsupported")
	}
	if len(document.Events) > titanMaxJournalEvents || len(document.Quarantine) > titanMaxQuarantine {
		return errors.New("Titan journal exceeds its bounds")
	}
	for index := range document.Events {
		if err := validateTitanEvent(document.Events[index]); err != nil {
			return err
		}
	}
	e.events = append([]TitanEvent(nil), document.Events...)
	e.quarantine = append([]titanQuarantineItem(nil), document.Quarantine...)
	e.totalEvents = document.TotalEvents
	if len(e.events) > 0 {
		e.sequence = e.events[len(e.events)-1].JournalSequence
	}
	return nil
}

func validateTitanEvent(event TitanEvent) error {
	if len(event.ID) < 8 || len(event.ID) > titanMaxEventIDBytes {
		return errors.New("Titan journal event identifier is invalid")
	}
	if event.ObservedUTC.IsZero() || len(event.Path) == 0 || len(event.Path) > titanMaxPathBytes || !filepath.IsAbs(event.Path) {
		return errors.New("Titan journal event path or time is invalid")
	}
	if !validTitanChangeType(event.ChangeType) {
		return errors.New("Titan journal event change type is invalid")
	}
	switch event.TrustState {
	case TitanTrustAuthorized, TitanTrustTolerated, TitanTrustUnexpected, TitanTrustCompromised:
	default:
		return errors.New("Titan journal event trust state is invalid")
	}
	if len(event.AuthorizationReason) > 512 || len(event.Response) > 128 || len(event.SHA256) > 64 {
		return errors.New("Titan journal event text is outside bounds")
	}
	return nil
}

// Run starts the bounded sensor loop and the policy-driven observation pipeline.
// A sensor failure degrades the Titan status and is recorded as evidence instead
// of being hidden.
func (e *TitanEngine) Run(ctx context.Context) {
	if e == nil || !e.enabled {
		return
	}
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()
	observer := e.deps.Observer
	if observer == nil {
		observer = newTitanPlatformObserver()
	}
	for {
		if ctx.Err() != nil {
			return
		}
		roots := e.currentRoots()
		observations := make(chan titanObservation, titanMaxSensorEvents)
		sensorCtx, cancel := context.WithCancel(ctx)
		sensorErr := make(chan error, 1)
		go func() {
			sensorErr <- observer.Run(sensorCtx, roots, observations)
		}()
		e.setSensor("healthy", "")
		e.recordEvidence(EvidenceRecord{
			Severity: "info", Kind: "titan.sensor.started", Source: "titan",
			Message: fmt.Sprintf("Titan sensor observing %d configured roots", len(roots)),
		})
		restart, runErr := e.watchLoop(sensorCtx, observations, sensorErr)
		cancel()
		if !restart {
			<-sensorErr
			return
		}
		if runErr == nil {
			runErr = <-sensorErr
		}
		if ctx.Err() != nil {
			return
		}
		if runErr != nil {
			e.setSensor("degraded", boundedTitanText(runErr.Error(), 240))
			e.recordEvidence(EvidenceRecord{
				Severity: "high", Kind: "titan.sensor.failed", Source: "titan",
				Message: "Titan integrity sensor stopped: " + boundedTitanText(runErr.Error(), 240),
			})
			e.emitEvent(Event{
				Severity: "critical", Kind: "titan.sensor.degraded", Source: "titan",
				Message: "Titan integrity sensor is degraded: " + boundedTitanText(runErr.Error(), 240),
			})
		} else {
			e.setSensor("degraded", "sensor stopped without an error")
		}
		if !restart {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (e *TitanEngine) watchLoop(ctx context.Context, observations <-chan titanObservation, sensorErr <-chan error) (bool, error) {
	for {
		select {
		case <-ctx.Done():
			return false, nil
		case <-e.rootsChanged:
			return true, nil
		case err := <-sensorErr:
			return true, err
		case observation, ok := <-observations:
			if !ok {
				return true, nil
			}
			e.observe(observation)
		}
	}
}
func (e *TitanEngine) currentRoots() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.policy.Roots...)
}

func (e *TitanEngine) setSensor(state, message string) {
	e.mu.Lock()
	e.sensor.State = state
	e.sensor.Error = message
	e.mu.Unlock()
}

func (e *TitanEngine) setSensorObservation(at time.Time) {
	e.mu.Lock()
	e.sensor.State = "healthy"
	e.sensor.Error = ""
	value := at.UTC()
	e.sensor.LastObservationUTC = &value
	e.mu.Unlock()
}

func (e *TitanEngine) recordEvidence(record EvidenceRecord) {
	if e == nil || e.deps.Evidence == nil {
		return
	}
	if record.Time.IsZero() {
		record.Time = e.now()
	}
	if record.Source == "" {
		record.Source = "titan"
	}
	_ = e.deps.Evidence(record)
}

func (e *TitanEngine) emitEvent(event Event) {
	if e == nil || e.deps.Events == nil {
		return
	}
	e.deps.Events(event)
}

func (e *TitanEngine) now() time.Time {
	if e == nil || e.deps.Now == nil {
		return time.Now().UTC()
	}
	return e.deps.Now().UTC()
}

// observe processes exactly one normalized sensor report through trust
// evaluation, response policy, evidence and the bounded journal.
func (e *TitanEngine) observe(observation titanObservation) {
	e.mu.RLock()
	enabled := e.enabled
	e.mu.RUnlock()
	if !enabled || observation.Path == "" {
		return
	}
	observedUTC := observation.ObservedUTC.UTC()
	if observedUTC.IsZero() {
		observedUTC = e.now()
	}
	policy := e.currentPolicy()
	identity := readTitanIdentity(observation.Path, policy.MaxFileBytes)
	event := TitanEvent{
		ID:                 randomID(),
		ObservedUTC:        observedUTC,
		Path:               identity.Path,
		ChangeType:         observation.ChangeType,
		Sensor:             observation.Sensor,
		SHA256:             identity.SHA256,
		Size:               identity.Size,
		FileMode:           identity.FileMode,
		Review:             "PENDING",
		CorrelationQuality: TitanCorrelationNone,
	}
	if event.Sensor == "" {
		event.Sensor = "linux-inotify"
	}
	e.attachContext(&event, observation, observedUTC)
	e.evaluateTrust(&event, observation, policy, identity)
	e.applyResponse(&event, policy)
	e.appendEvent(event)
	e.setSensorObservation(observedUTC)
	e.recordEvidence(EvidenceRecord{
		ID: event.ID, Time: event.ObservedUTC, Severity: event.Severity,
		Kind: "titan." + strings.ToLower(string(event.ChangeType)), Source: "titan",
		Message: "Titan observation: " + event.TrustState.String() + " - " + event.AuthorizationReason,
		Target:  event.Path,
	})
	if event.Severity == "critical" || event.Severity == "high" {
		e.emitEvent(Event{
			Severity: event.Severity, Kind: "titan.finding", Source: "titan",
			Message: fmt.Sprintf("Titan %s change on %s: %s (%s)", event.TrustState.String(), event.Path, event.AuthorizationReason, event.Response),
			Target:  event.Path,
		})
	}
}

func (e *TitanEngine) attachContext(event *TitanEvent, observation titanObservation, at time.Time) {
	if e.deps.Context == nil {
		event.CorrelationQuality = TitanCorrelationNone
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	count, err := e.deps.Context.RecentIncidents(ctx, at.Add(-2*time.Minute))
	if err != nil || count <= 0 {
		event.CorrelationQuality = TitanCorrelationNone
		return
	}
	// Only a temporal correlation exists: no process, file-handle or network
	// evidence ties the incident to this specific change, so it is never
	// upgraded to OBSERVED and no actor is named.
	event.CorrelationQuality = TitanCorrelationTemporal
}

func (e *TitanEngine) currentPolicy() titanPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	policy := e.policy
	policy.Roots = append([]string(nil), e.policy.Roots...)
	policy.Allowlist = append([]string(nil), e.policy.Allowlist...)
	policy.DevelopmentRoots = append([]string(nil), e.policy.DevelopmentRoots...)
	policy.ProtectedPaths = append([]string(nil), e.policy.ProtectedPaths...)
	return policy
}

// Policy returns the effective owner policy.
func (e *TitanEngine) Policy() titanPolicy {
	if e == nil {
		return titanPolicy{}
	}
	return e.currentPolicy()
}

// Enabled reports whether the module is configured to observe.
func (e *TitanEngine) Enabled() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// Status is the contract of GET /api/v1/titan/status.
func (e *TitanEngine) Status() TitanStatus {
	if e == nil {
		return TitanStatus{Mode: TitanModeObserve, Sensor: TitanSensorStatus{State: "disabled"}}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	sensor := e.sensor
	if sensor.State == "" {
		sensor.State = "degraded"
	}
	return TitanStatus{
		Version: e.version, Mode: e.policy.Mode, Armed: e.policy.Armed, AutoContain: e.policy.AutoContain,
		Trust: e.trustCounts, Correlation: e.corrCounts, EventsTotal: e.totalEvents,
		OpenFindings: e.openFindings, QuarantineCount: len(e.quarantine),
		Sensor: sensor, UpdatedUTC: e.now(),
	}
}

func (e *TitanEngine) appendEvent(event TitanEvent) {
	e.mu.Lock()
	e.sequence++
	event.JournalSequence = e.sequence
	e.events = append(e.events, event)
	maxEvents := e.policy.MaxEvents
	if len(e.events) > maxEvents {
		e.events = append([]TitanEvent(nil), e.events[len(e.events)-maxEvents:]...)
	}
	e.totalEvents++
	if event.Containment == TitanResponseContained && event.QuarantineID != "" {
		e.quarantine = append(e.quarantine, titanQuarantineItem{
			ID: event.QuarantineID, EventID: event.ID, Path: event.Path,
			SampleSHA256: event.SHA256, CreatedUTC: event.ObservedUTC, State: "APPLIED",
		})
		if len(e.quarantine) > titanMaxQuarantine {
			e.quarantine = append([]titanQuarantineItem(nil), e.quarantine[len(e.quarantine)-titanMaxQuarantine:]...)
		}
	}
	e.recountLocked()
	document := e.journalDocumentLocked()
	e.mu.Unlock()
	if err := e.persistJournal(document); err != nil {
		e.recordEvidence(EvidenceRecord{
			Severity: "high", Kind: "titan.journal.persist_failed", Source: "titan",
			Message: "Titan journal could not be persisted: " + boundedTitanText(err.Error(), 240),
		})
	}
}

func (e *TitanEngine) recountLocked() {
	e.trustCounts = TitanTrustCounts{}
	e.corrCounts = TitanCorrelationCounts{}
	e.openFindings = 0
	for _, event := range e.events {
		switch event.TrustState {
		case TitanTrustAuthorized:
			e.trustCounts.Authorized++
		case TitanTrustTolerated:
			e.trustCounts.Tolerated++
		case TitanTrustUnexpected:
			e.trustCounts.Unexpected++
			if event.Review == "" || event.Review == "PENDING" {
				e.openFindings++
			}
		case TitanTrustCompromised:
			e.trustCounts.Compromised++
			if event.Review == "" || event.Review == "PENDING" {
				e.openFindings++
			}
		}
		switch event.CorrelationQuality {
		case TitanCorrelationObserved:
			e.corrCounts.Observed++
		case TitanCorrelationTemporal:
			e.corrCounts.Temporal++
		default:
			e.corrCounts.None++
		}
	}
}

func (e *TitanEngine) journalDocumentLocked() titanJournalDocument {
	events := append([]TitanEvent(nil), e.events...)
	quarantine := append([]titanQuarantineItem(nil), e.quarantine...)
	return titanJournalDocument{
		Schema: titanJournalSchema, Version: titanJournalVersion, SavedUTC: e.now(),
		TotalEvents: e.totalEvents, Events: events, Quarantine: quarantine,
	}
}

func (e *TitanEngine) persistJournal(document titanJournalDocument) error {
	maxBytes := e.currentPolicy().JournalMaxBytes
	payload, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if int64(len(payload)+1) > maxBytes {
		e.mu.Lock()
		for len(e.events) > titanMinJournalEvents {
			e.events = append([]TitanEvent(nil), e.events[1:]...)
			document.Events = append([]TitanEvent(nil), e.events...)
			payload, err = json.Marshal(document)
			if err != nil {
				break
			}
			if int64(len(payload)+1) <= maxBytes {
				break
			}
		}
		document.Events = append([]TitanEvent(nil), e.events...)
		e.recountLocked()
		e.mu.Unlock()
		if err != nil {
			return err
		}
		payload, err = json.Marshal(document)
		if err != nil {
			return err
		}
		if int64(len(payload)+1) > maxBytes {
			return errors.New("Titan journal exceeds its bounded byte budget")
		}
	}
	return atomicWriteFile(e.journalPath, append(payload, '\n'), 0o600)
}

// Events returns newest-first events older than the opaque cursor.
func (e *TitanEngine) Events(limit int, before string) ([]TitanEvent, string, error) {
	if e == nil {
		return nil, "", errors.New("Titan engine unavailable")
	}
	if limit <= 0 {
		limit = titanDefaultLimit
	}
	if limit > titanMaxLimit {
		limit = titanMaxLimit
	}
	var beforeSequence uint64
	if strings.TrimSpace(before) != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(before)
		if err != nil {
			return nil, "", errors.New("Titan event cursor is malformed")
		}
		beforeSequence, err = strconv.ParseUint(string(decoded), 10, 64)
		if err != nil {
			return nil, "", errors.New("Titan event cursor is malformed")
		}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]TitanEvent, 0, limit)
	for index := len(e.events) - 1; index >= 0; index-- {
		event := e.events[index]
		if beforeSequence != 0 && event.JournalSequence >= beforeSequence {
			continue
		}
		result = append(result, cloneTitanEvent(event))
		if len(result) >= limit {
			break
		}
	}
	next := ""
	if len(result) > 0 {
		oldest := result[len(result)-1].JournalSequence
		for index := len(e.events) - 1; index >= 0; index-- {
			if e.events[index].JournalSequence < oldest {
				next = titanEventCursor(oldest)
				break
			}
		}
	}
	return result, next, nil
}

func titanEventCursor(sequence uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(sequence, 10)))
}

func cloneTitanEvent(event TitanEvent) TitanEvent {
	clone := event
	if event.ReviewUTC != nil {
		value := *event.ReviewUTC
		clone.ReviewUTC = &value
	}
	return clone
}

// ApplyPolicy validates and atomically persists an owner policy change.
func (e *TitanEngine) ApplyPolicy(mode TitanMode, armed, autoContain bool, reason string) (TitanStatus, error) {
	if e == nil {
		return TitanStatus{}, errors.New("Titan engine unavailable")
	}
	if _, err := validateTitanReason(reason); err != nil {
		return e.Status(), err
	}
	e.mu.Lock()
	next := e.policy
	next.Mode = mode
	next.Armed = armed
	next.AutoContain = autoContain
	next.Revision++
	next.UpdatedUTC = e.now()
	if err := normalizeTitanPolicy(&next); err != nil {
		e.mu.Unlock()
		return e.Status(), err
	}
	previous := e.policy
	e.policy = next
	document := titanPolicyDocument{Schema: titanPolicySchema, Version: 1, Policy: next, SavedUTC: next.UpdatedUTC}
	payload, err := json.Marshal(document)
	e.mu.Unlock()
	if err != nil {
		e.mu.Lock()
		e.policy = previous
		e.mu.Unlock()
		return e.Status(), err
	}
	if err := atomicWriteFile(e.policyPath, append(payload, '\n'), 0o600); err != nil {
		e.mu.Lock()
		e.policy = previous
		e.mu.Unlock()
		return e.Status(), err
	}
	e.recordEvidence(EvidenceRecord{
		Severity: "high", Kind: "titan.policy.updated", Source: "titan",
		Message: fmt.Sprintf("Titan policy set to %s (armed=%t auto_contain=%t); reason-sha256=%s", next.Mode, next.Armed, next.AutoContain, titanReasonDigest(reason)),
	})
	if next.Mode != previous.Mode || next.Armed != previous.Armed {
		e.emitEvent(Event{Severity: "high", Kind: "titan.policy.updated", Source: "titan",
			Message: fmt.Sprintf("Titan policy changed from %s to %s", previous.Mode, next.Mode)})
	}
	e.signalRootsChanged()
	return e.Status(), nil
}

func (e *TitanEngine) signalRootsChanged() {
	select {
	case e.rootsChanged <- struct{}{}:
	default:
	}
}

// Review records an operator decision for one finding.
func (e *TitanEngine) Review(id, decision, reason string) (TitanEvent, error) {
	if e == nil {
		return TitanEvent{}, errors.New("Titan engine unavailable")
	}
	if _, err := validateTitanReason(reason); err != nil {
		return TitanEvent{}, err
	}
	normalized := strings.ToUpper(strings.TrimSpace(decision))
	switch normalized {
	case "REVIEWED", "TOLERATED", "ESCALATED":
	default:
		return TitanEvent{}, errors.New("Titan review decision must be REVIEWED, TOLERATED or ESCALATED")
	}
	if len(id) < 8 || len(id) > titanMaxEventIDBytes {
		return TitanEvent{}, errors.New("Titan event identifier is invalid")
	}
	e.mu.Lock()
	found := -1
	for index := len(e.events) - 1; index >= 0; index-- {
		if e.events[index].ID == id {
			found = index
			break
		}
	}
	if found < 0 {
		e.mu.Unlock()
		return TitanEvent{}, errors.New("Titan event not found")
	}
	now := e.now()
	e.events[found].Review = normalized
	e.events[found].ReviewReason = boundedTitanText(reason, titanMaxReasonBytes)
	e.events[found].ReviewUTC = &now
	event := cloneTitanEvent(e.events[found])
	e.recountLocked()
	document := e.journalDocumentLocked()
	e.mu.Unlock()
	if err := e.persistJournal(document); err != nil {
		return event, err
	}
	e.recordEvidence(EvidenceRecord{
		Time: now, Severity: "high", Kind: "titan.review", Source: "titan",
		Message: fmt.Sprintf("Titan event %s reviewed as %s; reason-sha256=%s", id, normalized, titanReasonDigest(reason)),
		Target:  event.Path,
	})
	return event, nil
}

// Contain requests containment of one observed change through the existing
// quarantine transaction applier. It never deletes and never reports success it
// did not verify.
func (e *TitanEngine) Contain(ctx context.Context, eventID, reason string) (titanContainResponse, error) {
	if e == nil {
		return titanContainResponse{}, errors.New("Titan engine unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := validateTitanReason(reason); err != nil {
		return titanContainResponse{}, err
	}
	e.mu.RLock()
	var event TitanEvent
	found := false
	for index := len(e.events) - 1; index >= 0; index-- {
		if e.events[index].ID == eventID {
			event = cloneTitanEvent(e.events[index])
			found = true
			break
		}
	}
	containment := e.deps.Containment
	e.mu.RUnlock()
	if !found {
		return titanContainResponse{}, errors.New("Titan event not found")
	}
	response := titanContainResponse{Status: "REJECTED", Action: "NONE", EventID: eventID}
	if event.TrustState == TitanTrustAuthorized {
		response.Detail = "authorized changes are not contained"
		return response, nil
	}
	if containment == nil {
		response.Status = "UNAVAILABLE"
		response.Detail = "privileged quarantine core is unavailable"
		return response, nil
	}
	if err := e.validateTitanContainSafePath(event.Path); err != nil {
		response.Status = "UNAVAILABLE"
		response.Detail = err.Error()
		return response, nil
	}
	result, err := containment.RequestContain(ctx, event.Path, boundedTitanText(reason, 240))
	if err != nil {
		response.Status = "UNAVAILABLE"
		response.Detail = "quarantine transaction rejected: " + boundedTitanText(err.Error(), 200)
		e.recordEvidence(EvidenceRecord{
			Severity: "high", Kind: "titan.contain.failed", Source: "titan",
			Message: "Titan containment failed closed", Target: event.Path,
		})
		return response, nil
	}
	response.Status = "CONTAINED"
	response.Action = "QUARANTINE"
	response.Detail = "object moved to the quarantine vault by verified transaction " + result.TransactionID
	response.QuarantineID = result.TransactionID
	response.SHA256 = result.SHA256
	now := e.now()
	e.mu.Lock()
	for index := len(e.events) - 1; index >= 0; index-- {
		if e.events[index].ID == event.ID {
			e.events[index].Response = TitanResponseContained
			e.events[index].Containment = "CONTAINED"
			e.events[index].QuarantineID = result.TransactionID
			e.events[index].ContainmentDetail = response.Detail
			break
		}
	}
	e.quarantine = append(e.quarantine, titanQuarantineItem{
		ID: result.TransactionID, EventID: event.ID, Path: event.Path,
		SampleSHA256: result.SHA256, CreatedUTC: now, State: "APPLIED",
	})
	if len(e.quarantine) > titanMaxQuarantine {
		e.quarantine = append([]titanQuarantineItem(nil), e.quarantine[len(e.quarantine)-titanMaxQuarantine:]...)
	}
	e.recountLocked()
	document := e.journalDocumentLocked()
	e.mu.Unlock()
	_ = e.persistJournal(document)
	e.recordEvidence(EvidenceRecord{
		Severity: "critical", Kind: "titan.contained", Source: "titan",
		Message: "Titan containment completed through the quarantine transaction engine",
		Target:  event.Path,
	})
	return response, nil
}

type titanContainResponse struct {
	Status       string `json:"status"`
	Action       string `json:"action"`
	Detail       string `json:"detail"`
	EventID      string `json:"event_id,omitempty"`
	QuarantineID string `json:"quarantine_id,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
}

// Quarantine returns the bounded Titan-side quarantine view, refreshed from the
// transaction engine when it is available.
func (e *TitanEngine) Quarantine() TitanQuarantineStatus {
	if e == nil {
		return TitanQuarantineStatus{Items: []titanQuarantineItem{}}
	}
	var items titanContainment
	e.mu.RLock()
	items = e.deps.Containment
	e.mu.RUnlock()
	statuses := map[string]string{}
	if items != nil {
		for _, item := range items.Items() {
			statuses[item.ID] = item.State
		}
	}
	e.mu.RLock()
	result := make([]titanQuarantineItem, 0, len(e.quarantine))
	for _, item := range e.quarantine {
		if state, exists := statuses[item.ID]; exists && state != "" {
			item.State = state
		}
		result = append(result, item)
	}
	e.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedUTC.After(result[j].CreatedUTC) })
	return TitanQuarantineStatus{Items: result, Count: len(result)}
}

func (state TitanTrustState) String() string { return string(state) }

func validateTitanReason(reason string) (string, error) {
	trimmed := strings.TrimSpace(reason)
	if len(trimmed) < titanMinReasonBytes || len(trimmed) > titanMaxReasonBytes {
		return "", fmt.Errorf("reason must be %d-%d bytes", titanMinReasonBytes, titanMaxReasonBytes)
	}
	if !utf8Valid(trimmed) {
		return "", errors.New("reason is not valid UTF-8")
	}
	for _, character := range trimmed {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("reason contains control characters")
		}
	}
	return trimmed, nil
}

func titanReasonDigest(reason string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(reason)))
	return hex.EncodeToString(digest[:])
}

func boundedTitanText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// utf8Valid reports whether value contains no invalid UTF-8 so the policy and
// review paths share one standard-library check.
func utf8Valid(value string) bool {
	return utf8.ValidString(value)
}
