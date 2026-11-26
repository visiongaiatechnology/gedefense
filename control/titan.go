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
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
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

	// Titan sensor restart backoff (FIND-031): a recoverable sensor error must never
	// turn the Run loop into a CPU spin. The delay already exceeds 100ms on the first
	// retry, doubles per consecutive failure, is capped and carries bounded positive
	// jitter so independent instances do not retry in lockstep.
	titanSensorRestartBackoffBase = 250 * time.Millisecond
	titanSensorRestartBackoffMax  = 30 * time.Second
	// titanSensorHealthyResetAfter marks a sensor run long enough that the next restart
	// starts from the base delay again instead of continuing to grow.
	titanSensorHealthyResetAfter = 30 * time.Second
)

type TitanMode string

const (
	TitanModeObserve TitanMode = "OBSERVE"
	TitanModeContain TitanMode = "CONTAIN"
	TitanModeStrict  TitanMode = "STRICT"
)

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
	mu        sync.RWMutex
	journalMu sync.Mutex

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

func (state TitanTrustState) String() string { return string(state) }
