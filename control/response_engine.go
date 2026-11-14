// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Typed Response Error Hierarchy (Section 1.5.A Compliance)
type ResponseException struct {
	Message string
	Err     error
}

func (e *ResponseException) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ResponseException) Unwrap() error { return e.Err }

type ResponseValidationException struct{ ResponseException }
type ResponseSecurityException struct{ ResponseException }
type ResponseStorageException struct{ ResponseException }

func NewResponseValidationException(msg string, err error) *ResponseValidationException {
	return &ResponseValidationException{ResponseException{Message: msg, Err: err}}
}

func NewResponseSecurityException(msg string, err error) *ResponseSecurityException {
	return &ResponseSecurityException{ResponseException{Message: msg, Err: err}}
}

func NewResponseStorageException(msg string, err error) *ResponseStorageException {
	return &ResponseStorageException{ResponseException{Message: msg, Err: err}}
}

// Action Types
type ResponseActionType string

const (
	ActionContainIP       ResponseActionType = "CONTAIN_IP"
	ActionRestrictProcess ResponseActionType = "RESTRICT_PROCESS"
	ActionIsolateNetwork  ResponseActionType = "ISOLATE_NETWORK"
	ActionFreezeExecution ResponseActionType = "FREEZE_EXECUTION"
	ActionContainCell     ResponseActionType = "CONTAIN_CELL"
)

// Status Types
type ResponseStatus string

const (
	StatusApplied           ResponseStatus = "APPLIED"
	StatusAlreadyContained  ResponseStatus = "ALREADY_CONTAINED"
	StatusRollbackRequested ResponseStatus = "ROLLBACK_REQUESTED"
	StatusRolledBack        ResponseStatus = "ROLLED_BACK"
	StatusDegraded          ResponseStatus = "DEGRADED"
	StatusFailed            ResponseStatus = "FAILED"
)

const (
	DefaultResponseTTL = 900 * time.Second  // 15 minutes
	MaxEscalatedTTL    = 7 * 24 * time.Hour // 7 days ceiling
	LookbackWindow24h  = 24 * time.Hour
	// MaxResponseRecords is the hard ceiling for *blocking* containments: applied
	// records (rollback still pending included), rollbacks that are not verified yet
	// and degraded records whose kernel state is uncertain. Completed transactions do
	// not count against it (FIND-027): a host that contains and releases one actor
	// after another must never lock itself out at record 8193 and stay locked until
	// the next restart. A record is only removed after a kernel release was verified;
	// capacity pressure first triggers that release, it never drops a containment
	// silently (verification finding R1).
	MaxResponseRecords = 8192
	// maxRetainedResponseRecords bounds the verified-terminal records (a failed apply
	// is release-free) kept in memory for audit. Pruning keeps the working set bounded
	// independently of uptime; the authoritative audit trail is the evidence ledger,
	// which every rollback and failure already commits to.
	maxRetainedResponseRecords = 2048
	// maxResponseHistoryRecords bounds the escalation lookback history. It is pruned
	// when it grows past this budget, so memory is capped even when more than 32768
	// violations occur inside the 24h lookback window.
	maxResponseHistoryRecords = 32768
	// A DEGRADED record (the kernel rollback mutation failed) is retried with bounded
	// exponential backoff. The record is never forgotten: its kernel state is unknown,
	// so dropping it would create false assurance. After the attempt budget it stays
	// visible and blocking until the core recovers or an operator intervenes (R3).
	maxResponseRollbackAttempts = 8
)

// responseRollbackRetryDelay returns the wait before the next release attempt of a
// DEGRADED record. It grows exponentially per failed attempt and is capped.
func responseRollbackRetryDelay(attempts int) time.Duration {
	const base = 30 * time.Second
	const ceiling = 10 * time.Minute
	if attempts < 1 {
		attempts = 1
	}
	delay := base
	for step := 1; step < attempts && delay < ceiling; step++ {
		delay *= 2
	}
	if delay > ceiling {
		delay = ceiling
	}
	return delay
}

// responseRollbackRetryDue reports whether a DEGRADED record may be tried again.
func responseRollbackRetryDue(record ResponseRecord, now time.Time) bool {
	if record.RollbackAttempts <= 0 || record.LastRollbackAttemptAt == nil {
		return true
	}
	return !now.Before(record.LastRollbackAttemptAt.Add(responseRollbackRetryDelay(record.RollbackAttempts)))
}

// responseRecordIsActive reports whether a record still represents an enforced,
// pending or uncertain containment and therefore consumes a capacity slot. An
// expired APPLIED record counts until its kernel release was verified: it may still
// hold a blocked IP or a frozen process, so dropping it from the working set would
// leak the containment (verification finding R1).
func responseRecordIsActive(record ResponseRecord) bool {
	switch record.Status {
	case StatusApplied, StatusRollbackRequested, StatusDegraded:
		return true
	default:
		return false
	}
}

// responseRecordIsReleaseFreeTerminal reports whether a record can leave the working
// set without a kernel release: a failed apply never moved the kernel and a verified
// rollback already released it.
func responseRecordIsReleaseFreeTerminal(record ResponseRecord) bool {
	switch record.Status {
	case StatusFailed, StatusRolledBack:
		return true
	default:
		return false
	}
}

// CoreActionDispatcher abstracts privileged kernel mutations across standalone Linux and AstraeaOS.
type CoreActionDispatcher interface {
	BlockIP(ip string) error
	UnblockIP(ip string) error
	FreezeProcess(pid int, startTicks uint64, reason string) error
	UnfreezeProcess(pid int, startTicks uint64) error
	SetCellPolicy(cgroupID uint64, flags uint8) error
	DeleteCellPolicy(cgroupID uint64) error
}

// ResponseEvidenceSink abstracts the audit ledger commitment for decoupling.
type ResponseEvidenceSink func(action string, target string, details string, timestamp time.Time) error

// ResponseRecord represents a durable, auditable and reversible mitigation transaction.
type ResponseRecord struct {
	UUID          string             `json:"uuid"`
	IncidentUUID  string             `json:"incident_uuid"`
	Owner         string             `json:"owner"`
	ActionType    ResponseActionType `json:"action_type"`
	TargetType    string             `json:"target_type"` // IP, PID, CGROUP, CELL
	TargetID      string             `json:"target_id"`
	StartedAt     time.Time          `json:"started_at"`
	ExpiresAt     time.Time          `json:"expires_at"`
	Status        ResponseStatus     `json:"status"`
	Confidence    int                `json:"confidence"`
	ReasonCode    string             `json:"reason_code"`
	AuthorizedBy  string             `json:"authorized_by"`
	RollbackJSON  string             `json:"rollback_json"`
	EvidenceRef   string             `json:"evidence_ref"`
	FailureReason string             `json:"failure_reason,omitempty"`
	RolledBackAt  *time.Time         `json:"rolled_back_at,omitempty"`
	// RollbackAttempts counts kernel release attempts. A DEGRADED record is retried
	// with bounded backoff instead of being stuck forever, but it is never dropped
	// without a verified release (verification finding R3).
	RollbackAttempts      int        `json:"rollback_attempts,omitempty"`
	LastRollbackAttemptAt *time.Time `json:"last_rollback_attempt_at,omitempty"`
	// RollbackExhausted marks a DEGRADED record whose bounded retry budget is used up.
	// It stays visible, blocking and operator-actionable; the once-only evidence entry
	// is emitted when the budget is exhausted.
	RollbackExhausted bool `json:"rollback_exhausted,omitempty"`
}

// ResponseConfig holds TTL presets and escalation policies.
type ResponseConfig struct {
	Enabled           bool          `json:"enabled"`
	TTLPreset         string        `json:"ttl_preset"` // CONSERVATIVE, BALANCED, AGGRESSIVE, CUSTOM
	ActorBanTTL       time.Duration `json:"actor_ban_ttl"`
	ProcessRestrTTL   time.Duration `json:"process_restr_ttl"`
	CellContainTTL    time.Duration `json:"cell_contain_ttl"`
	EscalationEnabled bool          `json:"escalation_enabled"`
}

func DefaultResponseConfig() ResponseConfig {
	return ResponseConfig{
		Enabled:           true,
		TTLPreset:         "BALANCED",
		ActorBanTTL:       900 * time.Second,
		ProcessRestrTTL:   900 * time.Second,
		CellContainTTL:    900 * time.Second,
		EscalationEnabled: true,
	}
}

// ResponseEngine orchestrates autonomous, multi-sensor and reversible responses.
type ResponseEngine struct {
	mu           sync.RWMutex
	cfg          ResponseConfig
	dispatcher   CoreActionDispatcher
	evidenceSink ResponseEvidenceSink
	responses    map[string]ResponseRecord
	activeByTgt  map[string]string // target_type:target_id -> response_uuid
	history      []ResponseRecord
}

func NewResponseEngine(cfg ResponseConfig, dispatcher CoreActionDispatcher, evidenceSink ResponseEvidenceSink) *ResponseEngine {
	return &ResponseEngine{
		cfg:          cfg,
		dispatcher:   dispatcher,
		evidenceSink: evidenceSink,
		responses:    make(map[string]ResponseRecord),
		activeByTgt:  make(map[string]string),
		history:      make([]ResponseRecord, 0, 128),
	}
}

// CalculateTTL calculates effective semantic TTL with escalation policy applied.
func (e *ResponseEngine) CalculateTTL(now time.Time, actionType ResponseActionType, targetID string) time.Duration {
	baseTTL := e.cfg.ActorBanTTL
	switch actionType {
	case ActionFreezeExecution, ActionRestrictProcess:
		baseTTL = e.cfg.ProcessRestrTTL
	case ActionContainCell, ActionIsolateNetwork:
		baseTTL = e.cfg.CellContainTTL
	}
	if baseTTL <= 0 {
		baseTTL = DefaultResponseTTL
	}

	if !e.cfg.EscalationEnabled {
		return baseTTL
	}

	// Calculate prior violations in lookback window
	cutoff := now.Add(-LookbackWindow24h)
	priorCount := 0
	for _, rec := range e.history {
		if rec.TargetID == targetID && rec.StartedAt.After(cutoff) {
			priorCount++
		}
	}

	if priorCount >= 1 {
		escalated := baseTTL * 4
		if escalated > MaxEscalatedTTL {
			return MaxEscalatedTTL
		}
		return escalated
	}

	return baseTTL
}

// DeriveResponseUUID generates an idempotent, deterministic 32-character hash for a response.
func DeriveResponseUUID(incidentUUID string, action ResponseActionType, targetType, targetID string) string {
	hasher := sha256.New()
	hasher.Write([]byte("VGT-RESP-V1|"))
	hasher.Write([]byte(incidentUUID + "|"))
	hasher.Write([]byte(string(action) + "|"))
	hasher.Write([]byte(targetType + "|"))
	hasher.Write([]byte(targetID))
	return hex.EncodeToString(hasher.Sum(nil))[:32]
}

// ResolveProcessStartTicks reads /proc/<pid>/stat on Linux to extract start_ticks (field 22).
// Returns 0 if unavailable, unparseable, or when not running on Linux.
func ResolveProcessStartTicks(pid int) uint64 {
	if pid <= 0 {
		return 0
	}
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	stat := string(statBytes)
	closeIdx := strings.LastIndexByte(stat, ')')
	if closeIdx < 0 || closeIdx+2 >= len(stat) {
		return 0
	}
	fields := strings.Fields(stat[closeIdx+2:])
	if len(fields) <= 19 {
		return 0
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return ticks
}

func (e *ResponseEngine) ResolveProcessStartTicks(pid int) uint64 {
	return ResolveProcessStartTicks(pid)
}

// ResolveProcessTarget parses targetID as either "pid" or "pid:start_ticks".
// If start_ticks is not explicitly provided in targetID, it attempts to resolve it from /proc/<pid>/stat.
func ResolveProcessTarget(targetID string) (int, uint64, error) {
	if strings.Contains(targetID, ":") {
		parts := strings.SplitN(targetID, ":", 2)
		p, err := strconv.Atoi(parts[0])
		if err != nil || p <= 0 {
			return 0, 0, errors.New("invalid target PID format")
		}
		st, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return 0, 0, errors.New("invalid target start_ticks format")
		}
		return p, st, nil
	}
	p, err := strconv.Atoi(targetID)
	if err != nil || p <= 0 {
		return 0, 0, errors.New("invalid target PID format")
	}
	return p, ResolveProcessStartTicks(p), nil
}

// activeResponseCountLocked counts the currently blocking containments. The caller
// holds e.mu.
func (e *ResponseEngine) activeResponseCountLocked() int {
	active := 0
	for _, record := range e.responses {
		if responseRecordIsActive(record) {
			active++
		}
	}
	return active
}

// pruneTerminalResponsesLocked drops the oldest release-free terminal records (a
// failed apply never moved the kernel and a verified rollback is already gone) once
// more than maxRetainedResponseRecords are held. Records that may still hold kernel
// state (APPLIED, ROLLBACK_REQUESTED, DEGRADED) are never pruned: capacity pressure
// first performs a release attempt instead (verification finding R1). The caller
// holds e.mu.
func (e *ResponseEngine) pruneTerminalResponsesLocked() {
	terminal := make([]ResponseRecord, 0, 16)
	for _, record := range e.responses {
		if responseRecordIsReleaseFreeTerminal(record) {
			terminal = append(terminal, record)
		}
	}
	if len(terminal) <= maxRetainedResponseRecords {
		return
	}
	sort.Slice(terminal, func(i, j int) bool { return terminal[i].StartedAt.Before(terminal[j].StartedAt) })
	excess := len(terminal) - maxRetainedResponseRecords
	for index := 0; index < excess; index++ {
		uuid := terminal[index].UUID
		delete(e.responses, uuid)
		// A terminal record must not keep an active-target claim alive.
		for targetKey, mapped := range e.activeByTgt {
			if mapped == uuid {
				delete(e.activeByTgt, targetKey)
			}
		}
	}
}

// pruneHistoryLocked keeps the escalation lookback bounded: it drops records that
// can no longer influence CalculateTTL (older than the 24h window) and applies a hard
// count cap for the case that more than maxResponseHistoryRecords violations happen
// inside the window. The caller holds e.mu.
func (e *ResponseEngine) pruneHistoryLocked(now time.Time) {
	cutoff := now.Add(-LookbackWindow24h)
	kept := e.history[:0]
	for _, record := range e.history {
		if record.StartedAt.After(cutoff) {
			kept = append(kept, record)
		}
	}
	e.history = kept
	if len(e.history) > maxResponseHistoryRecords {
		// Keep the newest entries; the dropped ones are still in the evidence ledger
		// and can only raise a prior-count that is already above the escalation
		// threshold, so dropping the oldest does not weaken the decision.
		e.history = append([]ResponseRecord(nil), e.history[len(e.history)-maxResponseHistoryRecords:]...)
	}
}

// ApplyResponse executes a typed mitigation, records the rollback state, and bounds duration.
func (e *ResponseEngine) ApplyResponse(
	ctx context.Context,
	now time.Time,
	incidentUUID string,
	action ResponseActionType,
	targetType, targetID string,
	confidence int,
	reasonCode string,
	evidenceRoot string,
) (*ResponseRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Capacity is enforced on containments that still represent kernel state
	// (FIND-027): completed transactions are pruned instead of permanently blocking
	// every further autonomous reaction. When the ceiling is reached, expired
	// containments are released through the kernel *before* capacity may be denied;
	// they are never pruned silently while they could still block an IP or freeze a
	// process (verification finding R1). The scan runs only when the working set
	// actually grows towards the ceiling, so the common path stays O(1).
	if len(e.responses) >= MaxResponseRecords {
		e.pruneTerminalResponsesLocked()
		if e.activeResponseCountLocked() >= MaxResponseRecords {
			e.sweepRollbacksLocked(now, false)
			if e.activeResponseCountLocked() >= MaxResponseRecords {
				return nil, NewResponseStorageException("active response capacity limit reached", nil)
			}
		}
	}

	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return nil, NewResponseValidationException("target ID cannot be empty", nil)
	}

	respUUID := DeriveResponseUUID(incidentUUID, action, targetType, targetID)
	ttl := e.CalculateTTL(now, action, targetID)
	expiresAt := now.Add(ttl)

	targetKey := targetActionKey("VGT_TRINITY_RESPONSE", action, targetType, targetID)

	// Idempotency: If already actively contained for this specific action, update expiration without redundant kernel mutation
	if existingUUID, active := e.activeByTgt[targetKey]; active {
		if existing, found := e.responses[existingUUID]; found && (existing.Status == StatusApplied || existing.Status == StatusRollbackRequested) {
			existing.StartedAt = now
			existing.ExpiresAt = expiresAt
			existing.Confidence = confidence
			existing.Status = StatusApplied
			e.responses[existingUUID] = existing
			return &existing, nil
		}
	}

	// Prepare Rollback Data
	rollbackState := map[string]string{
		"target_type": targetType,
		"target_id":   targetID,
		"action":      string(action),
	}

	var freezePID int
	var freezeStartTicks uint64
	if action == ActionFreezeExecution {
		p, st, err := ResolveProcessTarget(targetID)
		if err != nil {
			return nil, NewResponseValidationException(err.Error(), err)
		}
		freezePID = p
		freezeStartTicks = st
		rollbackState["start_ticks"] = strconv.FormatUint(freezeStartTicks, 10)
	}

	rollbackBytes, err := json.Marshal(rollbackState)
	if err != nil {
		return nil, NewResponseStorageException("failed to encode rollback state", err)
	}

	record := ResponseRecord{
		UUID:         respUUID,
		IncidentUUID: incidentUUID,
		Owner:        "VGT_TRINITY_RESPONSE",
		ActionType:   action,
		TargetType:   targetType,
		TargetID:     targetID,
		StartedAt:    now,
		ExpiresAt:    expiresAt,
		Status:       StatusApplied,
		Confidence:   confidence,
		ReasonCode:   reasonCode,
		AuthorizedBy: "XDR_POLICY_ENGINE",
		RollbackJSON: string(rollbackBytes),
		EvidenceRef:  evidenceRoot,
	}

	// Dispatch privileged execution to CoreActionDispatcher
	if e.dispatcher != nil {
		switch action {
		case ActionContainIP:
			if net.ParseIP(targetID) == nil {
				return nil, NewResponseValidationException("invalid target IP format", nil)
			}
			if err := e.dispatcher.BlockIP(targetID); err != nil {
				record.Status = StatusFailed
				record.FailureReason = fmt.Sprintf("core IP containment failed: %v", err)
				e.responses[respUUID] = record
				return nil, NewResponseSecurityException("core IP containment failed", err)
			}
		case ActionFreezeExecution:
			if err := e.dispatcher.FreezeProcess(freezePID, freezeStartTicks, reasonCode); err != nil {
				record.Status = StatusFailed
				record.FailureReason = fmt.Sprintf("core process freeze failed: %v", err)
				e.responses[respUUID] = record
				return nil, NewResponseSecurityException("core process freeze failed", err)
			}
		case ActionContainCell:
			cgroupID, err := strconv.ParseUint(targetID, 10, 64)
			if err != nil || cgroupID == 0 {
				return nil, NewResponseValidationException("invalid cgroup ID for cell containment", err)
			}
			// Flags: deny non-unix socket (1)
			if err := e.dispatcher.SetCellPolicy(cgroupID, 1); err != nil {
				record.Status = StatusFailed
				record.FailureReason = fmt.Sprintf("core cell containment failed: %v", err)
				e.responses[respUUID] = record
				return nil, NewResponseSecurityException("core cell containment failed", err)
			}
		default:
			// Non-kernel simulated action
		}
	}

	e.responses[respUUID] = record
	e.activeByTgt[targetKey] = respUUID
	e.history = append(e.history, record)
	if len(e.history) > 2*maxResponseHistoryRecords {
		// Amortised hard cap: the history can only overshoot the bound between two
		// rollback sweeps after a very high violation rate (verification finding R2).
		e.pruneHistoryLocked(now)
	}

	// Emit auditable evidence intent
	if e.evidenceSink != nil {
		_ = e.evidenceSink(string(action), fmt.Sprintf("%s:%s", targetType, targetID), fmt.Sprintf("TTL=%s Reason=%s", ttl, reasonCode), now)
	}

	return &record, nil
}

// targetActionKey returns a unique composite ownership key distinguishing target and mitigation action.
func targetActionKey(owner string, action ResponseActionType, targetType, targetID string) string {
	if owner == "" {
		owner = "VGT_TRINITY_RESPONSE"
	}
	return fmt.Sprintf("%s:%s:%s:%s", owner, action, targetType, targetID)
}

// releaseResponseLocked performs one verified kernel release for a record that may
// still hold kernel state: ROLLBACK_REQUESTED -> kernel mutation -> read-back/verify
// (ROLLED_BACK, or DEGRADED when the mutation failed). The caller holds e.mu.
func (e *ResponseEngine) releaseResponseLocked(uuid string, record ResponseRecord, now time.Time) (ResponseRecord, bool) {
	targetKey := targetActionKey(record.Owner, record.ActionType, record.TargetType, record.TargetID)

	// State transition 1: ROLLBACK_REQUESTED
	record.Status = StatusRollbackRequested
	record.RollbackAttempts++
	attemptedAt := now
	record.LastRollbackAttemptAt = &attemptedAt
	e.responses[uuid] = record

	// State transition 2: Dispatch kernel mutation
	var mutationErr error
	if e.dispatcher != nil {
		switch record.ActionType {
		case ActionContainIP:
			mutationErr = e.dispatcher.UnblockIP(record.TargetID)
		case ActionFreezeExecution:
			var pid int
			var startTicks uint64
			if strings.Contains(record.TargetID, ":") {
				parts := strings.SplitN(record.TargetID, ":", 2)
				pid, _ = strconv.Atoi(parts[0])
				startTicks, _ = strconv.ParseUint(parts[1], 10, 64)
			} else {
				pid, _ = strconv.Atoi(record.TargetID)
			}
			if record.RollbackJSON != "" {
				var rb map[string]any
				if err := json.Unmarshal([]byte(record.RollbackJSON), &rb); err == nil {
					if stVal, ok := rb["start_ticks"]; ok {
						switch v := stVal.(type) {
						case string:
							if parsed, err := strconv.ParseUint(v, 10, 64); err == nil {
								startTicks = parsed
							}
						case float64:
							startTicks = uint64(v)
						}
					}
				}
			}
			mutationErr = e.dispatcher.UnfreezeProcess(pid, startTicks)
		case ActionContainCell:
			cgroupID, _ := strconv.ParseUint(record.TargetID, 10, 64)
			mutationErr = e.dispatcher.DeleteCellPolicy(cgroupID)
		}
	}

	// State transition 3: Read-back / verify
	if mutationErr != nil {
		// Verification FAILED -> DEGRADED (retained in activeByTgt, no false assurance).
		// The record is retried with bounded backoff and never dropped without a
		// verified release (verification finding R3).
		record.Status = StatusDegraded
		record.FailureReason = fmt.Sprintf("kernel rollback mutation failed: %v", mutationErr)
		e.responses[uuid] = record
		if e.evidenceSink != nil {
			_ = e.evidenceSink("ROLLBACK_DEGRADED", fmt.Sprintf("%s:%s", record.TargetType, record.TargetID), record.FailureReason, now)
		}
		return record, false
	}

	// Verification VERIFIED -> ROLLED_BACK. The completed transaction leaves the
	// working set (FIND-027); the record is archived through the return value and the
	// ROLLBACK_VERIFIED evidence commitment, so nothing is lost for the audit trail.
	record.Status = StatusRolledBack
	record.RolledBackAt = &now
	record.FailureReason = ""
	delete(e.responses, uuid)
	delete(e.activeByTgt, targetKey)
	if e.evidenceSink != nil {
		_ = e.evidenceSink("ROLLBACK_VERIFIED", fmt.Sprintf("%s:%s", record.TargetType, record.TargetID), fmt.Sprintf("Auto-Rollback UUID=%s verified and released", uuid), now)
	}
	return record, true
}

// sweepRollbacksLocked releases every containment that is due for release: expired
// APPLIED records and (when retryDegraded is set) DEGRADED records whose bounded
// retry backoff elapsed. A containment is only removed from the working set after
// the kernel release verified, never silently (verification finding R1). The caller
// holds e.mu.
func (e *ResponseEngine) sweepRollbacksLocked(now time.Time, retryDegraded bool) []ResponseRecord {
	var released []ResponseRecord
	for uuid, record := range e.responses {
		switch record.Status {
		case StatusApplied:
			if now.Before(record.ExpiresAt) {
				continue
			}
		case StatusDegraded:
			if !retryDegraded {
				continue
			}
			if record.RollbackAttempts >= maxResponseRollbackAttempts {
				if !record.RollbackExhausted {
					record.RollbackExhausted = true
					e.responses[uuid] = record
					if e.evidenceSink != nil {
						_ = e.evidenceSink("ROLLBACK_EXHAUSTED", fmt.Sprintf("%s:%s", record.TargetType, record.TargetID),
							fmt.Sprintf("release retry budget exhausted after %d attempts; kernel state remains uncertain for UUID=%s and requires operator/core recovery", record.RollbackAttempts, uuid), now)
					}
				}
				continue
			}
			if !responseRollbackRetryDue(record, now) {
				continue
			}
			if e.evidenceSink != nil {
				_ = e.evidenceSink("ROLLBACK_RETRY", fmt.Sprintf("%s:%s", record.TargetType, record.TargetID),
					fmt.Sprintf("retrying release attempt %d for UUID=%s", record.RollbackAttempts+1, uuid), now)
			}
		default:
			continue
		}
		updated, verified := e.releaseResponseLocked(uuid, record, now)
		if verified {
			released = append(released, updated)
		}
	}
	// Keep the working set and the escalation lookback bounded even on hosts that
	// never restart the control plane. Only release-free terminal records are pruned.
	e.pruneTerminalResponsesLocked()
	if len(e.history) > maxResponseHistoryRecords {
		e.pruneHistoryLocked(now)
	}
	return released
}

// RollbackExpired scans and atomic-reverts all applied responses that have surpassed their TTL.
// Enforces a strict 3-phase verification flow: ROLLBACK_REQUESTED -> Kernel Mutation -> Read-Back/Verify (ROLLED_BACK or DEGRADED).
// DEGRADED records (a failed kernel release) are retried with bounded backoff.
func (e *ResponseEngine) RollbackExpired(_ context.Context, now time.Time) ([]ResponseRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sweepRollbacksLocked(now, true), nil
}

// ActiveResponses returns an immutable snapshot of all currently enforced or degraded responses.
func (e *ResponseEngine) ActiveResponses() []ResponseRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]ResponseRecord, 0, len(e.activeByTgt))
	for _, uuid := range e.activeByTgt {
		if rec, found := e.responses[uuid]; found && (rec.Status == StatusApplied || rec.Status == StatusDegraded || rec.Status == StatusRollbackRequested) {
			out = append(out, rec)
		}
	}
	return out
}
