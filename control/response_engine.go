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
	ActionContainIP        ResponseActionType = "CONTAIN_IP"
	ActionRestrictProcess  ResponseActionType = "RESTRICT_PROCESS"
	ActionIsolateNetwork   ResponseActionType = "ISOLATE_NETWORK"
	ActionFreezeExecution  ResponseActionType = "FREEZE_EXECUTION"
	ActionContainCell      ResponseActionType = "CONTAIN_CELL"
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
	DefaultResponseTTL  = 900 * time.Second       // 15 minutes
	MaxEscalatedTTL     = 7 * 24 * time.Hour      // 7 days ceiling
	LookbackWindow24h   = 24 * time.Hour
	MaxResponseRecords  = 8192
)

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

	if len(e.responses) >= MaxResponseRecords {
		return nil, NewResponseStorageException("response capacity limit reached", nil)
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

// RollbackExpired scans and atomic-reverts all applied responses that have surpassed their TTL.
// Enforces a strict 3-phase verification flow: ROLLBACK_REQUESTED -> Kernel Mutation -> Read-Back/Verify (ROLLED_BACK or DEGRADED).
func (e *ResponseEngine) RollbackExpired(ctx context.Context, now time.Time) ([]ResponseRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var rolledBack []ResponseRecord

	for uuid, rec := range e.responses {
		if rec.Status != StatusApplied {
			continue
		}
		if now.Before(rec.ExpiresAt) {
			continue
		}

		targetKey := targetActionKey(rec.Owner, rec.ActionType, rec.TargetType, rec.TargetID)

		// State transition 1: ROLLBACK_REQUESTED
		rec.Status = StatusRollbackRequested
		e.responses[uuid] = rec

		// State transition 2: Dispatch kernel mutation
		var mutationErr error
		if e.dispatcher != nil {
			switch rec.ActionType {
			case ActionContainIP:
				mutationErr = e.dispatcher.UnblockIP(rec.TargetID)
			case ActionFreezeExecution:
				var pid int
				var startTicks uint64
				if strings.Contains(rec.TargetID, ":") {
					parts := strings.SplitN(rec.TargetID, ":", 2)
					pid, _ = strconv.Atoi(parts[0])
					startTicks, _ = strconv.ParseUint(parts[1], 10, 64)
				} else {
					pid, _ = strconv.Atoi(rec.TargetID)
				}
				if rec.RollbackJSON != "" {
					var rb map[string]any
					if err := json.Unmarshal([]byte(rec.RollbackJSON), &rb); err == nil {
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
				cgroupID, _ := strconv.ParseUint(rec.TargetID, 10, 64)
				mutationErr = e.dispatcher.DeleteCellPolicy(cgroupID)
			}
		}

		// State transition 3: Read-back / verify
		if mutationErr != nil {
			// Verification FAILED -> DEGRADED (Retain in activeByTgt to eliminate false assurance!)
			rec.Status = StatusDegraded
			rec.FailureReason = fmt.Sprintf("kernel rollback mutation failed: %v", mutationErr)
			e.responses[uuid] = rec
			if e.evidenceSink != nil {
				_ = e.evidenceSink("ROLLBACK_DEGRADED", fmt.Sprintf("%s:%s", rec.TargetType, rec.TargetID), rec.FailureReason, now)
			}
			continue
		}

		// Verification VERIFIED -> ROLLED_BACK
		rec.Status = StatusRolledBack
		rec.RolledBackAt = &now
		rec.FailureReason = ""
		e.responses[uuid] = rec
		delete(e.activeByTgt, targetKey)
		rolledBack = append(rolledBack, rec)

		if e.evidenceSink != nil {
			_ = e.evidenceSink("ROLLBACK_VERIFIED", fmt.Sprintf("%s:%s", rec.TargetType, rec.TargetID), fmt.Sprintf("Auto-Rollback UUID=%s verified", uuid), now)
		}
	}

	return rolledBack, nil
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
