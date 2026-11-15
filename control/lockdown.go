// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3: the Emergency Lockdown engine.
//
// The engine is the only place that owns the lockdown latch. It persists an
// authenticated, atomically written state document on every transition and it
// never claims a phase was applied unless the dedicated subsystem acknowledged
// it: the kernel via VGT3, the cell runtime via the existing CellGuard /
// TransactionEngine, the parser cells via ParserCellManager.BurnForIncident
// (docs/POINT5-LOCKDOWN.md §2, §6, §7, §9).
//
// Two properties are load-bearing:
//
//  1. Fail-closed latch. A state document that cannot be read, does not
//     authenticate or is structurally invalid latches the engine instead of
//     starting disarmed. A crash in "triggering" or "clearing" is recovered as
//     "active": the phases had been committed, only the bookkeeping was cut.
//  2. Latch over restart. Reaching "active" is persisted before the trigger is
//     reported as accepted, and only an authenticated operator clear with the
//     matching expected_epoch may leave it (§7, §9).

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// lockdownEngineStatePath is the documented, root-owned state document (§7).
	lockdownEngineStatePath = "/var/lib/vgt/gedefense/lockdown-engine.state"
	// lockdownEngineStateSchema versions the authenticated document.
	lockdownEngineStateSchema = "vgt-gedefense-lockdown-engine-v1"
	// lockdownEnginePurpose binds the AEAD envelope to this store.
	lockdownEnginePurpose = "lockdown-engine"
	// lockdownEngineStateMaxBytes bounds the document before it is decoded.
	lockdownEngineStateMaxBytes = int64(64 << 10)
)

// Engine errors. The API maps them onto HTTP statuses; nothing else may widen
// the meaning of one of these.
var (
	errLockdownDisabled        = errors.New("lockdown is disabled by the runtime settings")
	errLockdownLatched         = errors.New("lockdown is latched and requires an authenticated clear")
	errLockdownNotLatched      = errors.New("no lockdown is in force")
	errLockdownBusy            = errors.New("lockdown is transitioning; retry when the phase set is settled")
	errLockdownEpochMismatch   = errors.New("lockdown epoch mismatch")
	errLockdownCoreUnavailable = errors.New("kernel core is unavailable")
	errLockdownCapabilityMiss  = errors.New("kernel core does not implement the lockdown command family")
	errLockdownCooldown        = errors.New("automatic lockdown trigger is cooling down")
)

// lockdownEngineState is the persisted latch document. Every field is
// operator-relevant or needed for the compare-set clear; nothing secret and no
// path is stored.
type lockdownEngineState struct {
	Schema         string                `json:"schema"`
	Revision       uint64                `json:"revision"`
	State          string                `json:"state"`
	Mode           string                `json:"mode"`
	Epoch          string                `json:"epoch,omitempty"`
	Latched        bool                  `json:"latched"`
	CoreCapability string                `json:"core_capability,omitempty"`
	Trigger        *lockdownTriggerState `json:"trigger,omitempty"`
	Phases         []LockdownPhaseView   `json:"phases,omitempty"`
	// CellTransactions are the TransactionEngine ids of the cell freezes this
	// trigger applied. They are persisted so an authenticated clear can reverse
	// them across a restart; the engine reports a reversal failure instead of
	// silently leaving a cell frozen.
	CellTransactions []string           `json:"cell_transactions,omitempty"`
	LastClear        *LockdownClearView `json:"last_clear,omitempty"`
	LastError        string             `json:"last_error,omitempty"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

// lockdownTriggerState persists the closed tokens of the accepted trigger. The
// process identity is deliberately not persisted: a restart must not re-freeze
// a PID that may since have been recycled (§6.4).
type lockdownTriggerState struct {
	Source      string    `json:"source"`
	Reason      string    `json:"reason"`
	Mode        string    `json:"mode,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Incident    string    `json:"incident,omitempty"`
	At          time.Time `json:"at"`
	Epoch       string    `json:"epoch,omitempty"`
	Operator    bool      `json:"operator"`
	// The frozen process identity is persisted only so the authenticated clear can
	// resume it with the core's starttime check. A recycled PID is refused by the
	// core, so persisting it can never resume the wrong process.
	ProcessPID        int    `json:"process_pid,omitempty"`
	ProcessStartTicks uint64 `json:"process_start_ticks,omitempty"`
}

// lockdownTriggerCandidate is one evaluated trigger source. It is constructed
// by lockdown_triggers.go and never carries free text onto the wire.
type lockdownTriggerCandidate struct {
	Source      string
	Reason      string
	Fingerprint string
	Incident    string
	ReasonText  string
	Operator    bool
	PID         int
	StartTicks  uint64
	UID         uint32
}

// LockdownEngineConfig is the construction set. Path and Now are overridable so
// the engine is testable without the deployment directories; Storage may be nil
// in a development profile (the document is then plaintext and the engine says
// so in its status instead of pretending it is authenticated).
type LockdownEngineConfig struct {
	Path      string
	Storage   *StorageCipher
	Settings  *SettingsStore
	State     *State
	Core      *CoreClient
	CellGuard *CellGuard
	Now       func() time.Time
}

// LockdownEngine owns the state machine, the latch document and the phase
// orchestration. Transitions are serialised by opsMu; the status projection only
// takes stateMu for reading, so a slow phase never blocks the read-only API.
type LockdownEngine struct {
	path      string
	storage   *StorageCipher
	settings  *SettingsStore
	state     *State
	core      *CoreClient
	cellGuard *CellGuard
	now       func() time.Time

	opsMu   sync.Mutex
	stateMu sync.RWMutex
	doc     lockdownEngineState
	corrupt bool
	// triggerBusy collapses concurrent automatic trigger evaluations into one.
	// The incident hook must never run the phase orchestration (core I/O plus cell
	// freezes) on the XDR worker goroutine, so the hook hands the candidate to a
	// single bounded background evaluation instead.
	triggerBusy sync.Mutex

	// evidenceErr/persistErr name a degraded audit or persistence path without
	// turning it into an enforcement claim.
	evidenceErr string
	persistErr  string

	// Core projection. It is only ever replaced by a phase result or a bounded
	// poll; a status request never performs core I/O.
	coreCapability  string
	coreState       string
	coreEpoch       string
	coreFlags       uint8
	coreApplied     []string
	coreUnsupported []string
	coreHealth      *CoreLockdownHealth
	coreHealthAt    time.Time
	coreLastErr     string
	droppedEvents   uint64

	// Trigger engineering (dedupe/cooldown/RequireSources).
	lastAutomaticAt     time.Time
	lastFingerprint     string
	lastFingerprintAt   time.Time
	lastGuardEvidence   time.Time
	falsePositiveGuards uint64
	pendingSources      map[string]time.Time
	pendingFingerprint  string
	pendingID           string

	// Providers wired by main.go / tests (see lockdown_triggers.go).
	bootTrust        func() (string, string)
	bootTrustLast    string
	bootTrustSeen    bool
	bootTrustAt      time.Time
	duressPolled     bool
	duressReported   bool
	duressHash       string
	corePollAt       time.Time
	autoArmNext      time.Time
	autoArmAttempts  int
	lastCorePollSeen time.Time
}

// NewLockdownEngine loads the persisted latch and returns an engine that is
// already fail-closed when the document cannot be trusted.
func NewLockdownEngine(cfg LockdownEngineConfig) (*LockdownEngine, error) {
	if cfg.Settings == nil {
		return nil, errors.New("lockdown engine requires the runtime settings store")
	}
	path := cfg.Path
	if path == "" {
		path = lockdownEngineStatePath
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("lockdown engine state path must be absolute")
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	engine := &LockdownEngine{
		path: path, storage: cfg.Storage, settings: cfg.Settings, state: cfg.State,
		core: cfg.Core, cellGuard: cfg.CellGuard, now: now,
		coreCapability: "unknown", pendingSources: make(map[string]time.Time),
	}
	engine.doc = lockdownEngineState{
		Schema: lockdownEngineStateSchema, Revision: 1, State: lockdownStateDisarmed,
		Mode: lockdownModeUnlocked, UpdatedAt: now(),
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		// The directory is part of the deployment; a missing directory is a
		// fail-closed condition for persistence, not a reason to start enforced.
		engine.failClosed("state directory unavailable: " + err.Error())
		return engine, nil
	}
	engine.loadState()
	return engine, nil
}

// loadState reads and authenticates the latch document. A missing document is
// the documented first start (disarmed). Anything else that cannot be trusted
// latches the engine (§9).
func (e *LockdownEngine) loadState() {
	raw, err := readBoundedPrivateFile(e.path, lockdownEngineStateMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		e.failClosed("state document is unreadable: " + err.Error())
		return
	}
	if e.storage != nil {
		plaintext, _, decryptErr := e.storage.Decrypt(e.path, lockdownEnginePurpose, raw, nil)
		if decryptErr != nil {
			e.failClosed("state document failed authentication: " + decryptErr.Error())
			return
		}
		raw = plaintext
	}
	var doc lockdownEngineState
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		e.failClosed("state document is not valid JSON in the expected schema")
		return
	}
	if err := validateLockdownEngineState(&doc); err != nil {
		e.failClosed("state document is structurally invalid: " + err.Error())
		return
	}
	// A crash in "triggering" or "clearing" left the latch committed but the
	// bookkeeping unfinished: recover as active instead of releasing it.
	if doc.State == lockdownStateTriggering || doc.State == lockdownStateClearing {
		doc.State = lockdownStateActive
		doc.Latched = true
	}
	if doc.Latched && doc.State != lockdownStateActive {
		doc.State = lockdownStateActive
	}
	if doc.Mode != lockdownModeLocked && doc.Mode != lockdownModeUnlocked {
		doc.Mode = lockdownModeLocked
	}
	e.doc = doc
	if doc.Latched {
		e.addEvent("critical", "lockdown.recovered",
			fmt.Sprintf("Emergency lockdown latch recovered in state %s (epoch %s); only an authenticated clear with the matching epoch releases it", doc.State, doc.Epoch))
	}
}

func validateLockdownEngineState(doc *lockdownEngineState) error {
	if doc.Schema != lockdownEngineStateSchema || doc.Revision == 0 || doc.UpdatedAt.IsZero() {
		return errors.New("metadata is invalid")
	}
	switch doc.State {
	case lockdownStateDisarmed, lockdownStateArmed, lockdownStateTriggering, lockdownStateActive, lockdownStateClearing:
	default:
		return errors.New("state is not in the closed vocabulary")
	}
	if doc.Epoch != "" && !validLockdownEpoch(doc.Epoch) {
		return errors.New("epoch is not 8 hex characters")
	}
	if doc.Latched && doc.State == lockdownStateDisarmed {
		return errors.New("latched disarmed state is contradictory")
	}
	if len(doc.Phases) > len(lockdownPhaseOrder)+1 {
		return errors.New("phase list exceeds its bound")
	}
	if len(doc.CellTransactions) > lockdownMaxTargetsCap {
		return errors.New("reversible cell transaction list exceeds its bound")
	}
	for _, id := range doc.CellTransactions {
		if id == "" || len(id) > 96 || !protocolFieldValid(id) {
			return errors.New("reversible cell transaction id is invalid")
		}
	}
	return nil
}

// failClosed installs the latched recovery document, publishes a critical event
// and tries to persist the recovery so a restart stays latched.
func (e *LockdownEngine) failClosed(reason string) {
	epoch := e.newEpoch()
	e.doc = lockdownEngineState{
		Schema: lockdownEngineStateSchema, Revision: 1, State: lockdownStateActive,
		Mode: lockdownModeLocked, Epoch: epoch, Latched: true, UpdatedAt: e.now(),
		LastError: "state recovery: " + lockdownReasonText(reason),
	}
	e.corrupt = true
	e.stateMu.Lock()
	e.persistErr = ""
	e.stateMu.Unlock()
	e.addEvent("critical", "lockdown.state.corrupt",
		"Lockdown engine state could not be trusted; the engine is latched and requires an authenticated clear with the recovered epoch: "+lockdownReasonText(reason))
	_ = e.recordEvidence("critical", "lockdown.state.corrupt",
		"Lockdown engine state could not be trusted; fail-closed latch applied", "epoch:"+epoch)
	_ = e.persistLocked()
}

// newEpoch mints the 8-hex epoch used for the compare-set clear. The core is
// authoritative once it answers; this value covers the degraded window and the
// recovered-corrupt case where no core epoch is known.
func (e *LockdownEngine) newEpoch() string {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err == nil {
		if value := hex.EncodeToString(raw[:]); value != "00000000" {
			return value
		}
	}
	// A crypto/rand failure must not leave the latch without an epoch: derive a
	// bounded, non-secret value from the clock and a fresh random id instead.
	digest := sha256.Sum256([]byte(fmt.Sprintf("lockdown-epoch:%d:%s", e.now().UnixNano(), randomID())))
	return hex.EncodeToString(digest[:4])
}

// persistLocked writes the latch document atomically. Callers hold stateMu.
func (e *LockdownEngine) persistLocked() error {
	e.doc.Revision++
	e.doc.UpdatedAt = e.now()
	plaintext, err := json.Marshal(e.doc)
	if err != nil {
		e.persistErr = "state document could not be encoded"
		return err
	}
	data := plaintext
	if e.storage != nil {
		data, err = e.storage.Encrypt(e.path, lockdownEnginePurpose, e.doc.Revision, plaintext)
		if err != nil {
			e.persistErr = "state document could not be encrypted"
			return err
		}
	}
	if err := atomicWriteFile(e.path, data, 0o600); err != nil {
		e.persistErr = "state document could not be written atomically"
		return err
	}
	e.persistErr = ""
	return nil
}

func (e *LockdownEngine) effectiveSettings() LockdownFabricSettings {
	return effectiveLockdownSettings(e.settings.Get())
}
