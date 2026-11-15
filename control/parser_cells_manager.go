// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: the ParserCellManager - admission, lifecycle state machine
// requested -> spawned -> isolated -> expiring -> burning -> burned|failed, TTL
// supervision with an evidence-first burn intent, incident dispatch for CellGuard,
// bounded export import and ledger reconciliation.
//
// Non-negotiable rules (§5, §6, §8):
//   - Enabled=false is inert: no helper request, no event, no cell.
//   - A cell is only "isolated" when the helper attested sandbox+netns and the
//     operator-required host layers (if any) are applied. No attestation, no claim.
//   - Evidence before destruction: the burn intent is committed before CELL_BURN.
//   - Exports are untrusted evidence: bounded, hashed, scanned when an Airlock is
//     wired, stored for the operator - never rendered and never executed.
//   - A missing helper is capability-missing (create refused), never a silent ok.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

const (
	parserCellStateRequested = "requested"
	parserCellStateSpawned   = "spawned"
	parserCellStateIsolated  = "isolated"
	parserCellStateExpiring  = "expiring"
	parserCellStateBurning   = "burning"
	parserCellStateBurned    = "burned"
	parserCellStateFailed    = "failed"
	parserCellStateDegraded  = "degraded"

	parserCellTTLGraceMax     = 10 * time.Second
	parserCellReconcilePeriod = 15 * time.Second
	parserCellHealthPeriod    = 5 * time.Second
	parserCellCapsPeriod      = 30 * time.Second
	parserCellHistoryLimit    = 16
	parserCellStagedLimit     = 32
	parserCellStagedTTL       = 30 * time.Minute
	parserCellInputSuffix     = ".bin"
	parserCellExportSuffix    = ".export.bin"
	parserCellEvidenceSource  = "parser-cells"
	parserCellKindBurnIntent  = "cells.parser.burn.intent"
	parserCellKindBurned      = "cells.parser.burned"
	parserCellKindExport      = "cells.parser.export.untrusted"
	parserCellKindHelperDown  = "cells.parser.helper_unavailable"
	parserCellKindHelperUp    = "cells.parser.helper_recovered"
	parserCellKindIncident    = "cells.parser.incident_burn"
	parserCellKindReconciled  = "cells.parser.reconciled"
	parserCellGoBurnReasonTTL = "ttl-expired"
	parserCellGoBurnReasonOp  = "operator-burn"
)

type parserCellStagedInput struct {
	Token   string
	Path    string
	SHA256  string
	Size    int64
	Created time.Time
}

// ParserCellManager owns the control-plane view of the privileged helper. All
// blocking helper/core I/O happens outside the manager mutex; Status() is a local
// snapshot and never performs I/O.
type ParserCellManager struct {
	cfg       ParserCellsConfig
	state     *State
	settings  *SettingsStore
	kernel    *parserCellKernel
	airlock   *AirlockInspector
	client    parserCellTransport
	clientErr error
	now       func() time.Time
	evidence  func(EvidenceRecord) error
	addEvent  func(Event)

	mu            sync.Mutex
	desired       ParserCellsFabricSettings
	cells         map[string]*ParserCellRuntime
	staged        map[string]parserCellStagedInput
	recent        []ParserCellResult
	cooldown      map[uint64]time.Time
	active        int
	pending       int
	burned        int
	failed        int
	refused       int
	caps          ParserCellCapabilities
	capsKnown     bool
	capsAt        time.Time
	helperHealth  ParserCellHealth
	helperKnown   bool
	helperAt      time.Time
	helperDown    bool
	helperErr     string
	lastErr       string
	degradedWhy   string
	availability  parserCellKernelAvailability
	lastReconcile time.Time
}

func NewParserCellManager(cfg ParserCellsConfig, state *State, settings *SettingsStore, kernel *parserCellKernel, airlock *AirlockInspector) *ParserCellManager {
	manager := &ParserCellManager{cfg: cfg, state: state, settings: settings, kernel: kernel, airlock: airlock,
		now:      func() time.Time { return time.Now().UTC() },
		evidence: func(EvidenceRecord) error { return nil },
		addEvent: func(Event) {},
		desired:  defaultParserCellsFabricSettings(),
		cells:    make(map[string]*ParserCellRuntime, parserCellsMaxConcurrentCap),
		staged:   make(map[string]parserCellStagedInput, parserCellStagedLimit),
		cooldown: make(map[uint64]time.Time, parserCellsMaxConcurrentCap)}
	if settings != nil {
		manager.desired = effectiveParserCellsSettings(settings.Get())
	}
	if state != nil {
		manager.evidence = state.RecordEvidence
		manager.addEvent = state.AddEvent
	}
	client, err := newParserCellClient(cfg)
	if err != nil {
		manager.clientErr = err
	} else {
		manager.client = client
	}
	if manager.desired.Enabled {
		for _, dir := range []string{cfg.InputDir, cfg.ImportsDir} {
			if dir == "" {
				continue
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				manager.clientErr = fmt.Errorf("%w: parser cell staging: %v", ErrParserCellsRuntimeUnavailable, err)
			}
		}
	}
	return manager
}

// Configure records a new persisted revision. It never touches the helper: the
// supervisor loop applies the change, so a slow helper can never block settings.
func (m *ParserCellManager) Configure(settings RuntimeSettings) {
	if m == nil {
		return
	}
	next := effectiveParserCellsSettings(settings)
	m.mu.Lock()
	disabled := m.desired.Enabled && !next.Enabled
	m.desired = next
	if !next.Enabled {
		m.degradedWhy = ""
	}
	m.mu.Unlock()
	if disabled {
		m.addEvent(Event{Severity: "info", Kind: "cells.parser.disabled", Source: parserCellEvidenceSource,
			Message: "Parser cells were disabled by the operator; no further helper requests are made. Live cells expire by the helper TTL timer"})
	}
}

// Run is the supervisor loop: health/epoch poll, ledger reconcile and the TTL
// deadline watcher. Disabled means inert - the loop returns without any request.
func (m *ParserCellManager) Run(ctx context.Context) {
	if m == nil {
		return
	}
	m.refresh(time.Time{})
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refresh(time.Time{})
		}
	}
}

// refresh runs the periodic work that is due; tests drive it with an injected
// clock so the state machine is deterministic.
func (m *ParserCellManager) refresh(now time.Time) {
	if now.IsZero() {
		now = m.now()
	}
	m.mu.Lock()
	enabled, lastReconcile, helperAt := m.desired.Enabled, m.lastReconcile, m.helperAt
	m.mu.Unlock()
	if !enabled {
		return
	}
	if lastReconcile.IsZero() || now.Sub(lastReconcile) >= parserCellReconcilePeriod {
		m.reconcile(now)
	}
	if helperAt.IsZero() || now.Sub(helperAt) >= parserCellHealthPeriod {
		m.health(now)
	}
	m.superviseTTL(now)
}

// Status is the bounded operator projection. It performs no helper or core I/O.
func (m *ParserCellManager) Status() ParserCellsStatus {
	if m == nil {
		return ParserCellsStatus{Helper: "disabled", LayerCellLSM: parserCellLayerUnavailable + ":disabled",
			LayerStyxEgress: parserCellLayerUnavailable + ":disabled", LayerTitanExec: parserCellLayerUnavailable + ":disabled"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.desired
	status := ParserCellsStatus{Enabled: s.Enabled, TTLSeconds: s.TTLSeconds, MaxConcurrent: s.MaxConcurrent,
		MaxInputBytes: s.MaxInputBytes, MaxExportBytes: s.MaxExportBytes, BurnOnIncident: s.BurnOnIncident,
		IncidentScore: s.IncidentScore, CooldownSeconds: s.CooldownSeconds, RequireHostLayers: s.RequireHostLayers,
		Active: m.active, Burned: m.burned, Failed: m.failed, Refused: m.refused,
		HelperState: m.helperHealth.State, HelperCells: m.helperHealth.ActiveCells,
		Helper: "probing", PolledAt: m.helperAt, LastError: m.lastErr, DegradedWhy: m.degradedWhy,
		LayerCellLSM: parserCellLayerUnavailable + ":disabled", LayerStyxEgress: parserCellLayerUnavailable + ":disabled",
		LayerTitanExec: parserCellLayerUnavailable + ":disabled"}
	if !s.Enabled {
		status.Helper = "disabled"
		return status
	}
	if m.client != nil {
		status.Helper = "connected"
	}
	if m.clientErr != nil || m.helperDown {
		status.Helper = "unavailable"
	}
	if m.helperDown {
		status.LastError = m.helperErr
	}
	if m.capsKnown {
		status.ABI, status.Sandbox, status.BPFLSM = m.caps.ABI, m.caps.Sandbox, m.caps.BPFLSM
		status.Wayland = m.caps.Wayland
		status.Profiles = append([]string(nil), m.caps.Profiles...)
		status.Available = !m.helperDown && m.caps.Sandbox && m.clientErr == nil
	}
	status.LayerCellLSM = m.availability.CellLSM
	status.LayerStyxEgress = m.availability.StyxEgress
	status.LayerTitanExec = m.availability.TitanExec
	for _, cell := range m.cells {
		status.Cells = append(status.Cells, cloneParserCellRuntime(cell))
	}
	sort.Slice(status.Cells, func(i, j int) bool { return status.Cells[i].CreatedAt.Before(status.Cells[j].CreatedAt) })
	if len(status.Cells) > parserCellKernelLayerLimit {
		status.Cells = status.Cells[:parserCellKernelLayerLimit]
	}
	status.Recent = append([]ParserCellResult(nil), m.recent...)
	return status
}

// StageInput writes one bounded document into the staging directory and returns
// the token/hash the helper verifies. O_NOFOLLOW + O_EXCL: the path is a name the
// manager itself minted, never a client path (§1.2). Packaging provisions the
// input staging root as root:gedefense 0730 (group-writable, so the unprivileged
// control user may create the named file); the file mode is forced to exactly
// 0640 because the helper validates it independently of our umask. The imported
// export copy, by contrast, lives in the control-owned parser-imports root
// (parser_cells.imports_dir).
func (m *ParserCellManager) StageInput(data []byte) (ParserCellInput, error) {
	now := m.now()
	m.mu.Lock()
	s := m.desired
	clientErr := m.clientErr
	m.mu.Unlock()
	if !s.Enabled {
		return ParserCellInput{}, &ParserCellError{Code: "disabled"}
	}
	if clientErr != nil {
		return ParserCellInput{}, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, clientErr)
	}
	if len(data) == 0 || len(data) > s.MaxInputBytes {
		return ParserCellInput{}, &ParserCellError{Code: "input-invalid"}
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return ParserCellInput{}, fmt.Errorf("parser cell input token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(m.cfg.InputDir, 0o750); err != nil {
		return ParserCellInput{}, fmt.Errorf("%w: input staging: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	path := filepath.Join(m.cfg.InputDir, token+parserCellInputSuffix)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return ParserCellInput{}, fmt.Errorf("%w: input staging: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return ParserCellInput{}, fmt.Errorf("%w: input staging write failed", ErrParserCellsRuntimeUnavailable)
	}
	// The control unit runs with a strict umask, so the requested 0640 is masked to
	// 0600 at creation. The helper validates the staging file as exactly 0640 (its
	// config::validate_input contract), so the mode is enforced explicitly here.
	if err := os.Chmod(path, 0o640); err != nil {
		_ = os.Remove(path)
		return ParserCellInput{}, fmt.Errorf("%w: input staging mode: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	m.mu.Lock()
	m.staged[token] = parserCellStagedInput{Token: token, Path: path, SHA256: digest, Size: int64(len(data)), Created: now}
	parserCellPruneStaged(m.staged, now)
	m.mu.Unlock()
	return ParserCellInput{Token: token, SHA256: digest, Size: int64(len(data))}, nil
}

// Create is the admission gate plus helper spawn. It refuses instead of degrading:
// no enabled namespace, no capability, no profile, no staged input, no evidence
// gate or no concurrency budget means no cell.
func (m *ParserCellManager) Create(profile, inputToken, inputSHA256 string, inputSize int64, ttlSeconds int) (ParserCellRuntime, error) {
	now := m.now()
	m.mu.Lock()
	s := m.desired
	m.mu.Unlock()
	if !s.Enabled {
		return ParserCellRuntime{}, &ParserCellError{Code: "disabled"}
	}
	if m.state != nil {
		if _, err := m.state.EvidenceGateCondition(); err != nil {
			m.setDegraded("evidence gate closed: " + parserCellBoundedError(err))
			return ParserCellRuntime{}, &ParserCellError{Code: "evidence-gate"}
		}
	}
	if !parserCellProfileValid(profile) {
		return ParserCellRuntime{}, &ParserCellError{Code: "profile-invalid"}
	}
	if !parserCellProfileAllowed(s, profile) {
		return ParserCellRuntime{}, &ParserCellError{Code: "profile-unknown"}
	}
	caps, err := m.refreshCapabilities(now)
	if err != nil {
		return ParserCellRuntime{}, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	if !caps.Sandbox {
		m.refuse("create", profile, errors.New("helper reports sandbox=false"))
		return ParserCellRuntime{}, &ParserCellError{Code: "capability-missing"}
	}
	if len(caps.Profiles) == 0 || !parserCellContains(caps.Profiles, profile) {
		m.refuse("create", profile, errors.New("helper does not advertise the profile"))
		return ParserCellRuntime{}, &ParserCellError{Code: "profile-unknown"}
	}
	// Phase 1 cells run as the unprivileged parser uid (65534) and cannot own a
	// Wayland session socket. A profile the packaging declared as Wayland-dependent
	// is refused here, fail-closed and before the helper spawn, unless the helper
	// explicitly negotiated display capability (additive future ABI).
	if !caps.Wayland && parserCellContains(m.cfg.WaylandProfiles, profile) {
		m.refuse("create", profile, errors.New("wayland profile is unsupported in phase 1 (unprivileged cell uid)"))
		return ParserCellRuntime{}, &ParserCellError{Code: "capability-missing"}
	}
	maxConcurrent := s.MaxConcurrent
	if caps.MaxConcurrent > 0 && caps.MaxConcurrent < maxConcurrent {
		maxConcurrent = caps.MaxConcurrent
	}
	ttl := ttlSeconds
	if ttl <= 0 {
		ttl = s.TTLSeconds
	}
	if ttl > s.TTLSeconds {
		ttl = s.TTLSeconds
	}
	if caps.TTLMax > 0 && ttl > caps.TTLMax {
		ttl = caps.TTLMax
	}
	if ttl < parserCellsMinTTLSeconds {
		ttl = parserCellsMinTTLSeconds
	}
	staged, err := m.validateStagedInput(inputToken, inputSHA256, inputSize, s.MaxInputBytes)
	if err != nil {
		m.refuse("create", profile, err)
		return ParserCellRuntime{}, err
	}
	m.mu.Lock()
	if m.active+m.pending >= maxConcurrent {
		m.mu.Unlock()
		m.refuse("create", profile, errors.New("cell limit reached"))
		return ParserCellRuntime{}, &ParserCellError{Code: "cell-limit"}
	}
	m.pending++
	client := m.client
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.pending--
		m.mu.Unlock()
	}()
	result, err := client.Create(ParserCellCreateRequest{Profile: profile, InputToken: staged.Token, InputSHA256: staged.SHA256,
		InputSize: staged.Size, TTLSeconds: ttl})
	if err != nil {
		m.refuse("create", profile, err)
		if errors.Is(err, ErrParserCellsRuntimeUnavailable) {
			m.helperFailure(err)
		}
		return ParserCellRuntime{}, err
	}
	if !result.Sandbox || !result.NetNS {
		_, _ = client.Burn(result.UUID, result.Generation, result.CgroupID, "", "attestation-failed")
		m.refuse("attestation", profile, errors.New("helper did not attest the sandbox"))
		return ParserCellRuntime{}, &ParserCellError{Code: "sandbox-unavailable"}
	}
	runtime := ParserCellRuntime{UUID: result.UUID, CellClass: parserCellsClassEphemeral, Profile: profile,
		Generation: result.Generation, CgroupID: result.CgroupID, CgroupPath: result.CgroupPath, PID: result.PID,
		State: parserCellStateSpawned, Sandbox: result.Sandbox, NetNS: result.NetNS, TTLSeconds: ttl,
		CreatedAt: now, ExpiresAt: time.Unix(result.ExpiresAt, 0).UTC(),
		InputToken: staged.Token, InputSHA256: staged.SHA256, InputSize: staged.Size,
		Layers: ParserCellLayerStatus{Sandbox: "attested", CellLSM: parserCellLayerUnavailable,
			StyxEgress: parserCellLayerUnavailable, TitanExec: parserCellLayerUnavailable}}
	if m.kernel != nil {
		layers, layerErr := m.kernel.Apply(result.CgroupID, m.runtimeSettings())
		runtime.Layers = layers
		if layerErr != nil {
			runtime.LastError = parserCellBoundedError(layerErr)
			m.setDegraded("host layer attachment: " + runtime.LastError)
		}
	}
	runtime.Layers.Required = s.RequireHostLayers
	runtime.Layers.Satisfied = parserCellHostLayersSatisfied(s.RequireHostLayers, runtime.Layers)
	if !runtime.Layers.Satisfied {
		_, _ = client.Burn(result.UUID, result.Generation, result.CgroupID, "", "host-layers-missing")
		if m.kernel != nil {
			_ = m.kernel.Remove(result.CgroupID)
		}
		m.refuse("host-layers", profile, errors.New("required host layers are not applied"))
		return ParserCellRuntime{}, &ParserCellError{Code: "host-layers-required"}
	}
	runtime.State = parserCellStateIsolated
	m.mu.Lock()
	m.cells[runtime.UUID] = &runtime
	m.active++
	m.recordLocked(ParserCellResult{At: now, UUID: runtime.UUID, Cgroup: runtime.CgroupID, Action: "open", State: runtime.State, Reason: profile})
	m.mu.Unlock()
	m.addEvent(Event{Severity: "high", Kind: "cells.parser.isolated", Source: parserCellEvidenceSource,
		Message: fmt.Sprintf("Ephemeral parser cell %s opened for profile %s (layers: lsm=%s styx=%s titan=%s)",
			runtime.UUID, profile, runtime.Layers.CellLSM, runtime.Layers.StyxEgress, runtime.Layers.TitanExec), Target: runtime.UUID})
	return cloneParserCellRuntime(&runtime), nil
}
