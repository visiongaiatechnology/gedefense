// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: host-kernel layer attachment for parser cells (§5).
//
// L1 (namespaces/tmpfs/seccomp/cgroup) is owned by the privileged helper and is
// reported by its CELL_CREATE attestation - this file never claims it. L2/L3/L4
// are the existing privileged-core policies the control plane can only request:
//
//	L2 Cell-LSM   CELL_POLICY_SET(cgroup, DENY_NON_UNIX_SOCKET), only with bpf-LSM
//	L3 StyX egress STYX_MODE_SET(cgroup, enforce), only when the operator enabled StyX
//	L4 Titan exec  TITAN_EXEC_SCOPE_SET(cgroup, strict), only with bpf-LSM
//
// Every layer is reported as applied only after the core acknowledged the command;
// a missing capability is `unavailable`, never silently skipped into an "isolated"
// claim (§5 admission gate).
//
// StyX coordination (documented limitation): the StyX full syncer is not part of
// P2-T3's write scope and deletes scopes it does not know at a full re-sync. The
// manager therefore keeps its own dynamic-scope register and re-asserts it on every
// reconcile, so a full StyX sync can open a bounded convergence window but can
// never permanently release a live parser cell. The same register drives removal at
// burn time.

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	parserCellLayerApplied     = "applied"
	parserCellLayerUnavailable = "unavailable"
	parserCellLayerFailed      = "failed"
	parserCellLayerPending     = "pending"
	parserCellLayerAvailable   = "available"
	parserCellKernelLayerLimit = 64
)

// parserCellKernelCore is the subset of the privileged core client the layers
// need. It is an interface so the P2-T3 tests can prove the layer contract
// without a privileged core.
type parserCellKernelCore interface {
	CellPolicyEpoch() (string, error)
	CellPolicySet(cgroupID uint64, flags uint8) error
	CellPolicyDelete(cgroupID uint64) error
	StyxVersion() (string, error)
	StyxModeSet(cgroupID uint64, mode, flags uint8) error
	StyxModeDel(cgroupID uint64) error
	TitanExecVersion() (string, error)
	TitanExecStatus() (TitanExecCoreStatus, error)
	TitanExecScopeSet(cgroupID uint64, mode, flags uint8) error
	TitanExecScopeDel(cgroupID uint64) error
}

// parserCellKernelAvailability is the operator-facing capability view of the host
// layers, derived from the host fact (/sys/kernel/security/lsm), the operator
// settings and the core's ABI probe answers.
type parserCellKernelAvailability struct {
	BPFLSM     bool   `json:"bpf_lsm"`
	CellLSM    string `json:"cell_lsm"`
	StyxEgress string `json:"styx_egress"`
	TitanExec  string `json:"titan_exec"`
}

type parserCellKernelScope struct {
	CellLSM bool
	Styx    bool
	Titan   bool
}

type parserCellKernel struct {
	core     parserCellKernelCore
	facts    func() PlatformCapabilities
	settings func() RuntimeSettings
	mu       sync.Mutex
	scopes   map[uint64]parserCellKernelScope
}

// newParserCellKernel wires the real core client, hiding a nil client behind a
// nil interface instead of a typed nil that would panic on first use.
func newParserCellKernel(core *CoreClient, settings *SettingsStore) *parserCellKernel {
	var kernelCore parserCellKernelCore
	if core != nil {
		kernelCore = core
	}
	runtime := func() RuntimeSettings { return defaultRuntimeSettings(Config{}) }
	if settings != nil {
		runtime = settings.Get
	}
	return &parserCellKernel{
		core: kernelCore, facts: func() PlatformCapabilities { return DetectPlatformCapabilities("") },
		settings: runtime, scopes: make(map[uint64]parserCellKernelScope, parserCellKernelLayerLimit),
	}
}

func (k *parserCellKernel) runtimeSettings() RuntimeSettings {
	if k == nil || k.settings == nil {
		return defaultRuntimeSettings(Config{})
	}
	return k.settings()
}

func (k *parserCellKernel) hostFacts() PlatformCapabilities {
	if k == nil || k.facts == nil {
		return PlatformCapabilities{DetectedAt: time.Now().UTC()}
	}
	return k.facts()
}

// probe derives the three layer capabilities. Only a completed core probe counts
// as available: an old core, an inactive LSM or a disabled StyX namespace is a
// capability fact, never an enforcement claim.
func (k *parserCellKernel) probe(settings RuntimeSettings) (parserCellKernelAvailability, string) {
	availability := parserCellKernelAvailability{BPFLSM: k.hostFacts().HasBPFLSM}
	var reasons []string
	if availability.BPFLSM {
		availability.CellLSM = parserCellLayerAvailable
	} else {
		availability.CellLSM = parserCellLayerUnavailable + ":bpf-lsm-inactive"
	}
	if k == nil || k.core == nil {
		availability.CellLSM, availability.StyxEgress, availability.TitanExec = parserCellLayerUnavailable+":core-unavailable", parserCellLayerUnavailable+":core-unavailable", parserCellLayerUnavailable+":core-unavailable"
		return availability, "no privileged core client is attached"
	}
	if availability.BPFLSM {
		if _, err := k.core.CellPolicyEpoch(); err != nil {
			availability.CellLSM = parserCellLayerUnavailable + ":cell-lsm-capability-missing"
			reasons = append(reasons, "cell-lsm:"+parserCellBoundedError(err))
		}
	}
	if !effectiveStyxFabricSettings(settings).Enabled {
		availability.StyxEgress = parserCellLayerUnavailable + ":styx-disabled"
	} else if _, err := k.core.StyxVersion(); err != nil {
		availability.StyxEgress = parserCellLayerUnavailable + ":styx-capability-missing"
		reasons = append(reasons, "styx:"+parserCellBoundedError(err))
	} else {
		availability.StyxEgress = parserCellLayerAvailable
	}
	if !availability.BPFLSM {
		availability.TitanExec = parserCellLayerUnavailable + ":bpf-lsm-inactive"
	} else if _, err := k.core.TitanExecVersion(); err != nil {
		availability.TitanExec = parserCellLayerUnavailable + ":titan-exec-capability-missing"
		reasons = append(reasons, "titan-exec:"+parserCellBoundedError(err))
	} else if status, err := k.core.TitanExecStatus(); err != nil {
		availability.TitanExec = parserCellLayerUnavailable + ":titan-exec-status-unavailable"
		reasons = append(reasons, "titan-exec:"+parserCellBoundedError(err))
	} else if status.Path != titanExecPathBPFLSM || status.LSM != titanExecLSMActive {
		availability.TitanExec = parserCellLayerUnavailable + ":titan-exec-hook-inactive"
	} else {
		availability.TitanExec = parserCellLayerAvailable
	}
	return availability, joinParserCellReasons(reasons)
}

// Availability returns the bounded layer capability view used by the status API.
func (k *parserCellKernel) Availability(settings RuntimeSettings) parserCellKernelAvailability {
	if k == nil {
		return parserCellKernelAvailability{CellLSM: parserCellLayerUnavailable + ":core-unavailable",
			StyxEgress: parserCellLayerUnavailable + ":core-unavailable", TitanExec: parserCellLayerUnavailable + ":core-unavailable"}
	}
	availability, _ := k.probe(settings)
	return availability
}

// Apply requests every available host layer for one freshly spawned cell and
// returns the per-layer truth. A failed layer leaves the cell degraded; the caller
// decides whether the configured requirement makes that a refusal.
func (k *parserCellKernel) Apply(cgroupID uint64, settings RuntimeSettings) (ParserCellLayerStatus, error) {
	status := ParserCellLayerStatus{Sandbox: parserCellLayerPending, CellLSM: parserCellLayerUnavailable,
		StyxEgress: parserCellLayerUnavailable, TitanExec: parserCellLayerUnavailable}
	if k == nil || cgroupID == 0 {
		return status, errors.New("parser cell kernel layer attachment unavailable")
	}
	availability, _ := k.probe(settings)
	// The register records what was attempted, so Remove deletes every scope this
	// control plane may have installed even when the acknowledgement failed.
	scope := parserCellKernelScope{
		CellLSM: availability.CellLSM == parserCellLayerAvailable,
		Styx:    availability.StyxEgress == parserCellLayerAvailable,
		Titan:   availability.TitanExec == parserCellLayerAvailable,
	}
	var failures []error
	if scope.CellLSM {
		if err := k.core.CellPolicySet(cgroupID, cellLSMDenyNonUnixSocket); err != nil {
			status.CellLSM = parserCellLayerFailed
			failures = append(failures, fmt.Errorf("cell lsm: %w", err))
		} else {
			status.CellLSM = parserCellLayerApplied
		}
	}
	if scope.Styx {
		if err := k.core.StyxModeSet(cgroupID, 2, 0); err != nil {
			status.StyxEgress = parserCellLayerFailed
			failures = append(failures, fmt.Errorf("styX egress: %w", err))
		} else {
			status.StyxEgress = parserCellLayerApplied
		}
	}
	if scope.Titan {
		if err := k.core.TitanExecScopeSet(cgroupID, 3, 0); err != nil {
			status.TitanExec = parserCellLayerFailed
			failures = append(failures, fmt.Errorf("titan exec: %w", err))
		} else {
			status.TitanExec = parserCellLayerApplied
		}
	}
	k.mu.Lock()
	if len(k.scopes) < parserCellKernelLayerLimit || k.scopes[cgroupID].CellLSM || k.scopes[cgroupID].Styx || k.scopes[cgroupID].Titan {
		k.scopes[cgroupID] = scope
	}
	k.mu.Unlock()
	return status, errors.Join(failures...)
}

// Remove deletes every dynamic scope of one cell (burn/rollback). Deletion is
// idempotent in the core, so a partial earlier attachment can simply be removed.
func (k *parserCellKernel) Remove(cgroupID uint64) error {
	if k == nil || cgroupID == 0 {
		return nil
	}
	k.mu.Lock()
	scope, known := k.scopes[cgroupID]
	delete(k.scopes, cgroupID)
	k.mu.Unlock()
	if !known {
		// An adopted cell (control-plane restart) has no local register entry; every
		// layer deletion is idempotent, so attempting all three is the safe repair.
		scope = parserCellKernelScope{CellLSM: true, Styx: true, Titan: true}
	}
	var failures []error
	if scope.CellLSM {
		if err := k.core.CellPolicyDelete(cgroupID); err != nil {
			failures = append(failures, fmt.Errorf("cell lsm removal: %w", err))
		}
	}
	if scope.Styx {
		if err := k.core.StyxModeDel(cgroupID); err != nil && !errors.Is(err, ErrStyxUnavailable) {
			failures = append(failures, fmt.Errorf("styX removal: %w", err))
		}
	}
	if scope.Titan {
		if err := k.core.TitanExecScopeDel(cgroupID); err != nil && !errors.Is(err, ErrTitanExecUnavailable) {
			failures = append(failures, fmt.Errorf("titan exec removal: %w", err))
		}
	}
	return errors.Join(failures...)
}

// Reassert re-applies the registered dynamic scopes after a periodic reconcile and
// drops scopes whose cell is gone. It is the additive coordination with the StyX
// full sync documented at the top of this file.
func (k *parserCellKernel) Reassert(settings RuntimeSettings, active []uint64) {
	if k == nil {
		return
	}
	availailable := make(map[uint64]struct{}, len(active))
	for _, cgroupID := range active {
		if cgroupID != 0 {
			availailable[cgroupID] = struct{}{}
		}
	}
	k.mu.Lock()
	stale := make([]uint64, 0)
	for cgroupID := range k.scopes {
		if _, live := availailable[cgroupID]; !live {
			stale = append(stale, cgroupID)
		}
	}
	k.mu.Unlock()
	for _, cgroupID := range stale {
		_ = k.Remove(cgroupID)
	}
	availability, _ := k.probe(settings)
	k.mu.Lock()
	activeScopes := make([]uint64, 0, len(k.scopes))
	for cgroupID := range k.scopes {
		activeScopes = append(activeScopes, cgroupID)
	}
	k.mu.Unlock()
	for _, cgroupID := range activeScopes {
		if availability.CellLSM == parserCellLayerAvailable {
			_ = k.core.CellPolicySet(cgroupID, cellLSMDenyNonUnixSocket)
		}
		if availability.StyxEgress == parserCellLayerAvailable {
			_ = k.core.StyxModeSet(cgroupID, 2, 0)
		}
		if availability.TitanExec == parserCellLayerAvailable {
			_ = k.core.TitanExecScopeSet(cgroupID, 3, 0)
		}
	}
}

// parserCellHostLayersSatisfied implements the §5 admission gate: a cell may only
// be reported as isolated when the operator-required host layers are applied. With
// RequireHostLayers=false the helper's L1 sandbox is sufficient by design.
func parserCellHostLayersSatisfied(required bool, layers ParserCellLayerStatus) bool {
	if !required {
		return true
	}
	return layers.CellLSM == parserCellLayerApplied &&
		layers.StyxEgress == parserCellLayerApplied &&
		layers.TitanExec == parserCellLayerApplied
}

func joinParserCellReasons(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	text := reasons[0]
	for _, reason := range reasons[1:] {
		text += "; " + reason
	}
	if len(text) > parserCellsErrorMaxBytes {
		text = text[:parserCellsErrorMaxBytes]
	}
	return text
}
