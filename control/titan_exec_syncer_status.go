// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2: Titan exec-gate sync status transitions and the read-only
// operator projection (docs/POINT1-TITAN-EXEC-GATE.md §7.3).
//
// No enforcement claim is derived here: `applied` is set only after the ordered
// push of the complete plan succeeded, and a requested mode on a kernel without an
// active BPF-LSM hook is reported as `inactive`, never as applied (§8).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// Sync state vocabulary (§7.3). It is reported verbatim.
const (
	TitanExecSyncStateApplied           = "applied"
	TitanExecSyncStatePending           = "pending"
	TitanExecSyncStateFailed            = "failed"
	TitanExecSyncStateInactive          = "inactive"
	TitanExecSyncStateUnavailable       = "unavailable"
	TitanExecSyncStateCapabilityMissing = "capability-missing"
)

const (
	titanExecCapabilityUnknown = "unknown"
	titanExecCapabilityMissing = "missing"

	titanExecPathBPFLSM = "bpf-lsm"
	titanExecPathNone   = "none"

	titanExecLSMActive   = "active"
	titanExecLSMInactive = "inactive"

	titanExecOffsetsValid   = "valid"
	titanExecOffsetsInvalid = "invalid"
)

// TitanExecSyncStatus is the structured sync state of §7.3. It never contains a
// secret or a raw core payload: only state, counters, honest capability facts and
// error text produced by this control plane (bounded to titanExecStatusErrorMaxBytes).
type TitanExecSyncStatus struct {
	State          string     `json:"state"`
	Capability     string     `json:"capability"`
	Version        string     `json:"version,omitempty"`
	Epoch          string     `json:"epoch,omitempty"`
	Enabled        bool       `json:"enabled"`
	Mode           string     `json:"mode"`
	RequireCtime   bool       `json:"require_ctime"`
	Path           string     `json:"path"`
	LSM            string     `json:"lsm"`
	Offsets        string     `json:"offsets"`
	Entries        int        `json:"entries"`
	Scopes         int        `json:"scopes"`
	AppliedEntries int        `json:"applied_entries"`
	AppliedScopes  int        `json:"applied_scopes"`
	KernelEntries  int        `json:"kernel_entries"`
	KernelScopes   int        `json:"kernel_scopes"`
	Rejected       int        `json:"rejected"`
	Unverified     int        `json:"unverified"`
	LastError      string     `json:"last_error,omitempty"`
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty"`
	LastAppliedAt  *time.Time `json:"last_applied_at,omitempty"`
	RetryInSeconds int        `json:"retry_in_seconds,omitempty"`
}

// titanExecUnavailableStatus is the honest state of a control plane without a
// wired syncer: no capability was probed and no enforcement is claimed.
func titanExecUnavailableStatus() TitanExecSyncStatus {
	return TitanExecSyncStatus{
		State:      TitanExecSyncStateUnavailable,
		Capability: titanExecCapabilityUnknown,
		Mode:       TitanExecModeOff,
		Path:       titanExecPathNone,
		LSM:        titanExecLSMInactive,
		Offsets:    titanExecOffsetsInvalid,
	}
}

// ---------------------------------------------------------------- transitions

func (s *titanExecPolicySyncer) recordCapability(version string) {
	s.mu.Lock()
	s.status.Version = version
	s.status.Capability = version
	if s.status.State == TitanExecSyncStateCapabilityMissing || s.status.State == TitanExecSyncStateUnavailable {
		s.status.State = TitanExecSyncStatePending
	}
	s.mu.Unlock()
}

func (s *titanExecPolicySyncer) finishApplied(plan titanExecPolicyPlan, epoch, version string, coreStatus TitanExecCoreStatus, previousState string) TitanExecSyncStatus {
	now := s.now().UTC()
	fingerprint := plan.Fingerprint
	s.mu.Lock()
	previousFingerprint := s.fingerprint
	changed := previousState != TitanExecSyncStateApplied || previousFingerprint != fingerprint
	s.status = TitanExecSyncStatus{
		State: TitanExecSyncStateApplied, Capability: version, Version: version, Epoch: epoch,
		Enabled: plan.Enabled, Mode: plan.ModeName, RequireCtime: plan.GlobalFlags&titanExecGlobalFlagRequireCtime != 0,
		Path: coreStatus.Path, LSM: coreStatus.LSM, Offsets: coreStatus.Offsets,
		Entries: len(plan.Entries), Scopes: len(plan.Scopes),
		AppliedEntries: len(plan.Entries), AppliedScopes: len(plan.Scopes),
		KernelEntries: coreStatus.Entries, KernelScopes: coreStatus.Scopes,
		Rejected: plan.Rejected, Unverified: plan.Unverified,
		LastAttemptAt: &now, LastAppliedAt: &now,
	}
	s.fingerprint = fingerprint
	s.appliedEpoch = epoch
	s.lastFailure = ""
	s.dirty = false
	s.nextAttempt = now.Add(s.retryInterval)
	status := s.status
	s.mu.Unlock()

	// An unchanged plan is polled every 10 s for a core restart; only a real change
	// is worth an operator-visible event.
	if changed {
		message := fmt.Sprintf("Titan exec-gate policy applied: mode=%s require_ctime=%t allow_entries=%d scopes=%d kernel_path=%s lsm=%s; kernel-side exec/mmap decisions are authoritative",
			status.Mode, status.RequireCtime, status.Entries, status.Scopes, status.Path, status.LSM)
		if !plan.Enabled || plan.Mode == 0 {
			message = "Titan exec-gate policy applied: gate inactive by configuration; global mode is off and no allow entries or scopes remain"
		}
		if s.state != nil {
			s.state.AddEvent(Event{Severity: "info", Kind: "titan_exec.policy_applied", Source: "titan-exec", Message: message})
		}
	}
	return status
}

// finishUnchanged refreshes the epoch/capability bookkeeping of a steady-state poll
// without emitting an event: nothing was applied because nothing changed.
func (s *titanExecPolicySyncer) finishUnchanged(plan titanExecPolicyPlan, epoch, version string, coreStatus TitanExecCoreStatus) TitanExecSyncStatus {
	now := s.now().UTC()
	s.mu.Lock()
	s.status.State = TitanExecSyncStateApplied
	s.status.Capability = version
	s.status.Version = version
	s.status.Epoch = epoch
	s.status.Enabled = plan.Enabled
	s.status.Mode = plan.ModeName
	s.status.RequireCtime = plan.GlobalFlags&titanExecGlobalFlagRequireCtime != 0
	s.status.Path = coreStatus.Path
	s.status.LSM = coreStatus.LSM
	s.status.Offsets = coreStatus.Offsets
	s.status.Entries = len(plan.Entries)
	s.status.Scopes = len(plan.Scopes)
	s.status.AppliedEntries = len(plan.Entries)
	s.status.AppliedScopes = len(plan.Scopes)
	s.status.KernelEntries = coreStatus.Entries
	s.status.KernelScopes = coreStatus.Scopes
	s.status.Rejected = plan.Rejected
	s.status.Unverified = plan.Unverified
	s.status.LastAttemptAt = &now
	s.lastFailure = ""
	s.dirty = false
	s.nextAttempt = now.Add(s.retryInterval)
	status := s.status
	s.mu.Unlock()
	return status
}

func (s *titanExecPolicySyncer) finishFailure(err error) TitanExecSyncStatus {
	now := s.now().UTC()
	text := boundedTitanExecText(err)
	s.mu.Lock()
	previousState := s.status.State
	previousError := s.status.LastError
	// A disabled namespace that never installed anything produces no policy event on
	// a transient core outage: it is not a failed enforcement attempt. A real apply
	// failure - or any failure after something was installed - is always named.
	reportEvent := s.desired.Enabled || s.applied.Initialized
	s.status.State = TitanExecSyncStateFailed
	s.status.LastError = text
	s.status.LastAttemptAt = &now
	s.lastFailure = text
	s.nextAttempt = now.Add(s.retryInterval)
	status := s.status
	s.mu.Unlock()

	// The failure is reported once per condition, not once per retry: the backoff
	// stays visible in the status while the event stream stays readable.
	if reportEvent && (previousState != TitanExecSyncStateFailed || previousError != text) {
		log.Printf("titan exec-gate policy sync failed (no enforcement state is claimed): %s", text)
		if s.state != nil {
			s.state.AddEvent(Event{
				Severity: "high", Kind: "titan_exec.policy_sync_failed", Source: "titan-exec",
				Message: "Titan exec-gate policy could not be applied; the kernel may still hold a previous policy and no enforcement state is being claimed: " + text,
			})
		}
	}
	return status
}

// finishCapabilityMissing is the backwards-compatible path for a pre-TitanExec
// core: the sensor is unavailable, no failure event is raised and XDR is not
// degraded (§7.3).
func (s *titanExecPolicySyncer) finishCapabilityMissing(reason string) TitanExecSyncStatus {
	now := s.now().UTC()
	s.mu.Lock()
	previousState := s.status.State
	desired := s.desired
	s.status.State = TitanExecSyncStateCapabilityMissing
	s.status.Capability = titanExecCapabilityMissing
	s.status.Version = ""
	s.status.Epoch = ""
	s.status.Enabled = desired.Enabled
	s.status.Mode = desired.Mode
	s.status.RequireCtime = desired.RequireCtime
	s.status.Path = titanExecPathNone
	s.status.LSM = titanExecLSMInactive
	s.status.Offsets = titanExecOffsetsInvalid
	s.status.Entries = 0
	s.status.Scopes = 0
	s.status.AppliedEntries = 0
	s.status.AppliedScopes = 0
	s.status.KernelEntries = 0
	s.status.KernelScopes = 0
	s.status.Rejected = 0
	s.status.Unverified = 0
	s.status.LastError = ""
	s.status.LastAttemptAt = &now
	s.nextAttempt = now.Add(s.retryInterval)
	// The kernel maps belong to a core that cannot be talked to; nothing known about
	// them survives, so the next successful probe must perform a full re-sync.
	s.applied = titanExecAppliedPolicy{}
	s.fingerprint = ""
	status := s.status
	s.mu.Unlock()

	if previousState != TitanExecSyncStateCapabilityMissing {
		message := "The privileged core does not advertise the TITAN_EXEC_* command family; the kernel exec gate stays unavailable until it is upgraded. This is a capability fact, not an XDR degradation."
		if reason != "" {
			message = reason + ". " + message
		}
		log.Printf("titan exec-gate capability missing: %s", message)
		if s.state != nil {
			s.state.AddEvent(Event{Severity: "info", Kind: "titan_exec.capability_missing", Source: "titan-exec", Message: message})
		}
	}
	return status
}

// finishUnavailable is the honest state when no privileged core client exists at
// all: no capability can be probed and no enforcement is claimed.
func (s *titanExecPolicySyncer) finishUnavailable(reason string) TitanExecSyncStatus {
	now := s.now().UTC()
	text := boundedTitanExecText(errors.New(reason))
	s.mu.Lock()
	previousState := s.status.State
	desired := s.desired
	s.status = titanExecUnavailableStatus()
	s.status.Enabled = desired.Enabled
	s.status.Mode = desired.Mode
	s.status.RequireCtime = desired.RequireCtime
	s.status.LastError = text
	s.status.LastAttemptAt = &now
	s.lastFailure = text
	s.nextAttempt = now.Add(s.retryInterval)
	s.applied = titanExecAppliedPolicy{}
	s.fingerprint = ""
	status := s.status
	s.mu.Unlock()
	if previousState != TitanExecSyncStateUnavailable {
		log.Printf("titan exec-gate sync unavailable: %s", text)
	}
	return status
}

// finishEnforcementUnavailable is the honest state for a requested mode on a
// kernel whose BPF-LSM hook is not attached (§8): nothing is claimed as enforced
// and the bounded retry keeps watching for activation.
func (s *titanExecPolicySyncer) finishEnforcementUnavailable(reason, state string, plan titanExecPolicyPlan, epoch, version string, coreStatus TitanExecCoreStatus) TitanExecSyncStatus {
	now := s.now().UTC()
	text := boundedTitanExecText(errors.New(reason))
	if state != TitanExecSyncStateUnavailable {
		state = TitanExecSyncStateInactive
	}
	s.mu.Lock()
	previousState := s.status.State
	previousError := s.status.LastError
	s.status = TitanExecSyncStatus{
		State: state, Capability: version, Version: version, Epoch: epoch,
		Enabled: plan.Enabled, Mode: plan.ModeName, RequireCtime: plan.GlobalFlags&titanExecGlobalFlagRequireCtime != 0,
		Path: coreStatus.Path, LSM: coreStatus.LSM, Offsets: coreStatus.Offsets,
		Entries: len(plan.Entries), Scopes: len(plan.Scopes),
		KernelEntries: coreStatus.Entries, KernelScopes: coreStatus.Scopes,
		Rejected: plan.Rejected, Unverified: plan.Unverified,
		LastError: text, LastAttemptAt: &now,
	}
	s.lastFailure = text
	s.nextAttempt = now.Add(s.retryInterval)
	// Nothing of this plan reached the maps; the next attempt must start from the
	// fail-safe full re-sync instead of believing a previous state is current.
	s.applied = titanExecAppliedPolicy{}
	s.fingerprint = ""
	status := s.status
	s.mu.Unlock()

	if previousState != status.State || previousError != text {
		log.Printf("titan exec-gate enforcement %s (no enforcement claimed): %s", status.State, text)
		if s.state != nil {
			s.state.AddEvent(Event{
				Severity: "high", Kind: "titan_exec.enforcement_inactive", Source: "titan-exec",
				Message: "The Titan exec gate was configured to enforce but the kernel hook is not active; no exec/mmap decision is being enforced: " + text,
			})
		}
	}
	return status
}

// ---------------------------------------------------------------- helpers

func boundedTitanExecText(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(strings.Join(strings.Fields(err.Error()), " "))
	if len(text) > titanExecStatusErrorMaxBytes {
		text = text[:titanExecStatusErrorMaxBytes]
	}
	return text
}

func sortedTitanExecScopeIDs(scopes map[uint64]titanExecPlanScope) []uint64 {
	ids := make([]uint64, 0, len(scopes))
	for cgroupID := range scopes {
		ids = append(ids, cgroupID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// titanExecSameObservedIdentity reports whether a desired entry still names the same
// filesystem object as the applied one. A replaced binary must re-sync even when the
// path string is unchanged.
func titanExecSameObservedIdentity(applied, desired titanExecPlanEntry) bool {
	return applied.Path == desired.Path &&
		applied.ObservedDev == desired.ObservedDev &&
		applied.ObservedIno == desired.ObservedIno &&
		applied.ObservedCtimeNS == desired.ObservedCtimeNS
}

// titanExecEnforcementUnavailable is the §8 precondition check for a requested
// mode > 0: the kernel hook must be attached and the offsets valid.
func titanExecEnforcementUnavailable(plan titanExecPolicyPlan, status TitanExecCoreStatus) (reason, state string, unavailable bool) {
	if plan.Mode == 0 {
		return "", "", false
	}
	if status.Offsets != titanExecOffsetsValid {
		return "kernel exec-gate BTF offsets are invalid; the BPF-LSM hook is not attached and mode " + plan.ModeName + " cannot be enforced", TitanExecSyncStateUnavailable, true
	}
	if status.LSM != titanExecLSMActive {
		return "BPF-LSM is not active in the running kernel; add bpf to the lsm= kernel command line and reboot before enforcing (mode " + plan.ModeName + ")", TitanExecSyncStateInactive, true
	}
	if status.Path != titanExecPathBPFLSM {
		return "the kernel exec gate is not attached (path=" + status.Path + "); mode " + plan.ModeName + " cannot be enforced", TitanExecSyncStateInactive, true
	}
	return "", "", false
}

// titanExecEnforcementReason re-derives the operator-facing reason and state after
// a core rejection, so the status names the same fact the pre-check names.
func titanExecEnforcementReason(plan titanExecPolicyPlan, status TitanExecCoreStatus) (string, string) {
	if reason, state, unavailable := titanExecEnforcementUnavailable(plan, status); unavailable {
		return reason, state
	}
	return "the core rejected enforcement for mode " + plan.ModeName + " (enforcement-unavailable)", TitanExecSyncStateInactive
}

func titanExecIsEnforcementUnavailable(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "enforcement-unavailable") || strings.Contains(message, "enforcement unavailable")
}

// addEntries projects the allowlist. Batches are bounded to the §5 batch shape; a
// path that cannot fit is added individually. The returned map carries the kernel
// identities the core reported for the individual additions.
func (s *titanExecPolicySyncer) addEntries(ctx context.Context, entries []titanExecPlanEntry) (map[string]TitanExecAllowIdentity, error) {
	identities := make(map[string]TitanExecAllowIdentity, len(entries))
	batches, singles := titanExecPlanAddBatches(entries)
	for _, path := range singles {
		if err := titanExecContextErr(ctx); err != nil {
			return nil, err
		}
		identity, err := s.core.TitanExecAllowAdd(path)
		if err != nil {
			return nil, fmt.Errorf("add titan exec allow entry %q: %w", path, err)
		}
		identities[path] = identity
	}
	for _, batch := range batches {
		if err := titanExecContextErr(ctx); err != nil {
			return nil, err
		}
		result, err := s.core.TitanExecAllowAddBatch(batch)
		if err != nil {
			return nil, fmt.Errorf("add titan exec allow batch: %w", err)
		}
		if result.Rejected > 0 {
			// Partial acceptance is an explicit failure (§5): the plan is not fully
			// installed, so the sync must not report applied.
			return nil, fmt.Errorf("titan exec allow batch rejected %d of %d paths: %s", result.Rejected, len(batch), result.Error)
		}
		if result.Added+result.Rejected != len(batch) {
			// A batch that reports fewer results than submitted paths would silently
			// drop allow entries - under STRICT that is a lockout, so it fails.
			return nil, fmt.Errorf("titan exec allow batch covered %d of %d paths", result.Added+result.Rejected, len(batch))
		}
	}
	return identities, nil
}

// titanExecPlanAddBatches chunks the entries into the bounded wire shape: at most
// titanExecMaxBatchPaths paths and at most titanExecMaxBatchBytes decoded bytes per
// batch. Small policies are pushed one path at a time so the kernel identity of
// every entry is known for a later surgical delete; a single path that exceeds the
// batch byte budget is always added individually.
func titanExecPlanAddBatches(entries []titanExecPlanEntry) (batches [][]string, singles []string) {
	if len(entries) <= titanExecSingleAddThreshold {
		for _, entry := range entries {
			singles = append(singles, entry.Path)
		}
		return nil, singles
	}
	current := make([]string, 0, titanExecMaxBatchPaths)
	decodedBytes := 0
	flush := func() {
		if len(current) > 0 {
			batches = append(batches, current)
			current = make([]string, 0, titanExecMaxBatchPaths)
			decodedBytes = 0
		}
	}
	for _, entry := range entries {
		if len(entry.Path) > titanExecMaxBatchBytes {
			singles = append(singles, entry.Path)
			continue
		}
		additional := len(entry.Path)
		if len(current) > 0 {
			additional++
		}
		if len(current) >= titanExecMaxBatchPaths || decodedBytes+additional > titanExecMaxBatchBytes {
			flush()
			additional = len(entry.Path)
		}
		current = append(current, entry.Path)
		decodedBytes += additional
	}
	flush()
	return batches, singles
}
