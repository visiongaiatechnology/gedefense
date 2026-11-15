// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2: the Titan exec-gate policy syncer
// (docs/POINT1-TITAN-EXEC-GATE.md §5 resync contract, §7.3).
//
// The syncer is independent of the XDR detection engine: it runs its own bounded
// retry/epoch loop, because a kernel policy is not an XDR feature. It talks only to
// the privileged core through the authenticated VGT3 channel; the kernel owns the
// maps, the blocking and the incident telemetry. See titan_exec_syncer_status.go for
// the state transitions and the operator view.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// titanExecPolicySyncRetryInterval is both the retry backoff after a failure and
	// the epoch re-check interval after a success. A core restart must be noticed in
	// bounded time (§5: new epoch + empty maps => full re-sync).
	titanExecPolicySyncRetryInterval = 10 * time.Second

	// titanExecSingleAddThreshold small policies are pushed with individual
	// ALLOW_ADD calls because only that answer returns the kernel identity (§5),
	// which allows a later revision to remove exactly the stale inode instead of
	// clearing and re-adding the whole map.
	titanExecSingleAddThreshold = 16
)

// titanExecPolicyCore is the subset of the authenticated core client the syncer
// needs. It exists as an interface so the ordering/fail-safe contract is testable
// without a privileged core or a Unix socket.
type titanExecPolicyCore interface {
	TitanExecVersion() (string, error)
	TitanExecEpoch() (string, error)
	TitanExecStatus() (TitanExecCoreStatus, error)
	TitanExecSetGlobal(mode, flags uint8) error
	TitanExecAllowAdd(path string) (TitanExecAllowIdentity, error)
	TitanExecAllowAddBatch(paths []string) (TitanExecBatchResult, error)
	TitanExecAllowDel(dev uint32, ino uint64) error
	TitanExecClear() error
	TitanExecScopeSet(cgroupID uint64, mode, flags uint8) error
	TitanExecScopeDel(cgroupID uint64) error
}

// titanExecAppliedEntry is one entry this control plane has confirmed. Identity is
// only known for an entry that was added individually: the batch answer carries
// counts, not identities (§5). A removal of an entry with an unknown identity needs
// a full CLEAR instead of a per-entry DELETE.
type titanExecAppliedEntry struct {
	Plan     titanExecPlanEntry
	Identity TitanExecAllowIdentity
	Known    bool
}

type titanExecAppliedPolicy struct {
	Initialized bool
	Enabled     bool
	Mode        uint8
	GlobalFlags uint8
	Entries     map[string]titanExecAppliedEntry
	Scopes      map[uint64]titanExecPlanScope
}

type titanExecPolicySyncer struct {
	core  titanExecPolicyCore
	state *State
	deps  titanExecPlanDeps
	now   func() time.Time
	// retryInterval is a field so a test can drive the bounded retry without
	// sleeping; production always uses titanExecPolicySyncRetryInterval.
	retryInterval time.Duration

	syncMu sync.Mutex // serialises one full sync; never held while reading status
	mu     sync.Mutex // guards desired/status/applied/nextAttempt

	desired      TitanExecFabricSettings
	status       TitanExecSyncStatus
	applied      titanExecAppliedPolicy
	appliedEpoch string
	fingerprint  string
	dirty        bool
	nextAttempt  time.Time
	lastFailure  string
}

// NewTitanExecPolicySyncer constructs the syncer in the honest initial state:
// nothing has been applied and the core capability is unknown until probed. An
// empty deps struct is filled from the host: the package verifier is the same
// bounded local one the Titan engine uses, and the FIM lookup is the state's
// encrypted baseline.
func NewTitanExecPolicySyncer(core titanExecPolicyCore, state *State, settings RuntimeSettings, deps titanExecPlanDeps) *titanExecPolicySyncer {
	filled := deps
	if filled.Packages == nil {
		filled.Packages = newTitanPackageVerifier()
	}
	if filled.FIM == nil && state != nil {
		filled.FIM = state.FIM()
	}
	desired := effectiveTitanExecFabricSettings(settings)
	status := titanExecUnavailableStatus()
	status.State = TitanExecSyncStatePending
	status.Enabled = desired.Enabled
	status.Mode = desired.Mode
	status.RequireCtime = desired.RequireCtime
	return &titanExecPolicySyncer{
		core:          core,
		state:         state,
		deps:          filled,
		now:           func() time.Time { return time.Now().UTC() },
		retryInterval: titanExecPolicySyncRetryInterval,
		desired:       desired,
		status:        status,
	}
}

// Configure records a new persisted revision. The kernel is not touched here;
// Run/Sync does that, so a slow or absent core can never block the settings API.
func (s *titanExecPolicySyncer) Configure(settings RuntimeSettings) {
	if s == nil {
		return
	}
	desired := effectiveTitanExecFabricSettings(settings)
	s.mu.Lock()
	s.desired = cloneTitanExecFabricSettings(desired)
	s.dirty = true
	s.nextAttempt = time.Time{}
	if s.status.State != TitanExecSyncStateCapabilityMissing {
		s.status.State = TitanExecSyncStatePending
	}
	s.status.Enabled = desired.Enabled
	s.status.Mode = desired.Mode
	s.status.RequireCtime = desired.RequireCtime
	s.mu.Unlock()
}

// Run performs the initial sync and then the bounded retry/epoch loop. It returns
// when the engine context is cancelled.
func (s *titanExecPolicySyncer) Run(ctx context.Context) {
	if s == nil {
		return
	}
	s.Sync(ctx)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.SyncIfDue(ctx)
		}
	}
}

// SyncIfDue runs a sync only when a revision is pending or the retry/epoch
// interval elapsed.
func (s *titanExecPolicySyncer) SyncIfDue(ctx context.Context) TitanExecSyncStatus {
	if s == nil {
		return titanExecUnavailableStatus()
	}
	s.mu.Lock()
	due := s.dirty || s.nextAttempt.IsZero() || !s.now().Before(s.nextAttempt)
	s.mu.Unlock()
	if !due {
		return s.Snapshot()
	}
	return s.Sync(ctx)
}

// Snapshot returns the current structured status.
func (s *titanExecPolicySyncer) Snapshot() TitanExecSyncStatus {
	if s == nil {
		return titanExecUnavailableStatus()
	}
	s.mu.Lock()
	out := s.status
	next, retry := s.nextAttempt, s.retryInterval
	s.mu.Unlock()
	if !next.IsZero() && out.State != TitanExecSyncStateApplied {
		remaining := next.Sub(s.now())
		if remaining > 0 && remaining <= retry {
			out.RetryInSeconds = int(remaining.Round(time.Second) / time.Second)
		}
	}
	return out
}

// CapabilityKnown reports whether this core advertised the TitanExec ABI. A
// pre-TitanExec core is a capability fact, never an XDR degradation (§7.3).
func (s *titanExecPolicySyncer) CapabilityKnown() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status.Capability == titanExecSupportedVersion
}

// Sync performs one complete capability/epoch/policy pass. It is serialised: two
// callers can never interleave one half-applied policy with another.
func (s *titanExecPolicySyncer) Sync(ctx context.Context) TitanExecSyncStatus {
	if s == nil {
		return titanExecUnavailableStatus()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	if err := ctx.Err(); err != nil {
		return s.Snapshot()
	}
	s.mu.Lock()
	desired := cloneTitanExecFabricSettings(s.desired)
	previousState := s.status.State
	s.mu.Unlock()

	plan, err := compileTitanExecPolicyPlan(ctx, desired, s.deps)
	if err != nil {
		// Defensive: the settings store validates before persisting, so this only
		// happens for a document edited out-of-band or a plan the safety checks
		// refused (strict without evidence, unreadable root). It must never reach
		// the kernel.
		return s.finishFailure(err)
	}
	if s.core == nil {
		return s.finishUnavailable("no privileged core client is attached")
	}
	version, err := s.core.TitanExecVersion()
	if err != nil {
		if errors.Is(err, ErrTitanExecUnavailable) {
			return s.finishCapabilityMissing("")
		}
		return s.finishFailure(fmt.Errorf("titan exec capability probe failed: %w", err))
	}
	s.recordCapability(version)
	epoch, err := s.core.TitanExecEpoch()
	if err != nil {
		if errors.Is(err, ErrTitanExecUnavailable) {
			return s.finishCapabilityMissing("")
		}
		return s.finishFailure(fmt.Errorf("titan exec epoch probe failed: %w", err))
	}
	coreStatus, err := s.core.TitanExecStatus()
	if err != nil {
		if errors.Is(err, ErrTitanExecUnavailable) {
			return s.finishCapabilityMissing("")
		}
		return s.finishFailure(fmt.Errorf("titan exec status probe failed: %w", err))
	}

	s.mu.Lock()
	epochChanged := s.applied.Initialized && s.appliedEpoch != "" && s.appliedEpoch != epoch
	if epochChanged {
		// The core restarted: its maps are empty and every policy must be pushed
		// again (§5 resync contract). Nothing may be claimed until the push
		// succeeded.
		s.applied = titanExecAppliedPolicy{}
		s.fingerprint = ""
	}
	applied := s.applied
	samePlan := s.fingerprint != "" && s.fingerprint == plan.Fingerprint
	s.mu.Unlock()

	if previousState == TitanExecSyncStateApplied && samePlan && !epochChanged && applied.Initialized {
		// Steady state: the epoch poll found an unchanged core and an unchanged
		// plan. Re-writing thousands of map entries every 10 s would be churn.
		return s.finishUnchanged(plan, epoch, version, coreStatus)
	}
	if plan.Mode > 0 {
		// Enforcement requires an attached hook. Claiming otherwise would be a lie
		// (§8), so the attempt is refused visibly as `inactive`/`unavailable` until
		// the operator activated BPF-LSM and the core attached the hooks.
		if reason, state, unavailable := titanExecEnforcementUnavailable(plan, coreStatus); unavailable {
			return s.finishEnforcementUnavailable(reason, state, plan, epoch, version, coreStatus)
		}
	}

	next, applyErr := s.applyPlan(ctx, plan, applied)
	if applyErr != nil {
		if errors.Is(applyErr, ErrTitanExecUnavailable) {
			return s.finishCapabilityMissing("")
		}
		if plan.Mode > 0 && titanExecIsEnforcementUnavailable(applyErr) {
			reason, state := titanExecEnforcementReason(plan, coreStatus)
			return s.finishEnforcementUnavailable(reason, state, plan, epoch, version, coreStatus)
		}
		return s.finishFailure(applyErr)
	}
	s.mu.Lock()
	s.applied = next
	s.mu.Unlock()
	return s.finishApplied(plan, epoch, version, coreStatus, previousState)
}

// applyPlan is the ordered, fail-safe projection of one plan (§5):
// global off (fail-safe) -> allowlist -> scopes -> global mode. Every step is
// idempotent, so a partially failed sync is simply retried from the beginning.
func (s *titanExecPolicySyncer) applyPlan(ctx context.Context, plan titanExecPolicyPlan, applied titanExecAppliedPolicy) (titanExecAppliedPolicy, error) {
	// Step 1: fail-safe global off. It runs on every real apply, so a changed
	// revision can never leave a previous mode in force while entries are edited.
	if err := titanExecContextErr(ctx); err != nil {
		return applied, err
	}
	if err := s.core.TitanExecSetGlobal(0, 0); err != nil {
		return applied, fmt.Errorf("fail-safe titan exec global off: %w", err)
	}

	next := titanExecAppliedPolicy{
		Initialized: true, Enabled: plan.Enabled, Mode: plan.Mode, GlobalFlags: plan.GlobalFlags,
		Entries: make(map[string]titanExecAppliedEntry, len(plan.Entries)),
		Scopes:  make(map[uint64]titanExecPlanScope, len(plan.Scopes)),
	}
	if !plan.Enabled {
		// Disable path: global off is in force; now remove what we installed.
		return next, s.clearAppliedPolicy(ctx, applied)
	}

	desired := make(map[string]titanExecPlanEntry, len(plan.Entries))
	for _, entry := range plan.Entries {
		desired[entry.Path] = entry
	}
	additions := make([]titanExecPlanEntry, 0, len(plan.Entries))
	stale := make([]titanExecAppliedEntry, 0, len(applied.Entries))
	for _, entry := range plan.Entries {
		previous, exists := applied.Entries[entry.Path]
		if !exists {
			additions = append(additions, entry)
			continue
		}
		if titanExecSameObservedIdentity(previous.Plan, entry) {
			next.Entries[entry.Path] = previous
			continue
		}
		// The file was replaced at the same path: the old inode entry must go and
		// the new identity must be installed.
		stale = append(stale, previous)
		additions = append(additions, entry)
	}
	for path, previous := range applied.Entries {
		if _, keep := desired[path]; keep {
			continue
		}
		stale = append(stale, previous)
	}
	needClear := false
	for _, previous := range stale {
		if !previous.Known {
			// A batch-added entry has no kernel identity in this control plane
			// (§5 returns counts, not identities). The only safe way to remove it is
			// a full CLEAR while the global mode is off.
			needClear = true
			break
		}
	}
	if needClear {
		if err := titanExecContextErr(ctx); err != nil {
			return applied, err
		}
		if err := s.core.TitanExecClear(); err != nil {
			return applied, fmt.Errorf("clear titan exec allowlist: %w", err)
		}
		additions = append(make([]titanExecPlanEntry, 0, len(plan.Entries)), plan.Entries...)
		stale = nil
	}
	identities, err := s.addEntries(ctx, additions)
	if err != nil {
		return applied, err
	}
	for _, entry := range additions {
		identity, known := identities[entry.Path]
		next.Entries[entry.Path] = titanExecAppliedEntry{Plan: entry, Identity: identity, Known: known}
	}
	// Adds precede deletes: replacing an entry never leaves a window without one
	// while the final mode is restored.
	for _, previous := range stale {
		if !previous.Known {
			return applied, fmt.Errorf("stale titan exec entry %q has no kernel identity to delete", previous.Plan.Path)
		}
		if err := titanExecContextErr(ctx); err != nil {
			return applied, err
		}
		if err := s.core.TitanExecAllowDel(previous.Identity.Dev, previous.Identity.Ino); err != nil {
			return applied, fmt.Errorf("delete stale titan exec allow entry %q: %w", previous.Plan.Path, err)
		}
	}

	// Scopes: set the desired overrides first, then remove the stale ones.
	for _, scope := range plan.Scopes {
		if previous, exists := applied.Scopes[scope.CgroupID]; exists && previous == scope {
			next.Scopes[scope.CgroupID] = previous
			continue
		}
		if err := titanExecContextErr(ctx); err != nil {
			return applied, err
		}
		if err := s.core.TitanExecScopeSet(scope.CgroupID, scope.Mode, scope.Flags); err != nil {
			return applied, fmt.Errorf("apply titan exec scope %d: %w", scope.CgroupID, err)
		}
		next.Scopes[scope.CgroupID] = scope
	}
	desiredScopes := make(map[uint64]titanExecPlanScope, len(plan.Scopes))
	for _, scope := range plan.Scopes {
		desiredScopes[scope.CgroupID] = scope
	}
	for _, cgroupID := range sortedTitanExecScopeIDs(applied.Scopes) {
		if _, keep := desiredScopes[cgroupID]; keep {
			continue
		}
		if err := titanExecContextErr(ctx); err != nil {
			return applied, err
		}
		if err := s.core.TitanExecScopeDel(cgroupID); err != nil {
			return applied, fmt.Errorf("delete stale titan exec scope %d: %w", cgroupID, err)
		}
	}

	// Step 4: only now restore the configured mode. Any earlier failure left the
	// host in the safe off state instead of a half-applied policy.
	if err := titanExecContextErr(ctx); err != nil {
		return applied, err
	}
	if err := s.core.TitanExecSetGlobal(plan.Mode, plan.GlobalFlags); err != nil {
		// The core refuses mode>0 with a generic ERR when BPF-LSM/offsets/attach are
		// not ready (P1-T3). That never becomes `applied`: the status pre-check
		// already reports the honest inactive/unavailable state from the probed
		// facts, and an unexpected rejection after a ready probe is a failed sync
		// that is retried within the bounded backoff.
		return applied, fmt.Errorf("apply titan exec global mode %s: %w", plan.ModeName, err)
	}
	return next, nil
}

// clearAppliedPolicy is the disable path: the global mode is already off, then the
// allowlist is cleared and every scope this control plane installed is deleted
// (both operations are idempotent on the core, §5).
func (s *titanExecPolicySyncer) clearAppliedPolicy(ctx context.Context, applied titanExecAppliedPolicy) error {
	if err := titanExecContextErr(ctx); err != nil {
		return err
	}
	// CLEAR is issued even when this control plane has no bookkeeping (a control
	// restart while the core kept running): the operator disabled the gate and a
	// leftover allowlist must not survive. The global mode is off, so an empty map
	// denies nothing.
	if err := s.core.TitanExecClear(); err != nil {
		return fmt.Errorf("clear titan exec allowlist: %w", err)
	}
	for _, cgroupID := range sortedTitanExecScopeIDs(applied.Scopes) {
		if err := titanExecContextErr(ctx); err != nil {
			return err
		}
		if err := s.core.TitanExecScopeDel(cgroupID); err != nil {
			return fmt.Errorf("delete titan exec scope %d: %w", cgroupID, err)
		}
	}
	return nil
}

// titanExecContextErr keeps the cancellation checks of the ordered write path
// readable; a nil context is treated as background.
func titanExecContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
