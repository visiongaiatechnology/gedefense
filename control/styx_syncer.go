// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5: the StyX policy syncer. It projects the validated plan onto
// the core's STYX_* commands only; the privileged kernel owns the maps and
// the blocking. See styx_syncer_status.go for status transitions.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ------------------------------------------------------------------ syncer

// styxPolicyCore is the subset of the authenticated core client the syncer needs.
// It exists as an interface so the ordering/fail-safe contract is testable
// without a privileged core or a Unix socket.
type styxPolicyCore interface {
	StyxVersion() (string, error)
	StyxEpoch() (string, error)
	StyxGlobal(mode, flags uint8) error
	StyxModeSet(cgroupID uint64, mode, flags uint8) error
	StyxModeDel(cgroupID uint64) error
	StyxAllowAdd(family uint8, scope string, cgroupID uint64, cidr string, portLo, portHi uint16, protoMask uint8) error
	StyxAllowDel(family uint8, scope string, cgroupID uint64, cidr string, portLo, portHi uint16, protoMask uint8) error
	StyxResolverAdd(family uint8, cidr string) error
	StyxResolverDel(family uint8, cidr string) error
}

// StyxSyncStatus is the structured sync state of §8.3. It never contains a
// secret, a credential or a raw core payload: only state, counters and error text
// that was produced by this control plane (bounded to styxStatusErrorMaxBytes).
//
// M3: the identity fields make cgroup-id drift visible. A path-backed cell whose
// id was re-resolved after a reboot/unit restart is counted in CgroupDriftTotal;
// an unresolvable path degrades the identity layer (Degraded) while the resolvable
// part of the policy keeps being applied.
type StyxSyncStatus struct {
	State            string              `json:"state"`
	Capability       string              `json:"capability"`
	Version          string              `json:"version,omitempty"`
	Epoch            string              `json:"epoch,omitempty"`
	Enabled          bool                `json:"enabled"`
	Mode             string              `json:"mode"`
	LogFlows         bool                `json:"log_flows"`
	Cells            int                 `json:"cells"`
	AllowRules       int                 `json:"allow_rules"`
	Resolvers        int                 `json:"dns_resolvers"`
	PathsResolved    int                 `json:"paths_resolved"`
	PathsUnresolved  int                 `json:"paths_unresolved"`
	LegacyIDs        int                 `json:"legacy_ids"`
	CgroupDriftTotal uint64              `json:"cgroup_drift_total"`
	Degraded         bool                `json:"degraded"`
	DegradedReason   string              `json:"degraded_reason,omitempty"`
	Identities       []StyxIdentityState `json:"identities,omitempty"`
	LastError        string              `json:"last_error,omitempty"`
	LastAttemptAt    *time.Time          `json:"last_attempt_at,omitempty"`
	LastAppliedAt    *time.Time          `json:"last_applied_at,omitempty"`
	RetryInSeconds   int                 `json:"retry_in_seconds,omitempty"`
}

type styxAppliedPolicy struct {
	Initialized bool
	Enabled     bool
	Mode        uint8
	GlobalFlags uint8
	Cells       map[uint64]styxCellPlan
	Allow       []styxAllowPlan
	Resolvers   []styxResolverPlan
}

type styxPolicySyncer struct {
	core styxPolicyCore
	// resolver re-resolves every path-backed cell on each sync (M3.2). It is an
	// interface so the drift/degraded contract is testable without a privileged
	// host; the default reads /sys/fs/cgroup.
	resolver styxCgroupResolver
	// state is optional (tests may run the syncer without an engine); when present
	// every transition is reported as an event, never as a silent edit.
	state         *State
	now           func() time.Time
	retryInterval time.Duration

	syncMu sync.Mutex // serialises one full sync; never held while reading status
	mu     sync.Mutex // guards desired/status/applied/nextAttempt

	desired      StyxFabricSettings
	status       StyxSyncStatus
	applied      styxAppliedPolicy
	appliedEpoch string
	fingerprint  string
	dirty        bool
	nextAttempt  time.Time
	lastFailure  string

	// identity bookkeeping (guarded by mu): the ids resolved during the last
	// successful sync and the drift/degradation state that was already reported.
	resolvedPaths      map[string]uint64
	reportedDrift      map[string]struct{}
	identityDegraded   bool
	cgroupDriftTotal   uint64
	lastIdentityReport styxIdentityReport
}

// NewStyxPolicySyncer constructs the syncer in the honest initial state: nothing
// has been applied yet, and the capability of the core is unknown until probed.
func NewStyxPolicySyncer(core styxPolicyCore, state *State, settings RuntimeSettings) *styxPolicySyncer {
	desired := effectiveStyxFabricSettings(settings)
	status := StyxSyncStatus{
		State:      StyxSyncStatePending,
		Capability: styxCapabilityUnknown,
		Enabled:    desired.Enabled,
		Mode:       desired.Mode,
		LogFlows:   styxEffectiveLogFlows(desired),
	}
	return &styxPolicySyncer{
		core: core, state: state, resolver: newStyxSystemCgroupResolver(),
		now:           func() time.Time { return time.Now().UTC() },
		retryInterval: styxPolicySyncRetryInterval,
		desired:       desired,
		status:        status,
		nextAttempt:   time.Time{},
	}
}

// Configure records a new persisted revision. The kernel is not touched here;
// Run/Sync does that, so a slow or absent core can never block the settings API.
func (s *styxPolicySyncer) Configure(settings RuntimeSettings) {
	if s == nil {
		return
	}
	desired := effectiveStyxFabricSettings(settings)
	s.mu.Lock()
	s.desired = cloneStyxFabricSettings(desired)
	s.dirty = true
	s.nextAttempt = time.Time{}
	if s.status.State != StyxSyncStateCapabilityMissing {
		s.status.State = StyxSyncStatePending
	}
	s.status.Enabled = desired.Enabled
	s.status.Mode = desired.Mode
	s.status.LogFlows = styxEffectiveLogFlows(desired)
	s.mu.Unlock()
}

// Run performs the initial sync and then the bounded retry/epoch loop. It returns
// when the engine context is cancelled.
func (s *styxPolicySyncer) Run(ctx context.Context) {
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
func (s *styxPolicySyncer) SyncIfDue(ctx context.Context) StyxSyncStatus {
	if s == nil {
		return StyxSyncStatus{State: StyxSyncStateUnavailable, Capability: styxCapabilityUnknown}
	}
	s.mu.Lock()
	due := s.dirty || s.nextAttempt.IsZero() || !s.now().Before(s.nextAttempt)
	s.mu.Unlock()
	if !due {
		return s.Snapshot()
	}
	return s.Sync(ctx)
}

// Snapshot returns the current structured status. RetryInSeconds is derived so the
// operator can see that a failed sync is still being retried.
func (s *styxPolicySyncer) Snapshot() StyxSyncStatus {
	if s == nil {
		return StyxSyncStatus{State: StyxSyncStateUnavailable, Capability: styxCapabilityUnknown}
	}
	s.mu.Lock()
	out := s.status
	next, retry := s.nextAttempt, s.retryInterval
	s.mu.Unlock()
	if !next.IsZero() && out.State != StyxSyncStateApplied {
		remaining := next.Sub(s.now())
		if remaining > 0 && remaining <= retry {
			out.RetryInSeconds = int(remaining.Round(time.Second) / time.Second)
		}
	}
	return out
}

// CapabilityKnown reports whether this core advertised the StyX ABI. A pre-StyX
// core is a capability fact, never an XDR degradation (§9).
func (s *styxPolicySyncer) CapabilityKnown() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status.Capability == styxWireVersion
}

// Sync performs one complete capability/epoch/policy pass. It is serialised: two
// callers can never interleave one half-applied policy with another.
func (s *styxPolicySyncer) Sync(ctx context.Context) StyxSyncStatus {
	if s == nil {
		return StyxSyncStatus{State: StyxSyncStateUnavailable, Capability: styxCapabilityUnknown}
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	if err := ctx.Err(); err != nil {
		return s.Snapshot()
	}
	s.mu.Lock()
	desired := cloneStyxFabricSettings(s.desired)
	previousState := s.status.State
	s.mu.Unlock()

	// M3.2: re-resolve every path-backed identity before the plan is built. The
	// persisted numeric id is deliberately NOT used for path entries: a stale id
	// must never be written to the kernel after a reboot or unit restart.
	//
	// An inactive namespace (enabled=false or global mode=off) performs no
	// resolution at all: nothing is enforced, so claiming a "degraded identity"
	// there would be noise. A draft stays exactly as honest as before.
	resolved := cloneStyxFabricSettings(desired)
	var identity styxIdentityReport
	if styxNamespaceActive(desired) {
		s.mu.Lock()
		previousPaths := make(map[string]uint64, len(s.resolvedPaths))
		for cgroupPath, cgroupID := range s.resolvedPaths {
			previousPaths[cgroupPath] = cgroupID
		}
		s.mu.Unlock()
		resolved, identity = resolveStyxIdentities(desired, s.resolver, previousPaths)
		// Identity facts (drift/unresolved) are reported before the kernel push:
		// they were measured against the live host, so they are true even if the
		// push fails. The reconciler also emits the bounded operator events.
		s.reconcileIdentity(identity)
	} else {
		s.clearIdentityStatus()
	}

	plan, err := buildStyxPolicyPlan(resolved)
	if err != nil {
		// Defensive: the settings store validates before persisting, so this only
		// happens for a document edited out-of-band. It must never reach the map.
		return s.finishFailure(fmt.Errorf("styX policy is invalid: %w", err))
	}

	if s.core == nil {
		return s.finishCapabilityMissing("no privileged core client is attached")
	}
	version, err := s.core.StyxVersion()
	if err != nil {
		if errors.Is(err, ErrStyxUnavailable) {
			return s.finishCapabilityMissing("")
		}
		return s.finishFailure(fmt.Errorf("styX capability probe failed: %w", err))
	}
	s.recordCapability(version)
	epoch, err := s.core.StyxEpoch()
	if err != nil {
		if errors.Is(err, ErrStyxUnavailable) {
			return s.finishCapabilityMissing("")
		}
		return s.finishFailure(fmt.Errorf("styX epoch probe failed: %w", err))
	}

	s.mu.Lock()
	epochChanged := s.applied.Initialized && s.appliedEpoch != "" && s.appliedEpoch != epoch
	if epochChanged {
		// The core restarted: its maps are empty and every policy must be pushed
		// again (§5 resync contract). Forget what this control plane believed was
		// applied; nothing may be claimed until the push succeeded.
		s.applied = styxAppliedPolicy{}
		s.fingerprint = ""
	}
	applied := s.applied
	samePlan := s.fingerprint != "" && s.fingerprint == plan.fingerprint()
	s.mu.Unlock()

	// Steady state: the epoch poll found an unchanged core and an unchanged plan.
	// Re-writing 1000+ map entries every 10 s would be pure churn. The degraded
	// identity state is refreshed here too, so a persistent path failure keeps
	// being reported and a recovery is named without a kernel write.
	if (previousState == StyxSyncStateApplied || previousState == StyxSyncStateDegraded) &&
		samePlan && !epochChanged && applied.Initialized {
		return s.finishUnchanged(epoch, version, identity)
	}
	if err := s.applyPlan(ctx, plan, epoch, applied, !applied.Initialized || epochChanged); err != nil {
		return s.finishFailure(err)
	}
	s.mu.Lock()
	s.applied = styxAppliedPolicy{
		Initialized: true, Enabled: plan.Enabled, Mode: plan.Mode, GlobalFlags: plan.GlobalFlags,
		Cells: make(map[uint64]styxCellPlan, len(plan.Cells)),
		Allow: plan.Allow, Resolvers: plan.Resolvers,
	}
	for _, cell := range plan.Cells {
		s.applied.Cells[cell.cgroupID()] = cell
	}
	s.mu.Unlock()
	return s.finishApplied(plan, epoch, version, previousState, identity)
}

// applyPlan is the ordered, fail-safe projection of one plan (§8.3):
// global off (fail-safe) -> global configured -> per-cell -> allowlist -> resolvers.
func (s *styxPolicySyncer) applyPlan(ctx context.Context, plan styxPolicyPlan, epoch string, applied styxAppliedPolicy, resync bool) error {
	fullResync := resync

	// Step 1: fail-safe global off. It runs on every full re-sync, so an operator
	// value change or core restart can never leave an old `enforce` in force while
	// the new policy is being installed.
	if fullResync || applied.Enabled {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.core.StyxGlobal(0, 0); err != nil {
			return fmt.Errorf("fail-safe styX global off: %w", err)
		}
	}

	if !plan.Enabled {
		// Step 2 (disable path): off is in force; now remove every entry we installed.
		// Deletion is idempotent on the core (§5), so a partially failed previous sync
		// can simply be retried.
		for _, cgroupID := range sortedStyxCellIDs(applied.Cells) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := s.core.StyxModeDel(cgroupID); err != nil {
				return fmt.Errorf("delete styX cell %d: %w", cgroupID, err)
			}
		}
		for _, allow := range applied.Allow {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := s.core.StyxAllowDel(allow.Family, "cell", allow.CgroupID, allow.CIDR, allow.PortLo, allow.PortHi, allow.ProtoMask); err != nil {
				return fmt.Errorf("delete styX allow rule for cgroup %d: %w", allow.CgroupID, err)
			}
		}
		for _, resolver := range applied.Resolvers {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := s.core.StyxResolverDel(resolver.Family, resolver.CIDR); err != nil {
				return fmt.Errorf("delete styX resolver %s: %w", resolver.CIDR, err)
			}
		}
		return nil
	}

	// Step 2: per-cell modes and flags, then removal of entries no longer desired.
	desiredCells := make(map[uint64]styxCellPlan, len(plan.Cells))
	for _, cell := range plan.Cells {
		desiredCells[cell.CgroupID] = cell
	}
	for _, cell := range plan.Cells {
		if !fullResync {
			if previous, exists := applied.Cells[cell.CgroupID]; exists && previous.equalKernel(cell) {
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.core.StyxModeSet(cell.CgroupID, cell.Mode, cell.Flags); err != nil {
			return fmt.Errorf("apply styX cell %d: %w", cell.CgroupID, err)
		}
	}
	for _, cgroupID := range sortedStyxCellIDs(applied.Cells) {
		if _, keep := desiredCells[cgroupID]; keep {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.core.StyxModeDel(cgroupID); err != nil {
			return fmt.Errorf("delete stale styX cell %d: %w", cgroupID, err)
		}
	}

	// Step 4: allowlist. Additions precede deletions so a rule that is replaced can
	// never have a window without any rule.
	for _, allow := range plan.Allow {
		if !fullResync && containsStyxAllowPlan(applied.Allow, allow) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.core.StyxAllowAdd(allow.Family, "cell", allow.CgroupID, allow.CIDR, allow.PortLo, allow.PortHi, allow.ProtoMask); err != nil {
			return fmt.Errorf("add styX allow rule for cgroup %d: %w", allow.CgroupID, err)
		}
	}
	for _, allow := range applied.Allow {
		if containsStyxAllowPlan(plan.Allow, allow) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.core.StyxAllowDel(allow.Family, "cell", allow.CgroupID, allow.CIDR, allow.PortLo, allow.PortHi, allow.ProtoMask); err != nil {
			return fmt.Errorf("delete stale styX allow rule for cgroup %d: %w", allow.CgroupID, err)
		}
	}

	// Step 5: DNS/DoT resolver prefixes (global, the core keeps the mandatory veto
	// seed itself - §4).
	for _, resolver := range plan.Resolvers {
		if !fullResync && containsStyxResolverPlan(applied.Resolvers, resolver) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.core.StyxResolverAdd(resolver.Family, resolver.CIDR); err != nil {
			return fmt.Errorf("add styX resolver %s: %w", resolver.CIDR, err)
		}
	}
	for _, resolver := range applied.Resolvers {
		if containsStyxResolverPlan(plan.Resolvers, resolver) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.core.StyxResolverDel(resolver.Family, resolver.CIDR); err != nil {
			return fmt.Errorf("delete stale styX resolver %s: %w", resolver.CIDR, err)
		}
	}
	// Step 6: enable global StyX mode ONLY after per-cell policies, allowlists,
	// and DNS/DoT resolvers are synchronized so kernel traffic never encounters an
	// enabled global policy over empty tables (LIN-H06).
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.core.StyxGlobal(plan.Mode, plan.GlobalFlags); err != nil {
		return fmt.Errorf("apply styX global mode %s: %w", styxModeName(plan.Mode), err)
	}
	return nil
}
