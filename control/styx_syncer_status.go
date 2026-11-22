// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5: StyX sync status transitions, operator events and the plan
// predicates the syncer uses. No enforcement claim is ever derived here.

import (
	"fmt"
	"log"
	"sort"
	"strings"
)

func (cell styxCellPlan) cgroupID() uint64 { return cell.CgroupID }

func sortedStyxCellIDs(cells map[uint64]styxCellPlan) []uint64 {
	ids := make([]uint64, 0, len(cells))
	for cgroupID := range cells {
		ids = append(ids, cgroupID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// containsStyxAllowPlan compares the kernel map key/value only; the bookkeeping
// cgroup path must never turn an unchanged rule into add+delete churn.
func containsStyxAllowPlan(list []styxAllowPlan, want styxAllowPlan) bool {
	for _, candidate := range list {
		if candidate.equalKernel(want) {
			return true
		}
	}
	return false
}

func containsStyxResolverPlan(list []styxResolverPlan, want styxResolverPlan) bool {
	for _, candidate := range list {
		if candidate == want {
			return true
		}
	}
	return false
}

// styxNamespaceActive reports whether the namespace actually asks the kernel for
// an active policy. A disabled namespace or global mode=off performs no identity
// resolution: there is nothing to enforce, so there is nothing to degrade.
func styxNamespaceActive(in StyxFabricSettings) bool {
	if !in.Enabled {
		return false
	}
	mode, err := styxModeValue(in.Mode)
	if err != nil {
		return true // an invalid mode is reported by the plan builder, not guessed here
	}
	return mode != 0
}

// clearIdentityStatus resets the identity projection of an inactive namespace. It
// deliberately does not emit a "recovered" event: nothing changed on the host.
func (s *styxPolicySyncer) clearIdentityStatus() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identityDegraded = false
	s.resolvedPaths = nil
	s.lastIdentityReport = styxIdentityReport{}
	s.status.PathsResolved = 0
	s.status.PathsUnresolved = 0
	s.status.LegacyIDs = 0
	s.status.Degraded = false
	s.status.DegradedReason = ""
	s.status.Identities = nil
}

func (s *styxPolicySyncer) recordCapability(version string) {
	s.mu.Lock()
	s.status.Version = version
	s.status.Capability = version
	if s.status.State == StyxSyncStateCapabilityMissing {
		s.status.State = StyxSyncStatePending
	}
	s.mu.Unlock()
}

func (s *styxPolicySyncer) finishApplied(plan styxPolicyPlan, epoch, version string, previousState string, identity styxIdentityReport) StyxSyncStatus {
	now := s.now().UTC()
	appliedAt := now
	fingerprint := plan.fingerprint()
	state := StyxSyncStateApplied
	if identity.degraded() {
		state = StyxSyncStateDegraded
	}
	s.mu.Lock()
	previousFingerprint := s.fingerprint
	changed := previousState != StyxSyncStateApplied || previousFingerprint != fingerprint
	if identity.degraded() && previousState == StyxSyncStateDegraded {
		// Still degraded: the state did not change, so no repeated failure noise.
		changed = previousFingerprint != fingerprint
	}
	s.status = StyxSyncStatus{
		State: state, Capability: version, Version: version, Epoch: epoch,
		Enabled: plan.Enabled, Mode: styxModeName(plan.Mode), LogFlows: plan.LogFlows,
		Cells: len(plan.Cells), AllowRules: len(plan.Allow), Resolvers: len(plan.Resolvers),
		LastAttemptAt: &appliedAt, LastAppliedAt: &appliedAt,
	}
	s.writeIdentityStatusLocked(identity)
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
		message := fmt.Sprintf("StyX kernel egress policy applied: mode=%s flow_telemetry=%t cells=%d allow_rules=%d dns_resolvers=%d epoch=%s",
			status.Mode, status.LogFlows, status.Cells, status.AllowRules, status.Resolvers, epoch)
		if !plan.Enabled {
			message = "StyX kernel egress policy applied: disabled; global mode is off and no per-cell enforcement remains"
		} else if identity.degraded() {
			message = fmt.Sprintf("StyX kernel egress policy partially applied: mode=%s cells=%d allow_rules=%d; %d path-backed identity(ies) could not be resolved and were not written to the kernel (degraded): %s",
				status.Mode, status.Cells, status.AllowRules, identity.Unresolved, status.DegradedReason)
		}
		if s.state != nil {
			s.state.AddEvent(Event{Severity: "info", Kind: "styx.policy_applied", Source: "styx", Message: message})
		}
	}
	return status
}

// finishUnchanged refreshes the epoch/capability and identity bookkeeping of a
// steady-state poll without emitting a policy event: nothing was applied because
// nothing changed. The state still flips between applied and degraded when the
// identity layer changes, so a path failure can never hide behind "applied".
func (s *styxPolicySyncer) finishUnchanged(epoch, version string, identity styxIdentityReport) StyxSyncStatus {
	now := s.now().UTC()
	state := StyxSyncStateApplied
	if identity.degraded() {
		state = StyxSyncStateDegraded
	}
	s.mu.Lock()
	s.status.State = state
	s.status.Capability = version
	s.status.Version = version
	s.status.Epoch = epoch
	s.status.LastAttemptAt = &now
	s.writeIdentityStatusLocked(identity)
	s.lastFailure = ""
	s.dirty = false
	s.nextAttempt = now.Add(s.retryInterval)
	status := s.status
	s.mu.Unlock()
	return status
}

// reconcileIdentity records the last known kernel id per durable cgroup path and
// emits bounded operator events for the transitions the operator must not miss:
// a path that became unresolvable (degraded), a path that re-resolved to a new
// id after a reboot/unit restart (drift) and a recovery. It never writes to the
// kernel and never repairs a value silently.
func (s *styxPolicySyncer) reconcileIdentity(identity styxIdentityReport) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	wasDegraded := s.identityDegraded
	if s.resolvedPaths == nil {
		s.resolvedPaths = make(map[string]uint64, len(identity.Paths))
	}
	if s.reportedDrift == nil {
		s.reportedDrift = map[string]struct{}{}
	}
	for cgroupPath, cgroupID := range identity.Paths {
		s.resolvedPaths[cgroupPath] = cgroupID
	}
	// Bound the bookkeeping of a very long uptime; the identity list itself stays
	// capped by the syncer's cell caps, so this is purely defensive.
	if len(s.resolvedPaths) > 4*styxMaxPerCellModes {
		pruned := make(map[string]uint64, len(identity.Paths))
		for cgroupPath, cgroupID := range identity.Paths {
			pruned[cgroupPath] = cgroupID
		}
		s.resolvedPaths = pruned
	}
	s.cgroupDriftTotal += uint64(identity.Drifted)
	if len(s.reportedDrift) > 4*styxMaxPerCellModes {
		s.reportedDrift = map[string]struct{}{}
	}
	driftedPaths := make([]string, 0, identity.Drifted)
	for _, entry := range identity.Entries {
		if entry.State != styxIdentityDrifted {
			continue
		}
		key := fmt.Sprintf("%s|%d", entry.Path, entry.CgroupID)
		if _, reported := s.reportedDrift[key]; reported {
			continue
		}
		s.reportedDrift[key] = struct{}{}
		driftedPaths = append(driftedPaths, fmt.Sprintf("%s -> cgroup_id=%d", entry.Path, entry.CgroupID))
	}
	s.identityDegraded = identity.degraded()
	s.lastIdentityReport = identity
	if s.state == nil {
		return
	}
	if !wasDegraded && identity.degraded() {
		s.state.AddEvent(Event{Severity: "warning", Kind: "styx.cgroup_identity_degraded", Source: "styx",
			Message: "StyX cgroup identity degraded: " + identity.degradationReason() + ". The affected entries are not written to the kernel; no stale cgroup id is used and no enforcement state is claimed for them."})
	} else if wasDegraded && !identity.degraded() {
		s.state.AddEvent(Event{Severity: "info", Kind: "styx.cgroup_identity_recovered", Source: "styx",
			Message: "StyX cgroup identity recovered: every configured cgroup_path resolved against the unified hierarchy again"})
	}
	if len(driftedPaths) > 0 {
		if len(driftedPaths) > 4 {
			driftedPaths = driftedPaths[:4]
		}
		s.state.AddEvent(Event{Severity: "warning", Kind: "styx.cgroup_id_drift", Source: "styx",
			Message: "StyX cgroup id drift detected and handled (path re-resolved, no stale id written): " + strings.Join(driftedPaths, "; ")})
	}
}

// writeIdentityStatusLocked projects the identity report into the status. The
// caller must hold s.mu.
func (s *styxPolicySyncer) writeIdentityStatusLocked(identity styxIdentityReport) {
	s.status.PathsResolved = identity.Resolved
	s.status.PathsUnresolved = identity.Unresolved
	s.status.LegacyIDs = identity.Legacy
	s.status.CgroupDriftTotal = s.cgroupDriftTotal
	s.status.Degraded = identity.degraded()
	s.status.DegradedReason = ""
	s.status.Identities = nil
	if identity.degraded() {
		s.status.DegradedReason = identity.degradationReason()
		s.status.Identities = append([]StyxIdentityState(nil), identity.Entries...)
		return
	}
	if identity.Drifted > 0 || identity.Legacy > 0 {
		s.status.Identities = append([]StyxIdentityState(nil), identity.Entries...)
	}
}

func (s *styxPolicySyncer) finishFailure(err error) StyxSyncStatus {
	now := s.now().UTC()
	text := boundedStyxText(err)
	s.mu.Lock()
	previousState := s.status.State
	previousError := s.status.LastError
	// A disabled namespace that never installed anything produces no policy event on
	// a transient core outage: it is not a failed enforcement attempt, and the core
	// sensors already report the outage. A real apply failure - or any failure after
	// something was enforced - is always named.
	reportEvent := s.desired.Enabled || s.applied.Initialized
	s.status.State = StyxSyncStateFailed
	s.status.LastError = text
	s.status.LastAttemptAt = &now
	s.lastFailure = text
	s.nextAttempt = now.Add(s.retryInterval)
	status := s.status
	s.mu.Unlock()

	// The failure is reported once per condition, not once per retry: the retry
	// backoff stays visible in the status while the event stream stays readable.
	if reportEvent && (previousState != StyxSyncStateFailed || previousError != text) {
		log.Printf("styX policy sync failed (no enforcement state is claimed): %s", text)
		if s.state != nil {
			s.state.AddEvent(Event{
				Severity: "high", Kind: "styx.policy_sync_failed", Source: "styx",
				Message: "StyX kernel egress policy could not be applied; the kernel may still hold a previous policy and no enforcement state is being claimed: " + text,
			})
		}
	}
	return status
}

// finishCapabilityMissing is the backwards-compatible path for a pre-StyX core:
// the sensor is unavailable, no failure event is raised and XDR is not degraded.
func (s *styxPolicySyncer) finishCapabilityMissing(reason string) StyxSyncStatus {
	now := s.now().UTC()
	s.mu.Lock()
	previousState := s.status.State
	desired := s.desired
	s.status.State = StyxSyncStateCapabilityMissing
	s.status.Capability = styxCapabilityMissing
	s.status.Version = ""
	s.status.Epoch = ""
	s.status.Enabled = desired.Enabled
	s.status.Mode = desired.Mode
	s.status.LogFlows = styxEffectiveLogFlows(desired)
	s.status.Cells = 0
	s.status.AllowRules = 0
	s.status.Resolvers = 0
	s.status.LastError = ""
	s.status.LastAttemptAt = &now
	s.nextAttempt = now.Add(s.retryInterval)
	// The kernel maps belong to a core that cannot be talked to; nothing known about
	// them survives, so the next successful probe must perform a full re-sync.
	s.applied = styxAppliedPolicy{}
	s.fingerprint = ""
	status := s.status
	s.mu.Unlock()

	if previousState != StyxSyncStateCapabilityMissing {
		message := "The privileged core does not advertise the StyX command family; kernel egress enforcement and flow telemetry stay unavailable until it is upgraded. This is a capability fact, not an XDR degradation."
		if reason != "" {
			message = reason + ". " + message
		}
		log.Printf("styX capability missing: %s", message)
		if s.state != nil {
			s.state.AddEvent(Event{Severity: "info", Kind: "styx.capability_missing", Source: "styx", Message: message})
		}
	}
	return status
}

func boundedStyxText(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(strings.Join(strings.Fields(err.Error()), " "))
	if len(text) > styxStatusErrorMaxBytes {
		text = text[:styxStatusErrorMaxBytes]
	}
	return text
}
