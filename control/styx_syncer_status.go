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

func containsStyxAllowPlan(list []styxAllowPlan, want styxAllowPlan) bool {
	for _, candidate := range list {
		if candidate == want {
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

func (s *styxPolicySyncer) recordCapability(version string) {
	s.mu.Lock()
	s.status.Version = version
	s.status.Capability = version
	if s.status.State == StyxSyncStateCapabilityMissing {
		s.status.State = StyxSyncStatePending
	}
	s.mu.Unlock()
}

func (s *styxPolicySyncer) finishApplied(plan styxPolicyPlan, epoch, version string, previousState string) StyxSyncStatus {
	now := s.now().UTC()
	appliedAt := now
	fingerprint := plan.fingerprint()
	s.mu.Lock()
	previousFingerprint := s.fingerprint
	changed := previousState != StyxSyncStateApplied || previousFingerprint != fingerprint
	s.status = StyxSyncStatus{
		State: StyxSyncStateApplied, Capability: version, Version: version, Epoch: epoch,
		Enabled: plan.Enabled, Mode: styxModeName(plan.Mode), LogFlows: plan.LogFlows,
		Cells: len(plan.Cells), AllowRules: len(plan.Allow), Resolvers: len(plan.Resolvers),
		LastAttemptAt: &appliedAt, LastAppliedAt: &appliedAt,
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
		message := fmt.Sprintf("StyX kernel egress policy applied: mode=%s flow_telemetry=%t cells=%d allow_rules=%d dns_resolvers=%d epoch=%s",
			status.Mode, status.LogFlows, status.Cells, status.AllowRules, status.Resolvers, epoch)
		if !plan.Enabled {
			message = "StyX kernel egress policy applied: disabled; global mode is off and no per-cell enforcement remains"
		}
		if s.state != nil {
			s.state.AddEvent(Event{Severity: "info", Kind: "styx.policy_applied", Source: "styx", Message: message})
		}
	}
	return status
}

// finishUnchanged refreshes the epoch/capability bookkeeping of a steady-state
// poll without emitting an event: nothing was applied because nothing changed.
func (s *styxPolicySyncer) finishUnchanged(epoch, version string) StyxSyncStatus {
	now := s.now().UTC()
	s.mu.Lock()
	s.status.State = StyxSyncStateApplied
	s.status.Capability = version
	s.status.Version = version
	s.status.Epoch = epoch
	s.status.LastAttemptAt = &now
	s.lastFailure = ""
	s.dirty = false
	s.nextAttempt = now.Add(s.retryInterval)
	status := s.status
	s.mu.Unlock()
	return status
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
