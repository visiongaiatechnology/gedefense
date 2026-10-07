package main

import (
	"errors"
	"fmt"
	"time"
)

// networkBlockCore is the narrow kernel-policy surface required by the expiry
// transaction. Keeping it small makes the transaction independently testable
// without weakening the privileged CoreClient boundary.
type networkBlockCore interface {
	Add(target string) error
	Delete(target string) error
}

// reconcileExpiredNetworkBlocks is the single owner of temporary network-block
// expiry. State.Expired() removes candidates optimistically; this function then
// reconciles kernel state and durable signed policy as one transaction.
//
// A removal is considered committed only after:
//  1. the kernel rule has been removed (when the entry is enforced), and
//  2. the updated policy generation has been durably persisted.
//
// If either step fails, the prior state is restored. A failed rollback triggers
// the release fail-safe because userspace, signed policy and kernel state can no
// longer be proven equivalent.
func reconcileExpiredNetworkBlocks(
	now time.Time,
	state *State,
	core networkBlockCore,
	policy policyPersistence,
	cfg Config,
	release *ReleaseController,
) ([]BlockEntry, error) {
	if state == nil {
		return nil, errors.New("network block expiry requires state")
	}

	candidates := state.Expired(now)
	if len(candidates) == 0 {
		return nil, nil
	}

	removed := make([]BlockEntry, 0, len(candidates))
	var deferredErrs []error

	for _, block := range candidates {
		if block.Enforced {
			if core == nil {
				state.RestoreBlock(block)
				err := fmt.Errorf("cannot remove enforced block %s: kernel core unavailable", block.Target)
				deferredErrs = append(deferredErrs, err)
				state.AddEvent(Event{
					Severity: "warning", Kind: "block.expiry_deferred", Source: "policy",
					Message: "Kernel core unavailable for expired rule removal; signed policy retained the rule",
					Target:  block.Target,
				})
				continue
			}
			if err := core.Delete(block.Target); err != nil {
				state.RestoreBlock(block)
				deferredErrs = append(deferredErrs, fmt.Errorf("delete expired block %s: %w", block.Target, err))
				state.AddEvent(Event{
					Severity: "warning", Kind: "block.expiry_deferred", Source: "policy",
					Message: "Kernel core rejected expired rule removal; signed policy retained the rule",
					Target:  block.Target,
				})
				continue
			}
		}
		removed = append(removed, block)
	}

	if len(removed) == 0 {
		return nil, errors.Join(deferredErrs...)
	}

	if err := persistPolicy(policy, cfg, state); err != nil {
		var rollbackErrs []error
		for _, block := range removed {
			state.RestoreBlock(block)
			if block.Enforced {
				if core == nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("restore enforced block %s: kernel core unavailable", block.Target))
					continue
				}
				if rollbackErr := core.Add(block.Target); rollbackErr != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("restore enforced block %s: %w", block.Target, rollbackErr))
				}
			}
		}

		rollbackErr := errors.Join(rollbackErrs...)
		if rollbackErr != nil {
			var failSafeErr error
			if release != nil {
				failSafeErr = release.FailSafe("expired block policy rollback failed")
			}
			state.AddEvent(Event{
				Severity: "critical", Kind: "policy.rollback_failed", Source: "policy",
				Message: errors.Join(rollbackErr, failSafeErr).Error(),
			})
		}
		state.AddEvent(Event{
			Severity: "critical", Kind: "policy.persist_failed", Source: "policy",
			Message: "Failed to persist signed policy after expiry; removed rules were restored",
		})
		return nil, errors.Join(fmt.Errorf("persist policy after block expiry: %w", err), rollbackErr)
	}

	kineticExpired := uint64(0)
	var evidenceErrs []error
	for _, block := range removed {
		state.AddEvent(Event{
			Time: now.UTC(), Severity: "info", Kind: "block.expired", Source: "policy",
			Message: "Temporary block expired", Target: block.Target,
		})
		if block.Source != "kinetic" {
			continue
		}
		kineticExpired++
		if err := state.RecordEvidence(EvidenceRecord{
			ID:       randomID(),
			Time:     now.UTC(),
			Severity: "info",
			Kind:     "kinetic_rollback",
			Source:   "kinetic_response_engine",
			Message:  "Kinetic containment expired and was removed from kernel/policy state",
			Target:   block.Target,
		}); err != nil {
			evidenceErrs = append(evidenceErrs, fmt.Errorf("record expiry evidence for %s: %w", block.Target, err))
		}
	}
	if kineticExpired > 0 {
		state.UpdateKineticTelemetry(func(t *KineticTelemetry) {
			t.BansExpiredTotal += kineticExpired
		})
	}

	if evidenceErr := errors.Join(evidenceErrs...); evidenceErr != nil {
		state.AddEvent(Event{
			Severity: "critical", Kind: "kinetic.expiry_evidence_failed", Source: "kinetic_response_engine",
			Message: evidenceErr.Error(),
		})
		if release != nil {
			_ = release.FailSafe("kinetic expiry evidence recording failed")
		}
		return removed, errors.Join(evidenceErr, errors.Join(deferredErrs...))
	}

	return removed, errors.Join(deferredErrs...)
}
