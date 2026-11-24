package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"time"
)

// maintainPermitStore expires bounded TTLs, applies auto-invalidation and
// persists the result. A failed write keeps the in-memory view consistent with
// the last durable store and reports the failure instead of claiming success.
func (b *PermitBroker) maintainPermitStore(now time.Time, invalidateKinds []string) (expired int, changed bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded || b.corrupt {
		return 0, false, nil
	}
	kinds := make(map[string]struct{}, len(invalidateKinds))
	for _, kind := range invalidateKinds {
		kinds[kind] = struct{}{}
	}
	var next map[string]*PermitV1
	for id, permit := range b.permits {
		remove := false
		if !now.Before(permit.ValidUntil) {
			expired++
			remove = true
		}
		if !remove {
			for _, kind := range permit.AutoInvalidateOn {
				if _, invalidate := kinds[kind]; invalidate {
					remove = true
					break
				}
			}
		}
		if remove {
			if next == nil {
				next = make(map[string]*PermitV1, len(b.permits))
				for keepID, keep := range b.permits {
					next[keepID] = keep
				}
			}
			delete(next, id)
		}
	}
	if next == nil {
		return expired, false, nil
	}
	if err := b.persistPermitStoreLocked(next); err != nil {
		return expired, false, err
	}
	b.permits = next
	return expired, true, nil
}

// invalidateBinaryChanges re-verifies every permit that requested
// auto_invalidate_on=binary_changed against the current executable bytes and
// inode. A changed, missing or unreadable executable invalidates the permit.
func (b *PermitBroker) invalidateBinaryChanges(now time.Time) (invalidated int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded || b.corrupt {
		return 0, nil
	}
	var next map[string]*PermitV1
	for id, permit := range b.permits {
		if !containsPermitKind(permit.AutoInvalidateOn, "binary_changed") {
			continue
		}
		if permitBinaryMatches(permit, now) {
			continue
		}
		if next == nil {
			next = make(map[string]*PermitV1, len(b.permits))
			for keepID, keep := range b.permits {
				next[keepID] = keep
			}
		}
		delete(next, id)
		invalidated++
	}
	if next == nil {
		return 0, nil
	}
	if err := b.persistPermitStoreLocked(next); err != nil {
		return 0, err
	}
	b.permits = next
	return invalidated, nil
}

func containsPermitKind(kinds []string, want string) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}

// permitBinaryMatches re-stats and re-hashes the pinned executable. It reports
// false (invalidate) on any uncertainty: a permit must never stay active on an
// executable identity that can no longer be proven.
func permitBinaryMatches(permit *PermitV1, now time.Time) bool {
	if permit == nil || permit.Path == "" {
		return false
	}
	identity, err := statExecutableIdentity(permit.Path, now)
	if err != nil {
		return false
	}
	if identity.SHA256 != permit.SHA256 {
		return false
	}
	if identity.Device != permit.Inode.Device || identity.Inode != permit.Inode.Inode {
		return false
	}
	return true
}

// UpsertPermit validates, signs when a key is bound, persists and activates one
// permit. It refuses to write while the store is corrupt so forensic evidence
// is never overwritten by a fresh empty document.
func (b *PermitBroker) UpsertPermit(permit *PermitV1) error {
	if b == nil || permit == nil {
		return errors.New("permit object is missing")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded || b.corrupt {
		return errors.New("permit store is unavailable or corrupt")
	}
	if permit.Signature == "" {
		if len(b.signKey) == ed25519.PrivateKeySize {
			if err := SignPermitObject(permit, b.signKey); err != nil {
				return err
			}
		} else {
			permit.Signature = permitSignatureAbsent
			permit.Signer = ""
			if permit.TrustLevel != permitTrustAnalyst {
				permit.TrustLevel = permitTrustAnalyst
				b.notePermitDropLocked("unsigned_demoted_to_analyst")
			}
		}
	}
	if err := validatePermitV1(permit, b.now()); err != nil {
		return err
	}
	if permit.Signature != permitSignatureAbsent {
		if err := b.admitPermitTrustLocked(permit); err != nil {
			return err
		}
	}
	next := make(map[string]*PermitV1, len(b.permits)+1)
	for id, existing := range b.permits {
		next[id] = existing
	}
	if _, exists := next[permit.PermitID]; !exists && len(next) >= permitMaxStorePermits {
		return errors.New("permit store entry capacity reached")
	}
	next[permit.PermitID] = permit
	if err := b.persistPermitStoreLocked(next); err != nil {
		return err
	}
	b.permits = next
	return nil
}

// RemovePermit deletes one permit and persists the change.
func (b *PermitBroker) RemovePermit(permitID string) error {
	if b == nil || !validPermitID(permitID) {
		return errors.New("permit identifier is invalid")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded || b.corrupt {
		return errors.New("permit store is unavailable or corrupt")
	}
	if _, exists := b.permits[permitID]; !exists {
		return os.ErrNotExist
	}
	next := make(map[string]*PermitV1, len(b.permits))
	for id, permit := range b.permits {
		if id == permitID {
			continue
		}
		next[id] = permit
	}
	if err := b.persistPermitStoreLocked(next); err != nil {
		return err
	}
	b.permits = next
	return nil
}

// InvalidatePermits removes every permit whose auto_invalidate_on contains the
// given closed-set kind (baseline_rebaseline, policy_update, rule_update).
func (b *PermitBroker) InvalidatePermits(kind string) (int, error) {
	if _, ok := permitAutoInvalidateKinds[kind]; !ok || kind == "binary_changed" {
		return 0, errors.New("permit invalidation kind is invalid")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded || b.corrupt {
		return 0, errors.New("permit store is unavailable or corrupt")
	}
	var next map[string]*PermitV1
	removed := 0
	for id, permit := range b.permits {
		if !containsPermitKind(permit.AutoInvalidateOn, kind) {
			continue
		}
		if next == nil {
			next = make(map[string]*PermitV1, len(b.permits))
			for keepID, keep := range b.permits {
				next[keepID] = keep
			}
		}
		delete(next, id)
		removed++
	}
	if removed == 0 {
		return 0, nil
	}
	if err := b.persistPermitStoreLocked(next); err != nil {
		return 0, err
	}
	b.permits = next
	return removed, nil
}
