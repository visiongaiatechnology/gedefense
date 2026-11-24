// STATUS: DIAMANT VGT SUPREME
// Generation composition and authoritative kernel blocklist apply/clear
package main

import (
	"fmt"
	"sort"
	"time"
)

// composeGenerationsLocked rebuilds the three published generations from the
// current last-known-good state. Sources are visited in priority order, so the
// global entry budget is spent on the most trusted sources first and the same
// input always produces the same generation. The previous implementation
// iterated a map, which made the surviving subset of a capped union
// non-deterministic between syncs.
func (m *FeedManager) composeGenerationsLocked(settings ThreatIntelFabricSettings) (block, correlate, annotate []string) {
	stateByID := make(map[string]*FeedGenerationState, len(m.feedStates))
	ids := make([]string, 0, len(m.feedStates))
	for id, state := range m.feedStates {
		stateByID[id] = state
		ids = append(ids, id)
	}
	rank := make(map[string]int, len(settings.Feeds))
	for index, feed := range settings.Feeds {
		rank[feed.ID] = index
	}
	sort.Slice(ids, func(i, j int) bool {
		ri, iKnown := rank[ids[i]]
		rj, jKnown := rank[ids[j]]
		if iKnown != jKnown {
			return iKnown
		}
		if iKnown && ri != rj {
			return ri < rj
		}
		return ids[i] < ids[j]
	})

	budget := settings.MaxTotalEntries
	blockSet := make(map[string]struct{})
	corrSet := make(map[string]struct{})
	annotSet := make(map[string]struct{})
	for _, id := range ids {
		state := stateByID[id]
		if state == nil {
			continue
		}
		switch state.Action {
		case FeedActionBlock:
			for _, item := range state.LastGoodItems {
				if budget > 0 && len(blockSet) >= budget {
					break
				}
				blockSet[item] = struct{}{}
				corrSet[item] = struct{}{}
			}
		case FeedActionCorrelateOnly:
			for _, item := range state.LastGoodItems {
				if budget > 0 && len(corrSet) >= budget {
					break
				}
				corrSet[item] = struct{}{}
			}
		case FeedActionAnnotateOnly:
			for _, item := range state.LastGoodItems {
				if budget > 0 && len(annotSet) >= budget {
					break
				}
				annotSet[item] = struct{}{}
			}
		}
	}

	block = make([]string, 0, len(blockSet))
	for item := range blockSet {
		block = append(block, item)
	}
	correlate = make([]string, 0, len(corrSet))
	for item := range corrSet {
		correlate = append(correlate, item)
	}
	annotate = make([]string, 0, len(annotSet))
	for item := range annotSet {
		annotate = append(annotate, item)
	}
	sort.Strings(block)
	sort.Strings(correlate)
	sort.Strings(annotate)
	return block, correlate, annotate
}

// Invariant 5: Kernel diff updates must apply additions before deletions and must never
// publish a new userspace generation until the corresponding kernel update succeeded.
// Rollback on a failed diff is a hard safety invariant and is deliberately not
// administrable.
func (m *FeedManager) ApplyToKernel(core *CoreClient, allowlist []string) (int, int, error) {
	if m.localSigningEnabled() {
		// Load the operator key before taking the manager write lock: the loader
		// performs filesystem I/O, and a sticky load failure must be reported by
		// the local signing gate below instead of silently applying nothing.
		policy := m.localSigningPolicy()
		if policy.keyFile != "" {
			_ = m.ensureLocalSigningKey(policy.keyFile)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	settings := m.live.activeSettings()

	// Local signing is a second, independent kernel-apply gate. A manifest that
	// verifies against a pinned key the local operator cannot produce is not a
	// usable deployment: apply refuses instead of enforcing foreign content.
	if err := m.localSigningApplyGate(); err != nil {
		m.kernelApplyLastAt = time.Now().UTC()
		m.kernelApplyStatus = kernelApplyError
		m.lastKernelError = err.Error()
		_ = m.savePersistentStateLocked()
		return 0, 0, NewThreatIntelSecurityException("local feed signing trust anchor refused kernel apply", err)
	}

	// F-03 / CHAIN-009: a kernel diff may only be computed from generations that
	// carry a verified, unexpired signed manifest. The gate runs before any
	// addition or deletion; a failure retains the previous kernel enforcement
	// instead of releasing it.
	if m.cfg.RequireSignedManifest {
		if err := m.verifySignedKernelGenerationsLocked(settings); err != nil {
			m.kernelApplyLastAt = time.Now().UTC()
			m.kernelApplyStatus = kernelApplyError
			m.lastKernelError = err.Error()
			_ = m.savePersistentStateLocked()
			return 0, 0, err
		}
	}

	// Gather target BLOCK items through the deterministic, priority-ordered
	// composition so the published kernel set does not depend on map iteration
	// order.
	blockItems, _, _ := m.composeGenerationsLocked(settings)
	candidateSet := make(map[string]struct{}, len(blockItems))
	for _, item := range blockItems {
		candidateSet[item] = struct{}{}
	}

	// 1. Calculate Additions & Deletions
	toAdd := make([]string, 0)
	toDel := make([]string, 0)

	for _, it := range blockItems {
		if _, exists := m.appliedKernelEntries[it]; !exists {
			toAdd = append(toAdd, it)
		}
	}

	for it := range m.appliedKernelEntries {
		if _, exists := candidateSet[it]; !exists {
			toDel = append(toDel, it)
		}
	}

	sort.Strings(toAdd)
	sort.Strings(toDel)

	// Guard rail: a diff larger than the administrable budget is refused as a
	// whole. A partially applied kernel generation would be worse than none.
	if budget := settings.Kernel.MaximumDiffPerSync; budget > 0 && len(toAdd)+len(toDel) > budget {
		err := NewThreatIntelKernelSyncException(
			fmt.Sprintf("kernel diff of %d entries exceeds the configured budget of %d per sync", len(toAdd)+len(toDel), budget), nil)
		m.kernelApplyLastAt = time.Now().UTC()
		m.kernelApplyStatus = kernelApplyError
		m.lastKernelError = err.Error()
		_ = m.savePersistentStateLocked()
		return 0, 0, err
	}

	previousApplied := make(map[string]struct{}, len(m.appliedKernelEntries))
	for item := range m.appliedKernelEntries {
		previousApplied[item] = struct{}{}
	}

	// 2. Apply ADDITIONS FIRST
	addedItems := make([]string, 0, len(toAdd))
	if core != nil {
		for _, item := range toAdd {
			if err := core.Add(item); err != nil {
				// Addition failed: rollback newly added items immediately and abort publication
				rollbackFailed := false
				for _, rollbackItem := range addedItems {
					if rollbackErr := core.Delete(rollbackItem); rollbackErr != nil {
						rollbackFailed = true
					}
				}
				m.kernelApplyLastAt = time.Now().UTC()
				m.kernelApplyStatus = kernelApplyError
				m.lastKernelError = err.Error()
				if rollbackFailed {
					m.kernelApplyStatus = kernelApplyDivergent
					m.lastKernelError = fmt.Sprintf("%v; addition rollback incomplete", err)
				}
				_ = m.savePersistentStateLocked()
				return 0, 0, NewThreatIntelKernelSyncException(
					fmt.Sprintf("kernel block addition failed for %s; rolled back: %v", item, err),
					err,
				)
			}
			addedItems = append(addedItems, item)
		}
	} else {
		addedItems = append(addedItems, toAdd...)
	}

	// 3. Apply DELETIONS SECOND. Do not mutate the published in-memory kernel
	// mirror until every deletion succeeds. If one deletion fails, restore the
	// previous generation as far as possible and mark any incomplete rollback as
	// DIVERGENT instead of lying with a successful apply state.
	deletedItems := make([]string, 0, len(toDel))
	if core != nil {
		for _, item := range toDel {
			if err := core.Delete(item); err != nil {
				rollbackFailed := false
				for _, deletedItem := range deletedItems {
					if rollbackErr := core.Add(deletedItem); rollbackErr != nil {
						rollbackFailed = true
					}
				}
				for _, addedItem := range addedItems {
					if rollbackErr := core.Delete(addedItem); rollbackErr != nil {
						rollbackFailed = true
					}
				}
				m.appliedKernelEntries = previousApplied
				m.kernelApplyLastAt = time.Now().UTC()
				m.kernelApplyStatus = kernelApplyError
				m.lastKernelError = err.Error()
				if rollbackFailed {
					m.kernelApplyStatus = kernelApplyDivergent
					m.lastKernelError = fmt.Sprintf("%v; deletion rollback incomplete", err)
				}
				_ = m.savePersistentStateLocked()
				return 0, 0, NewThreatIntelKernelSyncException(
					fmt.Sprintf("kernel block deletion failed for %s; previous generation restored where possible: %v", item, err),
					err,
				)
			}
			deletedItems = append(deletedItems, item)
		}
	} else {
		deletedItems = append(deletedItems, toDel...)
	}

	// 4. Commit the kernel mirror only after the whole diff succeeded.
	m.appliedKernelEntries = make(map[string]struct{}, len(candidateSet))
	for item := range candidateSet {
		m.appliedKernelEntries[item] = struct{}{}
	}

	// 5. ONLY upon full kernel success: Publish new userspace generation & fingerprint
	activeBlockList := make([]string, 0, len(candidateSet))
	for it := range candidateSet {
		activeBlockList = append(activeBlockList, it)
	}

	activeCorrList, activeAnnotList := func() ([]string, []string) {
		_, correlate, annotate := m.composeGenerationsLocked(settings)
		return correlate, annotate
	}()

	m.blockIndex.Replace(activeBlockList)
	m.correlateIndex.Replace(activeCorrList)
	m.annotateIndex.Replace(activeAnnotList)
	m.generation++
	m.fingerprint = computeFingerprint(activeBlockList)
	m.kernelApplyLastAt = time.Now().UTC()
	m.kernelApplyStatus = kernelApplyApplied
	m.kernelGeneration = m.generation
	m.lastKernelAdded = len(addedItems)
	m.lastKernelDeleted = len(deletedItems)
	m.lastKernelError = ""
	_ = m.savePersistentStateLocked()

	return len(addedItems), len(deletedItems), nil
}

func (m *FeedManager) ClearFromKernel(core *CoreClient) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cleared := 0
	if core != nil {
		for item := range m.appliedKernelEntries {
			if err := core.Delete(item); err == nil {
				cleared++
			}
		}
	}
	m.appliedKernelEntries = make(map[string]struct{})
	m.blockIndex.Replace(nil)
	m.correlateIndex.Replace(nil)
	m.annotateIndex.Replace(nil)
	m.generation++
	m.fingerprint = computeFingerprint(nil)
	m.kernelApplyLastAt = time.Now().UTC()
	m.kernelApplyStatus = kernelApplyNotApplied
	m.kernelGeneration = m.generation
	m.lastKernelAdded = 0
	m.lastKernelDeleted = cleared
	m.lastKernelError = ""
	_ = m.savePersistentStateLocked()
	return cleared, nil
}
