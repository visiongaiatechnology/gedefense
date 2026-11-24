// STATUS: DIAMANT VGT SUPREME
// FeedManager lifecycle accessors, sync loop and per-source fetch pipeline
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

func (m *FeedManager) BlockIndex() *ThreatIndex     { return m.blockIndex }
func (m *FeedManager) CorrelateIndex() *ThreatIndex { return m.correlateIndex }
func (m *FeedManager) AnnotateIndex() *ThreatIndex  { return m.annotateIndex }
func (m *FeedManager) Index() *ThreatIndex          { return m.blockIndex }

func (m *FeedManager) Generation() uint64  { m.mu.RLock(); defer m.mu.RUnlock(); return m.generation }
func (m *FeedManager) Fingerprint() string { m.mu.RLock(); defer m.mu.RUnlock(); return m.fingerprint }
func (m *FeedManager) OverallStatus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.overallStatus != "" {
		return m.overallStatus
	}
	if m.lastAttemptAt.IsZero() {
		return "NEVER_SYNCED"
	}
	return "OK"
}
func (m *FeedManager) LastAttemptAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastAttemptAt
}
func (m *FeedManager) LastSuccessfulSyncAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastSuccessfulSyncAt
}
func (m *FeedManager) LastPartialSuccessfulSyncAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPartialSuccessfulSyncAt
}
func (m *FeedManager) LastFullySuccessfulSyncAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastFullySuccessfulSyncAt
}
func (m *FeedManager) KernelApplyStatus() (string, time.Time, uint64, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := m.kernelApplyStatus
	if status == "" {
		status = kernelApplyNotApplied
	}
	return status, m.kernelApplyLastAt, m.kernelGeneration, m.lastKernelError
}

func (m *FeedManager) LockStatus() (bool, time.Time, string, time.Duration) {
	return m.lock.Status()
}

func (m *FeedManager) SnapshotFeedStates() []FeedGenerationState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	settings := m.live.activeSettings()
	out := make([]FeedGenerationState, 0, len(m.feedStates))
	for _, s := range m.feedStates {
		cloned := *s
		cloned.LastGoodItems = nil // omit raw IP array in telemetry status
		cloned.Status = computeFeedStatus(s, settings)
		out = append(out, cloned)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *FeedManager) Telemetry() ThreatIntelTelemetry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	settings := m.live.activeSettings()
	feeds := make([]FeedGenerationState, 0, len(m.feedStates))
	for _, s := range m.feedStates {
		cloned := *s
		cloned.LastGoodItems = nil
		cloned.Status = computeFeedStatus(s, settings)
		feeds = append(feeds, cloned)
	}
	sort.Slice(feeds, func(i, j int) bool { return feeds[i].ID < feeds[j].ID })

	bCount := m.blockIndex.Count()
	cCount := m.correlateIndex.Count()
	aCount := m.annotateIndex.Count()

	status := m.overallStatus
	if status == "" {
		if m.lastAttemptAt.IsZero() {
			status = "NEVER_SYNCED"
		} else if !m.lastFullySuccessfulSyncAt.IsZero() {
			status = "OK"
		} else {
			status = "PARTIAL"
		}
	}

	kernelStatus := m.kernelApplyStatus
	if kernelStatus == "" {
		kernelStatus = kernelApplyNotApplied
	}

	return ThreatIntelTelemetry{
		OverallStatus:               status,
		LastAttemptAt:               m.lastAttemptAt,
		LastSuccessfulSyncAt:        m.lastSuccessfulSyncAt,
		LastPartialSuccessfulSyncAt: m.lastPartialSuccessfulSyncAt,
		LastFullySuccessfulSyncAt:   m.lastFullySuccessfulSyncAt,
		KernelApplyLastAt:           m.kernelApplyLastAt,
		KernelApplyStatus:           kernelStatus,
		KernelGeneration:            m.kernelGeneration,
		LastKernelAdded:             m.lastKernelAdded,
		LastKernelDeleted:           m.lastKernelDeleted,
		LastKernelError:             m.lastKernelError,
		Generation:                  m.generation,
		Fingerprint:                 m.fingerprint,
		BlockVectors:                bCount,
		CorrelateVectors:            cCount,
		AnnotateVectors:             aCount,
		TotalVectors:                bCount + cCount + aCount,
		Feeds:                       feeds,
		TUF:                         m.tufStatusLocked(),
	}
}

// SyncWithLock acquires the lock with live-owner invariant and executes synchronization.
func (m *FeedManager) SyncWithLock(ctx context.Context, holder string) ([]string, map[string]error, error) {
	locked, remaining := m.lock.TryLock(holder)
	if !locked {
		return nil, nil, NewThreatIntelLockException(
			fmt.Sprintf("vis_threat_intel_sync_lock active: held by %s, retry after %s", holder, remaining.Round(time.Second)),
			nil,
		)
	}
	defer m.lock.Unlock()

	items, errs := m.syncInternal(ctx)
	return items, errs, nil
}

func (m *FeedManager) Sync(ctx context.Context) ([]string, map[string]error) {
	items, errs, _ := m.SyncWithLock(ctx, "legacy_sync")
	return items, errs
}

func (m *FeedManager) syncInternal(ctx context.Context) ([]string, map[string]error) {
	type result struct {
		id    string
		url   string
		items []string
		cert  *threatFeedCertificate
		err   error
	}

	// One sync resolves exactly one configuration snapshot. A revision published
	// while this sync runs is observed by the next sync, never by half of this
	// one.
	snapshot := m.live.current()
	if snapshot == nil {
		return nil, map[string]error{"configuration": errors.New("threat intelligence configuration unavailable")}
	}
	sources := snapshot.orderedSources()
	if len(sources) == 0 {
		return nil, map[string]error{"configuration": errors.New("no threat intelligence source is enabled")}
	}
	concurrency := snapshot.settings.ConcurrentDownloads
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	out := make(chan result, len(sources))
	var wg sync.WaitGroup

	now := time.Now().UTC()
	m.mu.Lock()
	m.lastAttemptAt = now
	m.mu.Unlock()

	// Local operator signing runs before any fetch: it downloads every enabled
	// source under the same transport/size/format rules, persists the exact raw
	// bytes and publishes a manifest that signs them. The fetch loop then reads
	// those bytes instead of the network, so the verified and the parsed bytes
	// are the same bytes. A failure aborts the whole sync before a single feed
	// is promoted (fail closed, previous generation retained).
	if m.localSigningEnabled() {
		if prepErr := m.prepareLocalSignedSnapshots(ctx, snapshot); prepErr != nil {
			m.mu.Lock()
			m.overallStatus = "ERROR"
			for _, source := range snapshot.sources {
				if state := m.feedStates[source.ID]; state != nil {
					state.LastAttemptAt = now
					state.LastError = "local signing: " + prepErr.Error()
					state.ConsecutiveFails++
					state.Status = computeFeedStatus(state, snapshot.settings)
				}
			}
			_ = m.savePersistentStateLocked()
			m.mu.Unlock()
			return nil, map[string]error{"local_signing": prepErr}
		}
	}

	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, certificate, err := m.fetchSource(ctx, src, snapshot)
			out <- result{id: src.ID, url: src.URL, items: items, cert: certificate, err: err}
		}()
	}

	wg.Wait()
	close(out)

	errs := make(map[string]error)

	m.mu.Lock()
	defer m.mu.Unlock()

	successCount := 0
	failCount := 0

	// AP-9/S09: resolve the threshold envelope, its validity window and the
	// anti-rollback epoch against the persisted high-water register once for
	// this sync, before any last-known-good promotion. A gate rejection is
	// fail-closed: every feed keeps serving its previous generation.
	tufGate, tufGuardBlocked := m.tufSyncGateStateLocked(now)

	for r := range out {
		feedState := m.feedStates[r.id]
		if feedState == nil {
			source, known := snapshot.byID[r.id]
			action := FeedActionCorrelateOnly
			name := r.id
			if known {
				action = source.Action
				name = source.Name
			}
			feedState = &FeedGenerationState{ID: r.id, Name: name, Action: action}
			m.feedStates[r.id] = feedState
		}
		feedState.LastAttemptAt = now

		// Invariant 2: Failed, empty, malformed or truncated downloads must NEVER replace
		// the current active generation.
		if r.err != nil {
			failCount++
			errs[r.url] = r.err
			feedState.LastError = r.err.Error()
			feedState.ConsecutiveFails++
			feedState.Status = computeFeedStatus(feedState, snapshot.settings)
			continue
		}
		if len(r.items) == 0 {
			failCount++
			errEmpty := errors.New("empty download rejected: active generation preserved")
			errs[r.url] = errEmpty
			feedState.LastError = errEmpty.Error()
			feedState.ConsecutiveFails++
			feedState.Status = computeFeedStatus(feedState, snapshot.settings)
			continue
		}

		// Signed-manifest gate (F-03 / CHAIN-009): promotion to a new
		// last-known-good generation requires a verified, unexpired manifest and
		// a monotonic version. A missing certificate or a rollback keeps the
		// previous generation and reports the failure.
		if m.cfg.RequireSignedManifest {
			if r.cert == nil {
				failCount++
				errUnsigned := NewThreatIntelSecurityException("feed generation rejected: no verified signed manifest", nil)
				errs[r.url] = errUnsigned
				feedState.LastError = errUnsigned.Error()
				feedState.ConsecutiveFails++
				feedState.Status = computeFeedStatus(feedState, snapshot.settings)
				continue
			}
			if rollbackErr := checkManifestRollback(feedState, r.cert); rollbackErr != nil {
				failCount++
				errs[r.url] = rollbackErr
				feedState.LastError = rollbackErr.Error()
				feedState.ConsecutiveFails++
				feedState.Status = computeFeedStatus(feedState, snapshot.settings)
				continue
			}
		}

		// AP-9/S09: the threshold envelope verdict and the local semantic
		// anti-poisoning guard run after the existing signature/rollback gate and
		// before the last-known-good promotion. The semantic guard is signature
		// independent, so it runs even when the TUF capability is unavailable.
		if guardErr := m.tufScreenFeedPromotionLocked(&tufGate, feedState, r.items); guardErr != nil {
			failCount++
			errs[r.url] = guardErr
			feedState.LastError = guardErr.Error()
			feedState.ConsecutiveFails++
			feedState.Status = computeFeedStatus(feedState, snapshot.settings)
			if tufIsRejection(guardErr) {
				tufGuardBlocked = true
				reason := tufErrorReason(guardErr)
				if reason == "" {
					reason = TUFReasonSchema
				}
				m.recordTUFBlockedLocked(reason, r.id, now)
			}
			continue
		}

		// Valid download: promote to new last-known-good generation
		successCount++
		feedState.LastGoodItems = r.items
		feedState.LastGoodCount = len(r.items)
		digest := computeFingerprint(r.items)
		// Generation policy: a byte-identical re-download refreshes freshness but
		// does not churn the generation when the operator selected "stable".
		if shouldAdvanceGeneration(feedState, digest, snapshot.settings.Validation) {
			feedState.LastGoodGen++
		}
		feedState.LastGoodFingerprint = digest
		feedState.LastGoodAt = now
		feedState.LastError = ""
		feedState.ConsecutiveFails = 0
		feedState.Status = "OK"
		if r.cert != nil {
			feedState.ManifestVersion = r.cert.Version
			feedState.ManifestValidUntil = r.cert.ValidUntil
			feedState.ManifestVerified = true
			feedState.ManifestAuthenticity = "SIGNED"
		} else {
			feedState.ManifestVerified = false
			feedState.ManifestValidUntil = time.Time{}
			feedState.ManifestAuthenticity = "UNVERIFIED"
		}
	}

	// AP-9/S09: advance the anti-rollback epoch and the Last-Known-Good shadow
	// only for a sync that accepted the threshold envelope and promoted every
	// enabled source. On a rejected or partial sync the previous Last-Known-Good
	// keeps being served and the high-water epoch stays untouched. A commit
	// failure rolls the promotions back: an unauthenticated epoch advancement
	// must never be published.
	if tufGate.Active && tufGate.Reject == nil && !tufGuardBlocked && successCount == len(sources) && failCount == 0 {
		if commitErr := m.tufCommitSyncLocked(&tufGate, snapshot.settings, now); commitErr != nil {
			m.restoreLastKnownGoodLocked(tufGate.Restore)
			for _, source := range sources {
				errs[source.URL] = NewThreatIntelSecurityException(
					"TUF high-water register commit failed; feed generation was not activated", commitErr)
			}
			failCount += successCount
			successCount = 0
			m.recordTUFBlockedLocked(TUFReasonStateCorrupt, "", now)
		}
	}

	// Rule 14 / Point 64–67: Correct sync timestamp and status semantics
	if failCount == 0 && successCount == len(sources) {
		m.lastSuccessfulSyncAt = now
		m.lastFullySuccessfulSyncAt = now
		m.overallStatus = "OK"
	} else if successCount > 0 && failCount > 0 {
		m.lastSuccessfulSyncAt = now
		m.lastPartialSuccessfulSyncAt = now
		// Invariant: partial sync does NOT update lastFullySuccessfulSyncAt!
		m.overallStatus = "PARTIAL"
	} else if successCount == 0 {
		// Invariant: total failure updates NEITHER lastSuccessfulSyncAt NOR lastFullySuccessfulSyncAt!
		m.overallStatus = "ERROR"
	}

	// Recompose active generations across all sources in deterministic priority
	// order, then publish the correlation and annotation indices immediately.
	blockUnion, corrUnion, annotUnion := m.composeGenerationsLocked(snapshot.settings)
	m.correlateIndex.Replace(corrUnion)
	m.annotateIndex.Replace(annotUnion)
	_ = m.savePersistentStateLocked()

	return blockUnion, errs
}

// feedTransientError marks a failure that is worth retrying: a network fault or
// a temporary upstream status. Deterministic rejections (validation or security)
// are never retried.
type feedTransientError struct {
	Message string
	Err     error
}

func (e *feedTransientError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *feedTransientError) Unwrap() error { return e.Err }

func newFeedTransientError(message string, err error) *feedTransientError {
	return &feedTransientError{Message: message, Err: err}
}

// threatFeedRetryable reports whether a failed attempt may be repeated.
func threatFeedRetryable(err error) bool {
	if err == nil {
		return false
	}
	var transient *feedTransientError
	return errors.As(err, &transient)
}

// Invariant 8: Feed fetching requires strict connection/read deadlines, bounded response size,
// bounded token/line size and restricted redirects.
func (m *FeedManager) fetchSource(ctx context.Context, src ThreatFeedSource, snapshot *threatIntelSnapshot) ([]string, *threatFeedCertificate, error) {
	if snapshot == nil {
		return nil, nil, NewThreatIntelValidationException("threat intelligence configuration unavailable", nil)
	}
	// Local operator signing mode never touches the network on the fetch path:
	// the bytes were downloaded, snapshotted and signed by the same sync before
	// this call, so the manifest and the parsed bytes are provably the same.
	if m.localSigningEnabled() {
		return m.fetchSourceFromSnapshot(src, snapshot)
	}
	policy := snapshot.settings
	u, err := validateFeedSourceURL(src.URL)
	if err != nil {
		return nil, nil, err
	}
	if !snapshot.hostAllowed(u.Hostname()) {
		return nil, nil, NewThreatIntelSecurityException("feed host is outside the configured allowlist", nil)
	}

	attempts := policy.Retry.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(policy.Retry.BackoffSeconds) * time.Second * time.Duration(1<<uint(minInt(attempt-2, 4)))
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, nil, ctx.Err()
			case <-timer.C:
			}
		}
		items, certificate, fetchErr := m.fetchSourceOnce(ctx, src, snapshot, u)
		if fetchErr == nil {
			return items, certificate, nil
		}
		lastErr = fetchErr
		if !threatFeedRetryable(fetchErr) {
			return nil, nil, fetchErr
		}
	}
	return nil, nil, lastErr
}

// fetchSourceOnce runs the full network fetch path for one source: bounded
// download, signed-manifest verification of the exact raw bytes, parsing and
// indicator-digest verification. In local signing mode the bytes come from the
// snapshot instead of the network; the verification chain is identical.
func (m *FeedManager) fetchSourceOnce(ctx context.Context, src ThreatFeedSource, snapshot *threatIntelSnapshot, u *url.URL) ([]string, *threatFeedCertificate, error) {
	if m.localSigningEnabled() {
		return m.fetchSourceFromSnapshot(src, snapshot)
	}
	raw, contentType, err := m.fetchFeedRawOnce(ctx, src, snapshot, u)
	if err != nil {
		return nil, nil, err
	}
	// AP-9/S09/R5 interim isolation: shadow-parse the exact untrusted bytes
	// before the signed-manifest verifier and the feed parser consume them.
	shadowMaxEntries, shadowMaxBytes, _ := snapshot.feedBounds(src)
	if shadowErr := tufShadowValidateFeedBytes(raw, shadowMaxEntries, shadowMaxBytes); shadowErr != nil {
		return nil, nil, shadowErr
	}
	certificate, verifyErr := m.verifyFeedArtifact(src, raw)
	if verifyErr != nil {
		return nil, nil, verifyErr
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, certificate, nil
	}
	maxEntries, _, _ := snapshot.feedBounds(src)
	items, parseErr := parseFeedRaw(src, raw, contentType, snapshot.settings.Validation, maxEntries)
	if parseErr != nil {
		return nil, nil, parseErr
	}
	if digestErr := m.verifyFeedItemsDigest(certificate, src, items); digestErr != nil {
		return nil, nil, digestErr
	}
	return items, certificate, nil
}

// fetchFeedRawOnce performs one bounded HTTPS download and returns the exact
// bytes together with the response content type. The signed manifest binds the
// returned byte slice; callers must never re-read the body afterwards. A
// deterministic rejection (validation/security) is returned as-is; everything
// that may be transient is wrapped so the retry loop can decide.
func (m *FeedManager) fetchFeedRawOnce(ctx context.Context, src ThreatFeedSource, snapshot *threatIntelSnapshot, u *url.URL) ([]byte, string, error) {
	maxEntries, maxBytes, timeoutSeconds := snapshot.feedBounds(src)
	_ = maxEntries

	feedCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	feedCtx = context.WithValue(feedCtx, feedPolicyContextKey{}, snapshot)

	req, err := http.NewRequestWithContext(feedCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "VGT-GeDefense/6.2.0 sovereign-threat-intel")
	req.Header.Set("Accept", "text/plain, application/json, */*")

	resp, err := m.client.Do(req)
	if err != nil {
		var validation *ThreatIntelValidationException
		var security *ThreatIntelSecurityException
		if errors.As(err, &validation) || errors.As(err, &security) {
			return nil, "", err
		}
		return nil, "", newFeedTransientError("feed request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, "", newFeedTransientError(fmt.Sprintf("HTTP %d", resp.StatusCode), nil)
		}
		return nil, "", NewThreatIntelValidationException(fmt.Sprintf("feed returned HTTP %d", resp.StatusCode), nil)
	}
	if !snapshot.contentAllowed(resp.Header.Get("Content-Type")) {
		return nil, "", NewThreatIntelSecurityException("feed content type is outside the configured policy", nil)
	}

	// Read the bounded raw body once. The signed manifest binds these exact
	// bytes; parsing the same byte slice removes a re-read/TOCTOU window between
	// verification and parsing.
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if readErr != nil {
		return nil, "", newFeedTransientError("feed read failed", readErr)
	}
	if int64(len(raw)) > maxBytes {
		return nil, "", NewThreatIntelSecurityException("feed exceeds bounded size limit", nil)
	}
	return raw, resp.Header.Get("Content-Type"), nil
}

// downloadFeedRaw is the raw-byte downloader used by the local signing
// pipeline. It shares the transport policy, retry classification and byte
// bounds with the verification path, but deliberately skips manifest
// verification: this call is what produces the bytes a new manifest will sign.
func (m *FeedManager) downloadFeedRaw(ctx context.Context, src ThreatFeedSource, snapshot *threatIntelSnapshot) ([]byte, error) {
	if snapshot == nil {
		return nil, NewThreatIntelValidationException("threat intelligence configuration unavailable", nil)
	}
	u, err := validateFeedSourceURL(src.URL)
	if err != nil {
		return nil, err
	}
	if !snapshot.hostAllowed(u.Hostname()) {
		return nil, NewThreatIntelSecurityException("feed host is outside the configured allowlist", nil)
	}
	attempts := snapshot.settings.Retry.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(snapshot.settings.Retry.BackoffSeconds) * time.Second * time.Duration(1<<uint(minInt(attempt-2, 4)))
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		raw, _, fetchErr := m.fetchFeedRawOnce(ctx, src, snapshot, u)
		if fetchErr == nil {
			return raw, nil
		}
		lastErr = fetchErr
		if !threatFeedRetryable(fetchErr) {
			return nil, fetchErr
		}
	}
	return nil, lastErr
}
