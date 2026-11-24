// AP-9 / S09 — feed-pipeline integration of the threshold envelope and the
// local semantic guard.
//
// The gate is computed once per sync while the manager write lock is held, so
// exactly one configuration view and one file state are observed by all feeds
// of that sync. It is additive: the existing signed-manifest, HTTPS-only,
// SSRF-dial and kernel-apply checks are untouched and still run first.
//
// Activation contract implemented here:
//
//  1. Before any feed is promoted, the gate resolves the TUF capability, reads
//     the existing signed feed manifest (the content document), loads and
//     authenticates the high-water register, and verifies the threshold
//     envelope against the persisted epoch. Any failure rejects the whole sync
//     fail-closed: no feed reaches Last-Known-Good and the previous generation
//     keeps being served.
//  2. Every candidate feed is then screened by the semantic guard, which runs
//     even when the TUF capability is unavailable because it is a signature
//     independent, local check.
//  3. Only a sync that accepted the envelope and promoted every enabled source
//     commits a new high-water epoch and Last-Known-Good hash. If that commit
//     fails, the promotions are rolled back to the pre-sync projection: an
//     unauthenticated epoch advancement must never be published.

package main

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"
)

// tufSyncGate is the per-sync S09 decision plus the rollback snapshot.
type tufSyncGate struct {
	Active           bool
	CapabilityReason string
	Verified         *TUFVerifiedManifest
	ContentSHA256    string
	Register         *TUFHighWaterRegister
	Reject           error
	Restore          map[string]*FeedGenerationState
	Now              time.Time
}

// tufManifestEnvelopePath is the conventional envelope location: next to the
// existing feeds.manifest_path (which itself defaults to the state root).
func tufManifestEnvelopePath(manifestPath string) string {
	return filepath.Join(filepath.Dir(manifestPath), tufManifestFilename)
}

// tufPrepareSyncGateLocked resolves the S09 gate for one sync. The caller holds
// the manager write lock; it must not re-enter m.mu.
func (m *FeedManager) tufPrepareSyncGateLocked(now time.Time) tufSyncGate {
	gate := tufSyncGate{Now: now}
	capable, reason := m.tufCapabilityLocked()
	gate.CapabilityReason = reason
	if capable {
		m.tuf.Capability = TUFCapabilityAvailable
		m.tuf.CapabilityReason = ""
	} else {
		m.tuf.Capability = TUFCapabilityUnavailable
		m.tuf.CapabilityReason = reason
		return gate
	}
	gate.Active = true
	trust, err := newTUFTrustSet(m.signingKeys)
	if err != nil {
		gate.Reject = err
		return gate
	}
	_, keys, manifestPath, maxAge := m.signingConfigLocked()
	rawManifest, err := readFeedManifestRaw(manifestPath)
	if err != nil {
		gate.Reject = newTUFError(TUFReasonContentBinding,
			"signed feed manifest is unavailable for the TUF content binding")
		return gate
	}
	document, err := parseSignedFeedManifestDocument(rawManifest)
	if err != nil {
		gate.Reject = newTUFError(TUFReasonContentBinding,
			"signed feed manifest is malformed for the TUF content binding")
		return gate
	}
	if err := validateSignedFeedManifest(document, now, maxAge); err != nil {
		gate.Reject = newTUFError(TUFReasonContentBinding,
			"signed feed manifest failed its freshness window for the TUF content binding")
		return gate
	}
	if err := verifyFeedManifestSignature(document, keys); err != nil {
		gate.Reject = newTUFError(TUFReasonContentBinding,
			"signed feed manifest could not be verified for the TUF content binding")
		return gate
	}
	contentDigest := tufFeedManifestContentDigest(document)
	store := newTUFHighWaterStore(filepath.Dir(m.statePath))
	register, exists, err := store.Load()
	if err != nil {
		gate.Reject = err
		m.tuf.StateErr = err.Error()
		return gate
	}
	highWaterEpoch := uint64(0)
	if exists {
		highWaterEpoch = register.Epoch
		gate.Register = &register
	}
	rawEnvelope, err := readTUFManifestFile(tufManifestEnvelopePath(manifestPath))
	if err != nil {
		gate.Reject = err
		return gate
	}
	verified, err := verifyTUFManifestEnvelope(rawEnvelope, trust, TUFVerifyOptions{
		Now:                   now,
		HighWaterEpoch:        highWaterEpoch,
		ExpectedContentSHA256: contentDigest,
		Limits:                DefaultTUFLimits(),
	})
	if err != nil {
		gate.Reject = err
		return gate
	}
	gate.Verified = verified
	gate.ContentSHA256 = contentDigest
	gate.Restore = m.snapshotLastKnownGoodLocked()
	return gate
}

// tufScreenFeedPromotionLocked runs the signature-independent semantic guard and
// the TUF envelope verdict for one candidate feed generation. Every rejection is
// returned in the existing ThreatIntel error style and keeps the machine
// readable reason code reachable through errors.As.
func (m *FeedManager) tufScreenFeedPromotionLocked(gate *tufSyncGate, state *FeedGenerationState, items []string) error {
	if gate != nil && gate.Active && gate.Reject != nil {
		return tufWrapRejection(gate.Reject)
	}
	if state == nil {
		return nil
	}
	previous := tufFeedProtectionSnapshot(state.ID, state.Action, state.LastGoodItems)
	candidate := tufFeedProtectionSnapshot(state.ID, state.Action, items)
	if err := GuardTUFProtectionUpdate(previous, candidate, DefaultTUFSemanticGuardLimits()); err != nil {
		return tufWrapRejection(err)
	}
	return nil
}

// tufWrapRejection wraps a TUFError in the existing exception hierarchy so the
// sync error map, the journal and the state event keep the same machine readable
// reason without changing the feed API shape.
func tufWrapRejection(err error) error {
	reason := tufErrorReason(err)
	if reason == "" {
		reason = TUFReasonSchema
	}
	return NewThreatIntelSecurityException("feed generation rejected by the S09 anti-poisoning guard ("+reason+")", err)
}

// tufCommitSyncLocked advances the anti-rollback epoch and the Last-Known-Good
// shadow after a fully accepted sync. Called after all promotions were decided
// but before the sync publishes its status; a commit failure is handled by the
// caller as a rollback of the promotions.
func (m *FeedManager) tufCommitSyncLocked(gate *tufSyncGate, settings ThreatIntelFabricSettings, now time.Time) error {
	if gate == nil || !gate.Active || gate.Verified == nil {
		return nil
	}
	blockUnion, _, _ := m.composeGenerationsLocked(settings)
	register := TUFHighWaterRegister{
		Schema:              tufHighWaterSchema,
		Epoch:               gate.Verified.Epoch,
		SnapshotSHA256:      gate.Verified.SnapshotSHA256,
		ContentSHA256:       gate.Verified.ContentSHA256,
		LastKnownGoodSHA256: computeFingerprint(blockUnion),
		ActivatedAt:         now.UTC().Format(time.RFC3339Nano),
		Reason:              "feed-generation-activated",
	}
	store := newTUFHighWaterStore(filepath.Dir(m.statePath))
	if err := store.Commit(register); err != nil {
		m.tuf.StateErr = err.Error()
		return err
	}
	m.recordTUFActivationLocked(register)
	return nil
}

// tufIsRejection reports whether the error is (or wraps) a TUF rejection.
func tufIsRejection(err error) bool {
	return tufErrorReason(err) != ""
}

// tufManagerState is the bounded, lock-guarded S09 projection carried by the
// FeedManager. It is additive; no existing feed state shape changed.
type tufManagerState struct {
	Capability          string
	CapabilityReason    string
	Epoch               uint64
	LastKnownGoodSHA256 string
	LastActivatedAt     time.Time
	BlockedUpdates      uint64
	LastBlockedReason   string
	LastBlockedAt       time.Time
	StateErr            string
	Recent              []TUFBlockedEvent
}

// recordTUFBlockedLocked records one anti-poisoning rejection. The ring is
// bounded, the log line carries only the stable reason code, and the event
// message never contains a URL or key material.
func (m *FeedManager) recordTUFBlockedLocked(reason, feedID string, at time.Time) {
	if strings.TrimSpace(reason) == "" {
		reason = TUFReasonSchema
	}
	m.tuf.BlockedUpdates++
	m.tuf.LastBlockedReason = reason
	m.tuf.LastBlockedAt = at.UTC()
	event := TUFBlockedEvent{At: at.UTC(), Kind: "feed.poisoning_blocked", Reason: reason, FeedID: feedID}
	m.tuf.Recent = append([]TUFBlockedEvent{event}, m.tuf.Recent...)
	if len(m.tuf.Recent) > tufBlockedEventLimit {
		m.tuf.Recent = m.tuf.Recent[:tufBlockedEventLimit]
	}
	m.emitTUFStateEventLocked(reason, feedID, at)
	log.Printf("tuf: feed poisoning blocked: feed=%s reason=%s", feedID, reason)
}

// recordTUFActivationLocked projects a successful register commit.
func (m *FeedManager) recordTUFActivationLocked(register TUFHighWaterRegister) {
	m.tuf.Epoch = register.Epoch
	m.tuf.LastKnownGoodSHA256 = register.LastKnownGoodSHA256
	activatedAt, err := parseTUFCanonicalTime("activated_at", register.ActivatedAt)
	if err == nil {
		m.tuf.LastActivatedAt = activatedAt
	}
	m.tuf.StateErr = ""
}

// loadTUFStatusFromRegister projects the persisted register into the manager
// status once at construction time. A corrupt register is reported (and later
// fails the sync closed); it is never cleared or re-created here.
func (m *FeedManager) loadTUFStatusFromRegister() {
	capable, reason := m.tufCapabilityLocked()
	m.mu.Lock()
	m.tuf.Capability = TUFCapabilityUnavailable
	m.tuf.CapabilityReason = reason
	if capable {
		m.tuf.Capability = TUFCapabilityAvailable
		m.tuf.CapabilityReason = ""
	}
	m.mu.Unlock()
	log.Printf("tuf: capability=%s reason=%q threshold=2-of-3 r5_isolation=%s r5_helper=%s",
		m.tuf.Capability, m.tuf.CapabilityReason, TUFR5IsolationShadow, TUFR5HelperPending)
	if !capable {
		return
	}
	register, exists, err := newTUFHighWaterStore(filepath.Dir(m.statePath)).Load()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.tuf.StateErr = err.Error()
		log.Printf("tuf: high-water register unusable; feeds fail closed until it is repaired: %v", err)
		return
	}
	if exists {
		m.recordTUFActivationLocked(register)
	}
}

// tufCapabilityLocked derives the capability from the immutable bootstrap
// configuration. It is a projection only: it never weakens or strengthens the
// existing signed-manifest gate.
func (m *FeedManager) tufCapabilityLocked() (bool, string) {
	if !m.cfg.RequireSignedManifest {
		return false, "feeds.require_signed_manifest is disabled; a threshold envelope would be decorative"
	}
	if m.cfg.LocalSigning {
		return false, "feeds.local_signing cannot produce a role-separated 2-of-3 envelope"
	}
	if len(m.signingKeys) < tufRequiredRoleKeys {
		return false, fmt.Sprintf("%d pinned feed signing keys; %d required for root/content/snapshot", len(m.signingKeys), tufRequiredRoleKeys)
	}
	if _, err := newTUFTrustSet(m.signingKeys); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// tufStatusLocked builds the bounded projection exposed through the feed
// telemetry. The caller holds m.mu (read or write).
func (m *FeedManager) tufStatusLocked() TUFSecurityStatus {
	status := TUFSecurityStatus{
		Capability:          m.tuf.Capability,
		Reason:              m.tuf.CapabilityReason,
		Threshold:           "2-of-3",
		Roles:               []string{tufRoleRoot, tufRoleContent, tufRoleSnapshot},
		EnvelopeSchema:      tufEnvelopeSchema,
		Epoch:               m.tuf.Epoch,
		LastKnownGoodSHA256: m.tuf.LastKnownGoodSHA256,
		LastActivatedAt:     m.tuf.LastActivatedAt,
		BlockedUpdates:      m.tuf.BlockedUpdates,
		LastBlockedReason:   m.tuf.LastBlockedReason,
		LastBlockedAt:       m.tuf.LastBlockedAt,
		StateError:          m.tuf.StateErr,
		R5Isolation:         TUFR5IsolationShadow,
		R5HelperIsolation:   TUFR5HelperPending,
		RecentBlocked:       append([]TUFBlockedEvent(nil), m.tuf.Recent...),
	}
	if status.Capability == "" {
		status.Capability = TUFCapabilityUnavailable
	}
	return status
}

// TUFStatus returns the S09 security projection. It is safe for the status API
// and for tests; it performs no file I/O.
func (m *FeedManager) TUFStatus() TUFSecurityStatus {
	if m == nil {
		return TUFSecurityStatus{Capability: TUFCapabilityUnavailable, R5Isolation: TUFR5IsolationShadow, R5HelperIsolation: TUFR5HelperPending}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tufStatusLocked()
}
