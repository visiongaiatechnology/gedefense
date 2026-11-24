// STATUS: DIAMANT VGT SUPREME
// Authenticated threat-intelligence state persistence and integrity bookkeeping
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Persisted state integrity (FIND-023)
// ---------------------------------------------------------------------------

// persistentStateAuthenticityRequired reports whether the deployment has a feed
// authenticity model configured. Only a pipeline that is explicitly
// unauthenticated may persist/read plaintext state: there, the state cannot
// weaken an authenticity guarantee that the operator switched off.
func (m *FeedManager) persistentStateAuthenticityRequired() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.persistentStateAuthenticityRequiredLocked()
}

func (m *FeedManager) persistentStateAuthenticityRequiredLocked() bool {
	return m.cfg.RequireSignedManifest || m.cfg.LocalSigning || len(m.signingKeys) > 0
}

// recordStateIntegrityEventLocked appends one integrity decision to the bounded
// audit trail and mirrors it to the journal. Repeated identical events are
// collapsed so a failing persistence path cannot flood the log. m.mu must be held.
func (m *FeedManager) recordStateIntegrityEventLocked(kind, detail string) {
	if n := len(m.stateIntegrityEvents); n > 0 {
		last := m.stateIntegrityEvents[n-1]
		if last.Kind == kind && last.Detail == detail {
			return
		}
	}
	m.stateIntegrityEvents = append(m.stateIntegrityEvents, threatIntelStateIntegrityEvent{
		At: time.Now().UTC(), Kind: kind, Detail: detail,
	})
	if len(m.stateIntegrityEvents) > threatIntelStateIntegrityEventLimit {
		m.stateIntegrityEvents = m.stateIntegrityEvents[len(m.stateIntegrityEvents)-threatIntelStateIntegrityEventLimit:]
	}
	log.Printf("threat-intel state integrity: %s: %s", kind, detail)
}

func (m *FeedManager) noteStateIntegrityFailure(kind, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateIntegrityErr = detail
	m.recordStateIntegrityEventLocked(kind, detail)
}

func (m *FeedManager) noteStateIntegritySuccess(kind, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateIntegrityErr = ""
	m.recordStateIntegrityEventLocked(kind, detail)
}

// PersistentStateIntegrity returns the last persisted-state integrity error (empty
// when the state was authenticated or absent) and a copy of the integrity event
// trail, so a refusal is observable through the API and provable in tests.
func (m *FeedManager) PersistentStateIntegrity() (string, []threatIntelStateIntegrityEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	events := append([]threatIntelStateIntegrityEvent(nil), m.stateIntegrityEvents...)
	return m.stateIntegrityErr, events
}

// quarantinePersistentState moves an untrusted state file aside instead of
// deleting it. The bytes are evidence of a tampering attempt and the rename keeps
// them for the operator; the manager then rebuilds its state from safe defaults.
func (m *FeedManager) quarantinePersistentState(reason string) {
	m.mu.RLock()
	statePath := m.statePath
	m.mu.RUnlock()
	if strings.TrimSpace(statePath) == "" {
		return
	}
	target := statePath + threatIntelStateQuarantineSuffix + fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	if err := os.Rename(statePath, target); err != nil {
		log.Printf("threat-intel state quarantine failed (%s): %v", reason, err)
		return
	}
	log.Printf("threat-intel state moved to quarantine as untrusted (%s): %s", reason, target)
}

// cloneThreatIntelPersistentState deep-copies the document including every item
// slice, so the save path can normalise the projection without mutating the live
// manager state.
func cloneThreatIntelPersistentState(doc ThreatIntelPersistentState) ThreatIntelPersistentState {
	cloned := doc
	cloned.Feeds = make(map[string]*FeedGenerationState, len(doc.Feeds))
	for id, state := range doc.Feeds {
		if state == nil {
			continue
		}
		copied := *state
		copied.LastGoodItems = append([]string(nil), state.LastGoodItems...)
		cloned.Feeds[id] = &copied
	}
	return cloned
}

// resetFeedGenerationProjection removes every value that is only meaningful when
// it was authenticated by a verified manifest generation.
func resetFeedGenerationProjection(state *FeedGenerationState) {
	if state == nil {
		return
	}
	state.LastGoodItems = nil
	state.LastGoodCount = 0
	state.LastGoodGen = 0
	state.LastGoodAt = time.Time{}
	state.LastGoodFingerprint = ""
	state.ManifestVersion = 0
	state.ManifestValidUntil = time.Time{}
	state.ManifestVerified = false
	state.ManifestAuthenticity = "UNVERIFIED"
}

func (m *FeedManager) loadPersistentState() error {
	m.mu.RLock()
	statePath := m.statePath
	required := m.persistentStateAuthenticityRequiredLocked()
	m.mu.RUnlock()
	if strings.TrimSpace(statePath) == "" {
		return nil
	}

	// A missing state file on first start is normal and not an integrity finding.
	if _, statErr := os.Lstat(statePath); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		m.noteStateIntegrityFailure("state.read_refused", statErr.Error())
		return statErr
	}

	raw, readErr := readBoundedPrivateFile(statePath, maxThreatIntelStateBytes)
	if readErr != nil {
		m.noteStateIntegrityFailure("state.read_refused", readErr.Error())
		m.quarantinePersistentState("state file is not a private, bounded regular file")
		return readErr
	}

	var probe struct {
		Schema string `json:"schema"`
	}
	_ = json.Unmarshal(raw, &probe)

	if probe.Schema == threatIntelStateEnvelopeSchema {
		doc, mode, verificationErr := m.verifyPersistentStateEnvelope(raw)
		if verificationErr != nil {
			m.noteStateIntegrityFailure("state.untrusted", verificationErr.Error())
			m.quarantinePersistentState(verificationErr.Error())
			return verificationErr
		}
		m.applyPersistentStateDocument(doc)
		m.noteStateIntegritySuccess("state.loaded", "authenticated persisted state accepted ("+mode+")")
		return nil
	}

	var doc ThreatIntelPersistentState
	if err := json.Unmarshal(raw, &doc); err != nil {
		m.noteStateIntegrityFailure("state.untrusted", "persisted state is not valid JSON: "+err.Error())
		m.quarantinePersistentState("persisted state is not valid JSON")
		return err
	}
	if doc.Schema != threatIntelStateSchemaV1 && doc.Schema != threatIntelStateSchemaV2 && doc.Schema != threatIntelStateSchemaV3 {
		err := errors.New("state schema mismatch")
		m.noteStateIntegrityFailure("state.untrusted", err.Error())
		m.quarantinePersistentState(err.Error())
		return err
	}
	if required {
		// An unsigned document in a deployment that has a feed authenticity model
		// is exactly the downgrade this fix closes: never adopt its
		// ManifestVersion or LastGoodItems. Quarantine and rebuild.
		err := NewThreatIntelSecurityException("persisted threat-intelligence state is not authenticated; refusing to adopt its anti-rollback floor or indicator sets", nil)
		m.noteStateIntegrityFailure("state.untrusted", err.Error())
		m.quarantinePersistentState(err.Error())
		return err
	}

	// Explicitly unauthenticated pipeline: the legacy document is accepted and
	// re-persisted in the same format, because nothing about this pipeline is
	// authenticated in the first place.
	m.applyPersistentStateDocument(doc)
	m.noteStateIntegritySuccess("state.loaded_unauthenticated", "feed authenticity is not configured; legacy plaintext state accepted")
	return nil
}

// verifyPersistentStateEnvelope authenticates the state envelope and returns the
// document plus the mode that authenticated it. Any error is a fail-closed
// refusal; no partially verified document is returned.
func (m *FeedManager) verifyPersistentStateEnvelope(raw []byte) (ThreatIntelPersistentState, string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope threatIntelStateEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state envelope is malformed", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state envelope contains trailing data", nil)
	}
	if envelope.Schema != threatIntelStateEnvelopeSchema {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state envelope schema rejected", nil)
	}
	m.mu.RLock()
	keys := append([]ed25519.PublicKey(nil), m.signingKeys...)
	m.mu.RUnlock()
	switch envelope.Mode {
	case threatIntelStateModeSigned:
		return decodeSignedPersistentStateEnvelope(envelope, keys)
	case threatIntelStateModeAnchor:
		return m.decodeAnchoredPersistentStateEnvelope(envelope, keys)
	default:
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state envelope authenticity mode rejected", nil)
	}
}

func decodePersistentStateEnvelopePayload(envelope threatIntelStateEnvelope) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Payload))
	if err != nil {
		payload, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(envelope.Payload))
	}
	if err != nil || len(payload) == 0 {
		return nil, NewThreatIntelSecurityException("persisted state payload encoding rejected", nil)
	}
	if len(payload) > maxThreatIntelStateBytes {
		return nil, NewThreatIntelSecurityException("persisted state payload exceeds the bounded size", nil)
	}
	return payload, nil
}

func decodePersistentStateDocumentPayload(payload []byte) (ThreatIntelPersistentState, error) {
	var doc ThreatIntelPersistentState
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return ThreatIntelPersistentState{}, NewThreatIntelSecurityException("persisted state payload JSON rejected", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ThreatIntelPersistentState{}, NewThreatIntelSecurityException("persisted state payload contains trailing data", nil)
	}
	if doc.Schema != threatIntelStateSchemaV1 && doc.Schema != threatIntelStateSchemaV2 && doc.Schema != threatIntelStateSchemaV3 {
		return ThreatIntelPersistentState{}, NewThreatIntelSecurityException("persisted state payload schema rejected", nil)
	}
	return doc, nil
}

// decodeSignedPersistentStateEnvelope verifies the Ed25519 signature over the
// exact payload bytes against a pinned feed signing key. The envelope names its
// key, but the key must be one of the bootstrap pins: a state file cannot
// install its own trust anchor.
func decodeSignedPersistentStateEnvelope(envelope threatIntelStateEnvelope, keys []ed25519.PublicKey) (ThreatIntelPersistentState, string, error) {
	if len(keys) == 0 {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state is signed but no pinned feed signing key is configured; state refused", nil)
	}
	publicKeyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.PublicKey))
	if err != nil {
		publicKeyBytes, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(envelope.PublicKey))
	}
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state envelope public key rejected", nil)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)
	pinned := false
	for _, key := range keys {
		if key.Equal(publicKey) {
			pinned = true
			break
		}
	}
	if !pinned {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state envelope names a feed signing key that is not pinned", nil)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Signature))
	if err != nil {
		signature, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(envelope.Signature))
	}
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state signature encoding rejected", nil)
	}
	payload, err := decodePersistentStateEnvelopePayload(envelope)
	if err != nil {
		return ThreatIntelPersistentState{}, "", err
	}
	if !ed25519.Verify(publicKey, threatIntelStateSignatureMessage(payload), signature) {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state signature verification failed", nil)
	}
	doc, err := decodePersistentStateDocumentPayload(payload)
	if err != nil {
		return ThreatIntelPersistentState{}, "", err
	}
	return doc, threatIntelStateModeSigned, nil
}

// decodeAnchoredPersistentStateEnvelope authenticates the state against an
// embedded, Ed25519-signed feed manifest. The manifest signature is checked with
// the pinned keys; the anti-rollback floor, validity window and indicator sets of
// every feed must match the authenticated manifest entries. Anything that cannot
// be bound is dropped (never adopted); a malformed envelope refuses the whole
// document.
func (m *FeedManager) decodeAnchoredPersistentStateEnvelope(envelope threatIntelStateEnvelope, keys []ed25519.PublicKey) (ThreatIntelPersistentState, string, error) {
	if len(keys) == 0 {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state is anchored to a manifest but no pinned feed signing key is configured; state refused", nil)
	}
	manifestRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Manifest))
	if err != nil {
		manifestRaw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(envelope.Manifest))
	}
	if err != nil || len(manifestRaw) == 0 || len(manifestRaw) > maxThreatFeedManifestBytes {
		return ThreatIntelPersistentState{}, "", NewThreatIntelSecurityException("persisted state manifest anchor encoding rejected", nil)
	}
	manifest, err := parseSignedFeedManifestDocument(manifestRaw)
	if err != nil {
		return ThreatIntelPersistentState{}, "", err
	}
	// A historical manifest authenticates history even after its freshness window:
	// the anti-rollback floor must survive a restart during an offline window.
	if err := validateSignedFeedManifestIntegrity(manifest); err != nil {
		return ThreatIntelPersistentState{}, "", err
	}
	if err := verifyFeedManifestSignature(manifest, keys); err != nil {
		return ThreatIntelPersistentState{}, "", err
	}
	payload, err := decodePersistentStateEnvelopePayload(envelope)
	if err != nil {
		return ThreatIntelPersistentState{}, "", err
	}
	doc, err := decodePersistentStateDocumentPayload(payload)
	if err != nil {
		return ThreatIntelPersistentState{}, "", err
	}
	entries := make(map[string]threatFeedManifestEntry, len(manifest.Feeds))
	for _, entry := range manifest.Feeds {
		entries[entry.ID] = entry
	}
	for id, state := range doc.Feeds {
		if state == nil {
			continue
		}
		entry, known := entries[id]
		if !known {
			if state.ManifestVersion != 0 || state.ManifestVerified || len(state.LastGoodItems) > 0 {
				m.noteStateIntegrityFailure("state.feed_projection_refused", "feed "+id+" is not covered by the signed state anchor; its persisted generation was not adopted")
				resetFeedGenerationProjection(state)
			}
			continue
		}
		if state.ManifestVersion != 0 && state.ManifestVersion != entry.Version {
			m.noteStateIntegrityFailure("state.feed_projection_refused", fmt.Sprintf("feed %s persisted generation %d does not match the signed manifest generation %d; projection not adopted", id, state.ManifestVersion, entry.Version))
			resetFeedGenerationProjection(state)
			continue
		}
		if len(state.LastGoodItems) > 0 {
			itemsDigest := computeFingerprint(state.LastGoodItems)
			if !strings.EqualFold(itemsDigest, entry.ItemsSHA256) || !strings.EqualFold(state.LastGoodFingerprint, entry.ItemsSHA256) {
				m.noteStateIntegrityFailure("state.feed_projection_refused", "feed "+id+" persisted indicator set does not match the signed manifest digest; projection not adopted")
				resetFeedGenerationProjection(state)
				continue
			}
		} else {
			state.LastGoodAt = time.Time{}
			state.LastGoodGen = 0
			state.LastGoodFingerprint = ""
		}
		// The authenticated manifest entry is authoritative for the window and the
		// verification flag; the persisted copies are replaced, not trusted.
		state.LastGoodCount = len(state.LastGoodItems)
		state.ManifestValidUntil = entry.ValidUntil
		state.ManifestVerified = len(state.LastGoodItems) > 0
		if state.ManifestVersion > 0 {
			state.ManifestAuthenticity = "SIGNED"
		} else {
			state.ManifestAuthenticity = "UNVERIFIED"
		}
	}
	return doc, threatIntelStateModeAnchor, nil
}

// applyPersistentStateDocument installs an already authenticated (or explicitly
// unauthenticated) document into the live manager state.
func (m *FeedManager) applyPersistentStateDocument(doc ThreatIntelPersistentState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if doc.Schema == threatIntelStateSchemaV1 {
		if doc.LastAttemptAt.IsZero() {
			doc.LastAttemptAt = doc.LastSuccessfulSyncAt
		}
		if doc.LastFullySuccessfulSyncAt.IsZero() {
			doc.LastFullySuccessfulSyncAt = doc.LastSuccessfulSyncAt
		}
		if doc.OverallStatus == "" {
			if doc.LastSuccessfulSyncAt.IsZero() {
				doc.OverallStatus = "NEVER_SYNCED"
			} else {
				doc.OverallStatus = "OK"
			}
		}
	}

	m.lastAttemptAt = doc.LastAttemptAt
	m.lastSuccessfulSyncAt = doc.LastSuccessfulSyncAt
	m.lastPartialSuccessfulSyncAt = doc.LastPartialSuccessfulSyncAt
	m.lastFullySuccessfulSyncAt = doc.LastFullySuccessfulSyncAt
	m.overallStatus = doc.OverallStatus
	m.kernelApplyLastAt = doc.KernelApplyLastAt
	// Early 4.1 builds persisted "OK" while the API/UI contract used
	// "APPLIED". Normalize that legacy value during load so operators never see
	// a muted/unknown kernel state after an otherwise successful migration.
	if doc.KernelApplyStatus == "OK" {
		doc.KernelApplyStatus = kernelApplyApplied
	}
	m.kernelApplyStatus = doc.KernelApplyStatus
	if m.kernelApplyStatus == "" {
		m.kernelApplyStatus = kernelApplyNotApplied
	}
	m.kernelGeneration = doc.KernelGeneration
	m.lastKernelAdded = doc.LastKernelAdded
	m.lastKernelDeleted = doc.LastKernelDeleted
	m.lastKernelError = doc.LastKernelError
	m.generation = doc.Generation
	m.fingerprint = doc.Fingerprint

	for id, state := range doc.Feeds {
		if state == nil {
			continue
		}
		if existing, ok := m.feedStates[id]; ok {
			existing.LastGoodItems = state.LastGoodItems
			existing.LastGoodCount = len(state.LastGoodItems)
			existing.LastGoodGen = state.LastGoodGen
			existing.LastGoodAt = state.LastGoodAt
			existing.LastAttemptAt = state.LastAttemptAt
			existing.LastError = state.LastError
			existing.ConsecutiveFails = state.ConsecutiveFails
			existing.LastGoodFingerprint = state.LastGoodFingerprint
			// The signed-manifest projection must survive a restart: the
			// anti-rollback floor (ManifestVersion) and the hard validity window
			// are what keep a previously verified generation enforceable, and
			// dropping them would let the first sync after a restart reuse a
			// version this host already published.
			existing.ManifestVersion = state.ManifestVersion
			existing.ManifestValidUntil = state.ManifestValidUntil
			existing.ManifestVerified = state.ManifestVerified
			existing.ManifestAuthenticity = state.ManifestAuthenticity
			existing.Status = computeFeedStatus(existing, m.live.activeSettings())
		}
	}

	// Recompose through the deterministic, priority-ordered composition so a
	// restart publishes exactly the generation the runtime would have published.
	blockItems, corrItems, annotItems := m.composeGenerationsLocked(m.live.activeSettings())
	m.blockIndex.Replace(blockItems)
	m.correlateIndex.Replace(corrItems)
	m.annotateIndex.Replace(annotItems)
}

// persistentStateSigningKeyLocked returns the operator feed-signing key when
// local signing is enabled and the key is one of the pinned trust anchors.
// Anything else returns nil; the caller then falls back to the manifest anchor or
// fails closed.
func (m *FeedManager) persistentStateSigningKeyLocked() *feedSigningKeyPair {
	if !m.cfg.LocalSigning {
		return nil
	}
	keyFile := strings.TrimSpace(m.cfg.SigningKeyFile)
	if keyFile == "" {
		return nil
	}
	key, _ := m.localSigningKeyState()
	if key == nil {
		if err := m.ensureLocalSigningKey(keyFile); err != nil {
			return nil
		}
		key, _ = m.localSigningKeyState()
	}
	if key == nil || len(key.private) != ed25519.PrivateKeySize {
		return nil
	}
	for _, pinned := range m.signingKeys {
		if pinned.Equal(key.public) {
			return key
		}
	}
	return nil
}

// currentSignedManifestForStateAnchorLocked loads the current signed manifest for
// the state anchor. The live acceptance rules (freshness, signature) apply: only
// a manifest that would be accepted for feeds may anchor the persisted state.
func (m *FeedManager) currentSignedManifestForStateAnchorLocked() ([]byte, threatFeedManifestDocument, error) {
	_, keys, manifestPath, maxAge := m.signingConfigLocked()
	if len(keys) == 0 {
		return nil, threatFeedManifestDocument{}, errors.New("persisted state cannot be anchored: no pinned feed signing key is configured")
	}
	raw, err := readFeedManifestRaw(manifestPath)
	if err != nil {
		return nil, threatFeedManifestDocument{}, fmt.Errorf("persisted state cannot be anchored: %w", err)
	}
	document, err := parseSignedFeedManifestDocument(raw)
	if err != nil {
		return nil, threatFeedManifestDocument{}, fmt.Errorf("persisted state cannot be anchored: %w", err)
	}
	if err := validateSignedFeedManifest(document, time.Now().UTC(), maxAge); err != nil {
		return nil, threatFeedManifestDocument{}, fmt.Errorf("persisted state cannot be anchored: %w", err)
	}
	if err := verifyFeedManifestSignature(document, keys); err != nil {
		return nil, threatFeedManifestDocument{}, fmt.Errorf("persisted state cannot be anchored: %w", err)
	}
	return raw, document, nil
}

// anchorPersistentStateDocumentLocked normalises the document against the current
// signed manifest before it is persisted: the anti-rollback floor may only rise
// to an authenticated generation, indicator sets that the current manifest does
// not bind are dropped, and a persisted generation newer than the signed manifest
// is refused instead of silently lowering the floor.
func (m *FeedManager) anchorPersistentStateDocumentLocked(doc ThreatIntelPersistentState, manifest threatFeedManifestDocument) (ThreatIntelPersistentState, error) {
	entries := make(map[string]threatFeedManifestEntry, len(manifest.Feeds))
	for _, entry := range manifest.Feeds {
		entries[entry.ID] = entry
	}
	for id, state := range doc.Feeds {
		if state == nil {
			continue
		}
		entry, known := entries[id]
		if !known {
			resetFeedGenerationProjection(state)
			continue
		}
		if state.ManifestVersion > entry.Version {
			return ThreatIntelPersistentState{}, fmt.Errorf(
				"persisted feed %s generation %d is newer than the signed manifest generation %d; refusing to persist an unauthenticated anti-rollback floor", id, state.ManifestVersion, entry.Version)
		}
		if state.ManifestVersion == entry.Version && state.ManifestVerified && len(state.LastGoodItems) > 0 &&
			strings.EqualFold(state.LastGoodFingerprint, entry.ItemsSHA256) &&
			strings.EqualFold(computeFingerprint(state.LastGoodItems), entry.ItemsSHA256) {
			state.ManifestValidUntil = entry.ValidUntil
			state.LastGoodCount = len(state.LastGoodItems)
			state.ManifestAuthenticity = "SIGNED"
			continue
		}
		// The persisted indicator set is not bound by the current signed
		// manifest. Keep an authenticated floor (raising it to the manifest
		// generation is monotonic and cannot enable a rollback) but never the
		// unbound items.
		state.ManifestVersion = entry.Version
		state.ManifestValidUntil = entry.ValidUntil
		state.ManifestVerified = false
		state.ManifestAuthenticity = "UNVERIFIED"
		state.LastGoodItems = nil
		state.LastGoodCount = 0
		state.LastGoodGen = 0
		state.LastGoodAt = time.Time{}
		state.LastGoodFingerprint = ""
	}
	return doc, nil
}

// encodePersistentStateDocumentLocked serialises the document in the integrity
// mode the configuration allows. It returns an error (and thus refuses the save)
// when a feed authenticity model is configured but no authenticated format can be
// produced: an unsigned write in that state would be a silent downgrade.
func (m *FeedManager) encodePersistentStateDocumentLocked(doc ThreatIntelPersistentState) ([]byte, error) {
	doc = cloneThreatIntelPersistentState(doc)
	if !m.persistentStateAuthenticityRequiredLocked() {
		return json.MarshalIndent(doc, "", "  ")
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if key := m.persistentStateSigningKeyLocked(); key != nil {
		signature := ed25519.Sign(key.private, threatIntelStateSignatureMessage(payload))
		return marshalPersistentStateEnvelope(threatIntelStateEnvelope{
			Schema:    threatIntelStateEnvelopeSchema,
			Mode:      threatIntelStateModeSigned,
			Payload:   base64.StdEncoding.EncodeToString(payload),
			PublicKey: feedSigningPublicKeyBase64(key.public),
			Signature: base64.StdEncoding.EncodeToString(signature),
		})
	}
	manifestRaw, manifest, err := m.currentSignedManifestForStateAnchorLocked()
	if err != nil {
		return nil, err
	}
	anchored, err := m.anchorPersistentStateDocumentLocked(doc, manifest)
	if err != nil {
		return nil, err
	}
	anchoredPayload, err := json.Marshal(anchored)
	if err != nil {
		return nil, err
	}
	return marshalPersistentStateEnvelope(threatIntelStateEnvelope{
		Schema:   threatIntelStateEnvelopeSchema,
		Mode:     threatIntelStateModeAnchor,
		Payload:  base64.StdEncoding.EncodeToString(anchoredPayload),
		Manifest: base64.StdEncoding.EncodeToString(manifestRaw),
	})
}

func marshalPersistentStateEnvelope(envelope threatIntelStateEnvelope) ([]byte, error) {
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxThreatIntelStateBytes {
		return nil, fmt.Errorf("persisted state envelope exceeds the bounded state size of %d bytes", maxThreatIntelStateBytes)
	}
	return encoded, nil
}

func (m *FeedManager) savePersistentStateLocked() error {
	doc := ThreatIntelPersistentState{
		Schema:                      threatIntelStateSchema,
		OverallStatus:               m.overallStatus,
		LastAttemptAt:               m.lastAttemptAt,
		LastSuccessfulSyncAt:        m.lastSuccessfulSyncAt,
		LastPartialSuccessfulSyncAt: m.lastPartialSuccessfulSyncAt,
		LastFullySuccessfulSyncAt:   m.lastFullySuccessfulSyncAt,
		KernelApplyLastAt:           m.kernelApplyLastAt,
		KernelApplyStatus:           m.kernelApplyStatus,
		KernelGeneration:            m.kernelGeneration,
		LastKernelAdded:             m.lastKernelAdded,
		LastKernelDeleted:           m.lastKernelDeleted,
		LastKernelError:             m.lastKernelError,
		Generation:                  m.generation,
		Fingerprint:                 m.fingerprint,
		Feeds:                       m.feedStates,
	}
	data, err := m.encodePersistentStateDocumentLocked(doc)
	if err != nil {
		m.stateIntegrityErr = err.Error()
		m.recordStateIntegrityEventLocked("state.persist_refused", err.Error())
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o700); err != nil {
		return err
	}
	// Feed state is the record of which indicators were published; it goes through
	// the same symlink-refusing atomic writer as every other store.
	if err := atomicWriteFile(m.statePath, data, 0o600); err != nil {
		m.stateIntegrityErr = err.Error()
		m.recordStateIntegrityEventLocked("state.persist_failed", err.Error())
		return err
	}
	m.stateIntegrityErr = ""
	return nil
}
