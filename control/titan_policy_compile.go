// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

// Titan policy compilation/validation split out of titan.go (refactoring wave
// 1b, structure-only): configuration-to-policy compilation, the shared policy
// normalizer/validator, journal-event validation and the bounded reason/digest
// helpers used by the policy and review paths. Engine types and the observation
// pipeline stay in titan.go; persistence/sensor sync stays in titan_sync.go.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

func validTitanMode(mode TitanMode) bool {
	return mode == TitanModeObserve || mode == TitanModeContain || mode == TitanModeStrict
}

func validTitanChangeType(change TitanChangeType) bool {
	switch change {
	case TitanChangeCreated, TitanChangeModified, TitanChangeRemoved, TitanChangeAttributes, TitanChangeUnavailable:
		return true
	default:
		return false
	}
}

func titanPolicyFromConfig(cfg TitanConfig) (titanPolicy, error) {
	mode := TitanMode(strings.ToUpper(strings.TrimSpace(cfg.Mode)))
	if mode == "" {
		mode = TitanModeObserve
	}
	policy := titanPolicy{
		Mode: mode, Armed: cfg.Armed, AutoContain: cfg.AutoContain,
		Roots: append([]string(nil), cfg.Roots...), Allowlist: append([]string(nil), cfg.Allowlist...),
		DevelopmentRoots: append([]string(nil), cfg.DevelopmentRoots...), ProtectedPaths: append([]string(nil), cfg.ProtectedPaths...),
		MaxFileBytes: cfg.MaxFileBytes, MaxEvents: cfg.MaxEvents, JournalMaxBytes: cfg.JournalMaxBytes,
	}
	if err := normalizeTitanPolicy(&policy); err != nil {
		return titanPolicy{}, err
	}
	return policy, nil
}

// normalizeTitanPolicy canonicalizes and validates every policy field. It is
// used for configuration, for the persisted document and for the API request,
// so all three paths share one validator.
func normalizeTitanPolicy(policy *titanPolicy) error {
	if policy == nil {
		return errors.New("Titan policy is nil")
	}
	if !validTitanMode(policy.Mode) {
		return errors.New("Titan mode must be OBSERVE, CONTAIN or STRICT")
	}
	roots, err := normalizeTitanPaths(policy.Roots, titanMaxRoots)
	if err != nil {
		return fmt.Errorf("Titan roots: %w", err)
	}
	if len(roots) == 0 {
		return errors.New("Titan requires at least one configured root")
	}
	allowlist, err := normalizeTitanPaths(policy.Allowlist, titanMaxAllowlist)
	if err != nil {
		return fmt.Errorf("Titan allowlist: %w", err)
	}
	devRoots, err := normalizeTitanPaths(policy.DevelopmentRoots, titanMaxRoots)
	if err != nil {
		return fmt.Errorf("Titan development roots: %w", err)
	}
	protected, err := normalizeTitanPaths(policy.ProtectedPaths, titanMaxRoots*2)
	if err != nil {
		return fmt.Errorf("Titan protected paths: %w", err)
	}
	if policy.MaxFileBytes == 0 {
		policy.MaxFileBytes = 16 << 20
	}
	if policy.MaxFileBytes < titanMinFileBytes || policy.MaxFileBytes > titanMaxFileBytes {
		return fmt.Errorf("Titan max file bytes must be between %d and %d", titanMinFileBytes, titanMaxFileBytes)
	}
	if policy.MaxEvents == 0 {
		policy.MaxEvents = 500
	}
	if policy.MaxEvents < titanMinJournalEvents || policy.MaxEvents > titanMaxJournalEvents {
		return fmt.Errorf("Titan max journal events must be between %d and %d", titanMinJournalEvents, titanMaxJournalEvents)
	}
	if policy.JournalMaxBytes == 0 {
		policy.JournalMaxBytes = 4 << 20
	}
	if policy.JournalMaxBytes < titanMinJournalBytes || policy.JournalMaxBytes > titanMaxJournalBytes {
		return fmt.Errorf("Titan journal bytes must be between %d and %d", titanMinJournalBytes, titanMaxJournalBytes)
	}
	policy.Roots, policy.Allowlist, policy.DevelopmentRoots, policy.ProtectedPaths = roots, allowlist, devRoots, protected
	return nil
}

func normalizeTitanPaths(values []string, limit int) ([]string, error) {
	if len(values) > limit {
		return nil, fmt.Errorf("list exceeds %d entries", limit)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if len(value) > titanMaxPathBytes || strings.ContainsRune(value, '\x00') {
			return nil, errors.New("path contains NUL or is too long")
		}
		if !filepath.IsAbs(value) {
			return nil, fmt.Errorf("path %q is not absolute", value)
		}
		clean := filepath.Clean(value)
		if clean != value {
			return nil, fmt.Errorf("path %q is not canonical", value)
		}
		if clean == string(filepath.Separator) {
			return nil, errors.New("the filesystem root is not a bounded Titan target")
		}
		if _, duplicate := seen[clean]; duplicate {
			continue
		}
		seen[clean] = struct{}{}
		result = append(result, clean)
	}
	sort.Strings(result)
	return result, nil
}

func validateTitanEvent(event TitanEvent) error {
	if len(event.ID) < 8 || len(event.ID) > titanMaxEventIDBytes {
		return errors.New("Titan journal event identifier is invalid")
	}
	if event.ObservedUTC.IsZero() || len(event.Path) == 0 || len(event.Path) > titanMaxPathBytes || !filepath.IsAbs(event.Path) {
		return errors.New("Titan journal event path or time is invalid")
	}
	if !validTitanChangeType(event.ChangeType) {
		return errors.New("Titan journal event change type is invalid")
	}
	switch event.TrustState {
	case TitanTrustAuthorized, TitanTrustTolerated, TitanTrustUnexpected, TitanTrustCompromised:
	default:
		return errors.New("Titan journal event trust state is invalid")
	}
	if len(event.AuthorizationReason) > 512 || len(event.Response) > 128 || len(event.SHA256) > 64 {
		return errors.New("Titan journal event text is outside bounds")
	}
	return nil
}

// ApplyPolicy validates and atomically persists an owner policy change.
func (e *TitanEngine) ApplyPolicy(mode TitanMode, armed, autoContain bool, reason string) (TitanStatus, error) {
	if e == nil {
		return TitanStatus{}, errors.New("Titan engine unavailable")
	}
	if _, err := validateTitanReason(reason); err != nil {
		return e.Status(), err
	}
	e.mu.Lock()
	next := e.policy
	next.Mode = mode
	next.Armed = armed
	next.AutoContain = autoContain
	next.Revision++
	next.UpdatedUTC = e.now()
	if err := normalizeTitanPolicy(&next); err != nil {
		e.mu.Unlock()
		return e.Status(), err
	}
	previous := e.policy
	e.policy = next
	document := titanPolicyDocument{Schema: titanPolicySchema, Version: 1, Policy: next, SavedUTC: next.UpdatedUTC}
	payload, err := json.Marshal(document)
	e.mu.Unlock()
	if err != nil {
		e.mu.Lock()
		e.policy = previous
		e.mu.Unlock()
		return e.Status(), err
	}
	if err := atomicWriteFile(e.policyPath, append(payload, '\n'), 0o600); err != nil {
		e.mu.Lock()
		e.policy = previous
		e.mu.Unlock()
		return e.Status(), err
	}
	e.recordEvidence(EvidenceRecord{
		Severity: "high", Kind: "titan.policy.updated", Source: "titan",
		Message: fmt.Sprintf("Titan policy set to %s (armed=%t auto_contain=%t); reason-sha256=%s", next.Mode, next.Armed, next.AutoContain, titanReasonDigest(reason)),
	})
	if next.Mode != previous.Mode || next.Armed != previous.Armed {
		e.emitEvent(Event{Severity: "high", Kind: "titan.policy.updated", Source: "titan",
			Message: fmt.Sprintf("Titan policy changed from %s to %s", previous.Mode, next.Mode)})
	}
	e.signalRootsChanged()
	return e.Status(), nil
}

func validateTitanReason(reason string) (string, error) {
	trimmed := strings.TrimSpace(reason)
	if len(trimmed) < titanMinReasonBytes || len(trimmed) > titanMaxReasonBytes {
		return "", fmt.Errorf("reason must be %d-%d bytes", titanMinReasonBytes, titanMaxReasonBytes)
	}
	if !utf8Valid(trimmed) {
		return "", errors.New("reason is not valid UTF-8")
	}
	for _, character := range trimmed {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("reason contains control characters")
		}
	}
	return trimmed, nil
}

func titanReasonDigest(reason string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(reason)))
	return hex.EncodeToString(digest[:])
}

func boundedTitanText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// utf8Valid reports whether value contains no invalid UTF-8 so the policy and
// review paths share one standard-library check.
func utf8Valid(value string) bool {
	return utf8.ValidString(value)
}
