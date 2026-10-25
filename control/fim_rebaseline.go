// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Authorized release rebaseline.
//
// A release update legitimately replaces the files the integrity fabric
// protects: the manager's own binaries change, the shipped configuration file
// changes, and the encrypted baseline that was created for the previous release
// now reports them as deviations. Until this path existed the only ways out
// were to accept the deviation forever (the platform stays TAMPERED and the
// startup self-check keeps asking for an operator) or to bless the whole
// filesystem with a fresh baseline, which erases the evidence of every other
// change on the host at the same time.
//
// This file adds the third option: a rebaseline whose scope is a compile-time
// constant and whose preconditions are the verified release state, not a
// configuration value. It updates the release artifacts below
// /opt/vgt/gedefense/current and the explicitly named deployed configuration
// file, preserves every other baseline record untouched, and still runs a full
// verification afterwards so a deviation outside the accepted scope keeps the
// platform TAMPERED.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// fimRebaselineMaxDroppedDivisor bounds how much of the approved baseline a
// single release rebaseline may drop. A scope that would drop a larger share is
// a wrong path, not an update, and is refused before anything is written.
const fimRebaselineMaxDroppedDivisor = 4

// FIMRebaselineAuthorization is the release evidence the caller must present.
// The values come from ReleaseController.Status(); this file does not trust a
// caller's claim that a release is verified - it re-states the exact gate the
// startup supervisor applies before it re-arms.
type FIMRebaselineAuthorization struct {
	Phase             string `json:"phase"`
	FailSafeVerified  bool   `json:"fail_safe_verified"`
	KernelPolicyState string `json:"kernel_policy_state"`
	EmergencyStop     bool   `json:"emergency_stop"`
	ReleaseVersion    string `json:"release_version,omitempty"`
}

// validate enforces the release gate. Every refusal names the failing gate.
func (a FIMRebaselineAuthorization) validate() error {
	if strings.TrimSpace(a.Phase) != ReleasePhaseEnforce {
		return errors.New("release rebaseline refused: the platform is not in the enforce phase")
	}
	if !a.FailSafeVerified {
		return errors.New("release rebaseline refused: the fail-safe state is not verified")
	}
	if a.KernelPolicyState != "verified-enforce" {
		return errors.New("release rebaseline refused: kernel enforcement is not verified")
	}
	if a.EmergencyStop {
		return errors.New("release rebaseline refused: the emergency stop is active")
	}
	return nil
}

// FIMRebaselineChange is one accepted baseline transition. PreviousSHA256 is the
// old approved digest (empty for an added file) and CurrentSHA256 the new one
// (empty for a removed file); both are kept so the audit record answers "what
// exactly did the new release replace".
type FIMRebaselineChange struct {
	Path           string `json:"path"`
	State          string `json:"state"`
	PreviousSHA256 string `json:"previous_sha256,omitempty"`
	CurrentSHA256  string `json:"current_sha256,omitempty"`
}

const (
	fimRebaselineChangeUpdated = "UPDATED"
	fimRebaselineChangeAdded   = "ADDED"
	fimRebaselineChangeRemoved = "REMOVED"
)

type FIMRebaselineResult struct {
	Scope               string                `json:"scope"`
	Generation          uint64                `json:"generation"`
	ReleaseRoot         string                `json:"release_root"`
	Accepted            []FIMRebaselineChange `json:"accepted"`
	Preserved           int                   `json:"preserved"`
	RemainingDeviations int                   `json:"remaining_deviations"`
	TitanCandidatePaths []string              `json:"titan_candidate_paths,omitempty"`
	Status              FIMStatus             `json:"status"`
}

// AuditSummary is the bounded one-line form for the event journal: it names the
// number of accepted transitions and the old/new digest prefix of the first
// files, which is what an operator needs to correlate the update afterwards.
func (r FIMRebaselineResult) AuditSummary() string {
	const maxNamed = 8
	var builder strings.Builder
	fmt.Fprintf(&builder, "scope=%s generation=%d accepted=%d preserved=%d remaining_deviations=%d",
		r.Scope, r.Generation, len(r.Accepted), r.Preserved, r.RemainingDeviations)
	named := 0
	for _, change := range r.Accepted {
		if named >= maxNamed {
			builder.WriteString("; ...")
			break
		}
		fmt.Fprintf(&builder, "; %s %s:%s->%s", change.State, change.Path,
			digestPrefix(change.PreviousSHA256), digestPrefix(change.CurrentSHA256))
		named++
	}
	return boundedSummary(builder.String())
}

func digestPrefix(digest string) string {
	if digest == "" {
		return "none"
	}
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// CloneBaseline returns a defensive copy of the approved baseline. The
// rebaseline merges into the copy and only publishes it after the sealed file
// has been written, so a failed write can never leave the in-memory baseline
// ahead of the one on disk.
func (e *FIMEngine) CloneBaseline() FIMBaseline {
	if e == nil {
		return FIMBaseline{}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return cloneFIMBaseline(e.baseline)
}

// RebaselineRelease updates the approved baseline for the files a verified
// release replaced. It is intentionally narrow:
//
//   - the release gate must be verified (enforce + fail-safe verified + verified
//     kernel policy, no emergency stop);
//   - only paths below the compiled-in release root and the explicitly named
//     deployed configuration file are accepted;
//   - every other baseline record is preserved byte-for-byte;
//   - a full verification runs afterwards, so an out-of-scope deviation still
//     reports TAMPERED.
func (e *FIMEngine) RebaselineRelease(auth FIMRebaselineAuthorization, reason string) (FIMRebaselineResult, error) {
	if e == nil {
		return FIMRebaselineResult{}, errors.New("file integrity monitoring is unavailable")
	}
	reason, reasonErr := boundedRebaselineReason(reason)
	if reasonErr != nil {
		return FIMRebaselineResult{}, reasonErr
	}
	if err := auth.validate(); err != nil {
		return FIMRebaselineResult{}, err
	}
	policy := e.policySnapshot()
	if !policy.enabled {
		return FIMRebaselineResult{}, errors.New("file integrity monitoring is disabled by policy")
	}

	e.mu.RLock()
	releaseRoot := e.releaseRoot
	configPaths := append([]string(nil), e.releaseConfigPaths...)
	generation := e.baseline.Generation
	e.mu.RUnlock()
	if releaseRoot == "" {
		releaseRoot = fimReleaseRoot
	}
	releaseRoot = filepath.Clean(releaseRoot)
	if !filepath.IsAbs(releaseRoot) || releaseRoot == string(filepath.Separator) {
		return FIMRebaselineResult{}, errors.New("release root is not a bounded absolute path")
	}
	if generation == 0 {
		return FIMRebaselineResult{}, errors.New("no approved baseline exists yet; create the initial baseline instead of a release rebaseline")
	}

	if err := e.beginScan(); err != nil {
		return FIMRebaselineResult{}, err
	}
	defer e.endScan()

	files, err := e.collect()
	if err != nil {
		return e.rebaselineFault(fmt.Errorf("release rebaseline could not walk the protected roots: %w", err))
	}

	scope := make(map[string]FIMRecord, 64)
	for _, path := range files {
		if !fimRebaselinePathInScope(path, releaseRoot, configPaths) {
			continue
		}
		if len(scope) >= fimRebaselineMaxPaths {
			return FIMRebaselineResult{}, errors.New("release rebaseline scope exceeds its bounded file count")
		}
		record, hashErr := hashFIMFile(path, policy.maxFileBytes)
		if hashErr != nil {
			return e.rebaselineFault(fmt.Errorf("release rebaseline refused to trust %s: %w", path, hashErr))
		}
		scope[path] = record
	}
	if len(scope) == 0 {
		return FIMRebaselineResult{}, fmt.Errorf("no protected file is inside the release scope %s", releaseRoot)
	}

	previous := e.CloneBaseline()
	if previous.Generation != generation || !equalStrings(previous.Roots, e.Roots()) {
		return FIMRebaselineResult{}, errors.New("the approved baseline changed during the release rebaseline; retry")
	}

	next := cloneFIMBaseline(previous)
	if next.Files == nil {
		next.Files = make(map[string]FIMRecord, len(scope))
	}
	accepted := make([]FIMRebaselineChange, 0, len(scope))
	candidates := make([]string, 0, len(scope))
	for path, record := range scope {
		oldRecord, existed := previous.Files[path]
		if existed && oldRecord.SHA256 == record.SHA256 && oldRecord.Size == record.Size && oldRecord.Mode == record.Mode {
			continue
		}
		change := FIMRebaselineChange{Path: path, CurrentSHA256: record.SHA256, State: fimRebaselineChangeAdded}
		if existed {
			change.State = fimRebaselineChangeUpdated
			change.PreviousSHA256 = oldRecord.SHA256
		}
		accepted = append(accepted, change)
		candidates = append(candidates, path)
		next.Files[path] = record
	}
	for path, oldRecord := range previous.Files {
		if _, stillPresent := scope[path]; stillPresent {
			continue
		}
		if !fimRebaselinePathInScope(path, releaseRoot, configPaths) {
			continue
		}
		delete(next.Files, path)
		accepted = append(accepted, FIMRebaselineChange{
			Path: path, State: fimRebaselineChangeRemoved, PreviousSHA256: oldRecord.SHA256,
		})
		candidates = append(candidates, path)
	}
	if len(accepted) == 0 {
		return e.rebaselineFault(errors.New("no release artifact differs from the approved baseline; nothing to rebaseline"))
	}
	if len(accepted) > fimRebaselineMaxPaths {
		return FIMRebaselineResult{}, errors.New("release rebaseline accepted set exceeds its bounded file count")
	}
	removed := 0
	for _, change := range accepted {
		if change.State == fimRebaselineChangeRemoved {
			removed++
		}
	}
	if removed > len(previous.Files)/fimRebaselineMaxDroppedDivisor {
		return FIMRebaselineResult{}, errors.New("release rebaseline would drop too much of the approved baseline; check the release root")
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].Path < accepted[j].Path })
	sort.Strings(candidates)

	next.Schema = fimBaselineSchema
	next.Generation = previous.Generation + 1
	next.CreatedAt = time.Now().UTC()
	next.Roots = append([]string(nil), previous.Roots...)
	plaintext, encodeErr := json.Marshal(next)
	if encodeErr != nil {
		return FIMRebaselineResult{}, fmt.Errorf("release rebaseline could not encode the baseline: %w", encodeErr)
	}
	if int64(len(plaintext)) > policy.maxBaselineBytes {
		return FIMRebaselineResult{}, errors.New("release rebaseline baseline exceeds the configured byte boundary")
	}
	if _, decodeErr := decodeFIMBaseline(plaintext, policy); decodeErr != nil {
		return FIMRebaselineResult{}, fmt.Errorf("release rebaseline produced an invalid baseline: %w", decodeErr)
	}
	sealed, sealErr := e.storage.Encrypt(e.baselinePath, fimPurpose, next.Generation, plaintext)
	if sealErr != nil {
		return e.rebaselineFault(fmt.Errorf("release rebaseline could not seal the baseline: %w", sealErr))
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(e.baselinePath), 0o700); mkdirErr != nil {
		return e.rebaselineFault(fmt.Errorf("release rebaseline could not prepare the baseline directory: %w", mkdirErr))
	}
	if writeErr := atomicWriteFile(e.baselinePath, sealed, 0o600); writeErr != nil {
		return e.rebaselineFault(fmt.Errorf("release rebaseline could not persist the baseline: %w", writeErr))
	}

	e.mu.Lock()
	e.baseline = next
	e.integrityErr = nil
	e.lastScan = nil
	e.mu.Unlock()

	summary, scanErr := e.scanLocked()
	if scanErr != nil {
		return e.rebaselineFault(fmt.Errorf("post-rebaseline verification failed: %w", scanErr))
	}
	result := FIMRebaselineResult{
		Scope:               fimRebaselineScopeRelease,
		Generation:          next.Generation,
		ReleaseRoot:         releaseRoot,
		Accepted:            accepted,
		Preserved:           len(next.Files) - len(scope),
		TitanCandidatePaths: candidates,
		Status:              e.Status(),
	}
	result.RemainingDeviations = summary.Tampered + summary.Missing + summary.New + summary.Errors
	return result, nil
}

// rebaselineFault records a failed rebaseline as the engine's integrity fault so
// the status cannot keep claiming the previous verification was current, and
// returns the error unchanged.
func (e *FIMEngine) rebaselineFault(err error) (FIMRebaselineResult, error) {
	e.setFault(err)
	return FIMRebaselineResult{}, err
}

func boundedRebaselineReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < fimRebaselineMinReasonBytes {
		return "", fmt.Errorf("release rebaseline requires a reason of at least %d characters", fimRebaselineMinReasonBytes)
	}
	if len([]rune(reason)) > fimRebaselineMaxReasonBytes {
		reason = string([]rune(reason)[:fimRebaselineMaxReasonBytes])
	}
	if strings.ContainsRune(reason, '\x00') {
		return "", errors.New("release rebaseline reason contains an invalid character")
	}
	return reason, nil
}

// fimRebaselinePathInScope is the whole scope definition in one pure function:
// a path is accepted iff it is below the release root or exactly one of the
// named deployed configuration files.
func fimRebaselinePathInScope(path, releaseRoot string, configPaths []string) bool {
	clean := filepath.Clean(path)
	for _, configPath := range configPaths {
		if clean == filepath.Clean(configPath) {
			return true
		}
	}
	root := filepath.Clean(releaseRoot)
	if root == "." || root == string(filepath.Separator) {
		return false
	}
	return strings.HasPrefix(clean, root+string(filepath.Separator))
}
