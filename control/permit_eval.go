// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// V6.3.0 AP-7: deterministic PermitV1 evaluation.
//
// Evaluation is intentionally narrow:
//   - non-suppressible (kernel-proven) rules stop the evaluation immediately;
//   - a stored permit matches only when its executable identity (SHA-256 and
//     inode), optional parent lineage and full finding scope all agree;
//   - a built-in TOLERATED profile matches only by executable basename (never
//     by a spoofable comm when an absolute executable path is known) and only
//     inside its explicit rule scope;
//   - the result can suppress or downgrade a response. It can never raise a
//     score, turn "alert" into "contain"/"kill", or authorise anything.

// permitExecutableIdentity is a resolved executable file identity.
type permitExecutableIdentity struct {
	Path       string
	Device     uint64
	Inode      uint64
	Size       int64
	ModTime    time.Time
	ChangeTime time.Time
	SHA256     string
	ValidUntil time.Time
}

func cleanPermitExecutablePath(path string) string {
	return filepath.Clean(strings.TrimSuffix(strings.TrimSpace(path), " (deleted)"))
}

// statExecutableIdentity resolves the SHA-256, device and inode of one regular
// executable file. Symlinks are refused so a permit cannot be pointed at an
// attacker-chosen target after the fact.
func statExecutableIdentity(path string, now time.Time) (permitExecutableIdentity, error) {
	clean := cleanPermitExecutablePath(path)
	if clean == "" || !filepath.IsAbs(clean) {
		return permitExecutableIdentity{}, errors.New("permit executable path is invalid")
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return permitExecutableIdentity{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return permitExecutableIdentity{}, errors.New("permit executable must be a regular non-symlink file")
	}
	if info.Size() < 0 || info.Size() > permitMaxExecutableHashBytes {
		return permitExecutableIdentity{}, errors.New("permit executable exceeds the hash bound")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return permitExecutableIdentity{}, errors.New("permit executable identity is unavailable")
	}
	digest, err := hashPermitExecutable(clean, info.Size())
	if err != nil {
		return permitExecutableIdentity{}, err
	}
	return permitExecutableIdentity{
		Path: clean, Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Size: info.Size(),
		ModTime: info.ModTime(), ChangeTime: statChangeTime(stat), SHA256: digest,
		ValidUntil: now.Add(permitExecutableHashCacheTTL),
	}, nil
}

// statChangeTime returns the inode status-change time. Unlike mtime it cannot be
// set backwards through utimensat, so a same-size executable swap invalidates a
// cached hash instead of hiding behind a forged mtime inside the cache TTL.
func statChangeTime(stat *syscall.Stat_t) time.Time {
	return time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
}

func hashPermitExecutable(path string, expectedSize int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != expectedSize {
		return "", errors.New("permit executable changed while hashing")
	}
	digest := sha256.New()
	copied, err := io.Copy(digest, io.LimitReader(file, permitMaxExecutableHashBytes+1))
	if err != nil {
		return "", err
	}
	if copied != expectedSize || copied > permitMaxExecutableHashBytes {
		return "", errors.New("permit executable changed while hashing")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// executableIdentity resolves an identity through the broker's bounded cache so
// repeated evaluations of the same toolchain do not re-hash the binary.
func (b *PermitBroker) executableIdentity(path string, now time.Time) (permitExecutableIdentity, error) {
	clean := cleanPermitExecutablePath(path)
	if clean == "" || !filepath.IsAbs(clean) {
		return permitExecutableIdentity{}, errors.New("permit executable path is invalid")
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return permitExecutableIdentity{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return permitExecutableIdentity{}, errors.New("permit executable must be a regular non-symlink file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Size() < 0 || info.Size() > permitMaxExecutableHashBytes {
		return permitExecutableIdentity{}, errors.New("permit executable identity is unavailable")
	}
	b.mu.Lock()
	cached, found := b.hashCache[clean]
	b.mu.Unlock()
	if found && cached.Device == uint64(stat.Dev) && cached.Inode == uint64(stat.Ino) &&
		cached.Size == info.Size() && cached.ModTime.Equal(info.ModTime()) &&
		cached.ChangeTime.Equal(statChangeTime(stat)) && now.Before(cached.ValidUntil) {
		return cached, nil
	}
	identity, err := statExecutableIdentity(clean, now)
	if err != nil {
		return permitExecutableIdentity{}, err
	}
	b.mu.Lock()
	if b.hashCache == nil {
		b.hashCache = make(map[string]permitExecutableIdentity)
	}
	if len(b.hashCache) >= permitExecutableHashCacheSize {
		for key, entry := range b.hashCache {
			if now.After(entry.ValidUntil) {
				delete(b.hashCache, key)
			}
		}
		if len(b.hashCache) >= permitExecutableHashCacheSize {
			clear(b.hashCache)
		}
	}
	b.hashCache[clean] = identity
	b.mu.Unlock()
	return identity, nil
}

// permitScopeCovers evaluates the full scope. Rules and categories are a strict
// whitelist: a finding that contains any rule or category outside the permit
// scope is not explained by it. This is what keeps one tolerated rule from
// suppressing an unrelated kill-eligible finding in the same decision.
func permitScopeCovers(scope PermitScope, exe string, ruleIDs, categories []string) bool {
	if len(ruleIDs) == 0 {
		return false
	}
	if len(scope.Rules) > 0 {
		for _, rule := range ruleIDs {
			covered := false
			for _, pattern := range scope.Rules {
				if permitRulePatternMatches(pattern, rule) {
					covered = true
					break
				}
			}
			if !covered {
				return false
			}
		}
	}
	if len(scope.Categories) > 0 {
		for _, category := range categories {
			covered := false
			for _, expected := range scope.Categories {
				if expected == category {
					covered = true
					break
				}
			}
			if !covered {
				return false
			}
		}
	}
	if len(scope.PathPrefixes) > 0 {
		clean := cleanPermitExecutablePath(exe)
		covered := false
		for _, prefix := range scope.PathPrefixes {
			cleanPrefix := filepath.Clean(prefix)
			if clean == cleanPrefix || strings.HasPrefix(clean, cleanPrefix+string(filepath.Separator)) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// matchStoredPermit applies the full identity/lineage/scope contract of one
// persisted permit.
func (b *PermitBroker) matchStoredPermit(p ProcessSample, ruleIDs, categories []string, permit *PermitV1, now time.Time) (*PermitDecision, bool) {
	if permit == nil || !now.Before(permit.ValidUntil) || now.Before(permit.ValidFrom) {
		return nil, false
	}
	if _, ok := permitTrustLevels[permit.TrustLevel]; !ok {
		return nil, false
	}
	exe := cleanPermitExecutablePath(p.Exe)
	if exe == "" || !filepath.IsAbs(exe) {
		return nil, false
	}
	// Cheap, non-identity gates first: this keeps executable hashing (the
	// expensive part of evaluation) limited to permits whose path and scope
	// could actually match.
	if permit.Path != "" && cleanPermitExecutablePath(permit.Path) != exe {
		return nil, false
	}
	if !permitParentMatches(permit.AllowedParents, p.ParentExe) {
		return nil, false
	}
	if !permitScopeCovers(permit.Scope, exe, ruleIDs, categories) {
		return nil, false
	}
	identity, err := b.executableIdentity(exe, now)
	if err != nil {
		return nil, false
	}
	if !strings.EqualFold(identity.SHA256, permit.SHA256) {
		return nil, false
	}
	if identity.Device != permit.Inode.Device || identity.Inode != permit.Inode.Inode {
		return nil, false
	}
	scope := stringListSummary(permit.Scope.Rules, 4)
	return &PermitDecision{
		PermitID:   permit.PermitID,
		TrustLevel: permit.TrustLevel,
		Scope:      scope,
		Reason:     "stored permit identity/lineage/scope verified",
	}, true
}

// Evaluate returns the deterministic permit decision for one finding, or nil
// when no permit applies. Stored permits are considered in permit_id order,
// then built-in profiles in profile_id order; the first full match wins.
func (b *PermitBroker) Evaluate(p ProcessSample, ruleIDs []string, categories []string) *PermitDecision {
	if b == nil || len(ruleIDs) == 0 {
		return nil
	}
	for _, ruleID := range ruleIDs {
		if nonSuppressibleRule(ruleID) {
			return nil
		}
	}
	now := b.now()
	b.mu.Lock()
	stored := make([]*PermitV1, 0, len(b.permits))
	for _, permit := range b.permits {
		stored = append(stored, permit)
	}
	builtins := append([]permitProfile(nil), b.builtins...)
	b.mu.Unlock()
	sort.Slice(stored, func(left, right int) bool { return stored[left].PermitID < stored[right].PermitID })
	sort.Slice(builtins, func(left, right int) bool { return builtins[left].PermitID < builtins[right].PermitID })
	for _, permit := range stored {
		if decision, ok := b.matchStoredPermit(p, ruleIDs, categories, permit, now); ok {
			return decision
		}
	}
	for _, profile := range builtins {
		if decision, ok := matchBuiltinProfile(p, ruleIDs, categories, profile); ok {
			return decision
		}
	}
	return nil
}

// MatchingProfileName returns the built-in profile that names this executable
// (or comm when no absolute executable path is known), for explainability only.
func (b *PermitBroker) MatchingProfileName(exe, comm string) string {
	if b == nil {
		return ""
	}
	sample := ProcessSample{Exe: exe, Comm: comm}
	b.mu.Lock()
	builtins := append([]permitProfile(nil), b.builtins...)
	b.mu.Unlock()
	for _, profile := range builtins {
		if permitProfileNamesMatch(profile, sample) {
			for _, name := range profile.Names {
				if strings.EqualFold(filepath.Base(cleanPermitExecutablePath(exe)), name) {
					return name
				}
			}
			for _, prefix := range profile.NamePrefixes {
				base := filepath.Base(cleanPermitExecutablePath(exe))
				if strings.HasPrefix(strings.ToLower(base), strings.ToLower(prefix)) {
					return base
				}
			}
			if len(profile.Names) > 0 {
				return profile.Names[0]
			}
		}
	}
	return ""
}

// applyPermitDecision enforces the suppression-only semantics on a fully
// computed rule decision: a TOLERATED / ANALYST_MODE match downgrades the
// decision to alert and leaves every score, rule ID and category untouched.
// It never raises a decision and never turns alert into contain/kill.
func applyPermitDecision(decision XDRDecision, permit *PermitDecision) XDRDecision {
	if permit == nil || permit.TrustLevel == permitTrustAuthorized {
		return decision
	}
	switch permit.TrustLevel {
	case permitTrustTolerated, permitTrustAnalyst:
		decision.Decision = "alert"
	}
	return decision
}

// evaluatePermitBroker is the engine bridge consulted before a response is
// planned in XDREngine.evaluate.
func (e *XDREngine) evaluatePermitBroker(p ProcessSample, decision XDRDecision) *PermitDecision {
	if e == nil || e.permits == nil {
		return nil
	}
	return e.permits.Evaluate(p, decision.RuleIDs, decision.Categories)
}

// recordAuthorizedPermitOutcome records the bounded info event for an
// AUTHORIZED permit that kept an expected-scope finding out of the incident
// stream. It never creates a response and never an incident. The event is
// deduplicated per process/rule/permit so repeated network scans cannot flood
// the bounded event window or the evidence ledger.
func (e *XDREngine) recordAuthorizedPermitOutcome(p ProcessSample, decision XDRDecision, permit *PermitDecision) {
	if e == nil || permit == nil {
		return
	}
	fingerprint := fmt.Sprintf(
		"permit-authorized:%d:%d:%s:%s", p.PID, p.StartTicks, permit.PermitID, strings.Join(decision.RuleIDs, ","),
	)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	message := fmt.Sprintf(
		"PermitV1 %s (AUTHORIZED) suppressed an expected-scope finding for %s pid=%d rules=%s",
		permit.PermitID, boundedPermitText(p.Comm, 64), p.PID, stringListSummary(decision.RuleIDs, 8),
	)
	if len(message) > permitMaxFieldBytes {
		message = message[:permitMaxFieldBytes] + "…"
	}
	if e.state != nil {
		e.state.AddEvent(Event{
			Severity: "info", Kind: "xdr.permit.authorized_suppressed", Source: "permit-broker",
			Message: message, Target: fmt.Sprintf("pid:%d", p.PID),
		})
	}
}

// PermitEvaluate is the exported read-only evaluation helper for future wiring
// (there is no dashboard consumer yet). It never mutates a response by itself;
// callers must apply applyPermitDecision.
func (e *XDREngine) PermitEvaluate(process ProcessSample, ruleIDs, categories []string) *PermitDecision {
	if e == nil || e.permits == nil {
		return nil
	}
	return e.permits.Evaluate(process, ruleIDs, categories)
}

// ReplayPermit re-evaluates the permit decision for an already recorded
// incident. It is a read-only helper for future wiring and never mutates the
// incident.
func (e *XDREngine) ReplayPermit(incident XDRIncident) *PermitDecision {
	if e == nil || e.permits == nil {
		return nil
	}
	sample := ProcessSample{
		PID: incident.PID, PPID: incident.PPID, StartTicks: incident.StartTicks,
		UID: incident.UID, Comm: incident.Process, Exe: incident.Executable,
		ParentExe: incident.Parent, CmdSHA256: incident.CommandSHA256,
	}
	return e.permits.Evaluate(sample, incident.RuleIDs, incident.Categories)
}

// PermitReplay is the exported read-only replay entry point.
func (e *XDREngine) PermitReplay(incident XDRIncident) *PermitDecision {
	return e.ReplayPermit(incident)
}

// verifyPermitAgainstKey is a small exported helper for future permit-minting
// wiring; it never guesses a key.
func verifyPermitAgainstKey(permit *PermitV1, key ed25519.PublicKey) error {
	return verifyPermitObject(permit, key)
}
