// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Titan trust evaluation and response policy.
//
// The evaluation answers exactly one question: was this observed change covered
// by owner authorization evidence? It never names an actor. Package ownership,
// FIM baselines, protected paths, the explicit allowlist and development roots
// are the evidence sources; a temporal XDR correlation is a risk input, not an
// attribution and not proof of causation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type titanFileIdentity struct {
	Path     string
	SHA256   string
	Size     int64
	FileMode string
	Exists   bool
	Regular  bool
	Symlink  bool
	Readable bool
	Error    string
}

// readTitanIdentity reads bounded, non-symlink file identity. It never follows a
// symlink and never trusts a file that changed while it was being read.
func readTitanIdentity(path string, maxBytes int64) titanFileIdentity {
	identity := titanFileIdentity{Path: filepath.Clean(path)}
	if !filepath.IsAbs(path) || len(path) > titanMaxPathBytes || strings.ContainsRune(path, '\x00') {
		identity.Error = "path is not a bounded absolute path"
		return identity
	}
	before, err := os.Lstat(identity.Path)
	if err != nil {
		identity.Error = "object could not be inspected"
		return identity
	}
	identity.Exists = true
	identity.Symlink = before.Mode()&os.ModeSymlink != 0
	if identity.Symlink {
		identity.Error = "object is a symlink; content authorization is impossible"
		return identity
	}
	if !before.Mode().IsRegular() {
		identity.Error = "object is not a regular file"
		return identity
	}
	identity.Regular = true
	if before.Size() < 0 || before.Size() > maxBytes {
		identity.Size = before.Size()
		identity.Error = "object exceeds the bounded hash size"
		return identity
	}
	file, err := os.Open(identity.Path)
	if err != nil {
		identity.Size = before.Size()
		identity.Error = "object could not be opened for hashing"
		return identity
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		identity.Error = "object identity changed before hashing"
		return identity
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maxBytes+1))
	if err != nil || written != before.Size() {
		identity.Size = before.Size()
		identity.Error = "object changed while hashing"
		return identity
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		identity.Error = "object identity changed while hashing"
		return identity
	}
	identity.SHA256 = hex.EncodeToString(digest.Sum(nil))
	identity.Size = after.Size()
	identity.FileMode = after.Mode().Perm().String()
	identity.Readable = true
	return identity
}

// titanPathWithinRoots reports whether path is inside one of the roots.
func titanPathWithinRoots(path string, roots []string) bool {
	path = filepath.Clean(path)
	for _, root := range roots {
		if titanPathUnder(path, root) {
			return true
		}
	}
	return false
}

// titanPathUnder is a component-aware prefix check; "/var/www2" is not inside
// "/var/www".
func titanPathUnder(path, root string) bool {
	path, root = filepath.Clean(path), filepath.Clean(root)
	if path == root {
		return true
	}
	if root == string(filepath.Separator) {
		return strings.HasPrefix(path, root)
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

// titanBuiltinProtected lists the security-critical system areas whose change
// always needs independent evidence. The allowlist cannot authorize these on its
// own; they still fall through to baseline and package evidence.
var titanBuiltinProtected = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/pam.d",
	"/etc/security",
	"/etc/ssh",
	"/etc/ld.so.preload",
	"/etc/audit",
	"/etc/auditd.conf",
	"/etc/selinux",
	"/etc/apparmor.d",
	"/etc/systemd",
	"/lib/systemd",
	"/usr/lib/systemd",
	"/boot",
}

// titanBuiltinContainDeny keeps containment away from objects whose relocation
// would break or destabilise the running system. Titan fails closed with a
// reason instead.
var titanBuiltinContainDeny = []string{
	"/proc",
	"/sys",
	"/dev",
	"/run",
	"/boot",
	"/usr/lib/modules",
	"/lib/modules",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/ld.so.preload",
}

func titanPathProtected(path string, configured []string) bool {
	if titanPathWithinRoots(path, configured) {
		return true
	}
	return titanPathWithinRoots(path, titanBuiltinProtected)
}

func titanPathMatchesAllowlist(path string, allowlist []string) bool {
	return titanPathWithinRoots(path, allowlist)
}

// evaluateTrust applies the documented evidence ladder. Missing evidence lowers
// trust; only explicit owner authorization can raise it.
func (e *TitanEngine) evaluateTrust(event *TitanEvent, observation titanObservation, policy titanPolicy, identity titanFileIdentity) {
	event.Mode = policy.Mode
	event.ChangeType = observation.ChangeType
	protected := titanPathProtected(event.Path, policy.ProtectedPaths)
	rooted := titanPathWithinRoots(event.Path, policy.Roots)
	allowlisted := titanPathMatchesAllowlist(event.Path, policy.Allowlist)
	devRoot := titanPathWithinRoots(event.Path, policy.DevelopmentRoots)
	criticalProtected := titanPathWithinRoots(event.Path, titanBuiltinProtected)
	temporalContext := event.CorrelationQuality == TitanCorrelationTemporal
	removed := observation.ChangeType == TitanChangeRemoved
	identityUsable := identity.Regular && !identity.Symlink && identity.SHA256 != ""

	var (
		baseline        FIMRecord
		baselineKnown   bool
		baselineMatches bool
	)
	if e.deps.FIM != nil && identityUsable {
		baseline, _, baselineKnown = e.deps.FIM.TitanBaselineRecord(event.Path)
		baselineMatches = baselineKnown && baseline.SHA256 == identity.SHA256
	}

	// The allowlist authorizes an explicit path, but never a security-critical
	// system object: those always need content/package evidence.
	if allowlisted && !criticalProtected && !identity.Symlink && identity.Regular {
		event.TrustState = TitanTrustAuthorized
		if removed {
			event.TrustState = TitanTrustUnexpected
			event.AuthorizationReason = "allowlisted object was removed; removal is not covered by a path allowlist"
		} else {
			event.AuthorizationReason = "path is explicitly allowlisted by the owner policy"
		}
		setTitanSeverity(event, protected)
		return
	}
	if baselineMatches && !removed {
		event.TrustState = TitanTrustAuthorized
		event.AuthorizationReason = "content matches the approved encrypted FIM baseline"
		setTitanSeverity(event, protected)
		return
	}
	if !rooted {
		event.TrustState = TitanTrustUnexpected
		event.AuthorizationReason = "observed path is outside the configured Titan roots"
		setTitanSeverity(event, protected)
		return
	}

	var (
		owner       titanPackageOwner
		owned       bool
		packageNote string
	)
	if e.deps.Packages != nil && !allowlisted {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		owner, owned, _ = e.deps.Packages.Owner(ctx, event.Path)
		cancel()
		if owned {
			packageNote = "installed package " + owner.Package + " (" + owner.Manager + ")"
		}
	}

	baselineDeviation := baselineKnown && !baselineMatches
	switch {
	case baselineDeviation && owned:
		event.TrustState = TitanTrustUnexpected
		event.AuthorizationReason = "package-owned path differs from the approved FIM baseline (" + packageNote + ")"
	case baselineDeviation && protected:
		if temporalContext {
			event.TrustState = TitanTrustCompromised
			event.AuthorizationReason = "security-critical path deviates from the approved baseline with a temporally correlated XDR incident"
		} else {
			event.TrustState = TitanTrustUnexpected
			event.AuthorizationReason = "security-critical path deviates from the approved FIM baseline"
		}
	case baselineDeviation:
		event.TrustState = TitanTrustUnexpected
		event.AuthorizationReason = "path differs from the approved FIM baseline"
	case owned:
		event.TrustState = TitanTrustTolerated
		event.AuthorizationReason = "path is owned by " + packageNote + " but has no approved baseline or allowlist entry"
	case devRoot && !protected:
		event.TrustState = TitanTrustTolerated
		event.AuthorizationReason = "change is inside a configured development root; development context is not an owner authorization"
	case protected && !baselineKnown && temporalContext:
		event.TrustState = TitanTrustCompromised
		event.AuthorizationReason = "security-critical path has no approved baseline and changed during a temporally correlated XDR incident"
	case protected && !baselineKnown:
		event.TrustState = TitanTrustUnexpected
		event.AuthorizationReason = "security-critical path has no approved baseline and no explicit allowlist entry"
	case removed:
		event.TrustState = TitanTrustUnexpected
		event.AuthorizationReason = "object was removed without an approved baseline authorizing the removal"
	case !identityUsable:
		event.TrustState = TitanTrustUnexpected
		event.AuthorizationReason = "object content could not be verified: " + firstNonEmpty(identity.Error, "missing file identity")
	default:
		event.TrustState = TitanTrustUnexpected
		event.AuthorizationReason = "no approved baseline, allowlist entry or package ownership evidence exists"
	}

	// A symlink or non-regular object can never be authorized by content.
	if event.TrustState == TitanTrustAuthorized && (!identity.Regular || identity.Symlink) {
		event.TrustState = TitanTrustUnexpected
		event.AuthorizationReason = "object is a symlink or not a regular file; content authorization is impossible"
	}
	if event.TrustState == TitanTrustAuthorized && !identityUsable && removed {
		event.TrustState = TitanTrustUnexpected
	}
	setTitanSeverity(event, protected)
}

func setTitanSeverity(event *TitanEvent, protected bool) {
	switch event.TrustState {
	case TitanTrustCompromised:
		event.Severity = "critical"
	case TitanTrustUnexpected:
		if protected {
			event.Severity = "high"
		} else {
			event.Severity = "medium"
		}
	case TitanTrustTolerated:
		event.Severity = "low"
	case TitanTrustAuthorized:
		event.Severity = "info"
	default:
		event.Severity = "medium"
	}
}

// applyResponse maps trust state + mode + armed/auto-containment to one explicit
// response. It never claims containment that did not verify.
func (e *TitanEngine) applyResponse(event *TitanEvent, policy titanPolicy) {
	event.Response = TitanResponseObserved
	switch policy.Mode {
	case TitanModeObserve:
		return
	case TitanModeStrict:
		switch event.TrustState {
		case TitanTrustAuthorized:
			event.Response = TitanResponseObserved
		case TitanTrustTolerated:
			event.Response = TitanResponseReviewRequired
		default:
			e.tryAutoContain(event, policy)
			if event.Response != TitanResponseContained {
				event.Response = TitanResponseReviewRequired
			}
		}
	default:
		switch event.TrustState {
		case TitanTrustAuthorized, TitanTrustTolerated:
			event.Response = TitanResponseObserved
		default:
			e.tryAutoContain(event, policy)
		}
	}
}

func (e *TitanEngine) tryAutoContain(event *TitanEvent, policy titanPolicy) {
	if !policy.Armed || !policy.AutoContain {
		event.Response = TitanResponseNoAction
		event.Containment = "NOT_REQUESTED"
		event.ContainmentDetail = "auto-containment requires policy mode CONTAIN/STRICT, armed=true and auto_contain=true"
		return
	}
	if e.deps.Containment == nil {
		event.Response = TitanResponseContainUnavailable
		event.Containment = "UNAVAILABLE"
		event.ContainmentDetail = "privileged quarantine core is unavailable"
		return
	}
	if err := e.validateTitanContainSafePath(event.Path); err != nil {
		event.Response = TitanResponseContainUnavailable
		event.Containment = "UNAVAILABLE"
		event.ContainmentDetail = err.Error()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reason := "Titan automatic containment of an " + event.TrustState.String() + " change"
	result, err := e.deps.Containment.RequestContain(ctx, event.Path, reason)
	if err != nil {
		event.Response = TitanResponseContainFailed
		event.Containment = "FAILED"
		event.ContainmentDetail = "quarantine transaction rejected: " + boundedTitanText(err.Error(), 200)
		e.recordEvidence(EvidenceRecord{
			Severity: "critical", Kind: "titan.auto_contain.failed", Source: "titan",
			Message: "Automatic Titan containment failed closed", Target: event.Path,
		})
		return
	}
	event.Response = TitanResponseContained
	event.Containment = "CONTAINED"
	event.QuarantineID = result.TransactionID
	event.ContainmentDetail = "quarantined by verified transaction " + result.TransactionID
	e.recordEvidence(EvidenceRecord{
		Severity: "critical", Kind: "titan.auto_contained", Source: "titan",
		Message: "Automatic Titan containment completed through the quarantine transaction engine",
		Target:  event.Path,
	})
}

// validateTitanContainSafePath is the fail-closed precondition for containment.
// It never deletes, never follows links, and refuses the platform's own state
// documents and objects whose relocation would break the host.
func (e *TitanEngine) validateTitanContainSafePath(path string) error {
	if len(path) == 0 || len(path) > titanMaxPathBytes || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return errors.New("containment path is not a bounded absolute path")
	}
	clean := filepath.Clean(path)
	if clean != path {
		return errors.New("containment path is not canonical")
	}
	if clean == string(filepath.Separator) {
		return errors.New("filesystem root cannot be contained")
	}
	e.mu.RLock()
	policy := e.policy
	journalPath, policyPath := e.journalPath, e.policyPath
	e.mu.RUnlock()
	if !titanPathWithinRoots(clean, policy.Roots) {
		return errors.New("containment path is outside the configured Titan roots")
	}
	if clean == filepath.Clean(journalPath) || clean == filepath.Clean(policyPath) {
		return errors.New("Titan state documents cannot be contained")
	}
	for _, denied := range titanBuiltinContainDeny {
		if titanPathUnder(clean, denied) {
			return errors.New("system-critical object is excluded from automatic containment; operator review is required")
		}
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return errors.New("containment object is not present for a safe transaction")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("containment refuses a symlink target")
	}
	if !info.Mode().IsRegular() {
		return errors.New("containment requires a regular file")
	}
	if info.Size() < 0 || info.Size() > policy.MaxFileBytes {
		return errors.New("containment object exceeds the bounded size")
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
