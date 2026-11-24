// AP-9 / S09 — local semantic anti-poisoning guard that runs *before* a feed
// or rule document is activated, even when the document carries valid
// signatures.
//
// Signatures prove who published a document; they do not prove that the
// document is a safe evolution of what the host is already enforcing. A
// compromised or coerced publisher can sign a document that deletes the whole
// protection generation, whitelists the world, injects an exception for a
// system path, or ships a regular expression that is expensive or
// non-compiling. The TUF envelope cannot see that, so this guard compares the
// candidate document with the currently active one:
//
//   a. Diff budget: a candidate must not delete/deactivate more than 20 % of
//      the currently active protection entries (integer math: deleted*5 > total
//      rejects, so exactly 20 % is accepted). An empty previous set is the
//      bootstrap case and is allowed.
//   b. Immutable protection zone: protection entries that target sshd, systemd
//      units, kernel images/modules, GeDefense/VGT own components, or any root
//      inside CORE_QUARANTINE_FORBIDDEN_ROOTS may never be deleted or
//      deactivated by a feed update.
//   c. No global allow: a new allow/ignore entry that is 0.0.0.0/0, ::/0, *,
//      "any", an empty wildcard, or an allowlist entry for the immutable zone
//      is rejected (the latter with the explicit system-path-inject reason).
//   d. RE2 linear-complexity budget: every new/changed regex rule must compile
//      with the standard library regexp (RE2) and stay inside a deterministic,
//      documented budget (length, group nesting, bounded repetition, nested
//      repetition amplification).
//
// The guard is deliberately independent of the XDR runtime structs: it operates
// on a small normalized model so the feed pipeline, advisory pipeline and any
// future rule-document pipeline can all be screened by the same code. The
// concrete feed adapter lives in feeds.go; which artifacts are covered is
// documented on tufFeedProtectionSnapshot.
//
// Every rejection is a *TUFError with a stable reason code, so it can be logged
// and surfaced as a bounded state event without exposing URLs or keys.

package main

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"
)

// TUFProtectionKind classifies one normalized protection entry.
type TUFProtectionKind string

const (
	TUFKindBlockPrefix TUFProtectionKind = "block_prefix"
	TUFKindBlockHost   TUFProtectionKind = "block_host"
	TUFKindBlockPath   TUFProtectionKind = "block_path"
	TUFKindBlockHash   TUFProtectionKind = "block_hash"
	TUFKindRegexRule   TUFProtectionKind = "regex_rule"
	TUFKindServiceUnit TUFProtectionKind = "service_unit"
	TUFKindAllowHost   TUFProtectionKind = "allow_host"
	TUFKindAllowPath   TUFProtectionKind = "allow_path"
	TUFKindAllowPrefix TUFProtectionKind = "allow_prefix"
	TUFKindIntel       TUFProtectionKind = "intel"
	TUFKindOther       TUFProtectionKind = "other"
)

// TUFProtectionEntry is one normalized protection entry. It is intentionally
// free of XDR runtime types: ID is the stable identity across generations,
// Scope/Host/Pattern carry the target vocabulary of the producing pipeline.
type TUFProtectionEntry struct {
	ID         string
	Kind       TUFProtectionKind
	Scope      string
	Pattern    string
	Host       string
	Allow      bool
	FeedOrigin string
	Active     bool
}

// TUFProtectionSnapshot is the normalized document the guard compares: the
// previously active one and the candidate one.
type TUFProtectionSnapshot struct {
	ID      string
	Origin  string
	Entries []TUFProtectionEntry
}

// TUFSemanticGuardLimits bounds the guard's parsing and complexity work. The
// zero value is normalised to the documented S09 defaults.
type TUFSemanticGuardLimits struct {
	MaxEntries            int
	MaxDeletionPercent    int
	RegexMaxLength        int
	RegexMaxNesting       int
	RegexMaxRepeat        int
	RegexMaxAmplification int
	MaxFieldBytes         int
}

// DefaultTUFSemanticGuardLimits returns the immutable S09 defaults. The 20 %
// diff budget is a hard product invariant: a caller may tighten it, never
// raise it past 20.
func DefaultTUFSemanticGuardLimits() TUFSemanticGuardLimits {
	return TUFSemanticGuardLimits{
		MaxEntries:            250000,
		MaxDeletionPercent:    20,
		RegexMaxLength:        1024,
		RegexMaxNesting:       12,
		RegexMaxRepeat:        1024,
		RegexMaxAmplification: 1024,
		MaxFieldBytes:         4096,
	}
}

func (l TUFSemanticGuardLimits) normalised() TUFSemanticGuardLimits {
	defaults := DefaultTUFSemanticGuardLimits()
	if l.MaxEntries <= 0 || l.MaxEntries > defaults.MaxEntries {
		l.MaxEntries = defaults.MaxEntries
	}
	if l.MaxDeletionPercent <= 0 || l.MaxDeletionPercent > defaults.MaxDeletionPercent {
		l.MaxDeletionPercent = defaults.MaxDeletionPercent
	}
	if l.RegexMaxLength <= 0 || l.RegexMaxLength > defaults.RegexMaxLength {
		l.RegexMaxLength = defaults.RegexMaxLength
	}
	if l.RegexMaxNesting <= 0 || l.RegexMaxNesting > defaults.RegexMaxNesting {
		l.RegexMaxNesting = defaults.RegexMaxNesting
	}
	if l.RegexMaxRepeat <= 0 || l.RegexMaxRepeat > defaults.RegexMaxRepeat {
		l.RegexMaxRepeat = defaults.RegexMaxRepeat
	}
	if l.RegexMaxAmplification <= 0 || l.RegexMaxAmplification > defaults.RegexMaxAmplification {
		l.RegexMaxAmplification = defaults.RegexMaxAmplification
	}
	if l.MaxFieldBytes <= 0 || l.MaxFieldBytes > defaults.MaxFieldBytes {
		l.MaxFieldBytes = defaults.MaxFieldBytes
	}
	return l
}

// tufImmutableForbiddenRoots mirrors CORE_QUARANTINE_FORBIDDEN_ROOTS from
// rust/gedefense-core/src/quarantine.rs (read-only reference, grep-able by the
// security audit). The control plane and the Linux core must never disagree
// about which system roots are untouchable, and a feed update must never be
// able to revoke protection for one of them.
var tufImmutableForbiddenRoots = []string{
	"/proc", "/sys", "/run", "/boot", "/bin", "/sbin",
	"/lib", "/lib64", "/lib32", "/libx32", "/usr", "/etc",
	"/var/lib/vgt", "/etc/vgt", "/opt/vgt",
}

// tufImmutableSentinelPatterns are the explicit targets named by S09 that must
// stay protected even when a rule expresses them as a substring/regex rather
// than as a normalized absolute path.
var tufImmutableSentinelPatterns = []string{
	"/usr/sbin/sshd", "/usr/bin/sshd",
	"systemd", ".service", ".socket",
	"gedefense", "vgt-", "/vgt/",
	"vmlinuz", "/lib/modules", "kernel.",
}

// tufIsProtectionKind reports whether an entry is part of the active protection
// generation (and therefore counts against the diff budget).
func tufIsProtectionKind(kind TUFProtectionKind) bool {
	switch kind {
	case TUFKindBlockPrefix, TUFKindBlockHost, TUFKindBlockPath, TUFKindBlockHash,
		TUFKindRegexRule, TUFKindServiceUnit:
		return true
	default:
		return false
	}
}

func tufIsAllowKind(kind TUFProtectionKind) bool {
	switch kind {
	case TUFKindAllowHost, TUFKindAllowPath, TUFKindAllowPrefix:
		return true
	default:
		return false
	}
}

// tufEntryIsAllow reports whether the entry grants a protection exception.
func tufEntryIsAllow(entry TUFProtectionEntry) bool {
	return entry.Allow || tufIsAllowKind(entry.Kind)
}

// tufEntryTargets extracts the absolute path-like targets of an entry.
func tufEntryTargets(entry TUFProtectionEntry) []string {
	candidates := make([]string, 0, 3)
	for _, value := range []string{entry.Scope, entry.Host, entry.Pattern} {
		trimmed := strings.TrimSpace(value)
		if strings.HasPrefix(trimmed, "/") {
			candidates = append(candidates, path.Clean(trimmed))
		}
	}
	return candidates
}

// tufImmutablePathReason returns the immutable-zone reason for one absolute
// path, or "" when the path is not in the zone. It mirrors the Rust core path
// boundary plus the explicit S09 targets.
func tufImmutablePathReason(cleaned string) string {
	if cleaned == "/dev" || (strings.HasPrefix(cleaned, "/dev/") && !strings.HasPrefix(cleaned, "/dev/shm")) {
		return "forbidden device root"
	}
	for _, root := range tufImmutableForbiddenRoots {
		if cleaned == root || strings.HasPrefix(cleaned, root+"/") {
			return "forbidden system or control root " + root
		}
	}
	lower := strings.ToLower(cleaned)
	if strings.Contains(lower, "systemd") || strings.HasSuffix(lower, ".service") || strings.HasSuffix(lower, ".socket") {
		return "systemd unit"
	}
	for _, sentinel := range []string{"/usr/sbin/sshd", "/usr/bin/sshd", "vmlinuz", "/lib/modules", "kernel."} {
		if strings.Contains(lower, sentinel) {
			return "explicit S09 protected target " + sentinel
		}
	}
	return ""
}

// tufImmutableTextReason scans arbitrary entry text (scope, pattern, id) for
// sentinels that name the immutable zone. This is deliberately conservative:
// a feed deleting a rule that mentions the kernel, systemd, sshd or the
// GeDefense/VGT components is exactly the outcome S09 must block.
func tufImmutableTextReason(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	lower := strings.ToLower(text)
	for _, sentinel := range tufImmutableSentinelPatterns {
		if strings.Contains(lower, strings.ToLower(sentinel)) {
			return "protected target " + sentinel
		}
	}
	return ""
}

// tufImmutableEntryReason reports whether an entry touches the immutable zone.
func tufImmutableEntryReason(entry TUFProtectionEntry) string {
	for _, target := range tufEntryTargets(entry) {
		if reason := tufImmutablePathReason(target); reason != "" {
			return reason
		}
	}
	if entry.Kind == TUFKindServiceUnit {
		return "service unit protection is immutable"
	}
	for _, value := range []string{entry.Scope, entry.Pattern, entry.ID} {
		if reason := tufImmutableTextReason(value); reason != "" {
			return reason
		}
	}
	return ""
}

// tufGlobalAllowReason detects a protection exception that would exempt all
// traffic/targets. It returns a stable detail string, or "" for a scoped entry.
func tufGlobalAllowReason(entry TUFProtectionEntry) string {
	targets := []string{entry.Host, entry.Scope, entry.Pattern}
	emptyHost := entry.Kind == TUFKindAllowHost && strings.TrimSpace(entry.Host) == ""
	allEmpty := strings.TrimSpace(entry.Host) == "" && strings.TrimSpace(entry.Scope) == "" && strings.TrimSpace(entry.Pattern) == ""
	if emptyHost || allEmpty {
		return "empty host wildcard"
	}
	for _, raw := range targets {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		switch lower {
		case "*", "any", "all", "0.0.0.0", "::", "0.0.0.0/0", "::/0", "0/0":
			return "global wildcard target " + lower
		}
		if prefix, err := netip.ParsePrefix(lower); err == nil && prefix.Bits() == 0 {
			return "global network prefix " + lower
		}
		if addr, err := netip.ParseAddr(lower); err == nil && addr.IsUnspecified() {
			return "unspecified address " + lower
		}
	}
	return ""
}

// validateTUFProtectionEntry validates one candidate entry.
func validateTUFProtectionEntry(entry TUFProtectionEntry, limits TUFSemanticGuardLimits) error {
	if strings.TrimSpace(entry.ID) == "" {
		return newTUFError(TUFReasonSchema, "protection entry has no stable id")
	}
	for _, field := range []string{entry.ID, entry.Scope, entry.Host, entry.Pattern, entry.FeedOrigin} {
		if len(field) > limits.MaxFieldBytes {
			return newTUFError(TUFReasonEntryBudget, "protection entry field exceeds the bounded size")
		}
		for index := 0; index < len(field); index++ {
			if c := field[index]; c < 0x20 || c == 0x7f {
				return newTUFError(TUFReasonSchema, "protection entry contains a control character")
			}
		}
	}
	if tufEntryIsAllow(entry) {
		if reason := tufGlobalAllowReason(entry); reason != "" {
			return newTUFError(TUFReasonGlobalAllow, reason)
		}
		if reason := tufImmutableEntryReason(entry); reason != "" {
			return newTUFError(TUFReasonSystemPathInject, reason)
		}
		if len(entry.FeedOrigin) == 0 {
			return newTUFError(TUFReasonSystemPathInject, "protection exception has no trusted origin")
		}
	}
	if entry.Kind == TUFKindRegexRule || strings.TrimSpace(entry.Pattern) != "" {
		if err := validateTUFRegexPattern(entry.Pattern, limits); err != nil {
			return err
		}
	}
	return nil
}

// GuardTUFProtectionUpdate is the local semantic anti-poisoning gate. It
// compares the previously active protection generation with the candidate one
// and returns a typed *TUFError for the first violated rule in deterministic
// order: structural validation, immutable-zone deletion, diff budget.
func GuardTUFProtectionUpdate(previous, next TUFProtectionSnapshot, limits TUFSemanticGuardLimits) error {
	limits = limits.normalised()
	if len(previous.Entries) > limits.MaxEntries || len(next.Entries) > limits.MaxEntries {
		return newTUFError(TUFReasonEntryBudget, "protection document exceeds the bounded entry count")
	}
	nextByID := make(map[string]TUFProtectionEntry, len(next.Entries))
	for _, entry := range next.Entries {
		if _, duplicate := nextByID[entry.ID]; duplicate {
			return newTUFError(TUFReasonSchema, "duplicate protection entry id rejected")
		}
		nextByID[entry.ID] = entry
	}
	for _, entry := range next.Entries {
		if err := validateTUFProtectionEntry(entry, limits); err != nil {
			return err
		}
	}
	// Immutable zone: a currently active protection entry may never disappear.
	for _, entry := range previous.Entries {
		if !entry.Active || !tufIsProtectionKind(entry.Kind) {
			continue
		}
		if retained, ok := nextByID[entry.ID]; ok && retained.Active {
			continue
		}
		if reason := tufImmutableEntryReason(entry); reason != "" {
			return newTUFError(TUFReasonImmutableZone,
				"feed update would delete or deactivate an immutable protection entry ("+reason+")")
		}
	}
	// Diff budget: integer math, exactly 20 % is accepted, more is rejected.
	total := 0
	deleted := 0
	for _, entry := range previous.Entries {
		if !entry.Active || !tufIsProtectionKind(entry.Kind) {
			continue
		}
		total++
		if retained, ok := nextByID[entry.ID]; !ok || !retained.Active {
			deleted++
		}
	}
	if total > 0 && deleted*100 > total*limits.MaxDeletionPercent {
		return newTUFError(TUFReasonDiffBudget,
			fmt.Sprintf("feed update deletes %d of %d active protection entries (limit %d%%)",
				deleted, total, limits.MaxDeletionPercent))
	}
	return nil
}

// TUFSecurityStatus is the honest, bounded projection of the S09 posture. It is
// attached to the feed telemetry so the dashboard, journal and tests can see
// the capability state, the epoch, blocked-update counters and the R5 isolation
// mode without reading any secret.
type TUFSecurityStatus struct {
	Capability          string            `json:"capability"` // available | unavailable
	Reason              string            `json:"reason,omitempty"`
	Threshold           string            `json:"threshold"`
	Roles               []string          `json:"roles"`
	EnvelopeSchema      string            `json:"envelope_schema"`
	Epoch               uint64            `json:"epoch"`
	LastKnownGoodSHA256 string            `json:"last_known_good_sha256,omitempty"`
	LastActivatedAt     time.Time         `json:"last_activated_at,omitempty"`
	BlockedUpdates      uint64            `json:"blocked_updates"`
	LastBlockedReason   string            `json:"last_blocked_reason,omitempty"`
	LastBlockedAt       time.Time         `json:"last_blocked_at,omitempty"`
	StateError          string            `json:"state_error,omitempty"`
	R5Isolation         string            `json:"r5_isolation"`        // shadow (interim, in-process)
	R5HelperIsolation   string            `json:"r5_helper_isolation"` // helper-pending (R5 gap)
	RecentBlocked       []TUFBlockedEvent `json:"recent_blocked,omitempty"`
}

// TUFBlockedEvent is one bounded anti-poisoning rejection record.
type TUFBlockedEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Reason string    `json:"reason"`
	FeedID string    `json:"feed_id,omitempty"`
}

// Isolation projection values. The Rust cell-helper protocol can already run a
// pinned parser inside a sandboxed cell, but it has no feed/rule-bundle profile
// or bounded structured-IR contract yet, so the interim mitigation is the
// Go-side shadow parse (see tuf_shadow.go). Both facts are reported separately
// instead of claiming a helper isolation that is not wired.
const (
	TUFR5IsolationShadow     = "shadow"
	TUFR5HelperPending       = "helper-pending"
	TUFCapabilityAvailable   = "available"
	TUFCapabilityUnavailable = "unavailable"
)

// TUFBlockedStateEvent builds the state event for an anti-poisoning rejection.
// The message carries only the stable reason code: no URLs, keys or feed
// credentials are ever placed into an event.
func TUFBlockedStateEvent(reason, feedID string, at time.Time) Event {
	return Event{
		Severity: "high",
		Kind:     "feed.poisoning_blocked",
		Source:   "intelligence",
		Time:     at.UTC(),
		Target:   feedID,
		Message:  "Threat feed update blocked by the S09 anti-poisoning guard: " + reason,
	}
}

// SetTUFEventSink installs the state-event sink for anti-poisoning rejections.
// The status/server integration owner calls it once with state.AddEvent; a nil
// sink keeps the rejection logged and visible in the feed telemetry instead.
// This is the only wiring that cannot live in the S09 file set (server.go).
func (m *FeedManager) SetTUFEventSink(sink func(Event)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tufEventSink = sink
}

// emitTUFStateEventLocked delivers one rejection to the optional event sink.
// A defective sink must never take down the feed sync, so panics are contained.
func (m *FeedManager) emitTUFStateEventLocked(reason, feedID string, at time.Time) {
	sink := m.tufEventSink
	if sink == nil {
		return
	}
	event := TUFBlockedStateEvent(reason, feedID, at)
	defer func() {
		_ = recover()
	}()
	sink(event)
}
