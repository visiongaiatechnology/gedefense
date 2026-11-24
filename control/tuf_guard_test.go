// AP-9 / S09 — semantic anti-poisoning guard corpus: diff budget, immutable
// protection zone, global allow, system-path inject, RE2 complexity budget,
// bounded parsing and the honest status projection.
package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func tufTestMethodEntries(count int) []TUFProtectionEntry {
	entries := make([]TUFProtectionEntry, 0, count)
	for index := 0; index < count; index++ {
		entries = append(entries, TUFProtectionEntry{
			ID:         fmt.Sprintf("e%03d", index),
			Kind:       TUFKindBlockPrefix,
			Scope:      fmt.Sprintf("198.51.100.%d/32", index%250+1),
			FeedOrigin: "feed-test",
			Active:     true,
		})
	}
	return entries
}

func tufTestSnapshot(entries []TUFProtectionEntry) TUFProtectionSnapshot {
	return TUFProtectionSnapshot{ID: "test-document", Origin: "feed", Entries: entries}
}

func tufTestKeepExcept(entries []TUFProtectionEntry, removed map[string]struct{}) []TUFProtectionEntry {
	kept := make([]TUFProtectionEntry, 0, len(entries))
	for _, entry := range entries {
		if _, drop := removed[entry.ID]; drop {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

func TestTufGuardDiffBudget(t *testing.T) {
	limits := DefaultTUFSemanticGuardLimits()
	previous := tufTestMethodEntries(100)

	removeIDs := func(ids ...string) map[string]struct{} {
		set := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			set[id] = struct{}{}
		}
		return set
	}
	deleted21 := make([]string, 0, 21)
	for index := 0; index < 21; index++ {
		deleted21 = append(deleted21, fmt.Sprintf("e%03d", index))
	}
	deleted20 := deleted21[:20]

	if err := GuardTUFProtectionUpdate(tufTestSnapshot(previous), tufTestSnapshot(tufTestKeepExcept(previous, removeIDs(deleted21...))), limits); err == nil {
		t.Fatal("21 of 100 deleted entries were accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonDiffBudget)
	}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(previous), tufTestSnapshot(tufTestKeepExcept(previous, removeIDs(deleted20...))), limits); err != nil {
		t.Fatalf("exactly 20 %% deleted entries were rejected: %v", err)
	}

	// Deactivation counts exactly like deletion.
	candidate := tufTestKeepExcept(previous, nil)
	for index := 0; index < 21; index++ {
		candidate[index].Active = false
	}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(previous), tufTestSnapshot(candidate), limits); err == nil {
		t.Fatal("21 deactivated entries were accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonDiffBudget)
	}

	// Bootstrap and growth are allowed: an empty previous set and additions.
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot(tufTestMethodEntries(100)), limits); err != nil {
		t.Fatalf("bootstrap with an empty previous generation was rejected: %v", err)
	}
	previousTen := tufTestMethodEntries(10)
	grown := append([]TUFProtectionEntry(nil), previousTen...)
	for index := 0; index < 40; index++ {
		grown = append(grown, TUFProtectionEntry{
			ID:         fmt.Sprintf("added-%03d", index),
			Kind:       TUFKindBlockPrefix,
			Scope:      fmt.Sprintf("203.0.113.%d/32", index+1),
			FeedOrigin: "feed-test",
			Active:     true,
		})
	}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(previousTen), tufTestSnapshot(grown), limits); err != nil {
		t.Fatalf("additive update was rejected: %v", err)
	}
}

func TestTufGuardImmutableZoneDeletion(t *testing.T) {
	limits := DefaultTUFSemanticGuardLimits()
	immutableTargets := []string{
		"/usr/sbin/sshd",
		"/usr/bin/sshd",
		"/etc/systemd/system/gedefense-core.service",
		"/usr/lib/systemd/system/foo.socket",
		"/boot/vmlinuz-6.8.0-31-generic",
		"/lib/modules/6.8.0/kernel/sound/core.ko",
		"/opt/vgt/gedefense/current/bin/gedefense-control",
		"/etc/vgt/gedefense/secrets/core-ipc.key",
		"/var/lib/vgt/gedefense/threat-intel-state.json",
		"/proc/sys/kernel/tainted",
	}
	for _, target := range immutableTargets {
		target := target
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			previous := []TUFProtectionEntry{
				{ID: "keep-1", Kind: TUFKindBlockPath, Scope: "/var/www/html/index.php", Active: true},
				{ID: "keep-2", Kind: TUFKindBlockPath, Scope: "/srv/data/app.bin", Active: true},
				{ID: "protected", Kind: TUFKindBlockPath, Scope: target, Active: true},
				{ID: "keep-3", Kind: TUFKindBlockPath, Scope: "/home/analyst/notes.txt", Active: true},
				{ID: "keep-4", Kind: TUFKindBlockPath, Scope: "/mnt/usb/payload.bin", Active: true},
			}
			candidate := []TUFProtectionEntry{previous[0], previous[1], previous[3], previous[4]}
			if err := GuardTUFProtectionUpdate(tufTestSnapshot(previous), tufTestSnapshot(candidate), limits); err == nil {
				t.Fatalf("deletion of immutable target %q was accepted", target)
			} else {
				tufTestRequireReason(t, err, TUFReasonImmutableZone)
			}
		})
	}

	// A service-unit entry is immutable even when its scope is not a path.
	previous := []TUFProtectionEntry{
		{ID: "unit", Kind: TUFKindServiceUnit, Scope: "gedefense-core.service", Active: true},
		{ID: "n1", Kind: TUFKindBlockPrefix, Scope: "198.51.100.1/32", Active: true},
		{ID: "n2", Kind: TUFKindBlockPrefix, Scope: "198.51.100.2/32", Active: true},
		{ID: "n3", Kind: TUFKindBlockPrefix, Scope: "198.51.100.3/32", Active: true},
		{ID: "n4", Kind: TUFKindBlockPrefix, Scope: "198.51.100.4/32", Active: true},
	}
	candidate := previous[1:]
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(previous), tufTestSnapshot(candidate), limits); err == nil {
		t.Fatal("deletion of a service-unit protection entry was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonImmutableZone)
	}

	// Exactly 20 % deletion of ordinary paths is allowed.
	candidate = []TUFProtectionEntry{previous[1], previous[2], previous[3], previous[4]}
	ordinary := []TUFProtectionEntry{
		{ID: "p1", Kind: TUFKindBlockPath, Scope: "/var/www/html/a.php", Active: true},
		{ID: "p2", Kind: TUFKindBlockPath, Scope: "/var/www/html/b.php", Active: true},
		{ID: "p3", Kind: TUFKindBlockPath, Scope: "/var/www/html/c.php", Active: true},
		{ID: "p4", Kind: TUFKindBlockPath, Scope: "/var/www/html/d.php", Active: true},
		{ID: "p5", Kind: TUFKindBlockPath, Scope: "/var/www/html/e.php", Active: true},
	}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(ordinary), tufTestSnapshot(ordinary[:4]), limits); err != nil {
		t.Fatalf("ordinary 20 %% deletion was rejected: %v", err)
	}
}

func TestTufGuardGlobalAllow(t *testing.T) {
	limits := DefaultTUFSemanticGuardLimits()
	globalAllows := []TUFProtectionEntry{
		{ID: "allow-prefix-v4", Kind: TUFKindAllowPrefix, Scope: "0.0.0.0/0", Allow: true, FeedOrigin: "feed-x", Active: true},
		{ID: "allow-prefix-v6", Kind: TUFKindAllowPrefix, Scope: "::/0", Allow: true, FeedOrigin: "feed-x", Active: true},
		{ID: "allow-any", Kind: TUFKindAllowHost, Host: "any", Allow: true, FeedOrigin: "feed-x", Active: true},
		{ID: "allow-star", Kind: TUFKindAllowHost, Host: "*", Allow: true, FeedOrigin: "feed-x", Active: true},
		{ID: "allow-empty", Kind: TUFKindAllowHost, Host: "", Allow: true, FeedOrigin: "feed-x", Active: true},
		{ID: "allow-unspecified", Kind: TUFKindAllowHost, Host: "0.0.0.0", Allow: true, FeedOrigin: "feed-x", Active: true},
	}
	for _, entry := range globalAllows {
		entry := entry
		t.Run(entry.ID, func(t *testing.T) {
			if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot([]TUFProtectionEntry{entry}), limits); err == nil {
				t.Fatalf("global allow %+v was accepted", entry)
			} else {
				tufTestRequireReason(t, err, TUFReasonGlobalAllow)
			}
		})
	}
	scoped := TUFProtectionEntry{ID: "allow-api", Kind: TUFKindAllowHost, Host: "api.example.com", Allow: true, FeedOrigin: "feed-x", Active: true}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot([]TUFProtectionEntry{scoped}), limits); err != nil {
		t.Fatalf("scoped allow entry was rejected: %v", err)
	}
}

func TestTufGuardSystemPathInject(t *testing.T) {
	limits := DefaultTUFSemanticGuardLimits()
	injections := []TUFProtectionEntry{
		{ID: "allow-systemd", Kind: TUFKindAllowPath, Scope: "/etc/systemd/system/evil.service", Allow: true, FeedOrigin: "feed-x", Active: true},
		{ID: "allow-sshd", Kind: TUFKindAllowPath, Scope: "/usr/sbin/sshd", Allow: true, FeedOrigin: "feed-x", Active: true},
		{ID: "allow-own-binary", Kind: TUFKindAllowPath, Scope: "/opt/vgt/gedefense/current/bin/gedefense-control", Allow: true, FeedOrigin: "feed-x", Active: true},
		{ID: "allow-unattributed", Kind: TUFKindAllowHost, Host: "example.com", Allow: true, Active: true},
	}
	for _, entry := range injections {
		entry := entry
		t.Run(entry.ID, func(t *testing.T) {
			if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot([]TUFProtectionEntry{entry}), limits); err == nil {
				t.Fatalf("system-path inject %+v was accepted", entry)
			} else {
				tufTestRequireReason(t, err, TUFReasonSystemPathInject)
			}
		})
	}
}

func TestTufGuardRegexComplexity(t *testing.T) {
	limits := DefaultTUFSemanticGuardLimits()
	newRule := func(pattern string) TUFProtectionEntry {
		return TUFProtectionEntry{ID: "regex-rule", Kind: TUFKindRegexRule, Pattern: pattern, FeedOrigin: "feed-x", Active: true}
	}
	valid := []string{`^/usr/bin/wget(\.real)?$`, `a{500}`, `(ab|cd)+`}
	for _, pattern := range valid {
		if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot([]TUFProtectionEntry{newRule(pattern)}), limits); err != nil {
			t.Fatalf("valid RE2 rule %q was rejected: %v", pattern, err)
		}
	}
	invalid := []string{
		`(`,                       // does not compile
		strings.Repeat("a", 1025), // length budget
		strings.Repeat("(", 13) + "a" + strings.Repeat(")", 13), // nesting budget
		`(a{500}){500}`,   // nested repetition amplification
		`(?:a{100}){100}`, // non-capturing group amplification
	}
	for _, pattern := range invalid {
		pattern := pattern
		if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot([]TUFProtectionEntry{newRule(pattern)}), limits); err == nil {
			t.Fatalf("over-budget regex %q was accepted", pattern)
		} else {
			tufTestRequireReason(t, err, TUFReasonRegexComplexity)
		}
	}
}

func TestTufRegexBudgetEstimator(t *testing.T) {
	cases := []struct {
		pattern       string
		nesting       int
		maxRepeat     int
		amplification int
	}{
		{`abc`, 0, 0, 0},
		{`a{500}`, 0, 500, 500},
		{`(a{500})`, 1, 500, 500},
		{`(a{500}){500}`, 1, 500, 1025},
		{`((a{100}){100}){100}`, 2, 100, 1025},
		{`[a-z]{200}`, 0, 200, 200},
	}
	for _, testCase := range cases {
		budget := estimateTUFRegexBudget(testCase.pattern)
		if budget.Length != len(testCase.pattern) {
			t.Fatalf("%q length = %d", testCase.pattern, budget.Length)
		}
		if budget.Nesting != testCase.nesting || budget.MaxRepeat != testCase.maxRepeat || budget.Amplification != testCase.amplification {
			t.Fatalf("%q budget = %+v, want nesting=%d repeat=%d amplification=%d",
				testCase.pattern, budget, testCase.nesting, testCase.maxRepeat, testCase.amplification)
		}
	}
}

func TestTufGuardBoundedParsing(t *testing.T) {
	limits := DefaultTUFSemanticGuardLimits()
	duplicate := []TUFProtectionEntry{
		{ID: "same", Kind: TUFKindBlockPrefix, Scope: "198.51.100.1/32", Active: true},
		{ID: "same", Kind: TUFKindBlockPrefix, Scope: "198.51.100.2/32", Active: true},
	}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot(duplicate), limits); err == nil {
		t.Fatal("duplicate protection entry identifiers were accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSchema)
	}
	oversized := TUFProtectionEntry{ID: "big", Kind: TUFKindBlockPrefix, Scope: strings.Repeat("9", limits.MaxFieldBytes+1), Active: true}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot([]TUFProtectionEntry{oversized}), limits); err == nil {
		t.Fatal("oversized protection entry field was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonEntryBudget)
	}
	control := TUFProtectionEntry{ID: "ctrl", Kind: TUFKindBlockPrefix, Scope: "198.51.100.1/32\x00", Active: true}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot([]TUFProtectionEntry{control}), limits); err == nil {
		t.Fatal("control character in a protection entry was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSchema)
	}
	emptyID := TUFProtectionEntry{ID: "", Kind: TUFKindBlockPrefix, Scope: "198.51.100.1/32", Active: true}
	if err := GuardTUFProtectionUpdate(tufTestSnapshot(nil), tufTestSnapshot([]TUFProtectionEntry{emptyID}), limits); err == nil {
		t.Fatal("protection entry without a stable id was accepted")
	}
}

func TestTufSecurityStatusProjection(t *testing.T) {
	managerWithoutKeys := NewFeedManager(FeedConfig{RequireSignedManifest: true}, t.TempDir())
	status := managerWithoutKeys.TUFStatus()
	if status.Capability != TUFCapabilityUnavailable {
		t.Fatalf("capability = %q, want unavailable without pinned keys", status.Capability)
	}
	if status.Reason == "" {
		t.Fatal("unavailable capability did not report a reason")
	}
	if status.Threshold != "2-of-3" || len(status.Roles) != 3 {
		t.Fatalf("threshold projection = %q / %v", status.Threshold, status.Roles)
	}
	if status.R5Isolation != TUFR5IsolationShadow || status.R5HelperIsolation != TUFR5HelperPending {
		t.Fatalf("R5 projection = %q / %q", status.R5Isolation, status.R5HelperIsolation)
	}

	first := make([]byte, 32)
	for index := range first {
		first[index] = byte(index + 1)
	}
	second := make([]byte, 32)
	third := make([]byte, 32)
	for index := range second {
		second[index] = byte(index + 33)
		third[index] = byte(index + 65)
	}
	cfg := FeedConfig{
		RequireSignedManifest: true,
		TrustedSigningKeys: []string{
			base64.StdEncoding.EncodeToString(first),
			base64.StdEncoding.EncodeToString(second),
			base64.StdEncoding.EncodeToString(third),
		},
	}
	managerWithKeys := NewFeedManager(cfg, t.TempDir())
	status = managerWithKeys.TUFStatus()
	if status.Capability != TUFCapabilityAvailable {
		t.Fatalf("capability = %q (%s), want available with three pinned keys", status.Capability, status.Reason)
	}
	if status.Epoch != 0 || status.BlockedUpdates != 0 {
		t.Fatalf("fresh manager projection = %+v", status)
	}

	managerWithKeys.mu.Lock()
	managerWithKeys.recordTUFBlockedLocked(TUFReasonDiffBudget, "feodo-c2", time.Now().UTC())
	managerWithKeys.recordTUFBlockedLocked(TUFReasonImmutableZone, "test", time.Now().UTC())
	managerWithKeys.mu.Unlock()
	status = managerWithKeys.TUFStatus()
	if status.BlockedUpdates != 2 || status.LastBlockedReason != TUFReasonImmutableZone || len(status.RecentBlocked) != 2 {
		t.Fatalf("blocked projection = %+v", status)
	}
	if event := TUFBlockedStateEvent(TUFReasonDiffBudget, "feodo-c2", time.Now().UTC()); event.Kind != "feed.poisoning_blocked" ||
		event.Severity != "high" || !strings.Contains(event.Message, TUFReasonDiffBudget) {
		t.Fatalf("blocked state event = %+v", event)
	}
}

func TestTufBlockedStateEventSink(t *testing.T) {
	manager := NewFeedManager(FeedConfig{}, t.TempDir())
	var received []Event
	manager.SetTUFEventSink(func(event Event) { received = append(received, event) })
	manager.mu.Lock()
	manager.recordTUFBlockedLocked(TUFReasonDiffBudget, "feodo-c2", time.Now().UTC())
	manager.mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("state event sink received %d events, want 1", len(received))
	}
	if event := received[0]; event.Kind != "feed.poisoning_blocked" || event.Severity != "high" ||
		event.Target != "feodo-c2" || !strings.Contains(event.Message, TUFReasonDiffBudget) {
		t.Fatalf("state event = %+v", event)
	}
	if strings.Contains(received[0].Message, "https://") {
		t.Fatal("state event leaked a feed URL")
	}
	// A defective sink must never break the rejection path.
	manager.SetTUFEventSink(func(Event) { panic("observer bug") })
	manager.mu.Lock()
	manager.recordTUFBlockedLocked(TUFReasonImmutableZone, "test", time.Now().UTC())
	manager.mu.Unlock()
	if status := manager.TUFStatus(); status.BlockedUpdates != 2 {
		t.Fatalf("rejection counter after a panicking sink = %d, want 2", status.BlockedUpdates)
	}
}
