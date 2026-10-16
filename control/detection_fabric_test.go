// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"regexp"
	"strings"
	"testing"
)

// TestDetectionSwitchesMapOntoTheRuleCatalogue proves the operator switches reach the four rules,
// that the score always comes from the catalogue, and that a switch never touches another rule's
// override - the failure mode that would silently reset an unrelated tuning.
func TestDetectionSwitchesMapOntoTheRuleCatalogue(t *testing.T) {
	all := DetectionFabricSettings{
		RuleLogTamper: true, RuleCredentialProbe: true, RuleTunnelBinary: true, RulePersistenceDropin: true,
	}
	foreign := XDRRuleOverride{ID: "XDR.TEMP_EXEC", Enabled: false, Score: 55}
	overrides := detectionRuleOverrides(all, []XDRRuleOverride{foreign})

	byID := make(map[string]XDRRuleOverride, len(overrides))
	for _, override := range overrides {
		if _, twice := byID[override.ID]; twice {
			t.Fatalf("rule %q appears twice", override.ID)
		}
		byID[override.ID] = override
	}
	if kept, ok := byID["XDR.TEMP_EXEC"]; !ok || kept.Enabled || kept.Score != 55 {
		t.Fatalf("an unrelated override was changed: %+v", kept)
	}
	for _, id := range detectionRuleIDs {
		override, ok := byID[id]
		if !ok {
			t.Fatalf("rule %q has no override", id)
		}
		if !override.Enabled {
			t.Fatalf("rule %q was switched off although the settings say on", id)
		}
		if want := builtinRuleScores[id]; override.Score != want {
			t.Fatalf("rule %q score = %d, want the catalogue value %d", id, override.Score, want)
		}
	}

	none := DetectionFabricSettings{}
	overrides = detectionRuleOverrides(none, nil)
	for _, override := range overrides {
		if override.Enabled {
			t.Fatalf("rule %q stayed enabled with the switch off", override.ID)
		}
	}
}

// TestDetectionCredentialRuleQuotesOperatorPaths is the injection test: an administrator types a
// path, not a pattern. A directory whose name contains regular-expression syntax must match itself
// and nothing else.
func TestDetectionCredentialRuleQuotesOperatorPaths(t *testing.T) {
	rule, ok := detectionCredentialRule([]string{"/srv/data/foo.*", "/etc/vgt/gedefense/secrets"})
	if !ok {
		t.Fatal("the operator rule was not generated")
	}
	if !strings.Contains(rule.Pattern, `foo\.\*`) {
		t.Fatalf("the path was not quoted literally: %s", rule.Pattern)
	}
	compiled, err := regexp.Compile(rule.Pattern)
	if err != nil {
		t.Fatalf("the generated pattern does not compile: %v", err)
	}
	if !compiled.MatchString("cp /srv/data/foo.* /tmp/out") {
		t.Fatal("the literal path is not matched")
	}
	if compiled.MatchString("cp /srv/data/foobar /tmp/out") {
		t.Fatal("the literal path acted as a wildcard")
	}
	if _, ok := detectionCredentialRule(nil); ok {
		t.Fatal("an empty path list produced a rule")
	}
}

// TestDetectionCredentialPathsAreValidated states the boundary: configuration mistakes are refused,
// never quietly corrected.
func TestDetectionCredentialPathsAreValidated(t *testing.T) {
	if _, err := normalizeDetectionCredentialPaths([]string{"relative/path"}); err == nil {
		t.Fatal("a relative path was accepted")
	}
	if _, err := normalizeDetectionCredentialPaths([]string{"/ok\n/etc/shadow"}); err == nil {
		t.Fatal("a path with a control character was accepted")
	}
	tooMany := make([]string, detectionMaxCredentialPaths+1)
	for i := range tooMany {
		tooMany[i] = "/srv/store"
	}
	if _, err := normalizeDetectionCredentialPaths(tooMany); err == nil {
		t.Fatal("too many paths were accepted")
	}
	// Duplicates collapse, order is stable, and nothing else changes.
	got, err := normalizeDetectionCredentialPaths([]string{"/b", "/a", "/b"})
	if err != nil || len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Fatalf("normalisation = %v (%v)", got, err)
	}
}

// TestDetectionPresetNeverDropsAConfiguredRoot keeps the promise the switch makes: it adds what
// exists, it never removes what the operator configured.
func TestDetectionPresetNeverDropsAConfiguredRoot(t *testing.T) {
	settings := &RuntimeSettings{}
	settings.XDRFabric.ProtectedPaths = []string{"/opt/vgt/gedefense/current/bin/gedefense-control"}

	if err := applyDetectionSettings(settings, DetectionFabricSettings{ProtectionRootsPreset: false, CredentialPaths: []string{"/srv/keys"}}); err != nil {
		t.Fatal(err)
	}
	if len(settings.XDRFabric.ProtectedPaths) != 1 {
		t.Fatalf("the preset changed the roots while switched off: %v", settings.XDRFabric.ProtectedPaths)
	}
	if len(settings.CustomRules) != 1 || settings.CustomRules[0].ID != detectionCredentialRuleID {
		t.Fatalf("the operator rule was not written: %+v", settings.CustomRules)
	}

	if err := applyDetectionSettings(settings, DetectionFabricSettings{ProtectionRootsPreset: true, CredentialPaths: []string{"/srv/keys"}}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, root := range settings.XDRFabric.ProtectedPaths {
		if root == "/opt/vgt/gedefense/current/bin/gedefense-control" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the configured root was dropped by the preset: %v", settings.XDRFabric.ProtectedPaths)
	}
	if len(settings.CustomRules) != 1 {
		t.Fatalf("applying twice duplicated the operator rule: %+v", settings.CustomRules)
	}
}
