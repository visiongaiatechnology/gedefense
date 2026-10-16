// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The attack-detection module: the operator-facing shape of the rules that name what happens *after*
// a break-in, whoever caused it. It exists because those four rules - a wiped log, a copied
// credential store, an executed tunnelling tool, a persistence entry written by hand - are the ones
// an administrator must be able to adapt to their own host without touching the binary.
//
// One owner per fact: the rules themselves live in the catalogue (xdr_rules.go), their scores are
// read from there, and this module only decides whether they run and what host-specific paths they
// watch. Nothing here invents a second detection path.
type DetectionFabricSettings struct {
	// ProtectionRootsPreset adds the security-relevant directories that exist on this host (web
	// roots, persistence locations, log directories) to the protected roots. It is what makes a
	// dropped web shell and a deleted log visible at all; a host without a web server simply has
	// fewer of those directories.
	ProtectionRootsPreset bool `json:"protection_roots_preset"`
	// RuleLogTamper, RuleCredentialProbe, RuleTunnelBinary and RulePersistenceDropin switch the four
	// post-exploitation rules. They default to on: a platform that has to be told to look is a
	// platform that is not looking.
	RuleLogTamper         bool `json:"rule_log_tamper"`
	RuleCredentialProbe   bool `json:"rule_credential_probe"`
	RuleTunnelBinary      bool `json:"rule_tunnel_binary"`
	RulePersistenceDropin bool `json:"rule_persistence_dropin"`
	// CredentialPaths are the stores this host actually keeps: an appliance stores its secrets
	// somewhere else than a web server. The list is turned into one operator rule, quoted literally,
	// so a path can never smuggle regular-expression syntax into the engine.
	CredentialPaths []string `json:"credential_paths"`
}

const (
	detectionCredentialRuleID    = "OPERATOR.CREDENTIAL_PATH"
	detectionCredentialRuleScore = 100
	detectionMaxCredentialPaths  = 32
	detectionMaxCredentialPath   = 200
	detectionMaxCredentialBytes  = 4000
)

// detectionDefaultCredentialPaths are the stores the built-in rule does *not* already name. The
// built-in KD.LINUX.CREDENTIAL_PATH_PROBE covers the operating system's own files; this list covers
// what this platform itself keeps, which is what an attacker on an appliance is actually after.
var detectionDefaultCredentialPaths = []string{
	"/etc/vgt/gedefense/secrets",
	"/opt/beyondtrust",
}

// detectionRuleIDs are the four rules this module owns, in the order an operator meets them.
var detectionRuleIDs = []string{
	"KD.LINUX.LOG_TAMPER",
	"KD.LINUX.CREDENTIAL_PATH_PROBE",
	"KD.LINUX.TUNNEL_BINARY",
	"KD.LINUX.PERSISTENCE_DROPIN",
}

// builtinRuleScores reads the catalogue once. A rule's score has exactly one owner - the catalogue -
// so an operator switch can never silently change how loud a detection is.
var builtinRuleScores = func() map[string]int {
	engine := NewXDRRuleEngine()
	scores := make(map[string]int, len(engine.commandRules))
	for _, rule := range engine.commandRules {
		scores[rule.id] = rule.score
	}
	return scores
}()

func defaultDetectionFabricSettings() DetectionFabricSettings {
	return DetectionFabricSettings{
		ProtectionRootsPreset: true,
		RuleLogTamper:         true,
		RuleCredentialProbe:   true,
		RuleTunnelBinary:      true,
		RulePersistenceDropin: true,
		CredentialPaths:       append([]string(nil), detectionDefaultCredentialPaths...),
	}
}

func effectiveDetectionSettings(settings RuntimeSettings) DetectionFabricSettings {
	out := defaultDetectionFabricSettings()
	if settings.Detection == nil {
		return out
	}
	in := settings.Detection
	out.ProtectionRootsPreset = in.ProtectionRootsPreset
	out.RuleLogTamper = in.RuleLogTamper
	out.RuleCredentialProbe = in.RuleCredentialProbe
	out.RuleTunnelBinary = in.RuleTunnelBinary
	out.RulePersistenceDropin = in.RulePersistenceDropin
	if in.CredentialPaths != nil {
		out.CredentialPaths = append([]string(nil), in.CredentialPaths...)
	}
	return out
}

// normalizeDetectionCredentialPaths is the single validation path for operator-supplied paths. It
// rejects rather than repairs: a path that is not absolute, or that carries control characters, is a
// configuration mistake, and quietly dropping it would hide the mistake.
func normalizeDetectionCredentialPaths(paths []string) ([]string, error) {
	if len(paths) > detectionMaxCredentialPaths {
		return nil, fmt.Errorf("at most %d credential paths are supported", detectionMaxCredentialPaths)
	}
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		if len(trimmed) > detectionMaxCredentialPath {
			return nil, fmt.Errorf("credential path exceeds %d bytes", detectionMaxCredentialPath)
		}
		if !strings.HasPrefix(trimmed, "/") {
			return nil, fmt.Errorf("credential path %q must be absolute", trimmed)
		}
		if strings.ContainsAny(trimmed, "\x00\n\r\t") {
			return nil, fmt.Errorf("credential path %q contains control characters", trimmed)
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out, nil
}

func validateDetectionFabricSettings(in *DetectionFabricSettings) error {
	if in == nil {
		return errors.New("detection settings are missing")
	}
	_, err := normalizeDetectionCredentialPaths(in.CredentialPaths)
	return err
}

// detectionCredentialRule builds the operator rule from the configured stores. Every path is quoted
// literally, so a directory named `foo.*` matches itself and nothing else; the joined pattern is
// bounded before it ever reaches the engine.
func detectionCredentialRule(paths []string) (CustomRule, bool) {
	normalized, err := normalizeDetectionCredentialPaths(paths)
	if err != nil || len(normalized) == 0 {
		return CustomRule{}, false
	}
	quoted := make([]string, 0, len(normalized))
	for _, path := range normalized {
		quoted = append(quoted, regexp.QuoteMeta(path))
	}
	pattern := `(?i)\b(?:cp|tar|rsync|scp|dd|base64|openssl|zip|gzip|cat|less|more|strings|awk|sed|python3?|perl)\b[^\n]{0,500}(?:` + strings.Join(quoted, "|") + `)`
	if len(pattern) > detectionMaxCredentialBytes {
		return CustomRule{}, false
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return CustomRule{}, false
	}
	return CustomRule{
		ID:       detectionCredentialRuleID,
		Enabled:  true,
		Category: "credential",
		Summary:  "Configured credential store read, copied or encoded",
		Pattern:  pattern,
		Score:    detectionCredentialRuleScore,
	}, true
}

// detectionRuleOverrides maps the four switches onto the engine's existing override mechanism. The
// score always comes from the catalogue, and every other override the operator set is preserved:
// switching one rule off must never reset another.
func detectionRuleOverrides(in DetectionFabricSettings, existing []XDRRuleOverride) []XDRRuleOverride {
	enabled := map[string]bool{
		"KD.LINUX.LOG_TAMPER":            in.RuleLogTamper,
		"KD.LINUX.CREDENTIAL_PATH_PROBE": in.RuleCredentialProbe,
		"KD.LINUX.TUNNEL_BINARY":         in.RuleTunnelBinary,
		"KD.LINUX.PERSISTENCE_DROPIN":    in.RulePersistenceDropin,
	}
	owned := make(map[string]struct{}, len(detectionRuleIDs))
	for _, id := range detectionRuleIDs {
		owned[id] = struct{}{}
	}
	out := make([]XDRRuleOverride, 0, len(existing)+len(detectionRuleIDs))
	for _, override := range existing {
		if _, isOurs := owned[override.ID]; isOurs {
			continue
		}
		out = append(out, override)
	}
	for _, id := range detectionRuleIDs {
		score, known := builtinRuleScores[id]
		if !known {
			continue
		}
		out = append(out, XDRRuleOverride{ID: id, Enabled: enabled[id], Score: score})
	}
	return out
}

// applyDetectionSettings writes the module's decisions into the runtime model. It touches three
// facts and nothing else: which rules run, which stores the operator rule watches, and whether the
// startup preset contributes protected roots.
func applyDetectionSettings(next *RuntimeSettings, in DetectionFabricSettings) error {
	if next == nil {
		return errors.New("runtime settings are missing")
	}
	if err := validateDetectionFabricSettings(&in); err != nil {
		return err
	}
	normalized, err := normalizeDetectionCredentialPaths(in.CredentialPaths)
	if err != nil {
		return err
	}
	next.XDRFabric.RuleOverrides = detectionRuleOverrides(in, next.XDRFabric.RuleOverrides)

	// The generated rule replaces only itself; operator-written rules stay untouched.
	custom := make([]CustomRule, 0, len(next.CustomRules)+1)
	for _, rule := range next.CustomRules {
		if rule.ID == detectionCredentialRuleID {
			continue
		}
		custom = append(custom, rule)
	}
	if generated, ok := detectionCredentialRule(normalized); ok {
		custom = append(custom, generated)
	}
	next.CustomRules = custom

	// The protected roots are the operator's list plus - when the preset is on - the directories
	// that exist on this host. A configured root is never dropped by a preset switch.
	if in.ProtectionRootsPreset {
		roots, _ := securityProtectionRoots(next.XDRFabric.ProtectedPaths, true, securityProtectionRootLimit)
		next.XDRFabric.ProtectedPaths = roots
	}
	return nil
}
