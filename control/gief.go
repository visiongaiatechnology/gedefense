// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6: GIEF v1.0 — envelope construction and attachment.
//
// The closed, explicit rule classification tables (rule id -> sensor class and
// rule id -> SBC family) live in gief_types.go. This file owns the engine, the
// capability/correlation/blindspot derivation, the envelope builder and the
// attachment seam.
//
// A rule id the codebase grows later falls back to a documented default family
// and is counted (GIEFStats), never guessed into OBSERVED. attachGIEFEnvelope is
// metadata only: it never touches Score, ResponseScore, KillSignals, Decision,
// Action, RuleIDs or Categories.

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// ------------------------------------------------------- envelope metadata

// giefPrimaryAttackStoryNode returns the finding's own attack-story node.
//
// Every producer in this codebase appends its own node last (the correlator
// places the prior chain first, then the current node; standalone sensors emit a
// single node). Reading only the primary node is what keeps metadata from an
// *earlier correlated finding* from classifying or downgrading the current one.
func giefPrimaryAttackStoryNode(incident XDRIncident) (AttackStoryNode, bool) {
	if len(incident.AttackStory) == 0 {
		return AttackStoryNode{}, false
	}
	return incident.AttackStory[len(incident.AttackStory)-1], true
}

// giefPrimaryMetadata returns a non-empty metadata value of the finding's own
// attack-story node.
func giefPrimaryMetadata(incident XDRIncident, key string) (string, bool) {
	node, ok := giefPrimaryAttackStoryNode(incident)
	if !ok || node.Metadata == nil {
		return "", false
	}
	value := strings.TrimSpace(node.Metadata[key])
	return value, value != ""
}

// giefDeclaredFamily reads the family a sensor declared for its own finding. The
// declaration wins over the rule table because the producer knows its domain; an
// invalid or unknown token is ignored instead of trusted.
func giefDeclaredFamily(incident XDRIncident) (string, bool) {
	value, ok := giefPrimaryMetadata(incident, giefFamilyMetadataKey)
	if !ok {
		return "", false
	}
	family := strings.ToUpper(value)
	if giefKnownSBCFamily(family) {
		return family, true
	}
	return "", false
}

// giefDeclaredCorrelation reads the correlation quality a sensor declared for its
// own finding. It is used only to *downgrade* the claim derived from the rule
// family — a userspace rule can never become OBSERVED here.
func giefDeclaredCorrelation(incident XDRIncident) (string, bool) {
	value, ok := giefPrimaryMetadata(incident, giefCorrelationMetadataKey)
	if !ok {
		return "", false
	}
	declared := strings.ToUpper(value)
	if _, valid := giefCorrelationRanks[declared]; !valid {
		return "", false
	}
	return declared, true
}

// giefCorrelationForClass maps the observation channel to the correlation
// quality. Only a kernel-proven channel or a cryptographic platform-integrity
// check may claim OBSERVED; operational sensor-health events claim nothing.
func giefCorrelationForClass(class giefSensorClass) string {
	switch class {
	case giefSensorClassKernelLSM, giefSensorClassKernelTelemetry, giefSensorClassIntegrity:
		return giefCorrelationObserved
	case giefSensorClassUserspace:
		return giefCorrelationTemporal
	default:
		return giefCorrelationNone
	}
}

// ---------------------------------------------------------------- the engine

// GIEFEngine builds GIEF envelopes and keeps the bounded classification
// counters. The mappings themselves are pure functions; the engine exists so an
// unknown rule id cannot pass silently.
type GIEFEngine struct {
	envelopes             atomic.Uint64
	unknownRuleIDs        atomic.Uint64
	defaultFamily         atomic.Uint64
	correlationDowngrades atomic.Uint64
}

// NewGIEFEngine constructs the GIEF envelope builder.
func NewGIEFEngine() *GIEFEngine {
	return &GIEFEngine{}
}

// Stats returns the bounded counter projection of the builder.
func (g *GIEFEngine) Stats() GIEFStats {
	if g == nil {
		return GIEFStats{}
	}
	return GIEFStats{
		Envelopes:             g.envelopes.Load(),
		UnknownRuleIDs:        g.unknownRuleIDs.Load(),
		DefaultFamily:         g.defaultFamily.Load(),
		CorrelationDowngrades: g.correlationDowngrades.Load(),
	}
}

// classify resolves the SBC family and the sensor class of one incident and
// counts every rule id that is not in the closed classification.
func (g *GIEFEngine) classify(incident XDRIncident) (string, bool, giefSensorClass) {
	familyVotes := make(map[string]struct{})
	class := giefSensorClassNone
	for _, ruleID := range incident.RuleIDs {
		classification, known := giefRuleClassificationFor(ruleID)
		if !known {
			g.unknownRuleIDs.Add(1)
			continue
		}
		familyVotes[classification.family] = struct{}{}
		if classification.class > class {
			class = classification.class
		}
	}
	if declared, ok := giefDeclaredFamily(incident); ok {
		return declared, true, class
	}
	if family := giefPriorityFamily(familyVotes); family != "" {
		return family, true, class
	}
	if family, ok := giefFamilyForCategories(incident.Categories); ok {
		return family, true, class
	}
	return SBCDefaultFamily, false, class
}

// ------------------------------------------------------------ envelope builder

// giefBuildInput is everything the pure envelope builder needs for one finding.
type giefBuildInput struct {
	incident    XDRIncident
	facts       giefFacts
	family      string
	familyKnown bool
	class       giefSensorClass
	sbc         *SBCContext
}

// buildEnvelope assembles the GIEF v1.0 envelope. It is metadata only and has no
// side effects on the incident (the caller assigns the returned value).
func (g *GIEFEngine) buildEnvelope(in giefBuildInput) GIEFEnvelope {
	g.envelopes.Add(1)
	if !in.familyKnown {
		g.defaultFamily.Add(1)
	}
	baseCorrelation := giefCorrelationForClass(in.class)
	correlation := baseCorrelation
	downgrade := ""
	if declared, ok := giefDeclaredCorrelation(in.incident); ok {
		if giefCorrelationRanks[declared] < giefCorrelationRanks[baseCorrelation] {
			correlation = declared
			downgrade = declared
			g.correlationDowngrades.Add(1)
		}
	}
	hashes := giefEvidenceHashes(in.incident)
	envelope := GIEFEnvelope{
		Version:            GIEFVersion,
		Capability:         giefCapabilityFor(in.class, in.facts, giefRuleHint(in.incident)),
		CorrelationQuality: correlation,
		SBCFamily:          in.family,
		EvidenceHashes:     hashes,
		SBC:                in.sbc,
	}
	envelope.Stages = giefStages(in.incident, in.class, in.sbc)
	envelope.Explanations = giefExplanations(in, correlation, downgrade, hashes)
	envelope.Blindspots = giefBlindspots(in, correlation)
	return envelope
}

// giefCapabilityFor implements the documented capability mapping.
//
//	class / platform state                          level      visibility
//	kernel BPF-LSM, healthy, BPF LSM active         full       OBSERVED
//	kernel BPF-LSM, no BPF LSM on host              partial    OBSERVED
//	kernel BPF-LSM, XDR degraded                    partial    OBSERVED
//	kernel telemetry / platform integrity, healthy  full       OBSERVED
//	kernel telemetry / platform integrity, degraded partial    OBSERVED
//	operational sensor-health event                 unavailable NONE
//	userspace heuristic only                        minimal    TEMPORAL
//	no classified rule id                           unavailable NONE
func giefCapabilityFor(class giefSensorClass, facts giefFacts, ruleHint string) GIEFCapability {
	reasonForDegradation := func() string {
		reason := boundedText(facts.degradedReason, giefMaxTextBytes)
		if reason == "" {
			reason = "no degradation reason was reported by the engine"
		}
		return "platform degraded: " + reason
	}
	capability := GIEFCapability{
		Level:      giefLevelUnavailable,
		Visibility: giefVisibilityNone,
		Degraded:   facts.degraded,
	}
	switch class {
	case giefSensorClassKernelLSM:
		capability.Visibility = giefVisibilityObserved
		capability.Degraded = facts.degraded || !facts.hasBPFLSM
		switch {
		case facts.degraded:
			capability.Level = giefLevelPartial
			capability.Reason = reasonForDegradation()
		case !facts.capsKnown:
			capability.Level = giefLevelPartial
			capability.Reason = "platform capabilities were not probed; BPF-LSM availability is unknown for this kernel LSM finding"
		case !facts.hasBPFLSM:
			capability.Level = giefLevelPartial
			capability.Reason = "no BPF-LSM active on this host; the kernel LSM observation channel this finding depends on is unavailable"
		default:
			capability.Level = giefLevelFull
		}
	case giefSensorClassKernelTelemetry, giefSensorClassIntegrity:
		capability.Visibility = giefVisibilityObserved
		if facts.degraded {
			capability.Level = giefLevelPartial
			capability.Reason = reasonForDegradation()
		} else {
			capability.Level = giefLevelFull
		}
	case giefSensorClassUserspace:
		capability.Visibility = giefVisibilityTemporal
		capability.Level = giefLevelMinimal
		capability.Reason = "time-correlated userspace evidence only; no kernel-proven observation for this finding"
		if facts.degraded {
			capability.Reason += "; " + reasonForDegradation()
		}
	case giefSensorClassHealth:
		capability.Visibility = giefVisibilityNone
		capability.Level = giefLevelUnavailable
		capability.Reason = "operational platform/sensor-health finding; no threat-observation channel applies"
		if facts.degraded {
			capability.Reason += "; " + reasonForDegradation()
		}
	default:
		capability.Visibility = giefVisibilityNone
		capability.Level = giefLevelUnavailable
		capability.Reason = fmt.Sprintf("no classified observation basis for rule %s; capability unavailable", boundedText(ruleHint, 64))
	}
	capability.Reason = boundedText(capability.Reason, giefMaxTextBytes)
	return capability
}

// giefRuleHint is the bounded first rule id used in human-readable reasons.
func giefRuleHint(incident XDRIncident) string {
	for _, ruleID := range incident.RuleIDs {
		if trimmed := strings.TrimSpace(ruleID); trimmed != "" {
			return trimmed
		}
	}
	return "none"
}

// giefObservationLabel names the sensor channel of a class in one line.
func giefObservationLabel(class giefSensorClass) string {
	switch class {
	case giefSensorClassKernelLSM:
		return "kernel BPF-LSM hook"
	case giefSensorClassKernelTelemetry:
		return "kernel telemetry (tracepoint, iterator or cross-view)"
	case giefSensorClassIntegrity:
		return "platform-integrity check"
	case giefSensorClassHealth:
		return "platform/sensor-health event (operational, not a threat observation)"
	case giefSensorClassUserspace:
		return "userspace time-correlated sample"
	default:
		return "unclassified rule (no proven sensor channel)"
	}
}

// giefStages names the pipeline stages that actually happened for this finding.
func giefStages(incident XDRIncident, class giefSensorClass, sbc *SBCContext) []string {
	stages := make([]string, 0, giefMaxStages)
	stages = append(stages, "observation: "+giefObservationLabel(class))
	if count := len(incident.AttackStory); count > 0 {
		stages = append(stages, fmt.Sprintf("evidence: %d attack-story node(s) with chained digests", count))
	} else {
		stages = append(stages, "evidence: standalone finding (no attack story attached)")
	}
	if decision := boundedText(incident.Decision, 32); decision != "" {
		stages = append(stages, "response: decision="+decision+" was evaluated before the GIEF envelope was attached")
	}
	if sbc != nil {
		stages = append(stages, fmt.Sprintf("fusion: %d prior SBC famil(ies) corroborate the entity", len(sbc.Families)))
	}
	return giefBoundedList(stages, giefMaxStages)
}

// giefExplanations produces the bounded, secret-free explanation lines.
func giefExplanations(in giefBuildInput, correlation, downgrade string, hashes []string) []string {
	explanations := make([]string, 0, giefMaxExplanations)
	description := giefSBCFamilyDescriptions[in.family]
	if description == "" {
		description = "documented default evidence family"
	}
	explanations = append(explanations, "sbc family "+in.family+": "+description)
	if downgrade != "" {
		explanations = append(explanations, "correlation quality "+correlation+": the sensor declared weaker per-finding evidence than the rule-family baseline; the envelope only downgrades, never upgrades a correlation claim")
	} else {
		explanations = append(explanations, "correlation quality "+correlation+": "+giefCorrelationExplanation(in.class))
	}
	explanations = append(explanations, "observation channel: "+giefObservationLabel(in.class))
	if len(hashes) > 0 {
		explanations = append(explanations, fmt.Sprintf("evidence hashes: %d hash(es) copied from fields the incident already carries (record hash, evidence root, command/body digest, attack-story digests); no hash is computed here", len(hashes)))
	}
	if in.sbc != nil {
		explanations = append(explanations, fmt.Sprintf("SBC corroboration: %d prior observation famil(ies), decayed score %.4f at %.0f min half-life", in.sbc.Corroborations, in.sbc.DecayedScore, in.sbc.HalfLifeMinutes))
	}
	if !in.familyKnown {
		explanations = append(explanations, "no rule id or category mapped to a closed SBC family; the documented default "+SBCDefaultFamily+" was assigned and counted")
	}
	return giefBoundedList(explanations, giefMaxExplanations)
}

// giefCorrelationExplanation names why a correlation quality was claimed.
func giefCorrelationExplanation(class giefSensorClass) string {
	switch class {
	case giefSensorClassKernelLSM, giefSensorClassKernelTelemetry:
		return "the finding carries kernel-proven sensor evidence"
	case giefSensorClassIntegrity:
		return "the finding carries a cryptographic platform-integrity result"
	case giefSensorClassUserspace:
		return "the finding rests on time-correlated userspace evidence only"
	case giefSensorClassHealth:
		return "the finding reports platform or sensor health, not an observed threat"
	default:
		return "no observation basis was classified for the finding"
	}
}

// giefBlindspots names what this finding cannot prove, using only engine facts.
func giefBlindspots(in giefBuildInput, correlation string) []string {
	blindspots := make([]string, 0, giefMaxBlindspots)
	if in.facts.degraded {
		reason := boundedText(in.facts.degradedReason, 160)
		if reason == "" {
			reason = "no degradation reason was reported by the engine"
		}
		blindspots = append(blindspots, "platform degraded: "+reason)
	}
	if !in.facts.capsKnown {
		blindspots = append(blindspots, "platform capabilities were not probed; the capability block reports only the engine degradation state")
	}
	if in.class == giefSensorClassKernelLSM && in.facts.capsKnown && !in.facts.hasBPFLSM {
		blindspots = append(blindspots, "no BPF-LSM active: kernel LSM observation is a blindspot for this finding")
	}
	if in.class == giefSensorClassKernelTelemetry && in.facts.capsKnown && !in.facts.hasCgroupV2 {
		blindspots = append(blindspots, "cgroup v2 is unavailable: per-cgroup attribution of kernel telemetry is limited")
	}
	switch in.class {
	case giefSensorClassUserspace:
		blindspots = append(blindspots, "userspace observation cannot prove the absence of kernel-level activity; this finding is time-correlated evidence only")
	case giefSensorClassHealth:
		blindspots = append(blindspots, "the finding reports platform or sensor health, not an observed threat; no evidence correlation is claimed")
	case giefSensorClassNone:
		blindspots = append(blindspots, "no classified observation basis: the finding was recorded without a proven sensor channel")
	}
	if len(in.incident.AttackStory) == 0 {
		blindspots = append(blindspots, "no attack story: no causal chain could be established for this finding")
	}
	if strings.TrimSpace(in.incident.EvidenceRoot) == "" {
		blindspots = append(blindspots, "no evidence root digest on the finding")
	}
	if correlation == giefCorrelationNone && in.class != giefSensorClassNone {
		blindspots = append(blindspots, "the sensor declared correlation NONE: the finding's own evidence chain could not be verified")
	}
	return giefBoundedList(blindspots, giefMaxBlindspots)
}

// giefEvidenceHashes copies at most eight already-computed SHA-256 hex digests
// from the incident. Malformed values are ignored; a hash is never computed or
// invented here.
func giefEvidenceHashes(incident XDRIncident) []string {
	hashes := make([]string, 0, giefMaxEvidenceHashes)
	seen := make(map[string]struct{}, giefMaxEvidenceHashes)
	add := func(value string) {
		if len(hashes) >= giefMaxEvidenceHashes {
			return
		}
		digest := strings.ToLower(strings.TrimSpace(value))
		if !giefIsSHA256Hex(digest) {
			return
		}
		if _, ok := seen[digest]; ok {
			return
		}
		seen[digest] = struct{}{}
		hashes = append(hashes, digest)
	}
	add(incident.RecordHash)
	add(incident.EvidenceRoot)
	add(incident.CommandSHA256)
	add(incident.BodySHA256)
	for _, node := range incident.AttackStory {
		add(node.Digest)
	}
	return hashes
}

// giefIsSHA256Hex reports whether value is a lowercase 64-character hex digest.
func giefIsSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch {
		case value[i] >= '0' && value[i] <= '9':
		case value[i] >= 'a' && value[i] <= 'f':
		default:
			return false
		}
	}
	return true
}

// giefBoundedList caps a list without reordering it.
func giefBoundedList(items []string, limit int) []string {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

// ---------------------------------------------------------------- attachment

// attachGIEFEnvelope enriches one incident with the GIEF v1.0 envelope.
//
// It is a metadata-only seam: the returned incident is the input incident plus a
// GIEF pointer. Score, ResponseScore, KillSignals, Decision, Action, RuleIDs and
// Categories are read, never written, and the envelope is never consulted by the
// kill gate.
func (e *XDREngine) attachGIEFEnvelope(incident XDRIncident) XDRIncident {
	if e == nil || e.gief == nil {
		return incident
	}
	family, familyKnown, class := e.gief.classify(incident)
	var sbc *SBCContext
	if e.sbc != nil {
		now := incident.Time
		if now.IsZero() {
			now = time.Now().UTC()
		}
		sbc = e.sbc.observeIncident(incident, family, now)
	}
	degraded, degradedReason := e.degradedState()
	facts := giefFacts{
		degraded:       degraded,
		degradedReason: degradedReason,
		capsKnown:      !e.platformCaps.DetectedAt.IsZero(),
		hasBPFLSM:      e.platformCaps.HasBPFLSM,
		hasCgroupV2:    e.platformCaps.HasCgroupV2,
	}
	envelope := e.gief.buildEnvelope(giefBuildInput{
		incident: incident, facts: facts, family: family, familyKnown: familyKnown, class: class, sbc: sbc,
	})
	incident.GIEF = &envelope
	return incident
}
