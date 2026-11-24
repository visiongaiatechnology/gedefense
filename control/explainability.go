// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: mandatory explainability structure on every XDR finding.
//
// The explorer-visible fields (`stages`, `rules`, `evidence_hashes`,
// `capability_status`, `exonerating_evidence_hint`, `blindspots`) are derived
// from the finding and the current capability state. They never change the
// decision, score, action or any other incident field; a missing ingredient is
// named honestly instead of omitted, and a blindspot is only reported when the
// engine genuinely knows about it.

import (
	"strings"
	"time"
)

// FindingExplainability is the mandatory explainability block of a finding.
type FindingExplainability struct {
	Stages                  []string `json:"stages,omitempty"`
	Rules                   []string `json:"rules,omitempty"`
	EvidenceHashes          []string `json:"evidence_hashes,omitempty"`
	CapabilityStatus        string   `json:"capability_status,omitempty"`
	ExoneratingEvidenceHint string   `json:"exonerating_evidence_hint,omitempty"`
	Blindspots              []string `json:"blindspots,omitempty"`
}

// attachFindingExplainability enriches one incident with the mandatory
// explainability block. It is metadata only: the incident is copied, and only
// the Explainability field is set.
func (e *XDREngine) attachFindingExplainability(incident XDRIncident) XDRIncident {
	incident.Explainability = &FindingExplainability{
		Stages:                  e.explainabilityStages(incident),
		Rules:                   explainabilityRules(incident.RuleIDs),
		EvidenceHashes:          explainabilityEvidenceHashes(incident),
		CapabilityStatus:        e.explainabilityCapabilityStatus(),
		ExoneratingEvidenceHint: e.explainabilityExoneratingHint(incident),
		Blindspots:              e.explainabilityBlindspots(),
	}
	return incident
}

// explainabilityStages names the pipeline stages that produced the finding,
// bounded and ordered from ingestion to decision.
func (e *XDREngine) explainabilityStages(incident XDRIncident) []string {
	stages := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	appendStage := func(stage string) {
		if stage == "" || len(stages) >= 8 {
			return
		}
		if _, duplicate := seen[stage]; duplicate {
			return
		}
		seen[stage] = struct{}{}
		stages = append(stages, stage)
	}
	appendStage("ingest")
	if len(incident.AttackStory) > 0 {
		sensor := boundedPermitText(strings.ToLower(strings.TrimSpace(incident.AttackStory[0].Sensor)), 64)
		if sensor != "" {
			appendStage("sensor:" + sensor)
		}
	}
	if len(incident.RuleIDs) > 0 {
		appendStage("rule-engine")
	}
	for _, ruleID := range incident.RuleIDs {
		if strings.HasPrefix(ruleID, "BASELINE.") {
			appendStage("baseline")
			break
		}
	}
	for _, ruleID := range incident.RuleIDs {
		if strings.HasPrefix(ruleID, "XDR.ANOMALY.") {
			appendStage("behavior-model")
			break
		}
	}
	if incident.ExecutionChainID != "" || len(incident.AttackStory) > 1 {
		appendStage("correlation")
	}
	if incident.Permit != nil {
		appendStage("permit-broker")
	}
	if incident.GIEF != nil {
		appendStage("gief-v1")
	}
	return stages
}

// explainabilityRules copies the rule IDs of the finding, bounded.
func explainabilityRules(ruleIDs []string) []string {
	if len(ruleIDs) == 0 {
		return nil
	}
	limit := len(ruleIDs)
	if limit > 32 {
		limit = 32
	}
	out := make([]string, 0, limit)
	for _, ruleID := range ruleIDs[:limit] {
		bounded := boundedPermitText(ruleID, 96)
		if bounded != "" {
			out = append(out, bounded)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validEvidenceHash reports whether a value is a lowercase/uppercase SHA-256
// hex digest. Only hashes that already exist on the incident are copied.
func validEvidenceHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

// explainabilityEvidenceHashes lists the existing evidence digests of the
// finding, deduplicated and bounded.
func explainabilityEvidenceHashes(incident XDRIncident) []string {
	out := make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	for _, candidate := range []string{incident.CommandSHA256, incident.BodySHA256, incident.EvidenceRoot, incident.RecordHash} {
		if !validEvidenceHash(candidate) {
			continue
		}
		lowered := strings.ToLower(candidate)
		if _, duplicate := seen[lowered]; duplicate {
			continue
		}
		seen[lowered] = struct{}{}
		out = append(out, lowered)
		if len(out) >= 8 {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// explainabilityCapabilityStatus reports the honest engine capability state.
func (e *XDREngine) explainabilityCapabilityStatus() string {
	if e == nil {
		return "unknown: engine state unavailable"
	}
	degraded, reason := e.degradedState()
	if degraded {
		return boundedPermitText("degraded: "+reason, 320)
	}
	if e.platformCaps.DetectedAt.IsZero() {
		return "nominal; platform capability detection has not completed"
	}
	return "nominal"
}

// explainabilityExoneratingHint names the most plausible benign explanation a
// reviewer should check first. It is a hint, never a decision input.
func (e *XDREngine) explainabilityExoneratingHint(incident XDRIncident) string {
	if e == nil {
		return ""
	}
	if incident.Permit != nil {
		hint := "a PermitV1 " + incident.Permit.TrustLevel + " match"
		if incident.Permit.PermitID != "" {
			hint += " (" + incident.Permit.PermitID + ")"
		}
		return boundedPermitText(hint+" explains this finding; verify the permit scope and signer", 320)
	}
	if e.permits != nil {
		if profile := e.permits.MatchingProfileName(incident.Executable, incident.Process); profile != "" {
			return boundedPermitText("a PermitV1 TOLERATED profile for "+profile+" would explain this finding", 320)
		}
	}
	if incident.ExecutionChainID == "" && len(incident.AttackStory) <= 1 {
		return "no session or execution-chain correlation is available for this finding"
	}
	if incident.Remote != "" && e.styxFlowCapabilityKnown() {
		return "connection context is available but no session correlation covers this remote endpoint"
	}
	return ""
}

// explainabilityBlindspots lists only blindspots the engine can prove from its
// own state. Unknown capability state is reported as unknown, never as healthy.
func (e *XDREngine) explainabilityBlindspots() []string {
	if e == nil {
		return []string{"engine state unavailable"}
	}
	blindspots := make([]string, 0, 4)
	if e.platformCaps.DetectedAt.IsZero() {
		blindspots = append(blindspots, "platform capability state unknown (detection has not completed)")
	} else if !e.platformCaps.HasBPFLSM {
		blindspots = append(blindspots, "BPF-LSM not active: kernel-enforced deny telemetry is unavailable")
	}
	if e.styx != nil {
		e.styxFlowMu.Lock()
		telemetryState := e.styxFlowTelemetryState
		e.styxFlowMu.Unlock()
		switch telemetryState {
		case styxTelemetryUnavailable:
			blindspots = append(blindspots, "RX telemetry unavailable: flow/beacon correlation is limited")
		case styxTelemetryDegraded, styxTelemetryStale:
			blindspots = append(blindspots, "RX telemetry "+telemetryState+": flow/beacon correlation is limited")
		}
	}
	if len(blindspots) == 0 {
		return nil
	}
	if len(blindspots) > 8 {
		blindspots = blindspots[:8]
	}
	return blindspots
}

// explainabilityFindingDigest is a helper used by tests and future exports to
// identify the fingerprint an explainability block was attached to.
func explainabilityFindingDigest(incident XDRIncident) string {
	incident.Explainability = nil
	return reviewFindingHash(incident)
}

// explainabilityNow is a small clock indirection so tests can reason about the
// attach path without touching production behaviour.
var explainabilityNow = func() time.Time { return time.Now().UTC() }
