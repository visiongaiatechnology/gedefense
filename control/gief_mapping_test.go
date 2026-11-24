// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6 regression tests for the deterministic GIEF mappings: the
// capability matrix, the correlation-quality matrix (with sensor-declared
// downgrades), SBC family completeness including a source scan of every XDR.*
// rule literal, and the longest-prefix table invariant.

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestGIEFCapabilityMapping(t *testing.T) {
	cases := []struct {
		name           string
		rule           string
		facts          giefFacts
		wantLevel      string
		wantVisibility string
		wantDegraded   bool
		wantReason     string
	}{
		{
			name: "healthy kernel LSM finding", rule: "XDR.CREDENTIAL_READ_BLOCKED", facts: healthyGIEFFacts(),
			wantLevel: giefLevelFull, wantVisibility: giefVisibilityObserved,
		},
		{
			name: "healthy kernel telemetry finding", rule: "XDR.HIDDEN_PROCESS", facts: healthyGIEFFacts(),
			wantLevel: giefLevelFull, wantVisibility: giefVisibilityObserved,
		},
		{
			name: "healthy platform-integrity finding", rule: "XDR.SELF_TAMPER", facts: healthyGIEFFacts(),
			wantLevel: giefLevelFull, wantVisibility: giefVisibilityObserved,
		},
		{
			name: "degraded platform, kernel telemetry finding", rule: "XDR.PTRACE_ATTEMPT",
			facts:     giefFacts{capsKnown: true, hasBPFLSM: true, hasCgroupV2: true, degraded: true, degradedReason: "incident log unavailable"},
			wantLevel: giefLevelPartial, wantVisibility: giefVisibilityObserved, wantDegraded: true, wantReason: "platform degraded: incident log unavailable",
		},
		{
			name: "BPF-LSM absent, kernel LSM finding", rule: "XDR.CREDENTIAL_READ_BLOCKED",
			facts:     giefFacts{capsKnown: true, hasBPFLSM: false, hasCgroupV2: true},
			wantLevel: giefLevelPartial, wantVisibility: giefVisibilityObserved, wantDegraded: true, wantReason: "no BPF-LSM active",
		},
		{
			name: "capabilities not probed, kernel LSM finding", rule: "XDR.CREDENTIAL_READ_BLOCKED",
			facts:     giefFacts{capsKnown: false},
			wantLevel: giefLevelPartial, wantVisibility: giefVisibilityObserved, wantDegraded: true, wantReason: "not probed",
		},
		{
			name: "userspace finding", rule: "XDR.TEMP_EXEC", facts: healthyGIEFFacts(),
			wantLevel: giefLevelMinimal, wantVisibility: giefVisibilityTemporal, wantReason: "userspace",
		},
		{
			name: "operational sensor-health finding", rule: "MALWARE.EVENT_QUEUE_OVERFLOW", facts: healthyGIEFFacts(),
			wantLevel: giefLevelUnavailable, wantVisibility: giefVisibilityNone, wantReason: "platform/sensor-health",
		},
		{
			name: "unclassified rule", rule: "VENDOR.CUSTOM_RULE", facts: healthyGIEFFacts(),
			wantLevel: giefLevelUnavailable, wantVisibility: giefVisibilityNone, wantReason: "no classified",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newGIEFTestEngine(t, tc.facts.degraded, tc.facts.degradedReason, tc.facts.hasBPFLSM)
			envelope := buildGIEFTestEnvelope(engine, XDRIncident{RuleIDs: []string{tc.rule}}, tc.facts)
			capability := envelope.Capability
			if capability.Level != tc.wantLevel {
				t.Fatalf("level is %q, want %q (reason %q)", capability.Level, tc.wantLevel, capability.Reason)
			}
			if capability.Visibility != tc.wantVisibility {
				t.Fatalf("visibility is %q, want %q", capability.Visibility, tc.wantVisibility)
			}
			if capability.Degraded != tc.wantDegraded {
				t.Fatalf("degraded is %t, want %t (reason %q)", capability.Degraded, tc.wantDegraded, capability.Reason)
			}
			if tc.wantReason != "" && !strings.Contains(capability.Reason, tc.wantReason) {
				t.Fatalf("reason %q does not contain %q", capability.Reason, tc.wantReason)
			}
			if len(capability.Reason) > giefMaxTextBytes {
				t.Fatalf("reason exceeds %d bytes: %d", giefMaxTextBytes, len(capability.Reason))
			}
		})
	}
}

func TestGIEFCorrelationQualityMatrix(t *testing.T) {
	// Kernel-proven evidence plus the cryptographic platform-integrity checks may
	// claim OBSERVED. SELF_TAMPER is explicitly part of the closed OBSERVED set.
	observedRules := []string{
		"XDR.CREDENTIAL_READ_BLOCKED",
		"XDR.BPF_ANOMALY",
		"XDR.BPF_ROOTKIT_HELPER",
		"XDR.SELF_TAMPER",
		"XDR.SELF_ARTIFACT",
		"WITNESS.EQUIVOCATION",
		"XDR.HIDDEN_BPF_PROG",
		"XDR.HIDDEN_PROCESS",
		"XDR.LKM_HIDDEN",
		"XDR.LKM_LOAD",
		"XDR.RANSOM_ENTROPY_BURST",
		"XDR.RANSOM_RENAME_STORM",
		"XDR.PTRACE_ATTEMPT",
		"XDR.KERNEL_PROTOCOL_PROBE",
		"XDR.CREDENTIAL_PROBE",
		"XDR.IO_URING_ANOMALY",
		"XDR.LINKER_HOOK",
		"XDR.PERSISTENCE_ENTRY_DRIFT",
		"XDR.LD_PRELOAD_INTEGRITY",
		"XDR.PORTLESS_RAW_TAP",
		"XDR.PCR_ANOMALY",
		"XDR.STYX_PCR_EXFIL",
	}
	userspaceRules := []string{
		"XDR.TEMP_EXEC",
		"XDR.MEMFD_EXEC",
		"XDR.EXE_DELETED",
		"XDR.WEB_SHELL_LINEAGE",
		"XDR.THREAT_INTEL_C2",
		"XDR.ANOMALY.EXEC_BURST",
		"KD.LINUX.PIPE_SHELL",
		"MALWARE.CONTENT_MATCH",
		"XDR.DNS_TUNNEL",
	}
	operationalRules := []string{
		"XDR.WORKER_CRASH_STORM",
		"RELEASE.FAIL_SAFE",
		"MALWARE.SCAN_FAILURE",
		"MALWARE.EVENT_QUEUE_OVERFLOW",
	}
	engine := newGIEFTestEngine(t, false, "", true)
	for _, rule := range observedRules {
		envelope := buildGIEFTestEnvelope(engine, XDRIncident{RuleIDs: []string{rule}}, healthyGIEFFacts())
		if envelope.CorrelationQuality != giefCorrelationObserved {
			t.Fatalf("kernel/integrity rule %s claimed correlation %q, want OBSERVED", rule, envelope.CorrelationQuality)
		}
	}
	for _, rule := range userspaceRules {
		envelope := buildGIEFTestEnvelope(engine, XDRIncident{RuleIDs: []string{rule}}, healthyGIEFFacts())
		if envelope.CorrelationQuality != giefCorrelationTemporal {
			t.Fatalf("userspace rule %s claimed correlation %q, want TEMPORAL", rule, envelope.CorrelationQuality)
		}
	}
	for _, rule := range operationalRules {
		envelope := buildGIEFTestEnvelope(engine, XDRIncident{RuleIDs: []string{rule}}, healthyGIEFFacts())
		if envelope.CorrelationQuality != giefCorrelationNone {
			t.Fatalf("operational rule %s claimed correlation %q, want NONE", rule, envelope.CorrelationQuality)
		}
	}
	unknown := buildGIEFTestEnvelope(engine, XDRIncident{RuleIDs: []string{"VENDOR.CUSTOM_RULE"}}, healthyGIEFFacts())
	if unknown.CorrelationQuality != giefCorrelationNone {
		t.Fatalf("unclassified rule claimed correlation %q, want NONE", unknown.CorrelationQuality)
	}
	// A finding with a kernel rule and a userspace rule carries kernel evidence:
	// the strongest observation basis of the finding wins.
	mixed := buildGIEFTestEnvelope(engine, XDRIncident{RuleIDs: []string{"XDR.TEMP_EXEC", "XDR.CREDENTIAL_READ_BLOCKED"}}, healthyGIEFFacts())
	if mixed.CorrelationQuality != giefCorrelationObserved {
		t.Fatalf("mixed finding claimed correlation %q, want OBSERVED", mixed.CorrelationQuality)
	}
}

func TestGIEFSensorMetadataMayOnlyDowngradeCorrelation(t *testing.T) {
	engine := newGIEFTestEngine(t, false, "", true)
	// A kernel finding whose own sensor declared that its evidence chain could
	// not be verified (e.g. AP-5 LINKER_HOOK without a usable package database).
	downgraded := XDRIncident{
		RuleIDs: []string{"XDR.LINKER_HOOK"},
		AttackStory: []AttackStoryNode{{
			Digest:   giefTestHash(t, "linker-node"),
			Metadata: map[string]string{"correlation_quality": "NONE"},
		}},
	}
	envelope := buildGIEFTestEnvelope(engine, downgraded, healthyGIEFFacts())
	if envelope.CorrelationQuality != giefCorrelationNone {
		t.Fatalf("sensor-declared NONE did not downgrade the claim: %q", envelope.CorrelationQuality)
	}
	if envelope.Capability.Visibility != giefVisibilityObserved {
		t.Fatalf("downgrade changed the observation visibility: %+v", envelope.Capability)
	}
	if stats := engine.gief.Stats(); stats.CorrelationDowngrades != 1 {
		t.Fatalf("downgrade counter is %d, want 1", stats.CorrelationDowngrades)
	}
	// The reverse direction is impossible: a userspace heuristic can never be
	// upgraded to OBSERVED by metadata.
	upgradeAttempt := XDRIncident{
		RuleIDs: []string{"XDR.TEMP_EXEC"},
		AttackStory: []AttackStoryNode{{
			Digest:   giefTestHash(t, "temp-node"),
			Metadata: map[string]string{"correlation_quality": "OBSERVED"},
		}},
	}
	envelope = buildGIEFTestEnvelope(engine, upgradeAttempt, healthyGIEFFacts())
	if envelope.CorrelationQuality != giefCorrelationTemporal {
		t.Fatalf("userspace finding was upgraded to %q by metadata", envelope.CorrelationQuality)
	}
}

func TestGIEFSBCFamilyTableIsClosedAndComplete(t *testing.T) {
	// The closed family set is exactly the eight AP-6 families.
	families := []string{
		SBCFamilyProvenance, SBCFamilyExecution, SBCFamilyKernel, SBCFamilyCredential,
		SBCFamilyC2, SBCFamilyPersistence, SBCFamilyEvasion, SBCFamilyEvidence,
	}
	if len(giefSBCFamilyDescriptions) != 8 {
		t.Fatalf("family description set has %d entries, want 8", len(giefSBCFamilyDescriptions))
	}
	for _, family := range families {
		if _, ok := giefSBCFamilyDescriptions[family]; !ok {
			t.Fatalf("family %q has no description", family)
		}
		if _, ok := giefSBCFamilyPriority[family]; !ok {
			t.Fatalf("family %q has no tie-break priority", family)
		}
		if !giefKnownSBCFamily(family) {
			t.Fatalf("family %q is not recognized", family)
		}
	}
	if len(giefSBCFamilyDescriptions) != len(families) {
		t.Fatal("family description set contains a non-contract family")
	}

	// Representative production rule ids map to documented families.
	expected := map[string]string{
		"XDR.TEMP_EXEC":               SBCFamilyProvenance,
		"XDR.MEMFD_EXEC":              SBCFamilyProvenance,
		"MALWARE.CONTENT_MATCH":       SBCFamilyProvenance,
		"BASELINE.PARENT_MISMATCH":    SBCFamilyProvenance,
		"XDR.WEB_SHELL_LINEAGE":       SBCFamilyExecution,
		"XDR.ANOMALY.EXEC_BURST":      SBCFamilyExecution,
		"KD.LINUX.PIPE_SHELL":         SBCFamilyExecution,
		"TITAN.EXEC_DENIED":           SBCFamilyExecution,
		"XDR.BPF_ROOTKIT_HELPER":      SBCFamilyKernel,
		"XDR.HIDDEN_BPF_PROG":         SBCFamilyKernel,
		"XDR.LKM_LOAD":                SBCFamilyKernel,
		"XDR.FTRACE_HOOK_ANOMALY":     SBCFamilyKernel,
		"XDR.IO_URING_ANOMALY":        SBCFamilyKernel,
		"XDR.CREDENTIAL_READ_BLOCKED": SBCFamilyCredential,
		"XDR.CREDENTIAL_PROBE":        SBCFamilyCredential,
		"XDR.SECRET_STORE_ACCESS":     SBCFamilyCredential,
		"KD.LINUX.CREDENTIAL_ACCESS":  SBCFamilyCredential,
		"XDR.THREAT_INTEL_C2":         SBCFamilyC2,
		"XDR.PORTLESS_RAW_TAP":        SBCFamilyC2,
		"XDR.TLS.CONTROL_STORM":       SBCFamilyC2,
		"KD.LINUX.TUNNEL_BINARY":      SBCFamilyC2,
		"XDR.PCR_ANOMALY":             SBCFamilyC2,
		"XDR.STYX_PCR_EXFIL":          SBCFamilyC2,
		"XDR.DNS_TUNNEL":              SBCFamilyC2,
		"XDR.LIBRARY_CROSSVIEW":       SBCFamilyPersistence,
		"XDR.PERSISTENCE_ENTRY_DRIFT": SBCFamilyPersistence,
		"XDR.LD_PRELOAD_INTEGRITY":    SBCFamilyPersistence,
		"XDR.LINKER_HOOK":             SBCFamilyPersistence,
		"KD.LINUX.PERSISTENCE":        SBCFamilyPersistence,
		"KD.LINUX.LOG_TAMPER":         SBCFamilyEvasion,
		"XDR.PTRACE_ATTEMPT":          SBCFamilyEvasion,
		"XDR.EXE_DELETED":             SBCFamilyEvasion,
		"XDR.NAME_PATH_MISMATCH":      SBCFamilyEvasion,
		"XDR.SELF_TAMPER":             SBCFamilyEvidence,
		"XDR.RANSOM_ENTROPY_BURST":    SBCFamilyEvidence,
		"XDR.WORKER_CRASH_STORM":      SBCFamilyEvidence,
		"BASELINE.HASH_MISMATCH":      SBCFamilyEvidence,
		"WITNESS.EQUIVOCATION":        SBCFamilyEvidence,
	}
	for rule, wantFamily := range expected {
		classification, known := giefRuleClassificationFor(rule)
		if !known {
			t.Fatalf("production rule %s is not classified", rule)
		}
		if classification.family != wantFamily {
			t.Fatalf("rule %s maps to %s, want %s", rule, classification.family, wantFamily)
		}
	}

	// Tie-break: the strongest family wins when a finding carries several.
	engine := newGIEFTestEngine(t, false, "", true)
	multi := buildGIEFTestEnvelope(engine, XDRIncident{RuleIDs: []string{
		"XDR.TEMP_EXEC", "XDR.CREDENTIAL_READ_BLOCKED", "XDR.SELF_TAMPER",
	}}, healthyGIEFFacts())
	if multi.SBCFamily != SBCFamilyEvidence {
		t.Fatalf("multi-family finding mapped to %s, want %s", multi.SBCFamily, SBCFamilyEvidence)
	}

	// Sensor-declared family wins over the rule table (the producer classifies
	// its own finding), but an invalid declaration is ignored.
	declared := XDRIncident{
		RuleIDs: []string{"XDR.TEMP_EXEC"},
		AttackStory: []AttackStoryNode{{
			Digest:   giefTestHash(t, "declared-node"),
			Metadata: map[string]string{"sbc_family": "SBC-EVID-08"},
		}},
	}
	if envelope := buildGIEFTestEnvelope(engine, declared, healthyGIEFFacts()); envelope.SBCFamily != SBCFamilyEvidence {
		t.Fatalf("sensor-declared family was not honoured: %q", envelope.SBCFamily)
	}
	bogus := XDRIncident{
		RuleIDs: []string{"XDR.TEMP_EXEC"},
		AttackStory: []AttackStoryNode{{
			Digest:   giefTestHash(t, "bogus-node"),
			Metadata: map[string]string{"sbc_family": "SBC-BOGUS-09"},
		}},
	}
	if envelope := buildGIEFTestEnvelope(engine, bogus, healthyGIEFFacts()); envelope.SBCFamily != SBCFamilyProvenance {
		t.Fatalf("invalid declared family was trusted: %q", envelope.SBCFamily)
	}

	// Category fallback for an operator-defined rule id.
	categoryOnly := buildGIEFTestEnvelope(engine, XDRIncident{
		RuleIDs: []string{"VENDOR.OPERATOR_RULE"}, Categories: []string{"credential"},
	}, healthyGIEFFacts())
	if categoryOnly.SBCFamily != SBCFamilyCredential {
		t.Fatalf("category fallback mapped to %q, want %q", categoryOnly.SBCFamily, SBCFamilyCredential)
	}

	// Unknown is documented, deterministic and counted.
	unknownEngine := newGIEFTestEngine(t, false, "", true)
	unknown := buildGIEFTestEnvelope(unknownEngine, XDRIncident{RuleIDs: []string{"VENDOR.CUSTOM_RULE"}}, healthyGIEFFacts())
	if unknown.SBCFamily != SBCDefaultFamily {
		t.Fatalf("unknown rule mapped to %q, want documented default %q", unknown.SBCFamily, SBCDefaultFamily)
	}
	if unknown.CorrelationQuality != giefCorrelationNone {
		t.Fatalf("unknown rule claimed correlation %q", unknown.CorrelationQuality)
	}
	stats := unknownEngine.gief.Stats()
	if stats.DefaultFamily != 1 || stats.UnknownRuleIDs != 1 {
		t.Fatalf("unknown counters are %+v, want DefaultFamily=1 UnknownRuleIDs=1", stats)
	}
}

// giefRuleLiteralPattern extracts capitalized rule-id string literals from Go
// source. It is intentionally narrow: event-kind strings are lowercase and do not
// match, and a bare namespace prefix is still exercised through the same default
// path.
var giefRuleLiteralPattern = regexp.MustCompile(`"(XDR\.[A-Z0-9_.]+)"`)

// TestGIEFSBCFamilySourceScan iterates every XDR.* literal the source tree emits
// and proves the mapping is total: every id resolves to one of the eight closed
// families, and every id the closed tables do not know lands on the documented
// default family and is counted.
func TestGIEFSBCFamilySourceScan(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	ruleIDs := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		data, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, match := range giefRuleLiteralPattern.FindAllStringSubmatch(string(data), -1) {
			ruleIDs[match[1]] = struct{}{}
		}
	}
	if len(ruleIDs) < 20 {
		t.Fatalf("source scan found only %d XDR rule ids; the scan is not working", len(ruleIDs))
	}
	sortedIDs := make([]string, 0, len(ruleIDs))
	for id := range ruleIDs {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	engine := newGIEFTestEngine(t, false, "", true)
	var unknownIDs []string
	for _, id := range sortedIDs {
		family, known, _ := engine.gief.classify(XDRIncident{RuleIDs: []string{id}})
		if !giefKnownSBCFamily(family) {
			t.Fatalf("rule id %s mapped to non-contract family %q", id, family)
		}
		if known {
			if family == "" {
				t.Fatalf("known rule id %s has an empty family", id)
			}
			continue
		}
		if family != SBCDefaultFamily {
			t.Fatalf("unknown rule id %s mapped to %q, want documented default %q", id, family, SBCDefaultFamily)
		}
		unknownIDs = append(unknownIDs, id)
	}

	// Every unknown id must increment the default-family counter when an
	// envelope is actually built for it.
	before := engine.gief.Stats()
	for _, id := range unknownIDs {
		envelope := buildGIEFTestEnvelope(engine, XDRIncident{RuleIDs: []string{id}}, healthyGIEFFacts())
		if envelope.SBCFamily != SBCDefaultFamily {
			t.Fatalf("unknown rule id %s did not use the default family", id)
		}
	}
	after := engine.gief.Stats()
	if got, want := after.DefaultFamily, before.DefaultFamily+uint64(len(unknownIDs)); got != want {
		t.Fatalf("default-family counter is %d, want %d (unknown ids: %s)", got, want, strings.Join(unknownIDs, ","))
	}
}

func TestGIEFPrefixTableIsLongestFirst(t *testing.T) {
	// Deterministic classification requires that a more specific prefix is
	// always consulted before a shorter one that also matches.
	for i := 1; i < len(giefRulePrefixClassifications); i++ {
		previous := giefRulePrefixClassifications[i-1].prefix
		current := giefRulePrefixClassifications[i].prefix
		if len(current) > len(previous) {
			t.Fatalf("prefix table is not longest-first at index %d: %q before %q", i, previous, current)
		}
	}
}

func TestGIEFPriorChainMetadataDoesNotClassifyCurrentFinding(t *testing.T) {
	engine := newGIEFTestEngine(t, false, "", true)
	// The correlator places prior chain nodes before the finding's own node. A
	// prior node's declaration must not classify (or downgrade) the current
	// finding: only the primary node owns the current evidence.
	incident := XDRIncident{
		RuleIDs: []string{"XDR.TEMP_EXEC"},
		AttackStory: []AttackStoryNode{
			{Digest: giefTestHash(t, "prior"), Metadata: map[string]string{
				"sbc_family": "SBC-EVID-08", "correlation_quality": "NONE",
			}},
			{Digest: giefTestHash(t, "own")},
		},
	}
	envelope := buildGIEFTestEnvelope(engine, incident, healthyGIEFFacts())
	if envelope.SBCFamily != SBCFamilyProvenance {
		t.Fatalf("prior chain node classified the current finding: %q", envelope.SBCFamily)
	}
	if envelope.CorrelationQuality != giefCorrelationTemporal {
		t.Fatalf("prior chain node downgraded the current finding: %q", envelope.CorrelationQuality)
	}
	// The own node's declaration is honoured when it is present.
	incident.AttackStory[1].Metadata = map[string]string{
		"sbc_family": "SBC-C2-05", "correlation_quality": "NONE",
	}
	envelope = buildGIEFTestEnvelope(engine, incident, healthyGIEFFacts())
	if envelope.SBCFamily != SBCFamilyC2 {
		t.Fatalf("own node family declaration ignored: %q", envelope.SBCFamily)
	}
	if envelope.CorrelationQuality != giefCorrelationNone {
		t.Fatalf("own node correlation declaration ignored: %q", envelope.CorrelationQuality)
	}
}
