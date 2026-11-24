// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6 regression tests for GIEF evidence honesty: bounded hash copying,
// blindspot derivation and bounded list/text guarantees.

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestGIEFEvidenceHashesAreCopiedBoundedAndValidated(t *testing.T) {
	engine := newGIEFTestEngine(t, false, "", true)
	recordHash := giefTestHash(t, "record")
	evidenceRoot := giefTestHash(t, "root")
	bodyHash := giefTestHash(t, "body")
	incident := XDRIncident{
		RecordHash: recordHash, EvidenceRoot: evidenceRoot,
		CommandSHA256: "not-a-valid-digest", BodySHA256: bodyHash,
	}
	for i := 0; i < 10; i++ {
		incident.AttackStory = append(incident.AttackStory, AttackStoryNode{Digest: giefTestHash(t, fmt.Sprintf("story-%d", i))})
	}
	// A duplicate digest must not consume a second slot.
	incident.AttackStory = append(incident.AttackStory, AttackStoryNode{Digest: recordHash})
	envelope := engine.attachGIEFEnvelope(incident)
	for _, hash := range envelope.GIEF.EvidenceHashes {
		if !giefIsSHA256Hex(hash) {
			t.Fatalf("envelope carries a non-digest value %q", hash)
		}
	}
	if len(envelope.GIEF.EvidenceHashes) != giefMaxEvidenceHashes {
		t.Fatalf("evidence hash count is %d, want the bound %d", len(envelope.GIEF.EvidenceHashes), giefMaxEvidenceHashes)
	}
	want := []string{
		recordHash, evidenceRoot, bodyHash,
		giefTestHash(t, "story-0"), giefTestHash(t, "story-1"),
		giefTestHash(t, "story-2"), giefTestHash(t, "story-3"), giefTestHash(t, "story-4"),
	}
	if !reflect.DeepEqual(envelope.GIEF.EvidenceHashes, want) {
		t.Fatalf("evidence hashes are %v, want %v", envelope.GIEF.EvidenceHashes, want)
	}
	// An incident without digests gets no invented hashes.
	bare := engine.attachGIEFEnvelope(XDRIncident{RuleIDs: []string{"XDR.TEMP_EXEC"}})
	if len(bare.GIEF.EvidenceHashes) != 0 {
		t.Fatalf("bare incident invented hashes: %v", bare.GIEF.EvidenceHashes)
	}
}

func TestGIEFBlindspotsAreHonestAndBounded(t *testing.T) {
	degraded := newGIEFTestEngine(t, true, "incident log unavailable", false)
	incident := XDRIncident{
		RuleIDs: []string{"XDR.CREDENTIAL_READ_BLOCKED"}, Categories: []string{"credential"},
		Decision: "alert",
	}
	envelope := buildGIEFTestEnvelope(degraded, incident, giefFacts{degraded: true, degradedReason: "incident log unavailable", capsKnown: true, hasBPFLSM: false})
	joined := strings.Join(envelope.Blindspots, " | ")
	for _, want := range []string{"platform degraded: incident log unavailable", "no BPF-LSM active", "no attack story", "no evidence root digest"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("blindspots miss %q: %s", want, joined)
		}
	}
	if len(envelope.Blindspots) > giefMaxBlindspots {
		t.Fatalf("blindspots exceed the bound: %d", len(envelope.Blindspots))
	}

	healthy := newGIEFTestEngine(t, false, "", true)
	complete := XDRIncident{
		RecordHash:   giefTestHash(t, "record"),
		EvidenceRoot: giefTestHash(t, "root"),
		RuleIDs:      []string{"XDR.CREDENTIAL_READ_BLOCKED"},
		Decision:     "deny",
		AttackStory:  []AttackStoryNode{{Digest: giefTestHash(t, "node")}},
	}
	envelope = buildGIEFTestEnvelope(healthy, complete, healthyGIEFFacts())
	if len(envelope.Blindspots) != 0 {
		t.Fatalf("healthy complete finding claims blindspots: %v", envelope.Blindspots)
	}
	// Bounded lists and bounded text always hold.
	for _, text := range append(append(append([]string{}, envelope.Stages...), envelope.Explanations...), envelope.Blindspots...) {
		if len(text) > giefMaxTextBytes*4 {
			t.Fatalf("unbounded envelope text: %q", text)
		}
	}
	if len(envelope.Stages) > giefMaxStages || len(envelope.Explanations) > giefMaxExplanations {
		t.Fatal("envelope list exceeds its bound")
	}
}
