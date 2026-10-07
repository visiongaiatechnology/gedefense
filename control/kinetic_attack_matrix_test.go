package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// B13 regression: Threat Intelligence may strengthen an already-observed
// Kinetic signal, but remains evidence rather than a hidden bypass around the
// normal response/release/allowlist gates.
func TestB13ThreatIntelCorrelationBoostsObservedAttack(t *testing.T) {
	cfg := defaultConfig()
	cfg.Kinetic.EnforcementMode = "block"
	cfg.Kinetic.PortscanThreshold = 5

	build := func(withFeed bool) *KineticEngine {
		state := NewState("4.1.0", cfg)
		eng := NewKineticEngine(cfg.Kinetic, state, NewKineticRuleRegistry(), nil)
		if withFeed {
			correlate := NewThreatIndex()
			correlate.Replace([]string{"198.51.100.222/32"})
			eng.SetThreatIntel(nil, correlate, nil)
		}
		return eng
	}
	drive := func(eng *KineticEngine) KineticEvent {
		now := time.Now().UTC()
		var found KineticEvent
		for i, port := range []uint16{22, 80, 443, 3306, 5432, 8080} {
			events := eng.IngestPacket(IngressPacket{
				Family: 4, Protocol: 6, SrcIP: net.ParseIP("198.51.100.222"),
				DstIP: net.ParseIP("192.0.2.10"), DstPort: port, TCPFlags: 0x02,
				Bytes: 64, Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			})
			for _, evt := range events {
				if evt.RuleID == "NET.INGRESS.PORT_SCAN" {
					found = evt
				}
			}
		}
		if found.RuleID == "" {
			t.Fatal("expected NET.INGRESS.PORT_SCAN event")
		}
		return found
	}

	plain := drive(build(false))
	enriched := drive(build(true))
	if enriched.Score <= plain.Score {
		t.Fatalf("expected threat-intel correlation to increase score: plain=%d enriched=%d", plain.Score, enriched.Score)
	}
	if enriched.Metadata == nil || enriched.Metadata["feed_correlate_match"] != true || enriched.Metadata["threat_intel_match"] != true {
		t.Fatalf("expected explicit threat-intel evidence metadata, got %#v", enriched.Metadata)
	}
}

// B13 regression: untrusted remote cardinality must not make source state or
// the operator event ring unbounded. Eviction/drop counters must tell the truth.
func TestB13KineticStateAndEventBuffersRemainBoundedUnderCardinalityPressure(t *testing.T) {
	cfg := defaultConfig()
	cfg.Kinetic.MaxTrackingIPs = 32
	cfg.Kinetic.IPThreshold = 1
	cfg.Kinetic.EnforcementMode = "block"
	state := NewState("4.1.0", cfg)
	eng := NewKineticEngine(cfg.Kinetic, state, NewKineticRuleRegistry(), nil)
	now := time.Now().UTC()

	for i := 0; i < 320; i++ {
		// Distinct /24s avoid manufacturing one giant subnet campaign while
		// still forcing high source cardinality through the bounded tracker.
		ip := net.IPv4(11, byte(i%250), byte((i/250)+1), byte((i%200)+1))
		eng.IngestPacket(IngressPacket{
			Family: 4, Protocol: 6, SrcIP: ip, DstIP: net.ParseIP("192.0.2.10"),
			DstPort: 443, TCPFlags: 0x02, Bytes: 64,
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
		})
	}

	sources := eng.SourceSnapshot(1000)
	telem := eng.SnapshotTelemetry()
	events, eventDrops := eng.RecentEvents()
	if len(sources) > cfg.Kinetic.MaxTrackingIPs || telem.ActiveTrackingIPs > cfg.Kinetic.MaxTrackingIPs {
		t.Fatalf("source tracker exceeded bound: sources=%d telemetry=%d capacity=%d", len(sources), telem.ActiveTrackingIPs, cfg.Kinetic.MaxTrackingIPs)
	}
	if telem.TrackingEvictionsTotal == 0 && telem.TrackingDropsTotal == 0 {
		t.Fatal("expected observable tracker pressure under high source cardinality")
	}
	if len(events) > 250 {
		t.Fatalf("event ring exceeded fixed capacity: %d", len(events))
	}
	if eventDrops == 0 {
		t.Fatal("expected bounded event ring to report dropped/evicted events under pressure")
	}
}

// B13 end-to-end release gate for the durable security transaction:
// detection -> kernel apply -> signed/encrypted policy -> evidence -> expiry ->
// signed policy update -> kernel removal. This is intentionally separate from
// the faster unsigned compatibility test in kinetic_suite_test.go.
func TestB13SignedPolicyContainmentEndToEnd(t *testing.T) {
	dir := t.TempDir()
	storageKey := filepath.Join(dir, "storage-master.key")
	if err := os.WriteFile(storageKey, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	cfg.Node.Name = "b13-signed-policy-node"
	cfg.Defense.Enforcement = "enforce"
	cfg.Kinetic.EnforcementMode = "block"
	cfg.Kinetic.BanTTLSeconds = 60
	cfg.Policy = PolicyConfig{
		StateFile:      filepath.Join(dir, "policy.json"),
		SigningKeyFile: filepath.Join(dir, "policy.ed25519"),
		PublicKeyFile:  filepath.Join(dir, "policy.ed25519.pub"),
		StorageKeyFile: storageKey,
		RequireSigned:  true,
	}
	policy, err := NewPolicyStore(cfg.Policy, cfg.Node.Name)
	if err != nil {
		t.Fatalf("create signed policy store: %v", err)
	}

	ledger, err := NewEvidenceLedger(filepath.Join(dir, "evidence.jsonl"), filepath.Join(dir, "evidence.ed25519"), storageKey, cfg.Node.Name, 4<<20)
	if err != nil {
		t.Fatalf("create evidence ledger: %v", err)
	}
	state := NewState("4.1.0", cfg)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatalf("attach evidence ledger: %v", err)
	}
	armKineticResponseState(state)
	state.SetPolicyStatus(policy.Status())

	core := &mockReleaseCore{blocked: make(map[string]bool)}
	engine := NewKineticEngine(cfg.Kinetic, state, NewKineticRuleRegistry(), nil)
	response := NewKineticResponseEngine(cfg, state, core)
	attacker := net.ParseIP("198.51.100.240")
	now := time.Now().UTC()

	var selected KineticEvent
	for i := 0; i < 40; i++ {
		for _, evt := range engine.IngestPacket(IngressPacket{
			Family: 4, Protocol: 6, SrcIP: attacker, DstIP: net.ParseIP("192.0.2.10"),
			DstPort: 443, TCPFlags: 0x02, Bytes: 64,
			Timestamp: now.Add(time.Duration(i*20) * time.Millisecond),
		}) {
			if (evt.Action == "block" || evt.Action == "contain") && evt.Score >= selected.Score {
				selected = evt
			}
		}
	}
	if selected.RuleID == "" {
		t.Fatal("expected a containable kinetic detection")
	}

	decision := NetworkDecision{
		Target: selected.SourceIP, RuleIDs: []string{selected.RuleID}, Score: selected.Score,
		Confidence: selected.Confidence, SuggestedAction: selected.Action, BaseTTL: time.Minute,
		Reason: selected.Decision, EvidenceRoot: selected.EvidenceID, Timestamp: selected.Time,
	}
	applied, err := response.ExecuteDecision(decision)
	if err != nil {
		t.Fatalf("execute containment: %v", err)
	}
	if !core.blocked[applied.Target] {
		t.Fatalf("kernel mock did not receive block %s", applied.Target)
	}
	if err := persistPolicy(policy, cfg, state); err != nil {
		t.Fatalf("persist signed policy after apply: %v", err)
	}
	if err := response.CommitApplied(decision, applied); err != nil {
		t.Fatalf("commit containment evidence: %v", err)
	}

	fresh, err := NewPolicyStore(cfg.Policy, cfg.Node.Name)
	if err != nil {
		t.Fatalf("reopen signed policy store: %v", err)
	}
	envelope, err := fresh.Load()
	if err != nil {
		t.Fatalf("verify persisted policy signature: %v", err)
	}
	if !fresh.Status().Verified || len(envelope.Blocks) != 1 || envelope.Blocks[0].Target != applied.Target {
		t.Fatalf("signed policy did not preserve active containment: status=%+v blocks=%+v", fresh.Status(), envelope.Blocks)
	}
	if err := ledger.Verify(); err != nil {
		t.Fatalf("evidence verification after containment: %v", err)
	}

	future := applied.ExpiresAt.Add(time.Second)
	expired, err := reconcileExpiredNetworkBlocks(future, state, core, policy, cfg, nil)
	if err != nil {
		t.Fatalf("expire signed containment: %v", err)
	}
	if len(expired) != 1 || core.blocked[applied.Target] {
		t.Fatalf("expected containment to expire from kernel state: expired=%+v blocked=%v", expired, core.blocked[applied.Target])
	}

	after, err := NewPolicyStore(cfg.Policy, cfg.Node.Name)
	if err != nil {
		t.Fatalf("reopen policy after expiry: %v", err)
	}
	envelopeAfter, err := after.Load()
	if err != nil {
		t.Fatalf("verify policy after expiry: %v", err)
	}
	if !after.Status().Verified || len(envelopeAfter.Blocks) != 0 {
		t.Fatalf("expired containment remained in signed policy: status=%+v blocks=%+v", after.Status(), envelopeAfter.Blocks)
	}
	if err := ledger.Verify(); err != nil {
		t.Fatalf("evidence verification after expiry: %v", err)
	}
}
