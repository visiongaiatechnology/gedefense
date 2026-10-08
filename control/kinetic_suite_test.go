// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type corpusScenario struct {
	Scenario         string   `json:"scenario"`
	Type             string   `json:"type"`
	Description      string   `json:"description"`
	SourceIP         string   `json:"source_ip"`
	SourceIPs        []string `json:"source_ips,omitempty"`
	Subnet           string   `json:"subnet,omitempty"`
	TargetPort       uint16   `json:"target_port,omitempty"`
	TargetPorts      []uint16 `json:"target_ports,omitempty"`
	Protocol         string   `json:"protocol"`
	Flags            string   `json:"flags"`
	PacketCount      uint32   `json:"packet_count,omitempty"`
	PacketCountPerIP uint32   `json:"packet_count_per_ip,omitempty"`
	WindowSeconds    int      `json:"window_seconds"`
	IntervalMillis   int      `json:"interval_millis,omitempty"`
	Allowlisted      bool     `json:"allowlisted"`
	ExpectedDetected bool     `json:"expected_detected"`
	ExpectedRule     string   `json:"expected_rule,omitempty"`
	ExpectedAction   string   `json:"expected_action,omitempty"`
}

func loadCorpus(t *testing.T) []corpusScenario {
	paths := []string{
		filepath.Join("testdata", "kinetic", "corpus.json"),
		filepath.Join("..", "testdata", "kinetic", "corpus.json"),
	}
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("could not read kinetic test corpus from any known path: %v", err)
	}

	var scenarios []corpusScenario
	if err := json.Unmarshal(data, &scenarios); err != nil {
		t.Fatalf("failed to unmarshal corpus JSON: %v", err)
	}
	return scenarios
}

func TestKineticFalsePositiveAndAttackCorpus(t *testing.T) {
	scenarios := loadCorpus(t)
	if len(scenarios) == 0 {
		t.Fatal("empty test corpus")
	}

	for _, sc := range scenarios {
		t.Run(sc.Scenario, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.Kinetic.IPThreshold = 35
			cfg.Kinetic.VelocityLimit = 15
			cfg.Kinetic.RangeThreshold = 45
			cfg.Kinetic.IPv6SubThreshold = 55
			cfg.Kinetic.PortscanThreshold = 5
			cfg.Kinetic.EnforcementMode = "contain"

			var allowlist []string
			if sc.Allowlisted {
				allowlist = append(allowlist, sc.SourceIP)
			}

			state := NewState("4.1.0", cfg)
			rules := NewKineticRuleRegistry()
			eng := NewKineticEngine(cfg.Kinetic, state, rules, allowlist)
			// The burst corpus assumes one aligned accounting minute. A wall-clock
			// start near its boundary splits SYN samples into two independent windows.
			now := time.Now().UTC().Truncate(time.Minute)

			var detectedEvents []KineticEvent

			if len(sc.SourceIPs) > 0 {
				// Subnet distributed campaign
				for _, ipStr := range sc.SourceIPs {
					ip := net.ParseIP(ipStr)
					if ip == nil {
						t.Fatalf("invalid IP in corpus: %s", ipStr)
					}
					count := sc.PacketCountPerIP
					if count == 0 {
						count = 1
					}
					isSYN := sc.Flags == "SYN"
					var flags uint8 = 0x10 // ACK
					if isSYN {
						flags = 0x02 // SYN
					}
					family := uint8(4)
					if ip.To4() == nil {
						family = 6
					}
					for i := uint32(0); i < count; i++ {
						ts := now.Add(time.Duration(i*20) * time.Millisecond)
						evts := eng.IngestPacket(IngressPacket{
							Family:    family,
							Protocol:  6,
							SrcIP:     ip,
							DstIP:     net.ParseIP("198.51.100.1"),
							DstPort:   sc.TargetPort,
							TCPFlags:  flags,
							Bytes:     64,
							Timestamp: ts,
						})
						detectedEvents = append(detectedEvents, evts...)
					}
				}
			} else if len(sc.TargetPorts) > 0 {
				// Multi-port vertical scan
				ip := net.ParseIP(sc.SourceIP)
				if ip == nil {
					t.Fatalf("invalid source IP: %s", sc.SourceIP)
				}
				family := uint8(4)
				if ip.To4() == nil {
					family = 6
				}
				for i, port := range sc.TargetPorts {
					ts := now
					if sc.IntervalMillis > 0 {
						ts = now.Add(time.Duration(i*sc.IntervalMillis) * time.Millisecond)
					}
					evts := eng.IngestPacket(IngressPacket{
						Family:    family,
						Protocol:  6,
						SrcIP:     ip,
						DstIP:     net.ParseIP("198.51.100.1"),
						DstPort:   port,
						TCPFlags:  0x02, // SYN
						Bytes:     64,
						Timestamp: ts,
					})
					detectedEvents = append(detectedEvents, evts...)
				}
			} else {
				// Single source IP
				ip := net.ParseIP(sc.SourceIP)
				if ip == nil {
					t.Fatalf("invalid source IP: %s", sc.SourceIP)
				}
				count := sc.PacketCount
				if count == 0 {
					count = 1
				}
				isSYN := sc.Flags == "SYN"
				var flags uint8 = 0x10
				if isSYN {
					flags = 0x02
				}
				family := uint8(4)
				if ip.To4() == nil {
					family = 6
				}
				for i := uint32(0); i < count; i++ {
					ts := now.Add(time.Duration(i*20) * time.Millisecond)
					evts := eng.IngestPacket(IngressPacket{
						Family:    family,
						Protocol:  6,
						SrcIP:     ip,
						DstIP:     net.ParseIP("198.51.100.1"),
						DstPort:   sc.TargetPort,
						TCPFlags:  flags,
						Bytes:     64,
						Timestamp: ts,
					})
					detectedEvents = append(detectedEvents, evts...)
				}
			}

			if sc.Type == "false_positive_control" {
				if len(detectedEvents) > 0 {
					t.Fatalf("FALSE POSITIVE DETECTED in scenario %q: got %d events (%+v)", sc.Scenario, len(detectedEvents), detectedEvents[0])
				}
			} else if sc.Type == "attack_detection" {
				if len(detectedEvents) == 0 {
					t.Fatalf("ATTACK MISSED in scenario %q: expected rule %q but got 0 events", sc.Scenario, sc.ExpectedRule)
				}
				matchedExpected := false
				for _, ev := range detectedEvents {
					if ev.RuleID == sc.ExpectedRule {
						if sc.ExpectedAction != "" && ev.Action != sc.ExpectedAction {
							t.Fatalf("scenario %q: rule %q action=%q, expected %q", sc.Scenario, sc.ExpectedRule, ev.Action, sc.ExpectedAction)
						}
						matchedExpected = true
						break
					}
				}
				if !matchedExpected {
					t.Fatalf("scenario %q: expected rule %q, but events were: %+v", sc.Scenario, sc.ExpectedRule, detectedEvents)
				}
			}
		})
	}
}

type mockReleaseCore struct {
	blocked map[string]bool
}

func (m *mockReleaseCore) Add(target string) error {
	m.blocked[target] = true
	return nil
}

func (m *mockReleaseCore) Delete(target string) error {
	delete(m.blocked, target)
	return nil
}

func (m *mockReleaseCore) ClearBlocklist() error {
	m.blocked = make(map[string]bool)
	return nil
}

func (m *mockReleaseCore) VerifyBlocklistEmpty() error {
	return nil
}

func TestEvidenceEndToEndPipeline(t *testing.T) {
	// Point 96: Complete cryptographic tracking:
	// Sensor event -> rule match -> correlation -> decision -> block -> kernel applied -> signed policy -> evidence ledger -> UI -> expiry/rollback
	dir := t.TempDir()
	storageKey := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(storageKey, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence.jsonl")
	ledger, err := NewEvidenceLedger(path, filepath.Join(dir, "evidence.ed25519"), storageKey, "test-node", 4<<20)
	if err != nil {
		t.Fatalf("failed to create evidence ledger: %v", err)
	}

	cfg := defaultConfig()
	cfg.Release.EmergencyStopFile = filepath.Join(dir, "EMERGENCY_STOP")
	cfg.Policy.RequireSigned = false
	cfg.Kinetic.EnforcementMode = "block"
	state := NewState("4.2.1", cfg)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatalf("failed to attach evidence ledger: %v", err)
	}

	mockCore := &mockReleaseCore{blocked: make(map[string]bool)}
	armKineticResponseState(state)

	// 1. Ingress attack event
	rules := NewKineticRuleRegistry()
	engine := NewKineticEngine(cfg.Kinetic, state, rules, nil)
	attackerIP := net.ParseIP("198.51.100.200")
	now := time.Now().UTC()

	var events []KineticEvent
	for i := 0; i < 40; i++ {
		evts := engine.IngestPacket(IngressPacket{
			Family:    4,
			Protocol:  6,
			SrcIP:     attackerIP,
			DstIP:     net.ParseIP("198.51.100.1"),
			DstPort:   443,
			TCPFlags:  0x02, // SYN
			Bytes:     64,
			Timestamp: now.Add(time.Duration(i*20) * time.Millisecond),
		})
		events = append(events, evts...)
	}

	if len(events) == 0 {
		t.Fatal("expected kinetic detection events, got 0")
	}

	lastEvt := events[len(events)-1]
	if lastEvt.Fingerprint == "" {
		t.Fatal("expected non-empty deterministic fingerprint on KineticEvent")
	}

	// 2. Response decision
	decision := NetworkDecision{
		Target:          lastEvt.SourceIP,
		RuleIDs:         []string{lastEvt.RuleID},
		Score:           lastEvt.Score,
		Confidence:      lastEvt.Confidence,
		SuggestedAction: "block",
		BaseTTL:         24 * time.Hour,
		Reason:          lastEvt.Decision,
		Timestamp:       time.Now().UTC(),
	}

	respEngine := NewKineticResponseEngine(cfg, state, mockCore)
	executed, err := respEngine.ExecuteDecision(decision)
	if err != nil {
		t.Fatalf("failed to execute decision: %v", err)
	}

	if executed.Target != "198.51.100.200/32" {
		t.Fatalf("expected canonical /32 target, got %s", executed.Target)
	}
	if !executed.Enforced {
		t.Fatalf("expected executed.Enforced to be true")
	}

	// 3. The response engine applies the kernel mutation before the durable-commit
	// marker. In production CommitApplied runs only after signed policy persistence.
	target := executed.Target
	if !mockCore.blocked[target] {
		t.Fatalf("response engine did not apply kernel block for %s", target)
	}
	if err := respEngine.CommitApplied(decision, executed); err != nil {
		t.Fatalf("containment evidence commit failed: %v", err)
	}

	// 4. Verify Evidence Ledger integrity
	if err := ledger.Verify(); err != nil {
		t.Fatalf("evidence ledger verification failed: %v", err)
	}

	// 5. Verify snapshot reflects the block and rule evidence
	snap := state.Snapshot()
	if len(snap.Blocks) != 1 || snap.Blocks[0].Target != target {
		t.Fatalf("snapshot does not contain blocked target: %+v", snap.Blocks)
	}

	// 6. TTL Expiry and rollback through the single policy transaction owner.
	future := now.Add(24*time.Hour + 10*time.Second)
	expired, err := reconcileExpiredNetworkBlocks(future, state, mockCore, nil, cfg, nil)
	if err != nil {
		t.Fatalf("expiry transaction failed: %v", err)
	}
	if len(expired) != 1 || expired[0].Target != target {
		t.Fatalf("expected 1 expired rule, got %+v", expired)
	}
	if mockCore.blocked[target] {
		t.Fatalf("kernel mock still contains expired target %s", target)
	}

	// 7. Verify ledger again after full cycle
	if err := ledger.Verify(); err != nil {
		t.Fatalf("evidence ledger verification after expiry failed: %v", err)
	}

	records := ledger.Recent(100)
	if len(records) < 3 {
		t.Fatalf("expected detection, containment, and rollback evidence, got %d records", len(records))
	}
	kinds := make(map[string]bool)
	for _, record := range records {
		kinds[record.Kind] = true
	}
	for _, required := range []string{"kinetic_strike", "kinetic_containment", "kinetic_rollback"} {
		if !kinds[required] {
			t.Fatalf("expected evidence kind %s in full pipeline, got %+v", required, kinds)
		}
	}

	snapAfter := state.Snapshot()
	if len(snapAfter.Blocks) != 0 {
		t.Fatalf("expected 0 blocks after expiry, got %d", len(snapAfter.Blocks))
	}
}
