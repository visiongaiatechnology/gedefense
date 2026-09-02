// STATUS: DIAMANT VGT SUPREME
package main

import (
	"testing"
	"time"
)

func TestAttackStoryDAG_LinearChain(t *testing.T) {
	graph := NewAttackStoryGraph("test-chain-1")
	now := time.Now().UTC()

	node1 := AttackStoryNode{
		NodeID:     "node-1",
		Timestamp:  now,
		Sensor:     "EXEC",
		Category:   "EXECUTION",
		EventType:  "PROC_EXEC",
		EntityID:   "PID:1001",
		Actor:      "UID:1000",
		Severity:   "MEDIUM",
		Confidence: 75,
		CausalEdge: EdgeRootCause,
		EventUUID:  "uuid-1",
	}
	if err := graph.AddNode(node1); err != nil {
		t.Fatalf("failed to add root node: %v", err)
	}

	node2 := AttackStoryNode{
		NodeID:         "node-2",
		Timestamp:      now.Add(100 * time.Millisecond),
		Sensor:         "NETWORK",
		Category:       "LATERAL_MOVEMENT",
		EventType:      "SOCKET_CONNECT",
		EntityID:       "192.168.1.50:4444",
		Actor:          "UID:1000",
		Severity:       "HIGH",
		Confidence:     90,
		CausalEdge:     EdgeConnectedTo,
		CausalParentID: "node-1",
		EventUUID:      "uuid-2",
	}
	if err := graph.AddNode(node2); err != nil {
		t.Fatalf("failed to add child node: %v", err)
	}

	nodes := graph.CloneNodes()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if len(graph.RootNodes) != 1 || graph.RootNodes[0] != "node-1" {
		t.Fatalf("unexpected root nodes: %v", graph.RootNodes)
	}

	root := graph.EvidenceRoot()
	if root == "" || len(root) != 64 {
		t.Fatalf("invalid Merkle evidence root: %s", root)
	}
}

func TestAttackStoryDAG_CycleDetection(t *testing.T) {
	graph := NewAttackStoryGraph("test-cycle")
	now := time.Now().UTC()

	n1 := AttackStoryNode{
		NodeID:     "n1",
		Timestamp:  now,
		CausalEdge: EdgeRootCause,
	}
	if err := graph.AddNode(n1); err != nil {
		t.Fatalf("failed to add n1: %v", err)
	}

	n2 := AttackStoryNode{
		NodeID:         "n2",
		Timestamp:      now.Add(time.Millisecond),
		CausalParentID: "n1",
		CausalEdge:     EdgeConnectedTo,
	}
	if err := graph.AddNode(n2); err != nil {
		t.Fatalf("failed to add n2: %v", err)
	}

	// Try duplicate ID
	if err := graph.AddNode(n1); err == nil {
		t.Fatal("expected error on duplicate node ID, got nil")
	}

	// Try non-existent parent
	orphan := AttackStoryNode{
		NodeID:         "orphan",
		Timestamp:      now,
		CausalParentID: "does-not-exist",
	}
	if err := graph.AddNode(orphan); err == nil {
		t.Fatal("expected error on non-existent parent, got nil")
	}
}

func TestIncidentCorrelator_SlidingWindow(t *testing.T) {
	window := 2 * time.Second
	correlator := NewIncidentCorrelator(window)
	now := time.Now().UTC()

	node := AttackStoryNode{
		NodeID:     "event-1",
		Timestamp:  now,
		Sensor:     "DECEPTION",
		Category:   "CREDENTIAL_ACCESS",
		EventType:  "CANARY_HIT",
		EntityID:   "/tmp/.aws_credentials",
		Actor:      "user:bob",
		Severity:   "CRITICAL",
		Confidence: 100,
		CausalEdge: EdgeCanaryTriggered,
		EventUUID:  "evt-uuid-1",
	}

	graph, isNew, err := correlator.IngestEvent(now, "user:bob", "CREDENTIAL", "DECEPTION", node)
	if err != nil {
		t.Fatalf("failed to ingest: %v", err)
	}
	if !isNew {
		t.Fatal("expected new chain on first ingest")
	}
	if correlator.ActiveChainCount() != 1 {
		t.Fatalf("expected 1 active chain, got %d", correlator.ActiveChainCount())
	}

	// Ingest second node into same chain within window
	node2 := AttackStoryNode{
		NodeID:         "event-2",
		Timestamp:      now.Add(500 * time.Millisecond),
		Sensor:         "EXEC",
		Category:       "DECEPTION",
		EventType:      "PROC_KILL",
		EntityID:       "PID:5050",
		Actor:          "user:bob",
		Severity:       "CRITICAL",
		Confidence:     100,
		CausalParentID: "event-1",
		CausalEdge:     EdgePrivilegeEscalated,
		EventUUID:      "evt-uuid-2",
	}
	_, isNew2, err := correlator.IngestEvent(now.Add(500*time.Millisecond), "user:bob", "CREDENTIAL", "DECEPTION", node2)
	if err != nil {
		t.Fatalf("failed to ingest child: %v", err)
	}
	if isNew2 {
		t.Fatal("expected existing chain reuse, got new chain")
	}
	if len(graph.CloneNodes()) != 2 {
		t.Fatalf("expected 2 nodes in graph, got %d", len(graph.CloneNodes()))
	}

	// Advance time past sliding window -> should prune
	future := now.Add(5 * time.Second)
	correlator.IngestEvent(future, "user:alice", "NETWORK", "SCAN", AttackStoryNode{
		NodeID:     "alice-1",
		Timestamp:  future,
		CausalEdge: EdgeRootCause,
	})

	if correlator.ActiveChainCount() != 1 {
		t.Fatalf("expected old chain to be pruned, remaining: %d", correlator.ActiveChainCount())
	}
}
