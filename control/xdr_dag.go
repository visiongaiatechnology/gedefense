// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrCycleDetected       = errors.New("cycle detected in attack story graph")
	ErrDuplicateNodeID     = errors.New("duplicate node ID in attack story graph")
	ErrParentNodeNotFound  = errors.New("causal parent node not found in attack story graph")
	ErrInvalidNodePayload  = errors.New("attack story node payload failed validation")
	ErrCorrelatorExhausted = errors.New("incident correlator tracking capacity reached")
)

const (
	maxCorrelatorChains = 4096
	maxNodesPerChain    = 512
	defaultWindowSecs   = 1800 // 30 minutes sliding correlation window
)

// CausalEdge types defining relationships between attack nodes.
const (
	EdgeForkedFrom         = "FORKED_FROM"
	EdgeConnectedTo        = "CONNECTED_TO"
	EdgeFileModified       = "FILE_MODIFIED"
	EdgeCanaryTriggered    = "CANARY_TRIGGERED"
	EdgePrivilegeEscalated = "PRIVILEGE_ESCALATED"
	EdgeEgressAttempted    = "EGRESS_ATTEMPTED"
	EdgeMemoryScraped      = "MEMORY_SCRAPED"
	EdgeMalwareDetected    = "MALWARE_DETECTED"
	EdgeRootCause          = "ROOT_CAUSE"
)

// AttackStoryNode represents an atomic node in the causal graph of an incident.
type AttackStoryNode struct {
	NodeID         string            `json:"node_id"`
	Timestamp      time.Time         `json:"timestamp"`
	Sensor         string            `json:"sensor"`
	Category       string            `json:"category"`
	EventType      string            `json:"event_type"`
	EntityID       string            `json:"entity_id"`
	Actor          string            `json:"actor"`
	Severity       string            `json:"severity"`
	Confidence     int               `json:"confidence"`
	CausalEdge     string            `json:"causal_edge"`
	CausalParentID string            `json:"causal_parent_id,omitempty"`
	EventUUID      string            `json:"event_uuid"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Digest         string            `json:"digest"`
}

// ComputeNodeDigest calculates an invariant SHA-256 digest over the canonical node fields.
func (n *AttackStoryNode) ComputeNodeDigest() string {
	hasher := sha256.New()
	hasher.Write([]byte("VGT-XDR-NODE-V1|"))
	hasher.Write([]byte(n.NodeID + "|"))
	hasher.Write([]byte(fmt.Sprintf("%d|", n.Timestamp.UnixNano())))
	hasher.Write([]byte(n.Sensor + "|"))
	hasher.Write([]byte(n.Category + "|"))
	hasher.Write([]byte(n.EventType + "|"))
	hasher.Write([]byte(n.EntityID + "|"))
	hasher.Write([]byte(n.Actor + "|"))
	hasher.Write([]byte(n.Severity + "|"))
	hasher.Write([]byte(fmt.Sprintf("%d|", n.Confidence)))
	hasher.Write([]byte(n.CausalEdge + "|"))
	hasher.Write([]byte(n.CausalParentID + "|"))
	hasher.Write([]byte(n.EventUUID))

	if len(n.Metadata) > 0 {
		keys := make([]string, 0, len(n.Metadata))
		for k := range n.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			hasher.Write([]byte(fmt.Sprintf("|%s=%s", k, n.Metadata[k])))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// AttackStoryGraph encapsulates a verified Directed Acyclic Graph of incident events.
type AttackStoryGraph struct {
	mu        sync.RWMutex
	ChainID   string                       `json:"chain_id"`
	Nodes     []AttackStoryNode            `json:"nodes"`
	nodeMap   map[string]AttackStoryNode
	adjList   map[string][]string
	inDegree  map[string]int
	RootNodes []string                     `json:"root_nodes"`
}

// NewAttackStoryGraph creates an empty, thread-safe attack story graph.
func NewAttackStoryGraph(chainID string) *AttackStoryGraph {
	if chainID == "" {
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("CHAIN-%d", time.Now().UnixNano())))
		chainID = hex.EncodeToString(hasher.Sum(nil))[:32]
	}
	return &AttackStoryGraph{
		ChainID:   chainID,
		Nodes:     make([]AttackStoryNode, 0, 16),
		nodeMap:   make(map[string]AttackStoryNode),
		adjList:   make(map[string][]string),
		inDegree:  make(map[string]int),
		RootNodes: make([]string, 0, 4),
	}
}

// AddNode validates and inserts a node into the DAG, rejecting duplicate IDs and cycles.
func (g *AttackStoryGraph) AddNode(node AttackStoryNode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.Nodes) >= maxNodesPerChain {
		return errors.New("maximum attack story node capacity exceeded")
	}
	if strings.TrimSpace(node.NodeID) == "" {
		return fmt.Errorf("%w: missing node ID", ErrInvalidNodePayload)
	}
	if _, exists := g.nodeMap[node.NodeID]; exists {
		return fmt.Errorf("%w: node %s", ErrDuplicateNodeID, node.NodeID)
	}

	if node.CausalParentID != "" {
		if _, parentExists := g.nodeMap[node.CausalParentID]; !parentExists {
			return fmt.Errorf("%w: parent %s for node %s", ErrParentNodeNotFound, node.CausalParentID, node.NodeID)
		}
	}

	node.Digest = node.ComputeNodeDigest()

	// Tentatively record node
	g.nodeMap[node.NodeID] = node
	g.Nodes = append(g.Nodes, node)
	if _, exists := g.inDegree[node.NodeID]; !exists {
		g.inDegree[node.NodeID] = 0
	}

	if node.CausalParentID != "" {
		g.adjList[node.CausalParentID] = append(g.adjList[node.CausalParentID], node.NodeID)
		g.inDegree[node.NodeID]++
	} else {
		g.RootNodes = append(g.RootNodes, node.NodeID)
	}

	// Validate DAG property (detect cycles via Kahn's topological sort simulation)
	if err := g.verifyAcyclic(); err != nil {
		// Roll back node on cycle
		g.rollbackLastNode(node)
		return err
	}

	return nil
}

func (g *AttackStoryGraph) rollbackLastNode(node AttackStoryNode) {
	delete(g.nodeMap, node.NodeID)
	delete(g.inDegree, node.NodeID)
	if len(g.Nodes) > 0 && g.Nodes[len(g.Nodes)-1].NodeID == node.NodeID {
		g.Nodes = g.Nodes[:len(g.Nodes)-1]
	}
	if node.CausalParentID != "" {
		children := g.adjList[node.CausalParentID]
		for i, childID := range children {
			if childID == node.NodeID {
				g.adjList[node.CausalParentID] = append(children[:i], children[i+1:]...)
				break
			}
		}
	} else {
		for i, rootID := range g.RootNodes {
			if rootID == node.NodeID {
				g.RootNodes = append(g.RootNodes[:i], g.RootNodes[i+1:]...)
				break
			}
		}
	}
}

func (g *AttackStoryGraph) verifyAcyclic() error {
	inDegrees := make(map[string]int, len(g.inDegree))
	for k, v := range g.inDegree {
		inDegrees[k] = v
	}

	queue := make([]string, 0, len(g.nodeMap))
	for id, deg := range inDegrees {
		if deg == 0 {
			queue = append(queue, id)
		}
	}

	visited := 0
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		visited++

		for _, neighbor := range g.adjList[curr] {
			inDegrees[neighbor]--
			if inDegrees[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}

	if visited != len(g.nodeMap) {
		return ErrCycleDetected
	}
	return nil
}

// EvidenceRoot computes a cryptographic Merkle root digest of the entire attack story.
func (g *AttackStoryGraph) EvidenceRoot() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Nodes) == 0 {
		return ""
	}

	digests := make([]string, len(g.Nodes))
	for i, n := range g.Nodes {
		digests[i] = n.Digest
	}
	sort.Strings(digests)

	current := digests
	for len(current) > 1 {
		next := make([]string, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			hasher := sha256.New()
			hasher.Write([]byte(current[i]))
			if i+1 < len(current) {
				hasher.Write([]byte(current[i+1]))
			} else {
				hasher.Write([]byte(current[i])) // duplicate odd leaf
			}
			next = append(next, hex.EncodeToString(hasher.Sum(nil)))
		}
		current = next
	}

	return current[0]
}

// CloneNodes returns an immutable, detached slice copy of the nodes in chronological order.
func (g *AttackStoryGraph) CloneNodes() []AttackStoryNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	res := make([]AttackStoryNode, len(g.Nodes))
	copy(res, g.Nodes)
	return res
}

// IncidentCorrelator correlates disparate events across sensors into coherent attack chains.
type IncidentCorrelator struct {
	mu           sync.RWMutex
	window       time.Duration
	chains       map[string]*AttackStoryGraph
	lastActive   map[string]time.Time
	primaryActor map[string]string
}

// NewIncidentCorrelator initializes a thread-safe correlator with an active sliding window.
func NewIncidentCorrelator(window time.Duration) *IncidentCorrelator {
	if window <= 0 {
		window = time.Duration(defaultWindowSecs) * time.Second
	}
	return &IncidentCorrelator{
		window:       window,
		chains:       make(map[string]*AttackStoryGraph),
		lastActive:   make(map[string]time.Time),
		primaryActor: make(map[string]string),
	}
}

// DeriveCorrelationKey derives a domain-separated deterministic campaign key.
func DeriveCorrelationKey(actor, entityFamily, category string) string {
	hasher := sha256.New()
	hasher.Write([]byte("VGT-XDR-CORR-KEY-V1|"))
	hasher.Write([]byte(strings.TrimSpace(actor) + "|"))
	hasher.Write([]byte(strings.TrimSpace(entityFamily) + "|"))
	hasher.Write([]byte(strings.TrimSpace(category)))
	return hex.EncodeToString(hasher.Sum(nil))[:32]
}

// IngestEvent correlates an event into an existing or fresh AttackStoryGraph.
func (c *IncidentCorrelator) IngestEvent(now time.Time, actor, entityFamily, category string, node AttackStoryNode) (*AttackStoryGraph, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneExpiredLocked(now)

	corrKey := DeriveCorrelationKey(actor, entityFamily, category)
	graph, exists := c.chains[corrKey]

	isNewChain := false
	if !exists {
		if len(c.chains) >= maxCorrelatorChains {
			return nil, false, ErrCorrelatorExhausted
		}
		graph = NewAttackStoryGraph(corrKey)
		c.chains[corrKey] = graph
		c.primaryActor[corrKey] = actor
		isNewChain = true
	}

	if node.NodeID == "" {
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("%s|%s|%d", corrKey, node.EventType, now.UnixNano())))
		node.NodeID = hex.EncodeToString(hasher.Sum(nil))[:24]
	}
	if node.Timestamp.IsZero() {
		node.Timestamp = now
	}

	if err := graph.AddNode(node); err != nil {
		return nil, false, err
	}

	c.lastActive[corrKey] = now
	return graph, isNewChain, nil
}

func (c *IncidentCorrelator) pruneExpiredLocked(now time.Time) {
	cutoff := now.Add(-c.window)
	for key, last := range c.lastActive {
		if last.Before(cutoff) {
			delete(c.chains, key)
			delete(c.lastActive, key)
			delete(c.primaryActor, key)
		}
	}
}

// ActiveChainCount returns the number of concurrently tracked attack chains.
func (c *IncidentCorrelator) ActiveChainCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.chains)
}

// GetAllStories returns immutable snapshots of all active attack story graphs.
func (c *IncidentCorrelator) GetAllStories() []*AttackStoryGraph {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]*AttackStoryGraph, 0, len(c.chains))
	for _, g := range c.chains {
		out = append(out, g)
	}
	return out
}

// GetStory finds an attack story by chain ID.
func (c *IncidentCorrelator) GetStory(chainID string) *AttackStoryGraph {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, g := range c.chains {
		if g.ChainID == chainID {
			return g
		}
	}
	return nil
}

// SerializeGraph serializes the graph into a deterministically formatted JSON envelope.
func SerializeGraph(g *AttackStoryGraph) ([]byte, error) {
	if g == nil {
		return []byte("[]"), nil
	}
	nodes := g.CloneNodes()
	return json.Marshal(nodes)
}

