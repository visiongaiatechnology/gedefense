// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type l7CorrelationContext struct {
	seen       time.Time
	requestID  string
	host       string
	path       string
	score      int
	categories []string
}

type L7CorrelationStore struct {
	mu             sync.Mutex
	window         time.Duration
	maxPeers       int
	byRemote       map[string][]l7CorrelationContext
	slotByRemote   map[string]int
	slots          []string
	freeSlots      []int
	evictionCursor int
	lastPrune      time.Time
	pruneInterval  time.Duration
}

func NewL7CorrelationStore(window time.Duration, maxPeers int) *L7CorrelationStore {
	if window <= 0 {
		window = 30 * time.Second
	}
	if maxPeers < 128 {
		maxPeers = 128
	}
	pruneInterval := window / 4
	if pruneInterval < time.Second {
		pruneInterval = time.Second
	}
	if pruneInterval > 5*time.Second {
		pruneInterval = 5 * time.Second
	}
	freeSlots := make([]int, maxPeers)
	for i := range freeSlots {
		freeSlots[i] = maxPeers - 1 - i
	}
	return &L7CorrelationStore{
		window: window, maxPeers: maxPeers, byRemote: make(map[string][]l7CorrelationContext, maxPeers),
		slotByRemote: make(map[string]int, maxPeers), slots: make([]string, maxPeers), freeSlots: freeSlots,
		pruneInterval: pruneInterval,
	}
}

func (s *L7CorrelationStore) Observe(now time.Time, req l7NormalizedRequest, response L7InspectionResponse) {
	if s == nil || req.RemoteIP == "" || response.Score <= 0 || len(response.Findings) == 0 {
		return
	}
	categories := make([]string, 0, 4)
	seenCategory := make(map[string]struct{}, 4)
	for _, finding := range response.Findings {
		if _, exists := seenCategory[finding.Category]; exists {
			continue
		}
		seenCategory[finding.Category] = struct{}{}
		categories = append(categories, finding.Category)
		if len(categories) == 4 {
			break
		}
	}
	context := l7CorrelationContext{
		seen: now, requestID: req.RequestID, host: req.Host, path: req.Path,
		score: response.Score, categories: categories,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	s.ensurePeerSlotLocked(req.RemoteIP)
	contexts := s.byRemote[req.RemoteIP]
	if len(contexts) >= 4 {
		copy(contexts, contexts[len(contexts)-3:])
		contexts = contexts[:3]
	}
	s.byRemote[req.RemoteIP] = append(contexts, context)
}

func (s *L7CorrelationStore) Match(connections []NetConnection, now time.Time) []RuleMatch {
	if s == nil || len(connections) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	matches := make([]RuleMatch, 0, 1)
	seenRemote := make(map[string]struct{}, len(connections))
	for _, connection := range connections {
		remote := connection.RemoteIP
		if remote == "" {
			continue
		}
		if _, exists := seenRemote[remote]; exists {
			continue
		}
		seenRemote[remote] = struct{}{}
		contexts := s.byRemote[remote]
		fresh := contexts[:0]
		var strongest l7CorrelationContext
		hasStrongest := false
		for i := range contexts {
			if now.Sub(contexts[i].seen) > s.window {
				continue
			}
			fresh = append(fresh, contexts[i])
			if !hasStrongest || contexts[i].score > strongest.score {
				strongest = contexts[i]
				hasStrongest = true
			}
		}
		if len(fresh) == 0 {
			s.releasePeerSlotLocked(remote)
		} else {
			s.byRemote[remote] = fresh
		}
		if hasStrongest {
			score := strongest.score / 2
			if score < 20 {
				score = 20
			}
			if score > 55 {
				score = 55
			}
			matches = append(matches, RuleMatch{
				ID: "L7.CORRELATED_REMOTE", Category: "web-correlation", Score: score,
				Summary:      fmt.Sprintf("Recent hostile HTTP request from process-connected remote (%s%s)", strongest.host, strongest.path),
				KillEligible: false, AlertOnly: true, Remote: remote,
			})
			break
		}
	}
	return matches
}

func (s *L7CorrelationStore) maybePruneLocked(now time.Time) {
	if !s.lastPrune.IsZero() && now.Sub(s.lastPrune) < s.pruneInterval {
		return
	}
	s.pruneLocked(now)
	s.lastPrune = now
}

func (s *L7CorrelationStore) pruneLocked(now time.Time) {
	cutoff := now.Add(-s.window)
	for remote, contexts := range s.byRemote {
		fresh := contexts[:0]
		for _, context := range contexts {
			if !context.seen.Before(cutoff) {
				fresh = append(fresh, context)
			}
		}
		if len(fresh) == 0 {
			s.releasePeerSlotLocked(remote)
		} else {
			s.byRemote[remote] = fresh
		}
	}
}

func (s *L7CorrelationStore) ensurePeerSlotLocked(remote string) {
	if _, exists := s.slotByRemote[remote]; exists {
		return
	}
	if len(s.freeSlots) > 0 {
		last := len(s.freeSlots) - 1
		slot := s.freeSlots[last]
		s.freeSlots = s.freeSlots[:last]
		s.slots[slot] = remote
		s.slotByRemote[remote] = slot
		return
	}
	for scanned := 0; scanned < s.maxPeers; scanned++ {
		slot := s.evictionCursor % s.maxPeers
		s.evictionCursor = (s.evictionCursor + 1) % s.maxPeers
		oldRemote := s.slots[slot]
		if oldRemote == "" {
			s.slots[slot] = remote
			s.slotByRemote[remote] = slot
			return
		}
		delete(s.byRemote, oldRemote)
		delete(s.slotByRemote, oldRemote)
		s.slots[slot] = remote
		s.slotByRemote[remote] = slot
		return
	}
}

func (s *L7CorrelationStore) releasePeerSlotLocked(remote string) {
	delete(s.byRemote, remote)
	slot, exists := s.slotByRemote[remote]
	if !exists {
		return
	}
	delete(s.slotByRemote, remote)
	s.slots[slot] = ""
	s.freeSlots = append(s.freeSlots, slot)
}

func (e *XDREngine) RecordL7Inspection(req l7NormalizedRequest, response L7InspectionResponse) {
	if e == nil || len(response.Findings) == 0 {
		return
	}
	now := time.Now().UTC()
	if e.l7Recent != nil {
		e.l7Recent.Observe(now, req, response)
	}
	fingerprint := "l7:" + req.RequestID
	if !e.claimFingerprint(fingerprint) {
		return
	}
	severity := "warning"
	if response.Score >= e.cfg.L7.BlockScore {
		severity = "high"
	}
	if response.Score >= 150 {
		severity = "critical"
	}
	ruleIDs := make([]string, 0, len(response.Findings))
	categories := make([]string, 0, len(response.Findings))
	seenCategories := make(map[string]struct{}, len(response.Findings))
	for _, finding := range response.Findings {
		ruleIDs = append(ruleIDs, finding.RuleID)
		if _, exists := seenCategories[finding.Category]; !exists {
			seenCategories[finding.Category] = struct{}{}
			categories = append(categories, finding.Category)
		}
	}
	summary := l7FindingSummary(response.Findings)
	incidentID := randomID()
	node := AttackStoryNode{
		NodeID: fmt.Sprintf("http-%s", req.RequestID), Timestamp: now, Sensor: "l7", Category: strings.Join(categories, ","),
		EventType: "HTTP_REQUEST", EntityID: req.Host + req.Path, Actor: "IP:" + req.RemoteIP,
		Severity: severity, Confidence: response.Confidence, CausalEdge: EdgeRootCause, EventUUID: incidentID,
		Metadata: map[string]string{
			"method": req.Method, "host": req.Host, "path": req.Path, "request_id": req.RequestID,
			"body_sha256": req.BodySHA256, "server_process": req.ServerProcess,
		},
	}
	var story []AttackStoryNode
	chainID := node.NodeID
	recordHash := node.ComputeNodeDigest()
	if e.correlator != nil {
		graph, _, err := e.correlator.IngestEvent(now, "IP:"+req.RemoteIP, req.Host, "HTTP", node)
		if err == nil && graph != nil {
			story = graph.CloneNodes()
			chainID = graph.ChainID
			recordHash = graph.EvidenceRoot()
		}
	}
	if len(story) == 0 {
		node.Digest = node.ComputeNodeDigest()
		story = []AttackStoryNode{node}
	}
	decision := "alert"
	action := "none"
	outcome := "observed"
	if response.Enforced && response.Decision == "block" {
		decision = "deny-http"
		action = "deny-request"
		outcome = "blocked before upstream application handling"
	}
	incident := XDRIncident{
		ID: incidentID, Time: now, Severity: severity, Score: response.Score, ResponseScore: 0,
		PID: req.ServerPID, Process: req.ServerProcess, Remote: req.RemoteIP,
		RuleIDs: ruleIDs, Categories: categories, Summary: summary, Decision: decision, Action: action, Outcome: outcome,
		ExecutionChainID: chainID, AttackStory: story, RecordHash: recordHash,
		RequestID: req.RequestID, HTTPMethod: req.Method, HTTPHost: req.Host, HTTPPath: req.Path, BodySHA256: req.BodySHA256,
	}
	e.appendIncident(incident)
	kind := "l7.alert"
	if response.Enforced {
		kind = "l7.block"
	}
	e.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "l7", Message: summary, Target: req.Host + req.Path})
}

func (e *XDREngine) RecordL7ResponseInspection(req l7NormalizedRequest, statusCode int, findings []L7Finding) {
	if e == nil || len(findings) == 0 {
		return
	}
	score, confidence, unique := aggregateL7Findings(findings)
	if len(unique) == 0 {
		return
	}
	now := time.Now().UTC()
	fingerprint := fmt.Sprintf("l7-response:%s:%d:%s", req.RequestID, statusCode, unique[0].RuleID)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	severity := "warning"
	if score >= 80 {
		severity = "high"
	}
	if score >= 120 {
		severity = "critical"
	}
	ruleIDs := make([]string, 0, len(unique))
	categories := make([]string, 0, len(unique))
	seenCategories := make(map[string]struct{}, len(unique))
	for _, finding := range unique {
		ruleIDs = append(ruleIDs, finding.RuleID)
		if _, exists := seenCategories[finding.Category]; !exists {
			seenCategories[finding.Category] = struct{}{}
			categories = append(categories, finding.Category)
		}
	}
	node := AttackStoryNode{
		NodeID: fmt.Sprintf("http-response-%s", req.RequestID), Timestamp: now, Sensor: "l7", Category: strings.Join(categories, ","),
		EventType: "HTTP_RESPONSE", EntityID: req.Host + req.Path, Actor: "SERVICE:" + req.ServerProcess,
		Severity: severity, Confidence: confidence, CausalEdge: EdgeRootCause, EventUUID: randomID(),
		Metadata: map[string]string{
			"method": req.Method, "host": req.Host, "path": req.Path, "request_id": req.RequestID,
			"status_code": strconv.Itoa(statusCode), "body_sha256": req.BodySHA256,
		},
	}
	node.Digest = node.ComputeNodeDigest()
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: severity, Score: score, ResponseScore: 0,
		PID: req.ServerPID, Process: req.ServerProcess, Remote: req.RemoteIP,
		RequestID: req.RequestID, HTTPMethod: req.Method, HTTPHost: req.Host, HTTPPath: req.Path, BodySHA256: req.BodySHA256,
		RuleIDs: ruleIDs, Categories: categories, Summary: l7FindingSummary(unique),
		Decision: "alert", Action: "none", Outcome: "response observed; no destructive authority granted",
		AttackStory: []AttackStoryNode{node}, RecordHash: node.Digest,
	}
	e.appendIncident(incident)
	e.state.AddEvent(Event{Severity: severity, Kind: "l7.response", Source: "l7", Message: incident.Summary, Target: req.Host + req.Path})
}
