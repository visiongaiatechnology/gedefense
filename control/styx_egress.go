// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Typed Styx Error Hierarchy (Section 1.5.A Compliance)
type StyxException struct {
	Message string
	Err     error
}

func (e *StyxException) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *StyxException) Unwrap() error { return e.Err }

type StyxValidationException struct{ StyxException }
type StyxSecurityException struct{ StyxException }

func NewStyxValidationException(msg string, err error) *StyxValidationException {
	return &StyxValidationException{StyxException{Message: msg, Err: err}}
}

func NewStyxSecurityException(msg string, err error) *StyxSecurityException {
	return &StyxSecurityException{StyxException{Message: msg, Err: err}}
}

type EgressPolicyMode string

const (
	EgressModeDefaultDeny   EgressPolicyMode = "DEFAULT_DENY"
	EgressModeWhitelistOnly EgressPolicyMode = "WHITELIST_ONLY"
	EgressModeMonitored     EgressPolicyMode = "MONITORED"
)

// EgressRule defines a cryptographically identifiable outbound network permission.
type EgressRule struct {
	ID          string `json:"id"`
	ScopeType   string `json:"scope_type"` // CELL, CGROUP, SERVICE, GLOBAL
	ScopeID     string `json:"scope_id"`   // Cell UUID, systemd slice/service, or "*"
	Destination string `json:"destination"`
	Port        uint16 `json:"port"`
	Protocol    string `json:"protocol"` // TCP, UDP, ALL
	Action      string `json:"action"`   // ALLOW, DROP
	Description string `json:"description"`
}

// StyxEngine enforces kernel-level Zero-Trust Egress, SSRF shields and cell boundary networking.
type StyxEngine struct {
	mu              sync.RWMutex
	mode            EgressPolicyMode
	rules           map[string]EgressRule
	scopeRules      map[string][]EgressRule
	parsedCIDRs     map[string]*net.IPNet
	metadataBlocked atomic.Uint64
	egressDrops     atomic.Uint64
	correlator      *IncidentCorrelator
	incidentSink    func(XDRIncident) error
}

func NewStyxEngine(
	mode EgressPolicyMode,
	correlator *IncidentCorrelator,
	incidentSink func(XDRIncident) error,
) *StyxEngine {
	return &StyxEngine{
		mode:         mode,
		rules:        make(map[string]EgressRule),
		scopeRules:   make(map[string][]EgressRule),
		parsedCIDRs:  make(map[string]*net.IPNet),
		correlator:   correlator,
		incidentSink: incidentSink,
	}
}

// IsCloudMetadataDestination checks if an IP belongs to cloud metadata services (IMDS),
// carrier-grade NAT cloud endpoints, or cloud provider wire servers.
func IsCloudMetadataDestination(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Normalize IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254)
	if ip4 := ip.To4(); ip4 != nil {
		// 169.254.0.0/16 (Link-Local: AWS, GCP, Azure, OCI, OpenStack IMDS)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 100.100.100.200 (Alibaba Cloud IMDS)
		if ip4[0] == 100 && ip4[1] == 100 && ip4[2] == 100 && ip4[3] == 200 {
			return true
		}
		// 168.63.129.16 (Azure WireServer / Host Resolver)
		if ip4[0] == 168 && ip4[1] == 63 && ip4[2] == 129 && ip4[3] == 16 {
			return true
		}
		return false
	}
	// AWS IMDSv2 IPv6: [fd00:ec2::254]
	awsIPv6IMDS := net.ParseIP("fd00:ec2::254")
	if awsIPv6IMDS != nil && ip.Equal(awsIPv6IMDS) {
		return true
	}
	// General Link-Local IPv6 fe80::/10
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}

// AddRule registers an outbound egress permission with strict CIDR validation.
func (s *StyxEngine) AddRule(rule EgressRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule.Destination = strings.TrimSpace(rule.Destination)
	if rule.Destination == "" {
		return NewStyxValidationException("egress rule destination cannot be empty", nil)
	}

	if rule.ID == "" {
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("%s|%s|%s|%d|%s", rule.ScopeType, rule.ScopeID, rule.Destination, rule.Port, rule.Protocol)))
		rule.ID = "STYX-" + hex.EncodeToString(hasher.Sum(nil))[:16]
	}

	// Parse Destination IP / CIDR
	if strings.Contains(rule.Destination, "/") {
		_, ipNet, err := net.ParseCIDR(rule.Destination)
		if err != nil {
			return NewStyxValidationException("invalid destination CIDR format", err)
		}
		s.parsedCIDRs[rule.ID] = ipNet
	} else if ip := net.ParseIP(rule.Destination); ip != nil {
		mask := 32
		if ip.To4() == nil {
			mask = 128
		}
		_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), mask))
		s.parsedCIDRs[rule.ID] = ipNet
	}

	s.rules[rule.ID] = rule
	scopeKey := fmt.Sprintf("%s:%s", rule.ScopeType, rule.ScopeID)
	s.scopeRules[scopeKey] = append(s.scopeRules[scopeKey], rule)
	return nil
}

// EvaluateEgress validates whether a process in a designated cell or scope is authorized to connect out.
func (s *StyxEngine) EvaluateEgress(
	ctx context.Context,
	scopeType, scopeID string,
	remoteIPStr string,
	remotePort uint16,
	proto string,
	pid int,
	comm string,
) (bool, string, error) {
	ip := net.ParseIP(strings.TrimSpace(remoteIPStr))
	if ip == nil {
		return false, "DROP_INVALID_IP", NewStyxValidationException("invalid remote IP", nil)
	}

	now := time.Now().UTC()

	// 1. Morpheus Cloud-Metadata & SSRF Guard (Strict Invariant)
	if IsCloudMetadataDestination(ip) {
		s.metadataBlocked.Add(1)
		s.egressDrops.Add(1)

		incidentID := fmt.Sprintf("INC-SSRF-%d-%d", pid, now.UnixNano())
		actorStr := fmt.Sprintf("PID:%d|%s", pid, comm)

		storyNode := AttackStoryNode{
			NodeID:     fmt.Sprintf("node-ssrf-%d", now.UnixNano()),
			Timestamp:  now,
			Sensor:     "MORPHEUS_RASP_SSRF",
			Category:   "CREDENTIAL_ACCESS",
			EventType:  "METADATA_ACCESS_ATTEMPT",
			EntityID:   remoteIPStr,
			Actor:      actorStr,
			Severity:   "CRITICAL",
			Confidence: 100,
			CausalEdge: EdgeEgressAttempted,
			EventUUID:  incidentID,
			Metadata: map[string]string{
				"target_ip": remoteIPStr,
				"comm":      comm,
				"scope":     fmt.Sprintf("%s:%s", scopeType, scopeID),
			},
		}

		var storyNodes []AttackStoryNode
		var recordHash string
		if s.correlator != nil {
			graph, _, err := s.correlator.IngestEvent(now, actorStr, "METADATA_SSRF", "EXFILTRATION", storyNode)
			if err == nil && graph != nil {
				storyNodes = graph.CloneNodes()
				recordHash = graph.EvidenceRoot()
			}
		}
		if len(storyNodes) == 0 {
			storyNodes = []AttackStoryNode{storyNode}
			recordHash = storyNode.ComputeNodeDigest()
		}

		if s.incidentSink != nil {
			_ = s.incidentSink(XDRIncident{
				ID:            incidentID,
				Time:          now,
				Severity:      "CRITICAL",
				Score:         250,
				ResponseScore: 250,
				PID:           pid,
				Process:       comm,
				Remote:        remoteIPStr,
				Summary:       fmt.Sprintf("Cloud metadata exfiltration attempt blocked: PID %d (%s) attempted connecting to %s", pid, comm, remoteIPStr),
				RuleIDs:       []string{"STYX.EGRESS.METADATA_BLOCKED", "MORPHEUS.SSRF_IMDS"},
				Categories:    []string{"exfiltration", "credential_access"},
				Decision:      "drop",
				Action:        "block-egress",
				Outcome:       "dropped by kernel styx egress shield",
				AttackStory:   storyNodes,
				EvidenceRoot:  recordHash,
			})
		}

		return false, "DROP_CLOUD_METADATA_SSRF", nil
	}

	// 2. Monitored Mode -> always permit
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()

	if mode == EgressModeMonitored {
		return true, "PERMIT_MONITORED", nil
	}

	// 3. Evaluate Whitelist Policies
	s.mu.RLock()
	defer s.mu.RUnlock()

	scopeKey := fmt.Sprintf("%s:%s", scopeType, scopeID)
	globalKey := "GLOBAL:*"

	matchingRules := append([]EgressRule{}, s.scopeRules[scopeKey]...)
	matchingRules = append(matchingRules, s.scopeRules[globalKey]...)

	for _, rule := range matchingRules {
		if rule.Port != 0 && rule.Port != remotePort {
			continue
		}
		if rule.Protocol != "ALL" && !strings.EqualFold(rule.Protocol, proto) {
			continue
		}

		if ipNet, exists := s.parsedCIDRs[rule.ID]; exists && ipNet.Contains(ip) {
			if rule.Action == "ALLOW" {
				return true, "PERMIT_WHITELIST", nil
			}
			return false, "DROP_EXPLICIT_POLICY", nil
		}
	}

	// 4. Default-Deny Decision
	s.egressDrops.Add(1)
	return false, "DROP_DEFAULT_DENY", nil
}

// Rules returns an immutable copy of all installed egress policies.
func (s *StyxEngine) Rules() []EgressRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]EgressRule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	return out
}

// Stats returns atomic counters for egress drops and metadata shields.
func (s *StyxEngine) Stats() (uint64, uint64) {
	return s.egressDrops.Load(), s.metadataBlocked.Load()
}
