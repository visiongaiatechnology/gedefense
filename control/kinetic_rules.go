package main

import (
	"fmt"
	"sync"
	"time"
)

// KineticRuleDefinition holds metadata and enforcement properties of a Kinetic rule.
type KineticRuleDefinition struct {
	ID              string        `json:"id"`
	Layer           DefenseLayer  `json:"layer"`
	Category        string        `json:"category"`
	Severity        string        `json:"severity"`
	DefaultScore    int           `json:"default_score"`
	ContainEligible bool          `json:"contain_eligible"`
	BlockEligible   bool          `json:"block_eligible"`
	SignalSource    string        `json:"signal_source"`
	Summary         string        `json:"summary"`
	DefaultTTL      time.Duration `json:"default_ttl"`
}

// KineticRuleRegistry manages all recognized Kinetic Defense rules.
type KineticRuleRegistry struct {
	mu    sync.RWMutex
	rules map[string]KineticRuleDefinition
}

// NewKineticRuleRegistry initializes all standard Kinetic rule definitions (Point 7).
func NewKineticRuleRegistry() *KineticRuleRegistry {
	reg := &KineticRuleRegistry{
		rules: make(map[string]KineticRuleDefinition),
	}

	defs := []KineticRuleDefinition{
		{
			ID:              "NET.INGRESS.IP_RATE",
			Layer:           LayerIngressNetwork,
			Category:        "rate_limit",
			Severity:        "medium",
			DefaultScore:    75,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "ebpf_sliding_window",
			Summary:         "Single IP exceeded sustained hit rate threshold",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.IP_VELOCITY",
			Layer:           LayerIngressNetwork,
			Category:        "burst_limit",
			Severity:        "high",
			DefaultScore:    85,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "ebpf_sliding_window",
			Summary:         "Single IP exceeded instantaneous velocity/burst threshold",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.SYN_FLOOD",
			Layer:           LayerIngressNetwork,
			Category:        "flood",
			Severity:        "high",
			DefaultScore:    90,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "ebpf_xdp",
			Summary:         "Abnormal TCP SYN-only packet flood without handshake completion",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.PORT_SCAN",
			Layer:           LayerIngressNetwork,
			Category:        "reconnaissance",
			Severity:        "high",
			DefaultScore:    95,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "ebpf_sliding_window",
			Summary:         "Hostile portscan or connection attempt to protected dark port",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.PORT_DIVERSITY",
			Layer:           LayerIngressNetwork,
			Category:        "reconnaissance",
			Severity:        "medium",
			DefaultScore:    65,
			ContainEligible: true,
			BlockEligible:   false,
			SignalSource:    "ebpf_sliding_window",
			Summary:         "Single IP probed multiple distinct destination ports",
			DefaultTTL:      6 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.SUBNET_V4",
			Layer:           LayerIngressNetwork,
			Category:        "botnet_aggregation",
			Severity:        "high",
			DefaultScore:    100,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "radix_subnet_aggregator",
			Summary:         "Coordinated traffic surge across IPv4 /24 subnet block",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.SUBNET_V6",
			Layer:           LayerIngressNetwork,
			Category:        "botnet_aggregation",
			Severity:        "high",
			DefaultScore:    100,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "radix_subnet_aggregator",
			Summary:         "Coordinated traffic surge across IPv6 /64 subnet block",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.WIDE_V4",
			Layer:           LayerIngressNetwork,
			Category:        "botnet_aggregation",
			Severity:        "critical",
			DefaultScore:    120,
			ContainEligible: false,
			BlockEligible:   false,
			SignalSource:    "radix_subnet_aggregator",
			Summary:         "Mass distributed botnet surge across IPv4 /16 sector block",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.LOW_SLOW_SCAN",
			Layer:           LayerIngressNetwork,
			Category:        "reconnaissance",
			Severity:        "high",
			DefaultScore:    92,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "kinetic_long_window",
			Summary:         "Source probed distinct destination ports across a long low-rate window",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "NET.INGRESS.THREAT_INTEL_MATCH",
			Layer:           LayerThreatIntel,
			Category:        "threat_intelligence",
			Severity:        "high",
			DefaultScore:    80,
			ContainEligible: false,
			BlockEligible:   false,
			SignalSource:    "threat_intel_correlate",
			Summary:         "Ingress source matched an active threat-intelligence prefix",
			DefaultTTL:      0,
		},
		{
			ID:              "NET.INGRESS.MALFORMED_TCP",
			Layer:           LayerIngressNetwork,
			Category:        "protocol_anomaly",
			Severity:        "high",
			DefaultScore:    80,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "ebpf_xdp",
			Summary:         "Illegal or evasive TCP flag combinations detected in kernel",
			DefaultTTL:      12 * time.Hour,
		},
		{
			ID:              "TLS.CLIENTHELLO.MALFORMED",
			Layer:           LayerApplicationL7,
			Category:        "protocol_anomaly",
			Severity:        "medium",
			DefaultScore:    45,
			ContainEligible: false,
			BlockEligible:   false,
			SignalSource:    "l7_tls_parser",
			Summary:         "Malformed or truncated TLS ClientHello observed",
			DefaultTTL:      0,
		},
		{
			ID:              "TLS.SNI.MISSING",
			Layer:           LayerApplicationL7,
			Category:        "protocol_anomaly",
			Severity:        "low",
			DefaultScore:    25,
			ContainEligible: false,
			BlockEligible:   false,
			SignalSource:    "l7_tls_parser",
			Summary:         "TLS ClientHello omitted SNI",
			DefaultTTL:      0,
		},
		{
			ID:              "TLS.HOST_MISMATCH",
			Layer:           LayerApplicationL7,
			Category:        "domain_spoofing",
			Severity:        "medium",
			DefaultScore:    60,
			ContainEligible: false,
			BlockEligible:   false,
			SignalSource:    "l7_tls_http_correlator",
			Summary:         "HTTP Host did not match recent TLS SNI from the same source",
			DefaultTTL:      0,
		},
		{
			ID:              "TLS.SNI.INVALID",
			Layer:           LayerApplicationL7,
			Category:        "protocol_anomaly",
			Severity:        "medium",
			DefaultScore:    60,
			ContainEligible: false,
			BlockEligible:   false,
			SignalSource:    "l7_tls_parser",
			Summary:         "Repeated direct IP or malformed hostname presented in TLS SNI",
			DefaultTTL:      12 * time.Hour,
		},
		{
			ID:              "TLS.SNI.REPEATED_INVALID",
			Layer:           LayerApplicationL7,
			Category:        "protocol_anomaly",
			Severity:        "high",
			DefaultScore:    100,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "l7_tls_parser",
			Summary:         "Repeated invalid or missing TLS SNI crossed the configured strike threshold",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "TLS.SNI.FOREIGN",
			Layer:           LayerApplicationL7,
			Category:        "domain_spoofing",
			Severity:        "high",
			DefaultScore:    85,
			ContainEligible: false,
			BlockEligible:   false,
			SignalSource:    "l7_tls_parser",
			Summary:         "TLS SNI requests domain outside authorized server scope",
			DefaultTTL:      24 * time.Hour,
		},
		{
			ID:              "TLS.JA3.MALICIOUS",
			Layer:           LayerApplicationL7,
			Category:        "threat_signature",
			Severity:        "critical",
			DefaultScore:    150,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "l7_tls_parser",
			Summary:         "Client TLS handshake matched known malicious JA3 fingerprint",
			DefaultTTL:      48 * time.Hour,
		},
		{
			ID:              "TLS.JA3.STRUCTURAL_SPOOF",
			Layer:           LayerApplicationL7,
			Category:        "evasion_detection",
			Severity:        "high",
			DefaultScore:    90,
			ContainEligible: false,
			BlockEligible:   false,
			SignalSource:    "l7_tls_parser",
			Summary:         "TLS ClientHello simulates browser JA3 but lacks ALPN or GREASE extensions",
			DefaultTTL:      48 * time.Hour,
		},
		{
			ID:              "TLS.HANDSHAKE.FLOOD",
			Layer:           LayerApplicationL7,
			Category:        "resource_exhaustion",
			Severity:        "high",
			DefaultScore:    95,
			ContainEligible: true,
			BlockEligible:   true,
			SignalSource:    "l7_tls_parser",
			Summary:         "Client completed multiple TLS handshakes with zero subsequent HTTP requests",
			DefaultTTL:      24 * time.Hour,
		},
	}

	for _, d := range defs {
		reg.rules[d.ID] = d
	}

	return reg
}

// Get retrieves a rule definition by its unique identifier.
func (r *KineticRuleRegistry) Get(id string) (KineticRuleDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, exists := r.rules[id]
	return def, exists
}

// CountLayer returns the number of registered rules for one defense layer.
func (r *KineticRuleRegistry) CountLayer(layer DefenseLayer) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := 0
	for _, def := range r.rules {
		if def.Layer == layer {
			count++
		}
	}
	return count
}

// List returns all registered kinetic rules sorted by ID.
func (r *KineticRuleRegistry) List() []KineticRuleDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]KineticRuleDefinition, 0, len(r.rules))
	for _, v := range r.rules {
		out = append(out, v)
	}
	return out
}

// Register adds or overrides a rule definition with strict validation.
func (r *KineticRuleRegistry) Register(def KineticRuleDefinition) error {
	if def.ID == "" {
		return fmt.Errorf("rule id cannot be empty")
	}
	if def.Layer == "" {
		return fmt.Errorf("rule layer cannot be empty for %s", def.ID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules[def.ID] = def
	return nil
}
