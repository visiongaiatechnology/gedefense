// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Boot Trust and Policy Trust administration.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, sections 22 and 23.
//
// Scope decision: policy *evidence* requirements are administrable — which
// measurements must be present, which boot arguments count, how long evidence may
// be reused, and how strictly the policy document must be signed. The trust
// anchors themselves (the signing key pair, the storage root key, the attestation
// document schema) are bootstrap material: exposing a control that lets an
// operator replace a key from the dashboard would turn the control plane into the
// attack surface.

// ------------------------------------------------------------ boot trust

type BootTrustFabricSettings struct {
	TTLSeconds              int      `json:"ttl_seconds"`
	RequiredPCRSelection    []int    `json:"required_pcr_selection"`
	RequiredKernelArguments []string `json:"required_kernel_arguments"`
	RequireSecureBoot       bool     `json:"require_secure_boot"`
	RequireKernelLockdown   bool     `json:"require_kernel_lockdown"`
	RequireAttestation      bool     `json:"require_attestation"`
	MaxKernelImageBytes     int64    `json:"max_kernel_image_bytes"`
	MaxEvidenceTextBytes    int64    `json:"max_evidence_text_bytes"`
}

// bootTrustPolicy is the compiled view read by the probe.
type bootTrustPolicy struct {
	requiredPCRs        []int
	requiredArguments   []string
	requireSecureBoot   bool
	requireLockdown     bool
	requireAttestation  bool
	maxKernelImageBytes int64
	maxEvidenceText     int64
}

// effective substitutes the compiled-in defaults for any unset bound, so a
// zero-valued policy can never widen a read or disable a check.
func (p bootTrustPolicy) effective() bootTrustPolicy {
	defaults := defaultBootTrustFabricSettings().policy()
	if len(p.requiredPCRs) == 0 {
		p.requiredPCRs = defaults.requiredPCRs
	}
	if len(p.requiredArguments) == 0 {
		p.requiredArguments = defaults.requiredArguments
	}
	if p.maxKernelImageBytes <= 0 {
		p.maxKernelImageBytes = defaults.maxKernelImageBytes
	}
	if p.maxEvidenceText <= 0 {
		p.maxEvidenceText = defaults.maxEvidenceText
	}
	return p
}

const (
	bootTrustPCRFloor          = 0
	bootTrustPCRCeiling        = 23
	bootTrustEvidenceFloor     = 4 << 10
	bootTrustEvidenceCeiling   = 4 << 20
	bootTrustKernelFloor       = 1 << 20
	bootTrustKernelCeiling     = 4 << 30
	bootTrustArgumentLimit     = 32
	bootTrustTTLFloorSeconds   = 5
	bootTrustTTLCeilingSeconds = 86400
)

// defaultBootTrustFabricSettings mirrors the compiled-in boot evidence policy.
func defaultBootTrustFabricSettings() BootTrustFabricSettings {
	return BootTrustFabricSettings{
		TTLSeconds:              300,
		RequiredPCRSelection:    []int{0, 2, 4, 7, 9, 11, 12},
		RequiredKernelArguments: []string{"init_on_alloc=1", "init_on_free=1", "randomize_kstack_offset=on", "module.sig_enforce=1"},
		RequireSecureBoot:       false,
		RequireKernelLockdown:   false,
		RequireAttestation:      false,
		MaxKernelImageBytes:     256 << 20,
		MaxEvidenceTextBytes:    64 << 10,
	}
}

func cloneBootTrustFabricSettings(in BootTrustFabricSettings) BootTrustFabricSettings {
	out := in
	out.RequiredPCRSelection = append([]int(nil), in.RequiredPCRSelection...)
	out.RequiredKernelArguments = append([]string(nil), in.RequiredKernelArguments...)
	return out
}

func validateBootTrustFabricSettings(settings *BootTrustFabricSettings) error {
	if settings.TTLSeconds < bootTrustTTLFloorSeconds || settings.TTLSeconds > bootTrustTTLCeilingSeconds {
		return fmt.Errorf("boot evidence cache lifetime must be between %d and %d seconds", bootTrustTTLFloorSeconds, bootTrustTTLCeilingSeconds)
	}
	if len(settings.RequiredPCRSelection) == 0 || len(settings.RequiredPCRSelection) > 24 {
		return fmt.Errorf("required PCR selection must contain between 1 and 24 registers")
	}
	seenPCRs := make(map[int]struct{}, len(settings.RequiredPCRSelection))
	pcrSelection := make([]int, 0, len(settings.RequiredPCRSelection))
	for _, pcr := range settings.RequiredPCRSelection {
		if pcr < bootTrustPCRFloor || pcr > bootTrustPCRCeiling {
			return fmt.Errorf("PCR index %d is outside the 0-%d range", pcr, bootTrustPCRCeiling)
		}
		if _, exists := seenPCRs[pcr]; exists {
			continue
		}
		seenPCRs[pcr] = struct{}{}
		pcrSelection = append(pcrSelection, pcr)
	}
	// The attestation declares its selection in order, so the expected selection
	// is compared in order: it must be sorted to be reproducible.
	sort.Ints(pcrSelection)
	settings.RequiredPCRSelection = pcrSelection

	if len(settings.RequiredKernelArguments) > bootTrustArgumentLimit {
		return fmt.Errorf("required kernel argument list exceeds %d entries", bootTrustArgumentLimit)
	}
	seenArgs := make(map[string]struct{}, len(settings.RequiredKernelArguments))
	args := make([]string, 0, len(settings.RequiredKernelArguments))
	for _, raw := range settings.RequiredKernelArguments {
		argument := strings.TrimSpace(raw)
		if argument == "" {
			continue
		}
		if len(argument) > 128 || strings.ContainsAny(argument, " \t\r\n\x00") || !strings.Contains(argument, "=") {
			return fmt.Errorf("required kernel argument %q must be a single key=value token", raw)
		}
		if _, exists := seenArgs[argument]; exists {
			continue
		}
		seenArgs[argument] = struct{}{}
		args = append(args, argument)
	}
	sort.Strings(args)
	settings.RequiredKernelArguments = args

	if settings.MaxEvidenceTextBytes < bootTrustEvidenceFloor || settings.MaxEvidenceTextBytes > bootTrustEvidenceCeiling {
		return fmt.Errorf("boot evidence read bound must be between 4 KiB and 4 MiB")
	}
	if settings.MaxKernelImageBytes < bootTrustKernelFloor || settings.MaxKernelImageBytes > bootTrustKernelCeiling {
		return fmt.Errorf("kernel image bound must be between 1 MiB and 4 GiB")
	}
	return nil
}

func (s BootTrustFabricSettings) policy() bootTrustPolicy {
	return bootTrustPolicy{
		requiredPCRs:        append([]int(nil), s.RequiredPCRSelection...),
		requiredArguments:   append([]string(nil), s.RequiredKernelArguments...),
		requireSecureBoot:   s.RequireSecureBoot,
		requireLockdown:     s.RequireKernelLockdown,
		requireAttestation:  s.RequireAttestation,
		maxKernelImageBytes: s.MaxKernelImageBytes,
		maxEvidenceText:     s.MaxEvidenceTextBytes,
	}
}

// effectiveBootTrustSettings returns the persisted Boot Trust namespace.
func effectiveBootTrustSettings(settings RuntimeSettings) BootTrustFabricSettings {
	if settings.BootTrust != nil {
		return cloneBootTrustFabricSettings(*settings.BootTrust)
	}
	return defaultBootTrustFabricSettings()
}

// ApplyPolicy republishes the administrable boot evidence requirements. The
// collector's TTL is live, so the next collection observes the new lifetime.
func (c *BootTrustCollector) ApplyPolicy(settings BootTrustFabricSettings) error {
	if c == nil {
		return nil
	}
	if settings.TTLSeconds < bootTrustTTLFloorSeconds {
		return errors.New("boot evidence cache lifetime is below the safe floor")
	}
	c.mu.Lock()
	c.ttl = time.Duration(settings.TTLSeconds) * time.Second
	c.settings = cloneBootTrustFabricSettings(settings)
	// Force the next collection to re-probe rather than serving evidence that was
	// gathered under a different requirement set.
	c.expires = time.Time{}
	c.mu.Unlock()
	return nil
}

// Policy returns the active boot evidence requirements.
func (c *BootTrustCollector) Policy() BootTrustFabricSettings {
	if c == nil {
		return BootTrustFabricSettings{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneBootTrustFabricSettings(c.settings)
}

// ------------------------------------------------------------ policy trust

type PolicyTrustFabricSettings struct {
	RequireSigned         bool   `json:"require_signed"`
	MinimumGeneration     uint64 `json:"minimum_generation"`
	VerifyIntervalSeconds int    `json:"verify_interval_seconds"`
	MaxStateBytes         int64  `json:"max_state_bytes"`
}

const (
	policyTrustStateFloorBytes = 64 << 10
	policyTrustStateCeilBytes  = 512 << 20
	policyTrustVerifyFloor     = 30
	policyTrustVerifyCeiling   = 86400
)

func defaultPolicyTrustFabricSettings() PolicyTrustFabricSettings {
	return PolicyTrustFabricSettings{
		RequireSigned:         true,
		MinimumGeneration:     0,
		VerifyIntervalSeconds: 900,
		MaxStateBytes:         64 << 20,
	}
}

func validatePolicyTrustFabricSettings(settings *PolicyTrustFabricSettings) error {
	if settings.VerifyIntervalSeconds < policyTrustVerifyFloor || settings.VerifyIntervalSeconds > policyTrustVerifyCeiling {
		return fmt.Errorf("policy verification interval must be between %d and %d seconds", policyTrustVerifyFloor, policyTrustVerifyCeiling)
	}
	if settings.MaxStateBytes < policyTrustStateFloorBytes || settings.MaxStateBytes > policyTrustStateCeilBytes {
		return fmt.Errorf("policy state read bound must be between 64 KiB and 512 MiB")
	}
	return nil
}

// effectivePolicyTrustSettings returns the persisted Policy Trust namespace.
func effectivePolicyTrustSettings(settings RuntimeSettings) PolicyTrustFabricSettings {
	if settings.PolicyTrust != nil {
		return *settings.PolicyTrust
	}
	return defaultPolicyTrustFabricSettings()
}

// ApplyPolicy republishes the administrable policy trust requirements. A raised
// generation floor takes effect on the next load, so it can be used to pin a
// known-good policy revision against a replayed older document.
func (p *PolicyStore) ApplyPolicy(settings PolicyTrustFabricSettings) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trust = settings
	return nil
}

// Policy returns the active policy trust requirements.
func (p *PolicyStore) Policy() PolicyTrustFabricSettings {
	if p == nil {
		return PolicyTrustFabricSettings{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.trust
}

// requireSigned reports whether an unsigned or wrongly signed document must be
// refused. The compiled-in bootstrap value seeds the first revision and the
// Fabric namespace is authoritative afterwards.
func (p *PolicyStore) requireSigned() bool {
	return p.trust.RequireSigned
}

func (p *PolicyStore) maxStateBytes() int64 {
	if p.trust.MaxStateBytes > 0 {
		return p.trust.MaxStateBytes
	}
	return 64 << 20
}

// formatPCRSelection renders a PCR index list in the canonical ascending form
// used by the attestation contract.
func formatPCRSelection(pcrs []int) string {
	parts := make([]string, 0, len(pcrs))
	for _, pcr := range pcrs {
		parts = append(parts, strconv.Itoa(pcr))
	}
	return strings.Join(parts, ",")
}

// ------------------------------------------------------- distribution

// applyTrustPolicies projects the two trust namespaces onto their engines from
// one choke point.
func applyTrustPolicies(boot BootTrustFabricSettings, policyTrust PolicyTrustFabricSettings, collector *BootTrustCollector, store *PolicyStore) error {
	if collector != nil {
		if err := collector.ApplyPolicy(boot); err != nil {
			return fmt.Errorf("apply boot trust policy: %w", err)
		}
	}
	if store != nil {
		if err := store.ApplyPolicy(policyTrust); err != nil {
			return fmt.Errorf("apply policy trust settings: %w", err)
		}
	}
	return nil
}
