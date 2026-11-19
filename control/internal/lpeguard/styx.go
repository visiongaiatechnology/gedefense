package lpeguard

import (
	"net/netip"
	"strings"
)

// StyxProfileName is the published profile identifier.
const StyxProfileName = "web-ingress-only"

// StyxProfilePlan is the rendered StyX egress profile for web workers. The
// kernel-side default-deny profile allows loopback, the configured backend
// CIDRs and the configured DNS resolvers; everything else is denied.
type StyxProfilePlan struct {
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	Allow   []string `json:"allow"`
	DNS     []string `json:"dns"`
	Backend []string `json:"backend"`
}

// BuildStyxWebIngressPlan renders the plan. Canonical, deduplicated and
// deterministic: the same settings always produce the same published plan.
func BuildStyxWebIngressPlan(settings StyxProfileSettings) StyxProfilePlan {
	plan := StyxProfilePlan{
		Name: StyxProfileName, Enabled: settings.Enabled,
		Allow: []string{"127.0.0.0/8", "::1/128"}, DNS: []string{}, Backend: []string{},
	}
	for _, raw := range settings.BackendCIDRs {
		if canonical, ok := canonicalPrefix(raw); ok {
			plan.Backend = appendUnique(plan.Backend, canonical)
			plan.Allow = appendUnique(plan.Allow, canonical)
		}
	}
	for _, raw := range settings.DNSServers {
		if canonical, ok := canonicalPrefix(raw); ok {
			plan.DNS = appendUnique(plan.DNS, canonical)
		} else if host, ok := canonicalHost(raw); ok {
			// A DNS server may be configured as a bare address; publish it as a
			// host prefix so the kernel resolver allowlist can carry it.
			plan.DNS = appendUnique(plan.DNS, host)
		}
	}
	return plan
}

// StyxProfileSettings is the administrable subset of the profile.
type StyxProfileSettings struct {
	Enabled      bool
	BackendCIDRs []string
	DNSServers   []string
}

// canonicalPrefix normalizes one CIDR or bare address into a canonical prefix
// string. An invalid entry is dropped; the settings validator refuses invalid
// entries before they can reach this renderer.
func canonicalPrefix(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.Masked().String(), true
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()).String(), true
	}
	return "", false
}

// canonicalHost renders a bare address as a host prefix.
func canonicalHost(raw string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), true
}

// appendUnique adds a value if it is not already present, preserving order.
func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
