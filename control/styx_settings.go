// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5: StyX settings namespace, policy syncer and the
// kernel/beacon status projection (docs/POINT3-EGRESS-BEACON.md 8.3, 9, 12).
//
// The Go control plane stays unprivileged: it never touches the eBPF maps.
// It deliberately contains no enforcement decision and no active response: the
// beacon detector (styx_beacon.go, P3-T2) emits incidents through XDR's existing
// `appendIncident`/`respond()` path, and the kernel owns blocking.

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ---------------------------------------------------------------- constants

const (
	// StyxModeOff/Monitor/Enforce are the administrable modes (§3.1, §5 mode 0..2).
	StyxModeOff     = "off"
	StyxModeMonitor = "monitor"
	StyxModeEnforce = "enforce"

	// styxWireVersion is the only ABI version this control plane speaks (§5).
	styxWireVersion = "styx-v1"

	// Per-cell and allowlist ceilings from §8.3. They are enforced as caps and
	// never repaired silently; a list above the cap is rejected.
	styxMaxPerCellModes = 256
	styxMaxAllowRules   = 1024
	// STYX_RESOLVER_V4/V6 are sized 256 in the kernel (§4); refusing more in the
	// control plane is what keeps the sync from failing halfway through.
	styxMaxDNSResolvers = 256

	// Per-cell mode flag bits (§3.1). The mode itself travels as its own IPC
	// argument and is never repeated in the flags byte.
	styxModeFlagDNSResolver        = 1 << 3
	styxModeFlagAllowHostAllowlist = 1 << 5
	styxModeFlagLogFlows           = 1 << 6

	// STYX_GLOBAL carries exactly one documented IPC flag bit: bit 0 is LOG_FLOWS
	// (§5); the core translates it into the internal 1<<6 of §3.1.
	styxGlobalFlagLogFlows = 1 << 0

	// styxPolicySyncRetryInterval is both the retry backoff after a failure and the
	// epoch re-check interval after a success (a core restart must be noticed in
	// bounded time; §5 resync contract).
	styxPolicySyncRetryInterval = 10 * time.Second

	styxStatusErrorMaxBytes = 240
)

// Sync state vocabulary (§9 fail-closed matrix). It is reported verbatim.
const (
	StyxSyncStateApplied           = "applied"
	StyxSyncStatePending           = "pending"
	StyxSyncStateFailed            = "failed"
	StyxSyncStateCapabilityMissing = "capability-missing"
	StyxSyncStateUnavailable       = "unavailable"
)

const (
	styxCapabilityUnknown = "unknown"
	styxCapabilityMissing = "missing"
)

// ------------------------------------------------------------------ settings

// StyxCellMode is one per-cell default-deny/monitor entry. The flags mirror the
// §3.1 per-cgroup bits the operator can set.
type StyxCellMode struct {
	CgroupID           uint64 `json:"cgroup_id"`
	Mode               string `json:"mode"`
	DnsResolver        bool   `json:"dns_resolver"`
	AllowHostAllowlist bool   `json:"allow_host_allowlist"`
}

// StyxAllowRule is one per-cell allow entry. PortLo/PortHi: 0/0 and 0/65535 both
// mean "all ports"; an exact port requires a host CIDR and the core's documented
// LPM encoding (§4/§5). Proto is "any" (default), "tcp", "udp" or "tcp+udp".
type StyxAllowRule struct {
	CgroupID uint64 `json:"cgroup_id"`
	CIDR     string `json:"cidr"`
	PortLo   uint16 `json:"port_lo"`
	PortHi   uint16 `json:"port_hi"`
	Proto    string `json:"proto"`
}

// StyxFabricSettings is the operator-facing StyX namespace. The default is
// Enabled=false, Mode=off: an upgrade must never change kernel behaviour (§12).
type StyxFabricSettings struct {
	Enabled      bool            `json:"enabled"`
	Mode         string          `json:"mode"`
	LogFlows     bool            `json:"log_flows"`
	DnsResolvers []string        `json:"dns_resolvers"`
	PerCell      []StyxCellMode  `json:"per_cell"`
	Allowlist    []StyxAllowRule `json:"allowlist"`
}

func defaultStyxFabricSettings() StyxFabricSettings {
	// LogFlows defaults to true so that the documented activation path
	// (enabled=true, mode=monitor) actually produces the flow telemetry the beacon
	// detector consumes. It has no effect while the namespace stays enabled=false
	// or mode=off, which is the upgrade default.
	return StyxFabricSettings{
		Enabled:      false,
		Mode:         StyxModeOff,
		LogFlows:     true,
		DnsResolvers: []string{},
		PerCell:      []StyxCellMode{},
		Allowlist:    []StyxAllowRule{},
	}
}

func cloneStyxFabricSettings(in StyxFabricSettings) StyxFabricSettings {
	out := in
	out.DnsResolvers = append(make([]string, 0, len(in.DnsResolvers)), in.DnsResolvers...)
	out.PerCell = append(make([]StyxCellMode, 0, len(in.PerCell)), in.PerCell...)
	out.Allowlist = append(make([]StyxAllowRule, 0, len(in.Allowlist)), in.Allowlist...)
	return out
}

// styxDefaults returns the bootstrap seed for a document that predates the
// namespace, following the other additive namespaces.
func styxDefaults(defaults RuntimeSettings) StyxFabricSettings {
	if defaults.Styx != nil {
		return cloneStyxFabricSettings(*defaults.Styx)
	}
	return defaultStyxFabricSettings()
}

// effectiveStyxFabricSettings resolves a document into the administrable values,
// including the one derived fact §9 pins: Enabled=false means mode off.
func effectiveStyxFabricSettings(settings RuntimeSettings) StyxFabricSettings {
	out := defaultStyxFabricSettings()
	if settings.Styx != nil {
		out = cloneStyxFabricSettings(*settings.Styx)
	}
	if !out.Enabled || strings.TrimSpace(out.Mode) == "" {
		out.Mode = StyxModeOff
	}
	return out
}

func styxEffectiveLogFlows(in StyxFabricSettings) bool {
	return in.Enabled && in.LogFlows && in.Mode != StyxModeOff
}

func styxModeValue(mode string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case StyxModeOff, "":
		return 0, nil
	case StyxModeMonitor:
		return 1, nil
	case StyxModeEnforce:
		return 2, nil
	default:
		return 0, fmt.Errorf("styX mode %q must be off, monitor or enforce", mode)
	}
}

func styxModeName(mode uint8) string {
	switch mode {
	case 1:
		return StyxModeMonitor
	case 2:
		return StyxModeEnforce
	default:
		return StyxModeOff
	}
}

// normalizeStyxProto maps the settings-level protocol label onto the core's
// proto mask (0=all, 1=TCP, 2=UDP, 3=TCP+UDP, §5).
func normalizeStyxProto(proto string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "", "any", "all":
		return 0, nil
	case "tcp":
		return 1, nil
	case "udp":
		return 2, nil
	case "tcp+udp", "tcp,udp", "tcp+udp+", "udp+tcp":
		return 3, nil
	default:
		return 0, fmt.Errorf("styX allow rule protocol %q must be any, tcp, udp or tcp+udp", proto)
	}
}

// normalizeStyxTarget parses a canonical, family-correct CIDR through the same
// validator the IPC client uses (coreipc.go), so a value the settings accept can
// never be rejected half-way through the kernel sync.
func normalizeStyxTarget(raw string) (family uint8, canonical string, prefix netip.Prefix, err error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, "", netip.Prefix{}, errors.New("styX CIDR is empty")
	}
	if strings.ContainsAny(text, " \t\r\n\x00") {
		return 0, "", netip.Prefix{}, fmt.Errorf("styX CIDR %q contains rejected characters", raw)
	}
	var addr netip.Addr
	if strings.Contains(text, "/") {
		parsed, parseErr := netip.ParsePrefix(text)
		if parseErr != nil {
			return 0, "", netip.Prefix{}, fmt.Errorf("styX CIDR %q is not a valid prefix", raw)
		}
		addr = parsed.Addr()
	} else {
		parsed, parseErr := netip.ParseAddr(text)
		if parseErr != nil {
			return 0, "", netip.Prefix{}, fmt.Errorf("styX CIDR %q is not a valid address", raw)
		}
		addr = parsed
	}
	family = 6
	if addr.Is4() {
		family = 4
	}
	canonical, err = styxCanonicalCIDR(family, text)
	if err != nil {
		return 0, "", netip.Prefix{}, fmt.Errorf("styX CIDR %q: %w", raw, err)
	}
	prefix, err = netip.ParsePrefix(canonical)
	if err != nil {
		return 0, "", netip.Prefix{}, fmt.Errorf("styX CIDR %q could not be canonicalised: %w", raw, err)
	}
	return family, canonical, prefix, nil
}

func styxFullPrefixBits(family uint8) int {
	if family == 4 {
		return 32
	}
	return 128
}
