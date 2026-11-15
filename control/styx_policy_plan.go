// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5: the pure, validated StyX policy plan. Building it is side-effect
// free, so a local validation error can never leave a half-applied map behind.
// It is the planning half of the syncer (styx_syncer.go).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ------------------------------------------------------------- policy plan

// styxCellPlan is one validated per-cell mode entry sent through STYX_MODE_SET.
type styxCellPlan struct {
	CgroupID uint64
	Mode     uint8
	Flags    uint8
}

// styxAllowPlan is one validated allowlist entry sent through STYX_ALLOW_ADD.
// Scope is always "cell": the namespace only administrates workload rules; the
// host-wide allowlist stays owned by the core/threat-intel side.
type styxAllowPlan struct {
	CgroupID  uint64
	Family    uint8
	CIDR      string
	PortLo    uint16
	PortHi    uint16
	ProtoMask uint8
}

// styxResolverPlan is one validated DNS/DoT resolver prefix.
type styxResolverPlan struct {
	Family uint8
	CIDR   string
}

// styxPolicyPlan is the complete, validated desired kernel state. Building it is
// pure: local validation errors can never leave a half-applied map behind.
type styxPolicyPlan struct {
	Enabled     bool
	ModeName    string
	Mode        uint8
	LogFlows    bool
	GlobalFlags uint8
	Cells       []styxCellPlan
	Allow       []styxAllowPlan
	Resolvers   []styxResolverPlan
}

func buildStyxPolicyPlan(in StyxFabricSettings) (styxPolicyPlan, error) {
	plan := styxPolicyPlan{Enabled: in.Enabled, ModeName: styxModeOffName(in.Mode)}
	mode, err := styxModeValue(in.Mode)
	if err != nil {
		return styxPolicyPlan{}, err
	}
	if !in.Enabled {
		mode = 0
		plan.ModeName = StyxModeOff
	}
	plan.Mode = mode
	plan.LogFlows = in.Enabled && in.LogFlows && mode != 0
	if in.Enabled && mode == 0 {
		// §6.1 fail-safe shortcut: with the global mode off the kernel hook returns
		// before any policy lookup and disables flow logging. Accepting per-cell
		// modes, allowlist or resolver rules here would persist a policy the
		// operator believes is enforced while it is completely inert. Refuse it
		// visibly instead of storing a silent no-op.
		for _, cell := range in.PerCell {
			if cellMode, cellErr := styxModeValue(cell.Mode); cellErr == nil && cellMode != 0 {
				return styxPolicyPlan{}, errors.New("styX mode=off with per-cell/allowlist rules has no effect; set mode=monitor or enforce")
			}
		}
		if len(in.Allowlist) > 0 || len(in.DnsResolvers) > 0 {
			return styxPolicyPlan{}, errors.New("styX mode=off with per-cell/allowlist rules has no effect; set mode=monitor or enforce")
		}
	}
	if plan.LogFlows {
		plan.GlobalFlags = styxGlobalFlagLogFlows
	}

	// Resolvers: canonical, deduplicated, deterministic order.
	if len(in.DnsResolvers) > styxMaxDNSResolvers {
		return styxPolicyPlan{}, fmt.Errorf("styX DNS resolver list exceeds %d entries", styxMaxDNSResolvers)
	}
	resolverSeen := make(map[string]struct{}, len(in.DnsResolvers))
	for _, raw := range in.DnsResolvers {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		family, canonical, _, err := normalizeStyxTarget(raw)
		if err != nil {
			return styxPolicyPlan{}, err
		}
		key := fmt.Sprintf("%d|%s", family, canonical)
		if _, exists := resolverSeen[key]; exists {
			continue
		}
		resolverSeen[key] = struct{}{}
		plan.Resolvers = append(plan.Resolvers, styxResolverPlan{Family: family, CIDR: canonical})
	}
	sort.Slice(plan.Resolvers, func(i, j int) bool {
		if plan.Resolvers[i].Family != plan.Resolvers[j].Family {
			return plan.Resolvers[i].Family < plan.Resolvers[j].Family
		}
		return plan.Resolvers[i].CIDR < plan.Resolvers[j].CIDR
	})

	// Per-cell modes: one entry per cgroup, no ambiguity.
	if len(in.PerCell) > styxMaxPerCellModes {
		return styxPolicyPlan{}, fmt.Errorf("styX per-cell mode list exceeds %d entries", styxMaxPerCellModes)
	}
	cellSeen := make(map[uint64]struct{}, len(in.PerCell))
	for _, cell := range in.PerCell {
		if cell.CgroupID == 0 {
			return styxPolicyPlan{}, errors.New("styX per-cell entry requires a non-zero cgroup id")
		}
		if _, duplicate := cellSeen[cell.CgroupID]; duplicate {
			return styxPolicyPlan{}, fmt.Errorf("styX per-cell entry for cgroup %d is duplicated", cell.CgroupID)
		}
		cellSeen[cell.CgroupID] = struct{}{}
		cellMode, err := styxModeValue(cell.Mode)
		if err != nil {
			return styxPolicyPlan{}, err
		}
		flags := uint8(0)
		if cell.DnsResolver {
			flags |= styxModeFlagDNSResolver
		}
		if cell.AllowHostAllowlist {
			flags |= styxModeFlagAllowHostAllowlist
		}
		if plan.LogFlows {
			flags |= styxModeFlagLogFlows
		}
		plan.Cells = append(plan.Cells, styxCellPlan{CgroupID: cell.CgroupID, Mode: cellMode, Flags: flags})
	}
	sort.Slice(plan.Cells, func(i, j int) bool { return plan.Cells[i].CgroupID < plan.Cells[j].CgroupID })

	// Allowlist: canonical, deduplicated, deterministic order.
	if len(in.Allowlist) > styxMaxAllowRules {
		return styxPolicyPlan{}, fmt.Errorf("styX allowlist exceeds %d entries", styxMaxAllowRules)
	}
	allowSeen := make(map[string]struct{}, len(in.Allowlist))
	for _, rule := range in.Allowlist {
		allow, err := normalizeStyxAllowRule(rule)
		if err != nil {
			return styxPolicyPlan{}, err
		}
		key := fmt.Sprintf("%d|%d|%s|%d|%d|%d", allow.CgroupID, allow.Family, allow.CIDR, allow.PortLo, allow.PortHi, allow.ProtoMask)
		if _, exists := allowSeen[key]; exists {
			continue
		}
		allowSeen[key] = struct{}{}
		plan.Allow = append(plan.Allow, allow)
	}
	sort.Slice(plan.Allow, func(i, j int) bool {
		left, right := plan.Allow[i], plan.Allow[j]
		if left.CgroupID != right.CgroupID {
			return left.CgroupID < right.CgroupID
		}
		if left.Family != right.Family {
			return left.Family < right.Family
		}
		if left.CIDR != right.CIDR {
			return left.CIDR < right.CIDR
		}
		if left.PortLo != right.PortLo {
			return left.PortLo < right.PortLo
		}
		if left.PortHi != right.PortHi {
			return left.PortHi < right.PortHi
		}
		return left.ProtoMask < right.ProtoMask
	})
	return plan, nil
}

func styxModeOffName(mode string) string {
	value, err := styxModeValue(mode)
	if err != nil {
		return StyxModeOff
	}
	return styxModeName(value)
}

// normalizeStyxAllowRule validates one allow entry against the core's hard rules
// (§4/§5): canonical CIDR, wildcard ports encoded as 0/65535, an exact port only
// on a host prefix, and protocol restrictions only together with an exact port.
func normalizeStyxAllowRule(rule StyxAllowRule) (styxAllowPlan, error) {
	if rule.CgroupID == 0 {
		return styxAllowPlan{}, errors.New("styX allowlist entry requires a non-zero cgroup id")
	}
	family, canonical, prefix, err := normalizeStyxTarget(rule.CIDR)
	if err != nil {
		return styxAllowPlan{}, err
	}
	protoMask, err := normalizeStyxProto(rule.Proto)
	if err != nil {
		return styxAllowPlan{}, err
	}
	if family == 6 {
		// §4 Phase-1 limit: the cell-v6 LPM key has no port/proto slot. A
		// restriction would be silently widened to every port by the kernel, so it
		// is refused instead of installed as a different rule.
		if rule.PortLo != 0 || rule.PortHi != 0 || protoMask != 0 {
			return styxAllowPlan{}, fmt.Errorf("styX allow rule %s: IPv6 cell rules cannot carry port/protocol restrictions in phase 1", canonical)
		}
		return styxAllowPlan{CgroupID: rule.CgroupID, Family: family, CIDR: canonical, PortLo: 0, PortHi: 65535}, nil
	}
	portLo, portHi := rule.PortLo, rule.PortHi
	switch {
	case portLo == 0 && (portHi == 0 || portHi == 65535):
		// Wildcard: documented as 0/65535 on the IPC wire. (0,0) is an exact port 0
		// for the core and would only be legal on /32, which the settings never want.
		portLo, portHi = 0, 65535
	case portLo > 0 && portLo == portHi:
		if prefix.Bits() != styxFullPrefixBits(family) {
			return styxAllowPlan{}, fmt.Errorf("styX allow rule %s: a port rule requires a host CIDR (/32 or /128)", canonical)
		}
	default:
		return styxAllowPlan{}, fmt.Errorf("styX allow rule %s: port range must be a single port or 0-65535", canonical)
	}
	if protoMask != 0 && !(portLo == portHi) {
		return styxAllowPlan{}, fmt.Errorf("styX allow rule %s: a protocol rule requires an exact port", canonical)
	}
	return styxAllowPlan{
		CgroupID: rule.CgroupID, Family: family, CIDR: canonical,
		PortLo: portLo, PortHi: portHi, ProtoMask: protoMask,
	}, nil
}

// validateStyxFabricSettings validates and canonicalises one namespace. Existing
// migrations never rewrite operator values; this is the same reject-not-repair
// contract the dashboard and the import path use.
func validateStyxFabricSettings(in *StyxFabricSettings) error {
	if in == nil {
		return errors.New("styX settings are missing")
	}
	plan, err := buildStyxPolicyPlan(*in)
	if err != nil {
		return err
	}
	normalized := StyxFabricSettings{
		Enabled:      plan.Enabled,
		Mode:         plan.ModeName,
		LogFlows:     in.LogFlows,
		DnsResolvers: make([]string, 0, len(plan.Resolvers)),
		PerCell:      make([]StyxCellMode, 0, len(plan.Cells)),
		Allowlist:    make([]StyxAllowRule, 0, len(plan.Allow)),
	}
	for _, resolver := range plan.Resolvers {
		normalized.DnsResolvers = append(normalized.DnsResolvers, resolver.CIDR)
	}
	for _, cell := range plan.Cells {
		normalized.PerCell = append(normalized.PerCell, StyxCellMode{
			CgroupID:           cell.CgroupID,
			Mode:               styxModeName(cell.Mode),
			DnsResolver:        cell.Flags&styxModeFlagDNSResolver != 0,
			AllowHostAllowlist: cell.Flags&styxModeFlagAllowHostAllowlist != 0,
		})
	}
	for _, allow := range plan.Allow {
		proto := ""
		switch allow.ProtoMask {
		case 1:
			proto = "tcp"
		case 2:
			proto = "udp"
		case 3:
			proto = "tcp+udp"
		}
		normalized.Allowlist = append(normalized.Allowlist, StyxAllowRule{
			CgroupID: allow.CgroupID, CIDR: allow.CIDR,
			PortLo: allow.PortLo, PortHi: allow.PortHi, Proto: proto,
		})
	}
	*in = normalized
	return nil
}

// fingerprint is the stable identity of one plan. The syncer pushes only when it
// changes, which is what keeps a 10 s epoch poll from re-writing the whole map.
func (plan styxPolicyPlan) fingerprint() string {
	digest := sha256.New()
	fmt.Fprintf(digest, "styx-policy-v1|%t|%d|%d|%t\n", plan.Enabled, plan.Mode, plan.GlobalFlags, plan.LogFlows)
	for _, cell := range plan.Cells {
		fmt.Fprintf(digest, "cell|%d|%d|%d\n", cell.CgroupID, cell.Mode, cell.Flags)
	}
	for _, allow := range plan.Allow {
		fmt.Fprintf(digest, "allow|%d|%d|%s|%d|%d|%d\n", allow.CgroupID, allow.Family, allow.CIDR, allow.PortLo, allow.PortHi, allow.ProtoMask)
	}
	for _, resolver := range plan.Resolvers {
		fmt.Fprintf(digest, "resolver|%d|%s\n", resolver.Family, resolver.CIDR)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
