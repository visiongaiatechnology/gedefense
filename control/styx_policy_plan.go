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
// CgroupPath is carried for validation/normalisation only; the kernel command
// still uses the freshly resolved numeric CgroupID (M3.1). An entry with
// CgroupID == 0 is unresolved and never reaches the kernel.
type styxCellPlan struct {
	CgroupID   uint64
	CgroupPath string
	Mode       uint8
	Flags      uint8
}

// equalKernel compares everything that is sent to the kernel. The path is bookkeeping
// only: adding a durable path to an unchanged cell must not re-write the map.
func (cell styxCellPlan) equalKernel(other styxCellPlan) bool {
	return cell.CgroupID == other.CgroupID && cell.Mode == other.Mode && cell.Flags == other.Flags
}

// styxAllowPlan is one validated allowlist entry sent through STYX_ALLOW_ADD.
// Scope is always "cell": the namespace only administrates workload rules; the
// host-wide allowlist stays owned by the core/threat-intel side.
type styxAllowPlan struct {
	CgroupID   uint64
	CgroupPath string
	Family     uint8
	CIDR       string
	PortLo     uint16
	PortHi     uint16
	ProtoMask  uint8
}

// equalKernel compares the kernel map key/value and ignores the bookkeeping path.
func (allow styxAllowPlan) equalKernel(other styxAllowPlan) bool {
	return allow.CgroupID == other.CgroupID && allow.Family == other.Family &&
		allow.CIDR == other.CIDR && allow.PortLo == other.PortLo &&
		allow.PortHi == other.PortHi && allow.ProtoMask == other.ProtoMask
}

// styxResolverPlan is one validated DNS/DoT resolver prefix.
type styxResolverPlan struct {
	Family uint8
	CIDR   string
}

// styxPolicyPlan is the complete, validated desired kernel state. Building it is
// pure: local validation errors can never leave a half-applied map behind.
//
// UnresolvedCells/UnresolvedAllow carry valid path-backed entries whose cgroup id
// could not be resolved. They are reported (degraded) but never written to the
// kernel, so a stale numeric id can never be applied to the wrong cgroup.
type styxPolicyPlan struct {
	Enabled         bool
	ModeName        string
	Mode            uint8
	LogFlows        bool
	GlobalFlags     uint8
	Cells           []styxCellPlan
	Allow           []styxAllowPlan
	Resolvers       []styxResolverPlan
	UnresolvedCells []styxCellPlan
	UnresolvedAllow []styxAllowPlan
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

	// Per-cell modes: one entry per durable identity, no ambiguity.
	if len(in.PerCell) > styxMaxPerCellModes {
		return styxPolicyPlan{}, fmt.Errorf("styX per-cell mode list exceeds %d entries", styxMaxPerCellModes)
	}
	cellSeen := make(map[string]struct{}, len(in.PerCell))
	cellPlans := make([]styxCellPlan, 0, len(in.PerCell))
	for _, cell := range in.PerCell {
		canonicalPath := ""
		if strings.TrimSpace(cell.CgroupPath) != "" {
			normalizedPath, pathErr := normalizeStyxCgroupPath(cell.CgroupPath)
			if pathErr != nil {
				return styxPolicyPlan{}, pathErr
			}
			canonicalPath = normalizedPath
		}
		if cell.CgroupID == 0 && canonicalPath == "" {
			return styxPolicyPlan{}, errors.New("styX per-cell entry requires a non-zero cgroup id or a cgroup_path")
		}
		key := fmt.Sprintf("id:%d", cell.CgroupID)
		if canonicalPath != "" {
			key = "path:" + canonicalPath
		}
		if _, duplicate := cellSeen[key]; duplicate {
			return styxPolicyPlan{}, fmt.Errorf("styX per-cell entry %q is duplicated", key)
		}
		cellSeen[key] = struct{}{}
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
		cellPlans = append(cellPlans, styxCellPlan{CgroupID: cell.CgroupID, CgroupPath: canonicalPath, Mode: cellMode, Flags: flags})
	}
	// Two distinct durable entries may not resolve to the same kernel cgroup: the
	// core map is keyed by cgroup id, so one would silently overwrite the other.
	resolvedCellIDs := make(map[uint64]string, len(cellPlans))
	for _, cell := range cellPlans {
		if cell.CgroupID == 0 {
			continue
		}
		if other, exists := resolvedCellIDs[cell.CgroupID]; exists {
			return styxPolicyPlan{}, fmt.Errorf("styX entries %q and %q resolve to the same cgroup id %d", other, cell.CgroupPath, cell.CgroupID)
		}
		resolvedCellIDs[cell.CgroupID] = cell.CgroupPath
	}
	for _, cell := range cellPlans {
		if cell.CgroupID == 0 {
			plan.UnresolvedCells = append(plan.UnresolvedCells, cell)
			continue
		}
		plan.Cells = append(plan.Cells, cell)
	}
	sort.Slice(plan.Cells, func(i, j int) bool {
		if plan.Cells[i].CgroupID != plan.Cells[j].CgroupID {
			return plan.Cells[i].CgroupID < plan.Cells[j].CgroupID
		}
		return plan.Cells[i].CgroupPath < plan.Cells[j].CgroupPath
	})
	sort.Slice(plan.UnresolvedCells, func(i, j int) bool {
		return plan.UnresolvedCells[i].CgroupPath < plan.UnresolvedCells[j].CgroupPath
	})

	// Allowlist: canonical, deduplicated, deterministic order.
	if len(in.Allowlist) > styxMaxAllowRules {
		return styxPolicyPlan{}, fmt.Errorf("styX allowlist exceeds %d entries", styxMaxAllowRules)
	}
	allowSeen := make(map[string]struct{}, len(in.Allowlist))
	allowPlans := make([]styxAllowPlan, 0, len(in.Allowlist))
	for _, rule := range in.Allowlist {
		allow, err := normalizeStyxAllowRule(rule)
		if err != nil {
			return styxPolicyPlan{}, err
		}
		identity := fmt.Sprintf("id:%d", allow.CgroupID)
		if allow.CgroupPath != "" {
			identity = "path:" + allow.CgroupPath
		}
		key := fmt.Sprintf("%s|%d|%s|%d|%d|%d", identity, allow.Family, allow.CIDR, allow.PortLo, allow.PortHi, allow.ProtoMask)
		if _, exists := allowSeen[key]; exists {
			continue
		}
		allowSeen[key] = struct{}{}
		allowPlans = append(allowPlans, allow)
	}
	for _, allow := range allowPlans {
		if allow.CgroupID == 0 {
			plan.UnresolvedAllow = append(plan.UnresolvedAllow, allow)
			continue
		}
		plan.Allow = append(plan.Allow, allow)
	}
	sort.Slice(plan.Allow, func(i, j int) bool {
		left, right := plan.Allow[i], plan.Allow[j]
		if left.CgroupID != right.CgroupID {
			return left.CgroupID < right.CgroupID
		}
		return left.CgroupPath < right.CgroupPath || (left.CgroupPath == right.CgroupPath && styxAllowPlanLess(left, right))
	})
	sort.Slice(plan.UnresolvedAllow, func(i, j int) bool {
		left, right := plan.UnresolvedAllow[i], plan.UnresolvedAllow[j]
		if left.CgroupPath != right.CgroupPath {
			return left.CgroupPath < right.CgroupPath
		}
		return styxAllowPlanLess(left, right)
	})
	return plan, nil
}

// styxAllowPlanLess is the stable kernel-state ordering of two allow rules once
// their cgroup identity is fixed.
func styxAllowPlanLess(left, right styxAllowPlan) bool {
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
// The cgroup identity is either the durable cgroup_path or a legacy numeric id.
func normalizeStyxAllowRule(rule StyxAllowRule) (styxAllowPlan, error) {
	canonicalPath := ""
	if strings.TrimSpace(rule.CgroupPath) != "" {
		normalizedPath, pathErr := normalizeStyxCgroupPath(rule.CgroupPath)
		if pathErr != nil {
			return styxAllowPlan{}, pathErr
		}
		canonicalPath = normalizedPath
	}
	if rule.CgroupID == 0 && canonicalPath == "" {
		return styxAllowPlan{}, errors.New("styX allowlist entry requires a non-zero cgroup id or a cgroup_path")
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
		return styxAllowPlan{CgroupID: rule.CgroupID, CgroupPath: canonicalPath, Family: family, CIDR: canonical, PortLo: 0, PortHi: 65535}, nil
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
		CgroupID: rule.CgroupID, CgroupPath: canonicalPath, Family: family, CIDR: canonical,
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
		PerCell:      make([]StyxCellMode, 0, len(plan.Cells)+len(plan.UnresolvedCells)),
		Allowlist:    make([]StyxAllowRule, 0, len(plan.Allow)+len(plan.UnresolvedAllow)),
	}
	for _, resolver := range plan.Resolvers {
		normalized.DnsResolvers = append(normalized.DnsResolvers, resolver.CIDR)
	}
	cells := make([]styxCellPlan, 0, len(plan.Cells)+len(plan.UnresolvedCells))
	cells = append(cells, plan.Cells...)
	cells = append(cells, plan.UnresolvedCells...)
	sort.SliceStable(cells, func(i, j int) bool {
		if cells[i].CgroupID != cells[j].CgroupID {
			return cells[i].CgroupID < cells[j].CgroupID
		}
		return cells[i].CgroupPath < cells[j].CgroupPath
	})
	for _, cell := range cells {
		// M3.1: with a durable path the numeric id is re-resolved on every sync, so
		// the persisted form stays path-only. Keeping a stale id in the store would
		// give a future consumer a value that no longer names this cgroup.
		storedID := cell.CgroupID
		if cell.CgroupPath != "" {
			storedID = 0
		}
		normalized.PerCell = append(normalized.PerCell, StyxCellMode{
			CgroupID:           storedID,
			CgroupPath:         cell.CgroupPath,
			Mode:               styxModeName(cell.Mode),
			DnsResolver:        cell.Flags&styxModeFlagDNSResolver != 0,
			AllowHostAllowlist: cell.Flags&styxModeFlagAllowHostAllowlist != 0,
		})
	}
	allows := make([]styxAllowPlan, 0, len(plan.Allow)+len(plan.UnresolvedAllow))
	allows = append(allows, plan.Allow...)
	allows = append(allows, plan.UnresolvedAllow...)
	sort.SliceStable(allows, func(i, j int) bool {
		if allows[i].CgroupID != allows[j].CgroupID {
			return allows[i].CgroupID < allows[j].CgroupID
		}
		if allows[i].CgroupPath != allows[j].CgroupPath {
			return allows[i].CgroupPath < allows[j].CgroupPath
		}
		return styxAllowPlanLess(allows[i], allows[j])
	})
	for _, allow := range allows {
		proto := ""
		switch allow.ProtoMask {
		case 1:
			proto = "tcp"
		case 2:
			proto = "udp"
		case 3:
			proto = "tcp+udp"
		}
		storedID := allow.CgroupID
		if allow.CgroupPath != "" {
			storedID = 0
		}
		normalized.Allowlist = append(normalized.Allowlist, StyxAllowRule{
			CgroupID: storedID, CgroupPath: allow.CgroupPath, CIDR: allow.CIDR,
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
