// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5 tests: StyX settings namespace, the policy syncer's fail-safe
// ordering/retry contract, the XDR/beacon integration (incident exactly once,
// dedupe, degraded -> no response, evidence first) and the read-only API surface.
// The syncer is exercised against an in-process fake core, so the ordering
// contract is pinned without a privileged kernel.

import (
	"fmt"
	"strings"
	"testing"
)

// --------------------------------------------------- settings & validation

func TestStyxFabricSettingsDefaultsKeepUpgradeBehaviour(t *testing.T) {
	cfg := defaultConfig()
	defaults := defaultRuntimeSettings(cfg)
	if defaults.Styx == nil {
		t.Fatal("a fresh settings document carries no StyX namespace")
	}
	if defaults.Styx.Enabled || defaults.Styx.Mode != StyxModeOff {
		t.Fatalf("the StyX default must not change kernel behaviour: %+v", *defaults.Styx)
	}
	if err := validateRuntimeSettings(&defaults); err != nil {
		t.Fatalf("default runtime settings are invalid: %v", err)
	}

	// The real upgrade path ships from a v12 document: the namespace is seeded and
	// the migration note names it, because the operator sees new fields appear.
	legacy := defaultRuntimeSettings(cfg)
	legacy.FabricVersion = 12
	legacy.Styx = nil
	legacy.Migrations = nil
	if !upgradeRuntimeSettings(&legacy, defaults) {
		t.Fatal("a v12 document was not upgraded")
	}
	if legacy.Styx == nil || legacy.Styx.Enabled || legacy.Styx.Mode != StyxModeOff {
		t.Fatalf("upgrade did not seed the disabled namespace: %+v", legacy.Styx)
	}
	if legacy.FabricVersion != fabricSettingsVersion {
		t.Fatalf("document stayed at version %d", legacy.FabricVersion)
	}
	note := strings.Join(legacy.Migrations, " ")
	if !strings.Contains(note, "styX namespace") || !strings.Contains(note, "enabled=false") || !strings.Contains(note, "mode=off") {
		t.Fatalf("the migration did not record the new namespace honestly: %q", note)
	}

	// Older documents receive several namespaces at once (exactly like the earlier
	// additive modules) and must not accumulate a migration note for that seed: the
	// established migration contract only names a changed operator value.
	ancient := RuntimeSettings{FabricVersion: 9}
	if !upgradeRuntimeSettings(&ancient, defaults) {
		t.Fatal("an ancient document was not upgraded")
	}
	if ancient.Styx == nil || ancient.Styx.Enabled || ancient.Styx.Mode != StyxModeOff {
		t.Fatalf("ancient upgrade did not seed the disabled namespace: %+v", ancient.Styx)
	}
	if len(ancient.Migrations) != 0 {
		t.Fatalf("ancient upgrade invented migration notes: %v", ancient.Migrations)
	}
}

func TestStyxFabricSettingsCloneIsDeep(t *testing.T) {
	settings := styxPolicyTestSettings()
	clone := cloneRuntimeSettings(settings)
	clone.Styx.PerCell[0].CgroupID = 999
	clone.Styx.Allowlist[0].CIDR = "192.0.2.0/24"
	clone.Styx.DnsResolvers[0] = "192.0.2.1/32"
	if settings.Styx.PerCell[0].CgroupID == 999 || settings.Styx.Allowlist[0].CIDR == "192.0.2.0/24" || settings.Styx.DnsResolvers[0] == "192.0.2.1/32" {
		t.Fatal("cloneRuntimeSettings shared StyX slices with the source document")
	}
}

func TestStyxFabricSettingsValidationRejectsHostileInput(t *testing.T) {
	valid := styxPolicyTestSettings().Styx
	if valid == nil {
		t.Fatal("fixture has no StyX namespace")
	}
	cases := map[string]func(*StyxFabricSettings){
		"bad-mode": func(s *StyxFabricSettings) { s.Mode = "blocked" },
		"bad-cell-mode": func(s *StyxFabricSettings) {
			s.PerCell = append(s.PerCell, StyxCellMode{CgroupID: 7, Mode: "deny"})
		},
		"zero-cell-cgroup": func(s *StyxFabricSettings) {
			s.PerCell = append(s.PerCell, StyxCellMode{CgroupID: 0, Mode: StyxModeMonitor})
		},
		"duplicate-cell": func(s *StyxFabricSettings) {
			s.PerCell = append(s.PerCell, StyxCellMode{CgroupID: 100, Mode: StyxModeMonitor})
		},
		"zero-allow-cgroup": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 0, CIDR: "203.0.113.0/24"})
		},
		"noncanonical-cidr": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 100, CIDR: "10.0.0.1/8"})
		},
		"mapped-ipv6": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 100, CIDR: "::ffff:10.0.0.1/128"})
		},
		"short-cidr": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 100, CIDR: "10.0.0.0/2"})
		},
		"port-range": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 100, CIDR: "203.0.113.10/32", PortLo: 1000, PortHi: 2000})
		},
		"port-without-host-cidr": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 100, CIDR: "198.51.100.0/24", PortLo: 443, PortHi: 443})
		},
		"proto-with-wildcard-port": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 100, CIDR: "203.0.113.10/32", Proto: "tcp"})
		},
		"unknown-proto": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 100, CIDR: "203.0.113.10/32", PortLo: 443, PortHi: 443, Proto: "sctp"})
		},
		"ipv6-port-rule": func(s *StyxFabricSettings) {
			s.Allowlist = append(s.Allowlist, StyxAllowRule{CgroupID: 100, CIDR: "2001:db8::1/128", PortLo: 443, PortHi: 443})
		},
		"bad-resolver": func(s *StyxFabricSettings) { s.DnsResolvers = []string{"9.9.9.1/8"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := cloneStyxFabricSettings(*valid)
			mutate(&candidate)
			if err := validateStyxFabricSettings(&candidate); err == nil {
				t.Fatalf("hostile StyX settings were accepted: %+v", candidate)
			}
		})
	}

	tooManyCells := cloneStyxFabricSettings(*valid)
	tooManyCells.PerCell = make([]StyxCellMode, styxMaxPerCellModes+1)
	for index := range tooManyCells.PerCell {
		tooManyCells.PerCell[index] = StyxCellMode{CgroupID: uint64(index + 1), Mode: StyxModeOff}
	}
	if err := validateStyxFabricSettings(&tooManyCells); err == nil {
		t.Fatal("per-cell cap was not enforced")
	}
	tooManyAllow := cloneStyxFabricSettings(*valid)
	tooManyAllow.Allowlist = make([]StyxAllowRule, styxMaxAllowRules+1)
	for index := range tooManyAllow.Allowlist {
		tooManyAllow.Allowlist[index] = StyxAllowRule{CgroupID: uint64(index + 10), CIDR: fmt.Sprintf("198.51.100.%d/32", (index%250)+1)}
	}
	if err := validateStyxFabricSettings(&tooManyAllow); err == nil {
		t.Fatal("allowlist cap was not enforced")
	}
	tooManyResolvers := cloneStyxFabricSettings(*valid)
	tooManyResolvers.DnsResolvers = make([]string, styxMaxDNSResolvers+1)
	for index := range tooManyResolvers.DnsResolvers {
		tooManyResolvers.DnsResolvers[index] = fmt.Sprintf("198.51.%d.53/32", (index/250)+1)
	}
	if err := validateStyxFabricSettings(&tooManyResolvers); err == nil {
		t.Fatal("DNS resolver cap was not enforced")
	}
}

func TestStyxFabricSettingsValidationCanonicalises(t *testing.T) {
	settings := StyxFabricSettings{
		Enabled:      true,
		Mode:         " MONITOR ",
		LogFlows:     true,
		DnsResolvers: []string{"2001:db8::1/128", "9.9.9.9/32", "9.9.9.9/32"},
		PerCell: []StyxCellMode{
			{CgroupID: 300, Mode: "enforce", DnsResolver: true},
			{CgroupID: 100, Mode: "off"},
		},
		Allowlist: []StyxAllowRule{
			{CgroupID: 100, CIDR: "203.0.113.10"},
			{CgroupID: 100, CIDR: "203.0.113.10/32", PortLo: 443, PortHi: 443, Proto: "TCP+UDP"},
		},
	}
	if err := validateStyxFabricSettings(&settings); err != nil {
		t.Fatal(err)
	}
	if settings.Mode != StyxModeMonitor {
		t.Fatalf("mode was not normalised: %q", settings.Mode)
	}
	if len(settings.DnsResolvers) != 2 || settings.DnsResolvers[0] != "9.9.9.9/32" || settings.DnsResolvers[1] != "2001:db8::1/128" {
		t.Fatalf("resolvers were not canonicalised/sorted: %v", settings.DnsResolvers)
	}
	if len(settings.PerCell) != 2 || settings.PerCell[0].CgroupID != 100 || settings.PerCell[1].CgroupID != 300 {
		t.Fatalf("per-cell entries were not sorted: %+v", settings.PerCell)
	}
	if len(settings.Allowlist) != 2 {
		t.Fatalf("allowlist entries were dropped: %+v", settings.Allowlist)
	}
	wildcard := settings.Allowlist[0]
	if wildcard.CIDR != "203.0.113.10/32" || wildcard.PortLo != 0 || wildcard.PortHi != 65535 {
		t.Fatalf("wildcard port encoding is wrong: %+v", wildcard)
	}
	if settings.Allowlist[1].Proto != "tcp+udp" || settings.Allowlist[1].PortLo != 443 {
		t.Fatalf("protocol/port rule was not preserved: %+v", settings.Allowlist[1])
	}
}

// A global mode=off with per-cell/allowlist/resolver rules is a silent no-op:
// §6.1 makes the kernel hook return before any policy lookup and disables flow
// logging. The settings layer refuses it visibly instead of persisting an inert
// policy the operator would believe is enforced.
func TestStyxFabricSettingsRejectsInertModeOffPolicy(t *testing.T) {
	fixture := cloneStyxFabricSettings(*styxPolicyTestSettings().Styx)
	fixture.Mode = StyxModeOff
	err := validateStyxFabricSettings(&fixture)
	if err == nil || !strings.Contains(err.Error(), "mode=off") || !strings.Contains(err.Error(), "monitor or enforce") {
		t.Fatalf("inert mode=off policy was not refused visibly: %v", err)
	}
	if _, planErr := buildStyxPolicyPlan(fixture); planErr == nil {
		t.Fatal("plan builder (sync path) accepted an inert mode=off policy")
	}
	// No rules => a clean, visible off namespace is valid.
	clean := StyxFabricSettings{Enabled: true, Mode: StyxModeOff, LogFlows: true}
	if err := validateStyxFabricSettings(&clean); err != nil {
		t.Fatalf("clean off settings were rejected: %v", err)
	}
	// Per-cell entries that are themselves off are not an inert policy.
	offCells := StyxFabricSettings{Enabled: true, Mode: StyxModeOff, PerCell: []StyxCellMode{{CgroupID: 5, Mode: StyxModeOff}}}
	if err := validateStyxFabricSettings(&offCells); err != nil {
		t.Fatalf("off per-cell entries were rejected: %v", err)
	}
	// A disabled namespace may carry a draft: the upgrade path (Enabled=false)
	// must stay permissive because nothing is claimed to be enforced.
	draft := cloneStyxFabricSettings(*styxPolicyTestSettings().Styx)
	draft.Enabled = false
	draft.Mode = StyxModeOff
	if err := validateStyxFabricSettings(&draft); err != nil {
		t.Fatalf("disabled draft settings were rejected: %v", err)
	}
}

func TestStyxBeaconSettingsProjectModeOffHonestly(t *testing.T) {
	engine, _, _ := newStyxXDRFixture(t, activeBeaconConfig())
	engine.setStyxBeaconCapability(true)
	runtime := defaultRuntimeSettings(defaultConfig())
	off := StyxFabricSettings{Enabled: true, Mode: StyxModeOff, LogFlows: true}
	runtime.Styx = &off
	engine.applyStyxBeaconSettings(runtime)
	if got := engine.StyxBeaconSnapshot().SensorState; got != "off" {
		t.Fatalf("mode=off was projected as %q, want off", got)
	}
	if incidents := engine.styxBeacon.RecordFlows(combinedBeaconEvents()); len(incidents) != 0 {
		t.Fatalf("mode=off detector processed flows: %d incidents", len(incidents))
	}
	monitor := StyxFabricSettings{Enabled: true, Mode: StyxModeMonitor, LogFlows: true}
	runtime.Styx = &monitor
	engine.applyStyxBeaconSettings(runtime)
	if got := engine.StyxBeaconSnapshot().SensorState; got != "active" {
		t.Fatalf("monitor mode was projected as %q, want active", got)
	}
}

func TestStyxPolicyPlanMapping(t *testing.T) {
	plan := styxPolicyTestPlan(t, styxPolicyTestSettings())
	if !plan.Enabled || plan.Mode != 1 || plan.GlobalFlags != styxGlobalFlagLogFlows || !plan.LogFlows {
		t.Fatalf("enabled monitor plan is wrong: %+v", plan)
	}
	if len(plan.Cells) != 2 {
		t.Fatalf("expected two cell entries, got %+v", plan.Cells)
	}
	if plan.Cells[0].CgroupID != 100 || plan.Cells[0].Mode != 2 || plan.Cells[0].Flags != styxModeFlagAllowHostAllowlist|styxModeFlagLogFlows {
		t.Fatalf("enforce cell flags are wrong: %+v", plan.Cells[0])
	}
	if plan.Cells[1].CgroupID != 200 || plan.Cells[1].Mode != 1 || plan.Cells[1].Flags != styxModeFlagDNSResolver|styxModeFlagLogFlows {
		t.Fatalf("monitor cell flags are wrong: %+v", plan.Cells[1])
	}
	// The host+port rule keeps its restriction; the /24 stays a wildcard rule.
	if len(plan.Allow) != 2 || plan.Allow[0].PortHi != 65535 || plan.Allow[1].PortLo != 443 || plan.Allow[1].ProtoMask != 1 {
		t.Fatalf("allow plan mapping is wrong: %+v", plan.Allow)
	}
	if plan.fingerprint() == "" {
		t.Fatal("plan fingerprint is empty")
	}
	if other := styxPolicyTestPlan(t, styxDisabledSettings(styxPolicyTestSettings())); other.fingerprint() == plan.fingerprint() {
		t.Fatal("different plans share one fingerprint")
	}

	disabled := styxPolicyTestPlan(t, styxDisabledSettings(styxPolicyTestSettings()))
	if disabled.Enabled || disabled.Mode != 0 || disabled.GlobalFlags != 0 || disabled.LogFlows {
		t.Fatalf("disabled plan still asks for kernel state: %+v", disabled)
	}
}
