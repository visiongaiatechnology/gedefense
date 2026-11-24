// STATUS: DIAMANT VGT SUPREME
// Runtime-settings defaults, validation and effective-value resolution,
// split out of runtime_settings.go (refactoring wave 1b, structure-only).
package main

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

func defaultRuntimeSettings(cfg Config) RuntimeSettings {
	l7Fabric := defaultL7FabricSettings(cfg.L7)
	threatIntel := defaultThreatIntelFabricSettings(cfg.Feeds, DefaultThreatFeedSources)
	hardening := defaultHardeningFabricSettings(cfg, "")
	integrity := defaultIntegrityFabricSettings(cfg)
	detection := defaultDetectionFabricSettings()
	bootTrust := defaultBootTrustFabricSettings()
	policyTrust := defaultPolicyTrustFabricSettings()
	policyTrust.RequireSigned = cfg.Policy.RequireSigned
	forensics := defaultForensicsFabricSettings()
	system := defaultSystemFabricSettings(cfg)
	styx := defaultStyxFabricSettings()
	titanExec := defaultTitanExecFabricSettings()
	parserCells := defaultParserCellsFabricSettings()
	lockdown := defaultLockdownFabricSettings()
	witness := defaultWitnessFabricSettings()
	webExposure := defaultWebExposureFabricSettings()
	workerGuard := defaultWorkerGuardFabricSettings()
	tlsSensor := defaultTLSSensorFabricSettings()
	lpeGuard := defaultLPEGuardFabricSettings()
	edgeProxy := defaultEdgeProxyFabricSettings()
	return RuntimeSettings{
		FabricVersion:          fabricSettingsVersion,
		Revision:               1,
		UpdatedAt:              time.Now().UTC(),
		XDREnabled:             cfg.XDR.Enabled,
		NetworkSensorEnabled:   true,
		BehaviorEnabled:        cfg.XDR.BehaviorEnabled,
		FeedsEnabled:           threatIntel.Enabled,
		AutoFeedSync:           threatIntel.AutoSync,
		AutoDegrade:            cfg.Release.AutoDegrade,
		ScanIntervalMillis:     cfg.XDR.ScanIntervalMillis,
		NetworkIntervalSeconds: cfg.XDR.NetworkIntervalSeconds,
		AlertScore:             cfg.XDR.AlertScore,
		ContainScore:           cfg.XDR.ContainScore,
		KillScore:              cfg.XDR.KillScore,
		ManagementAllowlist:    append(make([]string, 0, len(cfg.Defense.Allowlist)), cfg.Defense.Allowlist...),
		EnabledRuleModules:     append([]string(nil), supportedRuleModules...),
		CustomRules:            []CustomRule{},
		Kinetic: KineticRuntimeSettings{
			Enabled: cfg.Kinetic.Enabled, EnforcementMode: cfg.Kinetic.EnforcementMode,
			IPThreshold: cfg.Kinetic.IPThreshold, VelocityLimit: cfg.Kinetic.VelocityLimit,
			RangeThreshold: cfg.Kinetic.RangeThreshold, IPv6SubThreshold: cfg.Kinetic.IPv6SubThreshold,
			WideRangeThreshold: cfg.Kinetic.WideRangeThreshold, PortscanThreshold: cfg.Kinetic.PortscanThreshold,
			SYNThreshold: cfg.Kinetic.SYNThreshold, SYNAckRatio: cfg.Kinetic.SYNAckRatio, LowSlowMinSeconds: cfg.Kinetic.LowSlowMinSeconds,
			SubnetMinSources: cfg.Kinetic.SubnetMinSources, IPv6SubnetMinSources: cfg.Kinetic.IPv6SubnetMinSources, WideMinSources: cfg.Kinetic.WideMinSources,
			AutoContainSingleIP: cfg.Kinetic.AutoContainSingleIP, AutoContainIPv4Subnet: cfg.Kinetic.AutoContainIPv4Subnet, AutoContainIPv6Subnet: cfg.Kinetic.AutoContainIPv6Subnet,
			MaxTrackingIPs: cfg.Kinetic.MaxTrackingIPs, BanTTLSeconds: cfg.Kinetic.BanTTLSeconds,
			MaxStrikesPerSec:  cfg.Kinetic.MaxStrikesPerSec,
			ServicePortsWeb:   append([]uint16(nil), cfg.Kinetic.ServicePortsWeb...),
			ServicePortsMail:  append([]uint16(nil), cfg.Kinetic.ServicePortsMail...),
			ServicePortsAdmin: append([]uint16(nil), cfg.Kinetic.ServicePortsAdmin...),
		},
		Network:    NetworkRuntimeSettings{DefaultTTLSeconds: cfg.Defense.DefaultTTLSeconds, MaxTTLSeconds: cfg.Defense.MaxTTLSeconds, MaxBlockEntries: cfg.Defense.MaxBlockEntries, StrictASNDrop: cfg.Defense.StrictASNDrop},
		Protection: ProtectionRuntimeSettings{MinimumObserveSeconds: cfg.Release.MinimumObserveSeconds, MinimumCanarySeconds: cfg.Release.MinimumCanarySeconds, CoreFailureThreshold: cfg.Release.CoreFailureThreshold, MaxEvaluationDropPermille: cfg.Release.MaxEvaluationDropPermille},
		XDRFabric: XDRFabricSettings{
			WorkerCount: cfg.XDR.WorkerCount, QueueCapacity: cfg.XDR.QueueCapacity, MaxEvaluationsPerScan: cfg.XDR.MaxEvaluationsPerScan,
			DedupeSeconds: cfg.XDR.DedupeSeconds, MaxCommandBytes: cfg.XDR.MaxCommandBytes, CommandPreviewBytes: cfg.XDR.CommandPreviewBytes,
			ContainmentTTLSeconds: 900, MalwareCorrelation: true, BehaviorExecBurst: 12, BehaviorWarmupSamples: cfg.XDR.BehaviorWarmupSamples,
			BehaviorZScoreMilli: cfg.XDR.BehaviorZScoreMilli, BehaviorMinConnections: cfg.XDR.BehaviorMinConnections,
			BehaviorMaxProfiles: cfg.XDR.BehaviorMaxProfiles, BehaviorMaxPorts: cfg.XDR.BehaviorMaxPorts,
			ProtectedPaths: append([]string(nil), cfg.XDR.ProtectedPaths...), AllowProcesses: append([]string(nil), cfg.XDR.AllowProcesses...), RuleOverrides: []XDRRuleOverride{},
		},
		L7:          &l7Fabric,
		ThreatIntel: &threatIntel,
		Hardening:   &hardening,
		Integrity:   &integrity,
		Detection:   &detection,
		BootTrust:   &bootTrust,
		PolicyTrust: &policyTrust,
		Forensics:   &forensics,
		System:      &system,
		Styx:        &styx,
		TitanExec:   &titanExec,
		ParserCells: &parserCells,
		Lockdown:    &lockdown,
		Witness:     &witness,
		WebExposure: &webExposure,
		WorkerGuard: &workerGuard,
		TLSSensor:   &tlsSensor,
		LPEGuard:    &lpeGuard,
		EdgeProxy:   &edgeProxy,
	}
}

// effectiveThreatIntelSettings returns the persisted Threat Intelligence
// namespace. The enablement flags always follow the document's authoritative
// legacy fields, so the namespace and the rest of the control plane can never
// disagree about whether threat intelligence is active.
func effectiveThreatIntelSettings(settings RuntimeSettings) ThreatIntelFabricSettings {
	out := defaultThreatIntelFabricSettings(FeedConfig{}, DefaultThreatFeedSources)
	if settings.ThreatIntel != nil {
		out = cloneThreatIntelFabricSettings(*settings.ThreatIntel)
	}
	out.Enabled = settings.FeedsEnabled
	out.AutoSync = settings.AutoFeedSync
	return out
}

// effectiveL7Settings returns the persisted Application Defense namespace, or
// the bootstrap-derived defaults when a document predates the namespace.
func effectiveL7Settings(settings RuntimeSettings, bootstrap L7Config) L7FabricSettings {
	if settings.L7 != nil {
		return cloneL7FabricSettings(*settings.L7)
	}
	return defaultL7FabricSettings(bootstrap)
}

func validatePortList(name string, ports []uint16) error {
	if len(ports) > 256 {
		return fmt.Errorf("%s exceeds 256 ports", name)
	}
	seen := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			return fmt.Errorf("%s contains invalid port 0", name)
		}
		if _, exists := seen[port]; exists {
			return fmt.Errorf("%s contains duplicate port %d", name, port)
		}
		seen[port] = struct{}{}
	}
	return nil
}

func validateRuntimeSettings(settings *RuntimeSettings) error {
	if settings.ScanIntervalMillis < 100 || settings.ScanIntervalMillis > 60000 {
		return errors.New("scan interval must be between 100 and 60000 milliseconds")
	}
	if settings.NetworkIntervalSeconds < 1 || settings.NetworkIntervalSeconds > 300 {
		return errors.New("network interval must be between 1 and 300 seconds")
	}
	if settings.AlertScore < 1 || settings.KillScore > 250 || !(settings.AlertScore < settings.ContainScore && settings.ContainScore < settings.KillScore) {
		return errors.New("scores must satisfy 1 <= alert < contain < kill <= 250")
	}
	if settings.AutoFeedSync && !settings.FeedsEnabled {
		return errors.New("automatic feed synchronization requires feeds to be enabled")
	}
	if len(settings.ManagementAllowlist) > 1024 {
		return errors.New("management allowlist exceeds 1024 entries")
	}
	seen := make(map[string]struct{}, len(settings.ManagementAllowlist))
	normalized := make([]string, 0, len(settings.ManagementAllowlist))
	for _, target := range settings.ManagementAllowlist {
		value, err := normalizeTarget(target)
		if err != nil {
			return fmt.Errorf("management allowlist %q: %w", target, err)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	settings.ManagementAllowlist = normalized
	if len(settings.EnabledRuleModules) > len(supportedRuleModules) {
		return errors.New("enabled rule modules exceed supported module count")
	}
	supported := make(map[string]struct{}, len(supportedRuleModules))
	for _, module := range supportedRuleModules {
		supported[module] = struct{}{}
	}
	if settings.EnabledRuleModules != nil {
		moduleSeen := make(map[string]struct{}, len(settings.EnabledRuleModules))
		modules := make([]string, 0, len(settings.EnabledRuleModules))
		for _, module := range settings.EnabledRuleModules {
			module = strings.ToLower(strings.TrimSpace(module))
			if _, ok := supported[module]; !ok {
				return fmt.Errorf("unsupported rule module %q", module)
			}
			if _, duplicate := moduleSeen[module]; duplicate {
				continue
			}
			moduleSeen[module] = struct{}{}
			modules = append(modules, module)
		}
		sort.Strings(modules)
		settings.EnabledRuleModules = modules
	}
	if len(settings.CustomRules) > 64 {
		return errors.New("custom rule limit of 64 exceeded")
	}
	ruleIDs := make(map[string]struct{}, len(settings.CustomRules))
	for index := range settings.CustomRules {
		rule := &settings.CustomRules[index]
		rule.ID = strings.ToUpper(strings.TrimSpace(rule.ID))
		rule.Category = strings.ToLower(strings.TrimSpace(rule.Category))
		rule.Summary = strings.TrimSpace(rule.Summary)
		if !strings.HasPrefix(rule.ID, "CUSTOM.") || len(rule.ID) > 64 || !protocolFieldValid(rule.ID) {
			return fmt.Errorf("custom rule %d ID must be a protocol-safe CUSTOM.* identifier", index)
		}
		if _, duplicate := ruleIDs[rule.ID]; duplicate {
			return fmt.Errorf("duplicate custom rule ID %q", rule.ID)
		}
		ruleIDs[rule.ID] = struct{}{}
		if len(rule.Category) < 2 || len(rule.Category) > 32 || !protocolFieldValid(rule.Category) {
			return fmt.Errorf("custom rule %s category is invalid", rule.ID)
		}
		if len(rule.Summary) < 3 || len(rule.Summary) > 160 || strings.ContainsAny(rule.Summary, "\r\n\x00") {
			return fmt.Errorf("custom rule %s summary must contain 3-160 single-line characters", rule.ID)
		}
		if len(rule.Pattern) < 1 || len(rule.Pattern) > 512 || strings.TrimSpace(rule.Pattern) == "" || strings.ContainsRune(rule.Pattern, '\x00') {
			return fmt.Errorf("custom rule %s pattern must contain 1-512 characters", rule.ID)
		}
		if rule.Score < 1 || rule.Score > 100 {
			return fmt.Errorf("custom rule %s score must be between 1 and 100", rule.ID)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("custom rule %s is not valid RE2 syntax: %w", rule.ID, err)
		}
	}
	sort.Slice(settings.CustomRules, func(i, j int) bool {
		return settings.CustomRules[i].ID < settings.CustomRules[j].ID
	})
	if settings.L7 != nil {
		l7Fabric := cloneL7FabricSettings(*settings.L7)
		if err := validateL7FabricSettings(&l7Fabric); err != nil {
			return fmt.Errorf("l7 settings: %w", err)
		}
		settings.L7 = &l7Fabric
	}
	if settings.ThreatIntel != nil {
		threatIntel := cloneThreatIntelFabricSettings(*settings.ThreatIntel)
		threatIntel.Enabled = settings.FeedsEnabled
		threatIntel.AutoSync = settings.AutoFeedSync
		if err := validateThreatIntelFabricSettings(&threatIntel); err != nil {
			return fmt.Errorf("threat intelligence settings: %w", err)
		}
		settings.ThreatIntel = &threatIntel
	}
	if settings.Hardening != nil {
		hardening := cloneHardeningFabricSettings(*settings.Hardening)
		if err := validateHardeningFabricSettings(&hardening, sysctlControlAllowlist()); err != nil {
			return fmt.Errorf("hardening settings: %w", err)
		}
		settings.Hardening = &hardening
	}
	if settings.Integrity != nil {
		integrity := cloneIntegrityFabricSettings(*settings.Integrity)
		if err := validateIntegrityFabricSettings(&integrity); err != nil {
			return fmt.Errorf("integrity settings: %w", err)
		}
		settings.Integrity = &integrity
	}
	if settings.BootTrust != nil {
		bootTrust := cloneBootTrustFabricSettings(*settings.BootTrust)
		if err := validateBootTrustFabricSettings(&bootTrust); err != nil {
			return fmt.Errorf("boot trust settings: %w", err)
		}
		settings.BootTrust = &bootTrust
	}
	if settings.PolicyTrust != nil {
		policyTrust := *settings.PolicyTrust
		if err := validatePolicyTrustFabricSettings(&policyTrust); err != nil {
			return fmt.Errorf("policy trust settings: %w", err)
		}
		settings.PolicyTrust = &policyTrust
	}
	if settings.Forensics != nil {
		forensics := cloneForensicsFabricSettings(*settings.Forensics)
		if err := validateForensicsFabricSettings(&forensics); err != nil {
			return fmt.Errorf("forensics settings: %w", err)
		}
		settings.Forensics = &forensics
	}
	if settings.System != nil {
		system := *settings.System
		if err := validateSystemFabricSettings(&system); err != nil {
			return fmt.Errorf("system settings: %w", err)
		}
		settings.System = &system
	}
	if settings.Styx != nil {
		styx := cloneStyxFabricSettings(*settings.Styx)
		if err := validateStyxFabricSettings(&styx); err != nil {
			return fmt.Errorf("styX settings: %w", err)
		}
		settings.Styx = &styx
	}
	if settings.TitanExec != nil {
		titanExec := cloneTitanExecFabricSettings(*settings.TitanExec)
		if err := validateTitanExecFabricSettings(&titanExec); err != nil {
			return fmt.Errorf("titan exec settings: %w", err)
		}
		settings.TitanExec = &titanExec
	}
	if settings.ParserCells != nil {
		parserCells := cloneParserCellsFabricSettings(*settings.ParserCells)
		if err := validateParserCellsFabricSettings(&parserCells); err != nil {
			return fmt.Errorf("parser cell settings: %w", err)
		}
		settings.ParserCells = &parserCells
	}
	if settings.Lockdown != nil {
		// Reject-not-repair: the emergency-lockdown bounds are enforced before the
		// revision can be persisted, so an accepted document is always one the engine
		// can honour without clamping a safety switch.
		lockdown := cloneLockdownFabricSettings(*settings.Lockdown)
		if err := validateLockdownFabricSettings(&lockdown); err != nil {
			return fmt.Errorf("lockdown settings: %w", err)
		}
		settings.Lockdown = &lockdown
	}
	if settings.Witness != nil {
		// Reject-not-repair: the witness transport anchors and bounds are enforced
		// before the revision can be persisted, so an accepted document is always
		// one the engine can honour without repairing a trust anchor.
		witness := cloneWitnessFabricSettings(*settings.Witness)
		if err := validateWitnessFabricSettings(&witness); err != nil {
			return fmt.Errorf("witness settings: %w", err)
		}
		settings.Witness = &witness
	}
	if settings.WebExposure != nil {
		// Reject-not-repair: scan bounds, configuration roots and the advisory
		// catalogue are validated before the revision can be persisted.
		webExposure := cloneWebExposureFabricSettings(*settings.WebExposure)
		if err := validateWebExposureFabricSettings(&webExposure); err != nil {
			return fmt.Errorf("web exposure settings: %w", err)
		}
		settings.WebExposure = &webExposure
	}
	if settings.WorkerGuard != nil {
		workerGuard := cloneWorkerGuardFabricSettings(*settings.WorkerGuard)
		if err := validateWorkerGuardFabricSettings(&workerGuard); err != nil {
			return fmt.Errorf("worker guard settings: %w", err)
		}
		settings.WorkerGuard = &workerGuard
	}
	if settings.TLSSensor != nil {
		tlsSensor := cloneTLSSensorFabricSettings(*settings.TLSSensor)
		if err := validateTLSSensorFabricSettings(&tlsSensor); err != nil {
			return fmt.Errorf("tls sensor settings: %w", err)
		}
		settings.TLSSensor = &tlsSensor
	}
	if settings.LPEGuard != nil {
		lpeGuard := cloneLPEGuardFabricSettings(*settings.LPEGuard)
		if err := validateLPEGuardFabricSettings(&lpeGuard); err != nil {
			return fmt.Errorf("lpe guard settings: %w", err)
		}
		settings.LPEGuard = &lpeGuard
	}
	if settings.EdgeProxy != nil {
		edgeProxy := cloneEdgeProxyFabricSettings(*settings.EdgeProxy)
		if err := validateEdgeProxyFabricSettings(&edgeProxy); err != nil {
			return fmt.Errorf("edge proxy settings: %w", err)
		}
		settings.EdgeProxy = &edgeProxy
	}
	if settings.FabricVersion >= fabricSettingsVersion {
		k := &settings.Kinetic
		if k.EnforcementMode != "observe" && k.EnforcementMode != "contain" && k.EnforcementMode != "block" {
			return errors.New("kinetic enforcement mode must be observe, contain, or block")
		}
		if k.IPThreshold < 1 || k.IPThreshold > 100000 || k.VelocityLimit < 1 || k.VelocityLimit > 50000 || k.RangeThreshold < 1 || k.RangeThreshold > 100000 || k.IPv6SubThreshold < 1 || k.IPv6SubThreshold > 100000 || k.WideRangeThreshold < 1 || k.WideRangeThreshold > 100000 || k.PortscanThreshold < 2 || k.PortscanThreshold > 65535 {
			return errors.New("kinetic detection thresholds are outside safe bounds")
		}
		if k.SYNThreshold < 1 || k.SYNThreshold > 100000 || k.SYNAckRatio < 1 || k.SYNAckRatio > 100 || k.LowSlowMinSeconds < 10 || k.LowSlowMinSeconds > 86400 || k.SubnetMinSources < 2 || k.SubnetMinSources > 1024 || k.IPv6SubnetMinSources < 2 || k.IPv6SubnetMinSources > 1024 || k.WideMinSources < 2 || k.WideMinSources > 4096 {
			return errors.New("kinetic SYN/subnet correlation settings are outside safe bounds")
		}
		if k.MaxTrackingIPs < 100 || k.MaxTrackingIPs > 500000 || k.BanTTLSeconds < 60 || k.BanTTLSeconds > 604800 || k.MaxStrikesPerSec < 1 || k.MaxStrikesPerSec > 10000 {
			return errors.New("kinetic resource/TTL settings are outside safe bounds")
		}
		if err := validatePortList("kinetic web service ports", k.ServicePortsWeb); err != nil {
			return err
		}
		if err := validatePortList("kinetic mail service ports", k.ServicePortsMail); err != nil {
			return err
		}
		if err := validatePortList("kinetic admin service ports", k.ServicePortsAdmin); err != nil {
			return err
		}
		n := &settings.Network
		if n.DefaultTTLSeconds < 60 || n.MaxTTLSeconds < n.DefaultTTLSeconds || n.MaxTTLSeconds > 2592000 || n.MaxBlockEntries < 100 || n.MaxBlockEntries > 1000000 {
			return errors.New("network TTL/capacity settings are outside safe bounds")
		}
		p := &settings.Protection
		if p.MinimumObserveSeconds < 0 || p.MinimumObserveSeconds > 604800 || p.MinimumCanarySeconds < 0 || p.MinimumCanarySeconds > 604800 || p.CoreFailureThreshold < 1 || p.CoreFailureThreshold > 100 || p.MaxEvaluationDropPermille < 0 || p.MaxEvaluationDropPermille > 1000 {
			return errors.New("protection gate settings are outside safe bounds")
		}
		x := &settings.XDRFabric
		if x.WorkerCount < 1 || x.WorkerCount > 64 || x.QueueCapacity < 128 || x.QueueCapacity > 131072 || x.MaxEvaluationsPerScan < 128 || x.MaxEvaluationsPerScan > 1000000 || x.DedupeSeconds < 0 || x.DedupeSeconds > 86400 {
			return errors.New("XDR worker/queue settings are outside safe bounds")
		}
		if x.MaxCommandBytes < 256 || x.MaxCommandBytes > 1<<20 || x.CommandPreviewBytes < 64 || x.CommandPreviewBytes > x.MaxCommandBytes || x.ContainmentTTLSeconds < 60 || x.ContainmentTTLSeconds > 604800 {
			return errors.New("XDR command/response settings are outside safe bounds")
		}
		if x.BehaviorWarmupSamples < 1 || x.BehaviorWarmupSamples > 100000 || x.BehaviorZScoreMilli < 1000 || x.BehaviorZScoreMilli > 20000 || x.BehaviorMinConnections < 1 || x.BehaviorMinConnections > 100000 || x.BehaviorMaxProfiles < 64 || x.BehaviorMaxProfiles > 100000 || x.BehaviorMaxPorts < 16 || x.BehaviorMaxPorts > 65535 || x.BehaviorExecBurst < 2 || x.BehaviorExecBurst > 10000 {
			return errors.New("XDR behavior settings are outside safe bounds")
		}
		if len(x.ProtectedPaths) > 512 || len(x.AllowProcesses) > 512 {
			return errors.New("XDR protected/allowed path list exceeds safe bound")
		}
		if len(x.RuleOverrides) > 64 {
			return errors.New("XDR built-in rule override limit exceeded")
		}
		overrideIDs := make(map[string]struct{}, len(x.RuleOverrides))
		for i := range x.RuleOverrides {
			o := &x.RuleOverrides[i]
			o.ID = strings.ToUpper(strings.TrimSpace(o.ID))
			if !xdrRuleOverrideIDAllowed(o.ID) {
				return fmt.Errorf("XDR rule override %q is not a supported built-in rule", o.ID)
			}
			if _, exists := overrideIDs[o.ID]; exists {
				return fmt.Errorf("duplicate XDR rule override %q", o.ID)
			}
			overrideIDs[o.ID] = struct{}{}
			if o.Score < 1 || o.Score > 250 {
				return fmt.Errorf("XDR rule override %s score must be between 1 and 250", o.ID)
			}
		}
		sort.Slice(x.RuleOverrides, func(i, j int) bool { return x.RuleOverrides[i].ID < x.RuleOverrides[j].ID })
	}
	return nil
}

func effectiveRuleModules(settings RuntimeSettings) map[string]bool {
	modules := settings.EnabledRuleModules
	if modules == nil {
		modules = supportedRuleModules
	}
	out := make(map[string]bool, len(modules))
	for _, module := range modules {
		out[module] = true
	}
	return out
}
