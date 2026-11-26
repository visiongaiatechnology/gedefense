// STATUS: DIAMANT VGT SUPREME
// Runtime-settings document structs and deep-copy helpers, split out of
// runtime_settings.go (refactoring wave 1b, structure-only).
package main

import (
	"sync"
	"time"
)

type CustomRule struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	Pattern  string `json:"pattern"`
	Score    int    `json:"score"`
}

type KineticRuntimeSettings struct {
	Enabled               bool     `json:"enabled"`
	EnforcementMode       string   `json:"enforcement_mode"`
	IPThreshold           int      `json:"ip_threshold"`
	VelocityLimit         int      `json:"velocity_limit"`
	RangeThreshold        int      `json:"range_threshold"`
	IPv6SubThreshold      int      `json:"ipv6_sub_threshold"`
	WideRangeThreshold    int      `json:"wide_range_threshold"`
	PortscanThreshold     int      `json:"portscan_threshold"`
	SYNThreshold          int      `json:"syn_threshold"`
	SYNAckRatio           int      `json:"syn_ack_ratio"`
	LowSlowMinSeconds     int      `json:"low_slow_min_seconds"`
	SubnetMinSources      int      `json:"subnet_min_sources"`
	IPv6SubnetMinSources  int      `json:"ipv6_subnet_min_sources"`
	WideMinSources        int      `json:"wide_min_sources"`
	AutoContainSingleIP   bool     `json:"auto_contain_single_ip"`
	AutoContainIPv4Subnet bool     `json:"auto_contain_ipv4_subnet"`
	AutoContainIPv6Subnet bool     `json:"auto_contain_ipv6_subnet"`
	MaxTrackingIPs        int      `json:"max_tracking_ips"`
	BanTTLSeconds         int      `json:"ban_ttl_seconds"`
	MaxStrikesPerSec      int      `json:"max_strikes_per_sec"`
	ServicePortsWeb       []uint16 `json:"service_ports_web"`
	ServicePortsMail      []uint16 `json:"service_ports_mail"`
	ServicePortsAdmin     []uint16 `json:"service_ports_admin"`
}

type NetworkRuntimeSettings struct {
	DefaultTTLSeconds int  `json:"default_ttl_seconds"`
	MaxTTLSeconds     int  `json:"max_ttl_seconds"`
	MaxBlockEntries   int  `json:"max_block_entries"`
	StrictASNDrop     bool `json:"strict_asn_drop"`
}

type ProtectionRuntimeSettings struct {
	MinimumObserveSeconds     int `json:"minimum_observe_seconds"`
	MinimumCanarySeconds      int `json:"minimum_canary_seconds"`
	CoreFailureThreshold      int `json:"core_failure_threshold"`
	MaxEvaluationDropPermille int `json:"max_evaluation_drop_permille"`
}

type XDRRuleOverride struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Score   int    `json:"score"`
}

type XDRFabricSettings struct {
	WorkerCount            int               `json:"worker_count"`
	QueueCapacity          int               `json:"queue_capacity"`
	MaxEvaluationsPerScan  int               `json:"max_evaluations_per_scan"`
	DedupeSeconds          int               `json:"dedupe_seconds"`
	MaxCommandBytes        int               `json:"max_command_bytes"`
	CommandPreviewBytes    int               `json:"command_preview_bytes"`
	ContainmentTTLSeconds  int               `json:"containment_ttl_seconds"`
	MalwareCorrelation     bool              `json:"malware_correlation"`
	BehaviorWarmupSamples  int               `json:"behavior_warmup_samples"`
	BehaviorZScoreMilli    int               `json:"behavior_zscore_milli"`
	BehaviorMinConnections int               `json:"behavior_min_connections"`
	BehaviorMaxProfiles    int               `json:"behavior_max_profiles"`
	BehaviorMaxPorts       int               `json:"behavior_max_ports"`
	BehaviorExecBurst      int               `json:"behavior_exec_burst"`
	ProtectedPaths         []string          `json:"protected_paths"`
	AllowProcesses         []string          `json:"allow_processes"`
	RuleOverrides          []XDRRuleOverride `json:"rule_overrides,omitempty"`
}

type RuntimeSettings struct {
	FabricVersion int `json:"fabric_version,omitempty"`
	// Migrations names every operator-visible value this document had changed on its
	// behalf during an upgrade. It is reported so an upgrade is never a silent edit of
	// somebody else's configuration.
	Migrations             []string                  `json:"migrations,omitempty"`
	Revision               uint64                    `json:"revision"`
	UpdatedAt              time.Time                 `json:"updated_at"`
	XDREnabled             bool                      `json:"xdr_enabled"`
	NetworkSensorEnabled   bool                      `json:"network_sensor_enabled"`
	BehaviorEnabled        bool                      `json:"behavior_enabled"`
	FeedsEnabled           bool                      `json:"feeds_enabled"`
	AutoFeedSync           bool                      `json:"auto_feed_sync"`
	AutoDegrade            bool                      `json:"auto_degrade"`
	ScanIntervalMillis     int                       `json:"scan_interval_millis"`
	NetworkIntervalSeconds int                       `json:"network_interval_seconds"`
	AlertScore             int                       `json:"alert_score"`
	ContainScore           int                       `json:"contain_score"`
	KillScore              int                       `json:"kill_score"`
	ManagementAllowlist    []string                  `json:"management_allowlist"`
	EnabledRuleModules     []string                  `json:"enabled_rule_modules,omitempty"`
	CustomRules            []CustomRule              `json:"custom_rules,omitempty"`
	Kinetic                KineticRuntimeSettings    `json:"kinetic,omitempty"`
	Network                NetworkRuntimeSettings    `json:"network,omitempty"`
	Protection             ProtectionRuntimeSettings `json:"protection,omitempty"`
	XDRFabric              XDRFabricSettings         `json:"xdr_fabric,omitempty"`
	// L7 is a pointer so that a document persisted before the Application
	// Defense namespace existed still produces byte-identical canonical JSON
	// and therefore still authenticates against its stored MAC. It is always
	// non-nil after the schema upgrade that runs during load.
	L7 *L7FabricSettings `json:"l7,omitempty"`
	// ThreatIntel follows the same rule for the Threat Intelligence namespace.
	ThreatIntel *ThreatIntelFabricSettings `json:"threat_intel,omitempty"`
	// Hardening follows the same rule for the Host Security namespace.
	Hardening *HardeningFabricSettings `json:"hardening,omitempty"`
	// Integrity follows the same rule for the integrity namespace.
	Integrity *IntegrityFabricSettings `json:"integrity,omitempty"`
	// Detection owns the post-exploitation rules and the stores this host actually protects. It is
	// the operator's page for turning a detection into one that fits their own machine.
	Detection *DetectionFabricSettings `json:"detection,omitempty"`
	// BootTrust follows the same rule for the boot evidence namespace.
	BootTrust *BootTrustFabricSettings `json:"boot_trust,omitempty"`
	// PolicyTrust follows the same rule for the policy trust namespace.
	PolicyTrust *PolicyTrustFabricSettings `json:"policy_trust,omitempty"`
	// Forensics follows the same rule for the forensics namespace.
	Forensics *ForensicsFabricSettings `json:"forensics,omitempty"`
	// System follows the same rule for the control plane's own bounds.
	System *SystemFabricSettings `json:"system,omitempty"`
	// Styx is the operator namespace for kernel-level per-cgroup egress
	// enforcement and flow telemetry (docs/POINT3-EGRESS-BEACON.md §8.3, §12).
	// It is a pointer for the same reason as every other namespace: a document
	// persisted before it existed must still authenticate byte-identically.
	Styx *StyxFabricSettings `json:"styx,omitempty"`
	// TitanExec is the operator namespace for the kernel exec/library gate
	// (docs/POINT1-TITAN-EXEC-GATE.md §7.1). Same pointer contract: an upgrade
	// seeds it disabled/off and changes no kernel behaviour.
	TitanExec *TitanExecFabricSettings `json:"titan_exec,omitempty"`
	// ParserCells is the operator namespace for ephemeral parser cells
	// (docs/POINT2-PARSER-CELLS.md §6). Same pointer contract: an upgrade seeds it
	// disabled and no privileged helper is contacted until an operator enables it.
	ParserCells *ParserCellsFabricSettings `json:"parser_cells,omitempty"`
	// Lockdown is the operator namespace for the anti-physical-extraction
	// Emergency Lockdown (docs/POINT5-LOCKDOWN.md §7). Same pointer contract: an
	// upgrade seeds it disabled and no LOCKDOWN_* command is issued until an
	// operator enables it.
	Lockdown *LockdownFabricSettings `json:"lockdown,omitempty"`
	// Witness is the operator namespace for the Out-of-Band Witness
	// (docs/POINT4-WITNESS.md §7). Same pointer contract: an upgrade seeds it
	// disabled/off and no checkpoint, request or export is produced until an
	// operator enables it.
	Witness *WitnessFabricSettings `json:"witness,omitempty"`
	// WebExposure is the 6.1.0 Module A namespace (read-only web posture).
	WebExposure *WebExposureFabricSettings `json:"web_exposure,omitempty"`
	// WorkerGuard is the 6.1.0 Module B namespace (worker crash correlation).
	WorkerGuard *WorkerGuardFabricSettings `json:"worker_guard,omitempty"`
	// TLSSensor is the 6.1.0 Module C namespace (AF_PACKET TLS sensor).
	TLSSensor *TLSSensorFabricSettings `json:"tls_sensor,omitempty"`
	// LPEGuard is the 6.1.0 Module D namespace (LPE kill-chain defence).
	LPEGuard *LPEGuardFabricSettings `json:"lpe_guard,omitempty"`
	// EdgeProxy is the 6.1.0 Module E namespace (memory-safe edge terminator).
	EdgeProxy *EdgeProxyFabricSettings `json:"edge_proxy,omitempty"`
	// V6AutoArmedApplied records whether GeDefense V6 safe defaults were applied
	// upon entering enforce so explicit subsequent operator overrides stay preserved.
	V6AutoArmedApplied bool `json:"v6_auto_armed_applied,omitempty"`
}

type runtimeSettingsEnvelope struct {
	Schema     string            `json:"schema"`
	Settings   RuntimeSettings   `json:"settings"`
	MAC        string            `json:"mac"`
	History    []RuntimeSettings `json:"history,omitempty"`
	HistoryMAC string            `json:"history_mac,omitempty"`
}

type SettingsStore struct {
	mu       sync.RWMutex
	path     string
	key      []byte
	crypto   *StorageCipher
	defaults RuntimeSettings
	current  RuntimeSettings
	history  []RuntimeSettings
}

func cloneRuntimeSettings(in RuntimeSettings) RuntimeSettings {
	out := in
	out.ManagementAllowlist = append(make([]string, 0, len(in.ManagementAllowlist)), in.ManagementAllowlist...)
	if in.Migrations != nil {
		out.Migrations = append([]string{}, in.Migrations...)
	}
	if in.EnabledRuleModules != nil {
		out.EnabledRuleModules = append([]string{}, in.EnabledRuleModules...)
	}
	if in.CustomRules != nil {
		out.CustomRules = append([]CustomRule{}, in.CustomRules...)
	}
	out.Kinetic.ServicePortsWeb = append([]uint16(nil), in.Kinetic.ServicePortsWeb...)
	out.Kinetic.ServicePortsMail = append([]uint16(nil), in.Kinetic.ServicePortsMail...)
	out.Kinetic.ServicePortsAdmin = append([]uint16(nil), in.Kinetic.ServicePortsAdmin...)
	out.XDRFabric.ProtectedPaths = append([]string(nil), in.XDRFabric.ProtectedPaths...)
	out.XDRFabric.AllowProcesses = append([]string(nil), in.XDRFabric.AllowProcesses...)
	out.XDRFabric.RuleOverrides = append([]XDRRuleOverride(nil), in.XDRFabric.RuleOverrides...)
	if in.L7 != nil {
		l7Fabric := cloneL7FabricSettings(*in.L7)
		out.L7 = &l7Fabric
	} else {
		out.L7 = nil
	}
	if in.ThreatIntel != nil {
		threatIntel := cloneThreatIntelFabricSettings(*in.ThreatIntel)
		out.ThreatIntel = &threatIntel
	} else {
		out.ThreatIntel = nil
	}
	if in.Hardening != nil {
		hardening := cloneHardeningFabricSettings(*in.Hardening)
		out.Hardening = &hardening
	} else {
		out.Hardening = nil
	}
	if in.Integrity != nil {
		integrity := cloneIntegrityFabricSettings(*in.Integrity)
		out.Integrity = &integrity
	} else {
		out.Integrity = nil
	}
	if in.BootTrust != nil {
		bootTrust := cloneBootTrustFabricSettings(*in.BootTrust)
		out.BootTrust = &bootTrust
	} else {
		out.BootTrust = nil
	}
	if in.PolicyTrust != nil {
		policyTrust := *in.PolicyTrust
		out.PolicyTrust = &policyTrust
	} else {
		out.PolicyTrust = nil
	}
	if in.Forensics != nil {
		forensics := cloneForensicsFabricSettings(*in.Forensics)
		out.Forensics = &forensics
	} else {
		out.Forensics = nil
	}
	if in.System != nil {
		system := *in.System
		out.System = &system
	} else {
		out.System = nil
	}
	if in.Styx != nil {
		styx := cloneStyxFabricSettings(*in.Styx)
		out.Styx = &styx
	} else {
		out.Styx = nil
	}
	if in.TitanExec != nil {
		titanExec := cloneTitanExecFabricSettings(*in.TitanExec)
		out.TitanExec = &titanExec
	} else {
		out.TitanExec = nil
	}
	if in.ParserCells != nil {
		parserCells := cloneParserCellsFabricSettings(*in.ParserCells)
		out.ParserCells = &parserCells
	} else {
		out.ParserCells = nil
	}
	if in.Lockdown != nil {
		lockdown := cloneLockdownFabricSettings(*in.Lockdown)
		out.Lockdown = &lockdown
	} else {
		out.Lockdown = nil
	}
	if in.Witness != nil {
		witness := cloneWitnessFabricSettings(*in.Witness)
		out.Witness = &witness
	} else {
		out.Witness = nil
	}
	if in.WebExposure != nil {
		webExposure := cloneWebExposureFabricSettings(*in.WebExposure)
		out.WebExposure = &webExposure
	} else {
		out.WebExposure = nil
	}
	if in.WorkerGuard != nil {
		workerGuard := cloneWorkerGuardFabricSettings(*in.WorkerGuard)
		out.WorkerGuard = &workerGuard
	} else {
		out.WorkerGuard = nil
	}
	if in.TLSSensor != nil {
		tlsSensor := cloneTLSSensorFabricSettings(*in.TLSSensor)
		out.TLSSensor = &tlsSensor
	} else {
		out.TLSSensor = nil
	}
	if in.LPEGuard != nil {
		lpeGuard := cloneLPEGuardFabricSettings(*in.LPEGuard)
		out.LPEGuard = &lpeGuard
	} else {
		out.LPEGuard = nil
	}
	if in.EdgeProxy != nil {
		edgeProxy := cloneEdgeProxyFabricSettings(*in.EdgeProxy)
		out.EdgeProxy = &edgeProxy
	} else {
		out.EdgeProxy = nil
	}
	return out
}

func cloneKineticRuntimeSettings(in KineticRuntimeSettings) KineticRuntimeSettings {
	out := in
	out.ServicePortsWeb = append([]uint16(nil), in.ServicePortsWeb...)
	out.ServicePortsMail = append([]uint16(nil), in.ServicePortsMail...)
	out.ServicePortsAdmin = append([]uint16(nil), in.ServicePortsAdmin...)
	return out
}

func cloneRuntimeSettingsHistory(in []RuntimeSettings) []RuntimeSettings {
	out := make([]RuntimeSettings, 0, len(in))
	for _, entry := range in {
		out = append(out, cloneRuntimeSettings(entry))
	}
	return out
}
