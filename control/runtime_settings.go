package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const runtimeSettingsSchema = "vgt-gedefense-runtime-settings-v1"

var supportedRuleModules = []string{
	"baseline",
	"command",
	"lineage",
	"masquerading",
	"origin",
	"threat-intel",
}

type CustomRule struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	Pattern  string `json:"pattern"`
	Score    int    `json:"score"`
}

const fabricSettingsVersion = 9
const runtimeSettingsHistoryLimit = 32

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
	FabricVersion          int                       `json:"fabric_version,omitempty"`
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
	// BootTrust follows the same rule for the boot evidence namespace.
	BootTrust *BootTrustFabricSettings `json:"boot_trust,omitempty"`
	// PolicyTrust follows the same rule for the policy trust namespace.
	PolicyTrust *PolicyTrustFabricSettings `json:"policy_trust,omitempty"`
	// Forensics follows the same rule for the forensics namespace.
	Forensics *ForensicsFabricSettings `json:"forensics,omitempty"`
	// System follows the same rule for the control plane's own bounds.
	System *SystemFabricSettings `json:"system,omitempty"`
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

func defaultRuntimeSettings(cfg Config) RuntimeSettings {
	l7Fabric := defaultL7FabricSettings(cfg.L7)
	threatIntel := defaultThreatIntelFabricSettings(cfg.Feeds, DefaultThreatFeedSources)
	hardening := defaultHardeningFabricSettings(cfg, "")
	integrity := defaultIntegrityFabricSettings(cfg)
	bootTrust := defaultBootTrustFabricSettings()
	policyTrust := defaultPolicyTrustFabricSettings()
	policyTrust.RequireSigned = cfg.Policy.RequireSigned
	forensics := defaultForensicsFabricSettings()
	system := defaultSystemFabricSettings(cfg)
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
		BootTrust:   &bootTrust,
		PolicyTrust: &policyTrust,
		Forensics:   &forensics,
		System:      &system,
	}
}

func NewSettingsStore(path, keyPath string, cfg Config) (*SettingsStore, error) {
	if path == "" {
		return nil, errors.New("runtime settings path is empty")
	}
	key, err := loadPrivateKeyFile(keyPath, 32)
	if err != nil {
		return nil, fmt.Errorf("runtime settings key: %w", err)
	}
	storage, err := NewStorageCipher(cfg.Runtime.StorageKeyFile, cfg.Node.Name)
	if err != nil {
		return nil, fmt.Errorf("runtime settings encryption: %w", err)
	}
	defaults := defaultRuntimeSettings(cfg)
	s := &SettingsStore{path: path, key: key, crypto: storage, defaults: cloneRuntimeSettings(defaults), current: defaults}
	if err := s.load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.persistLocked(s.current); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func loadPrivateKeyFile(path string, expected int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("key must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("key must not be group/world accessible")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != expected {
		return nil, fmt.Errorf("key must contain exactly %d bytes", expected)
	}
	return key, nil
}

func (s *SettingsStore) load() error {
	data, err := readBoundedPrivateFile(s.path, 4<<20)
	if err != nil {
		return err
	}
	legacy := false
	if s.crypto != nil {
		data, legacy, err = s.crypto.Decrypt(s.path, "runtime-settings", data, nil)
		if err != nil {
			return fmt.Errorf("runtime settings decrypt: %w", err)
		}
	}
	var document runtimeSettingsEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&document); err != nil {
		return fmt.Errorf("runtime settings decode: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("runtime settings contain trailing data")
	}
	if document.Schema != runtimeSettingsSchema {
		return errors.New("runtime settings schema mismatch")
	}
	// Authenticate the document exactly as it was persisted before applying any schema upgrade.
	expected, err := s.mac(document.Settings)
	if err != nil {
		return err
	}
	provided, err := hex.DecodeString(document.MAC)
	if err != nil {
		return errors.New("runtime settings authentication failed")
	}
	// Earlier writers signed a deep clone which normalized empty lists to null.
	// Verify that authenticated representation too, without changing the document.
	legacyExpected, err := s.mac(cloneRuntimeSettings(document.Settings))
	if err != nil {
		return err
	}
	validWire := hmac.Equal(expected, provided)
	validLegacy := hmac.Equal(legacyExpected, provided)
	if !validWire && !validLegacy {
		return errors.New("runtime settings authentication failed")
	}
	if document.HistoryMAC != "" {
		expectedHistory, err := s.macHistory(document.History)
		if err != nil {
			return err
		}
		providedHistory, err := hex.DecodeString(document.HistoryMAC)
		if err != nil {
			return errors.New("runtime settings history authentication failed")
		}
		legacyHistory, err := s.macHistory(cloneRuntimeSettingsHistory(document.History))
		if err != nil {
			return err
		}
		validWire := hmac.Equal(expectedHistory, providedHistory)
		validLegacy := hmac.Equal(legacyHistory, providedHistory)
		if !validWire && !validLegacy {
			return errors.New("runtime settings history authentication failed")
		}
	}
	upgraded := upgradeRuntimeSettings(&document.Settings, s.defaults)
	for i := range document.History {
		upgradeRuntimeSettings(&document.History[i], s.defaults)
	}
	if err := validateRuntimeSettings(&document.Settings); err != nil {
		return fmt.Errorf("runtime settings validation: %w", err)
	}
	s.history = cloneRuntimeSettingsHistory(document.History)
	if len(s.history) > runtimeSettingsHistoryLimit {
		s.history = append([]RuntimeSettings(nil), s.history[len(s.history)-runtimeSettingsHistoryLimit:]...)
	}
	s.current = cloneRuntimeSettings(document.Settings)
	if upgraded || (legacy && s.crypto != nil) {
		if err := s.persistLocked(s.current); err != nil {
			return fmt.Errorf("runtime settings migration: %w", err)
		}
	}
	return nil
}

func cloneRuntimeSettings(in RuntimeSettings) RuntimeSettings {
	out := in
	out.ManagementAllowlist = append(make([]string, 0, len(in.ManagementAllowlist)), in.ManagementAllowlist...)
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
	return out
}

// upgradeRuntimeSettings migrates an authenticated document to the current
// Fabric schema. Namespaces that already existed keep their operator values;
// only genuinely new namespaces are seeded from the bootstrap configuration.
func upgradeRuntimeSettings(settings *RuntimeSettings, defaults RuntimeSettings) bool {
	if settings == nil || settings.FabricVersion >= fabricSettingsVersion {
		return false
	}
	if settings.FabricVersion < 2 {
		// v1 carried no per-module namespaces at all.
		settings.Kinetic = cloneKineticRuntimeSettings(defaults.Kinetic)
		settings.Network = defaults.Network
		settings.Protection = defaults.Protection
		settings.XDRFabric = cloneXDRFabricSettings(defaults.XDRFabric)
	}
	if settings.L7 == nil {
		l7Fabric := cloneL7FabricSettings(l7Defaults(defaults))
		settings.L7 = &l7Fabric
	}
	if settings.ThreatIntel == nil {
		threatIntel := cloneThreatIntelFabricSettings(threatIntelDefaults(defaults))
		// The document's existing operator intent wins over the bootstrap seed.
		threatIntel.Enabled = settings.FeedsEnabled
		threatIntel.AutoSync = settings.AutoFeedSync
		settings.ThreatIntel = &threatIntel
	}
	if settings.Hardening == nil {
		hardening := cloneHardeningFabricSettings(hardeningDefaults(defaults))
		settings.Hardening = &hardening
	}
	if settings.Integrity == nil {
		integrity := cloneIntegrityFabricSettings(integrityDefaults(defaults))
		settings.Integrity = &integrity
	}
	if settings.BootTrust == nil {
		bootTrust := cloneBootTrustFabricSettings(bootTrustDefaults(defaults))
		settings.BootTrust = &bootTrust
	}
	if settings.PolicyTrust == nil {
		policyTrust := policyTrustDefaults(defaults)
		settings.PolicyTrust = &policyTrust
	}
	if settings.Forensics == nil {
		forensics := forensicsDefaults(defaults)
		settings.Forensics = &forensics
	}
	if settings.System == nil {
		system := systemDefaults(defaults)
		settings.System = &system
	}
	settings.FabricVersion = fabricSettingsVersion
	return true
}

func systemDefaults(defaults RuntimeSettings) SystemFabricSettings {
	if defaults.System != nil {
		return *defaults.System
	}
	return defaultSystemFabricSettings(Config{})
}

func forensicsDefaults(defaults RuntimeSettings) ForensicsFabricSettings {
	if defaults.Forensics != nil {
		return *defaults.Forensics
	}
	return defaultForensicsFabricSettings()
}

func bootTrustDefaults(defaults RuntimeSettings) BootTrustFabricSettings {
	if defaults.BootTrust != nil {
		return *defaults.BootTrust
	}
	return defaultBootTrustFabricSettings()
}

func policyTrustDefaults(defaults RuntimeSettings) PolicyTrustFabricSettings {
	if defaults.PolicyTrust != nil {
		return *defaults.PolicyTrust
	}
	return defaultPolicyTrustFabricSettings()
}

func integrityDefaults(defaults RuntimeSettings) IntegrityFabricSettings {
	if defaults.Integrity != nil {
		return *defaults.Integrity
	}
	return defaultIntegrityFabricSettings(Config{})
}

func hardeningDefaults(defaults RuntimeSettings) HardeningFabricSettings {
	if defaults.Hardening != nil {
		return *defaults.Hardening
	}
	return defaultHardeningFabricSettings(Config{}, "")
}

func threatIntelDefaults(defaults RuntimeSettings) ThreatIntelFabricSettings {
	if defaults.ThreatIntel != nil {
		return *defaults.ThreatIntel
	}
	return defaultThreatIntelFabricSettings(FeedConfig{}, DefaultThreatFeedSources)
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

func l7Defaults(defaults RuntimeSettings) L7FabricSettings {
	if defaults.L7 != nil {
		return *defaults.L7
	}
	return L7FabricSettings{TLSUnknownFingerprint: "allow", TLSUnknownFingerprintScore: 35, Rules: []L7RuleOverride{}}
}

func cloneKineticRuntimeSettings(in KineticRuntimeSettings) KineticRuntimeSettings {
	out := in
	out.ServicePortsWeb = append([]uint16(nil), in.ServicePortsWeb...)
	out.ServicePortsMail = append([]uint16(nil), in.ServicePortsMail...)
	out.ServicePortsAdmin = append([]uint16(nil), in.ServicePortsAdmin...)
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

func (s *SettingsStore) mac(settings RuntimeSettings) ([]byte, error) {
	// Preserve nil versus empty collections in the authenticated wire representation.
	canonical := settings
	canonical.UpdatedAt = canonical.UpdatedAt.UTC()
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(runtimeSettingsSchema))
	mac.Write([]byte{0})
	mac.Write(data)
	return mac.Sum(nil), nil
}

func (s *SettingsStore) macHistory(history []RuntimeSettings) ([]byte, error) {
	canonical := make([]RuntimeSettings, 0, len(history))
	for _, entry := range history {
		copy := entry
		copy.UpdatedAt = copy.UpdatedAt.UTC()
		canonical = append(canonical, copy)
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(runtimeSettingsSchema))
	mac.Write([]byte{0})
	mac.Write([]byte("history"))
	mac.Write([]byte{0})
	mac.Write(data)
	return mac.Sum(nil), nil
}

func (s *SettingsStore) persistLocked(settings RuntimeSettings) error {
	if err := validateRuntimeSettings(&settings); err != nil {
		return err
	}
	mac, err := s.mac(settings)
	if err != nil {
		return err
	}
	historyMAC, err := s.macHistory(s.history)
	if err != nil {
		return err
	}
	document := runtimeSettingsEnvelope{Schema: runtimeSettingsSchema, Settings: settings, MAC: hex.EncodeToString(mac), History: cloneRuntimeSettingsHistory(s.history), HistoryMAC: hex.EncodeToString(historyMAC)}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if s.crypto != nil {
		data, err = s.crypto.Encrypt(s.path, "runtime-settings", 0, data)
		if err != nil {
			return err
		}
		data = append(data, '\n')
	}
	if err := atomicWriteFile(s.path, data, 0o600); err != nil {
		return err
	}
	s.current = cloneRuntimeSettings(settings)
	return nil
}

func cloneRuntimeSettingsHistory(in []RuntimeSettings) []RuntimeSettings {
	out := make([]RuntimeSettings, 0, len(in))
	for _, entry := range in {
		out = append(out, cloneRuntimeSettings(entry))
	}
	return out
}

func (s *SettingsStore) History() []RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRuntimeSettingsHistory(s.history)
}

func (s *SettingsStore) Revision(revision uint64) (RuntimeSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current.Revision == revision {
		return cloneRuntimeSettings(s.current), nil
	}
	for i := len(s.history) - 1; i >= 0; i-- {
		if s.history[i].Revision == revision {
			return cloneRuntimeSettings(s.history[i]), nil
		}
	}
	return RuntimeSettings{}, os.ErrNotExist
}

func (s *SettingsStore) Get() RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRuntimeSettings(s.current)
}

func (s *SettingsStore) Update(next RuntimeSettings) (RuntimeSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next.FabricVersion = fabricSettingsVersion
	if err := validateRuntimeSettings(&next); err != nil {
		return cloneRuntimeSettings(s.current), err
	}
	if effectiveForensicsSettings(next).Quarantine.RestoreFileMode & ^effectiveForensicsSettings(s.current).Quarantine.RestoreFileMode != 0 {
		return cloneRuntimeSettings(s.current), errors.New("quarantine restore permissions must not widen")
	}
	next.Revision = s.current.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	oldHistory := cloneRuntimeSettingsHistory(s.history)
	s.history = append(s.history, cloneRuntimeSettings(s.current))
	if len(s.history) > runtimeSettingsHistoryLimit {
		s.history = append([]RuntimeSettings(nil), s.history[len(s.history)-runtimeSettingsHistoryLimit:]...)
	}
	if err := s.persistLocked(next); err != nil {
		s.history = oldHistory
		return cloneRuntimeSettings(s.current), err
	}
	return cloneRuntimeSettings(s.current), nil
}

func (s *SettingsStore) Rollback(revision uint64) (RuntimeSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var target *RuntimeSettings
	for i := len(s.history) - 1; i >= 0; i-- {
		if s.history[i].Revision == revision {
			copy := cloneRuntimeSettings(s.history[i])
			target = &copy
			break
		}
	}
	if target == nil {
		return cloneRuntimeSettings(s.current), os.ErrNotExist
	}
	next := cloneRuntimeSettings(*target)
	if effectiveForensicsSettings(next).Quarantine.RestoreFileMode & ^effectiveForensicsSettings(s.current).Quarantine.RestoreFileMode != 0 {
		return cloneRuntimeSettings(s.current), errors.New("quarantine restore permissions must not widen")
	}
	next.FabricVersion = fabricSettingsVersion
	next.Revision = s.current.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	if err := validateRuntimeSettings(&next); err != nil {
		return cloneRuntimeSettings(s.current), err
	}
	oldHistory := cloneRuntimeSettingsHistory(s.history)
	s.history = append(s.history, cloneRuntimeSettings(s.current))
	if len(s.history) > runtimeSettingsHistoryLimit {
		s.history = append([]RuntimeSettings(nil), s.history[len(s.history)-runtimeSettingsHistoryLimit:]...)
	}
	if err := s.persistLocked(next); err != nil {
		s.history = oldHistory
		return cloneRuntimeSettings(s.current), err
	}
	return cloneRuntimeSettings(s.current), nil
}

func (s *SettingsStore) AddAllowlist(target string) (RuntimeSettings, string, error) {
	normalized, err := normalizeTarget(target)
	if err != nil {
		return s.Get(), "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneRuntimeSettings(s.current)
	for _, value := range next.ManagementAllowlist {
		if value == normalized {
			return next, normalized, nil
		}
	}
	next.ManagementAllowlist = append(next.ManagementAllowlist, normalized)
	next.Revision++
	next.UpdatedAt = time.Now().UTC()
	if err := s.persistLocked(next); err != nil {
		return cloneRuntimeSettings(s.current), "", err
	}
	return cloneRuntimeSettings(s.current), normalized, nil
}

func (s *SettingsStore) RemoveAllowlist(target string) (RuntimeSettings, string, error) {
	normalized, err := normalizeTarget(target)
	if err != nil {
		return s.Get(), "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.current.ManagementAllowlist) <= 1 {
		return cloneRuntimeSettings(s.current), "", errors.New("the final management allowlist entry cannot be removed")
	}
	next := cloneRuntimeSettings(s.current)
	found := false
	out := next.ManagementAllowlist[:0]
	for _, value := range next.ManagementAllowlist {
		if value == normalized {
			found = true
			continue
		}
		out = append(out, value)
	}
	if !found {
		return cloneRuntimeSettings(s.current), "", os.ErrNotExist
	}
	next.ManagementAllowlist = append([]string(nil), out...)
	next.Revision++
	next.UpdatedAt = time.Now().UTC()
	if err := s.persistLocked(next); err != nil {
		return cloneRuntimeSettings(s.current), "", err
	}
	return cloneRuntimeSettings(s.current), normalized, nil
}
