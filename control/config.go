package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Node      NodeConfig
	Dashboard DashboardConfig
	Core      CoreConfig
	Defense   DefenseConfig
	Policy    PolicyConfig
	Feeds     FeedConfig
	XDR       XDRConfig
	L7        L7Config
	Release   ReleaseConfig
	Runtime   RuntimeConfig
	Cells     CellsConfig
}

type NodeConfig struct {
	Name      string
	Interface string
	Mode      string
}

type DashboardConfig struct {
	Listen             string
	AllowRemote        bool
	AllowedHosts       []string
	TokenFile          string
	TLSCertFile        string
	TLSKeyFile         string
	RateLimitPerMinute int
	RateLimitBurst     int
	MaxSSEClients      int
}

type CoreConfig struct {
	Socket               string
	AuthKeyFile          string
	RequestTimeoutMillis int
}

type DefenseConfig struct {
	Allowlist         []string
	Enforcement       string
	DefaultTTLSeconds int
	MaxTTLSeconds     int
	MaxBlockEntries   int
	StrictASNDrop     bool
	DPIEnabled        bool
}

type PolicyConfig struct {
	StateFile      string
	SigningKeyFile string
	PublicKeyFile  string
	StorageKeyFile string
	RequireSigned  bool
}

type L7Config struct {
	Enabled                      bool
	Mode                         string
	Socket                       string
	SocketGroup                  string
	RequestTimeoutMillis         int
	MaxConcurrent                int
	MaxEnvelopeBytes             int
	MaxBodyBytes                 int
	MaxURIBytes                  int
	MaxHeaderBytes               int
	MaxHeaders                   int
	MaxValueBytes                int
	MaxInspectionBytes           int
	MaxDecodedValues             int
	MaxDecodeDepth               int
	MaxJSONDepth                 int
	MaxFormFields                int
	MaxMultipartParts            int
	MaxUploadBytes               int
	AlertScore                   int
	BlockScore                   int
	ClientRatePerMinute          int
	ClientRateBurst              int
	SensitiveRatePerMinute       int
	SensitiveRateBurst           int
	SensitiveGlobalRatePerMinute int
	SensitiveGlobalRateBurst     int
	MaxTrackedClients            int
	SensitivePaths               []string
	RequirePeerCredentials       bool
	AllowedPeerUIDs              []uint32
	AllowedPeerGIDs              []uint32
	InlineEnabled                bool
	InlineSocket                 string
	InlineUpstream               string
	InlineMaxResponseBytes       int
}

type XDRConfig struct {
	Enabled                  bool
	Mode                     string
	ScanIntervalMillis       int
	NetworkIntervalSeconds   int
	IntegrityIntervalSeconds int
	AlertScore               int
	ContainScore             int
	KillScore                int
	MaxCommandBytes          int
	CommandPreviewBytes      int
	DedupeSeconds            int
	MaxIncidentLogBytes      int64
	IncidentLog              string
	LogKeyFile               string
	BaselineFile             string
	ProtectedPaths           []string
	AllowProcesses           []string
	WorkerCount              int
	QueueCapacity            int
	MaxEvaluationsPerScan    int
	BehaviorEnabled          bool
	BehaviorWarmupSamples    int
	BehaviorZScoreMilli      int
	BehaviorMinConnections   int
	BehaviorMaxProfiles      int
	BehaviorMaxPorts         int
	BehaviorProfileFile      string
	StorageKeyFile           string
}

type ReleaseConfig struct {
	Channel                   string
	MinimumObserveSeconds     int
	MinimumCanarySeconds      int
	CoreFailureThreshold      int
	MaxEvaluationDropPermille int
	EmergencyStopFile         string
	AutoDegrade               bool
}

type RuntimeConfig struct {
	SettingsFile   string
	KeyFile        string
	StorageKeyFile string
}

type CellsConfig struct {
	Enabled              bool
	Socket               string
	AuthKeyFile          string
	RequestTimeoutMillis int
}

type FeedConfig struct {
	Enabled          bool
	AutoApply        bool
	RefreshMinutes   int
	MaxDownloadBytes int64
	MaxEntries       int
	Sources          []string
}

func defaultConfig() Config {
	return Config{
		Node: NodeConfig{Name: "VGT-Beta-Node", Interface: "auto", Mode: "standalone"},
		Dashboard: DashboardConfig{
			Listen: "127.0.0.1:9843", TokenFile: "/var/lib/vgt/gedefense/dashboard.token",
			AllowedHosts:       []string{"127.0.0.1", "localhost", "[::1]"},
			RateLimitPerMinute: 240, RateLimitBurst: 40, MaxSSEClients: 16,
		},
		Core: CoreConfig{
			Socket: "/run/vgt-gedefense/core.sock", AuthKeyFile: "/etc/vgt/gedefense/secrets/core-ipc.key",
			RequestTimeoutMillis: 1500,
		},
		Defense: DefenseConfig{
			Allowlist: nil, Enforcement: "observe", DefaultTTLSeconds: 3600, MaxTTLSeconds: 604800,
			MaxBlockEntries: 250000, StrictASNDrop: false, DPIEnabled: false,
		},
		Policy: PolicyConfig{
			StateFile: "/var/lib/vgt/gedefense/policy.json", SigningKeyFile: "/var/lib/vgt/gedefense/policy.ed25519",
			PublicKeyFile: "/var/lib/vgt/gedefense/policy.ed25519.pub", StorageKeyFile: "/etc/vgt/gedefense/secrets/storage-master.key", RequireSigned: true,
		},
		L7: L7Config{
			Enabled: false, Mode: "observe", Socket: "/run/vgt-gedefense-l7/inspect.sock", SocketGroup: "", RequestTimeoutMillis: 750,
			MaxConcurrent: 16, MaxEnvelopeBytes: 3 << 20, MaxBodyBytes: 2 << 20, MaxURIBytes: 16 << 10,
			MaxHeaderBytes: 64 << 10, MaxHeaders: 128, MaxValueBytes: 16 << 10, MaxInspectionBytes: 4 << 20, MaxDecodedValues: 4096,
			MaxDecodeDepth: 4, MaxJSONDepth: 32, MaxFormFields: 512, MaxMultipartParts: 64, MaxUploadBytes: 2 << 20,
			AlertScore: 40, BlockScore: 90, ClientRatePerMinute: 600, ClientRateBurst: 100,
			SensitiveRatePerMinute: 30, SensitiveRateBurst: 10, SensitiveGlobalRatePerMinute: 300, SensitiveGlobalRateBurst: 50, MaxTrackedClients: 65536,
			SensitivePaths: []string{"/wp-login.php", "/xmlrpc.php", "/login", "/signin", "/api/login"},
			InlineEnabled:  false, InlineSocket: "/run/vgt-gedefense-l7/edge.sock", InlineUpstream: "http://127.0.0.1:8080",
			InlineMaxResponseBytes: 64 << 10,
		},
		XDR: XDRConfig{
			Enabled: true, Mode: "observe", ScanIntervalMillis: 750, NetworkIntervalSeconds: 3,
			IntegrityIntervalSeconds: 3, AlertScore: 40, ContainScore: 80, KillScore: 120,
			MaxCommandBytes: 8192, CommandPreviewBytes: 320, DedupeSeconds: 300,
			MaxIncidentLogBytes: 64 << 20,
			IncidentLog:         "/var/lib/vgt/gedefense/incidents.jsonl",
			LogKeyFile:          "/var/lib/vgt/gedefense/xdr-log.key",
			BaselineFile:        "/etc/vgt/gedefense/xdr-baseline.json",
			ProtectedPaths:      []string{"/opt/vgt/gedefense/current/bin/gedefense-control", "/opt/vgt/gedefense/current/libexec/gedefense-core", "/opt/vgt/gedefense/current/lib/gedefense/gedefense-ebpf"},
			WorkerCount:         4, QueueCapacity: 2048, MaxEvaluationsPerScan: 4096,
			BehaviorEnabled: true, BehaviorWarmupSamples: 24, BehaviorZScoreMilli: 3500,
			BehaviorMinConnections: 8, BehaviorMaxProfiles: 4096, BehaviorMaxPorts: 256, BehaviorProfileFile: "/var/lib/vgt/gedefense/behavior-profiles.json",
			StorageKeyFile: "/etc/vgt/gedefense/secrets/storage-master.key",
		},
		Runtime: RuntimeConfig{SettingsFile: "/var/lib/vgt/gedefense/runtime-settings.json", KeyFile: "/var/lib/vgt/gedefense/runtime-settings.key", StorageKeyFile: "/etc/vgt/gedefense/secrets/storage-master.key"},
		Cells: CellsConfig{
			Enabled: false, Socket: "/run/gaia-cells/control.sock",
			AuthKeyFile:          "/etc/vgt/gedefense/secrets/gaia-cells.key",
			RequestTimeoutMillis: 1500,
		},
		Release: ReleaseConfig{
			Channel: "beta", MinimumObserveSeconds: 300, MinimumCanarySeconds: 900,
			CoreFailureThreshold: 3, MaxEvaluationDropPermille: 5,
			EmergencyStopFile: "/var/lib/vgt/gedefense/EMERGENCY_STOP", AutoDegrade: true,
		},
		Feeds: FeedConfig{
			Enabled: false, AutoApply: false, RefreshMinutes: 60,
			MaxDownloadBytes: 8 << 20, MaxEntries: 100000,
			Sources: []string{
				"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
				"https://www.spamhaus.org/drop/drop.txt",
			},
		},
	}
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	section := ""
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			switch section {
			case "node", "dashboard", "core", "defense", "policy", "feeds", "xdr", "l7", "release", "runtime", "cells":
			default:
				return cfg, fmt.Errorf("line %d: unknown section %q", lineNo, section)
			}
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return cfg, fmt.Errorf("line %d: expected section key = value", lineNo)
		}
		key, raw = strings.TrimSpace(key), strings.TrimSpace(raw)
		if err := assignConfig(&cfg, section, key, raw); err != nil {
			return cfg, fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, err
	}
	if cfg.Defense.DPIEnabled {
		cfg.L7.Enabled = true
	}
	cfg.Defense.DPIEnabled = cfg.L7.Enabled
	if err := validateConfig(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func stripComment(line string) string {
	quoted, escaped := false, false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quoted {
			escaped = true
			continue
		}
		if r == '"' {
			quoted = !quoted
			continue
		}
		if r == '#' && !quoted {
			return line[:i]
		}
	}
	return line
}

func parseString(raw string) (string, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", errors.New("string values must be double quoted")
	}
	v, err := strconv.Unquote(raw)
	if err != nil {
		return "", fmt.Errorf("invalid string: %w", err)
	}
	if strings.ContainsRune(v, '\x00') {
		return "", errors.New("NUL is not allowed")
	}
	return v, nil
}

func parseBool(raw string) (bool, error) {
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("expected true or false, got %q", raw)
	}
}

func parseInt(raw string, min, max int) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("integer must be between %d and %d", min, max)
	}
	return n, nil
}

func assignConfig(cfg *Config, section, key, raw string) error {
	str := func() (string, error) { return parseString(raw) }
	switch section + "." + key {
	case "node.name":
		v, e := str()
		cfg.Node.Name = v
		return e
	case "node.interface":
		v, e := str()
		cfg.Node.Interface = v
		return e
	case "node.mode":
		v, e := str()
		cfg.Node.Mode = v
		return e
	case "dashboard.listen":
		v, e := str()
		cfg.Dashboard.Listen = v
		return e
	case "dashboard.allow_remote":
		v, e := parseBool(raw)
		cfg.Dashboard.AllowRemote = v
		return e
	case "dashboard.allowed_hosts":
		v, e := str()
		if e == nil {
			cfg.Dashboard.AllowedHosts = splitCSV(v)
		}
		return e
	case "dashboard.token_file":
		v, e := str()
		cfg.Dashboard.TokenFile = v
		return e
	case "dashboard.tls_cert_file":
		v, e := str()
		cfg.Dashboard.TLSCertFile = v
		return e
	case "dashboard.tls_key_file":
		v, e := str()
		cfg.Dashboard.TLSKeyFile = v
		return e
	case "dashboard.rate_limit_per_minute":
		v, e := parseInt(raw, 30, 100000)
		cfg.Dashboard.RateLimitPerMinute = v
		return e
	case "dashboard.rate_limit_burst":
		v, e := parseInt(raw, 1, 10000)
		cfg.Dashboard.RateLimitBurst = v
		return e
	case "dashboard.max_sse_clients":
		v, e := parseInt(raw, 1, 1024)
		cfg.Dashboard.MaxSSEClients = v
		return e
	case "core.socket":
		v, e := str()
		cfg.Core.Socket = v
		return e
	case "core.auth_key_file":
		v, e := str()
		cfg.Core.AuthKeyFile = v
		return e
	case "core.request_timeout_millis":
		v, e := parseInt(raw, 100, 10000)
		cfg.Core.RequestTimeoutMillis = v
		return e
	case "defense.allowlist":
		v, e := str()
		if e == nil {
			cfg.Defense.Allowlist = splitCSV(v)
		}
		return e
	case "defense.enforcement":
		v, e := str()
		cfg.Defense.Enforcement = v
		return e
	case "defense.default_ttl_seconds":
		v, e := parseInt(raw, 60, 604800)
		cfg.Defense.DefaultTTLSeconds = v
		return e
	case "defense.max_ttl_seconds":
		v, e := parseInt(raw, 60, 2592000)
		cfg.Defense.MaxTTLSeconds = v
		return e
	case "defense.max_block_entries":
		v, e := parseInt(raw, 1, 1000000)
		cfg.Defense.MaxBlockEntries = v
		return e
	case "defense.strict_asn_drop":
		v, e := parseBool(raw)
		cfg.Defense.StrictASNDrop = v
		return e
	case "defense.dpi_enabled":
		v, e := parseBool(raw)
		cfg.Defense.DPIEnabled = v
		return e
	case "policy.state_file":
		v, e := str()
		cfg.Policy.StateFile = v
		return e
	case "policy.signing_key_file":
		v, e := str()
		cfg.Policy.SigningKeyFile = v
		return e
	case "policy.public_key_file":
		v, e := str()
		cfg.Policy.PublicKeyFile = v
		return e
	case "policy.storage_key_file":
		v, e := str()
		cfg.Policy.StorageKeyFile = v
		return e
	case "policy.require_signed":
		v, e := parseBool(raw)
		cfg.Policy.RequireSigned = v
		return e
	case "l7.enabled":
		v, e := parseBool(raw)
		cfg.L7.Enabled = v
		return e
	case "l7.mode":
		v, e := str()
		cfg.L7.Mode = v
		return e
	case "l7.socket":
		v, e := str()
		cfg.L7.Socket = v
		return e
	case "l7.socket_group":
		v, e := str()
		cfg.L7.SocketGroup = v
		return e
	case "l7.request_timeout_millis":
		v, e := parseInt(raw, 50, 10000)
		cfg.L7.RequestTimeoutMillis = v
		return e
	case "l7.max_concurrent":
		v, e := parseInt(raw, 1, 512)
		cfg.L7.MaxConcurrent = v
		return e
	case "l7.max_envelope_bytes":
		v, e := parseInt(raw, 65536, 32<<20)
		cfg.L7.MaxEnvelopeBytes = v
		return e
	case "l7.max_body_bytes":
		v, e := parseInt(raw, 1024, 16<<20)
		cfg.L7.MaxBodyBytes = v
		return e
	case "l7.max_uri_bytes":
		v, e := parseInt(raw, 1024, 1<<20)
		cfg.L7.MaxURIBytes = v
		return e
	case "l7.max_header_bytes":
		v, e := parseInt(raw, 4096, 1<<20)
		cfg.L7.MaxHeaderBytes = v
		return e
	case "l7.max_headers":
		v, e := parseInt(raw, 8, 1024)
		cfg.L7.MaxHeaders = v
		return e
	case "l7.max_value_bytes":
		v, e := parseInt(raw, 1024, 1<<20)
		cfg.L7.MaxValueBytes = v
		return e
	case "l7.max_inspection_bytes":
		v, e := parseInt(raw, 64<<10, 64<<20)
		cfg.L7.MaxInspectionBytes = v
		return e
	case "l7.max_decoded_values":
		v, e := parseInt(raw, 16, 8192)
		cfg.L7.MaxDecodedValues = v
		return e
	case "l7.max_decode_depth":
		v, e := parseInt(raw, 1, 8)
		cfg.L7.MaxDecodeDepth = v
		return e
	case "l7.max_json_depth":
		v, e := parseInt(raw, 4, 128)
		cfg.L7.MaxJSONDepth = v
		return e
	case "l7.max_form_fields":
		v, e := parseInt(raw, 16, 8192)
		cfg.L7.MaxFormFields = v
		return e
	case "l7.max_multipart_parts":
		v, e := parseInt(raw, 1, 1024)
		cfg.L7.MaxMultipartParts = v
		return e
	case "l7.max_upload_bytes":
		v, e := parseInt(raw, 1024, 16<<20)
		cfg.L7.MaxUploadBytes = v
		return e
	case "l7.alert_score":
		v, e := parseInt(raw, 1, 249)
		cfg.L7.AlertScore = v
		return e
	case "l7.block_score":
		v, e := parseInt(raw, 2, 250)
		cfg.L7.BlockScore = v
		return e
	case "l7.client_rate_per_minute":
		v, e := parseInt(raw, 1, 1000000)
		cfg.L7.ClientRatePerMinute = v
		return e
	case "l7.client_rate_burst":
		v, e := parseInt(raw, 1, 100000)
		cfg.L7.ClientRateBurst = v
		return e
	case "l7.sensitive_rate_per_minute":
		v, e := parseInt(raw, 1, 100000)
		cfg.L7.SensitiveRatePerMinute = v
		return e
	case "l7.sensitive_rate_burst":
		v, e := parseInt(raw, 1, 10000)
		cfg.L7.SensitiveRateBurst = v
		return e
	case "l7.sensitive_global_rate_per_minute":
		v, e := parseInt(raw, 1, 1000000)
		cfg.L7.SensitiveGlobalRatePerMinute = v
		return e
	case "l7.sensitive_global_rate_burst":
		v, e := parseInt(raw, 1, 100000)
		cfg.L7.SensitiveGlobalRateBurst = v
		return e
	case "l7.max_tracked_clients":
		v, e := parseInt(raw, 1024, 1000000)
		cfg.L7.MaxTrackedClients = v
		return e
	case "l7.sensitive_paths":
		v, e := str()
		if e == nil {
			cfg.L7.SensitivePaths = splitCSV(v)
		}
		return e
	case "l7.require_peer_credentials":
		v, e := parseBool(raw)
		cfg.L7.RequirePeerCredentials = v
		return e
	case "l7.allowed_peer_uids":
		v, e := str()
		if e != nil {
			return e
		}
		ids, e := parseUint32CSV(v)
		cfg.L7.AllowedPeerUIDs = ids
		return e
	case "l7.allowed_peer_gids":
		v, e := str()
		if e != nil {
			return e
		}
		ids, e := parseUint32CSV(v)
		cfg.L7.AllowedPeerGIDs = ids
		return e
	case "l7.inline_enabled":
		v, e := parseBool(raw)
		cfg.L7.InlineEnabled = v
		return e
	case "l7.inline_socket":
		v, e := str()
		cfg.L7.InlineSocket = v
		return e
	case "l7.inline_upstream":
		v, e := str()
		cfg.L7.InlineUpstream = v
		return e
	case "l7.inline_max_response_bytes":
		v, e := parseInt(raw, 4096, 1<<20)
		cfg.L7.InlineMaxResponseBytes = v
		return e
	case "xdr.enabled":
		v, e := parseBool(raw)
		cfg.XDR.Enabled = v
		return e
	case "xdr.mode":
		v, e := str()
		cfg.XDR.Mode = v
		return e
	case "xdr.scan_interval_millis":
		v, e := parseInt(raw, 100, 60000)
		cfg.XDR.ScanIntervalMillis = v
		return e
	case "xdr.network_interval_seconds":
		v, e := parseInt(raw, 1, 300)
		cfg.XDR.NetworkIntervalSeconds = v
		return e
	case "xdr.integrity_interval_seconds":
		v, e := parseInt(raw, 1, 300)
		cfg.XDR.IntegrityIntervalSeconds = v
		return e
	case "xdr.alert_score":
		v, e := parseInt(raw, 1, 250)
		cfg.XDR.AlertScore = v
		return e
	case "xdr.contain_score":
		v, e := parseInt(raw, 1, 250)
		cfg.XDR.ContainScore = v
		return e
	case "xdr.kill_score":
		v, e := parseInt(raw, 1, 250)
		cfg.XDR.KillScore = v
		return e
	case "xdr.max_command_bytes":
		v, e := parseInt(raw, 256, 65536)
		cfg.XDR.MaxCommandBytes = v
		return e
	case "xdr.command_preview_bytes":
		v, e := parseInt(raw, 64, 2048)
		cfg.XDR.CommandPreviewBytes = v
		return e
	case "xdr.dedupe_seconds":
		v, e := parseInt(raw, 10, 86400)
		cfg.XDR.DedupeSeconds = v
		return e
	case "xdr.max_incident_log_bytes":
		v, e := parseInt(raw, 1<<20, 1<<30)
		cfg.XDR.MaxIncidentLogBytes = int64(v)
		return e
	case "xdr.incident_log":
		v, e := str()
		cfg.XDR.IncidentLog = v
		return e
	case "xdr.log_key_file":
		v, e := str()
		cfg.XDR.LogKeyFile = v
		return e
	case "xdr.baseline_file":
		v, e := str()
		cfg.XDR.BaselineFile = v
		return e
	case "xdr.protected_paths":
		v, e := str()
		if e == nil {
			cfg.XDR.ProtectedPaths = splitCSV(v)
		}
		return e
	case "xdr.allow_processes":
		v, e := str()
		if e == nil {
			cfg.XDR.AllowProcesses = splitCSV(v)
		}
		return e
	case "xdr.worker_count":
		v, e := parseInt(raw, 1, 64)
		cfg.XDR.WorkerCount = v
		return e
	case "xdr.queue_capacity":
		v, e := parseInt(raw, 64, 65536)
		cfg.XDR.QueueCapacity = v
		return e
	case "xdr.max_evaluations_per_scan":
		v, e := parseInt(raw, 64, 100000)
		cfg.XDR.MaxEvaluationsPerScan = v
		return e
	case "xdr.behavior_enabled":
		v, e := parseBool(raw)
		cfg.XDR.BehaviorEnabled = v
		return e
	case "xdr.behavior_warmup_samples":
		v, e := parseInt(raw, 5, 10000)
		cfg.XDR.BehaviorWarmupSamples = v
		return e
	case "xdr.behavior_zscore_milli":
		v, e := parseInt(raw, 1500, 10000)
		cfg.XDR.BehaviorZScoreMilli = v
		return e
	case "xdr.behavior_min_connections":
		v, e := parseInt(raw, 2, 100000)
		cfg.XDR.BehaviorMinConnections = v
		return e
	case "xdr.behavior_max_profiles":
		v, e := parseInt(raw, 64, 65536)
		cfg.XDR.BehaviorMaxProfiles = v
		return e
	case "xdr.behavior_max_ports_per_profile":
		v, e := parseInt(raw, 16, 65536)
		cfg.XDR.BehaviorMaxPorts = v
		return e
	case "xdr.behavior_profile_file":
		v, e := str()
		cfg.XDR.BehaviorProfileFile = v
		return e
	case "xdr.storage_key_file":
		v, e := str()
		cfg.XDR.StorageKeyFile = v
		return e

	case "release.channel":
		v, e := str()
		cfg.Release.Channel = v
		return e
	case "release.minimum_observe_seconds":
		v, e := parseInt(raw, 0, 86400)
		cfg.Release.MinimumObserveSeconds = v
		return e
	case "release.minimum_canary_seconds":
		v, e := parseInt(raw, 0, 604800)
		cfg.Release.MinimumCanarySeconds = v
		return e
	case "release.core_failure_threshold":
		v, e := parseInt(raw, 1, 100)
		cfg.Release.CoreFailureThreshold = v
		return e
	case "release.max_evaluation_drop_permille":
		v, e := parseInt(raw, 0, 1000)
		cfg.Release.MaxEvaluationDropPermille = v
		return e
	case "release.emergency_stop_file":
		v, e := str()
		cfg.Release.EmergencyStopFile = v
		return e
	case "release.auto_degrade":
		v, e := parseBool(raw)
		cfg.Release.AutoDegrade = v
		return e
	case "runtime.settings_file":
		v, e := str()
		cfg.Runtime.SettingsFile = v
		return e
	case "runtime.key_file":
		v, e := str()
		cfg.Runtime.KeyFile = v
		return e
	case "runtime.storage_key_file":
		v, e := str()
		cfg.Runtime.StorageKeyFile = v
		return e
	case "cells.enabled":
		v, e := parseBool(raw)
		cfg.Cells.Enabled = v
		return e
	case "cells.socket":
		v, e := str()
		cfg.Cells.Socket = v
		return e
	case "cells.auth_key_file":
		v, e := str()
		cfg.Cells.AuthKeyFile = v
		return e
	case "cells.request_timeout_millis":
		v, e := parseInt(raw, 100, 10000)
		cfg.Cells.RequestTimeoutMillis = v
		return e
	case "feeds.enabled":
		v, e := parseBool(raw)
		cfg.Feeds.Enabled = v
		return e
	case "feeds.auto_apply":
		v, e := parseBool(raw)
		cfg.Feeds.AutoApply = v
		return e
	case "feeds.refresh_minutes":
		v, e := parseInt(raw, 5, 1440)
		cfg.Feeds.RefreshMinutes = v
		return e
	case "feeds.max_download_bytes":
		v, e := parseInt(raw, 1024, 64<<20)
		cfg.Feeds.MaxDownloadBytes = int64(v)
		return e
	case "feeds.max_entries":
		v, e := parseInt(raw, 1, 500000)
		cfg.Feeds.MaxEntries = v
		return e
	case "feeds.sources":
		v, e := str()
		if e == nil {
			cfg.Feeds.Sources = splitCSV(v)
		}
		return e
	default:
		return fmt.Errorf("unknown key %s.%s", section, key)
	}
}

func parseUint32CSV(v string) ([]uint32, error) {
	parts := splitCSV(v)
	out := make([]uint32, 0, len(parts))
	seen := make(map[uint32]struct{}, len(parts))
	for _, part := range parts {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid numeric identity %q", part)
		}
		id := uint32(n)
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func validateAbsolutePath(label, path string, allowEmpty bool) error {
	if path == "" && allowEmpty {
		return nil
	}
	if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("%s must be an absolute path", label)
	}
	return nil
}

func isSafeUnixIdentityName(value string) bool {
	if len(value) < 1 || len(value) > 32 {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'a' && b <= 'z') || (i > 0 && b >= '0' && b <= '9') || (i > 0 && (b == '_' || b == '-')) {
			continue
		}
		return false
	}
	return true
}

func validateL7InlineUpstream(raw string) error {
	_, _, _, err := parseL7InlineUpstream(raw)
	return err
}

func parseL7InlineUpstream(raw string) (*url.URL, string, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, "", "", errors.New("l7.inline_upstream must not be empty")
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, "", "", errors.New("l7.inline_upstream is malformed")
	}
	if u.Scheme == "unix" {
		if u.Host != "" || u.Path == "" || !filepath.IsAbs(u.Path) || filepath.Clean(u.Path) != u.Path || len(u.Path) > 100 {
			return nil, "", "", errors.New("l7.inline_upstream unix socket must be a clean absolute path of at most 100 bytes")
		}
		target, parseErr := url.Parse("http://gedefense-inline-upstream")
		if parseErr != nil {
			return nil, "", "", fmt.Errorf("construct l7 inline unix target: %w", parseErr)
		}
		return target, "unix", u.Path, nil
	}
	if u.Scheme != "http" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return nil, "", "", errors.New("l7.inline_upstream must be unix:///path.sock or a static loopback http URL")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, "", "", errors.New("l7.inline_upstream TCP target must be an explicit loopback IP literal")
	}
	port := u.Port()
	if port == "" {
		return nil, "", "", errors.New("l7.inline_upstream TCP target requires an explicit port")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return nil, "", "", errors.New("l7.inline_upstream has an invalid port")
	}
	return u, "tcp", net.JoinHostPort(host, port), nil
}

func validateConfig(cfg *Config) error {
	if len(cfg.Node.Name) < 1 || len(cfg.Node.Name) > 64 {
		return errors.New("node.name must contain 1-64 characters")
	}
	if cfg.Node.Mode != "standalone" {
		return errors.New("node.mode must be standalone in this beta; Swarm/Mesh is deliberately deferred")
	}
	if cfg.Defense.Enforcement != "observe" && cfg.Defense.Enforcement != "enforce" {
		return errors.New("defense.enforcement must be observe or enforce")
	}
	if cfg.XDR.Mode != "observe" && cfg.XDR.Mode != "contain" && cfg.XDR.Mode != "enforce" {
		return errors.New("xdr.mode must be observe, contain, or enforce")
	}
	if cfg.L7.Mode != "observe" && cfg.L7.Mode != "block" {
		return errors.New("l7.mode must be observe or block")
	}
	if cfg.L7.AlertScore >= cfg.L7.BlockScore {
		return errors.New("l7 scores must satisfy alert < block")
	}
	if cfg.L7.MaxUploadBytes > cfg.L7.MaxBodyBytes {
		return errors.New("l7.max_upload_bytes must not exceed l7.max_body_bytes")
	}
	requiredInspection := cfg.L7.MaxBodyBytes + cfg.L7.MaxHeaderBytes + (2 * cfg.L7.MaxURIBytes) + (64 << 10)
	if cfg.L7.MaxInspectionBytes < requiredInspection {
		return fmt.Errorf("l7.max_inspection_bytes must be at least %d for the configured body/header/URI budgets", requiredInspection)
	}
	requiredEnvelope := ((cfg.L7.MaxBodyBytes + 2) / 3 * 4) + cfg.L7.MaxHeaderBytes + (64 << 10)
	if cfg.L7.MaxEnvelopeBytes < requiredEnvelope {
		return fmt.Errorf("l7.max_envelope_bytes must be at least %d for the configured body/header budgets", requiredEnvelope)
	}
	if int64(cfg.L7.MaxEnvelopeBytes)*int64(cfg.L7.MaxConcurrent) > 256<<20 {
		return errors.New("l7 concurrent envelope memory budget exceeds 256 MiB")
	}
	if int64(cfg.L7.MaxInspectionBytes)*int64(cfg.L7.MaxConcurrent) > 256<<20 {
		return errors.New("l7 concurrent inspection memory budget exceeds 256 MiB")
	}
	perInspectionBudget := int64(cfg.L7.MaxEnvelopeBytes) + int64(cfg.L7.MaxBodyBytes) + int64(cfg.L7.MaxInspectionBytes) + int64(cfg.L7.InlineMaxResponseBytes)
	if perInspectionBudget*int64(cfg.L7.MaxConcurrent) > 384<<20 {
		return errors.New("l7 aggregate concurrent memory budget exceeds 384 MiB")
	}
	if cfg.L7.RequirePeerCredentials && len(cfg.L7.AllowedPeerUIDs) == 0 && len(cfg.L7.AllowedPeerGIDs) == 0 {
		return errors.New("l7 peer credential enforcement requires at least one allowed UID or GID")
	}
	if cfg.L7.SocketGroup != "" && !isSafeUnixIdentityName(cfg.L7.SocketGroup) {
		return errors.New("l7.socket_group contains unsupported characters")
	}
	if cfg.L7.InlineEnabled {
		if !cfg.L7.Enabled {
			return errors.New("l7.inline_enabled requires l7.enabled")
		}
		if cfg.L7.InlineSocket == cfg.L7.Socket {
			return errors.New("l7.inline_socket must differ from l7.socket")
		}
		if err := validateL7InlineUpstream(cfg.L7.InlineUpstream); err != nil {
			return err
		}
	}
	seenSensitivePaths := make(map[string]struct{}, len(cfg.L7.SensitivePaths))
	normalizedSensitivePaths := make([]string, 0, len(cfg.L7.SensitivePaths))
	for _, path := range cfg.L7.SensitivePaths {
		if path == "" || path[0] != '/' || strings.ContainsAny(path, "?#\x00") || len(path) > cfg.L7.MaxURIBytes {
			return fmt.Errorf("invalid l7 sensitive path %q", path)
		}
		if _, exists := seenSensitivePaths[path]; exists {
			continue
		}
		seenSensitivePaths[path] = struct{}{}
		normalizedSensitivePaths = append(normalizedSensitivePaths, path)
	}
	cfg.L7.SensitivePaths = normalizedSensitivePaths
	if !(cfg.XDR.AlertScore < cfg.XDR.ContainScore && cfg.XDR.ContainScore < cfg.XDR.KillScore) {
		return errors.New("xdr scores must satisfy alert < contain < kill")
	}
	if cfg.Defense.DefaultTTLSeconds > cfg.Defense.MaxTTLSeconds {
		return errors.New("default TTL exceeds maximum TTL")
	}
	if len(cfg.Defense.Allowlist) > 1024 {
		return errors.New("defense.allowlist exceeds 1024 entries")
	}
	normalizedAllowlist := make([]string, 0, len(cfg.Defense.Allowlist))
	seenAllowlist := make(map[string]struct{}, len(cfg.Defense.Allowlist))
	for _, target := range cfg.Defense.Allowlist {
		normalized, err := normalizeTarget(target)
		if err != nil {
			return fmt.Errorf("defense.allowlist entry %q: %w", target, err)
		}
		if _, exists := seenAllowlist[normalized]; exists {
			continue
		}
		seenAllowlist[normalized] = struct{}{}
		normalizedAllowlist = append(normalizedAllowlist, normalized)
	}
	cfg.Defense.Allowlist = normalizedAllowlist
	host, _, err := net.SplitHostPort(cfg.Dashboard.Listen)
	if err != nil {
		return fmt.Errorf("dashboard.listen: %w", err)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !cfg.Dashboard.AllowRemote && !loopback {
		return errors.New("dashboard.listen must be loopback unless allow_remote=true")
	}
	if cfg.Dashboard.AllowRemote && (cfg.Dashboard.TLSCertFile == "" || cfg.Dashboard.TLSKeyFile == "") {
		return errors.New("remote dashboard access requires TLS certificate and key")
	}
	if len(cfg.Dashboard.AllowedHosts) == 0 {
		return errors.New("dashboard.allowed_hosts must not be empty")
	}
	if cfg.Feeds.AutoApply {
		return errors.New("feeds.auto_apply is intentionally unsupported in the beta release line")
	}
	if cfg.Release.Channel != "beta" {
		return errors.New("release.channel must be beta")
	}
	if cfg.Defense.Enforcement != "observe" || cfg.XDR.Mode != "observe" {
		return errors.New("beta startup configuration must begin in observe mode; promotion is runtime-gated")
	}
	for label, path := range map[string]string{
		"dashboard.token_file":        cfg.Dashboard.TokenFile,
		"core.socket":                 cfg.Core.Socket,
		"core.auth_key_file":          cfg.Core.AuthKeyFile,
		"l7.socket":                   cfg.L7.Socket,
		"l7.inline_socket":            cfg.L7.InlineSocket,
		"policy.state_file":           cfg.Policy.StateFile,
		"policy.signing_key_file":     cfg.Policy.SigningKeyFile,
		"policy.public_key_file":      cfg.Policy.PublicKeyFile,
		"policy.storage_key_file":     cfg.Policy.StorageKeyFile,
		"xdr.incident_log":            cfg.XDR.IncidentLog,
		"xdr.log_key_file":            cfg.XDR.LogKeyFile,
		"xdr.baseline_file":           cfg.XDR.BaselineFile,
		"xdr.behavior_profile_file":   cfg.XDR.BehaviorProfileFile,
		"xdr.storage_key_file":        cfg.XDR.StorageKeyFile,
		"release.emergency_stop_file": cfg.Release.EmergencyStopFile,
		"runtime.settings_file":       cfg.Runtime.SettingsFile,
		"runtime.key_file":            cfg.Runtime.KeyFile,
		"runtime.storage_key_file":    cfg.Runtime.StorageKeyFile,
		"cells.socket":                cfg.Cells.Socket,
		"cells.auth_key_file":         cfg.Cells.AuthKeyFile,
	} {
		if err := validateAbsolutePath(label, path, false); err != nil {
			return err
		}
	}
	if (cfg.Dashboard.TLSCertFile == "") != (cfg.Dashboard.TLSKeyFile == "") {
		return errors.New("TLS certificate and key must be configured together")
	}
	if err := validateAbsolutePath("dashboard.tls_cert_file", cfg.Dashboard.TLSCertFile, true); err != nil {
		return err
	}
	if err := validateAbsolutePath("dashboard.tls_key_file", cfg.Dashboard.TLSKeyFile, true); err != nil {
		return err
	}
	for _, u := range cfg.Feeds.Sources {
		if !strings.HasPrefix(u, "https://") || len(u) > 2048 {
			return fmt.Errorf("feed source must use HTTPS: %q", u)
		}
	}
	return nil
}
