package main

import (
	"fmt"
)

func assignTitanConfig(cfg *Config, key, raw string) error {
	str := func() (string, error) { return parseString(raw) }
	switch key {
	case "enabled":
		v, e := parseBool(raw)
		cfg.Titan.Enabled = v
		return e
	case "mode":
		v, e := str()
		cfg.Titan.Mode = v
		return e
	case "armed":
		v, e := parseBool(raw)
		cfg.Titan.Armed = v
		return e
	case "auto_contain":
		v, e := parseBool(raw)
		cfg.Titan.AutoContain = v
		return e
	case "roots":
		v, e := str()
		if e == nil {
			cfg.Titan.Roots = splitCSV(v)
		}
		return e
	case "allowlist":
		v, e := str()
		if e == nil {
			cfg.Titan.Allowlist = splitCSV(v)
		}
		return e
	case "development_roots":
		v, e := str()
		if e == nil {
			cfg.Titan.DevelopmentRoots = splitCSV(v)
		}
		return e
	case "protected_paths":
		v, e := str()
		if e == nil {
			cfg.Titan.ProtectedPaths = splitCSV(v)
		}
		return e
	case "policy_file":
		v, e := str()
		cfg.Titan.PolicyFile = v
		return e
	case "journal_file":
		v, e := str()
		cfg.Titan.JournalFile = v
		return e
	case "max_file_bytes":
		v, e := parseInt(raw, 1<<10, 64<<20)
		cfg.Titan.MaxFileBytes = int64(v)
		return e
	case "max_events":
		v, e := parseInt(raw, titanMinJournalEvents, titanMaxJournalEvents)
		cfg.Titan.MaxEvents = v
		return e
	case "journal_max_bytes":
		v, e := parseInt(raw, titanMinJournalBytes, titanMaxJournalBytes)
		cfg.Titan.JournalMaxBytes = int64(v)
		return e
	default:
		return fmt.Errorf("unknown key titan.%s", key)
	}
}

func assignConfigSections(cfg *Config, section, key, raw string) error {
	str := func() (string, error) { return parseString(raw) }
	switch section + "." + key {
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
	case "xdr.protected_security_roots":
		v, e := parseBool(raw)
		cfg.XDR.ProtectedSecurityRoots = v
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
	case "cells.auto_confine":
		v, e := parseBool(raw)
		cfg.Cells.AutoConfine = v
		return e
	case "cells.auto_confine_action":
		v, e := str()
		cfg.Cells.AutoConfineAction = v
		return e
	case "cells.auto_confine_score":
		v, e := parseInt(raw, 1, 249)
		cfg.Cells.AutoConfineScore = v
		return e
	case "cells.auto_confine_interval_seconds":
		v, e := parseInt(raw, 5, 3600)
		cfg.Cells.AutoConfineIntervalSeconds = v
		return e
	case "cells.auto_confine_cooldown_seconds":
		v, e := parseInt(raw, 30, 86400)
		cfg.Cells.AutoConfineCooldownSeconds = v
		return e
	case "cells.request_timeout_millis":
		v, e := parseInt(raw, 100, 10000)
		cfg.Cells.RequestTimeoutMillis = v
		return e
	case "parser_cells.socket":
		v, e := str()
		cfg.ParserCells.Socket = v
		return e
	case "parser_cells.auth_key_file":
		v, e := str()
		cfg.ParserCells.AuthKeyFile = v
		return e
	case "parser_cells.input_dir":
		v, e := str()
		cfg.ParserCells.InputDir = v
		return e
	case "parser_cells.imports_dir":
		v, e := str()
		cfg.ParserCells.ImportsDir = v
		return e
	case "parser_cells.wayland_profiles":
		v, e := str()
		if e == nil {
			cfg.ParserCells.WaylandProfiles = splitCSV(v)
		}
		return e
	case "parser_cells.request_timeout_millis":
		v, e := parseInt(raw, 100, 10000)
		cfg.ParserCells.RequestTimeoutMillis = v
		return e
	case "parser_cells.peer_uid":
		v, e := parseInt(raw, -1, 65535)
		cfg.ParserCells.PeerUID = v
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
	case "feeds.require_signed_manifest":
		v, e := parseBool(raw)
		cfg.Feeds.RequireSignedManifest = v
		return e
	case "feeds.trusted_signing_keys":
		v, e := str()
		if e != nil {
			return e
		}
		cfg.Feeds.TrustedSigningKeys = splitCSV(v)
		return e
	case "feeds.manifest_path":
		v, e := str()
		cfg.Feeds.ManifestPath = v
		return e
	case "feeds.manifest_max_age_minutes":
		v, e := parseInt(raw, 5, 10080)
		cfg.Feeds.ManifestMaxAgeMinutes = v
		return e
	case "feeds.local_signing":
		v, e := parseBool(raw)
		cfg.Feeds.LocalSigning = v
		return e
	case "feeds.signing_key_file":
		v, e := str()
		cfg.Feeds.SigningKeyFile = v
		return e
	case "feeds.snapshot_dir":
		v, e := str()
		cfg.Feeds.SnapshotDir = v
		return e
	case "kinetic.enabled":
		v, e := parseBool(raw)
		cfg.Kinetic.Enabled = v
		return e
	case "kinetic.enforcement_mode":
		v, e := str()
		cfg.Kinetic.EnforcementMode = v
		return e
	case "kinetic.ip_threshold":
		v, e := parseInt(raw, 1, 100000)
		cfg.Kinetic.IPThreshold = v
		return e
	case "kinetic.velocity_limit":
		v, e := parseInt(raw, 1, 50000)
		cfg.Kinetic.VelocityLimit = v
		return e
	case "kinetic.range_threshold":
		v, e := parseInt(raw, 1, 100000)
		cfg.Kinetic.RangeThreshold = v
		return e
	case "kinetic.ipv6_sub_threshold":
		v, e := parseInt(raw, 1, 100000)
		cfg.Kinetic.IPv6SubThreshold = v
		return e
	case "kinetic.wide_range_threshold":
		v, e := parseInt(raw, 1, 100000)
		cfg.Kinetic.WideRangeThreshold = v
		return e
	case "kinetic.portscan_threshold":
		v, e := parseInt(raw, 1, 1000)
		cfg.Kinetic.PortscanThreshold = v
		return e
	case "kinetic.syn_threshold":
		v, e := parseInt(raw, 1, 100000)
		cfg.Kinetic.SYNThreshold = v
		return e
	case "kinetic.syn_ack_ratio":
		v, e := parseInt(raw, 1, 100)
		cfg.Kinetic.SYNAckRatio = v
		return e
	case "kinetic.low_slow_min_seconds":
		v, e := parseInt(raw, 10, 86400)
		cfg.Kinetic.LowSlowMinSeconds = v
		return e
	case "kinetic.subnet_min_sources":
		v, e := parseInt(raw, 2, 1024)
		cfg.Kinetic.SubnetMinSources = v
		return e
	case "kinetic.ipv6_subnet_min_sources":
		v, e := parseInt(raw, 2, 1024)
		cfg.Kinetic.IPv6SubnetMinSources = v
		return e
	case "kinetic.wide_min_sources":
		v, e := parseInt(raw, 2, 4096)
		cfg.Kinetic.WideMinSources = v
		return e
	case "kinetic.auto_contain_single_ip":
		v, e := parseBool(raw)
		cfg.Kinetic.AutoContainSingleIP = v
		return e
	case "kinetic.auto_contain_ipv4_subnet":
		v, e := parseBool(raw)
		cfg.Kinetic.AutoContainIPv4Subnet = v
		return e
	case "kinetic.auto_contain_ipv6_subnet":
		v, e := parseBool(raw)
		cfg.Kinetic.AutoContainIPv6Subnet = v
		return e
	case "kinetic.max_tracking_ips":
		v, e := parseInt(raw, 100, 500000)
		cfg.Kinetic.MaxTrackingIPs = v
		return e
	case "kinetic.ban_ttl_seconds":
		v, e := parseInt(raw, 60, 2592000)
		cfg.Kinetic.BanTTLSeconds = v
		return e
	case "kinetic.max_strikes_per_sec":
		v, e := parseInt(raw, 1, 10000)
		cfg.Kinetic.MaxStrikesPerSec = v
		return e
	case "kinetic.service_ports_web":
		v, e := str()
		if e != nil {
			return e
		}
		ports, e := parsePortCSV(v)
		if e == nil {
			cfg.Kinetic.ServicePortsWeb = ports
		}
		return e
	case "kinetic.service_ports_mail":
		v, e := str()
		if e != nil {
			return e
		}
		ports, e := parsePortCSV(v)
		if e == nil {
			cfg.Kinetic.ServicePortsMail = ports
		}
		return e
	case "kinetic.service_ports_admin":
		v, e := str()
		if e != nil {
			return e
		}
		ports, e := parsePortCSV(v)
		if e == nil {
			cfg.Kinetic.ServicePortsAdmin = ports
		}
		return e
	case "kinetic.geoip_csv":
		v, e := str()
		cfg.Kinetic.GeoIPCSV = v
		return e
	case "kinetic.geoip_signing_keys":
		v, e := str()
		if e != nil {
			return e
		}
		cfg.Kinetic.GeoIPSigningKeys = splitCSV(v)
		return e
	default:
		if section == "titan" {
			return assignTitanConfig(cfg, key, raw)
		}
		return fmt.Errorf("unknown key %s.%s", section, key)
	}
}
