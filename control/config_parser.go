package main

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

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
	case "startup.enabled":
		v, e := parseBool(raw)
		cfg.Startup.Enabled = v
		return e
	case "startup.rounds":
		v, e := parseInt(raw, 1, 240)
		cfg.Startup.Rounds = v
		return e
	case "startup.round_gap_seconds":
		v, e := parseInt(raw, 1, 300)
		cfg.Startup.RoundGapSeconds = v
		return e
	case "startup.arm_interval_seconds":
		v, e := parseInt(raw, 30, 86400)
		cfg.Startup.ArmIntervalSec = v
		return e
	case "startup.heal_attempts":
		v, e := parseInt(raw, 1, 20)
		cfg.Startup.HealAttempts = v
		return e
	case "startup.qualification_file":
		v, e := str()
		cfg.Startup.QualificationFile = v
		return e
	case "advisories.enabled":
		v, e := parseBool(raw)
		cfg.Advisories.Enabled = v
		return e
	case "advisories.mode":
		v, e := str()
		cfg.Advisories.Mode = v
		return e
	case "advisories.max_exposure":
		v, e := parseInt(raw, 1, 100)
		cfg.Advisories.MaxExposure = v
		return e
	case "advisories.auto_mitigate":
		v, e := parseBool(raw)
		cfg.Advisories.AutoMitigate = v
		return e
	case "advisories.mitigation_watch_seconds":
		v, e := parseInt(raw, 30, 3600)
		cfg.Advisories.MitigationWatchSeconds = v
		return e
	case "advisories.mitigation_interval_seconds":
		v, e := parseInt(raw, 5, 300)
		cfg.Advisories.MitigationIntervalSeconds = v
		return e
	case "advisories.mitigation_failures":
		v, e := parseInt(raw, 1, 10)
		cfg.Advisories.MitigationFailures = v
		return e
	case "dashboard.token_owner":
		v, e := str()
		cfg.Dashboard.TokenOwner = v
		return e
	case "desktop.enabled":
		v, e := parseBool(raw)
		cfg.Desktop.Enabled = v
		return e
	case "desktop.socket":
		v, e := str()
		cfg.Desktop.SocketPath = v
		return e
	case "desktop.socket_mode":
		v, e := str()
		cfg.Desktop.SocketMode = v
		return e
	case "desktop.socket_group":
		v, e := str()
		cfg.Desktop.SocketGroup = v
		return e
	case "desktop.alert_window_seconds":
		v, e := parseInt(raw, 60, 86400)
		cfg.Desktop.AlertWindowSeconds = v
		return e
	case "desktop.max_connections_per_user":
		v, e := parseInt(raw, 1, 32)
		cfg.Desktop.MaxConnectionsPerUser = v
		return e
	case "desktop.rate_limit_per_minute":
		v, e := parseInt(raw, 1, 100000)
		cfg.Desktop.RateLimitPerMinute = v
		return e
	case "desktop.rate_limit_burst":
		v, e := parseInt(raw, 1, 10000)
		cfg.Desktop.RateLimitBurst = v
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
	case "l7.enforce_rules":
		v, e := str()
		if e == nil {
			cfg.L7.EnforceRules = splitCSV(v)
		}
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
	case "l7.coverage_required":
		v, e := str()
		if e != nil {
			return e
		}
		switch v {
		case "auto", "required", "optional":
			cfg.L7.CoverageRequired = v
			return nil
		default:
			return fmt.Errorf("l7.coverage_required must be auto, required or optional")
		}
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
	case "l7.tls_enabled":
		v, e := parseBool(raw)
		cfg.L7.TLSEnabled = v
		return e
	case "l7.tls_allowed_domains":
		v, e := str()
		if e == nil {
			cfg.L7.TLSAllowedDomains = splitCSV(v)
		}
		return e
	case "l7.tls_flood_threshold":
		v, e := parseInt(raw, 2, 100000)
		cfg.L7.TLSFloodThreshold = v
		return e
	case "l7.tls_sni_strike_threshold":
		v, e := parseInt(raw, 2, 1000)
		cfg.L7.TLSSNIStrikeThreshold = v
		return e
	case "l7.tls_anti_spoof":
		v, e := parseBool(raw)
		cfg.L7.TLSAntiSpoof = v
		return e
	case "l7.tls_max_client_hello_bytes":
		v, e := parseInt(raw, 1024, 1<<20)
		cfg.L7.TLSMaxClientHelloBytes = v
		return e
	case "l7.tls_ja3_file":
		v, e := str()
		cfg.L7.TLSJA3File = v
		return e
	default:
		return assignConfigSections(cfg, section, key, raw)
	}
}

func parsePortCSV(v string) ([]uint16, error) {
	parts := splitCSV(v)
	if len(parts) == 0 {
		return nil, errors.New("port list must not be empty")
	}
	out := make([]uint16, 0, len(parts))
	seen := make(map[uint16]struct{}, len(parts))
	for _, part := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		port := uint16(n)
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	slices.Sort(out)
	return out, nil
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
