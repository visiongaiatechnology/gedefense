package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
)

func validateTitanConfig(cfg *TitanConfig) error {
	mode := TitanMode(strings.ToUpper(strings.TrimSpace(cfg.Mode)))
	if mode == "" {
		mode = TitanModeObserve
	}
	if !validTitanMode(mode) {
		return errors.New("titan.mode must be OBSERVE, CONTAIN or STRICT")
	}
	cfg.Mode = string(mode)
	for label, values := range map[string][]string{
		"titan.roots":             cfg.Roots,
		"titan.allowlist":         cfg.Allowlist,
		"titan.development_roots": cfg.DevelopmentRoots,
		"titan.protected_paths":   cfg.ProtectedPaths,
	} {
		if _, err := normalizeTitanPaths(values, titanMaxRoots*2); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	if cfg.MaxFileBytes == 0 {
		cfg.MaxFileBytes = 16 << 20
	}
	if cfg.MaxFileBytes < titanMinFileBytes || cfg.MaxFileBytes > titanMaxFileBytes {
		return errors.New("titan.max_file_bytes is outside safe bounds")
	}
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = 500
	}
	if cfg.MaxEvents < titanMinJournalEvents || cfg.MaxEvents > titanMaxJournalEvents {
		return errors.New("titan.max_events is outside safe bounds")
	}
	if cfg.JournalMaxBytes == 0 {
		cfg.JournalMaxBytes = 4 << 20
	}
	if cfg.JournalMaxBytes < titanMinJournalBytes || cfg.JournalMaxBytes > titanMaxJournalBytes {
		return errors.New("titan.journal_max_bytes is outside safe bounds")
	}
	if cfg.PolicyFile != "" {
		if err := validateAbsolutePath("titan.policy_file", cfg.PolicyFile, false); err != nil {
			return err
		}
	}
	if cfg.JournalFile != "" {
		if err := validateAbsolutePath("titan.journal_file", cfg.JournalFile, false); err != nil {
			return err
		}
	}
	return nil
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

func validateConfig(cfg *Config) error {
	// Storage encryption is not an optional mode. An empty key path used to disable the cipher
	// silently, which left the policy signing key, the evidence signing key and the evidence and
	// incident records in plaintext on disk. A missing key is therefore a configuration error that
	// stops the start - not a quieter way to run.
	if err := validateAbsolutePath("policy.storage_key_file", cfg.Policy.StorageKeyFile, false); err != nil {
		return err
	}
	if err := validateAbsolutePath("xdr.storage_key_file", cfg.XDR.StorageKeyFile, false); err != nil {
		return err
	}
	if len(cfg.Node.Name) < 1 || len(cfg.Node.Name) > 64 {
		return errors.New("node.name must contain 1-64 characters")
	}
	if cfg.Node.Mode != "standalone" {
		return errors.New("node.mode must be standalone in this beta; Swarm/Mesh is deliberately deferred")
	}
	if cfg.Defense.Enforcement != "observe" && cfg.Defense.Enforcement != "enforce" {
		return errors.New("defense.enforcement must be observe or enforce")
	}
	if cfg.Advisories.Mode != advisoryModeReport && cfg.Advisories.Mode != advisoryModeStrict {
		return errors.New("advisories.mode must be report or strict")
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
	if len(cfg.L7.EnforceRules) > l7RuleOverrideLimit {
		return fmt.Errorf("l7.enforce_rules exceeds %d entries", l7RuleOverrideLimit)
	}
	seenEnforceRules := make(map[string]struct{}, len(cfg.L7.EnforceRules))
	normalizedEnforceRules := make([]string, 0, len(cfg.L7.EnforceRules))
	for _, raw := range cfg.L7.EnforceRules {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if !l7RuleOverrideIDAllowed(id) && !isL7RuleFamily(id) {
			return fmt.Errorf("l7.enforce_rules entry %q is not a supported built-in rule or family", raw)
		}
		if _, duplicate := seenEnforceRules[id]; duplicate {
			continue
		}
		seenEnforceRules[id] = struct{}{}
		normalizedEnforceRules = append(normalizedEnforceRules, id)
	}
	cfg.L7.EnforceRules = normalizedEnforceRules
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
	if cfg.L7.RequirePeerCredentials && (cfg.L7.Enabled || cfg.L7.InlineEnabled) &&
		len(cfg.L7.AllowedPeerUIDs) == 0 && len(cfg.L7.AllowedPeerGIDs) == 0 && strings.TrimSpace(cfg.L7.SocketGroup) == "" {
		return errors.New("l7 peer credential enforcement requires an allowed UID/GID list or a socket_group whose primary GID is attested via SO_PEERCRED")
	}
	if cfg.L7.SocketGroup != "" && !isSafeUnixIdentityName(cfg.L7.SocketGroup) {
		return errors.New("l7.socket_group contains unsupported characters")
	}
	if cfg.L7.TLSEnabled {
		if cfg.L7.TLSFloodThreshold < 2 {
			return errors.New("l7.tls_flood_threshold must be at least 2")
		}
		if cfg.L7.TLSSNIStrikeThreshold < 2 || cfg.L7.TLSSNIStrikeThreshold > 1000 {
			return errors.New("l7.tls_sni_strike_threshold must be between 2 and 1000")
		}
		if cfg.L7.TLSMaxClientHelloBytes < 1024 || cfg.L7.TLSMaxClientHelloBytes > 1<<20 {
			return errors.New("l7.tls_max_client_hello_bytes must be between 1024 and 1048576")
		}
	}
	seenTLSDomains := make(map[string]struct{}, len(cfg.L7.TLSAllowedDomains))
	normalizedTLSDomains := make([]string, 0, len(cfg.L7.TLSAllowedDomains))
	for _, domain := range cfg.L7.TLSAllowedDomains {
		normalized, err := normalizeTLSAllowedPattern(domain)
		if err != nil {
			return fmt.Errorf("invalid l7 TLS allowed domain %q: %w", domain, err)
		}
		if _, exists := seenTLSDomains[normalized]; exists {
			continue
		}
		seenTLSDomains[normalized] = struct{}{}
		normalizedTLSDomains = append(normalizedTLSDomains, normalized)
	}
	cfg.L7.TLSAllowedDomains = normalizedTLSDomains
	if cfg.L7.TLSJA3File != "" && (!filepath.IsAbs(cfg.L7.TLSJA3File) || filepath.Clean(cfg.L7.TLSJA3File) != cfg.L7.TLSJA3File) {
		return errors.New("l7.tls_ja3_file must be a clean absolute path when configured")
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
	if cfg.Release.Channel != "beta" {
		return errors.New("release.channel must be beta")
	}
	if cfg.Defense.Enforcement != "observe" || cfg.XDR.Mode != "observe" {
		return errors.New("beta startup configuration must begin in observe mode; promotion is runtime-gated")
	}
	if cfg.Kinetic.EnforcementMode != "observe" && cfg.Kinetic.EnforcementMode != "contain" && cfg.Kinetic.EnforcementMode != "block" {
		return errors.New("kinetic.enforcement_mode must be observe, contain, or block")
	}
	if cfg.Kinetic.IPThreshold < 1 || cfg.Kinetic.IPThreshold > 100000 {
		return errors.New("kinetic.ip_threshold must be between 1 and 100000")
	}
	if cfg.Kinetic.VelocityLimit < 1 || cfg.Kinetic.VelocityLimit > 50000 {
		return errors.New("kinetic.velocity_limit must be between 1 and 50000")
	}
	if cfg.Kinetic.RangeThreshold < 1 || cfg.Kinetic.RangeThreshold > 100000 {
		return errors.New("kinetic.range_threshold must be between 1 and 100000")
	}
	if cfg.Kinetic.IPv6SubThreshold < 1 || cfg.Kinetic.IPv6SubThreshold > 100000 {
		return errors.New("kinetic.ipv6_sub_threshold must be between 1 and 100000")
	}
	if cfg.Kinetic.WideRangeThreshold < 1 || cfg.Kinetic.WideRangeThreshold > 100000 {
		return errors.New("kinetic.wide_range_threshold must be between 1 and 100000")
	}
	if cfg.Kinetic.PortscanThreshold < 2 || cfg.Kinetic.PortscanThreshold > 65535 {
		return errors.New("kinetic.portscan_threshold must be between 2 and 65535")
	}
	if cfg.Kinetic.SYNThreshold < 1 || cfg.Kinetic.SYNThreshold > 100000 || cfg.Kinetic.SYNAckRatio < 1 || cfg.Kinetic.SYNAckRatio > 100 {
		return errors.New("kinetic SYN flood settings are outside safe bounds")
	}
	if cfg.Kinetic.LowSlowMinSeconds < 10 || cfg.Kinetic.LowSlowMinSeconds > 86400 {
		return errors.New("kinetic.low_slow_min_seconds must be between 10 and 86400")
	}
	if cfg.Kinetic.SubnetMinSources < 2 || cfg.Kinetic.SubnetMinSources > 1024 || cfg.Kinetic.IPv6SubnetMinSources < 2 || cfg.Kinetic.IPv6SubnetMinSources > 1024 || cfg.Kinetic.WideMinSources < 2 || cfg.Kinetic.WideMinSources > 4096 {
		return errors.New("kinetic subnet source gates are outside safe bounds")
	}
	if cfg.Kinetic.MaxTrackingIPs < 100 || cfg.Kinetic.MaxTrackingIPs > 500000 {
		return errors.New("kinetic.max_tracking_ips must be between 100 and 500000")
	}
	if err := validatePortList("kinetic web service ports", cfg.Kinetic.ServicePortsWeb); err != nil {
		return err
	}
	if err := validatePortList("kinetic mail service ports", cfg.Kinetic.ServicePortsMail); err != nil {
		return err
	}
	if err := validatePortList("kinetic admin service ports", cfg.Kinetic.ServicePortsAdmin); err != nil {
		return err
	}
	if cfg.Kinetic.GeoIPCSV != "" && !filepath.IsAbs(cfg.Kinetic.GeoIPCSV) {
		return errors.New("kinetic.geoip_csv must be an absolute path when configured")
	}
	if len(cfg.Kinetic.GeoIPSigningKeys) > 8 {
		return errors.New("kinetic.geoip_signing_keys exceeds 8 pinned keys")
	}
	for _, rawKey := range cfg.Kinetic.GeoIPSigningKeys {
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(rawKey))
		if decodeErr != nil {
			decoded, decodeErr = base64.RawStdEncoding.DecodeString(strings.TrimSpace(rawKey))
		}
		if decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
			return errors.New("kinetic.geoip_signing_keys contains an invalid Ed25519 public key")
		}
	}
	if len(cfg.Kinetic.GeoIPSigningKeys) > 0 && cfg.Kinetic.GeoIPCSV == "" {
		return errors.New("kinetic.geoip_signing_keys requires kinetic.geoip_csv")
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
		"parser_cells.socket":         cfg.ParserCells.Socket,
		"parser_cells.auth_key_file":  cfg.ParserCells.AuthKeyFile,
		"parser_cells.input_dir":      cfg.ParserCells.InputDir,
		"parser_cells.imports_dir":    cfg.ParserCells.ImportsDir,
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
	if cfg.Feeds.ManifestMaxAgeMinutes < 5 || cfg.Feeds.ManifestMaxAgeMinutes > 10080 {
		return errors.New("feeds.manifest_max_age_minutes must be between 5 and 10080")
	}
	if cfg.Feeds.ManifestPath != "" {
		if err := validateAbsolutePath("feeds.manifest_path", cfg.Feeds.ManifestPath, true); err != nil {
			return err
		}
	}
	if len(cfg.Feeds.TrustedSigningKeys) > 8 {
		return errors.New("feeds.trusted_signing_keys exceeds 8 pinned keys")
	}
	for _, rawKey := range cfg.Feeds.TrustedSigningKeys {
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(rawKey))
		if decodeErr != nil {
			decoded, decodeErr = base64.RawStdEncoding.DecodeString(strings.TrimSpace(rawKey))
		}
		if decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
			return errors.New("feeds.trusted_signing_keys contains an invalid Ed25519 public key")
		}
	}
	if cfg.Feeds.Enabled && cfg.Feeds.AutoApply && !cfg.Feeds.RequireSignedManifest {
		return errors.New("feeds.auto_apply requires feeds.require_signed_manifest: unsigned feeds must never reach the kernel blocklist")
	}
	if cfg.Feeds.AutoApply && len(cfg.Feeds.TrustedSigningKeys) == 0 {
		return errors.New("feeds.auto_apply requires at least one pinned feed signing key")
	}
	// Local operator signing (F-03 provisioning). The pipeline only makes sense
	// with the authenticity gate enabled and an absolute, owner-only key path;
	// a half-configured pipeline would silently produce nothing that the manager
	// accepts, so it is rejected at load time instead.
	if cfg.Feeds.LocalSigning {
		if !cfg.Feeds.RequireSignedManifest {
			return errors.New("feeds.local_signing requires feeds.require_signed_manifest=true")
		}
		if strings.TrimSpace(cfg.Feeds.SigningKeyFile) == "" {
			return errors.New("feeds.local_signing requires feeds.signing_key_file")
		}
		if err := validateAbsolutePath("feeds.signing_key_file", cfg.Feeds.SigningKeyFile, false); err != nil {
			return err
		}
		if strings.TrimSpace(cfg.Feeds.SnapshotDir) == "" {
			return errors.New("feeds.local_signing requires feeds.snapshot_dir")
		}
	}
	if strings.TrimSpace(cfg.Feeds.SigningKeyFile) != "" {
		if err := validateAbsolutePath("feeds.signing_key_file", cfg.Feeds.SigningKeyFile, false); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.Feeds.SnapshotDir) != "" {
		if err := validateAbsolutePath("feeds.snapshot_dir", cfg.Feeds.SnapshotDir, false); err != nil {
			return err
		}
	}
	if err := validateTitanConfig(&cfg.Titan); err != nil {
		return err
	}
	if err := validateParserCellsConfig(&cfg.ParserCells); err != nil {
		return err
	}
	return nil
}

// validateParserCellsConfig validates the bootstrap lists that are not covered by
// the path checks: a Wayland-profile declaration must be bounded and use the same
// protocol-safe profile ids as the helper, so the fail-closed create gate can only
// ever see unambiguous names.
func validateParserCellsConfig(cfg *ParserCellsConfig) error {
	if cfg.PeerUID < -1 || cfg.PeerUID > 65535 {
		return errors.New("parser_cells.peer_uid must be -1 (test rigs only) or a valid uid")
	}
	if len(cfg.WaylandProfiles) > parserCellsMaxProfiles {
		return fmt.Errorf("parser_cells.wayland_profiles exceeds %d entries", parserCellsMaxProfiles)
	}
	seen := make(map[string]struct{}, len(cfg.WaylandProfiles))
	profiles := make([]string, 0, len(cfg.WaylandProfiles))
	for _, profile := range cfg.WaylandProfiles {
		if !parserCellProfileValid(profile) {
			return fmt.Errorf("parser_cells.wayland_profiles entry %q is not a protocol-safe profile id", profile)
		}
		if _, duplicate := seen[profile]; duplicate {
			return fmt.Errorf("parser_cells.wayland_profiles entry %q is duplicated", profile)
		}
		seen[profile] = struct{}{}
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	cfg.WaylandProfiles = profiles
	return nil
}
