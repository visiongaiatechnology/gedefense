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

func defaultConfig() Config {
	return Config{
		Node:       NodeConfig{Name: "VGT-Beta-Node", Interface: "auto", Mode: "standalone"},
		Desktop:    defaultDesktopConfig(),
		Startup:    defaultStartupSupervisorConfig(),
		Advisories: defaultAdvisoryConfig(),
		Titan:      defaultTitanConfig(),
		Dashboard: DashboardConfig{
			// G-RUST-06: canonical topology is public access on 9843 and the
			// internal control plane on loopback 9844. This matches the packaged
			// access unit (backend http://127.0.0.1:9844) and the AstraeaOS
			// profile; it was historically 9843 here, which collided with the
			// public listener on package installs.
			Listen: canonicalDashboardInternalListen, TokenFile: defaultDashboardTokenFile,
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
			// Peer credentials are mandatory by default (F-06 / CHAIN-002). The
			// shipped profile authorises the L7 socket group through
			// SO_PEERCRED; explicit UID/GID allowlists are preferred and required
			// when no socket group is configured.
			RequirePeerCredentials: true,
			Enabled:                false, Mode: "observe", Socket: "/run/vgt-gedefense-l7/inspect.sock", SocketGroup: "gedefense-l7", RequestTimeoutMillis: 750,
			MaxConcurrent: 16, MaxEnvelopeBytes: 3 << 20, MaxBodyBytes: 2 << 20, MaxURIBytes: 16 << 10,
			MaxHeaderBytes: 64 << 10, MaxHeaders: 128, MaxValueBytes: 16 << 10, MaxInspectionBytes: 4 << 20, MaxDecodedValues: 4096,
			MaxDecodeDepth: 8, MaxJSONDepth: 32, MaxFormFields: 512, MaxMultipartParts: 64, MaxUploadBytes: 2 << 20,
			AlertScore: 40, BlockScore: 90, ClientRatePerMinute: 600, ClientRateBurst: 100,
			SensitiveRatePerMinute: 30, SensitiveRateBurst: 10, SensitiveGlobalRatePerMinute: 300, SensitiveGlobalRateBurst: 50, MaxTrackedClients: 65536,
			SensitivePaths: []string{"/wp-login.php", "/xmlrpc.php", "/login", "/signin", "/api/login"},
			InlineEnabled:  false, InlineSocket: "/run/vgt-gedefense-l7/edge.sock", InlineUpstream: "http://127.0.0.1:8080",
			InlineMaxResponseBytes: 64 << 10,
			// auto: the traffic path is required once something is actually wired in.
			// An engine that is enabled but has nothing attached is deliberately idle,
			// not broken, and must not degrade the platform.
			CoverageRequired: "auto",
			TLSEnabled:       true, TLSAllowedDomains: nil, TLSFloodThreshold: 15, TLSSNIStrikeThreshold: 10, TLSAntiSpoof: true,
			TLSMaxClientHelloBytes: 64 << 10, TLSJA3File: "",
		},
		XDR: XDRConfig{
			Enabled: true, Mode: "observe", ScanIntervalMillis: 750, NetworkIntervalSeconds: 3,
			IntegrityIntervalSeconds: 3, AlertScore: 40, ContainScore: 80, KillScore: 120,
			MaxCommandBytes: 8192, CommandPreviewBytes: 320, DedupeSeconds: 300,
			MaxIncidentLogBytes:    64 << 20,
			IncidentLog:            "/var/lib/vgt/gedefense/incidents.jsonl",
			LogKeyFile:             "/var/lib/vgt/gedefense/xdr-log.key",
			BaselineFile:           "/etc/vgt/gedefense/xdr-baseline.json",
			ProtectedPaths:         []string{"/opt/vgt/gedefense/current/bin/gedefense-control", "/opt/vgt/gedefense/current/libexec/gedefense-core", "/opt/vgt/gedefense/current/lib/gedefense/gedefense-ebpf"},
			ProtectedSecurityRoots: true,
			WorkerCount:            4, QueueCapacity: 2048, MaxEvaluationsPerScan: 4096,
			BehaviorEnabled: true, BehaviorWarmupSamples: 24, BehaviorZScoreMilli: 3500,
			BehaviorMinConnections: 8, BehaviorMaxProfiles: 4096, BehaviorMaxPorts: 256, BehaviorProfileFile: "/var/lib/vgt/gedefense/behavior-profiles.json",
			StorageKeyFile: "/etc/vgt/gedefense/secrets/storage-master.key",
		},
		Runtime: RuntimeConfig{SettingsFile: "/var/lib/vgt/gedefense/runtime-settings.json", KeyFile: "/var/lib/vgt/gedefense/runtime-settings.key", StorageKeyFile: "/etc/vgt/gedefense/secrets/storage-master.key"},
		Cells: CellsConfig{
			Enabled: false, Socket: "/run/gaia-cells/control.sock",
			AutoConfine: false, AutoConfineAction: cellActionRevokeNetwork, AutoConfineScore: 80,
			AutoConfineIntervalSeconds: 15, AutoConfineCooldownSeconds: 300,
			AuthKeyFile:          "/etc/vgt/gedefense/secrets/gaia-cells.key",
			RequestTimeoutMillis: 1500,
		},
		ParserCells: ParserCellsConfig{
			Socket:               "/run/vgt-gedefense/cell-helper.sock",
			AuthKeyFile:          "/etc/vgt/gedefense/secrets/cell-helper.key",
			InputDir:             "/var/lib/vgt/gedefense/parser-inputs",
			ImportsDir:           "/var/lib/vgt/gedefense/parser-imports",
			RequestTimeoutMillis: 2500,
			PeerUID:              0,
			WaylandProfiles:      []string{},
		},
		Release: ReleaseConfig{
			Channel: "beta", MinimumObserveSeconds: 300, MinimumCanarySeconds: 900,
			CoreFailureThreshold: 3, MaxEvaluationDropPermille: 5,
			EmergencyStopFile: "/var/lib/vgt/gedefense/EMERGENCY_STOP", AutoDegrade: true,
		},
		Feeds: FeedConfig{
			Enabled:          false,
			AutoApply:        false,
			RefreshMinutes:   720,
			MaxDownloadBytes: 16 << 20,
			MaxEntries:       250000,
			Sources:          append([]string(nil), DefaultThreatFeeds...),
			// Fail closed: unsigned feeds never reach the kernel unless the
			// operator explicitly disables the manifest gate (and then
			// auto_apply is refused by validation).
			RequireSignedManifest: true,
			TrustedSigningKeys:    nil,
			ManifestPath:          "/var/lib/vgt/gedefense/threat-feed-manifest.json",
			ManifestMaxAgeMinutes: 1440,
			// Local signing is an explicit operator opt-in: the key must be
			// generated with --init-feed-signing, pinned in
			// feeds.trusted_signing_keys and provisioned by the installer. The
			// default stays off so an unprovisioned host fails closed instead of
			// half-enabling a pipeline without a key.
			LocalSigning:   false,
			SigningKeyFile: "",
			SnapshotDir:    "/var/lib/vgt/gedefense/feed-snapshots",
		},
		Kinetic: KineticConfig{
			Enabled:            true,
			EnforcementMode:    "observe",
			IPThreshold:        35,
			VelocityLimit:      15,
			RangeThreshold:     45,
			IPv6SubThreshold:   55,
			WideRangeThreshold: 77,
			PortscanThreshold:  5,
			SYNThreshold:       25, SYNAckRatio: 4, LowSlowMinSeconds: 60,
			SubnetMinSources: 2, IPv6SubnetMinSources: 2, WideMinSources: 4,
			AutoContainSingleIP: true, AutoContainIPv4Subnet: true, AutoContainIPv6Subnet: true,
			MaxTrackingIPs:    65536,
			BanTTLSeconds:     86400,
			MaxStrikesPerSec:  100,
			ServicePortsWeb:   []uint16{80, 443, 8443},
			ServicePortsMail:  []uint16{25, 465, 587, 110, 995, 143, 993},
			ServicePortsAdmin: []uint16{22, 2222, 888, 3306, 5432},
			GeoIPCSV:          "/var/lib/vgt/gedefense/geoip.csv",
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
			case "node", "dashboard", "core", "defense", "policy", "feeds", "xdr", "l7", "release", "runtime", "cells", "kinetic", "advisories", "titan", "parser_cells":
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
