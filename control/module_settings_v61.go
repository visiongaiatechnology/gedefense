// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 Fabric Settings namespaces for modules A–D
// (docs/V6.1.0-BLUEPRINT.md §3.3, §4). Every namespace is additive: the
// compiled-in defaults are the safe ones, a v17 document receives the namespace
// on load and the migration record names it, and host behaviour changes only
// after an operator enables the module.
//
// The edge_proxy namespace (Module E) lives in module_settings_v61_edge.go so
// each file stays inside the 500-line bound; it follows the same contract.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/visiongaiatechnology/gedefense/control/internal/webposture"
)

// Migration records for the v17 -> v18 upgrade. One entry per namespace, so the
// operator sees exactly what the upgrade added on their behalf.
const (
	webExposureMigrationNote = "web_exposure namespace added with enabled=true (read-only sensor) and probe_loopback_alpn=true: only local /proc+ELF/configuration discovery and a loopback ALPN probe run; no host behaviour changes (§3.3, §4A)"
	workerGuardMigrationNote = "worker_guard namespace added with enabled=false: no crash source is subscribed, no strict Titan cgroup scope is applied and host behaviour is unchanged until an operator enables it (§3.3, §4B)"
	tlsSensorMigrationNote   = "tls_sensor namespace added with enabled=false and alert_only=true: no AF_PACKET capture and no flow snapshot run and host behaviour is unchanged until an operator enables it (§3.3, §4C)"
	lpeGuardMigrationNote    = "lpe_guard namespace added with enabled=false: no socket policy, no StyX profile and no hardening change is applied until an operator enables it (§3.3, §4D)"
)

// ----------------------------------------------------------------- Module A

// WebExposureFabricSettings is the Module A operator namespace. The sensor is
// read-only by default: it observes /proc, the server binaries, the configured
// configuration roots and (on request) probes loopback.
type WebExposureFabricSettings struct {
	Enabled             bool            `json:"enabled"`
	ProbeLoopbackALPN   bool            `json:"probe_loopback_alpn"`
	ProbeTimeoutSeconds int             `json:"probe_timeout_seconds"`
	ConfigRoots         []string        `json:"config_roots"`
	ExtraAdvisoriesJSON json.RawMessage `json:"extra_advisories_json"`
	MaxServers          int             `json:"max_servers"`
	ScanIntervalSeconds int             `json:"scan_interval_seconds"`
}

func defaultWebExposureFabricSettings() WebExposureFabricSettings {
	return WebExposureFabricSettings{
		Enabled:             true,
		ProbeLoopbackALPN:   true,
		ProbeTimeoutSeconds: 3,
		ConfigRoots: []string{
			"/etc/nginx", "/www/server/nginx/conf", "/www/server/panel/vhost/nginx",
			"/etc/apache2", "/etc/httpd",
		},
		ExtraAdvisoriesJSON: json.RawMessage(`[]`),
		MaxServers:          32,
		ScanIntervalSeconds: 60,
	}
}

func cloneWebExposureFabricSettings(in WebExposureFabricSettings) WebExposureFabricSettings {
	out := in
	out.ConfigRoots = append(make([]string, 0, len(in.ConfigRoots)), in.ConfigRoots...)
	if in.ExtraAdvisoriesJSON != nil {
		out.ExtraAdvisoriesJSON = append(json.RawMessage{}, in.ExtraAdvisoriesJSON...)
	}
	return out
}

func effectiveWebExposureSettings(settings RuntimeSettings) WebExposureFabricSettings {
	if settings.WebExposure != nil {
		return cloneWebExposureFabricSettings(*settings.WebExposure)
	}
	return defaultWebExposureFabricSettings()
}

func webExposureDefaults(defaults RuntimeSettings) WebExposureFabricSettings {
	if defaults.WebExposure != nil {
		return cloneWebExposureFabricSettings(*defaults.WebExposure)
	}
	return defaultWebExposureFabricSettings()
}

func validateWebExposureFabricSettings(in *WebExposureFabricSettings) error {
	if in == nil {
		return errors.New("web exposure settings are required")
	}
	if in.ProbeTimeoutSeconds < 1 || in.ProbeTimeoutSeconds > 10 {
		return errors.New("web exposure probe_timeout_seconds must be between 1 and 10")
	}
	if in.MaxServers < 8 || in.MaxServers > 128 {
		return errors.New("web exposure max_servers must be between 8 and 128")
	}
	if in.ScanIntervalSeconds < 15 || in.ScanIntervalSeconds > 3600 {
		return errors.New("web exposure scan_interval_seconds must be between 15 and 3600")
	}
	if len(in.ConfigRoots) > 32 {
		return errors.New("web exposure config_roots exceeds 32 entries")
	}
	seen := make(map[string]struct{}, len(in.ConfigRoots))
	roots := make([]string, 0, len(in.ConfigRoots))
	for _, root := range in.ConfigRoots {
		root = strings.TrimSpace(root)
		if root == "" || !strings.HasPrefix(root, "/") || strings.ContainsAny(root, "\x00\r\n") || len(root) > 512 {
			return fmt.Errorf("web exposure config root %q must be an absolute, single-line path", root)
		}
		root = strings.TrimSuffix(root, "/")
		if _, dup := seen[root]; dup {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	in.ConfigRoots = roots
	if _, err := webposture.ParseExtraAdvisories(in.ExtraAdvisoriesJSON); err != nil {
		return fmt.Errorf("web exposure extra_advisories_json: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------- Module B

// WorkerGuardFabricSettings is the Module B operator namespace.
type WorkerGuardFabricSettings struct {
	Enabled            bool     `json:"enabled"`
	Comms              []string `json:"comms"`
	UIDs               []uint32 `json:"uids"`
	ExcludeUnits       []string `json:"exclude_units"`
	StormThreshold     int      `json:"storm_threshold"`
	StormWindowSeconds int      `json:"storm_window_seconds"`
	CorrelatePeers     bool     `json:"correlate_peers"`
	StrictExec         bool     `json:"strict_exec"`
	StrictMmap         bool     `json:"strict_mmap"`
	AutoApplyStrict    bool     `json:"auto_apply_strict"`
}

func defaultWorkerGuardFabricSettings() WorkerGuardFabricSettings {
	return WorkerGuardFabricSettings{
		Enabled:            false,
		Comms:              []string{"nginx", "apache2", "httpd", "php-fpm"},
		UIDs:               []uint32{},
		ExcludeUnits:       []string{"systemd", "master", "php-fpm: master"},
		StormThreshold:     3,
		StormWindowSeconds: 60,
		CorrelatePeers:     true,
		StrictExec:         false,
		StrictMmap:         false,
		AutoApplyStrict:    false,
	}
}

func cloneWorkerGuardFabricSettings(in WorkerGuardFabricSettings) WorkerGuardFabricSettings {
	out := in
	out.Comms = append(make([]string, 0, len(in.Comms)), in.Comms...)
	out.UIDs = append(make([]uint32, 0, len(in.UIDs)), in.UIDs...)
	out.ExcludeUnits = append(make([]string, 0, len(in.ExcludeUnits)), in.ExcludeUnits...)
	return out
}

func effectiveWorkerGuardSettings(settings RuntimeSettings) WorkerGuardFabricSettings {
	if settings.WorkerGuard != nil {
		return cloneWorkerGuardFabricSettings(*settings.WorkerGuard)
	}
	return defaultWorkerGuardFabricSettings()
}

func workerGuardDefaults(defaults RuntimeSettings) WorkerGuardFabricSettings {
	if defaults.WorkerGuard != nil {
		return cloneWorkerGuardFabricSettings(*defaults.WorkerGuard)
	}
	return defaultWorkerGuardFabricSettings()
}

func validateWorkerGuardFabricSettings(in *WorkerGuardFabricSettings) error {
	if in == nil {
		return errors.New("worker guard settings are required")
	}
	if in.StormThreshold < 2 || in.StormThreshold > 100 {
		return errors.New("worker guard storm_threshold must be between 2 and 100")
	}
	if in.StormWindowSeconds < 10 || in.StormWindowSeconds > 600 {
		return errors.New("worker guard storm_window_seconds must be between 10 and 600")
	}
	if len(in.Comms) > 32 {
		return errors.New("worker guard comms exceeds 32 entries")
	}
	seenComms := make(map[string]struct{}, len(in.Comms))
	comms := make([]string, 0, len(in.Comms))
	for _, comm := range in.Comms {
		comm = strings.TrimSpace(comm)
		if comm == "" || len(comm) > 15 || strings.ContainsAny(comm, "\x00\r\n \t") {
			return fmt.Errorf("worker guard comm %q must be 1-15 printable bytes", comm)
		}
		if _, dup := seenComms[comm]; dup {
			continue
		}
		seenComms[comm] = struct{}{}
		comms = append(comms, comm)
	}
	in.Comms = comms
	if len(in.UIDs) > 256 {
		return errors.New("worker guard uids exceeds 256 entries")
	}
	seenUIDs := make(map[uint32]struct{}, len(in.UIDs))
	uids := make([]uint32, 0, len(in.UIDs))
	for _, uid := range in.UIDs {
		if _, dup := seenUIDs[uid]; dup {
			continue
		}
		seenUIDs[uid] = struct{}{}
		uids = append(uids, uid)
	}
	in.UIDs = uids
	if len(in.ExcludeUnits) > 32 {
		return errors.New("worker guard exclude_units exceeds 32 entries")
	}
	units := make([]string, 0, len(in.ExcludeUnits))
	for _, unit := range in.ExcludeUnits {
		unit = strings.TrimSpace(unit)
		if unit == "" || len(unit) > 64 || strings.ContainsAny(unit, "\x00\r\n") {
			return fmt.Errorf("worker guard exclude unit %q must be 1-64 single-line characters", unit)
		}
		units = append(units, unit)
	}
	in.ExcludeUnits = units
	if (in.StrictExec || in.StrictMmap || in.AutoApplyStrict) && !in.Enabled {
		return errors.New("worker guard strict scope requires the module to be enabled")
	}
	if in.AutoApplyStrict && !in.StrictExec && !in.StrictMmap {
		return errors.New("worker guard auto_apply_strict requires strict_exec or strict_mmap")
	}
	return nil
}

// ----------------------------------------------------------------- Module C

// TLSSensorFabricSettings is the Module C operator namespace.
type TLSSensorFabricSettings struct {
	Enabled            bool     `json:"enabled"`
	Interfaces         []string `json:"interfaces"`
	Ports              []uint16 `json:"ports"`
	MaxPayloadBytes    int      `json:"max_payload_bytes"`
	MaxTrackedFlows    int      `json:"max_tracked_flows"`
	RxThresholdBytes   int64    `json:"rx_threshold_bytes"`
	TxRatio            int      `json:"tx_ratio"`
	AvgPktLenBytes     int      `json:"avg_pkt_len_bytes"`
	MinPPSRatio        int      `json:"min_pps_ratio"`
	AlertOnly          bool     `json:"alert_only"`
	ThrottleTTLSeconds int      `json:"throttle_ttl_seconds"`
}

func defaultTLSSensorFabricSettings() TLSSensorFabricSettings {
	return TLSSensorFabricSettings{
		Enabled: false, Interfaces: []string{}, Ports: []uint16{443, 8443},
		MaxPayloadBytes: 1536, MaxTrackedFlows: 4096,
		RxThresholdBytes: 256 << 20, TxRatio: 4, AvgPktLenBytes: 240, MinPPSRatio: 8,
		AlertOnly: true, ThrottleTTLSeconds: 900,
	}
}

func cloneTLSSensorFabricSettings(in TLSSensorFabricSettings) TLSSensorFabricSettings {
	out := in
	out.Interfaces = append(make([]string, 0, len(in.Interfaces)), in.Interfaces...)
	out.Ports = append(make([]uint16, 0, len(in.Ports)), in.Ports...)
	return out
}

func effectiveTLSSensorSettings(settings RuntimeSettings) TLSSensorFabricSettings {
	if settings.TLSSensor != nil {
		return cloneTLSSensorFabricSettings(*settings.TLSSensor)
	}
	return defaultTLSSensorFabricSettings()
}

func tlsSensorDefaults(defaults RuntimeSettings) TLSSensorFabricSettings {
	if defaults.TLSSensor != nil {
		return cloneTLSSensorFabricSettings(*defaults.TLSSensor)
	}
	return defaultTLSSensorFabricSettings()
}

func validateTLSSensorFabricSettings(in *TLSSensorFabricSettings) error {
	if in == nil {
		return errors.New("tls sensor settings are required")
	}
	if len(in.Ports) == 0 || len(in.Ports) > 8 {
		return errors.New("tls sensor ports must contain 1-8 entries")
	}
	if err := validatePortList("tls sensor ports", in.Ports); err != nil {
		return err
	}
	if len(in.Interfaces) > 8 {
		return errors.New("tls sensor interfaces exceeds 8 entries")
	}
	for _, name := range in.Interfaces {
		if name == "" || len(name) > 15 || strings.ContainsAny(name, "\x00\r\n/ \t") {
			return fmt.Errorf("tls sensor interface %q is not a valid interface name", name)
		}
	}
	if in.MaxPayloadBytes < 512 || in.MaxPayloadBytes > 2048 {
		return errors.New("tls sensor max_payload_bytes must be between 512 and 2048")
	}
	if in.MaxTrackedFlows < 256 || in.MaxTrackedFlows > 65536 {
		return errors.New("tls sensor max_tracked_flows must be between 256 and 65536")
	}
	if in.RxThresholdBytes < 64<<20 || in.RxThresholdBytes > 8<<30 {
		return errors.New("tls sensor rx_threshold_bytes must be between 64 MiB and 8 GiB")
	}
	if in.TxRatio < 2 || in.TxRatio > 64 {
		return errors.New("tls sensor tx_ratio must be between 2 and 64")
	}
	if in.AvgPktLenBytes < 64 || in.AvgPktLenBytes > 512 {
		return errors.New("tls sensor avg_pkt_len_bytes must be between 64 and 512")
	}
	if in.MinPPSRatio < 2 || in.MinPPSRatio > 1000 {
		return errors.New("tls sensor min_pps_ratio must be between 2 and 1000")
	}
	if in.ThrottleTTLSeconds < 60 || in.ThrottleTTLSeconds > 86400 {
		return errors.New("tls sensor throttle_ttl_seconds must be between 60 and 86400")
	}
	return nil
}

// ----------------------------------------------------------------- Module D

// LPEGuardFabricSettings is the Module D operator namespace.
type LPEGuardFabricSettings struct {
	Enabled          bool     `json:"enabled"`
	DenyAFPacket     bool     `json:"deny_af_packet"`
	DenyAFTIPC       bool     `json:"deny_af_tipc"`
	DenyAFVSock      bool     `json:"deny_af_vsock"`
	DenySCTP         bool     `json:"deny_sctp"`
	DenyDCCP         bool     `json:"deny_dccp"`
	DenyRDS          bool     `json:"deny_rds"`
	StyxProfile      bool     `json:"styx_profile"`
	StyxBackendCIDRs []string `json:"styx_backend_cidrs"`
	StyxDnsServers   []string `json:"styx_dns_servers"`
	EnforceASLR      bool     `json:"enforce_aslr"`
	BlockLPEModules  bool     `json:"block_lpe_modules"`
}

func defaultLPEGuardFabricSettings() LPEGuardFabricSettings {
	return LPEGuardFabricSettings{
		Enabled:      false,
		DenyAFPacket: true, DenyAFTIPC: true, DenyAFVSock: true,
		DenySCTP: true, DenyDCCP: true, DenyRDS: true,
		StyxProfile: false, StyxBackendCIDRs: []string{}, StyxDnsServers: []string{},
		EnforceASLR: true, BlockLPEModules: true,
	}
}

func cloneLPEGuardFabricSettings(in LPEGuardFabricSettings) LPEGuardFabricSettings {
	out := in
	out.StyxBackendCIDRs = append(make([]string, 0, len(in.StyxBackendCIDRs)), in.StyxBackendCIDRs...)
	out.StyxDnsServers = append(make([]string, 0, len(in.StyxDnsServers)), in.StyxDnsServers...)
	return out
}

func effectiveLPEGuardSettings(settings RuntimeSettings) LPEGuardFabricSettings {
	if settings.LPEGuard != nil {
		return cloneLPEGuardFabricSettings(*settings.LPEGuard)
	}
	return defaultLPEGuardFabricSettings()
}

func lpeGuardDefaults(defaults RuntimeSettings) LPEGuardFabricSettings {
	if defaults.LPEGuard != nil {
		return cloneLPEGuardFabricSettings(*defaults.LPEGuard)
	}
	return defaultLPEGuardFabricSettings()
}

func validateLPEGuardFabricSettings(in *LPEGuardFabricSettings) error {
	if in == nil {
		return errors.New("lpe guard settings are required")
	}
	backend, err := canonicalCIDRList("lpe guard styx_backend_cidrs", in.StyxBackendCIDRs, 64)
	if err != nil {
		return err
	}
	in.StyxBackendCIDRs = backend
	dns, err := canonicalCIDRList("lpe guard styx_dns_servers", in.StyxDnsServers, 32)
	if err != nil {
		return err
	}
	in.StyxDnsServers = dns
	if in.StyxProfile && !in.Enabled {
		return errors.New("lpe guard styx_profile requires the module to be enabled")
	}
	if in.StyxProfile && !in.DenyAFPacket && !in.DenyAFTIPC && !in.DenyAFVSock && !in.DenySCTP && !in.DenyDCCP && !in.DenyRDS {
		// A profile with no deny bit and no explicit backend is a no-op; refuse
		// it instead of persisting an effect the operator would not get.
		if len(backend) == 0 {
			return errors.New("lpe guard styx_profile with no deny bit and no backend CIDR has no effect")
		}
	}
	return nil
}

// canonicalCIDRList validates and canonicalises a bounded CIDR/address list.
func canonicalCIDRList(name string, values []string, limit int) ([]string, error) {
	if len(values) > limit {
		return nil, fmt.Errorf("%s exceeds %d entries", name, limit)
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, addrErr := netip.ParseAddr(raw)
			if addrErr != nil {
				return nil, fmt.Errorf("%s entry %q is not a CIDR or address", name, raw)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		canonical := prefix.Masked().String()
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}
