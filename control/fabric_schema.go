// STATUS: DIAMANT VGT SUPREME
package main

import (
	"net/http"
	"sort"
	"strings"
)

// The Fabric Settings schema registry is the single authoritative description
// of every administrable setting. It carries the server-side validation
// bounds, the apply class, the risk class and the operator-facing description.
// The dashboard renders its Settings surface from this registry, so the UI can
// never drift from the backend contract and can never invent a setting.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, section 6 and
// section 45 (UI contract tests).

// Fabric apply classes (plan section 7).
const (
	FabricApplyHot     = "HOT"
	FabricApplyReload  = "RELOAD"
	FabricApplyDrain   = "DRAIN"
	FabricApplyRestart = "RESTART"
	FabricApplyReboot  = "REBOOT"
)

// Fabric risk levels (plan section 11).
const (
	FabricRiskLow      = "low"
	FabricRiskMedium   = "medium"
	FabricRiskHigh     = "high"
	FabricRiskCritical = "critical"
)

// Fabric value types drive server-side decoding and client-side rendering.
const (
	FabricTypeInteger = "integer"
	FabricTypeBoolean = "boolean"
	FabricTypeEnum    = "enum"
	FabricTypeText    = "text"
	FabricTypePath    = "path"
	FabricTypePorts   = "ports"
	FabricTypeList    = "list"
	FabricTypeJSON    = "json"
)

type FabricSettingMetadata struct {
	Key          string   `json:"key"`
	Module       string   `json:"module"`
	Group        string   `json:"group"`
	Label        string   `json:"label"`
	Type         string   `json:"type"`
	Unit         string   `json:"unit,omitempty"`
	Minimum      *int     `json:"minimum,omitempty"`
	Maximum      *int     `json:"maximum,omitempty"`
	Enum         []string `json:"enum,omitempty"`
	Default      any      `json:"default,omitempty"`
	ApplyClass   string   `json:"apply_class"`
	Risk         string   `json:"risk"`
	Description  string   `json:"description"`
	RequiresWait bool     `json:"requires_management_survival_check,omitempty"`
}

type fabricSettingDefinition struct {
	module string
	group  string
	key    string
	label  string
	kind   string
	unit   string
	def    any
	class  string
	risk   string
	desc   string
	min    *int
	max    *int
	enum   []string
}

func intPtr(value int) *int { return &value }

var fabricSettingDefinitions = []fabricSettingDefinition{
	// ---------------------------------------------------------------- kinetic
	{module: "kinetic", group: "Engine & Response", key: "enabled", label: "Kinetic Engine", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Enable live ingress analysis. Disabling stops the runtime sensor loop and automatic Kinetic response."},
	{module: "kinetic", group: "Engine & Response", key: "enforcement_mode", label: "Kinetic Mode", kind: FabricTypeEnum, def: "observe", class: FabricApplyHot, risk: FabricRiskHigh,
		enum: []string{"observe", "contain", "block"}, desc: "Observe detects only. Contain records containment state. Block may apply verified kernel drops when the global release gates permit it."},
	{module: "kinetic", group: "Engine & Response", key: "auto_contain_single_ip", label: "Auto-Contain Single IPs", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Allow verified /32 and /128 automatic containment."},
	{module: "kinetic", group: "Engine & Response", key: "ban_ttl_seconds", label: "Default Ban TTL", kind: FabricTypeInteger, unit: "s", def: 900, min: intPtr(60), max: intPtr(604800), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Base TTL for Kinetic network containment before repeat-offender escalation."},
	{module: "kinetic", group: "Engine & Response", key: "max_strikes_per_sec", label: "Max Auto Actions / Second", kind: FabricTypeInteger, def: 20, min: intPtr(1), max: intPtr(10000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Response token-bucket ceiling protecting the control plane from reaction storms."},
	{module: "kinetic", group: "Rate, Flood & Portscan", key: "ip_threshold", label: "IP Attempt Threshold", kind: FabricTypeInteger, def: 40, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Per-source attempt threshold inside the primary rolling window."},
	{module: "kinetic", group: "Rate, Flood & Portscan", key: "velocity_limit", label: "Velocity Limit", kind: FabricTypeInteger, unit: "/s", def: 15, min: intPtr(1), max: intPtr(50000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Fast burst / flash detection threshold per second."},
	{module: "kinetic", group: "Rate, Flood & Portscan", key: "syn_threshold", label: "SYN Flood Threshold", kind: FabricTypeInteger, def: 60, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Minimum SYN attempts inside the SYN-flood window before ratio evaluation."},
	{module: "kinetic", group: "Rate, Flood & Portscan", key: "syn_ack_ratio", label: "SYN : ACK Ratio", kind: FabricTypeInteger, def: 8, min: intPtr(1), max: intPtr(100), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Required SYN imbalance. Higher values are more conservative."},
	{module: "kinetic", group: "Rate, Flood & Portscan", key: "portscan_threshold", label: "Distinct Ports", kind: FabricTypeInteger, def: 12, min: intPtr(2), max: intPtr(65535), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Distinct destination ports required for port-scan correlation."},
	{module: "kinetic", group: "Rate, Flood & Portscan", key: "low_slow_min_seconds", label: "Low-and-Slow Minimum", kind: FabricTypeInteger, unit: "s", def: 300, min: intPtr(10), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Minimum observation duration for slow distributed port scanning."},
	{module: "kinetic", group: "Botnet / Subnet Correlation", key: "range_threshold", label: "IPv4 /24 Threshold", kind: FabricTypeInteger, def: 25, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Aggregated attempts inside one /24 required for subnet correlation."},
	{module: "kinetic", group: "Botnet / Subnet Correlation", key: "subnet_min_sources", label: "IPv4 /24 Min Sources", kind: FabricTypeInteger, def: 4, min: intPtr(2), max: intPtr(1024), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Independent source addresses required before /24 containment becomes eligible."},
	{module: "kinetic", group: "Botnet / Subnet Correlation", key: "auto_contain_ipv4_subnet", label: "Auto-Contain IPv4 /24", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Allow automatic /24 containment. A false positive can affect multiple hosts sharing the subnet."},
	{module: "kinetic", group: "Botnet / Subnet Correlation", key: "ipv6_sub_threshold", label: "IPv6 /64 Threshold", kind: FabricTypeInteger, def: 25, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Aggregated attempts inside one /64 required for subnet correlation."},
	{module: "kinetic", group: "Botnet / Subnet Correlation", key: "ipv6_subnet_min_sources", label: "IPv6 /64 Min Sources", kind: FabricTypeInteger, def: 4, min: intPtr(2), max: intPtr(1024), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Independent IPv6 source addresses required before /64 containment becomes eligible."},
	{module: "kinetic", group: "Botnet / Subnet Correlation", key: "auto_contain_ipv6_subnet", label: "Auto-Contain IPv6 /64", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Allow automatic /64 containment."},
	{module: "kinetic", group: "Botnet / Subnet Correlation", key: "wide_range_threshold", label: "IPv4 /16 Campaign Threshold", kind: FabricTypeInteger, def: 120, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Campaign correlation only. GeDefense never automatically blocks /16 from this control."},
	{module: "kinetic", group: "Botnet / Subnet Correlation", key: "wide_min_sources", label: "IPv4 /16 Min Sources", kind: FabricTypeInteger, def: 12, min: intPtr(2), max: intPtr(4096), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Source diversity required for /16 campaign detection."},
	{module: "kinetic", group: "Service Classification", key: "service_ports_web", label: "Public Web Ports", kind: FabricTypePorts, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "TCP service ports classified as public web."},
	{module: "kinetic", group: "Service Classification", key: "service_ports_mail", label: "Mail Ports", kind: FabricTypePorts, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "TCP service ports classified as mail services."},
	{module: "kinetic", group: "Service Classification", key: "service_ports_admin", label: "Admin / Sensitive Ports", kind: FabricTypePorts, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Ports receiving a higher scan-risk context."},
	{module: "kinetic", group: "Service Classification", key: "max_tracking_ips", label: "Max Tracked Sources", kind: FabricTypeInteger, def: 65536, min: intPtr(100), max: intPtr(500000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bounded source-state capacity. Lowering the bound can evict existing entries immediately."},

	// ---------------------------------------------------------------- network
	{module: "network", group: "CIDR Policy Limits", key: "network.default_ttl_seconds", label: "Default Manual TTL", kind: FabricTypeInteger, unit: "s", def: 3600, min: intPtr(60), max: intPtr(2592000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "TTL applied to manual CIDR policy entries when no explicit TTL is supplied."},
	{module: "network", group: "CIDR Policy Limits", key: "network.max_ttl_seconds", label: "Maximum TTL", kind: FabricTypeInteger, unit: "s", def: 604800, min: intPtr(60), max: intPtr(2592000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Hard ceiling for every automatic and manual containment TTL."},
	{module: "network", group: "CIDR Policy Limits", key: "network.max_block_entries", label: "Maximum Block Entries", kind: FabricTypeInteger, def: 250000, min: intPtr(100), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Userspace policy capacity shared by manual, XDR and Kinetic containment."},
	{module: "network", group: "CIDR Policy Limits", key: "network.strict_asn_drop", label: "Strict ASN Drop", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Keeps the strict ASN policy toggle. ASN automation remains constrained by signed policy and response gates."},
	{module: "network", group: "Management Survival", key: "management_allowlist", label: "Management Allowlist", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "One IPv4/IPv6 address or CIDR per entry. At least one entry is mandatory. Removing entries is permitted only in Observe/Degraded and is synchronised transactionally with the kernel."},

	// ------------------------------------------------------------- protection
	{module: "protection", group: "Fabric Safety", key: "auto_degrade", label: "Auto-Degrade", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Automatically fall back to a safer release phase when required health gates fail."},
	{module: "protection", group: "Fabric Safety", key: "gates.minimum_observe_seconds", label: "Minimum Observe", kind: FabricTypeInteger, unit: "s", def: 900, min: intPtr(0), max: intPtr(604800), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Minimum time in Observe before promotion becomes eligible."},
	{module: "protection", group: "Fabric Safety", key: "gates.minimum_canary_seconds", label: "Minimum Canary", kind: FabricTypeInteger, unit: "s", def: 900, min: intPtr(0), max: intPtr(604800), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Minimum canary soak before full enforcement becomes eligible."},
	{module: "protection", group: "Fabric Safety", key: "gates.core_failure_threshold", label: "Core Failure Threshold", kind: FabricTypeInteger, def: 3, min: intPtr(1), max: intPtr(100), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Consecutive authenticated Core failures before the release gate degrades."},
	{module: "protection", group: "Fabric Safety", key: "gates.max_evaluation_drop_permille", label: "Max Evaluation Drops", kind: FabricTypeInteger, unit: "\u2030", def: 50, min: intPtr(0), max: intPtr(1000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Maximum XDR evaluation-drop ratio accepted by readiness."},

	// -------------------------------------------------------------------- xdr
	{module: "xdr", group: "Engine & Sensors", key: "enabled", label: "XDR Engine", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Disabling XDR is allowed only in Observe/Degraded."},
	{module: "xdr", group: "Engine & Sensors", key: "network_sensor_enabled", label: "Network Correlation", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Correlate process lineage with observed network connections."},
	{module: "xdr", group: "Engine & Sensors", key: "behavior_enabled", label: "Adaptive Behavior", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Adaptive per-process behaviour learning and anomaly scoring."},
	{module: "xdr", group: "Engine & Sensors", key: "advanced.malware_correlation", label: "Malware \u2192 XDR Correlation", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Kernel malware blocking remains independent; this controls correlation into XDR incidents."},
	{module: "xdr", group: "Scanning & Pipeline", key: "scan_interval_millis", label: "Process Scan Interval", kind: FabricTypeInteger, unit: "ms", def: 750, min: intPtr(100), max: intPtr(60000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Interval between process-table evaluations."},
	{module: "xdr", group: "Scanning & Pipeline", key: "network_interval_seconds", label: "Network Scan Interval", kind: FabricTypeInteger, unit: "s", def: 3, min: intPtr(1), max: intPtr(300), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Interval between network connection samples."},
	{module: "xdr", group: "Scanning & Pipeline", key: "advanced.max_evaluations_per_scan", label: "Max Evaluations / Scan", kind: FabricTypeInteger, def: 4096, min: intPtr(128), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bounded evaluation budget per scan pass."},
	{module: "xdr", group: "Scanning & Pipeline", key: "advanced.worker_count", label: "Worker Count", kind: FabricTypeInteger, def: 4, min: intPtr(1), max: intPtr(64), class: FabricApplyRestart, risk: FabricRiskMedium,
		desc: "Restart required. The active worker pool is created at service start."},
	{module: "xdr", group: "Scanning & Pipeline", key: "advanced.queue_capacity", label: "Queue Capacity", kind: FabricTypeInteger, def: 2048, min: intPtr(128), max: intPtr(131072), class: FabricApplyRestart, risk: FabricRiskMedium,
		desc: "Restart required. Existing queues are never silently replaced while XDR is live."},
	{module: "xdr", group: "Scanning & Pipeline", key: "advanced.dedupe_seconds", label: "Incident Dedupe", kind: FabricTypeInteger, unit: "s", def: 300, min: intPtr(0), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Window in which identical rule evidence is folded into one incident."},
	{module: "xdr", group: "Decision Scores & Response", key: "alert_score", label: "Alert Score", kind: FabricTypeInteger, def: 40, min: intPtr(1), max: intPtr(248), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Must remain below Contain and Kill."},
	{module: "xdr", group: "Decision Scores & Response", key: "contain_score", label: "Contain Score", kind: FabricTypeInteger, def: 80, min: intPtr(2), max: intPtr(249), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Score at which network containment becomes eligible while the release gates permit it."},
	{module: "xdr", group: "Decision Scores & Response", key: "kill_score", label: "Kill Score", kind: FabricTypeInteger, def: 120, min: intPtr(3), max: intPtr(250), class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "A kill still requires multiple structurally kill-eligible signals. The UI cannot grant kill eligibility to arbitrary rules."},
	{module: "xdr", group: "Decision Scores & Response", key: "advanced.containment_ttl_seconds", label: "Network Containment TTL", kind: FabricTypeInteger, unit: "s", def: 900, min: intPtr(60), max: intPtr(604800), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "TTL of XDR-initiated network containment."},
	{module: "xdr", group: "Decision Scores & Response", key: "advanced.max_command_bytes", label: "Max Command Bytes", kind: FabricTypeInteger, def: 8192, min: intPtr(256), max: intPtr(1048576), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Maximum command line length read from the kernel event stream."},
	{module: "xdr", group: "Decision Scores & Response", key: "advanced.command_preview_bytes", label: "Command Preview Bytes", kind: FabricTypeInteger, def: 320, min: intPtr(64), max: intPtr(1048576), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Redacted command preview length. Must not exceed Max Command Bytes."},
	{module: "xdr", group: "Behavior Learning", key: "advanced.behavior_warmup_samples", label: "Warmup Samples", kind: FabricTypeInteger, def: 24, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Samples required before a behaviour profile becomes authoritative."},
	{module: "xdr", group: "Behavior Learning", key: "advanced.behavior_zscore_milli", label: "Z-Score \u00d71000", kind: FabricTypeInteger, def: 3500, min: intPtr(1000), max: intPtr(20000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "3500 equals a z-score of 3.5."},
	{module: "xdr", group: "Behavior Learning", key: "advanced.behavior_min_connections", label: "Minimum Connections", kind: FabricTypeInteger, def: 8, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Minimum observed connections before connection-fanout anomalies are reported."},
	{module: "xdr", group: "Behavior Learning", key: "advanced.behavior_exec_burst", label: "Exec Burst Threshold", kind: FabricTypeInteger, unit: "/min", def: 12, min: intPtr(2), max: intPtr(10000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Executions per minute from one executable before a burst anomaly is raised."},
	{module: "xdr", group: "Behavior Learning", key: "advanced.behavior_max_profiles", label: "Maximum Profiles", kind: FabricTypeInteger, def: 4096, min: intPtr(64), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bounded behaviour profile capacity. Lowering the bound evicts profiles safely."},
	{module: "xdr", group: "Behavior Learning", key: "advanced.behavior_max_ports", label: "Ports / Profile", kind: FabricTypeInteger, def: 256, min: intPtr(16), max: intPtr(65535), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Ports retained per behaviour profile."},
	{module: "xdr", group: "Process Scope", key: "advanced.allow_processes", label: "Allowed Executables", kind: FabricTypeList, class: FabricApplyReload, risk: FabricRiskHigh,
		desc: "Exact normalised executable paths excluded from normal XDR evaluation."},
	{module: "xdr", group: "Process Scope", key: "advanced.protected_paths", label: "Protected Paths", kind: FabricTypeList, class: FabricApplyRestart, risk: FabricRiskHigh,
		desc: "Restart required because integrity watchers are constructed at startup."},
	{module: "xdr", group: "Rule Modules", key: "enabled_rule_modules", label: "Enabled Modules", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Supported modules: baseline, command, lineage, masquerading, origin, threat-intel. Rule wiring changes are restricted to Observe/Degraded."},
	{module: "xdr", group: "Rule Modules", key: "advanced.rule_overrides", label: "Built-in Rule Overrides", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Array of {id, enabled, score}. Overrides cannot create new kill eligibility."},
	{module: "xdr", group: "Rule Modules", key: "custom_rules", label: "Custom RE2 Rules", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Operator rules remain alert-only evidence and never independently authorise destructive response."},

	// --------------------------------------------------------------------- l7
	{module: "l7", group: "Engine", key: "enabled", label: "Application Defense Engine", kind: FabricTypeBoolean, def: false, class: FabricApplyRestart, risk: FabricRiskHigh,
		desc: "Restart required: the L7 listener lifecycle is bound to service start. Changes are accepted only in Observe/Degraded."},
	{module: "l7", group: "Engine", key: "mode", label: "L7 Mode", kind: FabricTypeEnum, def: "observe", class: FabricApplyHot, risk: FabricRiskHigh,
		enum: []string{"observe", "block"}, desc: "Observe records findings only. Block may deny requests once the global release gate is in Enforce and healthy."},
	{module: "l7", group: "Engine", key: "max_concurrent", label: "Max Concurrent Inspections", kind: FabricTypeInteger, def: 16, min: intPtr(1), max: intPtr(1024), class: FabricApplyRestart, risk: FabricRiskMedium,
		desc: "Restart required: admission and inspection slots are sized at start."},
	{module: "l7", group: "Engine", key: "request_timeout_millis", label: "Inspection Timeout", kind: FabricTypeInteger, unit: "ms", def: 750, min: intPtr(50), max: intPtr(10000), class: FabricApplyRestart, risk: FabricRiskMedium,
		desc: "Restart required: HTTP server and per-request timeouts are fixed at listener creation."},
	{module: "l7", group: "Engine", key: "socket", label: "Inspection Socket", kind: FabricTypePath, class: FabricApplyRestart, risk: FabricRiskCritical,
		desc: "Restart required. Changes are accepted only in Observe/Degraded."},
	{module: "l7", group: "Request Limits", key: "max_envelope_bytes", label: "Max Envelope Bytes", kind: FabricTypeInteger, def: 3145728, min: intPtr(4096), max: intPtr(33554432), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Hard bound for the JSON inspection envelope accepted from the proxy sensor."},
	{module: "l7", group: "Request Limits", key: "max_body_bytes", label: "Max Body Bytes", kind: FabricTypeInteger, def: 2097152, min: intPtr(0), max: intPtr(16777216), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Maximum decoded request body retained for inspection."},
	{module: "l7", group: "Request Limits", key: "max_upload_bytes", label: "Max Upload Bytes", kind: FabricTypeInteger, def: 2097152, min: intPtr(0), max: intPtr(16777216), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Maximum single uploaded object handed to the Airlock inspector."},
	{module: "l7", group: "Request Limits", key: "max_uri_bytes", label: "Max URI Bytes", kind: FabricTypeInteger, def: 16384, min: intPtr(256), max: intPtr(1048576), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Maximum request URI length accepted for inspection."},
	{module: "l7", group: "Request Limits", key: "max_header_bytes", label: "Max Header Bytes", kind: FabricTypeInteger, def: 65536, min: intPtr(1024), max: intPtr(4194304), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Aggregate header byte budget for one inspected request."},
	{module: "l7", group: "Request Limits", key: "max_headers", label: "Max Header Count", kind: FabricTypeInteger, def: 128, min: intPtr(8), max: intPtr(4096), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Maximum number of request headers accepted."},
	{module: "l7", group: "Request Limits", key: "max_value_bytes", label: "Max Value Bytes", kind: FabricTypeInteger, def: 16384, min: intPtr(256), max: intPtr(1048576), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Maximum length of a single decoded inspection candidate."},
	{module: "l7", group: "Request Limits", key: "max_inspection_bytes", label: "Max Inspection Bytes", kind: FabricTypeInteger, def: 4194304, min: intPtr(4096), max: intPtr(67108864), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Aggregate decoded candidate budget for one inspection."},
	{module: "l7", group: "Request Limits", key: "max_decoded_values", label: "Max Decoded Values", kind: FabricTypeInteger, def: 4096, min: intPtr(16), max: intPtr(1048576), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Maximum number of decoded candidates retained per inspection."},
	{module: "l7", group: "Request Limits", key: "max_decode_depth", label: "Max Decode Depth", kind: FabricTypeInteger, def: 4, min: intPtr(1), max: intPtr(16), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Recursive decoding depth for nested encodings."},
	{module: "l7", group: "Request Limits", key: "max_json_depth", label: "Max JSON Depth", kind: FabricTypeInteger, def: 32, min: intPtr(1), max: intPtr(256), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Maximum JSON nesting evaluated in a request body."},
	{module: "l7", group: "Request Limits", key: "max_form_fields", label: "Max Form Fields", kind: FabricTypeInteger, def: 512, min: intPtr(1), max: intPtr(65536), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Maximum form, query or JSON values inspected in one request."},
	{module: "l7", group: "Request Limits", key: "max_multipart_parts", label: "Max Multipart Parts", kind: FabricTypeInteger, def: 64, min: intPtr(1), max: intPtr(4096), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Maximum multipart parts walked in one upload body."},
	{module: "l7", group: "Scores", key: "alert_score", label: "Alert Score", kind: FabricTypeInteger, def: 40, min: intPtr(1), max: intPtr(249), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Findings at or above this aggregated score are reported as observations. Must remain below the block score."},
	{module: "l7", group: "Scores", key: "block_score", label: "Block Score", kind: FabricTypeInteger, def: 90, min: intPtr(2), max: intPtr(250), class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Aggregated score at which a request becomes block-eligible when the mode and release gate allow it."},
	{module: "l7", group: "Client Rate Limiting", key: "client_rate_per_minute", label: "Requests / Minute", kind: FabricTypeInteger, def: 600, min: intPtr(1), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Per client and host request budget."},
	{module: "l7", group: "Client Rate Limiting", key: "client_rate_burst", label: "Burst", kind: FabricTypeInteger, def: 100, min: intPtr(1), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Token bucket depth for the per-client budget."},
	{module: "l7", group: "Client Rate Limiting", key: "max_tracked_clients", label: "Tracked Clients", kind: FabricTypeInteger, def: 65536, min: intPtr(64), max: intPtr(1000000), class: FabricApplyRestart, risk: FabricRiskMedium,
		desc: "Restart required: limiter shards are pre-sized from this bound."},
	{module: "l7", group: "Sensitive Path Limiting", key: "sensitive_rate_per_minute", label: "Per-Client Rate", kind: FabricTypeInteger, def: 30, min: intPtr(1), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Per client budget for sensitive routes."},
	{module: "l7", group: "Sensitive Path Limiting", key: "sensitive_rate_burst", label: "Per-Client Burst", kind: FabricTypeInteger, def: 10, min: intPtr(1), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Token bucket depth for the per-client sensitive-route budget."},
	{module: "l7", group: "Sensitive Path Limiting", key: "sensitive_global_rate_per_minute", label: "Global Rate", kind: FabricTypeInteger, def: 300, min: intPtr(1), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Global budget shared by all clients for one sensitive route."},
	{module: "l7", group: "Sensitive Path Limiting", key: "sensitive_global_rate_burst", label: "Global Burst", kind: FabricTypeInteger, def: 50, min: intPtr(1), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Token bucket depth for the global sensitive-route budget."},
	{module: "l7", group: "Sensitive Path Limiting", key: "sensitive_paths", label: "Sensitive Paths", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Absolute request paths receiving the stricter sensitive-route budget. Entries must start with '/' and must be free of query or fragment markers."},
	{module: "l7", group: "Peer Authentication", key: "require_peer_credentials", label: "Require Peer Credentials", kind: FabricTypeBoolean, def: false, class: FabricApplyRestart, risk: FabricRiskHigh,
		desc: "Restart required. Rejects inspection requests from peers without an allowed UID or GID."},
	{module: "l7", group: "Peer Authentication", key: "allowed_peer_uids", label: "Allowed UIDs", kind: FabricTypeList, class: FabricApplyRestart, risk: FabricRiskHigh,
		desc: "Restart required. Numeric UNIX user identifiers permitted to submit inspections."},
	{module: "l7", group: "Peer Authentication", key: "allowed_peer_gids", label: "Allowed GIDs", kind: FabricTypeList, class: FabricApplyRestart, risk: FabricRiskHigh,
		desc: "Restart required. Numeric UNIX group identifiers permitted to submit inspections."},
	{module: "l7", group: "Peer Authentication", key: "socket_group", label: "Socket Group", kind: FabricTypeText, class: FabricApplyRestart, risk: FabricRiskHigh,
		desc: "Restart required. Existing UNIX group owning the inspection socket."},
	{module: "l7", group: "Inline Edge", key: "inline_enabled", label: "Inline Edge Enabled", kind: FabricTypeBoolean, def: false, class: FabricApplyRestart, risk: FabricRiskCritical,
		desc: "Restart required. Enables the native inline request/response path."},
	{module: "l7", group: "Inline Edge", key: "inline_socket", label: "Edge Socket", kind: FabricTypePath, class: FabricApplyRestart, risk: FabricRiskCritical,
		desc: "Restart required. Listener for the inline edge path."},
	{module: "l7", group: "Inline Edge", key: "inline_upstream", label: "Upstream", kind: FabricTypeText, class: FabricApplyRestart, risk: FabricRiskCritical,
		desc: "Restart required. Only loopback and link-local HTTP upstreams are accepted."},
	{module: "l7", group: "Inline Edge", key: "inline_max_response_bytes", label: "Max Response Bytes", kind: FabricTypeInteger, def: 65536, min: intPtr(0), max: intPtr(16777216), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Maximum response prefix inspected for information disclosure."},
	{module: "l7", group: "TLS Defense", key: "tls_enabled", label: "TLS Sensor", kind: FabricTypeBoolean, def: true, class: FabricApplyRestart, risk: FabricRiskHigh,
		desc: "Restart required: the TLS inspection engine is constructed at service start. Disabling removes TLS coverage from readiness."},
	{module: "l7", group: "TLS Defense", key: "tls_allowed_domains", label: "Allowed Domains", kind: FabricTypeList, class: FabricApplyReload, risk: FabricRiskHigh,
		desc: "Authoritative domain set. Empty means every SNI is treated as foreign only when the list is non-empty."},
	{module: "l7", group: "TLS Defense", key: "tls_flood_threshold", label: "Handshake Flood Threshold", kind: FabricTypeInteger, def: 15, min: intPtr(2), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Handshakes per client inside the flood window before a flood finding is raised."},
	{module: "l7", group: "TLS Defense", key: "tls_sni_strike_threshold", label: "Invalid SNI Strikes", kind: FabricTypeInteger, def: 10, min: intPtr(2), max: intPtr(1000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Repeated invalid SNI events per client before an escalation finding is raised."},
	{module: "l7", group: "TLS Defense", key: "tls_anti_spoof", label: "Anti-Spoof Fingerprints", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Detect structurally spoofed JA3 fingerprints."},
	{module: "l7", group: "TLS Defense", key: "tls_max_client_hello_bytes", label: "Max ClientHello Bytes", kind: FabricTypeInteger, def: 65536, min: intPtr(1024), max: intPtr(1048576), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Maximum decoded ClientHello payload accepted by the TLS sensor."},
	{module: "l7", group: "TLS Defense", key: "tls_ja3_file", label: "JA3 Fingerprint File", kind: FabricTypePath, class: FabricApplyReload, risk: FabricRiskMedium,
		desc: "Absolute path of the local JA3 signature set. The file is read locally; no network fetch is ever performed."},
	{module: "l7", group: "TLS Defense", key: "tls_ja3_reload", label: "Reload Fingerprints", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Set to true together with a revision to re-read the JA3 fingerprint file."},
	{module: "l7", group: "TLS Defense", key: "tls_unknown_fingerprint", label: "Unknown Fingerprint Behaviour", kind: FabricTypeEnum, def: "allow", class: FabricApplyHot, risk: FabricRiskMedium,
		enum: []string{"allow", "alert"}, desc: "How a structurally valid but unknown JA3 fingerprint is treated."},
	{module: "l7", group: "TLS Defense", key: "tls_unknown_fingerprint_score", label: "Unknown Fingerprint Score", kind: FabricTypeInteger, def: 35, min: intPtr(1), max: intPtr(250), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Score contributed by the unknown-fingerprint finding when the behaviour is 'alert'."},
	{module: "l7", group: "L7 Rule Registry", key: "rules", label: "Rule Registry", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Array of {id, enabled, score, confidence, alert_only}. Built-in detection patterns are read-only; enablement, score, confidence and block eligibility are administrable. Alert-only rules can never authorise a block decision."},
	{module: "l7", group: "L7 Rule Registry", key: "enforce_rules", label: "Block-Eligible Rules", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Optional list of built-in rule IDs or families (for example L7.PHP.SESSION_UPLOAD_PROGRESS or L7.UPLOAD) that may authorise a block in block mode. Empty keeps the historical behaviour: every rule that is not alert-only may block. Findings outside the list are still recorded and still raise the alert score."},

	// ------------------------------------------------------------ threat_intel
	{module: "threat_intel", group: "Global", key: "enabled", label: "Threat Intelligence", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Master switch. Disabling removes every threat-intelligence rule from the kernel and stops all feed egress."},
	{module: "threat_intel", group: "Global", key: "auto_sync", label: "Automatic Synchronisation", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Synchronise feeds on the configured interval without operator action. Requires threat intelligence to be enabled."},
	{module: "threat_intel", group: "Global", key: "refresh_minutes", label: "Refresh Interval", kind: FabricTypeInteger, unit: "min", def: 720, min: intPtr(5), max: intPtr(1440), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Interval between automatic synchronisations. A per-feed override can shorten or lengthen it."},
	{module: "threat_intel", group: "Global", key: "stale_warning_minutes", label: "Stale Warning", kind: FabricTypeInteger, unit: "min", def: 1440, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Age of the last known-good generation at which a feed is reported as STALE."},
	{module: "threat_intel", group: "Global", key: "stale_critical_minutes", label: "Stale Critical", kind: FabricTypeInteger, unit: "min", def: 4320, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Age at which a feed is reported as CRITICAL. Must be at least the warning interval."},
	{module: "threat_intel", group: "Resource Bounds", key: "max_download_bytes_per_feed", label: "Max Download / Feed", kind: FabricTypeInteger, unit: "bytes", def: 16777216, min: intPtr(1024), max: intPtr(67108864), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Hard download ceiling for one feed. A per-feed override may lower or raise it inside the same bounds."},
	{module: "threat_intel", group: "Resource Bounds", key: "max_entries_per_feed", label: "Max Entries / Feed", kind: FabricTypeInteger, def: 250000, min: intPtr(1), max: intPtr(5000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Maximum indicators accepted from one feed download."},
	{module: "threat_intel", group: "Resource Bounds", key: "max_total_entries", label: "Max Total Entries", kind: FabricTypeInteger, def: 250000, min: intPtr(1), max: intPtr(5000000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Global bound for the published union. Sources are evaluated in priority order, so the budget is spent on the most trusted sources first."},
	{module: "threat_intel", group: "Resource Bounds", key: "download_timeout_seconds", label: "Download Timeout", kind: FabricTypeInteger, unit: "s", def: 25, min: intPtr(5), max: intPtr(300), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Per-attempt deadline for one feed download."},
	{module: "threat_intel", group: "Resource Bounds", key: "concurrent_downloads", label: "Concurrent Downloads", kind: FabricTypeInteger, def: 3, min: intPtr(1), max: intPtr(16), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Maximum simultaneous feed downloads."},
	{module: "threat_intel", group: "Transport Safety", key: "transport.allowed_hosts", label: "Allowed Hosts", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Optional hostname allowlist. Empty means any public host. HTTPS, port 443, the public-host requirement and resolved-address anti-poisoning remain unconditional."},
	{module: "threat_intel", group: "Transport Safety", key: "transport.max_redirects", label: "Max Redirects", kind: FabricTypeInteger, def: 2, min: intPtr(0), max: intPtr(10), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Redirect budget for one download. Every redirect is re-validated against the same revision that started the request."},
	{module: "threat_intel", group: "Transport Safety", key: "transport.allow_cross_host_redirect", label: "Allow Cross-Host Redirects", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Permit a redirect to a different hostname. Enable only when a feed provider redirects to a CDN you trust."},
	{module: "threat_intel", group: "Transport Safety", key: "transport.require_content_type", label: "Require Content Type", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Reject a download that omits Content-Type. A present header is always checked against the content type policy."},
	{module: "threat_intel", group: "Transport Safety", key: "transport.allowed_content_types", label: "Allowed Content Types", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Accepted media type prefixes, for example text/plain or application/json."},
	{module: "threat_intel", group: "Validation", key: "validation.ipv4_enabled", label: "Accept IPv4", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Accept IPv4 indicators. At least one address family must remain enabled."},
	{module: "threat_intel", group: "Validation", key: "validation.ipv6_enabled", label: "Accept IPv6", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Accept IPv6 indicators."},
	{module: "threat_intel", group: "Validation", key: "validation.minimum_valid_entry_permille", label: "Minimum Valid Entry Ratio", kind: FabricTypeInteger, unit: "\u2030", def: 0, min: intPtr(0), max: intPtr(1000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Minimum share of usable entries in a download. A download below the ratio is rejected so the active generation is preserved."},
	{module: "threat_intel", group: "Validation", key: "validation.malformed_entry_permille", label: "Malformed Entry Limit", kind: FabricTypeInteger, unit: "\u2030", def: 250, min: intPtr(0), max: intPtr(1000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Maximum share of malformed entries tolerated in a download before it is refused as corrupt."},
	{module: "threat_intel", group: "Validation", key: "validation.generation_policy", label: "Generation Policy", kind: FabricTypeEnum, def: "bump", class: FabricApplyHot, risk: FabricRiskLow,
		enum: []string{"bump", "stable"}, desc: "bump advances the feed generation on every successful download. stable keeps the generation for a byte-identical re-download and only refreshes freshness."},
	{module: "threat_intel", group: "Retry", key: "retry.attempts", label: "Attempts", kind: FabricTypeInteger, def: 2, min: intPtr(1), max: intPtr(5), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Total attempts per feed and sync. Only transient failures (network faults, HTTP 429 or 5xx) are retried; a validation or security rejection is final."},
	{module: "threat_intel", group: "Retry", key: "retry.backoff_seconds", label: "Backoff", kind: FabricTypeInteger, unit: "s", def: 5, min: intPtr(1), max: intPtr(300), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Base delay between attempts. The delay doubles per attempt up to a bounded ceiling and always honours cancellation."},
	{module: "threat_intel", group: "Kernel Apply", key: "kernel_apply.auto_apply", label: "Apply To Kernel Automatically", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Publish a validated generation to the kernel as part of the sync. With this off the operator must apply explicitly; additions always precede deletions and a failed diff is rolled back."},
	{module: "threat_intel", group: "Kernel Apply", key: "kernel_apply.maximum_diff_per_sync", label: "Maximum Diff / Sync", kind: FabricTypeInteger, def: 0, min: intPtr(0), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Refuse a kernel diff larger than this budget instead of applying it partially. 0 disables the budget."},
	{module: "threat_intel", group: "Kernel Apply", key: "kernel_apply.divergence_degrades_release", label: "Divergence Degrades Release", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "A userspace/kernel divergence withdraws NOMINAL and forces the release gate into a safe phase."},
	{module: "threat_intel", group: "Feed Sources", key: "feeds", label: "Feed Sources", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Structured feed definitions: id, name, enabled, url, format, action, priority, trust weight and per-feed bounds. Priority decides evaluation order and therefore which entries survive the global budget."},

	// ------------------------------------------------------------- hardening
	{module: "hardening", group: "Posture", key: "posture.auto_scan", label: "Automatic Posture Scan", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Evaluate the host posture periodically and raise an event when the level changes or a required domain drops below its threshold."},
	{module: "hardening", group: "Posture", key: "posture.scan_interval_seconds", label: "Scan Interval", kind: FabricTypeInteger, unit: "s", def: 900, min: intPtr(60), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Interval between periodic posture evaluations."},
	{module: "hardening", group: "Posture", key: "posture.hardened_threshold", label: "Hardened Threshold", kind: FabricTypeInteger, def: 90, min: intPtr(1), max: intPtr(100), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Score at or above which the posture is classified HARDENED."},
	{module: "hardening", group: "Posture", key: "posture.strong_threshold", label: "Strong Threshold", kind: FabricTypeInteger, def: 75, min: intPtr(0), max: intPtr(100), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Score at or above which the posture is classified STRONG, and the per-domain threshold a required domain must reach."},
	{module: "hardening", group: "Posture", key: "posture.basic_threshold", label: "Basic Threshold", kind: FabricTypeInteger, def: 50, min: intPtr(0), max: intPtr(100), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Score at or above which the posture is classified BASIC. Below it the posture is CRITICAL."},
	{module: "hardening", group: "Posture", key: "posture.required_domains", label: "Required Domains", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Posture domains that must reach the strong threshold: application-control, boot, encryption, filesystem, integrity, kernel, network. A domain with no measurable control is reported UNAVAILABLE and can never be silenced by removing it from a list."},
	{module: "hardening", group: "Sysctl Profiles", key: "sysctl.profiles", label: "Sysctl Profiles", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Named selections over the centrally allowed sysctl controls. The kernel keys and desired values come from the control definitions and are never operator-authored, so no arbitrary /proc/sys path can be reached."},
	{module: "hardening", group: "Sysctl Profiles", key: "sysctl.default_profile", label: "Default Profile", kind: FabricTypeText, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Profile applied when a hardening request omits an explicit profile. Empty means the request must name one."},
	{module: "hardening", group: "Sysctl Profiles", key: "sysctl.allow_ad_hoc_controls", label: "Allow Ad-Hoc Control Sets", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Permit an operator to submit an ad-hoc selection of allowed controls instead of a named profile. The control vocabulary stays closed either way."},
	{module: "hardening", group: "Morpheus RASP", key: "rasp.enabled", label: "RASP Data Path", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Let Morpheus RASP participate in the XDR evaluation path."},
	{module: "hardening", group: "Morpheus RASP", key: "rasp.protected_names", label: "Protected Process Names", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Process names that may never be traced or memory-inspected by a non-child process."},
	{module: "hardening", group: "Morpheus RASP", key: "rasp.trusted_debuggers", label: "Trusted Debuggers", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Process names exempt from RASP detection. An exemption applies to a named tool only; it can never disable detection for everyone."},
	{module: "hardening", group: "Morpheus RASP", key: "rasp.containment_enabled", label: "Freeze On Detection", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Apply a reversible process freeze when an unauthorised memory inspection is detected."},
	{module: "hardening", group: "Morpheus RASP", key: "rasp.alert_only", label: "Alert Only", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Report detections without any response action. Cannot be combined with freeze on detection."},
	{module: "hardening", group: "Deception", key: "deception.enabled", label: "Canary Grid", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Enable the decoy credential grid. Disabling stops all canary triage and response."},
	{module: "hardening", group: "Deception", key: "deception.canaries", label: "Canary Definitions", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Array of {path, type, enabled, owner_uid, file_mode}. A changed type, owner or mode re-enrols the canary so its signed token matches the definition."},
	{module: "hardening", group: "Deception", key: "deception.allowed_roots", label: "Allowed Canary Roots", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Filesystem roots a canary path may live under. A canary outside every root is rejected before it can be deployed."},
	{module: "hardening", group: "Deception", key: "deception.containment_level", label: "Containment Level", kind: FabricTypeEnum, def: "contain_and_block", class: FabricApplyHot, risk: FabricRiskCritical,
		enum: []string{"observe", "contain", "contain_and_block"}, desc: "observe reports only. contain freezes the accessing process. contain_and_block additionally contains a captured remote IP."},
	{module: "hardening", group: "Deception", key: "deception.correlate_remote_ip", label: "Correlate Remote IP", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Allow a canary hit to contain the captured remote address. Only applies at the contain_and_block level."},
	{module: "hardening", group: "Deception", key: "deception.unauthorized_score", label: "Unauthorized Accessor Score", kind: FabricTypeInteger, def: 200, min: intPtr(1), max: intPtr(250), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Incident score for a canary access by an ordinary process."},
	{module: "hardening", group: "Deception", key: "deception.system_accessor_score", label: "System Accessor Score", kind: FabricTypeInteger, def: 160, min: intPtr(1), max: intPtr(250), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Incident score for a canary access by a calibrated system process or backup scanner."},
	{module: "hardening", group: "Airlock", key: "airlock.enabled", label: "Airlock Inspection", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Inspect uploaded objects for disguised executables, polyglots and active SVG content."},
	{module: "hardening", group: "Airlock", key: "airlock.quarantine_directory", label: "Quarantine Directory", kind: FabricTypePath, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Absolute path of the staging vault. The path is resolved and jail-checked on every write."},
	{module: "hardening", group: "Airlock", key: "airlock.max_file_size_bytes", label: "Max File Size", kind: FabricTypeInteger, unit: "bytes", def: 104857600, min: intPtr(1024), max: intPtr(17179869184), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Hard size boundary for inspection and staging."},
	{module: "hardening", group: "Airlock", key: "airlock.mime_mismatch_action", label: "MIME Mismatch Action", kind: FabricTypeEnum, def: "report", class: FabricApplyHot, risk: FabricRiskHigh,
		enum: []string{"report", "ignore"}, desc: "Whether a declared extension that disagrees with the magic bytes is reported or ignored. Ignoring weakens detection."},
	{module: "hardening", group: "Airlock", key: "airlock.polyglot_detection", label: "Polyglot Detection", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Scan binary bodies for embedded server-side script payloads."},
	{module: "hardening", group: "Airlock", key: "airlock.svg_active_content", label: "SVG Active Content", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Reject SVG documents carrying active scripting, inline event handlers or XML external entities."},
	{module: "hardening", group: "Airlock", key: "airlock.executable_upload_policy", label: "Executable Upload Policy", kind: FabricTypeEnum, def: "reject", class: FabricApplyHot, risk: FabricRiskCritical,
		enum: []string{"reject", "report"}, desc: "reject scores a disguised executable as an immediate refusal. report records it at a score that cannot cross a block threshold on its own."},
	{module: "hardening", group: "Airlock", key: "airlock.auto_quarantine", label: "Automatic Quarantine", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Stage a refused upload into the quarantine vault so the evidence survives the request."},

	// ------------------------------------------------------------- detection
	// The rules that name what happens after a break-in, whoever caused it. Every switch defaults to
	// on, and every one of them can be adapted to this host without touching the binary.
	{module: "detection", group: "Post-Exploitation Rules", key: "rule_log_tamper", label: "Detect Log Tampering", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Reports forensic logs that are deleted, truncated or emptied, and shell histories that are wiped - the anti-forensics step of a real intrusion."},
	{module: "detection", group: "Post-Exploitation Rules", key: "rule_credential_probe", label: "Detect Credential Access", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Reports bulk reads, copies and encodings of the credential stores this host keeps."},
	{module: "detection", group: "Post-Exploitation Rules", key: "rule_tunnel_binary", label: "Detect Tunnelling Tools", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Reports executed tunnelling and proxy tools. Reporting only: these tools have legitimate uses, so the rule never terminates a process."},
	{module: "detection", group: "Post-Exploitation Rules", key: "rule_persistence_dropin", label: "Detect Persistence Entries", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Reports scheduled tasks, units and authorised keys written outside package management."},
	{module: "detection", group: "Protected Surface", key: "protection_roots_preset", label: "Protect Web, Log and Persistence Paths", kind: FabricTypeBoolean, def: true, class: FabricApplyRestart, risk: FabricRiskLow,
		desc: "Adds the web, log and persistence directories that exist on this host to the protected roots, so a dropped web shell and a deleted log become findings. A one-time acceptance of the new baseline follows."},
	{module: "detection", group: "Protected Surface", key: "credential_paths", label: "Credential Stores On This Host", kind: FabricTypeList, def: []string{"/etc/vgt/gedefense/secrets", "/opt/beyondtrust"}, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Absolute paths, up to 32. They become one operator rule, quoted literally, so a path can never introduce regular-expression syntax."},

	// ------------------------------------------------------------- integrity
	{module: "integrity", group: "File Integrity", key: "fim.enabled", label: "File Integrity Monitoring", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Disabling FIM stops periodic verification and refuses on-demand scans. The encrypted baseline is retained."},
	{module: "integrity", group: "File Integrity", key: "fim.roots", label: "Protected Roots", kind: FabricTypeList, class: FabricApplyRestart, risk: FabricRiskCritical,
		desc: "Restart required: the stored baseline is bound to this root set, so a change is persisted but activates only on the next service start."},
	{module: "integrity", group: "File Integrity", key: "fim.interval_seconds", label: "Integrity Scan Interval", kind: FabricTypeInteger, unit: "s", def: 30, min: intPtr(30), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Shared cadence for periodic FIM verification and the Chronos checkpoint pass."},
	{module: "integrity", group: "File Integrity", key: "fim.max_files", label: "Max Files", kind: FabricTypeInteger, def: 8192, min: intPtr(16), max: intPtr(1000000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bounded number of protected files considered in one pass."},
	{module: "integrity", group: "File Integrity", key: "fim.max_file_bytes", label: "Max File Size", kind: FabricTypeInteger, unit: "bytes", def: 67108864, min: intPtr(1024), max: intPtr(4294967296), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Per-file size boundary. A larger protected file is reported as out of bounds instead of being hashed."},
	{module: "integrity", group: "File Integrity", key: "fim.max_total_bytes", label: "Max Total Bytes", kind: FabricTypeInteger, unit: "bytes", def: 536870912, min: intPtr(1048576), max: intPtr(68719476736), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Aggregate traversal budget for one pass."},
	{module: "integrity", group: "File Integrity", key: "fim.max_baseline_bytes", label: "Max Baseline Size", kind: FabricTypeInteger, unit: "bytes", def: 16777216, min: intPtr(65536), max: intPtr(268435456), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bound on the encrypted baseline document that is read and authenticated at start."},
	{module: "integrity", group: "File Integrity", key: "fim.max_findings", label: "Max Findings", kind: FabricTypeInteger, def: 500, min: intPtr(10), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Bound on the findings retained for one scan result."},
	{module: "integrity", group: "Chronos", key: "chronos.enabled", label: "Chronos Checkpointing", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Enable the incremental checkpoint pass and its Merkle verification."},
	{module: "integrity", group: "Chronos", key: "chronos.roots", label: "Checkpoint Roots", kind: FabricTypeList, class: FabricApplyRestart, risk: FabricRiskHigh,
		desc: "Restart required: the resumable checkpoint is bound to the root set it was produced from."},
	{module: "integrity", group: "Chronos", key: "chronos.batch_size", label: "Batch Size", kind: FabricTypeInteger, def: 100, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Files hashed between checkpoint writes."},
	{module: "integrity", group: "Chronos", key: "chronos.yield_millis", label: "Yield", kind: FabricTypeInteger, unit: "ms", def: 1, min: intPtr(0), max: intPtr(1000), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Pause between batches so the walker cannot starve the host."},
	{module: "integrity", group: "Chronos", key: "chronos.max_files", label: "Max Files", kind: FabricTypeInteger, def: 200000, min: intPtr(16), max: intPtr(5000000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Bounded number of files in one checkpoint run. Exhausting the budget reports a partial digest set instead of a completed scan."},
	{module: "integrity", group: "Chronos", key: "chronos.max_total_bytes", label: "Max Total Bytes", kind: FabricTypeInteger, unit: "bytes", def: 68719476736, min: intPtr(1048576), max: intPtr(1099511627776), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Bounded number of bytes hashed in one checkpoint run."},
	{module: "integrity", group: "Package Integrity", key: "packages.enabled", label: "Package Integrity", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Enable package manifest verification. The database and filesystem roots and the bounded walk limits remain compiled-in hard safety invariants."},
	{module: "integrity", group: "Package Integrity", key: "packages.auto_scan", label: "Scheduled Verification", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Run package verification on the configured interval without operator action."},
	{module: "integrity", group: "Package Integrity", key: "packages.interval_hours", label: "Interval", kind: FabricTypeInteger, unit: "h", def: 24, min: intPtr(1), max: intPtr(720), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Interval between scheduled package verifications."},
	{module: "integrity", group: "Evidence Ledger", key: "evidence.max_bytes", label: "Ledger Budget", kind: FabricTypeInteger, unit: "bytes", def: 67108864, min: intPtr(1048576), max: intPtr(68719476736), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Size budget of the append-only ledger. Lowering it refuses further appends; existing records are never truncated."},
	{module: "integrity", group: "Evidence Ledger", key: "evidence.verify_interval_seconds", label: "Verification Interval", kind: FabricTypeInteger, unit: "s", def: 900, min: intPtr(30), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Interval between periodic chain verifications, so tampering is detected while the service is running."},
	{module: "integrity", group: "Evidence Ledger", key: "evidence.api_recent_default", label: "Default Page Size", kind: FabricTypeInteger, def: 100, min: intPtr(1), max: intPtr(500), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Records returned when the caller does not request a page size."},
	{module: "integrity", group: "Evidence Ledger", key: "evidence.api_recent_max", label: "Maximum Page Size", kind: FabricTypeInteger, def: 500, min: intPtr(1), max: intPtr(4096), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Ceiling for a caller-requested page size."},

	// ------------------------------------------------------------ boot trust
	{module: "boot_trust", group: "Evidence Cache", key: "ttl_seconds", label: "Evidence Lifetime", kind: FabricTypeInteger, unit: "s", def: 300, min: intPtr(5), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "How long a collected boot report may be reused. A change invalidates the cache so the next read re-probes."},
	{module: "boot_trust", group: "TPM Attestation", key: "required_pcr_selection", label: "Required PCR Selection", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "PCR registers the local attestation must report, compared in ascending order. An attestation whose selection differs is rejected, so narrowing the list cannot make an unmeasured boot look attested."},
	{module: "boot_trust", group: "TPM Attestation", key: "require_attestation", label: "Require Attestation", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Treat an absent local TPM2 attestation as a policy violation instead of a platform property."},
	{module: "boot_trust", group: "Platform Anchors", key: "require_secure_boot", label: "Require Secure Boot", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Report a disabled UEFI Secure Boot anchor as a policy violation rather than a neutral observation."},
	{module: "boot_trust", group: "Platform Anchors", key: "require_kernel_lockdown", label: "Require Kernel Lockdown", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Treat an inactive or unobservable kernel lockdown as a policy violation."},
	{module: "boot_trust", group: "Kernel Command Line", key: "required_kernel_arguments", label: "Required Boot Arguments", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Boot parameter tokens that must all be present. The kernel command line itself stays redacted; only the matched token list is published."},
	{module: "boot_trust", group: "Resource Bounds", key: "max_evidence_text_bytes", label: "Evidence Read Bound", kind: FabricTypeInteger, unit: "bytes", def: 65536, min: intPtr(4096), max: intPtr(4194304), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bound on every text read from the boot evidence sources."},
	{module: "boot_trust", group: "Resource Bounds", key: "max_kernel_image_bytes", label: "Kernel Image Bound", kind: FabricTypeInteger, unit: "bytes", def: 268435456, min: intPtr(1048576), max: intPtr(4294967296), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Largest kernel image that will be hashed as boot evidence."},

	// ---------------------------------------------------------- policy trust
	{module: "policy_trust", group: "Signature Enforcement", key: "require_signed", label: "Require Signed Policy", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Refuse a policy document whose Ed25519 signature cannot be verified. Disabling this accepts an unsigned policy state file."},
	{module: "policy_trust", group: "Signature Enforcement", key: "minimum_generation", label: "Minimum Generation", kind: FabricTypeInteger, def: 0, min: intPtr(0), class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Rollback protection: a document whose generation is below this floor is refused as a replayed older revision, so restoring an old state file cannot silently downgrade enforcement."},
	{module: "policy_trust", group: "Verification", key: "verify_interval_seconds", label: "Verification Interval", kind: FabricTypeInteger, unit: "s", def: 900, min: intPtr(30), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Interval between periodic signature re-verifications, so a tampered state file is detected while the service is running."},
	{module: "policy_trust", group: "Resource Bounds", key: "max_state_bytes", label: "State Read Bound", kind: FabricTypeInteger, unit: "bytes", def: 67108864, min: intPtr(65536), max: intPtr(536870912), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bound on the encrypted policy document that is read and authenticated."},

	// ------------------------------------------------------------ forensics
	{module: "forensics", group: "Cases", key: "cases.auto_create", label: "Automatic Case Creation", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Open a case automatically when an incident reaches the score threshold. Disabling it leaves case creation entirely to the operator."},
	{module: "forensics", group: "Cases", key: "cases.minimum_incident_score", label: "Creation Score Threshold", kind: FabricTypeInteger, def: 150, min: intPtr(1), max: intPtr(250), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Incidents below this score never open a case, so a noisy detector cannot flood the register on its own."},
	{module: "forensics", group: "Cases", key: "cases.max_cases", label: "Case Budget", kind: FabricTypeInteger, def: 4096, min: intPtr(1), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Bounded number of stored cases. Reaching it refuses new cases instead of evicting existing evidence."},
	{module: "forensics", group: "Cases", key: "cases.max_evidence_refs_per_case", label: "Evidence Refs per Case", kind: FabricTypeInteger, def: 256, min: intPtr(1), max: intPtr(4096), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bound on the evidence identifiers a single case accumulates."},
	{module: "forensics", group: "Cases", key: "cases.max_observations_per_case", label: "Observations per Case", kind: FabricTypeInteger, def: 256, min: intPtr(1), max: intPtr(4096), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bound on the observations retained per case. The newest are kept."},
	{module: "forensics", group: "Cases", key: "cases.list_max_limit", label: "List Ceiling", kind: FabricTypeInteger, def: 500, min: intPtr(1), max: intPtr(5000), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Largest case page a caller may request."},
	{module: "forensics", group: "Cases", key: "cases.correlation_window_minutes", label: "Correlation Window", kind: FabricTypeInteger, unit: "min", def: 60, min: intPtr(1), max: intPtr(43200), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "How far apart two incidents on the same target may be and still join one case. Beyond it the recurrence opens a new case instead of extending an old one indefinitely."},
	{module: "forensics", group: "Cases", key: "cases.auto_close_after_hours", label: "Auto-Close Idle Cases", kind: FabricTypeInteger, unit: "h", def: 0, min: intPtr(0), max: intPtr(8760), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Close an untouched open case after this many hours. 0 disables the sweep, which is the default: closing a case is an operator judgement."},
	{module: "forensics", group: "Export", key: "export.include_raw_records", label: "Include Raw Records", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Include the raw event and incident records in the signed export."},
	{module: "forensics", group: "Export", key: "export.include_policy_state", label: "Include Policy State", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Include the policy status and the full runtime settings in the export."},
	{module: "forensics", group: "Export", key: "export.include_system_metadata", label: "Include System Metadata", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Include node identity, version and telemetry in the export."},
	{module: "forensics", group: "Export", key: "export.redact_internal_ips", label: "Redact Internal Addresses", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Replace private, loopback, link-local and CGNAT addresses with a stable token before signing. Public addresses are kept: they are the indicator the record exists for. Redaction happens before signing, so a verifier sees the redacted content as canonical."},
	{module: "forensics", group: "Export", key: "export.max_export_bytes", label: "Export Size Boundary", kind: FabricTypeInteger, unit: "bytes", def: 33554432, min: intPtr(65536), max: intPtr(1073741824), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Largest shaped export that will be produced."},
	{module: "forensics", group: "Export", key: "export.signing_required", label: "Require Signature", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Refuse an export that cannot be signed. Disabling it produces an explicitly unsigned record, marked as such in the response header and body so it cannot be mistaken for a verified one."},
	{module: "forensics", group: "Quarantine", key: "quarantine.enabled", label: "Quarantine Transactions", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Allow quarantine transactions. Disabling refuses new quarantines without touching objects already stored."},
	{module: "forensics", group: "Quarantine", key: "quarantine.allowed_roots", label: "Allowed Roots", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "When set, only paths under these roots may be quarantined. A root that overlaps a forbidden root is rejected, so an allowlist cannot silently disable a denial."},
	{module: "forensics", group: "Quarantine", key: "quarantine.extra_forbidden_roots", label: "Additional Forbidden Roots", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Extra roots to deny. The built-in set covering /, /proc, /sys, /dev, /run and the service directories is compiled in and cannot be removed by any revision."},
	{module: "forensics", group: "Quarantine", key: "quarantine.restore_file_mode", label: "Restore Mode", kind: FabricTypeInteger, def: 384, min: intPtr(256), max: intPtr(448), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Permission mask applied to a restored object. Restricted to an owner-only range so a restore cannot widen access. 384 is 0600."},

	// --------------------------------------------------------------- system
	{module: "system", group: "Dashboard", key: "dashboard.rate_limit_per_minute", label: "API Rate Limit", kind: FabricTypeInteger, unit: "/min", def: 240, min: intPtr(1), max: intPtr(60000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Requests per minute accepted from one identity across the API, the health endpoints and the metrics exposition."},
	{module: "system", group: "Dashboard", key: "dashboard.rate_limit_burst", label: "API Burst Allowance", kind: FabricTypeInteger, def: 40, min: intPtr(1), max: intPtr(10000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Short-term allowance above the steady rate. Cannot exceed the per-minute limit, because a burst larger than the allowance would let a caller exceed the stated rate for a whole minute."},
	{module: "system", group: "Dashboard", key: "dashboard.max_sse_clients", label: "Stream Client Ceiling", kind: FabricTypeInteger, def: 16, min: intPtr(1), max: intPtr(512), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Concurrent event-stream subscribers. Every subscriber holds a channel and a connection, so this is the bound that keeps a stream flood from exhausting the control plane."},
	{module: "system", group: "Dashboard", key: "dashboard.metrics_enabled", label: "Metrics Exposition", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Serve the Prometheus exposition. Disabling it removes the endpoint entirely rather than returning an empty document."},
	{module: "system", group: "Resource Bounds", key: "events.max_event_cache", label: "Event Cache Budget", kind: FabricTypeInteger, def: 250, min: intPtr(16), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Events retained in the in-memory ring. A tightening revision trims the ring immediately; the signed evidence ledger keeps the full record either way."},
	{module: "system", group: "Resource Bounds", key: "events.max_api_payload_bytes", label: "API Payload Ceiling", kind: FabricTypeInteger, unit: "bytes", def: 1048576, min: intPtr(65536), max: intPtr(67108864), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Ceiling applied to every mutating request body before any handler sees it. It caps a handler's own limit rather than replacing it, so it can only tighten."},
	{module: "system", group: "Core IPC", key: "core.request_timeout_millis", label: "Core Command Deadline", kind: FabricTypeInteger, unit: "ms", def: 2000, min: intPtr(100), max: intPtr(60000), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Deadline for one command to the kernel core. Read on every call, so a revision takes effect on the next command without a restart."},

	// ------------------------------------------------------------------ styx
	// Kernel-level per-cgroup egress enforcement and the aggregate flow telemetry
	// the beacon detector consumes (docs/POINT3-EGRESS-BEACON.md §8.3). The shipped
	// default is disabled/off so an upgrade keeps the exact kernel behaviour of
	// 5.2.0; every value below is projected by the StyX policy syncer and reported
	// as applied/pending/failed/capability-missing, never assumed.
	{module: "styx", group: "Kernel Egress Enforcement", key: "enabled", label: "Styx Kernel Enforcement", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Enable the kernel-side per-cgroup egress policy. Disabled (the upgrade default) means no enforcement and no flow logging; the syncer then keeps the global mode at off."},
	{module: "styx", group: "Kernel Egress Enforcement", key: "mode", label: "Default Egress Mode", kind: FabricTypeEnum, def: "off", class: FabricApplyHot, risk: FabricRiskCritical,
		enum: []string{"off", "monitor", "enforce"}, desc: "Host-wide default for cgroups without their own entry. off records nothing and blocks nothing, monitor records flow telemetry without blocking, enforce is a default-deny that needs a complete allowlist (§12)."},
	{module: "styx", group: "Kernel Egress Enforcement", key: "log_flows", label: "Flow Telemetry", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Emit the kernel's aggregated flow events that feed the beacon/exfiltration detector. Telemetry is also produced automatically in monitor/enforce mode; this flag additionally enables it for per-cell entries whose mode is off."},
	{module: "styx", group: "Per-Cell Policy", key: "per_cell", label: "Per-Cell Modes", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Array of {cgroup_path, cgroup_id, mode, dns_resolver, allow_host_allowlist}, at most 256 entries. Prefer cgroup_path (e.g. /system.slice/php8.3-fpm.service): the numeric cgroup id is re-resolved from that path on every sync and survives a reboot or unit restart. A numeric-only cgroup_id is kept for backward compatibility but cannot survive a reboot (reported as legacy). One mode per workload cgroup; duplicates are refused rather than resolved silently."},
	{module: "styx", group: "Per-Cell Policy", key: "allowlist", label: "Per-Cell Allowlist", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Array of {cgroup_path, cgroup_id, cidr, port_lo, port_hi, proto}, at most 1024 entries. Prefer cgroup_path for the same reboot-stable identity as per_cell. CIDRs must be canonical; a port or protocol restriction requires a host CIDR (/32 or /128) and only a single port or the 0-65535 wildcard is accepted. IPv6 cell rules cannot carry port/protocol restrictions in phase 1 and are refused instead of silently widened."},
	{module: "styx", group: "DNS Pinning", key: "dns_resolvers", label: "DNS/DoT Resolvers", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Canonical IP prefixes the kernel may reach on ports 53/853 without a DNS-pinning violation, at most 256. The mandatory metadata/link-local veto seed stays owned by the core and is not administrable here."},

	// --------------------------------------------------------------- titan_exec
	// Kernel-side exec/library gate (docs/POINT1-TITAN-EXEC-GATE.md §7.1, §7.2). The
	// shipped default is disabled/off with empty lists, so an upgrade keeps the exact
	// kernel behaviour of 5.2.0. The compiled plan is projected by the Titan exec-gate
	// syncer and reported as applied/pending/failed/inactive/capability-missing, never
	// assumed; enforcement additionally requires an active BPF-LSM hook.
	{module: "titan_exec", group: "Kernel Exec Gate", key: "enabled", label: "Titan Exec Gate", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Enable the kernel-side exec/library gate. Disabled (the upgrade default) means no exec policy is installed and the syncer keeps the global mode at off."},
	{module: "titan_exec", group: "Kernel Exec Gate", key: "mode", label: "Exec Gate Mode", kind: FabricTypeEnum, def: "off", class: FabricApplyHot, risk: FabricRiskCritical,
		enum: []string{"off", "observe", "contain", "strict", "untrusted"}, desc: "off records and blocks nothing; observe audits exec/mmap decisions without blocking; contain denies unlinked, tmpfs/devtmpfs/proc/sysfs and write+exec mappings (plus anonymous exec outside the JIT scopes); strict additionally denies every exec that is not in the compiled allowlist and therefore needs a complete plan; untrusted (V6.2, global only) additionally denies executables from untrusted paths (non-root owner or world-writable directory) unless allowlisted. Applying enforce modes without an active BPF-LSM hook is reported as inactive, never as enforced."},
	{module: "titan_exec", group: "Kernel Exec Gate", key: "require_ctime", label: "Inode ctime Re-check", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Additionally verify i_ctime on every policy hit, mitigating inode recycling and in-place modification. A stale policy entry then fails closed (deny) instead of allowing a recycled inode."},
	{module: "titan_exec", group: "Allowlist Sources", key: "exec_roots", label: "Exec Roots", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Host directories whose regular, executable, non-symlink files are candidates for the kernel allowlist. Phase 1 admits a candidate only with package ownership or a verified FIM baseline digest; symlinks are skipped and counted. Absolute canonical paths only."},
	{module: "titan_exec", group: "Allowlist Sources", key: "allow_paths", label: "Explicit Allow Paths", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Files or directories that are trusted explicitly. A directory is walked with the same bounded rules as an exec root. Symlinks, non-regular and non-executable paths are refused instead of resolved."},
	{module: "titan_exec", group: "Allowlist Sources", key: "dev_roots", label: "Development Roots", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Documented development roots. Phase 1 never turns them into a kernel allowance: they are recorded for the operator view and do not widen the exec gate."},
	{module: "titan_exec", group: "Per-Cgroup Scopes", key: "jit_cgroups", label: "JIT Cgroups", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Array of non-zero cgroup ids that may execute anonymous JIT memory (TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW). The scope keeps the global mode; at most max_scopes distinct cgroups."},
	{module: "titan_exec", group: "Per-Cgroup Scopes", key: "strict_cgroups", label: "Strict Cgroups", kind: FabricTypeJSON, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Array of non-zero cgroup ids pinned to strict mode, so a global observe/contain gate can be tightened cell-by-cell only after the allowlist is complete. At most max_scopes distinct cgroups; a cgroup in both lists keeps the JIT allowance but is pinned to strict."},
	{module: "titan_exec", group: "Resource Bounds", key: "max_entries", label: "Allowlist Entry Bound", kind: FabricTypeInteger, unit: "entries", def: 8192, min: intPtr(1), max: intPtr(65536), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Upper bound of the compiled allowlist (kernel policy map is sized 65536). A plan that resolves more entries is refused instead of being truncated, because a partial strict allowlist would deny valid execs."},
	{module: "titan_exec", group: "Resource Bounds", key: "max_scopes", label: "Scope Bound", kind: FabricTypeInteger, unit: "cgroups", def: 256, min: intPtr(1), max: intPtr(4096), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Upper bound of per-cgroup scopes (kernel mode map is sized 4096). The JIT and strict lists together may not exceed it."},

	// --------------------------------------------------------------- parser_cells
	// Ephemeral parser cells (docs/POINT2-PARSER-CELLS.md §5, §6, §8). The shipped
	// default is disabled: no privileged helper is contacted, no cell is created and
	// an upgrade changes no host behaviour. The namespace only carries policy and
	// bounds - binary, argv and environment come from the helper's root-owned profile
	// table and are never administrable from the control plane.
	{module: "parser_cells", group: "Parser Cells", key: "enabled", label: "Ephemeral Parser Cells", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Enable ephemeral parser cells through the privileged cell helper. Disabled (the upgrade default) means no helper request, no cell and no event at all; enabling also requires the helper unit and its capability negotiation to be present."},
	{module: "parser_cells", group: "Parser Cells", key: "profiles", label: "Allowed Parser Profiles", kind: FabricTypeList, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Allowlist of helper profile ids a cell may be opened with, at most 16 (protocol-safe ids only). An empty list keeps the documented default: every profile the helper advertises is allowed. The binary, argv and environment of a profile remain exclusively package-managed."},
	{module: "parser_cells", group: "Parser Cells", key: "require_host_layers", label: "Require Host Isolation Layers", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "When set, a cell is only reported as isolated if the Cell-LSM, StyX-egress and Titan-exec strict layers were all acknowledged by the privileged core. Missing layers then refuse the cell instead of degrading silently; the default relies on the helper's own L1 sandbox (netns/tmpfs/seccomp) alone."},
	{module: "parser_cells", group: "Resource Limits", key: "ttl_seconds", label: "Default Cell TTL", kind: FabricTypeInteger, unit: "s", def: 120, min: intPtr(5), max: intPtr(3600), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Default until auto-burn, bounded by the helper profile ttl_max and the hard 5..3600 s window. The helper TTL timer stays authoritative and burns the cell even when the control plane is unavailable."},
	{module: "parser_cells", group: "Resource Limits", key: "max_concurrent", label: "Max Concurrent Cells", kind: FabricTypeInteger, unit: "cells", def: 4, min: intPtr(1), max: intPtr(16), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Admission bound for simultaneously open parser cells; the helper's own capability and hard cap additionally apply."},
	{module: "parser_cells", group: "Resource Limits", key: "max_input_bytes", label: "Max Input Document", kind: FabricTypeInteger, unit: "bytes", def: 8388608, min: intPtr(1024), max: intPtr(8388608), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Bound for one staged parser input (the API accepts the document as bounded base64). The helper verifies token, size and SHA-256 before binding it read-only."},
	{module: "parser_cells", group: "Resource Limits", key: "max_export_bytes", label: "Max Export Size", kind: FabricTypeInteger, unit: "bytes", def: 2097152, min: intPtr(1024), max: intPtr(2097152), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Bound for the helper export descriptor. The control plane reads at most this many bytes, verifies the digest and imports the export as untrusted evidence; it is never rendered or executed."},
	{module: "parser_cells", group: "Incident Response", key: "burn_on_incident", label: "Burn Parser Cells on Incident", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "When an incident on a managed parser-ephemeral cell reaches incident_score, the automatic CellGuard burns the cell instead of freezing it. A parser cell is destroyed, never paused; evidence intent is committed first."},
	{module: "parser_cells", group: "Incident Response", key: "incident_score", label: "Burn Threshold", kind: FabricTypeInteger, def: 80, min: intPtr(1), max: intPtr(250), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Incident score at which an automatic parser-cell burn is dispatched."},
	{module: "parser_cells", group: "Incident Response", key: "cooldown_seconds", label: "Burn Cooldown", kind: FabricTypeInteger, unit: "s", def: 300, min: intPtr(0), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Minimum interval between automatic burns for the same cgroup, so one recurring incident cannot turn into a burn storm."},

	// --------------------------------------------------------------- lockdown
	// Emergency Lockdown / anti-physical-extraction (docs/POINT5-LOCKDOWN.md §7).
	// The shipped default is disabled: no LOCKDOWN_* command is issued, no trigger
	// ticker sends traffic and no phase runs. Enabling the namespace requires at
	// least one phase; every phase status is reported as applied/partial/
	// unavailable/unsupported/failed from what the kernel and the dedicated
	// subsystems actually acknowledged, never assumed (§9).
	{module: "lockdown", group: "Emergency Lockdown", key: "enabled", label: "Emergency Lockdown", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Enable the emergency-lockdown engine. Disabled (the upgrade default) means no core LOCKDOWN_* command, no trigger evaluation and no event; host behaviour is unchanged until an operator enables it."},
	{module: "lockdown", group: "Emergency Lockdown", key: "auto_arm", label: "Auto-Arm on Start", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Re-arm the kernel arm mode on start without an operator click. Off by default: a restart must not arm a kernel policy that a previous operator decision had left disarmed."},
	{module: "lockdown", group: "Trigger Sources", key: "trigger_morpheus_critical", label: "Trigger on Morpheus CRITICAL", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Latch when a MORPHEUS.RASP.* incident with severity CRITICAL is recorded. Any other severity or rule family never triggers."},
	{module: "lockdown", group: "Trigger Sources", key: "trigger_canary_unauthorized", label: "Trigger on Canary Unauthorized Probe", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Latch on KD.LINUX.CANARY_ACCESS with the CANARY_UNAUTHORIZED_PROBE reason and CRITICAL severity. System and scanner accesses carry a different reason and severity and never trigger."},
	{module: "lockdown", group: "Trigger Sources", key: "trigger_boot_trust_drift", label: "Trigger on Boot-Trust Drift", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Latch when the 60 s boot-trust reconciliation observes a degradation from VERIFIED to OBSERVE. NOT_SUPPORTED and UNKNOWN are platform facts, not drift, and never trigger."},
	{module: "lockdown", group: "Trigger Sources", key: "trigger_witness_equivocation", label: "Trigger on Witness Equivocation", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Accept the Out-of-Band Witness equivocation/rollback alarm as a lockdown source. Off by default: it requires an explicit enable here and in witness.trigger_lockdown_on_equivocation, and the P5 dedupe, cooldown and RequireSources guards still apply."},
	{module: "lockdown", group: "Trigger Sources", key: "require_sources", label: "Required Trigger Sources", kind: FabricTypeInteger, unit: "sources", def: 1, min: intPtr(1), max: intPtr(4), class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Distinct trigger sources that must agree within the correlation window before an automatic lockdown fires. 1 fires on the first qualifying source; the operator API always bypasses this requirement because it is explicit intent."},
	{module: "lockdown", group: "Trigger Sources", key: "duress_token_path", label: "Duress Token File", kind: FabricTypePath, def: "", class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Optional absolute path of a bounded duress token file polled every second. Empty disables the poll entirely. A non-empty token triggers a MANUAL lockdown; the path is never disclosed by the status API."},

	// Isolation phases
	{module: "lockdown", group: "Isolation Phases", key: "network_lockdown", label: "Network Drop", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Ask the core to drop external traffic through the LOCKDOWN_STATE eBPF fast path (XDP/TC-ingress/cgroup egress). The phase is reported applied only after the core's read-back."},
	{module: "lockdown", group: "Isolation Phases", key: "allow_loopback", label: "Keep Loopback Reachable", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Pass 127.0.0.0/8 and ::1 through the lockdown drop so the authenticated clear path stays reachable. Disabling the clear path without a local fallback is an operator decision, not a default."},
	{module: "lockdown", group: "Isolation Phases", key: "drop_loopback", label: "Panic Mode: Drop Loopback", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Opt-in panic mode that also kills loopback. Clearing then only works from the local console, a duress file or a restart; the status API reports the isolation honestly."},
	{module: "lockdown", group: "Isolation Phases", key: "freeze_processes", label: "Freeze Incident Process", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Freeze the incident-bound process through the existing core response channel. UID 0 is excluded by default; without an incident-bound target the phase is reported unavailable instead of claiming a freeze."},
	{module: "lockdown", group: "Isolation Phases", key: "freeze_brokers", label: "Freeze Key Brokers", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Ask the core to SIGSTOP the fixed broker name list (ssh-agent, gpg-agent, gnome-keyring-d, keepassxc, vault, astraea-key-broker). The claim is frozen-not-locked: no RAM zeroization is performed."},
	{module: "lockdown", group: "Isolation Phases", key: "freeze_cells", label: "Freeze Gaia Cells", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Freeze live Gaia Cells through the existing CellGuard/TransactionEngine path. Cells already frozen count as applied; a missing runtime is reported unavailable, never as isolated."},
	{module: "lockdown", group: "Isolation Phases", key: "freeze_parser_cells", label: "Burn Parser Cells", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Burn managed parser-ephemeral cells through ParserCellManager.BurnForIncident. A parser cell is destroyed, never paused; without an active manager the phase is reported unavailable."},
	{module: "lockdown", group: "Isolation Phases", key: "cell_scope", label: "Cell Freeze Scope", kind: FabricTypeEnum, def: "all", class: FabricApplyHot, risk: FabricRiskCritical,
		enum: []string{"all", "high-risk"}, desc: "all freezes every live cell; high-risk freezes only the untrusted execution substrates (application/microvm) and keeps vault/workspace cells usable for the recovery console."},
	{module: "lockdown", group: "Isolation Phases", key: "hardening_apply", label: "Apply Reversible Hardening", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Forward LOCKDOWN_TRIGGER flag bit3 so the core writes its allowlisted reversible sysctls. modules_disabled is never applied automatically; an explicit LOCKDOWN_PHASE command is required for it."},

	// Resource bounds
	{module: "lockdown", group: "Resource Bounds", key: "cooldown_seconds", label: "Automatic Trigger Cooldown", kind: FabricTypeInteger, unit: "s", def: 300, min: intPtr(0), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Minimum interval between two automatic triggers. A suppressed candidate is counted once in the false-positive guard, not spammed into the event stream."},
	{module: "lockdown", group: "Resource Bounds", key: "max_targets", label: "Max Phase Targets", kind: FabricTypeInteger, unit: "targets", def: 256, min: intPtr(1), max: intPtr(1024), class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Bounds every per-phase target list (cells, parser cells, processes) so one trigger cannot walk an unbounded inventory. A truncated list is reported as bounded, not as fully covered."},
	{module: "lockdown", group: "Resource Bounds", key: "exclude_uid0", label: "Exclude UID 0", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Refuse to freeze a UID 0 process from the automatic path. Freezing root-owned infrastructure during an incident is how a recovery console is lost; the phase says so instead of doing it."},

	// ---------------------------------------------------------------- witness
	{module: "witness", group: "Transport", key: "enabled", label: "Out-of-Band Witness", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Enable out-of-band checkpoints. Disabled is the shipped default: no checkpoint is created, no request is sent and no export is produced."},
	{module: "witness", group: "Transport", key: "mode", label: "Witness Mode", kind: FabricTypeEnum, def: "off", class: FabricApplyHot, risk: FabricRiskHigh,
		enum: []string{"off", "http", "export"}, desc: "off disables the namespace, http uses the hardened pinned HTTPS client (Mode A), export is the air-gapped vgtw1 form (Mode B)."},
	{module: "witness", group: "Transport", key: "endpoint", label: "Witness Endpoint", kind: FabricTypeText, def: "", class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Absolute https base URL on port 443. The client appends /v1/challenge and /v1/checkpoint; redirects, proxies and any other port are refused."},
	{module: "witness", group: "Transport", key: "pinned_server_spki", label: "Pinned Server SPKI", kind: FabricTypeText, def: "", class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "SHA-256 over the server certificate's RawSubjectPublicKeyInfo as 64 lowercase hex characters. Compared in constant time before any checkpoint body is sent."},
	{module: "witness", group: "Transport", key: "pinned_server_key_file", label: "Pinned Receipt Key File", kind: FabricTypePath, def: "", class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Absolute path to the pinned Ed25519 receipt-verification public key (0600 file). Receipt signatures over VGT-GEDEFENSE-WITNESS-RECEIPT-V1 are verified against it."},
	{module: "witness", group: "Transport", key: "client_cert_file", label: "mTLS Client Certificate", kind: FabricTypePath, def: "", class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Optional client certificate for mutual TLS. It must be configured together with the client key file."},
	{module: "witness", group: "Transport", key: "client_key_file", label: "mTLS Client Key", kind: FabricTypePath, def: "", class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Optional client private key for mutual TLS (0600 file). It must be configured together with the client certificate file."},
	{module: "witness", group: "Transport", key: "auth_token_file", label: "Bearer Token File", kind: FabricTypePath, def: "", class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Optional absolute path to a 0600 bearer token file. The token itself never appears in the settings document or a log line."},
	{module: "witness", group: "Checkpoint Policy", key: "checkpoint_interval_seconds", label: "Checkpoint Interval", kind: FabricTypeInteger, unit: "s", def: 300, min: intPtr(30), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Ticker cadence at which a signed checkpoint is produced and, in http mode, pushed to the witness."},
	{module: "witness", group: "Checkpoint Policy", key: "nonce_ttl_seconds", label: "Challenge TTL", kind: FabricTypeInteger, unit: "s", def: 120, min: intPtr(10), max: intPtr(900), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Client-side lifetime of an accepted witness challenge. A nonce is used once and never replayed."},
	{module: "witness", group: "Checkpoint Policy", key: "request_timeout_seconds", label: "Request Timeout", kind: FabricTypeInteger, unit: "s", def: 10, min: intPtr(1), max: intPtr(60), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Timeout of one witness HTTP round trip. The response body is additionally capped at 64 KiB."},
	{module: "witness", group: "Checkpoint Policy", key: "require_ack", label: "Require Receipt", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "A push without a verified signed receipt is a degraded delivery, not a success. Phase 1 always requires the receipt."},
	{module: "witness", group: "Outbox & Retry", key: "outbox_max_bytes", label: "Outbox Maximum Bytes", kind: FabricTypeInteger, unit: "bytes", def: 4 << 20, min: intPtr(64 << 10), max: intPtr(64 << 20), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Encrypted outbox size bound. A full outbox fails closed: no new checkpoint is created and witness.outbox_full is recorded."},
	{module: "witness", group: "Outbox & Retry", key: "outbox_max_entries", label: "Outbox Maximum Entries", kind: FabricTypeInteger, def: 1024, min: intPtr(16), max: intPtr(65536), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Encrypted outbox entry bound. Acknowledged entries are pruned; a full outbox refuses new checkpoints instead of dropping evidence."},
	{module: "witness", group: "Outbox & Retry", key: "retry_attempts", label: "Retry Attempts", kind: FabricTypeInteger, def: 3, min: intPtr(0), max: intPtr(10), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Bounded retries for 5xx and network errors. A 4xx answer is never retried."},
	{module: "witness", group: "Outbox & Retry", key: "retry_backoff_seconds", label: "Retry Backoff", kind: FabricTypeInteger, unit: "s", def: 30, min: intPtr(1), max: intPtr(3600), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Base of the bounded exponential backoff between push attempts."},
	{module: "witness", group: "Outbox & Retry", key: "degrade_after_failures", label: "Degrade After Failures", kind: FabricTypeInteger, def: 3, min: intPtr(1), max: intPtr(100), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Consecutive push failures after which the witness status reports degraded. Unreachability never triggers a lockdown."},
	{module: "witness", group: "Escalation", key: "equivocation_alarm", label: "Equivocation Alarm", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Record critical evidence and an incident when the ledger epoch/sequence/head disagrees with the last acknowledged or observed checkpoint."},
	{module: "witness", group: "Escalation", key: "trigger_lockdown_on_equivocation", label: "Lockdown on Equivocation", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Optionally latch the P5 Emergency Lockdown when equivocation or rollback is proven. Off by default; the lockdown namespace must be enabled too."},
	// ------------------------------------------------------------ 6.1.0 modules
	// web_exposure (Module A): read-only posture sensor. The shipped default is
	// enabled because it only reads /proc, the server binaries and the configured
	// configuration roots; the loopback ALPN probe is the only network activity
	// and it is bounded to 127.0.0.1.
	{module: "web_exposure", group: "Detection", key: "enabled", label: "Web Exposure Sensor", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Read-only discovery of the local web server posture (binary build flags, listeners, configuration lines). Disabling stops discovery entirely; no host behaviour changes either way."},
	{module: "web_exposure", group: "Probe & Advisories", key: "probe_loopback_alpn", label: "Loopback ALPN Probe", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Dial 127.0.0.1 on the listening TLS port and read the negotiated ALPN protocol, TLS version and cipher. The probe accepts any certificate and sends no application data."},
	{module: "web_exposure", group: "Probe & Advisories", key: "probe_timeout_seconds", label: "Probe Timeout", kind: FabricTypeInteger, unit: "s", def: 3, min: intPtr(1), max: intPtr(10), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Deadline for one loopback ALPN probe."},
	{module: "web_exposure", group: "Probe & Advisories", key: "config_roots", label: "Configuration Roots", kind: FabricTypeList, def: []string{"/etc/nginx", "/www/server/nginx/conf", "/www/server/panel/vhost/nginx", "/etc/apache2", "/etc/httpd"}, class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Absolute directories searched for nginx/apache configuration evidence. The walk is bounded (2048 files, 1 MiB per file), never follows symlinks and never executes a directive."},
	{module: "web_exposure", group: "Probe & Advisories", key: "extra_advisories_json", label: "Extra Advisories", kind: FabricTypeJSON, def: []string{}, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Array of {id, product, min_version, max_version, severity, summary, workaround, requires_alpn, requires_reachable, requires_http2, requires_quic}. Entries only match a version that is also reachable for the affected feature."},
	{module: "web_exposure", group: "Bounds", key: "max_servers", label: "Max Servers", kind: FabricTypeInteger, def: 32, min: intPtr(8), max: intPtr(128), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Bound on the number of web-server processes reported and inspected."},
	{module: "web_exposure", group: "Bounds", key: "scan_interval_seconds", label: "Scan Interval", kind: FabricTypeInteger, unit: "s", def: 60, min: intPtr(15), max: intPtr(3600), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Cache lifetime of the posture report. A manual POST /web-exposure/scan refreshes on demand inside the server rate budget."},

	// worker_guard (Module B): fatal-crash correlation and strict-cgroup scope.
	// The shipped default is disabled; enabling it subscribes a kernel crash source
	// and nothing is enforced unless strict_exec/strict_mmap are enabled.
	{module: "worker_guard", group: "Registry", key: "enabled", label: "Worker Integrity Watch", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Enable the worker crash-storm watch. Disabled (the upgrade default) means no crash source is subscribed and host behaviour is unchanged."},
	{module: "worker_guard", group: "Registry", key: "comms", label: "Worker Names", kind: FabricTypeList, def: []string{"nginx", "apache2", "httpd", "php-fpm"}, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Kernel comm names (1-15 bytes) classified as web workers. Matching is a prefix, so 'php-fpm' also covers 'php-fpm: pool www'."},
	{module: "worker_guard", group: "Registry", key: "uids", label: "Worker UIDs", kind: FabricTypeList, def: []uint32{}, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Optional numeric UID filter. Empty means the comm registry alone decides."},
	{module: "worker_guard", group: "Registry", key: "exclude_units", label: "Excluded Control Units", kind: FabricTypeList, def: []string{"systemd", "master", "php-fpm: master"}, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Additional master/control-unit names that must never enter the strict scope. The compiled-in denylist (systemd, init, master, ...) cannot be shortened by this list."},
	{module: "worker_guard", group: "Crash Storm", key: "storm_threshold", label: "Crash Threshold", kind: FabricTypeInteger, def: 3, min: intPtr(2), max: intPtr(100), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Fatal crashes of one comm+uid inside the window that escalate to one CRITICAL XDR.WORKER_CRASH_STORM incident."},
	{module: "worker_guard", group: "Crash Storm", key: "storm_window_seconds", label: "Window", kind: FabricTypeInteger, unit: "s", def: 60, min: intPtr(10), max: intPtr(600), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Rolling correlation window. One incident is opened per comm+window; the crashes keep producing audit events."},
	{module: "worker_guard", group: "Crash Storm", key: "correlate_peers", label: "Correlate TLS Peers", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Attach the TLS sensor's recent peer snapshot to a crash-storm incident (bounded to 8 peers)."},
	{module: "worker_guard", group: "Enforcement", key: "strict_exec", label: "Strict Exec Scope", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Classify registered workers into the Titan exec-gate strict scope (shared library and exec mapping denial). Requires the module to be enabled; the scope is applied through the existing Titan exec settings/apply path."},
	{module: "worker_guard", group: "Enforcement", key: "strict_mmap", label: "Strict Mmap Scope", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Additionally deny anonymous W+X mappings outside the JIT scopes for the classified worker cgroups."},
	{module: "worker_guard", group: "Enforcement", key: "auto_apply_strict", label: "Apply Strict Scope Automatically", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Write the computed strict-cgroup list into the Titan exec namespace and apply it. Off by default: an upgrade never writes a kernel scope on its own."},

	// tls_sensor (Module C): passive ClientHello capture and the control-storm
	// budget. Disabled by default; the response is alert-only by default.
	{module: "tls_sensor", group: "Capture", key: "enabled", label: "TLS/ALPN Sensor", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Enable the AF_PACKET ClientHello sensor. Disabled (the upgrade default) means no capture socket, no flow snapshot and no event."},
	{module: "tls_sensor", group: "Capture", key: "interfaces", label: "Interfaces", kind: FabricTypeList, def: []string{}, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Capture interfaces. Empty means every interface."},
	{module: "tls_sensor", group: "Capture", key: "ports", label: "TLS Ports", kind: FabricTypePorts, def: []uint16{443, 8443}, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Destination ports of the passive capture and of the flow snapshot (TCP/UDP)."},
	{module: "tls_sensor", group: "Capture", key: "max_payload_bytes", label: "Max ClientHello Bytes", kind: FabricTypeInteger, unit: "bytes", def: 1536, min: intPtr(512), max: intPtr(2048), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Bound on the payload handed to the TLS parser per handshake. The capture keeps no payload after parsing."},
	{module: "tls_sensor", group: "Budget & Storm", key: "max_tracked_flows", label: "Max Tracked Flows", kind: FabricTypeInteger, def: 4096, min: intPtr(256), max: intPtr(65536), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Capacity of the bounded flow table. The kernel counters are re-read on every snapshot, so eviction is safe."},
	{module: "tls_sensor", group: "Budget & Storm", key: "rx_threshold_bytes", label: "Inbound Byte Threshold", kind: FabricTypeInteger, unit: "bytes", def: 256 << 20, min: intPtr(64 << 20), max: intPtr(8 << 30), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Storm predicate: inbound bytes per flow must exceed this value."},
	{module: "tls_sensor", group: "Budget & Storm", key: "tx_ratio", label: "Rx:Tx Ratio", kind: FabricTypeInteger, def: 4, min: intPtr(2), max: intPtr(64), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Storm predicate: rx_bytes must exceed tx_ratio * tx_bytes. Control storms are one-sided; uploads are not."},
	{module: "tls_sensor", group: "Budget & Storm", key: "avg_pkt_len_bytes", label: "Max Average Packet Length", kind: FabricTypeInteger, unit: "bytes", def: 240, min: intPtr(64), max: intPtr(512), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Storm predicate: rx_bytes / max(segs_in,1) must stay below this value. This is the test that keeps a large upload from ever triggering."},
	{module: "tls_sensor", group: "Budget & Storm", key: "min_pps_ratio", label: "Min Packet Ratio", kind: FabricTypeInteger, def: 8, min: intPtr(2), max: intPtr(1000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Storm predicate: segs_in must exceed min_pps_ratio * max(segs_out,1)."},
	{module: "tls_sensor", group: "Response", key: "alert_only", label: "Alert Only", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Record storm incidents without any response stage. Off enables the staged throttle plan and, after two consecutive matches, a ban candidate. The sensor itself never bans a flow that fails the average-length test."},
	{module: "tls_sensor", group: "Response", key: "throttle_ttl_seconds", label: "Throttle TTL", kind: FabricTypeInteger, unit: "s", def: 900, min: intPtr(60), max: intPtr(86400), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Lifetime of a per-peer throttle plan recorded for a matching flow."},

	// lpe_guard (Module D): socket-deny policy, StyX web-ingress profile and the
	// kernel LPE baseline. Disabled by default; applying is an explicit POST.
	{module: "lpe_guard", group: "Socket Policy", key: "enabled", label: "LPE Guard", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Enable the LPE kill-chain plan. Disabled (the upgrade default) means no socket policy, no StyX profile and no hardening change is applied; the plans are still rendered read-only."},
	{module: "lpe_guard", group: "Socket Policy", key: "deny_af_packet", label: "Deny AF_PACKET", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Cell-LSM flag bit 1: deny raw packet socket creation for the web-worker cgroups."},
	{module: "lpe_guard", group: "Socket Policy", key: "deny_af_tipc", label: "Deny AF_TIPC", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Cell-LSM flag bit 2: deny AF_TIPC socket creation."},
	{module: "lpe_guard", group: "Socket Policy", key: "deny_af_vsock", label: "Deny AF_VSOCK", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Cell-LSM flag bit 3: deny AF_VSOCK socket creation."},
	{module: "lpe_guard", group: "Socket Policy", key: "deny_sctp", label: "Deny SCTP", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Cell-LSM flag bit 4: deny SCTP socket creation."},
	{module: "lpe_guard", group: "Socket Policy", key: "deny_dccp", label: "Deny DCCP", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Cell-LSM flag bit 5: deny DCCP socket creation."},
	{module: "lpe_guard", group: "Socket Policy", key: "deny_rds", label: "Deny RDS", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Cell-LSM flag bit 6: deny RDS socket creation."},
	{module: "lpe_guard", group: "StyX Profile", key: "styx_profile", label: "Web-Ingress-Only Profile", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Render and apply the StyX egress profile for web workers: loopback, the configured backend CIDRs and the DNS resolvers are allowed, everything else is denied. Requires the styX namespace enabled with mode monitor/enforce."},
	{module: "lpe_guard", group: "StyX Profile", key: "styx_backend_cidrs", label: "Backend CIDRs", kind: FabricTypeList, def: []string{}, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Canonical CIDR/address list the web workers may reach as their upstream backend."},
	{module: "lpe_guard", group: "StyX Profile", key: "styx_dns_servers", label: "DNS Resolvers", kind: FabricTypeList, def: []string{}, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "DNS resolver CIDR/address list pinned in the StyX profile."},
	{module: "lpe_guard", group: "Kernel Baseline", key: "enforce_aslr", label: "Enforce ASLR", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Marks kernel.randomize_va_space=2 as enforceable and reports the sysctl transaction apply/rollback plan. Nothing is written without an operator transaction."},
	{module: "lpe_guard", group: "Kernel Baseline", key: "block_lpe_modules", label: "Check SCTP/DCCP/RDS Modules", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Report the sctp/dccp/rds module state from /proc/modules and /etc/modprobe.d with the concrete modprobe.d apply/rollback plan."},

	// edge_proxy (Module E settings): the memory-safe edge terminator is owned by
	// control/edge_proxy.go; this namespace is its operator contract. Off by
	// default and loopback-only by validation.
	{module: "edge_proxy", group: "Listener", key: "enabled", label: "Edge Terminator", kind: FabricTypeBoolean, def: false, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Enable the Go TLS terminator. Disabled (the upgrade default) means no listener is opened."},
	{module: "edge_proxy", group: "Listener", key: "listen", label: "Listen Address", kind: FabricTypeText, def: "127.0.0.1:8443", class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Loopback host:port only. The terminator is fronted by the gateway; a public bind is refused."},
	{module: "edge_proxy", group: "Listener", key: "cert_file", label: "TLS Certificate", kind: FabricTypePath, def: "", class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Absolute path of the server certificate. Must be configured together with the key file."},
	{module: "edge_proxy", group: "Listener", key: "key_file", label: "TLS Key", kind: FabricTypePath, def: "", class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Absolute path of the server private key. Must be configured together with the certificate file."},
	{module: "edge_proxy", group: "Listener", key: "min_tls_version", label: "Minimum TLS Version", kind: FabricTypeEnum, def: "TLS1.3", class: FabricApplyHot, risk: FabricRiskHigh,
		enum: []string{"TLS1.2", "TLS1.3"}, desc: "Minimum accepted TLS version. TLS1.3 is the shipped default; TLS1.2 exists for legacy clients."},
	{module: "edge_proxy", group: "Hard Limits", key: "max_concurrent_streams", label: "Max Concurrent Streams", kind: FabricTypeInteger, def: 128, min: intPtr(16), max: intPtr(1024), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "RFC 9113 SETTINGS_MAX_CONCURRENT_STREAMS advertised by the terminator."},
	{module: "edge_proxy", group: "Hard Limits", key: "max_header_bytes", label: "Max Header Bytes", kind: FabricTypeInteger, unit: "bytes", def: 32768, min: intPtr(8192), max: intPtr(131072), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Aggregate request header budget."},
	{module: "edge_proxy", group: "Hard Limits", key: "max_body_bytes", label: "Max Body Bytes", kind: FabricTypeInteger, unit: "bytes", def: 8388608, min: intPtr(65536), max: intPtr(67108864), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Hard request body bound. Inline WAF inspection requires at most 16 MiB."},
	{module: "edge_proxy", group: "Hard Limits", key: "idle_timeout_seconds", label: "Idle Timeout", kind: FabricTypeInteger, unit: "s", def: 60, min: intPtr(5), max: intPtr(600), class: FabricApplyHot, risk: FabricRiskLow,
		desc: "Keep-alive idle timeout of the terminator."},
	{module: "edge_proxy", group: "Hard Limits", key: "request_timeout_seconds", label: "Request Timeout", kind: FabricTypeInteger, unit: "s", def: 30, min: intPtr(5), max: intPtr(300), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Whole-request deadline for one proxied request."},
	{module: "edge_proxy", group: "Upstream & WAF", key: "upstream", label: "Upstream", kind: FabricTypeText, def: "http://127.0.0.1:8080", class: FabricApplyHot, risk: FabricRiskCritical,
		desc: "Loopback http(s) URL of the protected application. Non-loopback upstreams are refused."},
	{module: "edge_proxy", group: "Upstream & WAF", key: "allowed_methods", label: "Allowed Methods", kind: FabricTypeList, def: []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Closed HTTP method vocabulary accepted by the terminator; any other method is refused."},
	{module: "edge_proxy", group: "Upstream & WAF", key: "waf_inline", label: "Inline WAF", kind: FabricTypeBoolean, def: true, class: FabricApplyHot, risk: FabricRiskHigh,
		desc: "Run the existing inline WAF checks on the proxied request before it reaches the upstream."},
	{module: "edge_proxy", group: "Upstream & WAF", key: "rate_limit_per_minute", label: "Rate Limit", kind: FabricTypeInteger, unit: "/min", def: 600, min: intPtr(10), max: intPtr(100000), class: FabricApplyHot, risk: FabricRiskMedium,
		desc: "Per-client request budget enforced by the terminator."},
}

var (
	fabricSettingIndex = map[string]FabricSettingMetadata{}
	fabricSchemaGroups = map[string][]FabricSettingMetadata{}
)

func fabricSettingKey(module, key string) string { return module + "." + key }

func init() {
	for _, definition := range fabricSettingDefinitions {
		meta := FabricSettingMetadata{
			Key: definition.key, Module: definition.module, Group: definition.group,
			Label: definition.label, Type: definition.kind, Unit: definition.unit,
			Minimum: definition.min, Maximum: definition.max, Enum: definition.enum,
			Default: definition.def, ApplyClass: definition.class, Risk: definition.risk,
			Description: definition.desc,
		}
		indexKey := fabricSettingKey(definition.module, definition.key)
		fabricSettingIndex[indexKey] = meta
		fabricSchemaGroups[definition.module] = append(fabricSchemaGroups[definition.module], meta)
	}
	for module := range fabricSchemaGroups {
		group := fabricSchemaGroups[module]
		sort.SliceStable(group, func(i, j int) bool { return group[i].Key < group[j].Key })
		fabricSchemaGroups[module] = group
	}
}

// fabricSettingFor resolves the authoritative metadata for a flattened diff
// key such as "advanced.worker_count" inside a module namespace.
func fabricSettingFor(module, key string) (FabricSettingMetadata, bool) {
	key = strings.ToLower(strings.TrimSpace(key))
	meta, ok := fabricSettingIndex[fabricSettingKey(module, key)]
	return meta, ok
}

// fabricModuleSettings returns the full schema of one module in a stable
// order that preserves the operator-facing group sequence.
func fabricModuleSettings(module string) []FabricSettingMetadata {
	if _, ok := fabricModuleGroups[module]; !ok {
		return nil
	}
	order := fabricModuleGroups[module]
	out := make([]FabricSettingMetadata, 0, len(fabricSchemaGroups[module]))
	for _, group := range order {
		for _, meta := range fabricSchemaGroups[module] {
			if meta.Group == group {
				out = append(out, meta)
			}
		}
	}
	return out
}

// fabricModuleGroups lists the operator-facing group order per module. Groups
// missing from this table are appended alphabetically.
var fabricModuleGroups = map[string][]string{
	"kinetic":      {"Engine & Response", "Rate, Flood & Portscan", "Botnet / Subnet Correlation", "Service Classification"},
	"network":      {"CIDR Policy Limits", "Management Survival"},
	"detection":    {"Post-Exploitation Rules", "Protected Surface"},
	"protection":   {"Fabric Safety"},
	"xdr":          {"Engine & Sensors", "Scanning & Pipeline", "Decision Scores & Response", "Behavior Learning", "Process Scope", "Rule Modules"},
	"l7":           {"Engine", "Request Limits", "Scores", "Client Rate Limiting", "Sensitive Path Limiting", "Peer Authentication", "Inline Edge", "TLS Defense", "L7 Rule Registry"},
	"threat_intel": {"Global", "Resource Bounds", "Transport Safety", "Validation", "Retry", "Kernel Apply", "Feed Sources"},
	"hardening":    {"Posture", "Sysctl Profiles", "Morpheus RASP", "Deception", "Airlock"},
	"integrity":    {"File Integrity", "Chronos", "Package Integrity", "Evidence Ledger"},
	"boot_trust":   {"Evidence Cache", "TPM Attestation", "Platform Anchors", "Kernel Command Line", "Resource Bounds"},
	"policy_trust": {"Signature Enforcement", "Verification", "Resource Bounds"},
	"forensics":    {"Cases", "Export", "Quarantine"},
	"system":       {"Dashboard", "Resource Bounds", "Core IPC"},
	"styx":         {"Kernel Egress Enforcement", "Per-Cell Policy", "DNS Pinning"},
	"titan_exec":   {"Kernel Exec Gate", "Allowlist Sources", "Per-Cgroup Scopes", "Resource Bounds"},
	"parser_cells": {"Parser Cells", "Resource Limits", "Incident Response"},
	"lockdown":     {"Emergency Lockdown", "Trigger Sources", "Isolation Phases", "Resource Bounds"},
	"witness":      {"Transport", "Checkpoint Policy", "Outbox & Retry", "Escalation"},
	"web_exposure": {"Detection", "Probe & Advisories", "Bounds"},
	"worker_guard": {"Registry", "Crash Storm", "Enforcement"},
	"tls_sensor":   {"Capture", "Budget & Storm", "Response"},
	"lpe_guard":    {"Socket Policy", "StyX Profile", "Kernel Baseline"},
	"edge_proxy":   {"Listener", "Hard Limits", "Upstream & WAF"},
}

// fabricSettingsSchema is the global settings schema endpoint. It exposes the
// authoritative metadata so the dashboard can render validation, tooltips and
// risk classification from the same source the backend enforces.
func (s *APIServer) fabricSettingsSchema(w http.ResponseWriter, _ *http.Request) {
	modules := make([]string, 0, len(fabricModuleGroups))
	for module := range fabricModuleGroups {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	settings := make([]FabricSettingMetadata, 0, len(fabricSettingIndex))
	for _, module := range modules {
		settings = append(settings, fabricModuleSettings(module)...)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"apply_classes": []string{FabricApplyHot, FabricApplyReload, FabricApplyDrain, FabricApplyRestart, FabricApplyReboot},
		"risk_levels":   []string{FabricRiskLow, FabricRiskMedium, FabricRiskHigh, FabricRiskCritical},
		"modules":       modules,
		"settings":      settings,
	})
}

// fabricModuleRestartClass reports every restart-class key of one module so the
// runtime can distinguish "persisted but not yet active" from "active".
func fabricModuleRestartClass(module string) []string {
	keys := fabricModuleSettings(module)
	out := make([]string, 0, len(keys))
	for _, meta := range keys {
		if meta.ApplyClass == FabricApplyRestart || meta.ApplyClass == FabricApplyReboot || meta.ApplyClass == FabricApplyDrain {
			out = append(out, meta.Key)
		}
	}
	sort.Strings(out)
	return out
}
