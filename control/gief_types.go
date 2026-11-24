// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6: GIEF v1.0 — types, constants and the closed classification
// tables (rule id -> sensor class / SBC family).
//
// The tables are the contract behind the envelope: every rule id this codebase
// emits resolves deterministically here, and anything the tables do not know
// resolves to the documented default family (counted in GIEFStats). The envelope
// builder itself lives in gief.go.

import "strings"

const (
	// GIEFVersion is the versioned format identifier of the envelope.
	GIEFVersion = "gief/v1.0"

	// GIEFCapability.Level values.
	//
	// Mapping (implemented by giefCapabilityFor, documented on the function):
	//
	//	full        — kernel-proven observation and the platform capability it
	//	              depends on is present; XDR itself is not degraded.
	//	partial     — kernel-proven observation, but the platform is degraded or a
	//	              capability the finding depends on is unavailable.
	//	minimal     — userspace time-correlated evidence only; no kernel proof.
	//	unavailable — no classified observation basis for the finding at all.
	giefLevelFull        = "full"
	giefLevelPartial     = "partial"
	giefLevelMinimal     = "minimal"
	giefLevelUnavailable = "unavailable"

	// GIEFCapability.Visibility values (the channel the finding was observed on).
	giefVisibilityObserved = "OBSERVED"
	giefVisibilityTemporal = "TEMPORAL"
	giefVisibilityNone     = "NONE"

	// GIEF CorrelationQuality values (the strength of the evidence chain).
	giefCorrelationObserved = "OBSERVED"
	giefCorrelationTemporal = "TEMPORAL"
	giefCorrelationNone     = "NONE"

	// The eight SBC-01..08 evidence families. The numeric suffix is part of the
	// stable contract; the mapping of rule ids to families is the explicit table
	// giefRuleSBCFamily in gief.go.
	SBCFamilyProvenance  = "SBC-PROV-01"
	SBCFamilyExecution   = "SBC-EXEC-02"
	SBCFamilyKernel      = "SBC-KERNL-03"
	SBCFamilyCredential  = "SBC-CRED-04"
	SBCFamilyC2          = "SBC-C2-05"
	SBCFamilyPersistence = "SBC-PERSIST-06"
	SBCFamilyEvasion     = "SBC-EVASION-07"
	SBCFamilyEvidence    = "SBC-EVID-08"

	// SBCDefaultFamily is the documented default for a rule id the closed table
	// does not know. Every default assignment is counted (GIEFStats.DefaultFamily).
	SBCDefaultFamily = SBCFamilyExecution

	// GIEF envelope bounds. Every list in the envelope is capped, every text is
	// bounded, and nothing is truncated silently: a bound that bites is visible
	// in the content itself.
	giefMaxStages         = 8
	giefMaxEvidenceHashes = 8
	giefMaxExplanations   = 8
	giefMaxBlindspots     = 8
	giefMaxTextBytes      = 200

	// Attack-story metadata keys already produced by the sensors. Reading them
	// is how the envelope stays consistent with a per-finding assessment that a
	// kernel sensor already made (AP-0 self-guard, AP-1 exec-inode, AP-5
	// persistence/peripheral). The envelope may only *downgrade* a correlation
	// claim using them, never upgrade one.
	giefCorrelationMetadataKey = "correlation_quality"
	giefFamilyMetadataKey      = "sbc_family"
	giefEntityMetadataKey      = "sbc_entity"
)

// giEFCorrelationRanks orders the three quality values: a lower rank is weaker.
// Sensor-declared metadata may only lower the rank derived from the rule table.
var giefCorrelationRanks = map[string]int{
	giefCorrelationNone:     0,
	giefCorrelationTemporal: 1,
	giefCorrelationObserved: 2,
}

// GIEFEnvelope is the versioned finding envelope attached to XDR incidents.
//
// The pre-existing exported fields are a stable JSON contract. `SBC` is an
// additive, omitempty extension carrying the time-weighted fusion context that
// existed for the same entity *before* this finding was observed.
type GIEFEnvelope struct {
	Version            string         `json:"version"`
	Capability         GIEFCapability `json:"capability"`
	CorrelationQuality string         `json:"correlation_quality"`
	SBCFamily          string         `json:"sbc_family"`
	Stages             []string       `json:"stages,omitempty"`
	EvidenceHashes     []string       `json:"evidence_hashes,omitempty"`
	Explanations       []string       `json:"explanations,omitempty"`
	Blindspots         []string       `json:"blindspots,omitempty"`
	SBC                *SBCContext    `json:"sbc,omitempty"`
}

// GIEFCapability is the GIEF v1.0 capability block of one finding.
//
// Degraded is true when the platform's XDR state is degraded or when the
// observation channel this finding depends on is not available (e.g. a
// BPF-LSM-derived finding on a kernel without an active BPF LSM). Reason names
// the concrete condition in bounded, secret-free text; it is never a generic
// "degraded" claim.
type GIEFCapability struct {
	Level      string `json:"level"`
	Visibility string `json:"visibility"`
	Degraded   bool   `json:"degraded"`
	Reason     string `json:"reason,omitempty"`
}

// GIEFStats is the bounded counter projection of the envelope builder.
type GIEFStats struct {
	// Envelopes is the number of envelopes built since start.
	Envelopes uint64 `json:"envelopes"`
	// UnknownRuleIDs counts rule ids that the closed classification table did
	// not know (they still receive a documented deterministic family).
	UnknownRuleIDs uint64 `json:"unknown_rule_ids"`
	// DefaultFamily counts envelopes that received SBCDefaultFamily because no
	// rule id and no category mapped to a closed family.
	DefaultFamily uint64 `json:"default_family"`
	// CorrelationDowngrades counts envelopes whose correlation claim was
	// lowered by sensor-declared per-finding evidence metadata.
	CorrelationDowngrades uint64 `json:"correlation_downgrades"`
}

// giefFacts is the engine state the capability block is derived from. It is
// filled once per incident by attachGIEFEnvelope and passed to the pure builder,
// so every mapping decision is testable without a live engine.
type giefFacts struct {
	// degraded/degradedReason come from XDREngine.degradedState().
	degraded       bool
	degradedReason string
	// capsKnown is true when DetectPlatformCapabilities ran (DetectedAt set).
	capsKnown bool
	// hasBPFLSM is the platform fact kernel LSM findings depend on.
	hasBPFLSM bool
	// hasCgroupV2 is reported as context for kernel-telemetry findings.
	hasCgroupV2 bool
}

// giefSensorClass classifies *how* a rule id is observed. It decides the
// visibility and the capability level; it is deliberately independent of the
// SBC family (what the finding is about).
type giefSensorClass uint8

const (
	// giefSensorClassNone: the rule id is not in the closed table. No observation
	// basis is claimed (visibility NONE, correlation NONE, level unavailable).
	giefSensorClassNone giefSensorClass = iota
	// giefSensorClassUserspace: userspace polling/behavior/regex evidence only.
	giefSensorClassUserspace
	// giefSensorClassKernelLSM: kernel BPF-LSM hook observations. Depends on an
	// active BPF LSM on the platform.
	giefSensorClassKernelLSM
	// giefSensorClassKernelTelemetry: kernel tracepoint / iterator / cross-view /
	// NETLINK_SOCK_DIAG observations. Kernel-proven, but not LSM-dependent.
	giefSensorClassKernelTelemetry
	// giefSensorClassIntegrity: cryptographic/platform-integrity checks (digest
	// baseline, witness chain). Not LSM-dependent; this is proven evidence, but it
	// is not a heuristic over time-correlated userspace samples.
	giefSensorClassIntegrity
	// giefSensorClassHealth: operational platform/sensor-health events (fail-safe
	// transitions, scan/queue failures, worker crash storms). They report the
	// state of the sensor itself, not an observed threat, so no observation
	// channel and no correlation quality are claimed for them.
	giefSensorClassHealth
)

// String returns the stable sensor-channel token used in stage/explanation text.
func (c giefSensorClass) String() string {
	switch c {
	case giefSensorClassKernelLSM:
		return "kernel-bpf-lsm"
	case giefSensorClassKernelTelemetry:
		return "kernel-telemetry"
	case giefSensorClassIntegrity:
		return "platform-integrity"
	case giefSensorClassHealth:
		return "platform-health"
	case giefSensorClassUserspace:
		return "userspace"
	default:
		return "unclassified"
	}
}

// ---------------------------------------------------------------- rule tables

// giefRuleClassification is the deterministic closed classification of one rule id.
type giefRuleClassification struct {
	family string
	class  giefSensorClass
}

// giefRuleClassifications is the explicit, closed table of rule ids produced by
// this codebase. Kernel-proven families are listed first; the sender of each
// finding is what decides the sensor class, not the severity of the finding.
var giefRuleClassifications = map[string]giefRuleClassification{
	// AP-1/AP-2/AP-4/AP-5 kernel BPF-LSM observations.
	"XDR.CREDENTIAL_READ_BLOCKED": {SBCFamilyCredential, giefSensorClassKernelLSM},
	"XDR.KERNEL_PROTOCOL_PROBE":   {SBCFamilyKernel, giefSensorClassKernelLSM},
	"XDR.LD_PRELOAD_INTEGRITY":    {SBCFamilyPersistence, giefSensorClassKernelLSM},
	"XDR.LINKER_HOOK":             {SBCFamilyPersistence, giefSensorClassKernelLSM},
	"XDR.PERSISTENCE_ENTRY_DRIFT": {SBCFamilyPersistence, giefSensorClassKernelLSM},
	"XDR.PERIPHERAL_BG_ACCESS":    {SBCFamilyEvasion, giefSensorClassKernelLSM},
	"XDR.EVDEV_KEYLOG_PROBE":      {SBCFamilyEvasion, giefSensorClassKernelLSM},
	"XDR.MEMORY_SCRAPE_PROBE":     {SBCFamilyCredential, giefSensorClassKernelLSM},
	"XDR.SECRET_STORE_ACCESS":     {SBCFamilyCredential, giefSensorClassKernelLSM},
	"CELL.LSM_SOCKET_DENY":        {SBCFamilyKernel, giefSensorClassKernelLSM},
	"TITAN.EXEC_AUDIT":            {SBCFamilyExecution, giefSensorClassKernelLSM},
	"TITAN.EXEC_DENIED":           {SBCFamilyExecution, giefSensorClassKernelLSM},
	"TITAN.MMAP_DENIED":           {SBCFamilyExecution, giefSensorClassKernelLSM},

	// AP-0/AP-2/AP-3/AP-4/AP-6 kernel tracepoint / iterator / cross-view telemetry.
	"XDR.PTRACE_ATTEMPT":         {SBCFamilyEvasion, giefSensorClassKernelTelemetry},
	"XDR.CREDENTIAL_PROBE":       {SBCFamilyCredential, giefSensorClassKernelTelemetry},
	"XDR.SYMLINK_OVER_SENSITIVE": {SBCFamilyCredential, giefSensorClassKernelTelemetry},
	"XDR.NAME_PATH_MISMATCH":     {SBCFamilyEvasion, giefSensorClassKernelTelemetry},
	"XDR.RANSOM_ENTROPY_BURST":   {SBCFamilyEvidence, giefSensorClassKernelTelemetry},
	"XDR.RANSOM_RENAME_STORM":    {SBCFamilyEvidence, giefSensorClassKernelTelemetry},
	"XDR.BPF_ANOMALY":            {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.BPF_ROOTKIT_HELPER":     {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.BPF_PIN_TAMPER":         {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.BPF_LINK_TAMPER":        {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.HIDDEN_BPF_PROG":        {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.HIDDEN_BPF_MAP":         {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.HIDDEN_BPF_LINK":        {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.HIDDEN_SOCKET":          {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.HIDDEN_PROCESS":         {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.LKM_HIDDEN":             {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.LKM_LOAD":               {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.FTRACE_HOOK_ANOMALY":    {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.IO_URING_ANOMALY":       {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.PORTLESS_RAW_TAP":       {SBCFamilyC2, giefSensorClassKernelTelemetry},
	"XDR.CROSS_VIEW_ANOMALY":     {SBCFamilyKernel, giefSensorClassKernelTelemetry},
	"XDR.LIBRARY_CROSSVIEW":      {SBCFamilyPersistence, giefSensorClassUserspace},
	"XDR.STYX_PCR_EXFIL":         {SBCFamilyC2, giefSensorClassKernelTelemetry},
	"XDR.PCR_ANOMALY":            {SBCFamilyC2, giefSensorClassKernelTelemetry},

	// AP-0 adversarial/self-protection observations (cryptographic platform checks).
	// SELF_TAMPER is explicitly part of the closed OBSERVED set: the evidence is a
	// digest comparison, not a heuristic.
	"XDR.SELF_TAMPER":      {SBCFamilyEvidence, giefSensorClassIntegrity},
	"XDR.SELF_ARTIFACT":    {SBCFamilyEvidence, giefSensorClassIntegrity},
	"WITNESS.EQUIVOCATION": {SBCFamilyEvidence, giefSensorClassIntegrity},

	// Operational platform/sensor-health events: they report the state of the
	// sensor, not an observed threat, so they claim no observation channel.
	"XDR.WORKER_CRASH_STORM":       {SBCFamilyEvidence, giefSensorClassHealth},
	"RELEASE.FAIL_SAFE":            {SBCFamilyEvidence, giefSensorClassHealth},
	"MALWARE.SCAN_FAILURE":         {SBCFamilyEvidence, giefSensorClassHealth},
	"MALWARE.EVENT_QUEUE_OVERFLOW": {SBCFamilyEvidence, giefSensorClassHealth},

	// Userspace time-correlated heuristics over /proc, cmdline, behaviour, feeds,
	// content scans and network samples. These are never claimed as OBSERVED.
	"XDR.EXE_DELETED":                {SBCFamilyEvasion, giefSensorClassUserspace},
	"XDR.MEMFD_EXEC":                 {SBCFamilyProvenance, giefSensorClassUserspace},
	"XDR.TEMP_EXEC":                  {SBCFamilyProvenance, giefSensorClassUserspace},
	"XDR.WEB_SHELL_LINEAGE":          {SBCFamilyExecution, giefSensorClassUserspace},
	"XDR.THREAT_INTEL_C2":            {SBCFamilyC2, giefSensorClassUserspace},
	"XDR.ANOMALY.EXEC_BURST":         {SBCFamilyExecution, giefSensorClassUserspace},
	"XDR.ANOMALY.CONNECTION_FANOUT":  {SBCFamilyC2, giefSensorClassUserspace},
	"XDR.ANOMALY.REMOTE_DIVERSITY":   {SBCFamilyC2, giefSensorClassUserspace},
	"XDR.ANOMALY.PORT_DIVERSITY":     {SBCFamilyC2, giefSensorClassUserspace},
	"XDR.TLS.CONTROL_STORM":          {SBCFamilyC2, giefSensorClassUserspace},
	"XDR.DNS_TUNNEL":                 {SBCFamilyC2, giefSensorClassUserspace},
	"XDR.DNS_TUNNELING":              {SBCFamilyC2, giefSensorClassUserspace},
	"KD.LINUX.PIPE_SHELL":            {SBCFamilyExecution, giefSensorClassUserspace},
	"KD.LINUX.ENCODED_EXEC":          {SBCFamilyExecution, giefSensorClassUserspace},
	"KD.LINUX.REVERSE_SHELL":         {SBCFamilyC2, giefSensorClassUserspace},
	"KD.LINUX.LD_PRELOAD":            {SBCFamilyEvasion, giefSensorClassUserspace},
	"KD.LINUX.CREDENTIAL_ACCESS":     {SBCFamilyCredential, giefSensorClassUserspace},
	"KD.LINUX.DESTRUCTIVE":           {SBCFamilyEvidence, giefSensorClassUserspace},
	"KD.LINUX.PERSISTENCE":           {SBCFamilyPersistence, giefSensorClassUserspace},
	"KD.LINUX.BPF_LOAD":              {SBCFamilyKernel, giefSensorClassUserspace},
	"KD.LINUX.LOG_TAMPER":            {SBCFamilyEvasion, giefSensorClassUserspace},
	"KD.LINUX.CREDENTIAL_PATH_PROBE": {SBCFamilyCredential, giefSensorClassUserspace},
	"KD.LINUX.TUNNEL_BINARY":         {SBCFamilyC2, giefSensorClassUserspace},
	"KD.LINUX.PERSISTENCE_DROPIN":    {SBCFamilyPersistence, giefSensorClassUserspace},
	"KD.LINUX.DISCOVERY.ACCOUNT":     {SBCFamilyEvasion, giefSensorClassUserspace},
	"KD.LINUX.DISCOVERY.SUID":        {SBCFamilyEvasion, giefSensorClassUserspace},
	"KD.LINUX.CANARY_ACCESS":         {SBCFamilyEvidence, giefSensorClassUserspace},
	"MALWARE.CONTENT_MATCH":          {SBCFamilyProvenance, giefSensorClassUserspace},
	"MALWARE.CONTENT_SUSPICIOUS":     {SBCFamilyProvenance, giefSensorClassUserspace},
	"MALWARE.MANUAL_MATCH":           {SBCFamilyProvenance, giefSensorClassUserspace},
	"MALWARE.MANUAL_SUSPICIOUS":      {SBCFamilyProvenance, giefSensorClassUserspace},
	"BASELINE.HASH_MISMATCH":         {SBCFamilyEvidence, giefSensorClassUserspace},
	"BASELINE.NETWORK_DEVIATION":     {SBCFamilyC2, giefSensorClassUserspace},
	"BASELINE.NETWORK_FORBIDDEN":     {SBCFamilyC2, giefSensorClassUserspace},
	"BASELINE.PARENT_MISMATCH":       {SBCFamilyProvenance, giefSensorClassUserspace},
	"BASELINE.UID_MISMATCH":          {SBCFamilyProvenance, giefSensorClassUserspace},
	"L7.CORRELATED_REMOTE":           {SBCFamilyC2, giefSensorClassUserspace},
	"EDGE.PROXY_BLOCK":               {SBCFamilyC2, giefSensorClassUserspace},
}

// giefRulePrefixClassification extends the closed table to whole rule namespaces
// that are produced dynamically or will be added by the AP-6 flow work package.
// The list is ordered longest prefix first; giefRuleClassificationFor walks it in
// order, so a more specific prefix always wins. A test asserts the ordering.
var giefRulePrefixClassifications = []struct {
	prefix string
	family string
	class  giefSensorClass
}{
	// The list is strictly ordered by descending prefix length: a more specific
	// prefix is always consulted before a shorter one that would also match.
	//
	// AP-6 flow rules (StyX phase 2, PCR and DNS tunnelling) — deterministic
	// classification for the moment the flow package starts emitting them.
	{"L7.RATE_LIMIT", SBCFamilyC2, giefSensorClassUserspace},
	{"NET.INGRESS.", SBCFamilyC2, giefSensorClassUserspace},
	{"XDR.ANOMALY.", SBCFamilyExecution, giefSensorClassUserspace},
	{"XDR.HIDDEN_", SBCFamilyKernel, giefSensorClassKernelTelemetry},
	{"XDR.RANSOM_", SBCFamilyEvidence, giefSensorClassKernelTelemetry},
	{"L7.SCANNER", SBCFamilyC2, giefSensorClassUserspace},
	{"STYX.DNS_", SBCFamilyC2, giefSensorClassUserspace},
	{"XDR.STYX_", SBCFamilyC2, giefSensorClassKernelTelemetry},
	{"MORPHEUS.", SBCFamilyCredential, giefSensorClassUserspace},
	{"KD.LINUX.", SBCFamilyExecution, giefSensorClassUserspace},
	{"BASELINE.", SBCFamilyEvidence, giefSensorClassUserspace},
	// Namespaces produced by other sensors of this codebase.
	{"NEMESIS.", SBCFamilyEvidence, giefSensorClassKernelTelemetry},
	{"WITNESS.", SBCFamilyEvidence, giefSensorClassIntegrity},
	{"RELEASE.", SBCFamilyEvidence, giefSensorClassHealth},
	{"CELL.LSM", SBCFamilyKernel, giefSensorClassKernelLSM},
	{"KINETIC.", SBCFamilyC2, giefSensorClassUserspace},
	{"MALWARE.", SBCFamilyProvenance, giefSensorClassUserspace},
	{"XDR.LKM_", SBCFamilyKernel, giefSensorClassKernelTelemetry},
	{"XDR.BPF_", SBCFamilyKernel, giefSensorClassKernelTelemetry},
	{"XDR.PCR_", SBCFamilyC2, giefSensorClassKernelTelemetry},
	{"XDR.DNS_", SBCFamilyC2, giefSensorClassUserspace},
	{"TITAN.", SBCFamilyExecution, giefSensorClassKernelLSM},
	{"EDGE.", SBCFamilyC2, giefSensorClassUserspace},
	{"STYX.", SBCFamilyC2, giefSensorClassUserspace},
	{"TLS.", SBCFamilyC2, giefSensorClassUserspace},
	{"L7.", SBCFamilyExecution, giefSensorClassUserspace},
}

// giefCategorySBCFamily maps an incident category to a family when (and only
// when) none of its rule ids is in the tables above. This keeps operator-defined
// custom rules deterministic without pretending their provenance is known.
var giefCategorySBCFamily = map[string]string{
	"origin":              SBCFamilyProvenance,
	"provenance":          SBCFamilyProvenance,
	"malware":             SBCFamilyProvenance,
	"manual-scan":         SBCFamilyProvenance,
	"lineage":             SBCFamilyExecution,
	"execution":           SBCFamilyExecution,
	"behavior":            SBCFamilyExecution,
	"masquerading":        SBCFamilyEvasion,
	"identity":            SBCFamilyEvasion,
	"defense-evasion":     SBCFamilyEvasion,
	"evasion_detection":   SBCFamilyEvasion,
	"peripheral":          SBCFamilyEvasion,
	"kernel":              SBCFamilyKernel,
	"lsm":                 SBCFamilyKernel,
	"cell-isolation":      SBCFamilyKernel,
	"credential":          SBCFamilyCredential,
	"access":              SBCFamilyCredential,
	"memory":              SBCFamilyCredential,
	"network":             SBCFamilyC2,
	"c2":                  SBCFamilyC2,
	"tls-sensor":          SBCFamilyC2,
	"exfiltration":        SBCFamilyC2,
	"command_and_control": SBCFamilyC2,
	"persistence":         SBCFamilyPersistence,
	"linker":              SBCFamilyPersistence,
	"impact":              SBCFamilyEvidence,
	"ransomware":          SBCFamilyEvidence,
	"integrity":           SBCFamilyEvidence,
	"sensor-health":       SBCFamilyEvidence,
	"worker-integrity":    SBCFamilyEvidence,
	"witness":             SBCFamilyEvidence,
	"xdr":                 SBCFamilyEvidence,
}

// giefSBCFamilyDescriptions is the closed set of families (stable contract).
var giefSBCFamilyDescriptions = map[string]string{
	SBCFamilyProvenance:  "provenance and executable origin",
	SBCFamilyExecution:   "execution and process behaviour",
	SBCFamilyKernel:      "kernel integrity and hidden-object cross-view",
	SBCFamilyCredential:  "credential and secret access",
	SBCFamilyC2:          "network command-and-control, exfiltration and remote peers",
	SBCFamilyPersistence: "persistence and loader integrity",
	SBCFamilyEvasion:     "defence evasion and anti-forensics",
	SBCFamilyEvidence:    "evidence integrity, self-tamper and platform trust",
}

// giefSBCFamilyPriority breaks ties when one finding maps to several families.
// Lower is stronger: an attack on the evidence chain outranks a credential
// signal, which outranks a network signal, and so on down to plain execution.
var giefSBCFamilyPriority = map[string]int{
	SBCFamilyEvidence:    0,
	SBCFamilyCredential:  1,
	SBCFamilyC2:          2,
	SBCFamilyKernel:      3,
	SBCFamilyEvasion:     4,
	SBCFamilyPersistence: 5,
	SBCFamilyProvenance:  6,
	SBCFamilyExecution:   7,
}

func giefKnownSBCFamily(family string) bool {
	_, ok := giefSBCFamilyDescriptions[family]
	return ok
}

// giefRuleClassificationFor resolves one rule id against the closed table and the
// documented namespace prefixes. It never guesses: false means "unclassified".
func giefRuleClassificationFor(ruleID string) (giefRuleClassification, bool) {
	id := strings.TrimSpace(ruleID)
	if id == "" {
		return giefRuleClassification{}, false
	}
	if classification, ok := giefRuleClassifications[id]; ok {
		return classification, true
	}
	for _, prefix := range giefRulePrefixClassifications {
		if strings.HasPrefix(id, prefix.prefix) {
			return giefRuleClassification{family: prefix.family, class: prefix.class}, true
		}
	}
	return giefRuleClassification{}, false
}

// giefPriorityFamily returns the strongest family of a set of candidate families.
func giefPriorityFamily(families map[string]struct{}) string {
	best := ""
	bestPriority := 0
	for family := range families {
		priority, ok := giefSBCFamilyPriority[family]
		if !ok {
			continue
		}
		if best == "" || priority < bestPriority {
			best = family
			bestPriority = priority
		}
	}
	return best
}

// giefFamilyForCategories maps incident categories when no rule id resolved.
func giefFamilyForCategories(categories []string) (string, bool) {
	candidates := make(map[string]struct{})
	for _, category := range categories {
		if family, ok := giefCategorySBCFamily[strings.ToLower(strings.TrimSpace(category))]; ok {
			candidates[family] = struct{}{}
		}
	}
	if best := giefPriorityFamily(candidates); best != "" {
		return best, true
	}
	return "", false
}

// giefMetadataString returns the first non-empty attack-story metadata value for
// one key, with the strict value validation left to the caller.
