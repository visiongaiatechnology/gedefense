// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Host Security (Hardening) Fabric administration.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, section 20.
//
// Scope decision: the namespace administers *behaviour* inside a fixed,
// centrally allowed control set. Operators can tune enablement, thresholds,
// detection wiring, response posture and deception content. They cannot invent
// new sysctl keys, new /proc paths, new detection patterns or new response
// primitives, and they cannot disable the anti-poisoning style filters that keep
// the host from being reconfigured into an unsafe state (plan section 43).

// ---------------------------------------------------------------- posture

// HardeningPostureSettings controls the periodic posture evaluation.
type HardeningPostureSettings struct {
	AutoScan            bool     `json:"auto_scan"`
	ScanIntervalSeconds int      `json:"scan_interval_seconds"`
	HardenedThreshold   int      `json:"hardened_threshold"`
	StrongThreshold     int      `json:"strong_threshold"`
	BasicThreshold      int      `json:"basic_threshold"`
	RequiredDomains     []string `json:"required_domains"`
}

// ---------------------------------------------------------------- sysctl

// SysctlProfileSettings is one administrable sysctl profile. It names a subset
// of the centrally allowed controls; the desired values themselves are fixed by
// the control definitions and are never operator-authored.
type SysctlProfileSettings struct {
	Name     string   `json:"name"`
	Controls []string `json:"controls"`
}

type HardeningSysctlSettings struct {
	Profiles           []SysctlProfileSettings `json:"profiles"`
	DefaultProfile     string                  `json:"default_profile"`
	AllowAdHocControls bool                    `json:"allow_ad_hoc_controls"`
}

// ------------------------------------------------------------------- RASP

type HardeningRASPSettings struct {
	Enabled            bool     `json:"enabled"`
	ProtectedNames     []string `json:"protected_names"`
	TrustedDebuggers   []string `json:"trusted_debuggers"`
	ContainmentEnabled bool     `json:"containment_enabled"`
	AlertOnly          bool     `json:"alert_only"`
}

// -------------------------------------------------------------- deception

type CanarySettings struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`
	OwnerUID uint32 `json:"owner_uid"`
	FileMode uint32 `json:"file_mode"`
}

type DeceptionFabricSettings struct {
	Enabled             bool             `json:"enabled"`
	Canaries            []CanarySettings `json:"canaries"`
	AllowedRoots        []string         `json:"allowed_roots"`
	ContainmentLevel    string           `json:"containment_level"`
	CorrelateRemoteIP   bool             `json:"correlate_remote_ip"`
	UnauthorizedScore   int              `json:"unauthorized_score"`
	SystemAccessorScore int              `json:"system_accessor_score"`
}

// ---------------------------------------------------------------- airlock

type AirlockFabricSettings struct {
	Enabled                bool   `json:"enabled"`
	QuarantineDirectory    string `json:"quarantine_directory"`
	MaxFileSizeBytes       int64  `json:"max_file_size_bytes"`
	MimeMismatchAction     string `json:"mime_mismatch_action"`
	PolyglotDetection      bool   `json:"polyglot_detection"`
	SVGActiveContent       bool   `json:"svg_active_content"`
	ExecutableUploadPolicy string `json:"executable_upload_policy"`
	AutoQuarantine         bool   `json:"auto_quarantine"`
}

// ------------------------------------------------------------- namespace

type HardeningFabricSettings struct {
	Posture   HardeningPostureSettings `json:"posture"`
	Sysctl    HardeningSysctlSettings  `json:"sysctl"`
	RASP      HardeningRASPSettings    `json:"rasp"`
	Deception DeceptionFabricSettings  `json:"deception"`
	Airlock   AirlockFabricSettings    `json:"airlock"`
}

// hardeningDomainAllowlist is the closed set of posture domains the collector
// can produce. A required-domain entry outside this set is rejected, so an
// operator cannot silence a domain by inventing a name for it.
var hardeningDomainAllowlist = []string{
	"application-control", "boot", "encryption", "filesystem", "integrity", "kernel", "network",
}

// defaultProtectedRASPNames mirrors the built-in Morpheus protected set.
var defaultProtectedRASPNames = []string{
	"gedefense-core", "gedefense-control", "astraea-key-broker", "key-broker", "systemd-resolved",
	"ssh-agent", "gnome-keyring-d", "keepassxc", "vault",
}

const (
	hardeningDefaultPostureIntervalSeconds = 900
	deceptionContainmentObserve            = "observe"
	deceptionContainmentContain            = "contain"
	deceptionContainmentContainAndBlock    = "contain_and_block"
	airlockMimeActionReport                = "report"
	airlockMimeActionIgnore                = "ignore"
	airlockExecPolicyReport                = "report"
	airlockExecPolicyReject                = "reject"
	hardeningCanaryLimit                   = 128
	hardeningSysctlProfileLimit            = 16
)

// defaultHardeningFabricSettings derives the first Fabric revision from the
// compiled-in behaviour of every host-security engine, so an existing
// deployment keeps exactly its previous posture after migration.
func defaultHardeningFabricSettings(cfg Config, storageDir string) HardeningFabricSettings {
	quarantineDir := ""
	if dir := hostSecurityStorageDir(cfg, storageDir); dir != "" {
		quarantineDir = filepath.Join(dir, "airlock_quarantine")
	}
	return HardeningFabricSettings{
		Posture: HardeningPostureSettings{
			AutoScan:            true,
			ScanIntervalSeconds: hardeningDefaultPostureIntervalSeconds,
			HardenedThreshold:   90,
			StrongThreshold:     75,
			BasicThreshold:      50,
			RequiredDomains:     append([]string(nil), hardeningDomainAllowlist...),
		},
		Sysctl: HardeningSysctlSettings{
			Profiles: []SysctlProfileSettings{
				{Name: "linux-server-balanced", Controls: []string{"filesystem.protected-links", "filesystem.suid-dumps", "kernel.aslr", "kernel.dmesg", "kernel.kptr", "network.ipv4-redirects", "network.ipv6-redirects", "network.syn-cookies"}},
				{Name: "astraeaos-workstation-strict", Controls: []string{"filesystem.protected-links", "filesystem.suid-dumps", "kernel.aslr", "kernel.bpf", "kernel.dmesg", "kernel.kptr", "kernel.ptrace", "network.ipv4-redirects", "network.ipv6-redirects", "network.syn-cookies"}},
			},
			DefaultProfile:     "linux-server-balanced",
			AllowAdHocControls: true,
		},
		RASP: HardeningRASPSettings{
			Enabled:            true,
			ProtectedNames:     append([]string(nil), defaultProtectedRASPNames...),
			TrustedDebuggers:   []string{},
			ContainmentEnabled: true,
			AlertOnly:          false,
		},
		Deception: DeceptionFabricSettings{
			Enabled: true,
			Canaries: []CanarySettings{
				{Path: "/tmp/.aws_credentials", Type: string(CanaryCloudCred), Enabled: true, OwnerUID: 1000, FileMode: 0o600},
				{Path: "/etc/shadow.bak", Type: string(CanaryShadow), Enabled: true, OwnerUID: 0, FileMode: 0o600},
			},
			AllowedRoots:        []string{"/etc", "/home", "/opt", "/root", "/srv", "/tmp", "/var"},
			ContainmentLevel:    deceptionContainmentContainAndBlock,
			CorrelateRemoteIP:   true,
			UnauthorizedScore:   200,
			SystemAccessorScore: 160,
		},
		Airlock: AirlockFabricSettings{
			Enabled:                true,
			QuarantineDirectory:    quarantineDir,
			MaxFileSizeBytes:       100 << 20,
			MimeMismatchAction:     airlockMimeActionReport,
			PolyglotDetection:      true,
			SVGActiveContent:       true,
			ExecutableUploadPolicy: airlockExecPolicyReject,
			AutoQuarantine:         false,
		},
	}
}

// hostSecurityStorageDir resolves the directory the host-security engines keep
// their state in. It mirrors the XDR engine's own resolution so a deployment
// cannot end up with two different quarantine or checkpoint locations.
func hostSecurityStorageDir(cfg Config, override string) string {
	dir := strings.TrimSpace(override)
	if dir == "" || dir == "." {
		dir = filepath.Dir(cfg.XDR.IncidentLog)
	}
	if dir == "" || dir == "." {
		dir = "/var/lib/vgt-gedefense"
	}
	return dir
}

func cloneHardeningFabricSettings(in HardeningFabricSettings) HardeningFabricSettings {
	out := in
	out.Posture.RequiredDomains = append([]string(nil), in.Posture.RequiredDomains...)
	out.Sysctl.Profiles = make([]SysctlProfileSettings, 0, len(in.Sysctl.Profiles))
	for _, profile := range in.Sysctl.Profiles {
		out.Sysctl.Profiles = append(out.Sysctl.Profiles, SysctlProfileSettings{Name: profile.Name, Controls: append([]string(nil), profile.Controls...)})
	}
	out.RASP.ProtectedNames = append([]string(nil), in.RASP.ProtectedNames...)
	out.RASP.TrustedDebuggers = append([]string(nil), in.RASP.TrustedDebuggers...)
	out.Deception.Canaries = append([]CanarySettings(nil), in.Deception.Canaries...)
	out.Deception.AllowedRoots = append([]string(nil), in.Deception.AllowedRoots...)
	return out
}

// validateHardeningFabricSettings normalizes and bounds the whole namespace.
func validateHardeningFabricSettings(settings *HardeningFabricSettings, allowedSysctlControls map[string]bool) error {
	// ------------------------------------------------------------- posture
	if settings.Posture.ScanIntervalSeconds < 60 || settings.Posture.ScanIntervalSeconds > 86400 {
		return fmt.Errorf("hardening posture scan interval must be between 60 and 86400 seconds")
	}
	if settings.Posture.HardenedThreshold < 1 || settings.Posture.HardenedThreshold > 100 ||
		settings.Posture.StrongThreshold < 0 || settings.Posture.StrongThreshold > 100 ||
		settings.Posture.BasicThreshold < 0 || settings.Posture.BasicThreshold > 100 {
		return fmt.Errorf("hardening posture thresholds must be between 0 and 100")
	}
	if !(settings.Posture.HardenedThreshold > settings.Posture.StrongThreshold && settings.Posture.StrongThreshold > settings.Posture.BasicThreshold) {
		return fmt.Errorf("hardening posture thresholds must satisfy hardened > strong > basic")
	}
	if len(settings.Posture.RequiredDomains) > len(hardeningDomainAllowlist) {
		return fmt.Errorf("hardening posture required domain list exceeds the known domain count")
	}
	seenDomains := make(map[string]struct{}, len(settings.Posture.RequiredDomains))
	domains := make([]string, 0, len(settings.Posture.RequiredDomains))
	for _, raw := range settings.Posture.RequiredDomains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if !containsString(hardeningDomainAllowlist, domain) {
			return fmt.Errorf("hardening posture required domain %q is not a known posture domain", raw)
		}
		if _, exists := seenDomains[domain]; exists {
			continue
		}
		seenDomains[domain] = struct{}{}
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	settings.Posture.RequiredDomains = domains

	// -------------------------------------------------------------- sysctl
	if len(settings.Sysctl.Profiles) > hardeningSysctlProfileLimit {
		return fmt.Errorf("hardening sysctl profile limit of %d exceeded", hardeningSysctlProfileLimit)
	}
	seenProfiles := make(map[string]struct{}, len(settings.Sysctl.Profiles))
	profiles := make([]SysctlProfileSettings, 0, len(settings.Sysctl.Profiles))
	for index := range settings.Sysctl.Profiles {
		profile := &settings.Sysctl.Profiles[index]
		profile.Name = strings.ToLower(strings.TrimSpace(profile.Name))
		if len(profile.Name) < 3 || len(profile.Name) > 64 {
			return fmt.Errorf("sysctl profile %d name must contain 3-64 characters", index)
		}
		for i := 0; i < len(profile.Name); i++ {
			c := profile.Name[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return fmt.Errorf("sysctl profile %q name contains an invalid character", profile.Name)
		}
		if _, exists := seenProfiles[profile.Name]; exists {
			return fmt.Errorf("duplicate sysctl profile %q", profile.Name)
		}
		seenProfiles[profile.Name] = struct{}{}
		if len(profile.Controls) == 0 || len(profile.Controls) > len(allowedSysctlControls) {
			return fmt.Errorf("sysctl profile %q must select between 1 and %d controls", profile.Name, len(allowedSysctlControls))
		}
		seenControls := make(map[string]struct{}, len(profile.Controls))
		controls := make([]string, 0, len(profile.Controls))
		for _, raw := range profile.Controls {
			control := strings.ToLower(strings.TrimSpace(raw))
			if !allowedSysctlControls[control] {
				return fmt.Errorf("sysctl profile %q references %q which is not a centrally allowed control", profile.Name, raw)
			}
			if _, exists := seenControls[control]; exists {
				continue
			}
			seenControls[control] = struct{}{}
			controls = append(controls, control)
		}
		sort.Strings(controls)
		profile.Controls = controls
		profiles = append(profiles, *profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	settings.Sysctl.Profiles = profiles
	settings.Sysctl.DefaultProfile = strings.ToLower(strings.TrimSpace(settings.Sysctl.DefaultProfile))
	if settings.Sysctl.DefaultProfile != "" {
		if _, exists := seenProfiles[settings.Sysctl.DefaultProfile]; !exists {
			return fmt.Errorf("sysctl default profile %q is not defined", settings.Sysctl.DefaultProfile)
		}
	}
	if len(profiles) == 0 && !settings.Sysctl.AllowAdHocControls {
		return fmt.Errorf("hardening sysctl requires at least one profile or ad-hoc control submission")
	}

	// ---------------------------------------------------------------- RASP
	if len(settings.RASP.ProtectedNames) > 256 {
		return fmt.Errorf("RASP protected name list exceeds 256 entries")
	}
	names := make([]string, 0, len(settings.RASP.ProtectedNames))
	seenNames := make(map[string]struct{}, len(settings.RASP.ProtectedNames))
	for _, raw := range settings.RASP.ProtectedNames {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" || len(name) > 64 || strings.ContainsAny(name, "/ \t\r\n\x00") {
			return fmt.Errorf("RASP protected name %q must be a bare process name", raw)
		}
		if _, exists := seenNames[name]; exists {
			continue
		}
		seenNames[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	settings.RASP.ProtectedNames = names
	if len(settings.RASP.TrustedDebuggers) > 128 {
		return fmt.Errorf("RASP trusted debugger list exceeds 128 entries")
	}
	debuggers := make([]string, 0, len(settings.RASP.TrustedDebuggers))
	seenDebuggers := make(map[string]struct{}, len(settings.RASP.TrustedDebuggers))
	for _, raw := range settings.RASP.TrustedDebuggers {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" || len(name) > 64 || strings.ContainsAny(name, "/ \t\r\n\x00") {
			return fmt.Errorf("RASP trusted debugger %q must be a bare process name", raw)
		}
		if _, exists := seenDebuggers[name]; exists {
			continue
		}
		seenDebuggers[name] = struct{}{}
		debuggers = append(debuggers, name)
	}
	sort.Strings(debuggers)
	settings.RASP.TrustedDebuggers = debuggers
	if settings.RASP.AlertOnly && settings.RASP.ContainmentEnabled {
		return fmt.Errorf("RASP cannot be alert-only and enforce containment at the same time")
	}

	// ----------------------------------------------------------- deception
	if len(settings.Deception.Canaries) > hardeningCanaryLimit {
		return fmt.Errorf("deception canary limit of %d exceeded", hardeningCanaryLimit)
	}
	switch settings.Deception.ContainmentLevel {
	case deceptionContainmentObserve, deceptionContainmentContain, deceptionContainmentContainAndBlock:
	default:
		return fmt.Errorf("deception containment level must be observe, contain or contain_and_block")
	}
	if settings.Deception.UnauthorizedScore < 1 || settings.Deception.UnauthorizedScore > 250 {
		return fmt.Errorf("deception unauthorized accessor score must be between 1 and 250")
	}
	if settings.Deception.SystemAccessorScore < 1 || settings.Deception.SystemAccessorScore > 250 {
		return fmt.Errorf("deception system accessor score must be between 1 and 250")
	}
	if len(settings.Deception.AllowedRoots) > 64 {
		return fmt.Errorf("deception allowed root list exceeds 64 entries")
	}
	roots := make([]string, 0, len(settings.Deception.AllowedRoots))
	seenRoots := make(map[string]struct{}, len(settings.Deception.AllowedRoots))
	for _, raw := range settings.Deception.AllowedRoots {
		root := strings.TrimSpace(raw)
		if err := validateAbsoluteCleanPath("deception allowed root", root); err != nil {
			return err
		}
		if root == "/" {
			return fmt.Errorf("deception allowed root must not be the filesystem root")
		}
		if _, exists := seenRoots[root]; exists {
			continue
		}
		seenRoots[root] = struct{}{}
		roots = append(roots, root)
	}
	sort.Strings(roots)
	settings.Deception.AllowedRoots = roots
	if settings.Deception.Enabled && len(settings.Deception.Canaries) == 0 {
		return fmt.Errorf("deception requires at least one canary definition while enabled")
	}
	seenPaths := make(map[string]struct{}, len(settings.Deception.Canaries))
	canaries := make([]CanarySettings, 0, len(settings.Deception.Canaries))
	for index := range settings.Deception.Canaries {
		canary := &settings.Deception.Canaries[index]
		canary.Path = strings.TrimSpace(canary.Path)
		canary.Type = strings.ToUpper(strings.TrimSpace(canary.Type))
		if err := validateAbsoluteCleanPath("canary path", canary.Path); err != nil {
			return err
		}
		if canary.Path == "/" {
			return fmt.Errorf("canary path must not be the filesystem root")
		}
		switch CanaryType(canary.Type) {
		case CanarySSHKey, CanaryCloudCred, CanaryShadow, CanaryDotEnv:
		default:
			return fmt.Errorf("canary %s type must be SSH_KEY, CLOUD_CRED, SHADOW_BAK or DOTENV", canary.Path)
		}
		if canary.FileMode == 0 || canary.FileMode > 0o777 {
			return fmt.Errorf("canary %s file mode must be a permission mask between 0001 and 0777", canary.Path)
		}
		if !pathUnderAnyRoot(canary.Path, roots) {
			return fmt.Errorf("canary %s is outside every allowed deception root", canary.Path)
		}
		if _, exists := seenPaths[canary.Path]; exists {
			return fmt.Errorf("duplicate canary path %q", canary.Path)
		}
		seenPaths[canary.Path] = struct{}{}
		canaries = append(canaries, *canary)
	}
	sort.Slice(canaries, func(i, j int) bool { return canaries[i].Path < canaries[j].Path })
	settings.Deception.Canaries = canaries

	// ------------------------------------------------------------- airlock
	if settings.Airlock.QuarantineDirectory != "" {
		if err := validateAbsoluteCleanPath("airlock quarantine directory", settings.Airlock.QuarantineDirectory); err != nil {
			return err
		}
		if settings.Airlock.QuarantineDirectory == "/" {
			return fmt.Errorf("airlock quarantine directory must not be the filesystem root")
		}
	}
	if settings.Airlock.Enabled && strings.TrimSpace(settings.Airlock.QuarantineDirectory) == "" {
		return fmt.Errorf("airlock requires a quarantine directory while enabled")
	}
	if settings.Airlock.MaxFileSizeBytes < 1<<10 || settings.Airlock.MaxFileSizeBytes > 16<<30 {
		return fmt.Errorf("airlock maximum file size must be between 1 KiB and 16 GiB")
	}
	switch settings.Airlock.MimeMismatchAction {
	case airlockMimeActionReport, airlockMimeActionIgnore:
	default:
		return fmt.Errorf("airlock MIME mismatch action must be report or ignore")
	}
	switch settings.Airlock.ExecutableUploadPolicy {
	case airlockExecPolicyReport, airlockExecPolicyReject:
	default:
		return fmt.Errorf("airlock executable upload policy must be report or reject")
	}
	return nil
}

// pathUnderAnyRoot reports whether a clean absolute path lives under one of the
// allowed roots. An empty root list means "no root restriction", which is only
// reachable before normalization.
func pathUnderAnyRoot(path string, roots []string) bool {
	if len(roots) == 0 {
		return true
	}
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// -------------------------------------------------------- posture assessment

// HardeningDomainFinding is one required-domain verdict of the periodic posture
// evaluation.
type HardeningDomainFinding struct {
	Domain    string `json:"domain"`
	Title     string `json:"title"`
	Score     int    `json:"score"`
	State     string `json:"state"`
	Reason    string `json:"reason"`
	Threshold int    `json:"threshold"`
}

// assessHardeningPosture evaluates required domains against the administrable
// thresholds. A required domain that produced no measurable check is reported as
// UNAVAILABLE rather than quietly dropped: an unevaluable control is not a
// passing control, so removing a domain from the required list cannot turn a red
// posture green.
func assessHardeningPosture(posture HardeningPosture, settings HardeningPostureSettings) []HardeningDomainFinding {
	byDomain := make(map[string]HardeningDomain, len(posture.Domains))
	for _, domain := range posture.Domains {
		byDomain[domain.ID] = domain
	}
	findings := make([]HardeningDomainFinding, 0, len(settings.RequiredDomains))
	for _, id := range settings.RequiredDomains {
		threshold := settings.StrongThreshold
		domain, ok := byDomain[id]
		if !ok {
			findings = append(findings, HardeningDomainFinding{
				Domain: id, Title: hardeningDomainTitle(id), Score: 0, State: "UNAVAILABLE",
				Reason: "no measurable control was available for this domain", Threshold: threshold,
			})
			continue
		}
		state := "PROTECTED"
		reason := "domain score meets the required threshold"
		if domain.Score < settings.BasicThreshold {
			state = "CRITICAL"
			reason = "domain score is below the basic threshold"
		} else if domain.Score < threshold {
			state = "WEAK"
			reason = "domain score is below the strong threshold"
		}
		findings = append(findings, HardeningDomainFinding{
			Domain: id, Title: domain.Title, Score: domain.Score, State: state, Reason: reason, Threshold: threshold,
		})
	}
	return findings
}

// effectiveHardeningSettings returns the persisted Host Security namespace. The
// namespace is always seeded by the schema upgrade, so the fallback only serves a
// zero-value document.
func effectiveHardeningSettings(settings RuntimeSettings) HardeningFabricSettings {
	if settings.Hardening != nil {
		return cloneHardeningFabricSettings(*settings.Hardening)
	}
	return defaultHardeningFabricSettings(Config{}, "")
}

// buildSysctlProfiles expands administrable profile definitions into the
// key/value sets the transaction applier applies. Every value comes from the
// centrally allowed control definitions: an operator selects controls, and can
// never author a kernel key or value.
func buildSysctlProfiles(profiles []SysctlProfileSettings) (map[string]SysctlProfile, error) {
	out := make(map[string]SysctlProfile, len(profiles))
	for _, profile := range profiles {
		values := make(map[string]string)
		for _, control := range profile.Controls {
			definition, ok := sysctlControlDefinitions[control]
			if !ok {
				return nil, fmt.Errorf("sysctl control %q is not centrally allowed", control)
			}
			for key, value := range definition.Values {
				values[key] = value
			}
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("sysctl profile %q resolves to no kernel key", profile.Name)
		}
		out[profile.Name] = SysctlProfile{Name: profile.Name, Values: values}
	}
	return out, nil
}

// UpdateProfiles republishes the administrable sysctl profile set. The control
// vocabulary stays closed; only the named selections are administrable.
func (a *SysctlTransactionApplier) UpdateProfiles(settings HardeningSysctlSettings) error {
	if a == nil {
		return nil
	}
	profiles, err := buildSysctlProfiles(settings.Profiles)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.profiles = profiles
	a.defaultProfile = settings.DefaultProfile
	a.allowAdHocControls = settings.AllowAdHocControls
	return nil
}

// sysctlControlAllowlist returns the closed set of centrally allowed sysctl
// controls. It is the only vocabulary a profile may reference.
func sysctlControlAllowlist() map[string]bool {
	out := make(map[string]bool, len(sysctlControlDefinitions))
	for control := range sysctlControlDefinitions {
		out[control] = true
	}
	return out
}

// boolToDecision selects one of two strings from an administrative boolean. It
// keeps response-posture branches explicit instead of nesting conditionals in
// detection code.
func boolToDecision(condition bool, whenTrue, whenFalse string) string {
	if condition {
		return whenTrue
	}
	return whenFalse
}

// applyHardeningPolicy projects the Host Security namespace onto the engines
// that consume it. It is a single choke point so a revision can never reach one
// host-security engine and not the others.
func applyHardeningPolicy(settings HardeningFabricSettings, morpheus *MorpheusRASP, airlock *AirlockInspector, deception *DeceptionEngine) error {
	if morpheus != nil {
		morpheus.ApplyPolicy(settings.RASP)
	}
	if airlock != nil {
		if err := airlock.ApplyPolicy(settings.Airlock); err != nil {
			return fmt.Errorf("apply airlock policy: %w", err)
		}
	}
	if deception != nil {
		if _, _, err := deception.ApplyPolicy(settings.Deception); err != nil {
			return fmt.Errorf("apply deception policy: %w", err)
		}
	}
	return nil
}

// errHardeningDisabled is returned by apply helpers when the operator switched a
// subsystem off, so callers can distinguish "off" from "failed".
var errHardeningDisabled = errors.New("hardening subsystem disabled")
