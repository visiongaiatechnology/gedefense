package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"
)

type NetworkModuleSettings struct {
	Network             NetworkRuntimeSettings `json:"network"`
	ManagementAllowlist []string               `json:"management_allowlist"`
}

type ProtectionModuleSettings struct {
	AutoDegrade bool                      `json:"auto_degrade"`
	Gates       ProtectionRuntimeSettings `json:"gates"`
}

type XDRModuleSettings struct {
	Enabled                bool              `json:"enabled"`
	NetworkSensorEnabled   bool              `json:"network_sensor_enabled"`
	BehaviorEnabled        bool              `json:"behavior_enabled"`
	ScanIntervalMillis     int               `json:"scan_interval_millis"`
	NetworkIntervalSeconds int               `json:"network_interval_seconds"`
	AlertScore             int               `json:"alert_score"`
	ContainScore           int               `json:"contain_score"`
	KillScore              int               `json:"kill_score"`
	EnabledRuleModules     []string          `json:"enabled_rule_modules"`
	CustomRules            []CustomRule      `json:"custom_rules"`
	Advanced               XDRFabricSettings `json:"advanced"`
}

type FabricModuleView struct {
	Module     string         `json:"module"`
	Revision   uint64         `json:"revision"`
	UpdatedAt  time.Time      `json:"updated_at"`
	ApplyState string         `json:"apply_state"`
	Source     string         `json:"source"`
	Settings   interface{}    `json:"settings"`
	Details    map[string]any `json:"details,omitempty"`
}

type FabricSettingDiff struct {
	Key        string      `json:"key"`
	OldValue   interface{} `json:"old_value"`
	NewValue   interface{} `json:"new_value"`
	Risk       string      `json:"risk"`
	ApplyClass string      `json:"apply_class"`
}

type FabricSettingsPreview struct {
	Module           string              `json:"module"`
	ExpectedRevision uint64              `json:"expected_revision"`
	CurrentRevision  uint64              `json:"current_revision"`
	Valid            bool                `json:"valid"`
	RequiresRestart  bool                `json:"requires_restart"`
	HighestRisk      string              `json:"highest_risk"`
	Diff             []FabricSettingDiff `json:"diff"`
}

type fabricModuleMutation struct {
	ExpectedRevision uint64          `json:"expected_revision"`
	Settings         json.RawMessage `json:"settings"`
}

type fabricRollbackRequest struct {
	Revision uint64 `json:"revision"`
}

func fabricModuleName(raw string) (string, bool) {
	module := strings.ToLower(strings.TrimSpace(raw))
	switch module {
	case "kinetic", "network", "protection", "xdr", "l7", "threat_intel", "hardening", "integrity", "boot_trust", "policy_trust", "forensics", "system":
		return module, true
	default:
		return "", false
	}
}

func fabricModuleSnapshot(settings RuntimeSettings, module string) (interface{}, error) {
	switch module {
	case "kinetic":
		out := settings.Kinetic
		out.ServicePortsWeb = append([]uint16(nil), out.ServicePortsWeb...)
		out.ServicePortsMail = append([]uint16(nil), out.ServicePortsMail...)
		out.ServicePortsAdmin = append([]uint16(nil), out.ServicePortsAdmin...)
		return out, nil
	case "network":
		return NetworkModuleSettings{Network: settings.Network, ManagementAllowlist: append([]string(nil), settings.ManagementAllowlist...)}, nil
	case "protection":
		return ProtectionModuleSettings{AutoDegrade: settings.AutoDegrade, Gates: settings.Protection}, nil
	case "xdr":
		return XDRModuleSettings{
			Enabled: settings.XDREnabled, NetworkSensorEnabled: settings.NetworkSensorEnabled, BehaviorEnabled: settings.BehaviorEnabled,
			ScanIntervalMillis: settings.ScanIntervalMillis, NetworkIntervalSeconds: settings.NetworkIntervalSeconds,
			AlertScore: settings.AlertScore, ContainScore: settings.ContainScore, KillScore: settings.KillScore,
			EnabledRuleModules: append([]string(nil), settings.EnabledRuleModules...), CustomRules: append([]CustomRule(nil), settings.CustomRules...),
			Advanced: cloneXDRFabricSettings(settings.XDRFabric),
		}, nil
	case "l7":
		if settings.L7 == nil {
			return L7FabricSettings{}, nil
		}
		return cloneL7FabricSettings(*settings.L7), nil
	case "threat_intel":
		return effectiveThreatIntelSettings(settings), nil
	case "hardening":
		return effectiveHardeningSettings(settings), nil
	case "integrity":
		return effectiveIntegritySettings(settings), nil
	case "boot_trust":
		return effectiveBootTrustSettings(settings), nil
	case "policy_trust":
		return effectivePolicyTrustSettings(settings), nil
	case "forensics":
		return effectiveForensicsSettings(settings), nil
	case "system":
		return effectiveSystemSettings(settings), nil
	default:
		return nil, fmt.Errorf("unsupported settings module %q", module)
	}
}

func cloneXDRFabricSettings(in XDRFabricSettings) XDRFabricSettings {
	out := in
	out.ProtectedPaths = append([]string(nil), in.ProtectedPaths...)
	out.AllowProcesses = append([]string(nil), in.AllowProcesses...)
	out.RuleOverrides = append([]XDRRuleOverride(nil), in.RuleOverrides...)
	return out
}

func decodeModuleSettings(raw json.RawMessage, module string, next *RuntimeSettings) error {
	decode := func(dst interface{}) error {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dst); err != nil {
			return err
		}
		var trailing interface{}
		if err := dec.Decode(&trailing); err == nil {
			return errors.New("settings contain trailing JSON")
		}
		return nil
	}
	switch module {
	case "kinetic":
		var in KineticRuntimeSettings
		if err := decode(&in); err != nil {
			return err
		}
		next.Kinetic = in
	case "network":
		var in NetworkModuleSettings
		if err := decode(&in); err != nil {
			return err
		}
		next.Network = in.Network
		next.ManagementAllowlist = append([]string(nil), in.ManagementAllowlist...)
	case "protection":
		var in ProtectionModuleSettings
		if err := decode(&in); err != nil {
			return err
		}
		next.AutoDegrade = in.AutoDegrade
		next.Protection = in.Gates
	case "xdr":
		var in XDRModuleSettings
		if err := decode(&in); err != nil {
			return err
		}
		next.XDREnabled = in.Enabled
		next.NetworkSensorEnabled = in.NetworkSensorEnabled
		next.BehaviorEnabled = in.BehaviorEnabled
		next.ScanIntervalMillis = in.ScanIntervalMillis
		next.NetworkIntervalSeconds = in.NetworkIntervalSeconds
		next.AlertScore = in.AlertScore
		next.ContainScore = in.ContainScore
		next.KillScore = in.KillScore
		next.EnabledRuleModules = append([]string(nil), in.EnabledRuleModules...)
		next.CustomRules = append([]CustomRule(nil), in.CustomRules...)
		next.XDRFabric = cloneXDRFabricSettings(in.Advanced)
	case "l7":
		var in L7FabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		previous := L7FabricSettings{}
		if next.L7 != nil {
			previous = *next.L7
		}
		in = in.withSocketPaths(previous)
		if err := validateL7FabricSettings(&in); err != nil {
			return err
		}
		next.L7 = &in
	case "threat_intel":
		var in ThreatIntelFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateThreatIntelFabricSettings(&in); err != nil {
			return err
		}
		// The namespace owns enablement, and the legacy fields the rest of the
		// control plane reads are derived from it in the same transaction.
		next.FeedsEnabled = in.Enabled
		next.AutoFeedSync = in.AutoSync
		next.ThreatIntel = &in
	case "hardening":
		var in HardeningFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateHardeningFabricSettings(&in, sysctlControlAllowlist()); err != nil {
			return err
		}
		next.Hardening = &in
	case "integrity":
		var in IntegrityFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateIntegrityFabricSettings(&in); err != nil {
			return err
		}
		next.Integrity = &in
	case "boot_trust":
		var in BootTrustFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateBootTrustFabricSettings(&in); err != nil {
			return err
		}
		next.BootTrust = &in
	case "policy_trust":
		var in PolicyTrustFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validatePolicyTrustFabricSettings(&in); err != nil {
			return err
		}
		next.PolicyTrust = &in
	case "forensics":
		var in ForensicsFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateForensicsFabricSettings(&in); err != nil {
			return err
		}
		if in.Quarantine.RestoreFileMode & ^effectiveForensicsSettings(*next).Quarantine.RestoreFileMode != 0 {
			return fmt.Errorf("quarantine restore permissions must not widen")
		}
		next.Forensics = &in
	case "system":
		var in SystemFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateSystemFabricSettings(&in); err != nil {
			return err
		}
		next.System = &in
	default:
		return fmt.Errorf("unsupported settings module %q", module)
	}
	return nil
}

// settingRisk resolves the risk class and apply class of one flattened diff
// key. The Fabric schema registry is authoritative; the heuristics below only
// cover keys that have no registered metadata yet.
func settingRisk(module, key string) (string, string) {
	if meta, ok := fabricSettingFor(module, key); ok {
		return meta.Risk, meta.ApplyClass
	}
	key = strings.ToLower(key)
	switch module {
	case "kinetic":
		if strings.Contains(key, "max_tracking") {
			return "medium", "HOT"
		}
		if strings.Contains(key, "enforcement") || strings.Contains(key, "threshold") || strings.Contains(key, "ttl") || strings.Contains(key, "ports") {
			return "high", "HOT"
		}
	case "network":
		if strings.Contains(key, "management") {
			return "critical", "HOT"
		}
		return "high", "HOT"
	case "protection":
		return "high", "HOT"
	case "xdr":
		if strings.Contains(key, "worker_count") || strings.Contains(key, "queue_capacity") || strings.Contains(key, "protected_paths") {
			return "medium", "RESTART"
		}
		if strings.Contains(key, "kill_score") || strings.Contains(key, "rule") {
			return "high", "HOT"
		}
		return "medium", "HOT"
	}
	return "low", "HOT"
}

func riskRank(risk string) int {
	switch risk {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func moduleDiff(module string, oldValue, newValue interface{}) ([]FabricSettingDiff, string, bool, error) {
	oldRaw, err := json.Marshal(oldValue)
	if err != nil {
		return nil, "", false, err
	}
	newRaw, err := json.Marshal(newValue)
	if err != nil {
		return nil, "", false, err
	}
	var oldRoot, newRoot interface{}
	if err := json.Unmarshal(oldRaw, &oldRoot); err != nil {
		return nil, "", false, err
	}
	if err := json.Unmarshal(newRaw, &newRoot); err != nil {
		return nil, "", false, err
	}
	oldMap := make(map[string]interface{})
	newMap := make(map[string]interface{})
	flattenSettingsValue("", oldRoot, oldMap)
	flattenSettingsValue("", newRoot, newMap)
	keys := make(map[string]struct{}, len(oldMap)+len(newMap))
	for key := range oldMap {
		keys[key] = struct{}{}
	}
	for key := range newMap {
		keys[key] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	diffs := make([]FabricSettingDiff, 0)
	highest := "low"
	highestRank := 1
	restart := false
	for _, key := range ordered {
		if reflect.DeepEqual(oldMap[key], newMap[key]) {
			continue
		}
		risk, class := settingRisk(module, key)
		if riskRank(risk) > highestRank {
			highest, highestRank = risk, riskRank(risk)
		}
		if class == "RESTART" {
			restart = true
		}
		diffs = append(diffs, FabricSettingDiff{Key: key, OldValue: oldMap[key], NewValue: newMap[key], Risk: risk, ApplyClass: class})
	}
	return diffs, highest, restart, nil
}

func flattenSettingsValue(prefix string, value interface{}, out map[string]interface{}) {
	if object, ok := value.(map[string]interface{}); ok {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			flattenSettingsValue(path, object[key], out)
		}
		return
	}
	out[prefix] = value
}

func (s *APIServer) fabricSettingsModule(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		apiError(w, http.StatusServiceUnavailable, "runtime settings unavailable", nil)
		return
	}
	module, ok := fabricModuleName(r.PathValue("module"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	current := s.settings.Get()
	view, err := fabricModuleSnapshot(current, module)
	if err != nil {
		apiError(w, http.StatusBadRequest, "settings module unavailable", err)
		return
	}
	applyState := s.fabricModuleApplyState(current, module)
	writeJSON(w, http.StatusOK, FabricModuleView{Module: module, Revision: current.Revision, UpdatedAt: current.UpdatedAt, ApplyState: applyState, Source: "encrypted-runtime-settings", Settings: view, Details: s.fabricModuleDetails(module)})
}

// fabricModuleApplyState compares the persisted revision with what the running
// components actually activated. A restart-class divergence is reported as
// restart_required instead of pretending the revision is live.
func (s *APIServer) fabricModuleApplyState(settings RuntimeSettings, module string) string {
	if module == "xdr" {
		active := s.cfg.XDR
		if s.xdr != nil {
			active = s.xdr.cfg.XDR
		}
		if settings.XDRFabric.WorkerCount != active.WorkerCount || settings.XDRFabric.QueueCapacity != active.QueueCapacity || !reflect.DeepEqual(settings.XDRFabric.ProtectedPaths, active.ProtectedPaths) {
			return "restart_required"
		}
	}
	if module == "l7" {
		if s.l7 == nil {
			return "disabled"
		}
		desired := effectiveL7Settings(settings, s.cfg.L7)
		if l7RestartClassChanged(s.l7.LiveSettings(), desired) {
			return "restart_required"
		}
	}
	if module == "threat_intel" {
		if s.feeds == nil {
			return "disabled"
		}
		desired := effectiveThreatIntelSettings(settings)
		if s.feeds.LiveRevision() != settings.Revision || !equalThreatIntelSettings(s.feeds.LiveSettings(), desired) {
			return "reload_pending"
		}
	}
	if module == "integrity" {
		desired := effectiveIntegritySettings(settings)
		if s.fim != nil && !equalStringSlices(desired.FIM.Roots, s.fim.Roots()) {
			return "restart_required"
		}
	}
	if module == "integrity" {
		// The FIM root set is restart-class: the stored baseline is bound to it, so
		// a differing root set is persisted but not silently activated.
		desired := effectiveIntegritySettings(settings)
		if s.fim != nil && !equalStringSlices(desired.FIM.Roots, s.fim.Roots()) {
			return "restart_required"
		}
	}
	if module == "boot_trust" {
		if s.bootTrust == nil {
			return "engine_unavailable"
		}
	}
	if module == "policy_trust" {
		if s.policy == nil {
			return "engine_unavailable"
		}
		if s.policy.Status().Verified == false && s.policy.Policy().RequireSigned {
			// The published requirement cannot be met by the document on disk.
			return "rejected"
		}
	}
	if module == "forensics" {
		if s.state == nil || s.state.Cases() == nil {
			return "engine_unavailable"
		}
	}
	if module == "system" {
		if s.limiter == nil || s.state == nil {
			return "engine_unavailable"
		}
	}
	if module == "hardening" {
		// The RASP, deception and Airlock engines live inside the XDR engine. If
		// that engine is absent the policy is persisted but cannot be projected,
		// and the module says so instead of claiming success.
		if s.xdr == nil {
			return "engine_unavailable"
		}
	}
	return "applied"
}

// equalThreatIntelSettings compares a published revision with the persisted one
// so the module can report an honest apply state.
func equalThreatIntelSettings(a, b ThreatIntelFabricSettings) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	if errLeft != nil || errRight != nil {
		return false
	}
	return bytes.Equal(left, right)
}

// fabricModuleDetails exposes module-specific presentation data that must not
// participate in the settings diff, such as the L7 rule catalogue and the
// computed inspection memory budget.
func (s *APIServer) fabricModuleDetails(module string) map[string]any {
	if module == "l7" {
		persisted := effectiveL7Settings(s.settings.Get(), s.cfg.L7)
		active := persisted
		if s.l7 != nil {
			active = s.l7.LiveSettings()
		}
		details := map[string]any{
			"active":        active,
			"rule_registry": describeL7RuleCatalog(),
			"memory_budget": computeL7MemoryBudget(persisted),
		}
		if s.l7 != nil {
			version, source, signatures, profiles := s.l7.TLSFingerprintStatus()
			details["tls_fingerprints"] = map[string]any{
				"version": version, "source": source, "signatures": signatures, "profiles": profiles,
			}
		}
		return details
	}
	if module == "threat_intel" {
		details := map[string]any{"runtime": ThreatIntelModuleDetails{}}
		if s.feeds != nil {
			details["runtime"] = s.feeds.ModuleDetails()
		}
		return details
	}
	if module == "boot_trust" {
		report := s.bootTrust.Collect()
		settings := effectiveBootTrustSettings(s.settings.Get())
		violations := 0
		for _, item := range report.Items {
			switch item.State {
			case bootStateWarning, bootStateDisabled:
				violations++
			}
		}
		return map[string]any{
			"claim_level":       report.ClaimLevel,
			"summary":           report.Summary,
			"violations":        violations,
			"required_pcr_list": formatPCRSelection(settings.RequiredPCRSelection),
		}
	}
	if module == "policy_trust" {
		status := s.policy.Status()
		return map[string]any{
			"verified":           status.Verified,
			"generation":         status.Generation,
			"updated_at":         status.UpdatedAt,
			"signer":             status.Signer,
			"error":              status.Error,
			"minimum_generation": s.policy.Policy().MinimumGeneration,
		}
	}
	if module == "system" {
		settings := effectiveSystemSettings(s.settings.Get())
		details := map[string]any{
			"budgets":     systemBudgetAudit(settings),
			"event_cap":   s.state.EventCap(),
			"payload_cap": s.apiPayloadLimit(),
			"sse_ceiling": s.sseClientLimit(),
			"core_ms":     settings.Core.RequestTimeoutMillis,
		}
		if s.core != nil {
			details["core_deadline_ms"] = s.core.deadline().Milliseconds()
		}
		return details
	}
	if module == "forensics" {
		settings := effectiveForensicsSettings(s.settings.Get())
		details := map[string]any{
			"quarantine": map[string]any{
				"builtin_forbidden": quarantineBuiltinForbidden,
				"allowed_roots":     settings.Quarantine.AllowedRoots,
				"extra_forbidden":   settings.Quarantine.ExtraForbidden,
			},
			"case_policy": settings.Cases,
		}
		if s.state != nil {
			if engine := s.state.Cases(); engine != nil {
				details["cases"] = engine.Status(settings.Cases.ListMaxLimit)
			}
		}
		return details
	}
	if module == "integrity" {
		settings := effectiveIntegritySettings(s.settings.Get())
		details := map[string]any{
			"fim": map[string]any{
				"enabled": s.fim != nil && s.fim.Enabled(),
				"roots":   settings.FIM.Roots,
			},
			"packages": map[string]any{
				"database_root":   s.packages.dbRoot,
				"filesystem_root": s.packages.fsRoot,
				"available":       s.packages.Status().Available,
			},
		}
		if s.xdr != nil {
			if chronos := s.xdr.Chronos(); chronos != nil {
				details["chronos"] = map[string]any{
					"enabled": chronos.Enabled(), "roots": chronos.Roots(), "encrypted": chronos.Encrypted(),
				}
			}
		}
		if ledger := s.state.EvidenceLedger(); ledger != nil {
			details["evidence"] = ledger.Status()
		}
		return details
	}
	if module == "hardening" {
		settings := effectiveHardeningSettings(s.settings.Get())
		posture := s.hardening.Collect(s.state.Snapshot(), s.bootTrust.Collect())
		posture.Checks = append(posture.Checks, packageIntegrityPostureCheck(s.packages.Status()))
		summarized := summarizeHardening(posture.CollectedAt, posture.Checks, settings.Posture.thresholds())
		details := map[string]any{
			"posture": map[string]any{
				"score":            summarized.Score,
				"level":            summarized.Level,
				"required_domains": assessHardeningPosture(summarized, settings.Posture),
				"domains":          summarized.Domains,
			},
			"sysctl_controls": sysctlControlCatalog(),
		}
		if s.xdr != nil {
			if deception := s.xdr.Deception(); deception != nil {
				details["canaries"] = deception.ListCanaries()
			}
		}
		return details
	}
	return nil
}

// sysctlControlCatalog publishes the closed control vocabulary so the dashboard
// renders the real allowlist instead of a hand-maintained copy.
func sysctlControlCatalog() []map[string]any {
	out := make([]map[string]any, 0, len(sysctlControlDefinitions))
	for id, definition := range sysctlControlDefinitions {
		keys := make([]string, 0, len(definition.Values))
		for key := range definition.Values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out = append(out, map[string]any{"id": id, "keys": keys, "mask": definition.Mask})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	return out
}

func xdrRestartSettingsChanged(current, next RuntimeSettings) bool {
	return current.XDRFabric.WorkerCount != next.XDRFabric.WorkerCount ||
		current.XDRFabric.QueueCapacity != next.XDRFabric.QueueCapacity ||
		!reflect.DeepEqual(current.XDRFabric.ProtectedPaths, next.XDRFabric.ProtectedPaths)
}

func xdrRuleWiringChanged(current, next RuntimeSettings) bool {
	return !reflect.DeepEqual(current.EnabledRuleModules, next.EnabledRuleModules) ||
		!reflect.DeepEqual(current.CustomRules, next.CustomRules) ||
		!reflect.DeepEqual(current.XDRFabric.RuleOverrides, next.XDRFabric.RuleOverrides)
}

func (s *APIServer) decodeFabricMutation(w http.ResponseWriter, r *http.Request) (string, fabricModuleMutation, RuntimeSettings, RuntimeSettings, error) {
	if s.settings == nil {
		return "", fabricModuleMutation{}, RuntimeSettings{}, RuntimeSettings{}, errors.New("runtime settings unavailable")
	}
	module, ok := fabricModuleName(r.PathValue("module"))
	if !ok {
		return "", fabricModuleMutation{}, RuntimeSettings{}, RuntimeSettings{}, errors.New("unsupported settings module")
	}
	var in fabricModuleMutation
	if err := decodeStrictJSON(w, r, 256<<10, &in); err != nil {
		return "", in, RuntimeSettings{}, RuntimeSettings{}, err
	}
	current := s.settings.Get()
	if in.ExpectedRevision == 0 || in.ExpectedRevision != current.Revision {
		return module, in, current, current, fmt.Errorf("runtime settings revision conflict: expected %d current %d", in.ExpectedRevision, current.Revision)
	}
	if len(in.Settings) == 0 || string(in.Settings) == "null" {
		return module, in, current, current, errors.New("settings payload is required")
	}
	next := cloneRuntimeSettings(current)
	if err := decodeModuleSettings(in.Settings, module, &next); err != nil {
		return module, in, current, current, err
	}
	if module == "network" && len(next.ManagementAllowlist) == 0 {
		return module, in, current, current, errors.New("management allowlist must contain at least one protected target")
	}
	next.FabricVersion = fabricSettingsVersion
	if err := validateRuntimeSettings(&next); err != nil {
		return module, in, current, current, err
	}
	return module, in, current, next, nil
}

func (s *APIServer) fabricSettingsPreview(w http.ResponseWriter, r *http.Request) {
	module, in, current, next, err := s.decodeFabricMutation(w, r)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "revision conflict") {
			status = http.StatusConflict
		}
		apiError(w, status, "settings preview rejected", err)
		return
	}
	oldView, _ := fabricModuleSnapshot(current, module)
	newView, _ := fabricModuleSnapshot(next, module)
	diff, risk, restart, err := moduleDiff(module, oldView, newView)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "settings preview failed", err)
		return
	}
	writeJSON(w, http.StatusOK, FabricSettingsPreview{Module: module, ExpectedRevision: in.ExpectedRevision, CurrentRevision: current.Revision, Valid: true, RequiresRestart: restart, HighestRisk: risk, Diff: diff})
}

func (s *APIServer) fabricSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	module, _, current, next, err := s.decodeFabricMutation(w, r)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "revision conflict") {
			status = http.StatusConflict
		}
		apiError(w, status, "settings update rejected", err)
		return
	}
	phase := s.release.Status().Phase
	if module == "xdr" && !next.XDREnabled && phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded {
		apiError(w, http.StatusConflict, "XDR can only be disabled in Observe", nil)
		return
	}
	if module == "xdr" && phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded {
		if xdrRuleWiringChanged(current, next) {
			apiError(w, http.StatusConflict, "XDR rule wiring can only be changed in Observe/Degraded", nil)
			return
		}
		if xdrRestartSettingsChanged(current, next) {
			apiError(w, http.StatusConflict, "restart-required XDR settings can only be changed in Observe/Degraded", nil)
			return
		}
	}
	if module == "l7" && phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded {
		if l7RuleWiringChanged(effectiveL7Settings(current, s.cfg.L7), effectiveL7Settings(next, s.cfg.L7)) {
			apiError(w, http.StatusConflict, "L7 rule registry can only be changed in Observe/Degraded", nil)
			return
		}
		if l7RestartClassChanged(effectiveL7Settings(current, s.cfg.L7), effectiveL7Settings(next, s.cfg.L7)) {
			apiError(w, http.StatusConflict, "restart-required L7 settings can only be changed in Observe/Degraded", nil)
			return
		}
	}
	var allowlistTxn *managementAllowlistKernelTxn
	if module == "network" && !reflect.DeepEqual(current.ManagementAllowlist, next.ManagementAllowlist) {
		allowlistTxn, err = s.stageManagementAllowlistChange(current.ManagementAllowlist, next.ManagementAllowlist)
		if err != nil {
			apiError(w, http.StatusConflict, "management allowlist pre-apply failed", err)
			return
		}
	}
	updated, err := s.settings.Update(next)
	if err != nil {
		_ = s.rollbackManagementAllowlistChange(allowlistTxn)
		apiError(w, http.StatusBadRequest, "settings update rejected", err)
		return
	}
	if err := s.applyRuntimeSettings(current, updated, module); err != nil {
		rolledBack, rbErr := s.settings.Rollback(current.Revision)
		if rbErr == nil {
			_ = s.applyRuntimeSettings(updated, rolledBack, module)
		}
		kernelRollbackErr := s.rollbackManagementAllowlistChange(allowlistTxn)
		apiError(w, http.StatusServiceUnavailable, "settings apply failed and was rolled back", errors.Join(err, rbErr, kernelRollbackErr))
		return
	}
	if module == "network" {
		s.state.SetAllowlistReady(s.state.Snapshot().CoreConnected)
	}
	s.state.AddEvent(Event{Severity: "high", Kind: "fabric.settings.updated", Source: "operator", Message: fmt.Sprintf("%s settings revision %d activated", module, updated.Revision)})
	view, _ := fabricModuleSnapshot(updated, module)
	writeJSON(w, http.StatusOK, FabricModuleView{Module: module, Revision: updated.Revision, UpdatedAt: updated.UpdatedAt, ApplyState: s.fabricModuleApplyState(updated, module), Source: "encrypted-runtime-settings", Settings: view, Details: s.fabricModuleDetails(module)})
}

func (s *APIServer) fabricSettingsHistory(w http.ResponseWriter, _ *http.Request) {
	if s.settings == nil {
		apiError(w, http.StatusServiceUnavailable, "runtime settings unavailable", nil)
		return
	}
	history := s.settings.History()
	type item struct {
		Revision  uint64    `json:"revision"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	out := make([]item, 0, len(history))
	for i := len(history) - 1; i >= 0; i-- {
		out = append(out, item{Revision: history[i].Revision, UpdatedAt: history[i].UpdatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"current_revision": s.settings.Get().Revision, "history": out})
}

func (s *APIServer) fabricSettingsRollback(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		apiError(w, http.StatusServiceUnavailable, "runtime settings unavailable", nil)
		return
	}
	var in fabricRollbackRequest
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid rollback request", err)
		return
	}
	current := s.settings.Get()
	target, targetErr := s.settings.Revision(in.Revision)
	if targetErr != nil {
		apiError(w, http.StatusNotFound, "settings revision not found", targetErr)
		return
	}
	allowlistTxn, err := s.stageManagementAllowlistChange(current.ManagementAllowlist, target.ManagementAllowlist)
	if err != nil {
		apiError(w, http.StatusConflict, "management allowlist rollback pre-apply failed", err)
		return
	}
	updated, err := s.settings.Rollback(in.Revision)
	if err != nil {
		_ = s.rollbackManagementAllowlistChange(allowlistTxn)
		apiError(w, http.StatusNotFound, "settings revision not found", err)
		return
	}
	if err := s.applyRuntimeSettings(current, updated, "rollback"); err != nil {
		restored, storeErr := s.settings.Rollback(current.Revision)
		if storeErr == nil {
			_ = s.applyRuntimeSettings(updated, restored, "rollback-compensation")
		}
		kernelErr := s.rollbackManagementAllowlistChange(allowlistTxn)
		apiError(w, http.StatusServiceUnavailable, "settings rollback could not be applied", errors.Join(err, storeErr, kernelErr))
		return
	}
	s.state.SetAllowlistReady(s.state.Snapshot().CoreConnected)
	s.state.AddEvent(Event{Severity: "high", Kind: "fabric.settings.rollback", Source: "operator", Message: fmt.Sprintf("Fabric settings restored from revision %d as revision %d", in.Revision, updated.Revision)})
	writeJSON(w, http.StatusOK, updated)
}
