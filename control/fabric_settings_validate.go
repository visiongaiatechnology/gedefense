package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Fabric settings validation and normalisation layer split out of
// fabric_settings.go (refactoring wave 1b, structure-only): strict payload
// decoding, per-module validation, the diff snapshot and the risk/diff model.

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
	case "detection":
		return effectiveDetectionSettings(settings), nil
	case "boot_trust":
		return effectiveBootTrustSettings(settings), nil
	case "policy_trust":
		return effectivePolicyTrustSettings(settings), nil
	case "forensics":
		return effectiveForensicsSettings(settings), nil
	case "system":
		return effectiveSystemSettings(settings), nil
	case "styx":
		return effectiveStyxFabricSettings(settings), nil
	case "titan_exec":
		return effectiveTitanExecFabricSettings(settings), nil
	case "parser_cells":
		return effectiveParserCellsSettings(settings), nil
	case "lockdown":
		return effectiveLockdownSettings(settings), nil
	case "witness":
		return effectiveWitnessSettings(settings), nil
	case "web_exposure":
		return effectiveWebExposureSettings(settings), nil
	case "worker_guard":
		return effectiveWorkerGuardSettings(settings), nil
	case "tls_sensor":
		return effectiveTLSSensorSettings(settings), nil
	case "lpe_guard":
		return effectiveLPEGuardSettings(settings), nil
	case "edge_proxy":
		return effectiveEdgeProxySettings(settings), nil
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
	case "detection":
		var in DetectionFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateDetectionFabricSettings(&in); err != nil {
			return err
		}
		next.Detection = &in
		// The switches own derived facts - which rules run, what the operator rule watches, which
		// roots the preset contributes - so they are applied with the change, not at some later point
		// where a partial state could be observed.
		if err := applyDetectionSettings(next, in); err != nil {
			return err
		}
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
	case "styx":
		var in StyxFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		// Validate and canonicalise before the revision is compared/persisted, so a
		// non-canonical CIDR or a port rule the core would reject never reaches the
		// settings store and therefore never fails the kernel sync midway.
		if err := validateStyxFabricSettings(&in); err != nil {
			return err
		}
		next.Styx = &in
	case "titan_exec":
		var in TitanExecFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		// Validate and canonicalise before the revision is compared/persisted, so a
		// relative/non-canonical path or a per-cgroup rule the core would reject
		// never reaches the settings store and therefore never fails the kernel
		// sync midway.
		if err := validateTitanExecFabricSettings(&in); err != nil {
			return err
		}
		next.TitanExec = &in
	case "parser_cells":
		var in ParserCellsFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		// Reject-not-repair: caps, profile ids and bounds are validated before the
		// revision is persisted or compared, exactly like the other modules.
		if err := validateParserCellsFabricSettings(&in); err != nil {
			return err
		}
		next.ParserCells = &in
	case "lockdown":
		var in LockdownFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		// POINT 5 / P5-T3: bounds and the closed vocabularies are enforced before the
		// revision is persisted, so the engine never receives a document it would have
		// to clamp. A disabling edit is always valid; enabling requires a phase.
		if err := validateLockdownFabricSettings(&in); err != nil {
			return err
		}
		next.Lockdown = &in
	case "witness":
		var in WitnessFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		// POINT 4 / P4-T2: transport anchors, bounds and the mode contract are
		// enforced before the revision is persisted. Enabling http mode without a
		// pin is refused here, exactly as the engine would refuse to start it.
		if err := validateWitnessFabricSettings(&in); err != nil {
			return err
		}
		next.Witness = &in
	case "web_exposure":
		var in WebExposureFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateWebExposureFabricSettings(&in); err != nil {
			return err
		}
		next.WebExposure = &in
	case "worker_guard":
		var in WorkerGuardFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateWorkerGuardFabricSettings(&in); err != nil {
			return err
		}
		next.WorkerGuard = &in
	case "tls_sensor":
		var in TLSSensorFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateTLSSensorFabricSettings(&in); err != nil {
			return err
		}
		next.TLSSensor = &in
	case "lpe_guard":
		var in LPEGuardFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateLPEGuardFabricSettings(&in); err != nil {
			return err
		}
		next.LPEGuard = &in
	case "edge_proxy":
		var in EdgeProxyFabricSettings
		if err := decode(&in); err != nil {
			return err
		}
		if err := validateEdgeProxyFabricSettings(&in); err != nil {
			return err
		}
		next.EdgeProxy = &in
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
