package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
)

// Fabric settings module projections split out of fabric_settings.go
// (refactoring wave 1b, structure-only): apply-state, module details, the
// hardening catalogue projection and the titan_exec runtime mapping.

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
	if module == "styx" {
		if s.xdr == nil {
			return "engine_unavailable"
		}
		sync := s.xdr.StyxPolicyStatus()
		if !effectiveStyxFabricSettings(settings).Enabled {
			// Disabled is the safe default: there is nothing the kernel has to apply,
			// so capability and retry state are reported by /api/v1/styx/status, not
			// by claiming this revision failed to activate.
			if sync.State == StyxSyncStateApplied || sync.State == StyxSyncStateCapabilityMissing {
				return "applied"
			}
			return "reload_pending"
		}
		switch sync.State {
		case StyxSyncStateApplied:
			return "applied"
		case StyxSyncStateDegraded:
			// M3: the resolvable part of the policy is in force, but at least one
			// path-backed cell identity could not be re-resolved. Claiming "applied"
			// would hide that; "reload_pending" would suggest a reload fixes it.
			return "degraded"
		case StyxSyncStateCapabilityMissing:
			// Persisted, but the running core cannot apply it. The status endpoint
			// names the capability; claiming "applied" here would be a lie.
			return "engine_unavailable"
		default:
			return "reload_pending"
		}
	}
	if module == "titan_exec" {
		// The syncer is wired by the XDR engine composition (P1-T5). Until it is
		// present the module reports the honest unavailable runtime instead of
		// claiming a persisted enforcement revision was activated.
		sync, wired := titanExecRuntimeStatus(s.xdr)
		return titanExecModuleApplyState(settings, sync, wired)
	}
	if module == "parser_cells" {
		// POINT 2 / P2-T3: the runtime is the wired ParserCellManager. Disabled is
		// the shipped default and answers "disabled" - a persisted draft that is
		// deliberately inert is not a failure. Enabled but unavailable (no helper,
		// no sandbox capability) must not claim the revision was activated.
		manager := s.parserCellsManager()
		if manager == nil {
			return "engine_unavailable"
		}
		status := manager.Status()
		if !status.Enabled {
			return "disabled"
		}
		if !status.Available {
			return "engine_unavailable"
		}
		return "applied"
	}
	if module == "lockdown" {
		// POINT 5 / P5-T3: the engine reads the persisted namespace live on every
		// operation, so an enabled revision is active as soon as it is persisted.
		// Disabled is the upgrade default and answers "disabled" - a deliberately
		// inert draft is not a failure. Without a wired engine, or against a core
		// that cannot speak the command family, nothing can be activated.
		if s.lockdown == nil {
			return "engine_unavailable"
		}
		if !effectiveLockdownSettings(settings).Enabled {
			return "disabled"
		}
		if s.lockdown.StatusView().Core.Capability == "missing" {
			return "engine_unavailable"
		}
		return "applied"
	}
	if module == "hardening" {
		// The RASP, deception and Airlock engines live inside the XDR engine. If
		// that engine is absent the policy is persisted but cannot be projected,
		// and the module says so instead of claiming success.
		if s.xdr == nil {
			return "engine_unavailable"
		}
	}
	if module == "witness" {
		// POINT 4 / P4-T2: the engine reads the persisted namespace live on every
		// cycle, so an enabled revision is active as soon as it is persisted.
		// Disabled is the upgrade default and answers "disabled" - a deliberately
		// inert draft is not a failure. Without a wired engine nothing can run.
		if s.witness == nil {
			return "engine_unavailable"
		}
		if !witnessModeActive(effectiveWitnessSettings(settings)) {
			return "disabled"
		}
		return "applied"
	}
	if state, handled := s.v61ModuleApplyState(settings, module); handled {
		return state
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
	if module == "styx" {
		details := map[string]any{"runtime": StyxStatusView{State: StyxSyncStateUnavailable, Sync: StyxSyncStatus{State: StyxSyncStateUnavailable}}}
		if s.xdr != nil {
			details["runtime"] = s.styxStatusView()
		}
		return details
	}
	if module == "titan_exec" {
		sync, wired := titanExecRuntimeStatus(s.xdr)
		return titanExecModuleDetails(sync, wired)
	}
	if module == "parser_cells" {
		// POINT 2 / P2-T3: the runtime projection is already bounded by the manager;
		// without wiring the module says so instead of presenting a fake runtime.
		details := map[string]any{"runtime": "unavailable"}
		if manager := s.parserCellsManager(); manager != nil {
			details["runtime"] = manager.Status()
		}
		return details
	}
	if module == "lockdown" {
		// POINT 5 / P5-T3: the bounded engine projection. Without wiring the module
		// says so instead of presenting a fake runtime; the status view itself never
		// carries a duress path, token or PID.
		if s.lockdown == nil {
			return map[string]any{"runtime": "unavailable"}
		}
		return map[string]any{"runtime": s.lockdown.StatusView()}
	}
	if module == "witness" {
		// POINT 4 / P4-T2: the bounded engine projection. It carries counters,
		// hashes and enums only - never a path, endpoint or key material.
		if s.witness == nil {
			return map[string]any{"runtime": "unavailable"}
		}
		return map[string]any{"runtime": s.witness.StatusView()}
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
			// M2.4: the kernel credential guard is a read-only runtime projection
			// (no admin toggle yet); showing it here keeps the settings surface
			// honest about whether credential-read protection is really active.
			details["credential_guard"] = s.xdr.CredentialGuardReport()
		}
		return details
	}
	if details := s.v61ModuleDetails(module); details != nil {
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

// --------------------------------------------------- titan_exec module projection

// titanExecStatusSource is implemented by the XDR engine once the syncer is wired
// there (P1-T5: xdr.go). Until then the settings module reports an honest
// unavailable runtime instead of claiming the persisted revision was activated.
type titanExecStatusSource interface {
	TitanExecPolicyStatus() TitanExecSyncStatus
}

// titanExecRuntimeStatus resolves the wired runtime status for the settings module.
func titanExecRuntimeStatus(xdr *XDREngine) (TitanExecSyncStatus, bool) {
	if xdr == nil {
		return titanExecUnavailableStatus(), false
	}
	source, ok := any(xdr).(titanExecStatusSource)
	if !ok {
		return titanExecUnavailableStatus(), false
	}
	return source.TitanExecPolicyStatus(), true
}

// titanExecModuleApplyState maps the persisted revision and the runtime status onto
// the Fabric Settings apply-state vocabulary. It is pure so the mapping is testable
// without an engine.
func titanExecModuleApplyState(settings RuntimeSettings, sync TitanExecSyncStatus, wired bool) string {
	desired := effectiveTitanExecFabricSettings(settings)
	if !wired {
		if !desired.Enabled {
			// The upgrade default needs no activation; there is nothing to project.
			return "applied"
		}
		// Persisted, but the running control plane has no wired syncer: claiming
		// "applied" would be the exact lie §8 forbids.
		return "engine_unavailable"
	}
	if !desired.Enabled {
		if sync.State == TitanExecSyncStateApplied || sync.State == TitanExecSyncStateCapabilityMissing {
			return "applied"
		}
		return "reload_pending"
	}
	switch sync.State {
	case TitanExecSyncStateApplied:
		if sync.Enabled && sync.Mode == desired.Mode {
			return "applied"
		}
		return "reload_pending"
	case TitanExecSyncStateCapabilityMissing, TitanExecSyncStateInactive, TitanExecSyncStateUnavailable:
		// Persisted, but the running core cannot apply or enforce it. The status
		// endpoint names the capability/activation fact; claiming "applied" here
		// would be a lie.
		return "engine_unavailable"
	default:
		return "reload_pending"
	}
}

// titanExecModuleDetails is the module-specific runtime presentation. It carries
// the bounded status view and whether the syncer is wired at all.
func titanExecModuleDetails(sync TitanExecSyncStatus, wired bool) map[string]any {
	return map[string]any{"runtime": sync, "wired": wired}
}
