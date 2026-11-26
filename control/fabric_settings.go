package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
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
	// Migrations names every operator-visible value this document had changed on the
	// operator's behalf during a schema upgrade. An upgrade that edits somebody else's
	// configuration has to say so where that configuration is read.
	Migrations []string `json:"migrations,omitempty"`
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
	case "kinetic", "network", "protection", "xdr", "l7", "threat_intel", "hardening", "integrity", "boot_trust", "policy_trust", "forensics", "system", "detection", "styx", "titan_exec", "parser_cells", "lockdown", "witness",
		"web_exposure", "worker_guard", "tls_sensor", "lpe_guard", "edge_proxy":
		return module, true
	default:
		return "", false
	}
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
	writeJSON(w, http.StatusOK, FabricModuleView{Module: module, Revision: current.Revision, UpdatedAt: current.UpdatedAt, ApplyState: applyState, Source: "encrypted-runtime-settings", Settings: view, Details: s.fabricModuleDetails(module), Migrations: current.Migrations})
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
	updated, err := s.settings.UpdateIfRevision(current.Revision, next)
	if err != nil {
		_ = s.rollbackManagementAllowlistChange(allowlistTxn)
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "revision conflict") {
			status = http.StatusConflict
		}
		apiError(w, status, "settings update rejected", err)
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
