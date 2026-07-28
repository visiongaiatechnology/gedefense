package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"slices"
)

func (s *APIServer) settingsStatus(w http.ResponseWriter, _ *http.Request) {
	if s.settings == nil {
		apiError(w, http.StatusServiceUnavailable, "runtime settings unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.settings.Get())
}

func (s *APIServer) updateSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		apiError(w, http.StatusServiceUnavailable, "runtime settings unavailable", nil)
		return
	}
	var in struct {
		XDREnabled             *bool         `json:"xdr_enabled"`
		NetworkSensorEnabled   *bool         `json:"network_sensor_enabled"`
		BehaviorEnabled        *bool         `json:"behavior_enabled"`
		FeedsEnabled           *bool         `json:"feeds_enabled"`
		AutoFeedSync           *bool         `json:"auto_feed_sync"`
		AutoDegrade            *bool         `json:"auto_degrade"`
		ScanIntervalMillis     *int          `json:"scan_interval_millis"`
		NetworkIntervalSeconds *int          `json:"network_interval_seconds"`
		AlertScore             *int          `json:"alert_score"`
		ContainScore           *int          `json:"contain_score"`
		KillScore              *int          `json:"kill_score"`
		Revision               *uint64       `json:"revision"`
		EnabledRuleModules     *[]string     `json:"enabled_rule_modules"`
		CustomRules            *[]CustomRule `json:"custom_rules"`
	}
	if err := decodeStrictJSON(w, r, 128<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid runtime settings request", err)
		return
	}
	next := s.settings.Get()
	if in.Revision != nil && *in.Revision != next.Revision {
		apiError(w, http.StatusConflict, "runtime settings revision conflict", nil)
		return
	}
	if in.XDREnabled != nil {
		next.XDREnabled = *in.XDREnabled
	}
	if in.NetworkSensorEnabled != nil {
		next.NetworkSensorEnabled = *in.NetworkSensorEnabled
	}
	if in.BehaviorEnabled != nil {
		next.BehaviorEnabled = *in.BehaviorEnabled
	}
	if in.FeedsEnabled != nil {
		next.FeedsEnabled = *in.FeedsEnabled
	}
	if in.AutoFeedSync != nil {
		next.AutoFeedSync = *in.AutoFeedSync
	}
	if in.AutoDegrade != nil {
		next.AutoDegrade = *in.AutoDegrade
	}
	if in.ScanIntervalMillis != nil {
		next.ScanIntervalMillis = *in.ScanIntervalMillis
	}
	if in.NetworkIntervalSeconds != nil {
		next.NetworkIntervalSeconds = *in.NetworkIntervalSeconds
	}
	if in.AlertScore != nil {
		next.AlertScore = *in.AlertScore
	}
	if in.ContainScore != nil {
		next.ContainScore = *in.ContainScore
	}
	if in.KillScore != nil {
		next.KillScore = *in.KillScore
	}
	if in.EnabledRuleModules != nil {
		next.EnabledRuleModules = append([]string(nil), (*in.EnabledRuleModules)...)
	}
	if in.CustomRules != nil {
		next.CustomRules = append([]CustomRule(nil), (*in.CustomRules)...)
	}
	phase := s.release.Status().Phase
	if !next.XDREnabled && phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded {
		apiError(w, http.StatusConflict, "XDR can only be disabled in Observe", nil)
		return
	}
	current := s.settings.Get()
	if phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded &&
		(!slices.Equal(current.EnabledRuleModules, next.EnabledRuleModules) || !reflect.DeepEqual(current.CustomRules, next.CustomRules)) {
		apiError(w, http.StatusConflict, "rule modules and custom rules can only be changed in Observe", nil)
		return
	}
	updated, err := s.settings.Update(next)
	if err != nil {
		apiError(w, http.StatusBadRequest, "runtime settings rejected", err)
		return
	}
	s.state.SetSettings(updated)
	s.state.SetXDREnabled(updated.XDREnabled, updated.NetworkSensorEnabled)
	s.state.AddEvent(Event{Severity: "high", Kind: "settings.updated", Source: "operator", Message: fmt.Sprintf("Runtime settings revision %d activated", updated.Revision)})
	s.release.Evaluate()
	writeJSON(w, http.StatusOK, updated)
}

func (s *APIServer) addAllowlist(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		apiError(w, http.StatusServiceUnavailable, "runtime settings unavailable", nil)
		return
	}
	var in struct {
		Target string `json:"target"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid allowlist request", err)
		return
	}
	normalized, err := normalizeTarget(in.Target)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid allowlist target", err)
		return
	}
	snap := s.state.Snapshot()
	if snap.CoreConnected {
		if err := s.core.AllowAdd(normalized); err != nil {
			s.state.SetAllowlistReady(false)
			apiError(w, http.StatusServiceUnavailable, "kernel allowlist update failed", err)
			return
		}
	}
	updated, _, err := s.settings.AddAllowlist(normalized)
	if err != nil {
		if snap.CoreConnected {
			if rollbackErr := s.core.AllowDelete(normalized); rollbackErr != nil {
				s.state.SetAllowlistReady(false)
				apiError(w, http.StatusServiceUnavailable, "allowlist transaction reconciliation failed", errors.Join(err, rollbackErr))
				return
			}
		}
		apiError(w, http.StatusBadRequest, "allowlist update rejected", err)
		return
	}
	s.state.SetSettings(updated)
	s.state.SetAllowlistReady(snap.CoreConnected)
	s.state.AddEvent(Event{Severity: "high", Kind: "allowlist.added", Source: "operator", Message: "Management CIDR synchronized with XDP", Target: normalized})
	s.release.Evaluate()
	writeJSON(w, http.StatusCreated, updated)
}

func (s *APIServer) removeAllowlist(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		apiError(w, http.StatusServiceUnavailable, "runtime settings unavailable", nil)
		return
	}
	if phase := s.release.Status().Phase; phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded {
		apiError(w, http.StatusConflict, "allowlist entries can only be removed in Observe", nil)
		return
	}
	var in struct {
		Target string `json:"target"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid allowlist request", err)
		return
	}
	normalized, err := normalizeTarget(in.Target)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid allowlist target", err)
		return
	}
	current := s.settings.Get()
	if len(current.ManagementAllowlist) <= 1 {
		apiError(w, http.StatusConflict, "the final management allowlist entry cannot be removed", nil)
		return
	}
	snap := s.state.Snapshot()
	if snap.CoreConnected {
		if err := s.core.AllowDelete(normalized); err != nil {
			apiError(w, http.StatusServiceUnavailable, "kernel allowlist removal failed", err)
			return
		}
	}
	updated, _, err := s.settings.RemoveAllowlist(normalized)
	if err != nil {
		if snap.CoreConnected {
			if rollbackErr := s.core.AllowAdd(normalized); rollbackErr != nil {
				s.state.SetAllowlistReady(false)
				apiError(w, http.StatusServiceUnavailable, "allowlist transaction reconciliation failed", errors.Join(err, rollbackErr))
				return
			}
		}
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		apiError(w, http.StatusBadRequest, "allowlist update rejected", err)
		return
	}
	s.state.SetSettings(updated)
	s.state.SetAllowlistReady(snap.CoreConnected)
	s.state.AddEvent(Event{Severity: "high", Kind: "allowlist.removed", Source: "operator", Message: "Management CIDR removed from XDP", Target: normalized})
	s.release.Evaluate()
	writeJSON(w, http.StatusOK, updated)
}
