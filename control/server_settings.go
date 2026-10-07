package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"slices"
	"time"
)

type managementAllowlistKernelTxn struct {
	added   []string
	deleted []string
	applied bool
}

func stringSetDiff(current, next []string) (added, deleted []string) {
	currentSet := make(map[string]struct{}, len(current))
	nextSet := make(map[string]struct{}, len(next))
	for _, value := range current {
		currentSet[value] = struct{}{}
	}
	for _, value := range next {
		nextSet[value] = struct{}{}
		if _, exists := currentSet[value]; !exists {
			added = append(added, value)
		}
	}
	for _, value := range current {
		if _, exists := nextSet[value]; !exists {
			deleted = append(deleted, value)
		}
	}
	slices.Sort(added)
	slices.Sort(deleted)
	return added, deleted
}

func (s *APIServer) stageManagementAllowlistChange(current, next []string) (*managementAllowlistKernelTxn, error) {
	added, deleted := stringSetDiff(current, next)
	txn := &managementAllowlistKernelTxn{added: added, deleted: deleted}
	if len(added) == 0 && len(deleted) == 0 {
		return txn, nil
	}
	phase := s.release.Status().Phase
	if len(deleted) > 0 && phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded {
		return nil, errors.New("management allowlist entries can only be removed in Observe/Degraded")
	}
	snap := s.state.Snapshot()
	if !snap.CoreConnected || s.core == nil {
		s.state.SetAllowlistReady(false)
		if phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded {
			return nil, errors.New("management allowlist cannot change while kernel core is unavailable outside Observe")
		}
		return txn, nil
	}

	addedDone := make([]string, 0, len(added))
	deletedDone := make([]string, 0, len(deleted))
	rollbackPartial := func(cause error) error {
		var errs []error
		// Restore protections first, then remove any newly-added entries.
		for i := len(deletedDone) - 1; i >= 0; i-- {
			if err := s.core.AllowAdd(deletedDone[i]); err != nil {
				errs = append(errs, fmt.Errorf("restore allowlist %s: %w", deletedDone[i], err))
			}
		}
		for i := len(addedDone) - 1; i >= 0; i-- {
			if err := s.core.AllowDelete(addedDone[i]); err != nil {
				errs = append(errs, fmt.Errorf("remove staged allowlist %s: %w", addedDone[i], err))
			}
		}
		if len(errs) > 0 {
			s.state.SetAllowlistReady(false)
			return errors.Join(append([]error{cause}, errs...)...)
		}
		return cause
	}
	for _, target := range added {
		if err := s.core.AllowAdd(target); err != nil {
			return nil, rollbackPartial(fmt.Errorf("kernel allowlist add %s: %w", target, err))
		}
		addedDone = append(addedDone, target)
	}
	for _, target := range deleted {
		if err := s.core.AllowDelete(target); err != nil {
			return nil, rollbackPartial(fmt.Errorf("kernel allowlist delete %s: %w", target, err))
		}
		deletedDone = append(deletedDone, target)
	}
	txn.applied = true
	return txn, nil
}

func (s *APIServer) rollbackManagementAllowlistChange(txn *managementAllowlistKernelTxn) error {
	if txn == nil || !txn.applied || s.core == nil {
		return nil
	}
	var errs []error
	for i := len(txn.deleted) - 1; i >= 0; i-- {
		if err := s.core.AllowAdd(txn.deleted[i]); err != nil {
			errs = append(errs, fmt.Errorf("restore allowlist %s: %w", txn.deleted[i], err))
		}
	}
	for i := len(txn.added) - 1; i >= 0; i-- {
		if err := s.core.AllowDelete(txn.added[i]); err != nil {
			errs = append(errs, fmt.Errorf("remove staged allowlist %s: %w", txn.added[i], err))
		}
	}
	if len(errs) > 0 {
		s.state.SetAllowlistReady(false)
		return errors.Join(errs...)
	}
	return nil
}

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
	// The Threat Intelligence namespace owns feed enablement. Mirror the legacy
	// fields into it so the aggregate endpoint cannot create a second truth.
	if next.ThreatIntel != nil {
		next.ThreatIntel.Enabled = next.FeedsEnabled
		next.ThreatIntel.AutoSync = next.AutoFeedSync
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
	if err := s.applyRuntimeSettings(current, updated, "legacy"); err != nil {
		rolledBack, rollbackErr := s.settings.Rollback(current.Revision)
		if rollbackErr == nil {
			_ = s.applyRuntimeSettings(updated, rolledBack, "legacy-rollback")
		}
		apiError(w, http.StatusServiceUnavailable, "runtime settings apply failed and was rolled back", errors.Join(err, rollbackErr))
		return
	}
	s.state.AddEvent(Event{Severity: "high", Kind: "settings.updated", Source: "operator", Message: fmt.Sprintf("Runtime settings revision %d activated", updated.Revision)})
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
	if s.kinetic != nil {
		s.kinetic.UpdateAllowlist(updated.ManagementAllowlist)
	}
	if s.kineticResponse != nil {
		s.kineticResponse.UpdateAllowlist(updated.ManagementAllowlist)
	}
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
	if s.kinetic != nil {
		s.kinetic.UpdateAllowlist(updated.ManagementAllowlist)
	}
	if s.kineticResponse != nil {
		s.kineticResponse.UpdateAllowlist(updated.ManagementAllowlist)
	}
	s.state.AddEvent(Event{Severity: "high", Kind: "allowlist.removed", Source: "operator", Message: "Management CIDR removed from XDP", Target: normalized})
	s.release.Evaluate()
	writeJSON(w, http.StatusOK, updated)
}

// applyRuntimeSettings propagates a committed Fabric Settings revision into the
// live components. It is intentionally centralized so legacy and module-scoped
// mutation paths cannot drift into different runtime behavior.
func (s *APIServer) applyRuntimeSettings(previous, updated RuntimeSettings, module string) error {
	if s.state != nil {
		s.state.SetSettings(updated)
		s.state.SetXDREnabled(updated.XDREnabled, updated.NetworkSensorEnabled)
	}
	if s.kinetic != nil {
		s.kinetic.UpdateConfig(updated.Kinetic)
		s.kinetic.UpdateAllowlist(updated.ManagementAllowlist)
	}
	if s.kineticResponse != nil {
		s.kineticResponse.UpdateConfig(updated.Kinetic, updated.Network)
		s.kineticResponse.UpdateAllowlist(updated.ManagementAllowlist)
	}
	if s.kinetic != nil {
		s.setKineticRuntimeEnabled(updated.Kinetic.Enabled)
	}
	if s.xdr != nil {
		if err := s.xdr.ApplyRuntimeSettings(updated); err != nil {
			return fmt.Errorf("apply XDR runtime settings: %w", err)
		}
	}
	if s.l7 != nil {
		if _, err := applyL7FabricSettings(s.l7, effectiveL7Settings(updated, s.cfg.L7), updated.Revision); err != nil {
			return fmt.Errorf("apply L7 runtime settings: %w", err)
		}
	}
	if s.feeds != nil {
		if err := s.feeds.applyThreatIntelSettings(effectiveThreatIntelSettings(updated), updated.Revision); err != nil {
			return fmt.Errorf("apply threat intelligence settings: %w", err)
		}
	}
	var chronos *ChronosScanner
	if s.xdr != nil {
		chronos = s.xdr.Chronos()
	}
	if err := applyIntegrityPolicies(effectiveIntegritySettings(updated), s.fim, chronos, s.packages, s.state.EvidenceLedger()); err != nil {
		return fmt.Errorf("apply integrity settings: %w", err)
	}
	if err := applyTrustPolicies(effectiveBootTrustSettings(updated), effectivePolicyTrustSettings(updated), s.bootTrust, s.policy); err != nil {
		return fmt.Errorf("apply trust settings: %w", err)
	}
	if err := applyForensicsPolicies(effectiveForensicsSettings(updated), s.caseEngine(), s.quarantineApplier()); err != nil {
		return fmt.Errorf("apply forensics settings: %w", err)
	}
	if err := applySystemPolicies(effectiveSystemSettings(updated), s.limiter, s.state, s.core); err != nil {
		return fmt.Errorf("apply system settings: %w", err)
	}
	if previous.FeedsEnabled && !updated.FeedsEnabled && s.feeds != nil {
		if s.core != nil {
			cleared, err := s.feeds.ClearFromKernel(s.core)
			if err != nil {
				return fmt.Errorf("clear disabled threat-intel kernel rules: %w", err)
			}
			if cleared > 0 && s.state != nil {
				s.state.AddEvent(Event{Severity: "info", Kind: "feeds.cleared", Source: "intelligence", Message: fmt.Sprintf("Threat intelligence deactivated: removed %d rules from kernel", cleared)})
			}
		}
		if s.state != nil {
			s.state.SetFeedVectors(0, time.Now().UTC())
		}
	}
	if s.release != nil {
		s.release.Evaluate()
	}
	return nil
}
