// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"strings"
	"time"
)

// SelfGuardReport is the bounded read-only projection of AP-0 kernel sensor
// self-protection for GET /api/v1/antispyware/status.
type SelfGuardReport struct {
	State      string     `json:"state"`
	Capability string     `json:"capability"`
	Reason     string     `json:"reason,omitempty"`
	Enabled    bool       `json:"enabled"`
	Armed      bool       `json:"armed"`
	BPFFSOK    bool       `json:"bpffs_ok"`
	PinsOK     bool       `json:"pins_ok"`
	CanaryOK   bool       `json:"canary_ok"`
	Events     uint64     `json:"events"`
	Drops      uint64     `json:"drops"`
	SampledAt  *time.Time `json:"sampled_at,omitempty"`
}

// SelfGuardReport returns the honest read-only AP-0 self-guard state.
func (e *XDREngine) SelfGuardReport() SelfGuardReport {
	report := SelfGuardReport{State: "unavailable", Capability: "unknown"}
	if e == nil {
		return report
	}
	e.selfGuardMu.Lock()
	status := e.selfGuardStatus
	statusErr := e.selfGuardStatusErr
	known := e.selfGuardCapabilityKnown
	sampled := e.selfGuardStatusAt
	e.selfGuardMu.Unlock()

	report.Enabled = status.Enabled
	report.Armed = status.Armed
	report.BPFFSOK = status.PinsAvailable
	report.PinsOK = status.PinsAvailable && status.PinsMissing == 0 && status.PinsReplaced == 0
	report.CanaryOK = status.CanaryFailures == 0 && (status.CanaryState == "" || status.CanaryState == "healthy" || status.CanaryState == "ok" || status.CanaryState == "active" || status.CanaryRuns > 0)
	report.Events = status.Events
	report.Drops = status.QueueDropped
	if known && statusErr == "" && !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known:
		report.Capability = "missing"
		if statusErr != "" {
			report.State = "degraded"
			report.Reason = statusErr
		} else {
			report.Reason = "privileged core does not advertise SELF_GUARD_*"
		}
	case statusErr != "":
		report.Capability = "available"
		report.State = "degraded"
		report.Reason = statusErr
	case !status.Enabled:
		report.Capability = "available"
		report.State = "disarmed"
		report.Reason = "self-guard is disarmed"
	case !report.BPFFSOK || !report.PinsOK || status.CanaryFailures > 0:
		report.Capability = "available"
		report.State = "degraded"
		report.Reason = "self-guard detected pin, bpffs or canary degradation"
	default:
		report.Capability = "available"
		report.State = "active"
	}
	return report
}

// antispywareStatus serves GET /api/v1/antispyware/status: read-only, bounded
// aggregation across all V6.3.0 antispyware & anti-rootkit planes (AP-0..AP-9).
func (s *APIServer) antispywareStatus(w http.ResponseWriter, _ *http.Request) {
	snap := s.state.Snapshot()
	selfGuard := s.xdr.SelfGuardReport()
	execInode := s.xdr.ExecInodeGateReport()
	bpfGuard := s.xdr.BpfGuardReport()
	crossView := s.xdr.CrossViewReport()
	kernelHooks := s.xdr.KernelHooksReport()
	persistence := s.xdr.PersistenceGuardReport()
	dns := s.xdr.DNSReport()
	styxPhase2 := s.xdr.StyxPhase2Report()
	sbcFusion := s.xdr.SBCFusionReport()
	secCrit := s.xdr.SecCritReport()
	credGuard := s.xdr.CredentialGuardReport()
	ransom := s.xdr.RansomSensorReport()
	titanExec := s.xdr.TitanExecStatusReport()
	styxView := s.styxStatusView()

	lpeMode := "disabled"
	lpeCap := "inactive"
	lpeReason := ""
	if s.v61 != nil && s.v61.lpeGuard != nil && s.settings != nil {
		settings := effectiveLPEGuardSettings(s.settings.Get())
		lpeCap = s.v61.lpeGuard.capabilityString()
		lpeReason = s.v61.lpeGuard.reasonString()
		if !settings.Enabled {
			lpeMode = "disabled"
		} else if lpeCap == "active" {
			lpeMode = "enforce"
		} else {
			lpeMode = "observe"
		}
	}

	chameleonMode := "standard"
	chameleonActive := false
	chameleonRoot := chameleonBpfPinRoot()
	if profile := activeChameleonProfile(); profile.Active() {
		chameleonActive = true
		chameleonMode = "chameleon"
	}

	fanotifyActive := snap.CoreConnected && strings.Contains(strings.ToLower(snap.XDR.Sensor), "fanotify-exec")
	planes := []string{
		selfGuard.State,
		execInode.State,
		bpfGuard.State,
		crossView.State,
		kernelHooks.State,
		persistence.State,
		dns.State,
		credGuard.State,
		ransom.State,
		secCrit.State,
	}
	activePlanes := 0
	for _, st := range planes {
		if st == "active" || st == "enforcing" || st == "enforced" {
			activePlanes++
		}
	}
	if fanotifyActive {
		activePlanes++
	}
	if titanExec.State == TitanExecSyncStateApplied || styxView.SensorState == "active" {
		activePlanes++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC(),
		"summary": map[string]any{
			"version":         snap.Version,
			"ui_build":        embeddedUIBuild(),
			"release_phase":   snap.Release.Phase,
			"xdr_enabled":     snap.XDR.Enabled,
			"xdr_mode":        snap.XDR.Mode,
			"core_connected":  snap.CoreConnected,
			"fanotify_active": fanotifyActive,
			"sensor":          snap.XDR.Sensor,
			"active_planes":   activePlanes,
			"total_planes":    len(planes) + 2,
		},
		"self_guard":       selfGuard,
		"exec_inode":       execInode,
		"bpf_guard":        bpfGuard,
		"cross_view":       crossView,
		"kernel_hooks":     kernelHooks,
		"persistence":      persistence,
		"dns":              dns,
		"styx_phase2":      styxPhase2,
		"styx":             styxView,
		"sbc_fusion":       sbcFusion,
		"sec_crit":         secCrit,
		"credential_guard": credGuard,
		"ransom":           ransom,
		"titan_exec":       titanExec,
		"chameleon": map[string]any{
			"active":       chameleonActive,
			"mode":         chameleonMode,
			"bpf_pin_root": chameleonRoot,
		},
		"lpe_guard": map[string]any{
			"mode":       lpeMode,
			"capability": lpeCap,
			"reason":     lpeReason,
		},
	})
}
