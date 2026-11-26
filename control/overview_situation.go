// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// OverviewSituationLayer projects one defense plane into the hero cockpit pill bar.
type OverviewSituationLayer struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	State  string `json:"state"` // active | observe | warn | danger | off
	Metric string `json:"metric"`
}

// OverviewSituationReason explains why the correlated traffic light selected its level.
type OverviewSituationReason struct {
	Severity string `json:"severity"` // info | warn | critical
	Code     string `json:"code"`
	Text     string `json:"text"`
}

// OverviewSituationMetrics carries 24h/live correlated counts behind the verdict.
type OverviewSituationMetrics struct {
	Incidents24h    int    `json:"incidents_24h"`
	Critical24h     int    `json:"critical_24h"`
	High24h         int    `json:"high_24h"`
	Blocked24h      int    `json:"blocked_24h"`
	ActiveBans      int    `json:"active_bans"`
	L7Blocked       uint64 `json:"l7_blocked"`
	L7Findings      uint64 `json:"l7_findings"`
	WorkerCrashes   uint64 `json:"worker_crashes"`
	WorkerStorms    uint64 `json:"worker_storms"`
	TLSHandshakes   uint64 `json:"tls_handshakes"`
	TLSStorms       int    `json:"tls_storms"`
	StyxFlows       int    `json:"styx_flows"`
	StyxFlagged     int    `json:"styx_flagged"`
	TitanDenies     uint64 `json:"titan_denies"`
	ExposureServers int    `json:"exposure_servers"`
	ExposureCVEs    int    `json:"exposure_cves"`
	LPEStrict       bool   `json:"lpe_strict"`
	EdgeRunning     bool   `json:"edge_running"`
	FullProtection  bool   `json:"full_protection"`
	CoveragePercent int    `json:"coverage_percent"`
	ProtectionPhase string `json:"protection_phase"`
	FIMNew          int    `json:"fim_new,omitempty"`
	FIMTampered     int    `json:"fim_tampered,omitempty"`

	// M2: StyX enforcement and StyX telemetry are separate facts. A drop-driven
	// telemetry degradation is reported here as exactly that, never as "StyX off".
	StyxEnforcementActive bool    `json:"styx_enforcement_active"`
	StyxTelemetryState    string  `json:"styx_telemetry_state"`
	StyxTelemetryDegraded bool    `json:"styx_telemetry_degraded"`
	StyxDropRatio         float64 `json:"styx_drop_ratio"`
	StyxRingDropsDelta    uint64  `json:"styx_ring_drops_delta"`
	StyxEmittedDelta      uint64  `json:"styx_emitted_delta"`
	StyxDrainLagSeconds   float64 `json:"styx_drain_lag_seconds"`

	// M2.4: credential-guard visibility in the cockpit. Active is only claimed by
	// the guard report itself (armed+attached+files>0).
	CredentialGuardState  string `json:"credential_guard_state"`
	CredentialGuardActive bool   `json:"credential_guard_active"`
	CredentialGuardDenied uint64 `json:"credential_guard_denied"`
	CredentialGuardDrops  uint64 `json:"credential_guard_drops"`
}

// OverviewSituationResponse backs GET /api/v1/overview/situation.
type OverviewSituationResponse struct {
	GeneratedAt time.Time                 `json:"generated_at"`
	Level       string                    `json:"level"` // green | yellow | red
	StatusCode  string                    `json:"status_code"`
	Headline    string                    `json:"headline"`
	Summary     string                    `json:"summary"`
	Metrics     OverviewSituationMetrics  `json:"metrics"`
	Reasons     []OverviewSituationReason `json:"reasons"`
	Layers      []OverviewSituationLayer  `json:"layers"`
}

const (
	// situationActiveWindow is the acute escalation window during which an active
	// worker crash storm or unacknowledged critical alert keeps the posture on RED
	// (or an active burst of blocked events keeps the posture on YELLOW).
	situationActiveWindow = 15 * time.Minute
	// situationCooldownWindow is the post-incident observation window during which
	// a recently subsided storm or critical/high alert steps down from RED to YELLOW
	// before returning automatically to GREEN.
	situationCooldownWindow = 60 * time.Minute
)

type situationInput struct {
	Now                 time.Time
	Snap                Snapshot
	WorkerEvents        uint64
	WorkerStorms        uint64
	WorkerStormsCooling uint64
	WorkerSource        string
	TLSHandshakes       uint64
	TLSCapture          string
	TLSStormActive      bool
	LPEStrict           bool
	EdgeRunning         bool
	EdgeBlocked         uint64
	StyxFlows           int
	StyxFlagged         int
	StyxState           string
	StyxMode            string
	StyxTelemetry       StyxFlowMetrics
	CredentialGuard     CredentialGuardStatus
	TitanDenies         uint64
	TitanState          string
	ExposureServers     int
	ExposureCVEs        int
	ExposureGrade       string
}

func (s *APIServer) overviewSituation(w http.ResponseWriter, _ *http.Request) {
	in := situationInput{
		Now:  time.Now().UTC(),
		Snap: s.clientSnapshot(),
	}
	if s.v61 != nil {
		if wg := s.v61.workerGuard; wg != nil {
			srcMode, _, _ := wg.liveSourceState()
			wg.mu.Lock()
			correlator := wg.correlator
			wg.mu.Unlock()
			in.WorkerSource = srcMode
			if correlator != nil {
				c := correlator.CounterSnapshot()
				in.WorkerEvents = c.Events
				activeCutoff := in.Now.Add(-situationActiveWindow)
				cooldownCutoff := in.Now.Add(-situationCooldownWindow)
				for _, storm := range correlator.RecentStorms(0) {
					lastAt := storm.LastAt
					if lastAt.IsZero() {
						lastAt = storm.FirstAt
					}
					if !lastAt.Before(activeCutoff) {
						in.WorkerStorms++
					} else if !lastAt.Before(cooldownCutoff) {
						in.WorkerStormsCooling++
					}
				}
			}
		}
		if ts := s.v61.tlsSensor; ts != nil {
			ts.mu.Lock()
			in.TLSCapture = ts.capture
			in.TLSHandshakes = ts.handshakeCnt
			in.TLSStormActive = ts.storm.Active
			ts.mu.Unlock()
		}
		if we := s.v61.webExposure; we != nil {
			rep := we.Snapshot()
			in.ExposureServers = rep.Summary.Servers
			in.ExposureCVEs = rep.Summary.AffectedCVEs
			in.ExposureGrade = rep.Summary.Grade
		}
		if lg := s.v61.lpeGuard; lg != nil && s.settings != nil {
			settings := effectiveLPEGuardSettings(s.settings.Get())
			in.LPEStrict = settings.Enabled
		}
	}
	edgeStatus := v61Edge.Status()
	in.EdgeRunning = edgeStatus.State == "running"
	in.EdgeBlocked = edgeStatus.Counters.Blocked
	if s.xdr != nil {
		sb := s.xdr.StyxBeaconSnapshot()
		in.StyxFlows = sb.Flows
		in.StyxState = sb.SensorState
		in.StyxMode = s.xdr.StyxPolicyStatus().Mode
		in.StyxTelemetry = s.xdr.StyxFlowMetrics()
		in.CredentialGuard = s.xdr.CredentialGuardReport()
		for _, f := range sb.Top {
			if f.Score >= 50 || len(f.Signals) > 0 {
				in.StyxFlagged++
			}
		}
		if ts := s.xdr.TitanExecStatusSnapshot(); ts != nil {
			in.TitanState = ts.State
			in.TitanDenies = ts.Denies
		}
	}
	writeJSON(w, http.StatusOK, buildOverviewSituation(in))
}

// buildOverviewSituation correlates every real host signal into a transparent traffic light verdict.
func buildOverviewSituation(in situationInput) OverviewSituationResponse {
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-24 * time.Hour)
	snap := in.Snap
	m := OverviewSituationMetrics{
		ActiveBans:      len(snap.Blocks),
		L7Blocked:       snap.L7.BlockedTotal + snap.L7.InlineBlockedTotal,
		L7Findings:      snap.L7.FindingsTotal + snap.L7.InlineFindingsTotal,
		WorkerCrashes:   in.WorkerEvents,
		WorkerStorms:    in.WorkerStorms,
		TLSHandshakes:   in.TLSHandshakes,
		StyxFlows:       in.StyxFlows,
		StyxFlagged:     in.StyxFlagged,
		TitanDenies:     in.TitanDenies,
		ExposureServers: in.ExposureServers,
		ExposureCVEs:    in.ExposureCVEs,
		LPEStrict:       in.LPEStrict,
		EdgeRunning:     in.EdgeRunning,
		FullProtection:  snap.Protection.Effective,
	}
	styxEnforcement := strings.EqualFold(in.StyxMode, StyxModeMonitor) || strings.EqualFold(in.StyxMode, StyxModeEnforce)
	m.StyxEnforcementActive = styxEnforcement
	m.StyxTelemetryState = in.StyxTelemetry.TelemetryState
	m.StyxTelemetryDegraded = in.StyxTelemetry.TelemetryDegraded
	m.StyxDropRatio = in.StyxTelemetry.DropRatio
	m.StyxRingDropsDelta = in.StyxTelemetry.RingDropsDelta
	m.StyxEmittedDelta = in.StyxTelemetry.EmittedDelta
	m.StyxDrainLagSeconds = in.StyxTelemetry.DrainLagSeconds
	m.CredentialGuardState = in.CredentialGuard.State
	m.CredentialGuardActive = in.CredentialGuard.State == "active"
	m.CredentialGuardDenied = in.CredentialGuard.Denied
	m.CredentialGuardDrops = in.CredentialGuard.Drops
	if in.TLSStormActive {
		m.TLSStorms = 1
	}

	activeCutoff := now.Add(-situationActiveWindow)
	cooldownCutoff := now.Add(-situationCooldownWindow)
	var unmitigatedCrit int
	var coolingAlert60m int
	var recentIncidents15m int
	var recentBlocked15m int
	var recentHigh15m int
	for _, inc := range snap.Incidents {
		if inc.Time.Before(cutoff) {
			continue
		}
		m.Incidents24h++
		sev := strings.ToLower(strings.TrimSpace(inc.Severity))
		blocked := incidentBlocked(inc.Decision, inc.Action)
		inActive := !inc.Time.Before(activeCutoff)
		inCooldown := !inActive && !inc.Time.Before(cooldownCutoff)
		if inActive {
			recentIncidents15m++
		}
		if blocked {
			m.Blocked24h++
			if inActive {
				recentBlocked15m++
			}
		}
		switch sev {
		case "critical":
			m.Critical24h++
			if !blocked && !inc.Acknowledged {
				if inActive {
					unmitigatedCrit++
				} else if inCooldown {
					coolingAlert60m++
				}
			}
		case "high":
			m.High24h++
			if !blocked && !inc.Acknowledged {
				if inActive {
					recentHigh15m++
				} else if inCooldown {
					coolingAlert60m++
				}
			}
		}
	}

	phase := strings.ToLower(strings.TrimSpace(snap.Release.Phase))
	m.ProtectionPhase = phase
	if snap.FIM.LastScan != nil {
		m.FIMNew = snap.FIM.LastScan.New
		m.FIMTampered = snap.FIM.LastScan.Tampered + snap.FIM.LastScan.Missing
	}
	fimOnlyNew := snap.FIM.Health == fimHealthTampered && snap.FIM.LastScan != nil &&
		snap.FIM.LastScan.Tampered == 0 && snap.FIM.LastScan.Missing == 0 && snap.FIM.LastScan.New > 0
	fimRealTamper := snap.FIM.Health == fimHealthTampered && !fimOnlyNew
	lockdownTriggered := snap.Lockdown != nil && (snap.Lockdown.Latched || strings.EqualFold(snap.Lockdown.State, "triggered"))
	policyValid := snap.Policy.Verified

	layers := make([]OverviewSituationLayer, 0, 6)
	activeLayers := 0
	// 1. Kernel XDP
	xdpState := "off"
	xdpMetric := "offline"
	if snap.CoreConnected {
		if snap.Enforcement == "enforce" {
			xdpState = "active"
			xdpMetric = strconv.Itoa(m.ActiveBans) + " bans"
			activeLayers++
		} else {
			xdpState = "observe"
			xdpMetric = "observe"
		}
	}
	layers = append(layers, OverviewSituationLayer{ID: "xdp", Label: "Kernel XDP", State: xdpState, Metric: xdpMetric})

	// 2. L7 + Edge
	l7State := "off"
	l7Metric := "off"
	if snap.L7.Enabled {
		l7State = "active"
		if strings.EqualFold(snap.L7.Mode, "observe") {
			l7State = "observe"
		} else {
			activeLayers++
		}
		l7Metric = strconv.FormatUint(m.L7Blocked, 10) + " blocked"
	} else if in.EdgeRunning {
		l7State = "active"
		l7Metric = "edge " + strconv.FormatUint(in.EdgeBlocked, 10)
		activeLayers++
	}
	layers = append(layers, OverviewSituationLayer{ID: "l7", Label: "L7 & Edge", State: l7State, Metric: l7Metric})

	// 3. Web Posture A-C
	webState := "observe"
	if in.WorkerStorms > 0 || in.TLSStormActive {
		webState = "danger"
	} else if in.TLSCapture == "active" || in.ExposureServers > 0 {
		webState = "active"
		activeLayers++
	}
	webMetric := strconv.Itoa(in.ExposureServers) + " srv · " + strconv.FormatUint(in.TLSHandshakes, 10) + " TLS"
	layers = append(layers, OverviewSituationLayer{ID: "web", Label: "Web & TLS", State: webState, Metric: webMetric})

	// 4. XDR & Titan
	xdrDegraded := isXDROperationallyDegraded(snap.XDR)
	xdrState := "off"
	xdrMetric := "off"
	if snap.XDR.Enabled {
		if xdrDegraded {
			xdrState = "warn"
			xdrMetric = "degraded"
		} else if strings.EqualFold(snap.XDR.Mode, "enforce") {
			xdrState = "active"
			xdrMetric = strconv.Itoa(snap.XDR.Processes) + " proc"
			activeLayers++
		} else {
			xdrState = "observe"
			xdrMetric = strconv.Itoa(snap.XDR.Processes) + " proc"
		}
	}
	layers = append(layers, OverviewSituationLayer{ID: "xdr", Label: "XDR & Titan", State: xdrState, Metric: xdrMetric})

	// 5. StyX Egress. Enforcement and telemetry are shown as two separate facts:
	// an applied enforcement revision stays "active" even while the flow telemetry
	// is degraded - the layer then reports "Telemetrie degraded" instead of
	// pretending StyX is down or pretending the sensor is healthy.
	styxState := "off"
	styxMetric := "off"
	// An applied enforcement revision or an actively reporting detector counts as
	// the StyX layer being up; telemetry degradation is still reported separately
	// and overrides "active" with the honest "warn".
	styxLayerActive := styxEnforcement || (in.StyxState == "active" && in.StyxFlows > 0)
	switch {
	case !styxLayerActive && in.StyxState == "off":
		styxState, styxMetric = "off", "off"
	case in.StyxTelemetry.TelemetryDegraded:
		styxState = "warn"
		styxMetric = "Telemetrie degraded"
	case styxLayerActive && in.StyxFlagged > 0:
		styxState = "warn"
		styxMetric = strconv.Itoa(in.StyxFlagged) + " flagged"
	case styxLayerActive:
		styxState = "active"
		styxMetric = strconv.Itoa(in.StyxFlows) + " flows"
		activeLayers++
	default:
		styxState = "observe"
		styxMetric = strconv.Itoa(in.StyxFlows) + " flows"
	}
	layers = append(layers, OverviewSituationLayer{ID: "styx", Label: "StyX Egress", State: styxState, Metric: styxMetric})

	// 6. Integrity & FIM / Lockdown
	intState := "warn"
	intMetric := "check"
	if lockdownTriggered {
		intState = "danger"
		intMetric = "LOCKDOWN"
	} else if fimRealTamper {
		intState = "danger"
		intMetric = "TAMPER"
	} else if fimOnlyNew {
		intState = "warn"
		intMetric = strconv.Itoa(snap.FIM.LastScan.New) + " new"
	} else if snap.FIM.Health == fimHealthVerified && policyValid {
		intState = "active"
		intMetric = "verified"
		activeLayers++
	} else if policyValid {
		intState = "observe"
		intMetric = "policy ok"
	}
	layers = append(layers, OverviewSituationLayer{ID: "integrity", Label: "FIM & Trust", State: intState, Metric: intMetric})
	m.CoveragePercent = (activeLayers * 100) / 6

	reasons := make([]OverviewSituationReason, 0, 5)
	addReason := func(sev, code, text string) {
		if len(reasons) < 5 {
			reasons = append(reasons, OverviewSituationReason{Severity: sev, Code: code, Text: text})
		}
	}

	level := "green"
	statusCode := "calm_protected"

	if snap.Release.EmergencyStop {
		level, statusCode = "red", "emergency_stop"
		addReason("critical", "emergency_stop", "Emergency stop is active; automatic enforcement halted.")
	}
	if lockdownTriggered {
		level, statusCode = "red", "lockdown_active"
		addReason("critical", "lockdown", "Emergency lockdown is triggered on host.")
	}
	if in.WorkerStorms > 0 {
		level, statusCode = "red", "worker_crash_storm"
		addReason("critical", "worker_storm", strconv.FormatUint(in.WorkerStorms, 10)+" worker crash storm(s) correlated.")
	}
	if in.TLSStormActive {
		level, statusCode = "red", "tls_control_storm"
		addReason("critical", "tls_storm", "Active TLS/HTTP2 control-frame storm detected.")
	}
	if unmitigatedCrit > 0 {
		level, statusCode = "red", "critical_unmitigated"
		addReason("critical", "unmitigated_crit", strconv.Itoa(unmitigatedCrit)+" unmitigated critical incident(s) in the last 24h.")
	}
	if phase == "enforce" && !snap.CoreConnected {
		level, statusCode = "red", "core_offline_in_enforce"
		addReason("critical", "core_offline", "Core XDP daemon offline while enforce mode requested.")
	}
	if fimRealTamper {
		level, statusCode = "red", "fim_tamper"
		addReason("critical", "fim_tampered", "File Integrity Monitoring detected altered or missing baseline files.")
	}

	if level != "red" {
		if !snap.Protection.Effective || phase != "enforce" {
			level, statusCode = "yellow", "partial_protection"
			addReason("warn", "protection_phase", "Protection phase "+strings.ToUpper(phase)+" (full enforce not active across all layers).")
		}
		if fimOnlyNew {
			level = "yellow"
			if statusCode == "calm_protected" {
				statusCode = "fim_new_files"
			}
			addReason("warn", "fim_new_files", strconv.Itoa(snap.FIM.LastScan.New)+" new unbaselined system file(s) pending FIM review.")
		}
		if xdrDegraded {
			level = "yellow"
			addReason("warn", "xdr_degraded", "XDR sensor reported degraded telemetry pipeline.")
		}
		if in.WorkerStormsCooling > 0 || coolingAlert60m > 0 || recentHigh15m > 0 || recentIncidents15m >= 25 || recentBlocked15m >= 25 {
			level = "yellow"
			if statusCode == "calm_protected" {
				statusCode = "elevated_activity"
			}
			addReason("warn", "activity_24h", strconv.Itoa(m.Incidents24h)+" correlated incidents ("+strconv.Itoa(m.Blocked24h)+" blocked) in 24h.")
		}
		if in.StyxFlagged > 0 {
			level = "yellow"
			addReason("warn", "styx_egress", strconv.Itoa(in.StyxFlagged)+" outbound egress flow(s) flagged by StyX.")
		}
		if in.StyxTelemetry.TelemetryDegraded { // A telemetry drop is not an enforcement failure. It is reported as its
			// own warning so the cockpit never says "active" while the flow sensor
			// is silently losing events.
			level = "yellow"
			if statusCode == "calm_protected" {
				statusCode = "styx_telemetry_degraded"
			}
			reason := "StyX flow telemetry is degraded (" + in.StyxTelemetry.TelemetryState + "); enforcement itself is unchanged: "
			if in.StyxTelemetry.Reason != "" {
				reason += in.StyxTelemetry.Reason
			} else {
				reason += "kernel ring drops or drain lag exceed the documented bounds"
			}
			addReason("warn", "styx_telemetry_degraded", reason)
		}
		if in.ExposureCVEs > 0 {
			level = "yellow"
			addReason("warn", "exposure_cve", strconv.Itoa(in.ExposureCVEs)+" reachable web exposure advisory match(es).")
		}
		if in.CredentialGuard.State == "degraded" && in.CredentialGuard.Capability == "available" {
			// A configured-but-inactive credential guard is an operator warning; a
			// core without the capability stays a silent capability fact.
			level = "yellow"
			addReason("warn", "credential_guard_degraded", "Kernel credential guard is degraded: "+in.CredentialGuard.Reason)
		}
	}

	if level == "green" {
		if m.Blocked24h > 0 || m.ActiveBans > 0 {
			statusCode = "calm_mitigated"
			addReason("info", "mitigated", "All active protection layers healthy; "+strconv.Itoa(m.Blocked24h)+" event(s) neutralized in 24h.")
		} else {
			addReason("info", "nominal", "All protection layers active and nominal; no hostile pressure in 24h.")
		}
	}

	headline := "Lage normal · Vollschutz aktiv"
	summary := "Systeme laufen im erwarteten Fenster."
	switch level {
	case "red":
		headline = "KRITISCHE LAGE · SOFORTIGE PRÜFUNG ERFORDERLICH"
		summary = reasons[0].Text
	case "yellow":
		if phase != "enforce" {
			headline = "Erhöhte Aufmerksamkeit · Teilschutz (" + strings.ToUpper(phase) + ")"
		} else {
			headline = "Erhöhte Aktivität · Aktive Abwehr arbeitet"
		}
		summary = reasons[0].Text
	case "green":
		if m.Blocked24h > 0 {
			headline = "Lage ruhig · Vollschutz aktiv (" + strconv.Itoa(m.Blocked24h) + " Angriffe abgewehrt)"
		} else {
			headline = "Lage ruhig · Vollschutz aktiv"
		}
		summary = reasons[0].Text
	}

	return OverviewSituationResponse{
		GeneratedAt: now,
		Level:       level,
		StatusCode:  statusCode,
		Headline:    headline,
		Summary:     summary,
		Metrics:     m,
		Reasons:     reasons,
		Layers:      layers,
	}
}
