// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Dashboard overview, health and stream surface split out of server.go
// (refactoring wave 1a, structure-only). The mux for every route below stays in
// server.go; this file owns the overview/status/health/SSE handlers and the
// dashboard snapshot projection.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// clientSnapshot is the snapshot served to the dashboard. It carries the release readiness next
// to the state so the interface does not have to fetch it separately: readiness used to be
// requested twice per status frame - more traffic than the status itself - although it only
// changes on a release transition. A controller that cannot answer leaves the field nil instead
// of turning the whole status into an error; the screen then keeps the last readiness it knows.
func (s *APIServer) clientSnapshot() Snapshot {
	snapshot := s.state.Snapshot()
	// The XDR timeline row does not render the attack story, but one correlated incident can carry
	// hundreds of nodes: on the production host 250 incidents summed to 12.6 MB of story data and
	// every status frame pushed ~12.9 MB through the browser. The list keeps the fields it renders;
	// the full story stays on the surfaces that draw it (L7 findings drawer, forensics, the overview
	// map), which read it from their own endpoints. The snapshot is a fresh slice, so clearing the
	// field on it cannot mutate the state those endpoints read.
	for index := range snapshot.Incidents {
		snapshot.Incidents[index].AttackStory = nil
	}
	// Bridge active Module C passive TLS/ALPN capture into the L7 TLS path view
	// so Application Defense reflects live ClientHello visibility automatically.
	if s.v61 != nil && s.v61.tlsSensor != nil {
		s.v61.tlsSensor.ApplyToL7Status(&snapshot.L7)
	}
	// POINT 1 / P1-T5: a bounded Titan exec-gate projection is attached when the
	// engine carries the syncer. It is a separate field on purpose - it never
	// feeds xdrSensorMode or the enforcement label, and without wiring the payload
	// stays byte-identical to before.
	snapshot.TitanExec = s.xdr.TitanExecStatusSnapshot()
	// POINT 5 / P5-T3: the bounded Emergency Lockdown projection. It stays absent
	// when no engine is wired into this composition, so an installation that never
	// enabled the namespace keeps its exact status payload.
	if s.lockdown != nil {
		lockdownView := s.lockdown.StatusView()
		snapshot.Lockdown = &lockdownView
	}
	// POINT 4 / P4-T2: the bounded Out-of-Band Witness projection. It stays absent
	// when no engine is wired, and it carries no path, endpoint, token or key.
	if s.witness != nil {
		witnessView := s.witness.StatusView()
		snapshot.Witness = &witnessView
	}
	// The startup self-check answers "why is protection not armed yet". It is a
	// bounded projection (startup_supervisor.go) and carries no secrets; a
	// supervisor that has not published yet leaves the field absent instead of
	// inventing a healthy default.
	if startup, ok := CurrentStartupStatus(); ok {
		snapshot.Startup = &startup
	}
	if s.release == nil {
		return snapshot
	}
	canary, canaryErr := s.release.Readiness(ReleasePhaseCanary)
	enforce, enforceErr := s.release.Readiness(ReleasePhaseEnforce)
	if canaryErr != nil || enforceErr != nil {
		return snapshot
	}
	snapshot.Readiness = &ReleaseReadinessSet{Canary: canary, Enforce: enforce}
	return snapshot
}

func (s *APIServer) status(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.clientSnapshot()
	// POINT 3 / P3-T5: a bounded StyX projection is attached when the engine carries
	// the kernel sensor. It is a separate field on purpose - SetXDRStatus/xdrSensorMode
	// are test-pinned and a kernel egress sensor must not overwrite the XDR sensor
	// label. Without StyX wiring the payload stays byte-identical to before.
	if styx := s.xdr.StyxStatusSnapshot(); styx != nil {
		writeJSON(w, http.StatusOK, struct {
			Snapshot
			Styx *StyxStatus `json:"styx,omitempty"`
		}{Snapshot: snapshot, Styx: styx})
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

// liveness and readiness deliberately expose only the minimum a supervisor needs: an
// unauthenticated loopback surface must not reveal the build, posture or policy state of
// the platform (F-23 / CHAIN-007). The detailed health picture is served by the
// authenticated /api/v1/status and /bootz endpoints.
func (s *APIServer) liveness(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *APIServer) readiness(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	ready, _ := s.release.Ready()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ok": ready})
}

func localHealthRequest(r *http.Request) bool {
	return isLoopbackRemote(r.RemoteAddr)
}

func (s *APIServer) bootHealth(w http.ResponseWriter, r *http.Request) {
	if !localHealthRequest(r) {
		http.NotFound(w, r)
		return
	}
	snap := s.state.Snapshot()
	status := http.StatusOK
	if !snap.CoreConnected {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"ok":             snap.CoreConnected,
		"core_connected": snap.CoreConnected,
		"core_mode":      snap.CoreMode,
	})
}

func (s *APIServer) panelStatus(w http.ResponseWriter, r *http.Request) {
	if !localHealthRequest(r) {
		http.NotFound(w, r)
		return
	}
	snap := s.state.Snapshot()
	openFindings := snap.Cases.Open
	if !snap.Cases.Healthy {
		uniqueFindings := make(map[string]struct{})
		for _, incident := range snap.Incidents {
			if !incident.Acknowledged {
				uniqueFindings[caseFingerprint(incident)] = struct{}{}
			}
		}
		openFindings = len(uniqueFindings)
	}
	safe := snap.CoreConnected && !snap.XDR.Degraded && openFindings == 0
	state := "alert"
	if safe {
		state = "safe"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             safe,
		"state":          state,
		"open_findings":  openFindings,
		"core_connected": snap.CoreConnected,
		"xdr_degraded":   snap.XDR.Degraded,
		"xdr_sensor":     snap.XDR.Sensor,
	})
}

func isLoopbackRemote(remote string) bool {
	host := remoteIdentity(remote)
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *APIServer) stream(w http.ResponseWriter, r *http.Request) {
	if s.sseClients.Add(1) > s.sseClientLimit() {
		s.sseClients.Add(-1)
		http.Error(w, "stream capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer s.sseClients.Add(-1)
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	s.state.RecordStreamConnect()
	defer s.state.RecordStreamDisconnect()
	ch, cancel := s.state.Subscribe()
	defer cancel()
	if _, err := fmt.Fprint(w, "event: snapshot\ndata: "); err != nil {
		s.state.RecordStreamWriteError()
		return
	}
	if err := json.NewEncoder(w).Encode(s.clientSnapshot()); err != nil {
		s.state.RecordStreamWriteError()
		return
	}
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		s.state.RecordStreamWriteError()
		return
	}
	fl.Flush()
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprint(w, "event: event\ndata: "); err != nil {
				s.state.RecordStreamWriteError()
				return
			}
			if err := json.NewEncoder(w).Encode(e); err != nil {
				s.state.RecordStreamWriteError()
				return
			}
			if _, err := fmt.Fprint(w, "\n"); err != nil {
				s.state.RecordStreamWriteError()
				return
			}
			fl.Flush()
		case <-heartbeat.C:
			s.state.RecordStreamHeartbeat()
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				s.state.RecordStreamWriteError()
				return
			}
			fl.Flush()
		}
	}
}

func (s *APIServer) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.metricsAllowed() {
		http.NotFound(w, r)
		return
	}
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	snap := s.state.Snapshot()
	core := 0
	if snap.CoreConnected {
		core = 1
	}
	xdrDegraded := 0
	if snap.XDR.Degraded {
		xdrDegraded = 1
	}
	policyVerified := 0
	if snap.Policy.Verified {
		policyVerified = 1
	}
	fmt.Fprintf(w, "# HELP gedefense_up Control plane health.\n# TYPE gedefense_up gauge\ngedefense_up 1\n")
	fmt.Fprintf(w, "# TYPE gedefense_core_connected gauge\ngedefense_core_connected %d\n", core)
	fmt.Fprintf(w, "# TYPE gedefense_policy_verified gauge\ngedefense_policy_verified %d\n", policyVerified)
	fmt.Fprintf(w, "# TYPE gedefense_policy_generation gauge\ngedefense_policy_generation %d\n", snap.Policy.Generation)
	fmt.Fprintf(w, "# TYPE gedefense_blocks_active gauge\ngedefense_blocks_active %d\n", len(snap.Blocks))
	fmt.Fprintf(w, "# TYPE gedefense_feed_vectors gauge\ngedefense_feed_vectors %d\n", snap.FeedVectors)
	fmt.Fprintf(w, "# TYPE gedefense_cpu_percent gauge\ngedefense_cpu_percent %.2f\n", snap.Telemetry.CPUPercent)
	fmt.Fprintf(w, "# TYPE gedefense_memory_percent gauge\ngedefense_memory_percent %.2f\n", snap.Telemetry.MemoryPercent)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_incidents_total counter\ngedefense_xdr_incidents_total %d\n", snap.XDR.IncidentsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_actions_total counter\ngedefense_xdr_actions_total %d\n", snap.XDR.ActionsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_degraded gauge\ngedefense_xdr_degraded %d\n", xdrDegraded)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_processes gauge\ngedefense_xdr_processes %d\n", snap.XDR.Processes)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_external_connections gauge\ngedefense_xdr_external_connections %d\n", snap.XDR.OpenConnections)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_evaluations_total counter\ngedefense_xdr_evaluations_total %d\n", snap.XDR.EvaluationsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_evaluation_drops_total counter\ngedefense_xdr_evaluation_drops_total %d\n", snap.XDR.EvaluationDrops)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_anomalies_total counter\ngedefense_xdr_anomalies_total %d\n", snap.XDR.AnomaliesTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_queue_depth gauge\ngedefense_xdr_queue_depth %d\n", snap.XDR.QueueDepth)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_behavior_profiles gauge\ngedefense_xdr_behavior_profiles %d\n", snap.XDR.Behavior.Profiles)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_hits_total counter\ngedefense_kinetic_hits_total %d\n", snap.Kinetic.HitsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_velocity_bursts_total counter\ngedefense_kinetic_velocity_bursts_total %d\n", snap.Kinetic.VelocityBurstsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_portscans_total counter\ngedefense_kinetic_portscans_total %d\n", snap.Kinetic.PortscansTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_subnet_strikes_total counter\ngedefense_kinetic_subnet_strikes_total %d\n", snap.Kinetic.SubnetStrikesTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_active_tracking_ips gauge\ngedefense_kinetic_active_tracking_ips %d\n", snap.Kinetic.ActiveTrackingIPs)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_tracking_drops_total counter\ngedefense_kinetic_tracking_drops_total %d\n", snap.Kinetic.TrackingDropsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_tracking_evictions_total counter\ngedefense_kinetic_tracking_evictions_total %d\n", snap.Kinetic.TrackingEvictionsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_aggregate_evictions_total counter\ngedefense_kinetic_aggregate_evictions_total %d\n", snap.Kinetic.AggregateEvictionsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_kernel_ring_drops_total counter\ngedefense_kinetic_kernel_ring_drops_total %d\n", snap.Kinetic.KernelRingDrops)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_kernel_track_insert_failures_total counter\ngedefense_kinetic_kernel_track_insert_failures_total %d\n", snap.Kinetic.KernelTrackInsertFailures)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_bans_enforced_total counter\ngedefense_kinetic_bans_enforced_total %d\n", snap.Kinetic.BansEnforcedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_bans_expired_total counter\ngedefense_kinetic_bans_expired_total %d\n", snap.Kinetic.BansExpiredTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_response_applied_total counter\ngedefense_kinetic_response_applied_total %d\n", snap.Kinetic.ResponseAppliedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_response_suppressed_total counter\ngedefense_kinetic_response_suppressed_total %d\n", snap.Kinetic.ResponseSuppressedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_response_failed_total counter\ngedefense_kinetic_response_failed_total %d\n", snap.Kinetic.ResponseFailedTotal)
	l7Healthy := 0
	if snap.L7.Healthy {
		l7Healthy = 1
	}
	fmt.Fprintf(w, "# TYPE gedefense_l7_healthy gauge\ngedefense_l7_healthy %d\n", l7Healthy)
	fmt.Fprintf(w, "# TYPE gedefense_l7_requests_total counter\ngedefense_l7_requests_total %d\n", snap.L7.RequestsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_findings_total counter\ngedefense_l7_findings_total %d\n", snap.L7.FindingsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_blocked_total counter\ngedefense_l7_blocked_total %d\n", snap.L7.BlockedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_rate_limited_total counter\ngedefense_l7_rate_limited_total %d\n", snap.L7.RateLimitedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_rejected_total counter\ngedefense_l7_rejected_total %d\n", snap.L7.RejectedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_active_requests gauge\ngedefense_l7_active_requests %d\n", snap.L7.ActiveConnections)
	inlineHealthy := 0
	if snap.L7.InlineHealthy {
		inlineHealthy = 1
	}
	fmt.Fprintf(w, "# TYPE gedefense_l7_inline_healthy gauge\ngedefense_l7_inline_healthy %d\n", inlineHealthy)
	// The inline counter is a subset of gedefense_l7_requests_total, which now
	// aggregates socket and inline inspection. Kept as a separate series for
	// dashboards that track the inline producer specifically.
	fmt.Fprintf(w, "# HELP gedefense_l7_inline_requests_total Inline-edge subset of gedefense_l7_requests_total counter\n# TYPE gedefense_l7_inline_requests_total counter\ngedefense_l7_inline_requests_total %d\n", snap.L7.InlineRequestsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_inline_blocked_total counter\ngedefense_l7_inline_blocked_total %d\n", snap.L7.InlineBlockedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_inline_upstream_errors_total counter\ngedefense_l7_inline_upstream_errors_total %d\n", snap.L7.InlineUpstreamErrorsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_responses_inspected_total counter\ngedefense_l7_responses_inspected_total %d\n", snap.L7.ResponsesInspectedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_response_findings_total counter\ngedefense_l7_response_findings_total %d\n", snap.L7.ResponseFindingsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_response_inspection_errors_total counter\ngedefense_l7_response_inspection_errors_total %d\n", snap.L7.ResponseInspectionErrorsTotal)
	releaseReady := 0
	if snap.Release.Ready {
		releaseReady = 1
	}
	fmt.Fprintf(w, "# TYPE gedefense_release_ready gauge\ngedefense_release_ready %d\n", releaseReady)
	fmt.Fprintf(w, "# TYPE gedefense_release_core_misses gauge\ngedefense_release_core_misses %d\n", snap.Release.CoreMisses)
}

func (s *APIServer) platformCapabilities(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		writeJSON(w, http.StatusOK, DetectPlatformCapabilities("/"))
		return
	}
	writeJSON(w, http.StatusOK, s.xdr.PlatformCaps())
}

func (s *APIServer) activeResponses(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Responses() == nil {
		writeJSON(w, http.StatusOK, []ResponseRecord{})
		return
	}
	writeJSON(w, http.StatusOK, s.xdr.Responses().ActiveResponses())
}
