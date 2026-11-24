// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Titan exec-gate, StyX kernel enforcement and boot-trust HTTP surface split out
// of server.go (refactoring wave 1a, structure-only). The lockdown and witness
// handlers already live in lockdown_api.go and witness_api.go; this file carries
// the remaining Titan/StyX/boot-trust handlers. The mux registration stays in
// server.go.

import (
	"net/http"
	"strconv"
)

func (s *APIServer) bootTrustStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.bootTrust.Collect())
}

func (s *APIServer) styxRules(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Styx() == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []EgressRule{}, "drops": 0, "metadata_hits": 0})
		return
	}
	drops, hits := s.xdr.Styx().Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":         s.xdr.Styx().Rules(),
		"drops":         drops,
		"metadata_hits": hits,
	})
}

func (s *APIServer) addStyxRule(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Styx() == nil {
		apiError(w, http.StatusServiceUnavailable, "styx engine offline", nil)
		return
	}
	var rule EgressRule
	if err := decodeStrictJSON(w, r, 64*1024, &rule); err != nil {
		apiError(w, http.StatusBadRequest, "invalid rule payload", err)
		return
	}
	if err := s.xdr.Styx().AddRule(rule); err != nil {
		apiFault(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "rule": rule})
}

// styxStatusView assembles the read-only StyX kernel status. It joins the sync
// state (applied/pending/failed/capability-missing), the kernel flow health and the
// detector's bounded sensor view. Nothing here is derived from a secret, and no
// unbounded list leaves the process.
func (s *APIServer) styxStatusView() StyxStatusView {
	view := StyxStatusView{
		State: StyxSyncStateUnavailable, SensorState: "unavailable", Capability: styxCapabilityUnknown,
		TelemetryState: styxTelemetryUnavailable,
		Sync:           StyxSyncStatus{State: StyxSyncStateUnavailable, Capability: styxCapabilityUnknown},
		Flow:           StyxFlowMetrics{TelemetryState: styxTelemetryUnavailable},
		Beacon:         StyxBeaconView{Top: []StyxBeaconFlowSnapshot{}},
	}
	if s.xdr == nil {
		return view
	}
	sync := s.xdr.StyxPolicyStatus()
	beacon := s.xdr.StyxBeaconSnapshot()
	health, at, healthErr := s.xdr.StyxFlowHealthStatus()
	flow := s.xdr.StyxFlowMetrics()
	view.State = sync.State
	view.SensorState = beacon.SensorState
	view.Capability = sync.Capability
	view.EnforcementActive = styxEnforcementActive(sync)
	view.TelemetryState = flow.TelemetryState
	view.TelemetryDegraded = flow.TelemetryDegraded
	view.Sync = sync
	view.Flow = flow
	view.KernelHealth = health
	if !at.IsZero() {
		healthAt := at
		view.KernelHealthAt = &healthAt
	}
	view.KernelHealthError = healthErr
	view.Beacon = styxBeaconView(beacon)
	if engine := s.xdr.Styx(); engine != nil {
		drops, metadataHits := engine.Stats()
		view.GoRuleCount = len(engine.Rules())
		view.GoRuleDrops = drops
		view.GoRuleMetadata = metadataHits
	}
	return view
}

// styxKernelStatus serves GET /api/v1/styx/status: sync state, kernel health, the
// bounded beacon sensor view and the Go evaluator's counters in one read.
func (s *APIServer) styxKernelStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.styxStatusView())
}

// styxBeacons serves GET /api/v1/styx/beacons: the detector's bounded Top-10 view
// plus its counters and the kernel visibility counters. A degraded sensor is named
// as degraded; it never implies "no beacons".
func (s *APIServer) styxBeacons(w http.ResponseWriter, _ *http.Request) {
	view := s.styxStatusView()
	writeJSON(w, http.StatusOK, StyxBeaconsView{
		State: view.Sync.State, SensorState: view.SensorState, Capability: view.Capability,
		EnforcementActive: view.EnforcementActive, TelemetryState: view.TelemetryState,
		TelemetryDegraded: view.TelemetryDegraded,
		SyncState:         view.Sync.State, Epoch: view.Sync.Epoch,
		Beacon: view.Beacon, Flow: view.Flow, KernelHealth: view.KernelHealth,
		KernelHealthAt: view.KernelHealthAt, KernelHealthError: view.KernelHealthError,
	})
}

// titanExecStatus serves GET /api/v1/titan/exec/status: the exec-gate sync state,
// the kernel facts with the last health sample and the bounded ingestion counters.
// The report is derived from the engine's own projection, so a namespace without
// wiring, on a core without the ABI, or on a kernel without BPF-LSM never claims
// an active sensor or an applied enforcement state.
func (s *APIServer) titanExecStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.xdr.TitanExecStatusReport())
}

// titanExecEvents serves GET /api/v1/titan/exec/events?limit=N: the newest
// decoded kernel decisions from the bounded history (max 64). It is read-only;
// the history contains kernel facts only (no tokens, no credentials, no argv).
func (s *APIServer) titanExecEvents(w http.ResponseWriter, r *http.Request) {
	limit := titanExecEventHistoryLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			writePublicError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = value
	}
	writeJSON(w, http.StatusOK, s.xdr.TitanExecEventsReport(limit))
}
