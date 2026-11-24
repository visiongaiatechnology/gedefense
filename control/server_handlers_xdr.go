// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// XDR, incident, case, evidence, forensics and airlock HTTP surface split out
// of server.go (refactoring wave 1a, structure-only). The mux registration stays
// in server.go; the review-queue and quarantine-prune handlers live in
// server_handlers_permits.go.

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

func (s *APIServer) evidenceStatus(w http.ResponseWriter, r *http.Request) {
	ledger := s.state.EvidenceLedger()
	// The page bounds are administrable so an operator can widen the evidence
	// view without a code change, while the ceiling keeps the response bounded.
	pageDefault, pageCeiling := 100, 500
	if s.settings != nil {
		policy := effectiveIntegritySettings(s.settings.Get()).Evidence
		if policy.APIRecentDefault > 0 {
			pageDefault = policy.APIRecentDefault
		}
		if policy.APIRecentMax >= pageDefault {
			pageCeiling = policy.APIRecentMax
		}
	}
	limit := pageDefault
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > pageCeiling {
			apiError(w, http.StatusBadRequest, "invalid evidence limit", err)
			return
		}
		limit = value
	}
	if ledger == nil {
		apiError(w, http.StatusServiceUnavailable, "evidence ledger unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": ledger.Status(), "records": ledger.Recent(limit)})
}

func (s *APIServer) evidenceVerify(w http.ResponseWriter, _ *http.Request) {
	ledger := s.state.EvidenceLedger()
	if ledger == nil {
		apiError(w, http.StatusServiceUnavailable, "evidence ledger unavailable", nil)
		return
	}
	if err := ledger.Verify(); err != nil {
		apiError(w, http.StatusServiceUnavailable, "evidence verification failed", err)
		return
	}
	writeJSON(w, http.StatusOK, ledger.Status())
}

func (s *APIServer) ackIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		apiError(w, http.StatusBadRequest, "missing incident id", nil)
		return
	}
	if !s.state.AcknowledgeIncident(id) {
		http.NotFound(w, r)
		return
	}
	s.state.AddEvent(Event{Severity: "info", Kind: "xdr.acknowledged", Source: "operator", Message: "XDR incident acknowledged", Target: id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *APIServer) behaviorProfiles(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 1 && value <= 500 {
			limit = value
		}
	}
	if s.xdr == nil || s.xdr.behavior == nil {
		writeJSON(w, http.StatusOK, map[string]any{"profiles": []any{}, "summary": BehaviorSummary{IntegrityOK: true}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": s.xdr.behavior.Snapshot(limit), "summary": s.xdr.behavior.Summary()})
}

func (s *APIServer) malwareScan(w http.ResponseWriter, r *http.Request) {
	if s.core == nil {
		apiError(w, http.StatusServiceUnavailable, "malware scanner unavailable", nil)
		return
	}
	var request struct {
		Path string `json:"path"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid malware scan request", err)
		return
	}
	result, err := s.core.MalwareScan(request.Path)
	if err != nil {
		apiError(w, http.StatusConflict, "malware scan rejected", err)
		return
	}
	severity := "info"
	kind := "malware.clean"
	if result.State == "suspicious" {
		severity = "high"
		kind = "malware.suspicious"
	} else if result.State == "malicious" {
		severity = "critical"
		kind = "malware.detected"
	}
	s.state.AddEvent(Event{
		Severity: severity, Kind: kind, Source: "malware-scanner",
		Message: fmt.Sprintf("Content scan %s: type=%s reason=%s size=%d sha256=%s", result.State, result.Classification, result.Reason, result.Size, result.SHA256),
		Target:  request.Path,
	})
	if result.State != "clean" && s.xdr != nil {
		s.xdr.recordManualMalwareFinding(request.Path, result)
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *APIServer) caseStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Cases()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "case engine unavailable", nil)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > caseListMaxLimit {
			apiError(w, http.StatusBadRequest, "case limit is invalid", nil)
			return
		}
		limit = parsed
	}
	writeJSON(w, http.StatusOK, engine.Status(limit))
}

func (s *APIServer) caseSetStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Cases()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "case engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validCaseID(id) {
		apiError(w, http.StatusBadRequest, "case identifier is invalid", nil)
		return
	}
	var request struct {
		Status     string `json:"status"`
		Resolution string `json:"resolution"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid case status request", err)
		return
	}
	record, err := engine.SetStatus(id, request.Status, request.Resolution)
	if err != nil {
		apiError(w, http.StatusConflict, "case status mutation rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "case.status_changed", Source: "operator",
		Message: "Security case status changed with durable evidence",
		Target:  record.ID + " " + record.Status,
	})
	writeJSON(w, http.StatusOK, record)
}

// forensicsExport produces the signed forensic record.
//
// The administrable policy shapes the snapshot before it is signed, so the
// signature covers exactly the bytes the operator receives. Redaction therefore
// cannot be undone by a verifier, and an export that was redacted is
// distinguishable from one that was not because the redaction changed the signed
// content rather than a display layer.
func (s *APIServer) forensicsExport(w http.ResponseWriter, _ *http.Request) {
	settings := effectiveForensicsSettings(s.settings.Get()).Export
	snapshot, err := shapeForensicsSnapshot(s.state.Snapshot(), settings, s.policy.TrustedPublicKey() != nil)
	if err != nil {
		apiError(w, http.StatusConflict, "forensics export rejected by policy", err)
		return
	}
	if !settings.SigningRequired {
		// The operator explicitly accepted an unauthenticated record. The response
		// says so in a header and in the body, so a consumer cannot mistake it for a
		// verified one.
		w.Header().Set("X-Gedefense-Signature", "none")
		w.Header().Set("Content-Disposition", `attachment; filename="gedefense-forensics.unsigned.json"`)
		writeJSON(w, http.StatusOK, map[string]any{"signed": false, "snapshot": snapshot})
		return
	}
	document, err := s.policy.SignForensics(snapshot)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "forensics export could not be signed", err)
		return
	}
	w.Header().Set("X-Gedefense-Signature", "ed25519")
	w.Header().Set("Content-Disposition", `attachment; filename="gedefense-forensics.signed.json"`)
	writeJSON(w, http.StatusOK, document)
}

func (s *APIServer) deceptionTestAccess(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Deception() == nil {
		apiError(w, http.StatusServiceUnavailable, "deception engine offline", nil)
		return
	}
	var req struct {
		CanaryPath string `json:"canary_path"`
		PID        int    `json:"pid"`
		Comm       string `json:"comm"`
		RemoteIP   string `json:"remote_ip"`
	}
	if err := decodeStrictJSON(w, r, 64*1024, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	evt := DeceptionAccessEvent{
		CanaryPath:   req.CanaryPath,
		AccessorPID:  req.PID,
		AccessorUID:  1000,
		AccessorComm: req.Comm,
		RemoteIP:     req.RemoteIP,
		Timestamp:    time.Now().UTC(),
	}
	inc, resp, err := s.xdr.Deception().HandleCanaryAccess(r.Context(), evt)
	if err != nil {
		apiFault(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incident": inc,
		"response": resp,
	})
}

func (s *APIServer) attackStories(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Correlator() == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	stories := s.xdr.Correlator().GetAllStories()
	type storySummary struct {
		ChainID      string            `json:"chain_id"`
		RootNodes    []string          `json:"root_nodes"`
		EvidenceRoot string            `json:"evidence_root"`
		NodeCount    int               `json:"node_count"`
		Nodes        []AttackStoryNode `json:"nodes"`
	}
	out := make([]storySummary, 0, len(stories))
	for _, g := range stories {
		out = append(out, storySummary{
			ChainID:      g.ChainID,
			RootNodes:    g.RootNodes,
			EvidenceRoot: g.EvidenceRoot(),
			NodeCount:    len(g.Nodes),
			Nodes:        g.CloneNodes(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *APIServer) airlockInspect(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Airlock() == nil {
		apiError(w, http.StatusServiceUnavailable, "airlock inspector offline", nil)
		return
	}
	var req struct {
		FilePath string `json:"file_path"`
	}
	if err := decodeStrictJSON(w, r, 64*1024, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid inspect request", err)
		return
	}
	// The requested path is attacker-influenced data. InspectFile binds it to the
	// configured staging root and only ever opens below it (openat walk with
	// O_NOFOLLOW); a boundary violation is a refusal, not an inspection result.
	res, err := s.xdr.Airlock().InspectFile(req.FilePath)
	if err != nil {
		// The detail stays internal: an authenticated caller must not learn absolute paths or errno
		// text from a success response. The operator receives a reason code, the journal the cause.
		log.Printf("airlock inspect: %v", err)
		var boundaryErr *AirlockBoundaryException
		if errors.As(err, &boundaryErr) {
			if s.state != nil {
				s.state.AddEvent(Event{
					Severity: "warning", Kind: "airlock.path_rejected", Source: "airlock",
					Message: "Airlock inspection refused a target outside the configured staging root or through a symbolic link",
					Target:  r.Method + " " + r.URL.Path,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{"clean": false, "error": "inspection target refused"})
			return
		}
		var validationErr *AirlockValidationException
		if errors.As(err, &validationErr) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"clean": false, "error": "inspection request rejected", "result": res})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"clean": false, "error": "inspection unavailable", "result": res})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clean": true, "result": res})
}

func (s *APIServer) chronosStatus(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Chronos() == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "offline"})
		return
	}
	cp, err := s.xdr.Chronos().LoadCheckpoint()
	if err != nil || cp == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "idle", "checkpoint": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": cp.Phase, "checkpoint": cp})
}
