// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Active-defense HTTP surface split out of server.go (refactoring wave 1a,
// structure-only): kernel exposure/mitigation, automatic confinement, hardening
// posture, manual block mutations, L7 findings and the release gate. The mux
// registration stays in server.go; kinetic handlers live in
// server_handlers_kinetic.go and feed handlers in server_handlers_defense_feeds.go.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// kernelExposureStatus reports the measured kernel-advisory exposure.
//
// The answer is deliberately richer than a boolean: it names the advisory, the fixed build per
// release channel, the verdict that could not be decided and the measured entry points, so an
// operator can see why a host is scored the way it is. ?refresh=1 re-takes the measurement, which is
// what an operator uses right after applying a mitigation to see the score move.
func (s *APIServer) kernelExposureStatus(w http.ResponseWriter, r *http.Request) {
	if s.kernelExposure == nil || !s.cfg.Advisories.Enabled {
		writeJSON(w, http.StatusOK, struct {
			Enabled bool `json:"enabled"`
		}{Enabled: false})
		return
	}
	exposure := s.kernelExposure.Current()
	if r.URL.Query().Get("refresh") != "" {
		exposure = s.kernelExposure.Refresh()
	}
	writeJSON(w, http.StatusOK, struct {
		Enabled     bool   `json:"enabled"`
		Mode        string `json:"mode"`
		MaxExposure int    `json:"max_exposure"`
		KernelExposure
	}{
		Enabled: true, Mode: s.cfg.Advisories.Mode, MaxExposure: s.cfg.Advisories.MaxExposure,
		KernelExposure: exposure,
	})
}

// kernelMitigationStatus reports the automatic mitigation and the value the kernel actually holds.
func (s *APIServer) kernelMitigationStatus(w http.ResponseWriter, _ *http.Request) {
	if s.mitigationGuard == nil {
		writeJSON(w, http.StatusOK, MitigationStatus{State: mitigationStateDisabled})
		return
	}
	writeJSON(w, http.StatusOK, s.mitigationGuard.Status())
}

// kernelMitigationPlan is the dry run: what the guard would change on this host right now. It writes
// nothing, which is what makes it safe to call on a production system before enabling the automatic
// path.
func (s *APIServer) kernelMitigationPlan(w http.ResponseWriter, _ *http.Request) {
	if s.mitigationGuard == nil {
		writeJSON(w, http.StatusOK, MitigationPlan{Reason: "no mitigation guard is attached"})
		return
	}
	writeJSON(w, http.StatusOK, s.mitigationGuard.Plan())
}

type mitigationRequest struct {
	Reason  string `json:"reason"`
	Confirm string `json:"confirm"`
}

// expectedMitigationConfirmation mirrors the transaction engine: the phrase is derivable from the
// target, so it proves intent, not authority. It is compared verbatim and never treated as a secret.
func expectedMitigationConfirmation(verb, key string) string { return verb + " " + key }

func decodeMitigationRequest(r *http.Request) (mitigationRequest, error) {
	payload, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if err != nil {
		return mitigationRequest{}, err
	}
	var request mitigationRequest
	if len(bytes.TrimSpace(payload)) > 0 {
		if err := json.Unmarshal(payload, &request); err != nil {
			return mitigationRequest{}, errors.New("the request body is not valid JSON")
		}
	}
	request.Reason = strings.TrimSpace(request.Reason)
	request.Confirm = strings.TrimSpace(request.Confirm)
	if len([]rune(request.Reason)) < 3 {
		return mitigationRequest{}, errors.New("a reason of at least three characters is required")
	}
	if len([]rune(request.Reason)) > 240 {
		request.Reason = string([]rune(request.Reason)[:240])
	}
	return request, nil
}

// kernelMitigationApply closes the entry point. In report mode the guard refuses: the automatic path
// exists only when the operator enabled it, and an unrequested kernel change is never acceptable.
func (s *APIServer) kernelMitigationApply(w http.ResponseWriter, r *http.Request) {
	request, err := decodeMitigationRequest(r)
	if err != nil {
		writePublicError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.mitigationGuard == nil {
		writePublicError(w, http.StatusServiceUnavailable, "no mitigation guard is attached")
		return
	}
	if !s.mitigationLimiter.Allow(remoteIdentity(r.RemoteAddr), time.Now()) {
		apiError(w, http.StatusTooManyRequests, "too many mitigation requests", nil)
		return
	}
	plan := s.mitigationGuard.Plan()
	required := expectedMitigationConfirmation("APPLY", plan.Key)
	if request.Confirm != required {
		writePublicError(w, http.StatusBadRequest, "confirmation required: "+required)
		return
	}
	status, err := s.mitigationGuard.Apply(request.Reason)
	if err != nil {
		writePublicError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// kernelMitigationRollback restores the previous value and is always available, including after the
// probation window: an operator must be able to undo what the platform did.
func (s *APIServer) kernelMitigationRollback(w http.ResponseWriter, r *http.Request) {
	request, err := decodeMitigationRequest(r)
	if err != nil {
		writePublicError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.mitigationGuard == nil {
		writePublicError(w, http.StatusServiceUnavailable, "no mitigation guard is attached")
		return
	}
	if !s.mitigationLimiter.Allow(remoteIdentity(r.RemoteAddr), time.Now()) {
		apiError(w, http.StatusTooManyRequests, "too many mitigation requests", nil)
		return
	}
	current := s.mitigationGuard.Status()
	required := expectedMitigationConfirmation("ROLLBACK", current.Key)
	if request.Confirm != required {
		writePublicError(w, http.StatusBadRequest, "confirmation required: "+required)
		return
	}
	status, err := s.mitigationGuard.Rollback(request.Reason)
	if err != nil {
		writePublicError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// cellsConfinementStatus reports the automatic isolation policy and what it has done.
func (s *APIServer) cellsConfinementStatus(w http.ResponseWriter, _ *http.Request) {
	if s.cellGuard == nil {
		writeJSON(w, http.StatusOK, CellConfinementStatus{Enabled: false})
		return
	}
	writeJSON(w, http.StatusOK, s.cellGuard.Status())
}

// confineIncident isolates the workload behind one incident. It is the manual path; the automatic one
// runs from the guard's own scan.
func (s *APIServer) confineIncident(w http.ResponseWriter, r *http.Request) {
	if s.cellGuard == nil {
		apiError(w, http.StatusServiceUnavailable, "cell isolation is unavailable", nil)
		return
	}
	incidentID := strings.TrimSpace(r.PathValue("id"))
	var request struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid confinement request", err)
		return
	}
	reason := strings.TrimSpace(request.Reason)
	if len([]rune(reason)) < 3 {
		apiError(w, http.StatusBadRequest, "a reason of at least three characters is required", nil)
		return
	}
	if !s.confineLimiter.Allow(remoteIdentity(r.RemoteAddr), time.Now()) {
		apiError(w, http.StatusTooManyRequests, "too many confinement requests", nil)
		return
	}
	result, err := s.cellGuard.ConfineIncident(incidentID, request.Action, reason)
	if err != nil {
		apiError(w, http.StatusConflict, "the workload could not be isolated", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// hardeningPosture evaluates the live posture with the administrable thresholds
// and reports the required-domain verdicts beside it, so the dashboard never has
// to re-derive a classification the backend already made.
func (s *APIServer) hardeningPosture(w http.ResponseWriter, _ *http.Request) {
	settings := HardeningPostureSettings{}
	if s.settings != nil {
		settings = effectiveHardeningSettings(s.settings.Get()).Posture
	}
	posture := s.hardening.Collect(s.state.Snapshot(), s.bootTrust.Collect())
	posture.Checks = append(posture.Checks, packageIntegrityPostureCheck(s.packages.Status()))
	summarized := summarizeHardening(posture.CollectedAt, posture.Checks, settings.thresholds())
	writeJSON(w, http.StatusOK, struct {
		HardeningPosture
		RequiredDomains []HardeningDomainFinding `json:"required_domains"`
	}{HardeningPosture: summarized, RequiredDomains: assessHardeningPosture(summarized, settings)})
}

func (s *APIServer) addBlock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target     string `json:"target"`
		Reason     string `json:"reason"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := decodeStrictJSON(w, r, 16<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request", err)
		return
	}
	network := NetworkRuntimeSettings{DefaultTTLSeconds: s.cfg.Defense.DefaultTTLSeconds, MaxTTLSeconds: s.cfg.Defense.MaxTTLSeconds, MaxBlockEntries: s.cfg.Defense.MaxBlockEntries}
	if s.settings != nil {
		network = s.settings.Get().Network
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = network.DefaultTTLSeconds
	}
	if in.TTLSeconds < 60 || in.TTLSeconds > network.MaxTTLSeconds {
		apiError(w, http.StatusBadRequest, "TTL outside policy", nil)
		return
	}
	normalizedTarget, err := normalizeTarget(in.Target)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid target", err)
		return
	}
	in.Target = normalizedTarget
	if s.kineticResponse != nil && s.kineticResponse.IsAllowlistProtected(in.Target) {
		apiError(w, http.StatusConflict, "target overlaps immutable management allowlist", ErrAllowlistProtected)
		return
	}
	enforced := false
	enforcement, _ := s.state.Modes()
	if enforcement == "enforce" {
		if err := s.core.Add(in.Target); err != nil {
			s.state.SetCore(false, "offline")
			apiError(w, http.StatusServiceUnavailable, "kernel core unavailable", err)
			return
		}
		enforced = true
	}
	b, err := s.state.AddBlock(in.Target, in.Reason, "manual", time.Duration(in.TTLSeconds)*time.Second, enforced, network.MaxBlockEntries)
	if err != nil {
		if enforced {
			if rollbackErr := s.core.Delete(in.Target); rollbackErr != nil {
				failSafeErr := s.release.FailSafe("manual block rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiFault(w, http.StatusBadRequest, err)
		return
	}
	if err := persistPolicy(s.policy, s.cfg, s.state); err != nil {
		s.state.RemoveBlockByID(b.ID)
		if enforced {
			if rollbackErr := s.core.Delete(b.Target); rollbackErr != nil {
				failSafeErr := s.release.FailSafe("manual block policy rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiError(w, http.StatusInternalServerError, "signed policy persistence failed", err)
		return
	}
	s.state.AddEvent(Event{Severity: "high", Kind: "block.added", Source: "operator", Message: "Signed block rule activated", Target: b.Target})
	writeJSON(w, http.StatusCreated, b)
}

func (s *APIServer) deleteBlock(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		apiError(w, http.StatusBadRequest, "missing rule id", nil)
		return
	}
	b, ok := s.state.BlockByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	expected := "REMOVE BLOCK " + b.Target
	if _, ok := s.requireProtectionRemovalConfirmation(w, r, expected); !ok {
		return
	}
	b, ok = s.state.RemoveBlockByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if b.Enforced {
		if err := s.core.Delete(b.Target); err != nil {
			s.state.RestoreBlock(b)
			apiError(w, http.StatusServiceUnavailable, "kernel core rejected rule removal", err)
			return
		}
	}
	if err := persistPolicy(s.policy, s.cfg, s.state); err != nil {
		s.state.RestoreBlock(b)
		if b.Enforced {
			if rollbackErr := s.core.Add(b.Target); rollbackErr != nil {
				s.state.AddEvent(Event{Severity: "critical", Kind: "policy.rollback_failed", Source: "policy", Message: "Kernel rollback failed after signed policy persistence error", Target: b.Target})
				failSafeErr := s.release.FailSafe("block deletion policy rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiError(w, http.StatusInternalServerError, "signed policy persistence failed", err)
		return
	}
	token, undoErr := s.newUndoToken(undoEntry{kind: "block", block: b})
	if undoErr != nil {
		log.Printf("block removal undo unavailable: %v", undoErr)
	}
	s.state.AddEvent(Event{Severity: "info", Kind: "block.removed", Source: "operator", Message: "Signed block rule removed; a short-lived server-side undo is available", Target: b.Target})
	writeJSON(w, http.StatusOK, map[string]any{
		"removed": b, "undo_token": token, "undo_expires_seconds": int(undoEntryTTL.Seconds()),
	})
}

func (s *APIServer) policyStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": s.policy.Status(), "blocks": s.state.BlocksSnapshot()})
}

func (s *APIServer) releaseStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.release.Status())
}

func (s *APIServer) releaseReadiness(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	readiness, err := s.release.Readiness(target)
	if err != nil {
		apiFault(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, readiness)
}

func (s *APIServer) l7Findings(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	snap := s.state.Snapshot()
	type L7FindingItem struct {
		ID         string            `json:"id"`
		Time       time.Time         `json:"time"`
		Severity   string            `json:"severity"`
		Score      int               `json:"score"`
		Confidence int               `json:"confidence"`
		RequestID  string            `json:"request_id"`
		Method     string            `json:"method"`
		Host       string            `json:"host"`
		Path       string            `json:"path"`
		RemoteIP   string            `json:"remote_ip"`
		RuleIDs    []string          `json:"rule_ids"`
		Categories []string          `json:"categories"`
		Summary    string            `json:"summary"`
		Decision   string            `json:"decision"`
		Action     string            `json:"action"`
		Outcome    string            `json:"outcome"`
		BodySHA256 string            `json:"body_sha256,omitempty"`
		Story      []AttackStoryNode `json:"attack_story,omitempty"`
	}
	items := make([]L7FindingItem, 0, limit)
	for i := len(snap.Incidents) - 1; i >= 0 && len(items) < limit; i-- {
		inc := snap.Incidents[i]
		if inc.RequestID != "" || inc.HTTPHost != "" || strings.HasPrefix(inc.Decision, "deny-http") {
			conf := 95
			if len(inc.AttackStory) > 0 && inc.AttackStory[0].Confidence > 0 {
				conf = inc.AttackStory[0].Confidence
			}
			items = append(items, L7FindingItem{
				ID:         inc.ID,
				Time:       inc.Time,
				Severity:   inc.Severity,
				Score:      inc.Score,
				Confidence: conf,
				RequestID:  inc.RequestID,
				Method:     inc.HTTPMethod,
				Host:       inc.HTTPHost,
				Path:       inc.HTTPPath,
				RemoteIP:   inc.Remote,
				RuleIDs:    inc.RuleIDs,
				Categories: inc.Categories,
				Summary:    inc.Summary,
				Decision:   inc.Decision,
				Action:     inc.Action,
				Outcome:    inc.Outcome,
				BodySHA256: inc.BodySHA256,
				Story:      inc.AttackStory,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": items,
		"total":    len(items),
		"status":   snap.L7,
	})
}

func (s *APIServer) releaseTransition(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target       string `json:"target"`
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid release transition request", err)
		return
	}
	status, err := s.release.Transition(in.Target, in.Confirmation, in.Reason)
	if err != nil {
		apiError(w, http.StatusConflict, "release gate rejected transition", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) releaseEmergencyStop(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid emergency stop request", err)
		return
	}
	status, err := s.release.EmergencyStop(in.Reason)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "emergency stop failed", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) releaseEmergencyStopClear(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid emergency-stop clear request", err)
		return
	}
	status, err := s.release.ClearEmergencyStop(in.Confirmation, in.Reason)
	if err != nil {
		apiError(w, http.StatusConflict, "emergency stop could not be cleared", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}
