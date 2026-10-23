// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// HTTP surface of GeDefense Titan.
//
// Every route is registered through APIServer.auth, so authentication, origin
// checking, the X-VGT-Request-ID replay guard and the evidence gate behave
// exactly like every other operator endpoint. Reads are bounded; writes require
// a reason and record evidence through the engine.

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

func (s *APIServer) titanEngine() *TitanEngine {
	if s == nil || s.state == nil {
		return nil
	}
	return s.state.Titan()
}

// titanStatus serves GET /api/v1/titan/status.
func (s *APIServer) titanStatus(w http.ResponseWriter, _ *http.Request) {
	engine := s.titanEngine()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "Titan engine unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, engine.Status())
}

type titanEventsResponse struct {
	Events     []TitanEvent `json:"events"`
	NextBefore string       `json:"next_before"`
}

// titanEvents serves GET /api/v1/titan/events?limit=20&before=<opaque>.
func (s *APIServer) titanEvents(w http.ResponseWriter, r *http.Request) {
	engine := s.titanEngine()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "Titan engine unavailable", nil)
		return
	}
	limit := titanDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			apiError(w, http.StatusBadRequest, "invalid Titan event limit", err)
			return
		}
		limit = parsed
	}
	if limit > titanMaxLimit {
		limit = titanMaxLimit
	}
	events, next, err := engine.Events(limit, r.URL.Query().Get("before"))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid Titan event cursor", err)
		return
	}
	if events == nil {
		events = []TitanEvent{}
	}
	writeJSON(w, http.StatusOK, titanEventsResponse{Events: events, NextBefore: next})
}

// titanSetPolicy serves POST /api/v1/titan/policy.
func (s *APIServer) titanSetPolicy(w http.ResponseWriter, r *http.Request) {
	engine := s.titanEngine()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "Titan engine unavailable", nil)
		return
	}
	var request struct {
		Mode        string `json:"mode"`
		Armed       *bool  `json:"armed"`
		AutoContain *bool  `json:"auto_contain"`
		Reason      string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid Titan policy request", err)
		return
	}
	mode := TitanMode(strings.ToUpper(strings.TrimSpace(request.Mode)))
	if !validTitanMode(mode) || !titanReasonOK(request.Reason) {
		apiError(w, http.StatusBadRequest, "invalid Titan policy request", nil)
		return
	}
	current := engine.Status()
	armed, autoContain := current.Armed, current.AutoContain
	if request.Armed != nil {
		armed = *request.Armed
	}
	if request.AutoContain != nil {
		autoContain = *request.AutoContain
	}
	status, err := engine.ApplyPolicy(mode, armed, autoContain, request.Reason)
	if err != nil {
		apiError(w, http.StatusConflict, "Titan policy update rejected", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// titanReview serves POST /api/v1/titan/events/{id}/review.
func (s *APIServer) titanReview(w http.ResponseWriter, r *http.Request) {
	engine := s.titanEngine()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "Titan engine unavailable", nil)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if !validTitanEventID(id) {
		apiError(w, http.StatusBadRequest, "invalid Titan review request", nil)
		return
	}
	var request struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid Titan review request", err)
		return
	}
	decision := strings.ToUpper(strings.TrimSpace(request.Decision))
	if (decision != "REVIEWED" && decision != "TOLERATED" && decision != "ESCALATED") || !titanReasonOK(request.Reason) {
		apiError(w, http.StatusBadRequest, "invalid Titan review request", nil)
		return
	}
	event, err := engine.Review(id, decision, request.Reason)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			apiError(w, http.StatusNotFound, "Titan event not found", nil)
			return
		}
		apiError(w, http.StatusConflict, "Titan review rejected", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "event": event})
}

// titanQuarantine serves GET /api/v1/titan/quarantine.
func (s *APIServer) titanQuarantine(w http.ResponseWriter, _ *http.Request) {
	engine := s.titanEngine()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "Titan engine unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, engine.Quarantine())
}

// titanContain serves POST /api/v1/titan/contain. A containment that is not
// safely available is answered with an explicit status and reason; success is
// only reported for a verified quarantine transaction.
func (s *APIServer) titanContain(w http.ResponseWriter, r *http.Request) {
	engine := s.titanEngine()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "Titan engine unavailable", nil)
		return
	}
	var request struct {
		EventID string `json:"event_id"`
		Reason  string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid Titan containment request", err)
		return
	}
	eventID := strings.TrimSpace(request.EventID)
	if !validTitanEventID(eventID) || !titanReasonOK(request.Reason) {
		apiError(w, http.StatusBadRequest, "invalid Titan containment request", nil)
		return
	}
	response, err := engine.Contain(r.Context(), eventID, request.Reason)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			apiError(w, http.StatusNotFound, "Titan event not found", nil)
			return
		}
		apiError(w, http.StatusConflict, "Titan containment rejected", err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func titanReasonOK(reason string) bool {
	_, err := validateTitanReason(reason)
	return err == nil
}

// validTitanEventID matches the identifier format minted by randomID() and is
// deliberately strict: a path segment can never become a filesystem lookup.
func validTitanEventID(id string) bool {
	if len(id) < 8 || len(id) > titanMaxEventIDBytes {
		return false
	}
	for _, character := range id {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

// titanErrorIsNotFound keeps the handler mapping readable for callers that want
// a sentinel instead of text matching.
var errTitanNotFound = errors.New("Titan event not found")
