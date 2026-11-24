// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Reversible security transactions, quarantine and Gaia Cells preview surface
// split out of server.go (refactoring wave 1a, structure-only). The mux
// registration stays in server.go.

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func (s *APIServer) transactionStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			apiError(w, http.StatusBadRequest, "transaction limit is invalid", nil)
			return
		}
		limit = parsed
	}
	writeJSON(w, http.StatusOK, engine.Status(limit))
}

func (s *APIServer) quarantineStatus(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "quarantine unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, engine.QuarantineStatus())
}

func (s *APIServer) quarantinePreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "quarantine unavailable", nil)
		return
	}
	var request struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid quarantine preview request", err)
		return
	}
	payload, err := json.Marshal(quarantineRequest{Path: request.Path})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "quarantine preview unavailable", err)
		return
	}
	transaction, err := engine.Preview(
		quarantineTransactionType,
		"Quarantine file",
		request.Reason,
		payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "quarantine preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "quarantine.previewed", Source: "operator",
		Message: "File quarantine preview committed with immutable identity",
		Target:  transaction.ID,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) cellsStatus(w http.ResponseWriter, _ *http.Request) {
	adapter := s.state.Cells()
	if adapter == nil {
		apiError(w, http.StatusServiceUnavailable, "Gaia Cells adapter unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, adapter.Status(true))
}

func (s *APIServer) cellsPreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	var request struct {
		UUID       string `json:"uuid"`
		Generation uint64 `json:"generation"`
		CgroupID   uint64 `json:"cgroup_id"`
		Action     string `json:"action"`
		Reason     string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid Gaia Cell preview request", err)
		return
	}
	payload, err := json.Marshal(cellIsolationRequest{
		UUID: request.UUID, Generation: request.Generation,
		CgroupID: request.CgroupID, Action: request.Action,
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "Gaia Cell preview unavailable", err)
		return
	}
	transaction, err := engine.Preview(
		cellTransactionType,
		"Gaia Cell "+request.Action,
		request.Reason,
		payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "Gaia Cell preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "cell.isolation_previewed", Source: "operator",
		Message: "Gaia Cell isolation preview bound to immutable cgroup identity",
		Target:  transaction.ID + " " + request.UUID,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) transactionPreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	var request struct {
		Type    string          `json:"type"`
		Summary string          `json:"summary"`
		Reason  string          `json:"reason"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := decodeStrictJSON(w, r, 32<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction preview request", err)
		return
	}
	transaction, err := engine.Preview(
		request.Type, request.Summary, request.Reason, request.Payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "info", Kind: "transaction.previewed", Source: "operator",
		Message: "Reversible security transaction preview committed",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) transactionApply(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validTransactionID(id) {
		apiError(w, http.StatusBadRequest, "transaction identifier is invalid", nil)
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeStrictJSON(w, r, 4<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction apply request", err)
		return
	}
	transaction, err := engine.Apply(id, request.Confirmation)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction apply rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "transaction.applied", Source: "operator",
		Message: "Security transaction applied and verified",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusOK, transaction)
}

func (s *APIServer) transactionReverse(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validTransactionID(id) {
		apiError(w, http.StatusBadRequest, "transaction identifier is invalid", nil)
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeStrictJSON(w, r, 4<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction reverse request", err)
		return
	}
	transaction, err := engine.Reverse(id, request.Confirmation)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction reverse rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "critical", Kind: "transaction.reversed", Source: "operator",
		Message: "Security transaction reversed and verified",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusOK, transaction)
}
