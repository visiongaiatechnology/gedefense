// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: operator HTTP surface for the persistent review queue and the
// evidence-first quarantine prune.
//
//   GET    /api/v1/xdr/review              bounded review queue + honest report
//   POST   /api/v1/xdr/review/{id}/ack     mark one finding reviewed
//   DELETE /api/v1/xdr/review/{id}         delete one finding
//   POST   /api/v1/quarantine/prune        evidence-first false-positive vault prune
//
// Every route is wrapped by the existing s.auth middleware (bearer token,
// origin check, pre-auth budget, replay guard and the mandatory operator
// mutation evidence gate). This file adds no second authentication model.
//
// DISCLOSURE: failure bodies use the shared opaque apiFault/apiError path or a
// fixed literal; no internal error text, path or core message crosses the API
// boundary. The literal "review queue unavailable" is static and carries no
// host detail (the shared operatorMessages allowlist lives in another work
// package's file and is not extended here).

import (
	"errors"
	"net/http"
	"os"
	"strconv"
)

// reviewQueueUnavailable is the static rejection body for an unwired queue.
func reviewQueueUnavailable(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "review queue unavailable"})
}

// xdrReviewQueue serves the bounded persistent review queue.
func (s *APIServer) xdrReviewQueue(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			apiError(w, http.StatusBadRequest, "invalid event limit", nil)
			return
		}
		limit = parsed
	}
	if s.xdr == nil {
		reviewQueueUnavailable(w)
		return
	}
	report, entries, available := s.xdr.ReviewQueueReport(limit)
	view := ReviewQueueView{Report: report, Entries: entries, Limit: limit}
	if entries == nil {
		view.Entries = []ReviewEntry{}
	}
	if !available && !report.Corrupt {
		// The store could not be read but is not corrupt (for example a
		// transient failure during the first bind): still return the honest
		// report with an empty bounded window.
		reviewQueueUnavailable(w)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// xdrReviewAck marks one queue entry as reviewed.
func (s *APIServer) xdrReviewAck(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		reviewQueueUnavailable(w)
		return
	}
	id := r.PathValue("id")
	changed, err := s.xdr.AcknowledgeReviewEntry(id)
	if errors.Is(err, os.ErrNotExist) || (!changed && err == nil) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		apiFault(w, http.StatusConflict, err)
		return
	}
	if s.state != nil {
		s.state.AddEvent(Event{
			Severity: "info", Kind: "xdr.review_acknowledged", Source: "operator",
			Message: "Persistent review-queue finding acknowledged", Target: boundedPermitText(id, 64),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// xdrReviewDelete removes one queue entry.
func (s *APIServer) xdrReviewDelete(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		reviewQueueUnavailable(w)
		return
	}
	id := r.PathValue("id")
	changed, err := s.xdr.DeleteReviewEntry(id)
	if errors.Is(err, os.ErrNotExist) || (!changed && err == nil) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		apiFault(w, http.StatusConflict, err)
		return
	}
	if s.state != nil {
		s.state.AddEvent(Event{
			Severity: "info", Kind: "xdr.review_deleted", Source: "operator",
			Message: "Persistent review-queue finding deleted by an operator", Target: boundedPermitText(id, 64),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// quarantinePrune performs the evidence-first prune of a verified false-positive
// vault object. The request must carry the full identity and a confirm field
// equal to the object id; a prune without an identity is impossible.
func (s *APIServer) quarantinePrune(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ObjectID string              `json:"object_id"`
		Identity *QuarantineIdentity `json:"identity"`
		Confirm  string              `json:"confirm"`
	}
	if err := decodeStrictJSON(w, r, 16<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request", err)
		return
	}
	if s.core == nil {
		apiError(w, http.StatusServiceUnavailable, "kernel core unavailable", nil)
		return
	}
	var evidence quarantinePruneEvidence
	if s.state != nil {
		evidence = s.state
	}
	pruner := newQuarantinePruner(s.core, evidence, func(event Event) {
		if s.state != nil {
			s.state.AddEvent(event)
		}
	})
	if s.state != nil {
		pruner.requestID = r.Header.Get("X-VGT-Request-ID")
	}
	result, err := pruner.Prune(request.ObjectID, request.Identity, request.Confirm)
	if err != nil {
		switch {
		case errors.Is(err, errQuarantinePruneCore):
			apiError(w, http.StatusServiceUnavailable, "kernel core unavailable", err)
		case errors.Is(err, errQuarantinePruneEvidence):
			apiError(w, http.StatusServiceUnavailable, "mandatory evidence commit failed", err)
		case errors.Is(err, errQuarantinePruneRejected):
			apiFault(w, http.StatusConflict, err)
		case errors.Is(err, errQuarantinePruneConfirmOnly):
			// The object is gone; the audit trail is incomplete. Say both.
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":  "mandatory evidence commit failed",
				"result": result,
			})
		default:
			apiError(w, http.StatusBadRequest, "invalid request", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}
