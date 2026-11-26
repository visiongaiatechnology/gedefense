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
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
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

// xdrSBCFusion returns the bounded AP-6 Styx Beacon / Cross-Domain Corroboration report.
func (s *APIServer) xdrSBCFusion(w http.ResponseWriter, _ *http.Request) {
	if s.xdr == nil {
		writeJSON(w, http.StatusOK, SBCFusionReport{
			Version:         SBCFusionVersion,
			State:           "unavailable",
			Capacity:        SBCCapacity,
			HalfLifeMinutes: float64(SBCDefaultHalfLifeMinutes),
		})
		return
	}
	writeJSON(w, http.StatusOK, s.xdr.SBCFusionReport())
}

// xdrSecCrit returns the bounded S12 high-priority security ring and quota report.
func (s *APIServer) xdrSecCrit(w http.ResponseWriter, _ *http.Request) {
	if s.xdr == nil {
		writeJSON(w, http.StatusOK, SecCritReport{
			State:      "unavailable",
			Capability: "unknown",
			Quotas: SecCritQuotaReport{
				Enforced:               true,
				QuarantineReserveBytes: secCritQuarantineReserve,
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, s.xdr.SecCritReport())
}

// xdrPermitsList projects the PermitV1 broker report and stored entries.
func (s *APIServer) xdrPermitsList(w http.ResponseWriter, _ *http.Request) {
	if s.xdr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "permit broker unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"report":  s.xdr.PermitReport(),
		"permits": s.xdr.ListPermits(),
	})
}

// xdrPermitsUpsert validates, stores and activates one PermitV1 entry (Critical step-up required).
func (s *APIServer) xdrPermitsUpsert(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "permit broker unavailable"})
		return
	}
	var permit PermitV1
	if err := decodeStrictJSON(w, r, permitMaxObjectBytes, &permit); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request", err)
		return
	}
	now := time.Now().UTC()
	if strings.TrimSpace(permit.PermitID) == "" {
		id, err := newPermitID()
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "permit identifier unavailable", err)
			return
		}
		permit.PermitID = id
	}
	if permit.SHA256 == "" && permit.Inode.Inode == 0 && strings.TrimSpace(permit.Path) != "" {
		if !validPermitPath(permit.Path) {
			apiError(w, http.StatusBadRequest, "permit executable path is invalid", nil)
			return
		}
		identity, err := statExecutableIdentity(permit.Path, now)
		if err != nil {
			apiFault(w, http.StatusConflict, err)
			return
		}
		permit.SHA256 = identity.SHA256
		permit.Inode = PermitInode{Device: identity.Device, Inode: identity.Inode}
	}
	if permit.Schema == "" {
		permit.Schema = permitSchemaV1
	}
	if permit.ValidFrom.IsZero() {
		permit.ValidFrom = now
	}
	if permit.ValidUntil.IsZero() {
		permit.ValidUntil = now.Add(permitDefaultTTLAuthorized)
	}
	if err := s.xdr.UpsertPermit(&permit); err != nil {
		apiFault(w, http.StatusConflict, err)
		return
	}
	if s.state != nil {
		s.state.AddEvent(Event{
			Severity: "high", Kind: "xdr.permit_upserted", Source: "operator",
			Message: fmt.Sprintf("PermitV1 %s upserted (trust_level=%s)", boundedPermitText(permit.PermitID, 64), boundedPermitText(permit.TrustLevel, 32)),
			Target:  boundedPermitText(permit.PermitID, 64),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"permit_id":   permit.PermitID,
		"trust_level": permit.TrustLevel,
		"report":      s.xdr.PermitReport(),
	})
}

// xdrPermitsDelete removes one stored PermitV1 entry (Critical step-up required).
func (s *APIServer) xdrPermitsDelete(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "permit broker unavailable"})
		return
	}
	id := r.PathValue("id")
	if err := s.xdr.RemovePermit(id); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		apiFault(w, http.StatusConflict, err)
		return
	}
	if s.state != nil {
		s.state.AddEvent(Event{
			Severity: "high", Kind: "xdr.permit_removed", Source: "operator",
			Message: "PermitV1 entry removed by operator", Target: boundedPermitText(id, 64),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// chameleonStatus returns the non-secret installation identity posture.
func (s *APIServer) chameleonStatus(w http.ResponseWriter, _ *http.Request) {
	profile := activeChameleonProfile()
	if !profile.Active() {
		writeJSON(w, http.StatusOK, map[string]any{
			"active":       false,
			"mode":         "standard",
			"core_socket":  chameleonDefaultCoreSocket,
			"scan_socket":  chameleonDefaultScanSocket,
			"bpf_pin_root": chameleonDefaultBpfPinRoot,
		})
		return
	}
	manifest, _ := profile.Manifest()
	mapping, _ := profile.AuditMapping()
	writeJSON(w, http.StatusOK, map[string]any{
		"active":           true,
		"mode":             "chameleon",
		"install_id":       manifest.InstallID,
		"unit_prefix":      manifest.NeutralPrefix,
		"core_socket":      manifest.CoreSocket,
		"scan_socket":      manifest.ScanSocket,
		"bpf_pin_root":     manifest.BpfPinRoot,
		"state_dir":        manifest.StateDir,
		"public_port":      manifest.PublicPort,
		"backend_port":     manifest.BackendPort,
		"salt_fingerprint": mapping.SaltFingerprint,
		"mapping_hash":     mapping.MappingHash,
	})
}

// chameleonReveal writes a mandatory evidence record before returning the
// installation's non-secret Chameleon audit commitment (Critical step-up required).
func (s *APIServer) chameleonReveal(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Reason  string `json:"reason"`
		Confirm string `json:"confirm"`
	}
	if err := decodeStrictJSON(w, r, 4096, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request", err)
		return
	}
	reason := strings.TrimSpace(request.Reason)
	if len(reason) < 8 || len(reason) > 240 || strings.TrimSpace(request.Confirm) != "REVEAL CHAMELEON" {
		apiError(w, http.StatusBadRequest, "chameleon reveal requires confirmation REVEAL CHAMELEON and reason", nil)
		return
	}
	profile := activeChameleonProfile()
	if !profile.Active() {
		apiError(w, http.StatusConflict, "chameleon identity mode is not active on this host", nil)
		return
	}
	manifest, _ := profile.Manifest()
	mapping, ok := profile.AuditMapping()
	if !ok {
		apiError(w, http.StatusConflict, "chameleon audit mapping unavailable", nil)
		return
	}
	if s.state != nil {
		if err := s.state.RecordEvidence(EvidenceRecord{
			Severity: "high", Kind: "chameleon.mapping_revealed", Source: "operator",
			Message: fmt.Sprintf("Chameleon identity mapping commitment revealed by operator (install_id=%s hash=%s reason=%s)",
				boundedPermitText(mapping.InstallID, 64), boundedPermitText(mapping.MappingHash, 64), boundedPermitText(reason, 120)),
			Target: boundedPermitText(mapping.InstallID, 64),
		}); err != nil {
			apiError(w, http.StatusServiceUnavailable, "mandatory evidence commit failed", err)
			return
		}
		s.state.AddEvent(Event{
			Severity: "high", Kind: "chameleon.mapping_revealed", Source: "operator",
			Message: "Chameleon mapping commitment revealed after critical step-up", Target: boundedPermitText(mapping.InstallID, 64),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":           true,
		"install_id":       mapping.InstallID,
		"salt_fingerprint": mapping.SaltFingerprint,
		"mapping_hash":     mapping.MappingHash,
		"unit_prefix":      manifest.NeutralPrefix,
		"core_socket":      manifest.CoreSocket,
		"scan_socket":      manifest.ScanSocket,
		"bpf_pin_root":     manifest.BpfPinRoot,
		"admin_audit_path": manifest.AdminAuditPath,
	})
}

// xdrUpdateWindowOverride closes an open update window or opens one ONLY via a
// verified signed release manifest (Critical step-up required; never an unsigned bypass).
func (s *APIServer) xdrUpdateWindowOverride(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		apiError(w, http.StatusServiceUnavailable, "xdr engine unavailable", nil)
		return
	}
	var request struct {
		Action        string `json:"action"`
		ManifestPath  string `json:"manifest_path"`
		PublicKeyPath string `json:"public_key_path"`
		ArtifactDir   string `json:"artifact_dir"`
		Reason        string `json:"reason"`
		TTLSeconds    int    `json:"ttl_seconds"`
		Confirm       string `json:"confirm"`
	}
	if err := decodeStrictJSON(w, r, 8192, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request", err)
		return
	}
	reason := strings.TrimSpace(request.Reason)
	if len(reason) < 8 || len(reason) > 240 {
		apiError(w, http.StatusBadRequest, "override reason must contain 8-240 characters", nil)
		return
	}
	switch strings.TrimSpace(request.Action) {
	case "close":
		if strings.TrimSpace(request.Confirm) != "CLOSE UPDATE WINDOW" {
			apiError(w, http.StatusBadRequest, "confirmation CLOSE UPDATE WINDOW is required", nil)
			return
		}
		s.xdr.EndSignedUpdateWindow(reason)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "active": false})
	case "open":
		if strings.TrimSpace(request.Confirm) != "OPEN SIGNED UPDATE WINDOW" {
			apiError(w, http.StatusBadRequest, "confirmation OPEN SIGNED UPDATE WINDOW is required", nil)
			return
		}
		if err := s.xdr.BeginSignedUpdateWindow(
			strings.TrimSpace(request.ManifestPath),
			strings.TrimSpace(request.PublicKeyPath),
			strings.TrimSpace(request.ArtifactDir),
			reason,
			time.Duration(request.TTLSeconds)*time.Second,
		); err != nil {
			apiFault(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "active": s.xdr.SignedUpdateWindowActive()})
	default:
		apiError(w, http.StatusBadRequest, "unsupported update-window action", nil)
	}
}
