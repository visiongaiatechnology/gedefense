package main

import (
	"encoding/json"
	"net/http"
)

type cmsUpdateRequest struct {
	Settings cmsSettings `json:"settings"`
}

func (s *APIServer) cmsStatus(w http.ResponseWriter, _ *http.Request) {
	if s.cms == nil {
		apiError(w, http.StatusServiceUnavailable, "CMS defense engine unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.cms.Status())
}

func (s *APIServer) cmsUpdate(w http.ResponseWriter, r *http.Request) {
	if s.cms == nil {
		apiError(w, http.StatusServiceUnavailable, "CMS defense engine unavailable", nil)
		return
	}
	var request cmsUpdateRequest
	if err := decodeStrictJSON(w, r, 32<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "CMS settings rejected", err)
		return
	}
	if err := s.cms.UpdateSettings(request.Settings); err != nil {
		apiError(w, http.StatusConflict, "CMS settings could not be persisted", err)
		return
	}
	writeJSON(w, http.StatusOK, s.cms.Status())
}

func (s *APIServer) cmsRotateBridgeKey(w http.ResponseWriter, _ *http.Request) {
	if s.cms == nil {
		apiError(w, http.StatusServiceUnavailable, "CMS defense engine unavailable", nil)
		return
	}
	secret, err := s.cms.rotateBridgeKey()
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "CMS bridge key could not be rotated", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"fingerprint": s.cms.bridgeFingerprint(),
	})
}

func (s *APIServer) cmsRevokeLeases(w http.ResponseWriter, _ *http.Request) {
	if s.cms == nil {
		apiError(w, http.StatusServiceUnavailable, "CMS defense engine unavailable", nil)
		return
	}
	count := s.cms.RevokeLeases()
	writeJSON(w, http.StatusOK, map[string]any{"revoked": count, "status": s.cms.Status()})
}

// Keep json imported for future response envelopes without inventing a second
// decoder path; the handlers above all use the shared strict decoder.
var _ = json.Valid
