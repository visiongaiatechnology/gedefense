package main

import (
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

const xdrRecoveryConfirmation = "ARCHIVE_AND_REINITIALIZE_XDR"

func (s *APIServer) xdrIntegrityStatus(w http.ResponseWriter, _ *http.Request) {
	if s.xdr == nil {
		apiError(w, http.StatusServiceUnavailable, "XDR integrity service unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.xdr.IncidentIntegrityReport())
}

func (s *APIServer) xdrIntegrityVerify(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		apiError(w, http.StatusServiceUnavailable, "XDR integrity service unavailable", nil)
		return
	}
	var input struct{}
	if err := decodeStrictJSON(w, r, 256, &input); err != nil {
		apiError(w, http.StatusBadRequest, "invalid verification request", err)
		return
	}
	report, err := s.xdr.VerifyIncidentIntegrity(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, report)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type xdrRecoveryRequest struct {
	Action       string `json:"action"`
	Confirmation string `json:"confirmation"`
	Reason       string `json:"reason"`
}

func (s *APIServer) xdrRecovery(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		apiError(w, http.StatusServiceUnavailable, "XDR recovery service unavailable", nil)
		return
	}
	var input xdrRecoveryRequest
	if err := decodeStrictJSON(w, r, 4<<10, &input); err != nil {
		apiError(w, http.StatusBadRequest, "invalid XDR recovery request", err)
		return
	}
	if input.Action != "archive_and_reinitialize" || input.Confirmation != xdrRecoveryConfirmation {
		apiError(w, http.StatusBadRequest, "invalid XDR recovery confirmation", nil)
		return
	}
	reason := strings.TrimSpace(input.Reason)
	if !validRecoveryReason(reason) {
		apiError(w, http.StatusBadRequest, "recovery reason must contain 8 to 240 printable characters", nil)
		return
	}
	result, err := s.xdr.RecoverIncidentLedger(r.Context(), reason)
	if err != nil {
		switch {
		case errors.Is(err, errIncidentRecoveryNotRequired):
			apiError(w, http.StatusConflict, "XDR recovery is not required", err)
		case errors.Is(err, errIncidentRecoveryNotAllowed):
			apiError(w, http.StatusConflict, "XDR recovery is not permitted in the current integrity state", err)
		default:
			apiError(w, http.StatusConflict, "XDR recovery could not be completed", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func validRecoveryReason(reason string) bool {
	if !utf8.ValidString(reason) {
		return false
	}
	length := utf8.RuneCountInString(reason)
	if length < 8 || length > 240 {
		return false
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
