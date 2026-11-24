// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// File-integrity, package-integrity and startup self-check handlers split out
// of server.go (refactoring wave 1a, structure-only). The mux registration stays
// in server.go.

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func (s *APIServer) fimStatus(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, engine.Status())
}

func (s *APIServer) fimScan(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	summary, err := engine.Scan()
	if err != nil {
		apiError(w, http.StatusConflict, "file integrity scan rejected", err)
		return
	}
	severity := "info"
	kind := "fim.verified"
	if summary.Tampered > 0 || summary.Missing > 0 || summary.New > 0 || summary.Errors > 0 {
		severity = "critical"
		kind = "fim.deviation"
	}
	s.state.AddEvent(Event{
		Severity: severity, Kind: kind, Source: "operator",
		Message: fmt.Sprintf(
			"Manual FIM scan: verified=%d tampered=%d missing=%d new=%d errors=%d",
			summary.Verified, summary.Tampered, summary.Missing, summary.New, summary.Errors,
		),
	})
	writeJSON(w, http.StatusOK, summary)
}

// startupStatus serves GET /api/v1/startup. Before the supervisor publishes its
// first report the endpoint answers 503: there is no honest status to serve yet,
// and a fabricated "all green" is exactly what the self-check exists to prevent.
func (s *APIServer) startupStatus(w http.ResponseWriter, _ *http.Request) {
	status, ok := CurrentStartupStatus()
	if !ok {
		apiError(w, http.StatusServiceUnavailable, "startup self-check has not published a report yet", nil)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// fimBaseline creates a new approved baseline.
//
// Two modes share the route because the dashboard and the post-update script are
// the same operator action at different scopes:
//
//   - no request body: the historical full baseline (every protected path). Kept
//     for compatibility with the existing console button.
//   - {"scope":"release","reason":"...","confirm":"REBASELINE RELEASE"}: the
//     authorized release rebaseline (fim_rebaseline.go). It only accepts files
//     below /opt/vgt/gedefense/current plus the deployed configuration file, and
//     only while the release gate is verified (enforce, fail-safe verified,
//     kernel policy verified, no emergency stop). Afterwards the Titan findings
//     covered by the new baseline are accepted (titan_rebaseline.go).
func (s *APIServer) fimBaseline(w http.ResponseWriter, r *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	if r.ContentLength == 0 {
		status, err := engine.CreateBaseline()
		if err != nil {
			apiError(w, http.StatusConflict, "file integrity baseline rejected", err)
			return
		}
		s.state.AddEvent(Event{
			Severity: "high", Kind: "fim.baseline_created", Source: "operator",
			Message: fmt.Sprintf(
				"Encrypted FIM baseline generation %d committed for %d protected files",
				status.Generation, status.BaselineCount,
			),
		})
		writeJSON(w, http.StatusOK, status)
		return
	}
	var request struct {
		Scope   string `json:"scope"`
		Reason  string `json:"reason"`
		Confirm string `json:"confirm"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid file integrity baseline request", err)
		return
	}
	if strings.TrimSpace(request.Scope) != fimRebaselineScopeRelease {
		writePublicError(w, http.StatusBadRequest, "unsupported file integrity baseline scope")
		return
	}
	if strings.TrimSpace(request.Confirm) != fimRebaselineConfirmPhrase {
		writePublicError(w, http.StatusBadRequest, "confirmation required: "+fimRebaselineConfirmPhrase)
		return
	}
	if s.release == nil {
		apiError(w, http.StatusServiceUnavailable, "release controller unavailable", nil)
		return
	}
	release := s.release.Status()
	authorization := FIMRebaselineAuthorization{
		Phase:             release.Phase,
		FailSafeVerified:  release.FailSafeVerified,
		KernelPolicyState: release.KernelPolicyState,
		EmergencyStop:     release.EmergencyStop,
		ReleaseVersion:    s.state.Snapshot().Version,
	}
	result, err := engine.RebaselineRelease(authorization, request.Reason)
	if err != nil {
		apiError(w, http.StatusConflict, "file integrity release rebaseline rejected", err)
		return
	}
	acceptance := TitanRebaselineAcceptance{}
	if titan := s.state.Titan(); titan != nil && len(result.TitanCandidatePaths) > 0 {
		accepted, acceptErr := titan.AcceptRebaselinedPaths(result.TitanCandidatePaths, request.Reason)
		if acceptErr != nil {
			// The FIM baseline is already committed and verified; Titan keeps its
			// findings open rather than closing them without evidence. The
			// operator sees the reason in the response and the journal.
			log.Printf("titan baseline acceptance after FIM rebaseline: %v", acceptErr)
		} else {
			acceptance = accepted
		}
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "fim.rebaseline.release", Source: "operator",
		Message: fmt.Sprintf("Authorized release rebaseline: %s; titan accepted=%d closed=%d deferred_compromised=%d",
			result.AuditSummary(), acceptance.ApprovedPaths, acceptance.ClosedFindings, acceptance.CompromisedDeferred),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "rebaselined",
		"fim":    result,
		"titan":  acceptance,
	})
}

func (s *APIServer) packageIntegrityStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.packages.Status())
}

func (s *APIServer) packageIntegrityScan(w http.ResponseWriter, _ *http.Request) {
	err := s.packages.Start(func(status PackageIntegrityStatus) {
		severity := "info"
		kind := "package_integrity.verified"
		message := fmt.Sprintf("Pacman package integrity verified: packages=%d files=%d verified=%d", status.Packages, status.Files, status.Verified)
		if status.Modified > 0 || status.Missing > 0 || status.Errors > 0 {
			severity = "critical"
			kind = "package_integrity.deviation"
			message = fmt.Sprintf(
				"Pacman package integrity deviation: modified=%d missing=%d errors=%d",
				status.Modified, status.Missing, status.Errors,
			)
		}
		s.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "package-integrity", Message: message})
	})
	if err != nil {
		apiError(w, http.StatusConflict, "package integrity scan rejected", err)
		return
	}
	writeJSON(w, http.StatusAccepted, s.packages.Status())
}
