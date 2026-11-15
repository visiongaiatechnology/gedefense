// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3: the operator API of the Emergency Lockdown.
//
//   GET  /api/v1/lockdown/status   read-only, bounded, secret-free
//   POST /api/v1/lockdown/arm      {mode: locked|unlocked, reason}
//   POST /api/v1/lockdown/trigger  {confirmation: "TRIGGER LOCKDOWN", reason, source?}
//   POST /api/v1/lockdown/clear    {confirmation: "CLEAR:LOCKDOWN", reason, expected_epoch}
//
// Every route goes through s.auth, which already supplies the bearer check, the
// authenticated rate budget, the replay guard and the mandatory
// operator.mutation.intent evidence record. The two emergency routes are
// exempted from the evidence *gate* (server.go): the gate exists so no mutation
// is accepted without an audit record, and a condition that makes the ledger
// unavailable must not also make it impossible to isolate or release the host.
// Both handlers still commit their own intent evidence first.

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// LockdownAPIReason is the bounded reason every mutating route requires. It is
// human intent, never an authority: the bearer token remains the authority.
type LockdownAPIReason struct {
	Reason string `json:"reason"`
}

type lockdownArmRequest struct {
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
}

type lockdownTriggerRequest struct {
	Confirmation string `json:"confirmation"`
	Reason       string `json:"reason"`
	Source       string `json:"source"`
}

type lockdownClearRequest struct {
	Confirmation  string `json:"confirmation"`
	Reason        string `json:"reason"`
	ExpectedEpoch string `json:"expected_epoch"`
}

// AttachLockdown wires the engine into the API server and the status snapshot.
func (s *APIServer) AttachLockdown(engine *LockdownEngine) {
	s.lockdown = engine
}

// bootTrustVerdict is the provider the lockdown engine polls every 60 s. It is
// the same bounded collector the /api/v1/boot-trust endpoint renders.
func (s *APIServer) bootTrustVerdict() (string, string) {
	if s.bootTrust == nil {
		return "", ""
	}
	report := s.bootTrust.Collect()
	return report.Status, report.Summary
}

// lockdownStatus serves GET /api/v1/lockdown/status: the read-only, bounded
// projection. It performs no core or helper I/O and carries no secret.
func (s *APIServer) lockdownStatus(w http.ResponseWriter, _ *http.Request) {
	if s.lockdown == nil {
		writeJSON(w, http.StatusOK, LockdownStatusView{
			Enabled: false, State: "unavailable", Phases: []LockdownPhaseView{},
			Evidence: "unavailable",
			Degraded: "no lockdown engine is wired into this control plane",
		})
		return
	}
	view := s.lockdown.StatusView()
	if s.settings != nil {
		// The persisted revision is authoritative for the settings summary even in
		// the short window before the engine observes a change.
		view.Settings = lockdownSettingsView(effectiveLockdownSettings(s.settings.Get()))
	}
	writeJSON(w, http.StatusOK, view)
}

// lockdownArm serves POST /api/v1/lockdown/arm.
func (s *APIServer) lockdownArm(w http.ResponseWriter, r *http.Request) {
	if s.lockdown == nil {
		writePublicError(w, http.StatusServiceUnavailable, "no lockdown engine is wired into this control plane")
		return
	}
	var in lockdownArmRequest
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		writePublicError(w, http.StatusBadRequest, "invalid lockdown arm request")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	if _, err := lockdownModeToken(mode); err != nil {
		writePublicError(w, http.StatusBadRequest, "lockdown mode must be locked or unlocked")
		return
	}
	reason, err := lockdownAPIReason(in.Reason)
	if err != nil {
		writePublicError(w, http.StatusBadRequest, err.Error())
		return
	}
	view, err := s.lockdown.Arm(mode, lockdownReasonManual, reason, r.Header.Get("X-VGT-Request-ID"))
	if err != nil {
		lockdownAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"armed": true, "lockdown": view})
}

// lockdownTrigger serves POST /api/v1/lockdown/trigger. The phrase proves
// intent, not authority; the replay guard from s.auth and the 1/min budget make
// an accidental double click harmless.
func (s *APIServer) lockdownTrigger(w http.ResponseWriter, r *http.Request) {
	if s.lockdown == nil {
		writePublicError(w, http.StatusServiceUnavailable, "no lockdown engine is wired into this control plane")
		return
	}
	var in lockdownTriggerRequest
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		writePublicError(w, http.StatusBadRequest, "invalid lockdown trigger request")
		return
	}
	if strings.TrimSpace(in.Confirmation) != lockdownConfirmationTrigger {
		// A wrong phrase is an authority-shaped mistake, not a malformed body: it
		// is refused with 403 and never treated as a secret.
		writePublicError(w, http.StatusForbidden, "confirmation phrase does not match")
		return
	}
	reason, err := lockdownAPIReason(in.Reason)
	if err != nil {
		writePublicError(w, http.StatusBadRequest, err.Error())
		return
	}
	source := strings.ToLower(strings.TrimSpace(in.Source))
	if source == "" {
		source = lockdownSourceManual
	}
	if _, err := lockdownSourceToken(source); err != nil {
		writePublicError(w, http.StatusBadRequest, "lockdown source is not in the closed vocabulary")
		return
	}
	s.ensureLimiters()
	if !s.lockdownLimiter.Allow(s.authenticatedRateIdentity(r, currentBearer(r)), time.Now()) {
		w.Header().Set("Retry-After", "60")
		writePublicError(w, http.StatusTooManyRequests, "lockdown trigger rate limit exceeded (at most one per minute)")
		return
	}
	view, err := s.lockdown.Trigger(lockdownTriggerCandidate{
		Source: source, Reason: lockdownReasonManual, Operator: true,
		Fingerprint: lockdownFingerprint("operator", reason, r.Header.Get("X-VGT-Request-ID")),
		ReasonText:  reason,
	})
	if err != nil {
		lockdownAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": true,
		"latched":  view.Latched,
		"lockdown": view,
	})
}

// lockdownClear serves POST /api/v1/lockdown/clear. It is the only way out of
// the latch and requires the exact epoch the engine reports.
func (s *APIServer) lockdownClear(w http.ResponseWriter, r *http.Request) {
	if s.lockdown == nil {
		writePublicError(w, http.StatusServiceUnavailable, "no lockdown engine is wired into this control plane")
		return
	}
	var in lockdownClearRequest
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		writePublicError(w, http.StatusBadRequest, "invalid lockdown clear request")
		return
	}
	if strings.TrimSpace(in.Confirmation) != lockdownConfirmationClear {
		writePublicError(w, http.StatusForbidden, "confirmation phrase does not match")
		return
	}
	epoch := strings.ToLower(strings.TrimSpace(in.ExpectedEpoch))
	if !validLockdownEpoch(epoch) {
		writePublicError(w, http.StatusBadRequest, "expected_epoch must be the 8 hex characters reported by the status endpoint")
		return
	}
	reason, err := lockdownAPIReason(in.Reason)
	if err != nil {
		writePublicError(w, http.StatusBadRequest, err.Error())
		return
	}
	view, err := s.lockdown.Clear(epoch, lockdownReasonManual, reason, r.Header.Get("X-VGT-Request-ID"))
	if err != nil {
		lockdownAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true, "lockdown": view})
}

// lockdownAPIReason bounds the operator reason: 8..240 runes, single line. The
// same window is used by the engine so the API cannot accept text the engine
// would then have to truncate.
func lockdownAPIReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	if len([]rune(reason)) < lockdownMinTriggerReasonLen {
		return "", errors.New("a reason of at least 8 characters is required")
	}
	if len([]rune(reason)) > lockdownMaxTriggerReasonLen {
		return "", errors.New("the reason must not exceed 240 characters")
	}
	if strings.ContainsAny(reason, "\r\n\x00") {
		return "", errors.New("the reason must be a single line without control characters")
	}
	return reason, nil
}

// currentBearer returns the credential a request authenticated with. It is only
// used to key the dedicated trigger budget on the same identity as the global
// authenticated budget.
func currentBearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// lockdownAPIError maps the engine error vocabulary onto HTTP without widening
// a failure into an enforcement claim. Only documented operator messages cross
// the disclosure boundary.
func lockdownAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errLockdownDisabled):
		writePublicError(w, http.StatusConflict, "lockdown is disabled by the runtime settings (enabled=false)")
	case errors.Is(err, errLockdownLatched):
		writePublicError(w, http.StatusConflict, "lockdown is latched; an authenticated clear with the matching epoch is required")
	case errors.Is(err, errLockdownNotLatched):
		writePublicError(w, http.StatusConflict, "no lockdown is in force")
	case errors.Is(err, errLockdownBusy):
		writePublicError(w, http.StatusConflict, "lockdown is transitioning; retry when the phase set is settled")
	case errors.Is(err, errLockdownEpochMismatch):
		w.Header().Set("X-Lockdown-Conflict", "epoch")
		writePublicError(w, http.StatusConflict, "lockdown epoch mismatch; the engine remains latched and the status endpoint reports the epoch in force")
	case errors.Is(err, errLockdownCooldown):
		writePublicError(w, http.StatusTooManyRequests, "automatic lockdown trigger is cooling down")
	case errors.Is(err, errLockdownSourcesPending):
		writePublicError(w, http.StatusConflict, "lockdown requires additional distinct trigger sources before it can latch")
	case errors.Is(err, errLockdownCoreUnavailable):
		writePublicError(w, http.StatusServiceUnavailable, "kernel core is unavailable; the lockdown command was not confirmed")
	case errors.Is(err, errLockdownCapabilityMiss):
		writePublicError(w, http.StatusServiceUnavailable, "kernel core does not implement the lockdown command family")
	default:
		writePublicError(w, http.StatusInternalServerError, "lockdown operation failed")
	}
}
