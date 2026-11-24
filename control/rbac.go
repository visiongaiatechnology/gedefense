// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (R6): the server-side role enforcement of the management API.
//
// The enforcement is applied inside the existing authentication middleware
// (`s.auth`), so every route keeps its exact registration, order and evidence
// gate. A request is classified from the credential it presents:
//
//   - the existing dashboard bearer is the Operator role, which satisfies every
//     non-critical route exactly as before;
//   - the optional adjacent observer credential is the Observer role and is
//     accepted for GET/HEAD only;
//   - the critical class (AP-7 quarantine prune and review ack/delete) is refused
//     until a fresh, single-use step-up proof is presented - from the direct
//     loopback path or as a gateway-signed role claim.
//
// Nothing here trusts a header for authority: the gateway claim is MAC-verified
// over the backend credential, the direct proof is HMAC-verified over the
// dedicated key file, and both are bounded in TTL and replay.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// classifyCredential derives the role a presented bearer credential carries. The
// operator credential is checked first, so the existing behaviour and its
// rotation semantics are untouched; the observer credential is only consulted
// for a token that is not the operator token.
func (s *APIServer) classifyCredential(token string) (Role, bool) {
	if token == "" {
		return RoleObserver, false
	}
	if operatorToken := s.currentToken(); operatorToken != "" && tokenEqual(token, operatorToken) {
		return RoleOperator, true
	}
	if observerToken, err := s.observerToken(); err == nil && observerToken != "" && tokenEqual(token, observerToken) {
		return RoleObserver, true
	}
	return RoleObserver, false
}

// enforceManagementRole applies the method rule and the critical-action rule to
// one authenticated request. A false return means the response was already
// written; the caller must not run the handler.
func (s *APIServer) enforceManagementRole(w http.ResponseWriter, r *http.Request, role Role, operatorToken string) bool {
	if role < RoleOperator && r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.reportRBACEventOnce("observer-mutation:"+rbacRemoteFingerprint(r.RemoteAddr), "warning", "rbac.denied",
			"A read-only observer credential attempted a mutating management request; the request was refused")
		writeRBACRefusal(w, http.StatusForbidden, "the presented role does not permit this action")
		return false
	}
	if _, critical := criticalManagementAction(r.Method, r.URL.Path); !critical {
		return true
	}
	return s.enforceCriticalAction(w, r, operatorToken)
}

// enforceCriticalAction is the Critical-Unlock gate. The lockout check happens
// first so a source that keeps presenting invalid proofs cannot keep probing;
// a successful proof clears the source's failure history.
func (s *APIServer) enforceCriticalAction(w http.ResponseWriter, r *http.Request, operatorToken string) bool {
	now := s.rbacClock()
	remote := remoteIdentity(r.RemoteAddr)
	lock := s.stepUpLockout()
	if locked, retryAfter := lock.locked(remote); locked {
		w.Header().Set("Retry-After", retryAfterSeconds(retryAfter))
		writeRBACRefusal(w, http.StatusTooManyRequests, "critical unlock is temporarily locked after repeated failures")
		return false
	}
	failure := s.authorizeCriticalAction(r, operatorToken, now)
	if failure == nil {
		lock.success(remote)
		return true
	}
	if failure.unavailable {
		writeRBACRefusal(w, http.StatusServiceUnavailable, "critical unlock is not available on this host")
		return false
	}
	locked, retryAfter, fresh := lock.fail(remote)
	if fresh {
		s.reportRBACEvent("warning", "rbac.lockout",
			"Critical-unlock verification locked out a source after repeated invalid step-up proofs")
	}
	s.reportRBACEventOnce("critical-denied:"+rbacRemoteFingerprint(r.RemoteAddr), "warning", "rbac.denied",
		"A destructive management action was refused: no valid critical step-up proof or gateway claim was presented")
	// The attempt that reaches the threshold is still answered with the ordinary
	// refusal; only later attempts see the lockout status.
	if locked && !fresh {
		w.Header().Set("Retry-After", retryAfterSeconds(retryAfter))
		writeRBACRefusal(w, http.StatusTooManyRequests, "critical unlock is temporarily locked after repeated failures")
		return false
	}
	writeRBACRefusal(w, http.StatusForbidden, "critical unlock required")
	return false
}

// authorizeCriticalAction verifies exactly one of the two step-up paths. The
// paths are mutually exclusive: a gateway-proxied request may only use the
// gateway claim, and a direct request may only use the direct proof.
func (s *APIServer) authorizeCriticalAction(r *http.Request, operatorToken string, now time.Time) *criticalAuthFailure {
	if r == nil {
		return &criticalAuthFailure{reason: "missing request"}
	}
	if !remoteIsLoopback(r.RemoteAddr) {
		// The control plane is loopback-only by configuration; this is the second
		// line of defence for the two transport proofs.
		return &criticalAuthFailure{reason: "critical action requires a loopback peer"}
	}
	if requestIsGatewayProxied(r) {
		_, failure := s.verifyGatewayCriticalClaim(r, operatorToken, now)
		if failure.reason == "" {
			return nil
		}
		return &failure
	}
	// The direct path needs the optional key file before anything else: without it
	// the capability is unavailable, which is an honest answer and not the same as
	// "a proof is required".
	key, err := s.criticalStepUpKey()
	if err != nil {
		return &criticalAuthFailure{reason: "critical step-up key is unavailable", unavailable: true}
	}
	defer zeroRBACBytes(key)
	proof := strings.TrimSpace(r.Header.Get(directStepUpHeader))
	if proof == "" {
		return &criticalAuthFailure{reason: "step-up proof is required"}
	}
	if _, err := verifyCriticalStepUpProof(proof, key, now, s.directStepUpReplays()); err != nil {
		if errors.Is(err, errCriticalUnavailable) {
			return &criticalAuthFailure{reason: "critical step-up key is unavailable", unavailable: true}
		}
		return &criticalAuthFailure{reason: "step-up proof was rejected"}
	}
	return nil
}

// requireRole states a minimum role at the registration site. The existing route
// table is enforced inside s.auth so that no existing registration had to change;
// this wrapper is the explicit per-route form used by the new auth routes and
// available for a future route whose requirement should be visible where it is
// registered.
func (s *APIServer) requireRole(min Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if RoleFromRequest(r) < min {
			s.reportRBACEventOnce("role-required:"+min.String(), "warning", "rbac.denied",
				"A management request was refused because the presented role is below the route's minimum")
			writeRBACRefusal(w, http.StatusForbidden, "the presented role does not permit this action")
			return
		}
		next(w, r)
	}
}

// writeRBACRefusal answers a refused role or step-up check with a stable, opaque
// message. The detail stays in the typed failure and the bounded event.
func writeRBACRefusal(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func retryAfterSeconds(d time.Duration) string {
	seconds := int(d / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

// rbacRemoteFingerprint names a source in a bounded event without writing the
// source address into it. Eight hex characters distinguish two sources.
func rbacRemoteFingerprint(remoteAddr string) string {
	sum := sha256.Sum256([]byte(remoteIdentity(remoteAddr)))
	return hex.EncodeToString(sum[:4])
}

// ------------------------------------------------------------ management routes

// authRoles reports the roles this process actually offers and the requirements a
// client has to meet. It is read-only, bounded and carries no credential material.
func (s *APIServer) authRoles(w http.ResponseWriter, r *http.Request) {
	s.writeRBACRoles(w, RoleFromRequest(r))
}

// writeRBACRoles renders the role matrix for the authenticated caller.
func (s *APIServer) writeRBACRoles(w http.ResponseWriter, role Role) {
	observerAvailable := false
	if token, err := s.observerToken(); err == nil && token != "" {
		observerAvailable = true
	}
	criticalAvailable := false
	reasons := make([]string, 0, 2)
	if key, err := s.criticalStepUpKey(); err == nil && len(key) >= criticalKeyMinBytes {
		criticalAvailable = true
	} else {
		reasons = append(reasons, "the optional critical step-up key file is not provisioned")
	}
	if !observerAvailable {
		reasons = append(reasons, "the optional observer credential file is not provisioned")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"role": role.String(),
		"roles": map[string]any{
			"observer": map[string]any{
				"available": observerAvailable,
				"permits":   "GET and HEAD on every management route",
			},
			"operator": map[string]any{
				"available": true,
				"permits":   "every non-critical management route (policy and actions)",
			},
			"critical_unlock": map[string]any{
				"available": criticalAvailable,
				"permits":   "quarantine prune, review acknowledgement and review deletion",
				"step_up":   "a fresh, single-use proof: direct loopback token or gateway password re-authentication claim",
			},
		},
		"critical_actions": []string{
			"POST /api/v1/quarantine/prune",
			"POST /api/v1/xdr/review/{id}/ack",
			"DELETE /api/v1/xdr/review/{id}",
		},
		"step_up": map[string]any{
			"direct_ttl_seconds":           int(criticalStepUpTTL.Seconds()),
			"direct_max_ttl_seconds":       int(criticalStepUpMaxTTL.Seconds()),
			"gateway_claim_window_seconds": int(gatewayClaimWindow.Seconds()),
			"direct_header":                directStepUpHeader,
			"gateway_headers":              []string{gatewayRoleHeader, gatewayStepUpHeader, gatewayClaimTsHeader, gatewayClaimMACHeader},
		},
		"unavailable_reasons": reasons,
	})
}

// authStepUp mints one direct-loopback critical step-up proof.
//
// It is deliberately not available to a request that came through the gateway:
// a browser session must re-authenticate its password at the gateway, so
// proxying this mint would let a session escalate without the password. The
// gateway sets its trust marker on every proxied request, and a browser cannot
// remove it.
func (s *APIServer) authStepUp(w http.ResponseWriter, r *http.Request) {
	if requestIsGatewayProxied(r) {
		writeRBACRefusal(w, http.StatusForbidden, "browser sessions must use the gateway step-up flow")
		return
	}
	if !remoteIsLoopback(r.RemoteAddr) {
		writeRBACRefusal(w, http.StatusForbidden, "the direct step-up flow requires a loopback peer")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var in struct {
		Purpose string `json:"purpose"`
	}
	if err := decoder.Decode(&in); err != nil {
		writeRBACRefusal(w, http.StatusBadRequest, "request rejected")
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeRBACRefusal(w, http.StatusBadRequest, "request rejected")
		return
	}
	if strings.TrimSpace(in.Purpose) != criticalStepUpPurpose {
		writeRBACRefusal(w, http.StatusBadRequest, "step-up purpose is not accepted")
		return
	}
	key, err := s.criticalStepUpKey()
	if err != nil {
		writeRBACRefusal(w, http.StatusServiceUnavailable, "critical unlock is not available on this host")
		return
	}
	defer zeroRBACBytes(key)
	now := s.rbacClock()
	proof, token, err := issueCriticalStepUpProof(key, now)
	if err != nil {
		writeRBACRefusal(w, http.StatusServiceUnavailable, "critical unlock is not available on this host")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	s.reportRBACEvent("info", "rbac.step_up_issued",
		"A direct loopback critical step-up proof was issued (purpose=critical, ttl bounded)")
	writeJSON(w, http.StatusOK, map[string]any{
		"step_up":     token,
		"purpose":     criticalStepUpPurpose,
		"expires_at":  proof.ExpiresAt.UTC().Format(time.RFC3339),
		"ttl_seconds": int(criticalStepUpTTL.Seconds()),
	})
}

func zeroRBACBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
