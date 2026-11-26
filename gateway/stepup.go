// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (R6): gateway-side password step-up for critical management
// actions.
//
// A browser session is an operator session by construction - the only way a
// gateway session is created is a successful Argon2id password verification - but
// reaching the most destructive control-plane actions requires proving the
// password again, now. This file owns that proof:
//
//   - POST /gateway/step-up verifies the session, the same-origin requirement and
//     the operator password through the existing Argon2id verifier, then returns
//     one opaque, TTL-bounded, single-use proof;
//   - the browser presents that proof once on the critical request;
//   - protectedProxy consumes it, checks it against the server-side session, and
//     attaches the MACed role claim the control plane verifies.
//
// Brute-force protection is a fixed-window per-source lockout with a bounded
// table; it never locks a session that presents the correct password before the
// threshold. Responses never carry password material, the backend credential or
// the session id, and the failure text is deliberately undifferentiated.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// The step-up authority lives as long as the gateway process; the per-session
	// proof table is bounded and TTL-pruned.
	stepUpProofMaxTokenBytes = 128
)

type stepUpProofRecord struct {
	sessionID string
	expires   time.Time
}

// stepUpFailureWindow is the bounded brute-force state of one source.
type stepUpFailureWindow struct {
	failures    []time.Time
	lockedUntil time.Time
	lastSeen    time.Time
}

// stepUpAuthority owns the one-time proofs and the per-source lockout. Both
// tables are bounded; a full table evicts the oldest entry instead of failing
// closed for every new client (the same availability trade-off as the session
// registry).
type stepUpAuthority struct {
	mu            sync.Mutex
	proofs        map[string]stepUpProofRecord
	proofOrder    []string
	failures      map[string]*stepUpFailureWindow
	maxEntries    int
	maxSources    int
	failureLimit  int
	failureWindow time.Duration
	lockout       time.Duration
	now           func() time.Time
}

func newStepUpAuthority(now func() time.Time) *stepUpAuthority {
	if now == nil {
		now = time.Now
	}
	return &stepUpAuthority{
		proofs:        make(map[string]stepUpProofRecord),
		failures:      make(map[string]*stepUpFailureWindow),
		maxEntries:    gatewayStepUpAuthorityMaxEntries,
		maxSources:    gatewayStepUpAuthorityMaxSources,
		failureLimit:  gatewayStepUpFailureLimit,
		failureWindow: gatewayStepUpFailureWindow,
		lockout:       gatewayStepUpLockoutDuration,
		now:           now,
	}
}

// proofKey hashes a proof token. The table never stores the token itself, so a
// memory disclosure does not hand out live capabilities.
func proofKey(proof string) string {
	digest := sha256.Sum256([]byte(proof))
	return hex.EncodeToString(digest[:])
}

// issue mints one opaque, session-bound, single-use proof.
func (a *stepUpAuthority) issue(sessionID string) (string, time.Time, error) {
	if sessionID == "" {
		return "", time.Time{}, errors.New("a step-up proof requires a session")
	}
	token, err := randomLowerHex(gatewayStepUpProofTokenBytes)
	if err != nil {
		return "", time.Time{}, errors.New("a step-up proof could not be generated")
	}
	now := a.now()
	expires := now.Add(gatewayStepUpProofTTL)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(now)
	for len(a.proofs) >= a.maxEntries && len(a.proofOrder) > 0 {
		oldest := a.proofOrder[0]
		a.proofOrder = a.proofOrder[1:]
		delete(a.proofs, oldest)
	}
	key := proofKey(token)
	a.proofs[key] = stepUpProofRecord{sessionID: sessionID, expires: expires}
	a.proofOrder = append(a.proofOrder, key)
	return token, expires.UTC(), nil
}

// consume validates and burns one proof for exactly the session it was issued to.
// A proof is single use even when it is presented twice inside its TTL.
func (a *stepUpAuthority) consume(sessionID, proof string) bool {
	if sessionID == "" {
		return false
	}
	proof = strings.TrimSpace(proof)
	if proof == "" || len(proof) > stepUpProofMaxTokenBytes {
		return false
	}
	key := proofKey(proof)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.proofs[key]
	if !ok {
		return false
	}
	delete(a.proofs, key)
	if !now.Before(record.expires) {
		return false
	}
	return record.sessionID == sessionID
}

// locked reports whether a source is currently locked out.
func (a *stepUpAuthority) locked(source string) (bool, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	window, ok := a.failures[source]
	if !ok {
		return false, 0
	}
	now := a.now()
	if !window.lockedUntil.IsZero() && now.Before(window.lockedUntil) {
		return true, window.lockedUntil.Sub(now)
	}
	if !window.lockedUntil.IsZero() {
		delete(a.failures, source)
	}
	return false, 0
}

// fail records one failed password re-entry. It reports the retry-after the source
// now has to observe and whether this call is the transition into the lockout.
func (a *stepUpAuthority) fail(source string) (bool, time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	window, ok := a.failures[source]
	if !ok {
		if len(a.failures) >= a.maxSources {
			a.evictSourceLocked()
		}
		window = &stepUpFailureWindow{}
		a.failures[source] = window
	}
	window.lastSeen = now
	if !window.lockedUntil.IsZero() && now.Before(window.lockedUntil) {
		return true, window.lockedUntil.Sub(now), false
	}
	cutoff := now.Add(-a.failureWindow)
	kept := window.failures[:0]
	for _, stamp := range window.failures {
		if stamp.After(cutoff) {
			kept = append(kept, stamp)
		}
	}
	window.failures = append(kept, now)
	if len(window.failures) < a.failureLimit {
		return false, 0, false
	}
	window.failures = window.failures[:0]
	window.lockedUntil = now.Add(a.lockout)
	return true, a.lockout, true
}

// success clears the failure history of a source that proved the password.
func (a *stepUpAuthority) success(source string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.failures, source)
}

func (a *stepUpAuthority) evictSourceLocked() {
	var oldestKey string
	var oldest time.Time
	for source, window := range a.failures {
		reference := window.lastSeen
		if oldestKey == "" || reference.Before(oldest) {
			oldestKey, oldest = source, reference
		}
	}
	if oldestKey != "" {
		delete(a.failures, oldestKey)
	}
}

// pruneLocked drops expired proofs and stale failure windows. It is called on
// every issue, so the tables cannot grow with age.
func (a *stepUpAuthority) pruneLocked(now time.Time) {
	for key, record := range a.proofs {
		if !now.Before(record.expires) {
			delete(a.proofs, key)
		}
	}
	for source, window := range a.failures {
		if window.lockedUntil.IsZero() && now.Sub(window.lastSeen) > a.failureWindow {
			delete(a.failures, source)
		}
	}
}

// ensureStepUp lazily creates the authority so gateway literals in tests keep
// working unchanged.
func (g *gateway) ensureStepUp() {
	g.stepUpOnce.Do(func() {
		if g.stepUp == nil {
			g.stepUp = newStepUpAuthority(time.Now)
		}
	})
}

// stepUpRoute is POST /gateway/step-up.
func (g *gateway) stepUpRoute(w http.ResponseWriter, r *http.Request) {
	session, ok := g.validateSession(nil, r)
	if !ok {
		writeGatewayJSONError(w, http.StatusUnauthorized, "authorization required")
		return
	}
	// A password re-entry is a mutation: it must carry the exact public origin.
	if !g.sameOriginRequired(r) {
		writeGatewayJSONError(w, http.StatusForbidden, "origin rejected")
		return
	}
	if len(g.claimKey) < 32 {
		writeGatewayJSONError(w, http.StatusServiceUnavailable, "critical unlock claim key is unavailable on this host")
		return
	}
	g.ensureStepUp()
	source := clientIP(r.RemoteAddr)
	if locked, retryAfter := g.stepUp.locked(source); locked {
		w.Header().Set("Retry-After", gatewayRetryAfterSeconds(retryAfter))
		writeGatewayJSONError(w, http.StatusTooManyRequests, "step-up temporarily locked after repeated failures")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, gatewayStepUpBodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var in struct {
		Password string `json:"password"`
	}
	if err := decoder.Decode(&in); err != nil {
		writeGatewayJSONError(w, http.StatusBadRequest, "request rejected")
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeGatewayJSONError(w, http.StatusBadRequest, "request rejected")
		return
	}
	password := []byte(in.Password)
	in.Password = ""
	if len(password) < gatewayStepUpPasswordMinBytes || len(password) > gatewayStepUpPasswordMaxBytes {
		zero(password)
		writeGatewayJSONError(w, http.StatusBadRequest, "request rejected")
		return
	}
	verified, kdfErr := g.verifyPasswordGated(r.Context(), source, password)
	zero(password)
	if kdfErr != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(kdfErr, errKDFIdentityBusy) || errors.Is(kdfErr, errKDFOverloaded) {
			status = http.StatusTooManyRequests
		}
		w.Header().Set("Retry-After", "2")
		writeGatewayJSONError(w, status, "step-up verification capacity is saturated; retry shortly")
		return
	}
	if !verified {
		locked, retryAfter, fresh := g.stepUp.fail(source)
		if fresh {
			log.Printf("step-up lockout engaged source=%q", fingerprint(source))
		}
		g.reportAuthDenial(r, "operator password re-entry rejected for a critical step-up")
		// The attempt that reaches the threshold is answered as a rejection; only
		// later attempts see the lockout status.
		if locked && !fresh {
			w.Header().Set("Retry-After", gatewayRetryAfterSeconds(retryAfter))
			writeGatewayJSONError(w, http.StatusTooManyRequests, "step-up temporarily locked after repeated failures")
			return
		}
		writeGatewayJSONError(w, http.StatusUnauthorized, "password rejected")
		return
	}
	g.stepUp.success(source)
	proof, expires, err := g.stepUp.issue(session.id)
	if err != nil {
		writeGatewayJSONError(w, http.StatusServiceUnavailable, "a step-up proof could not be issued")
		return
	}
	log.Printf("gateway step-up issued session=%s", shortSessionID(session.id))
	writeGatewayJSON(w, http.StatusOK, map[string]any{
		"step_up_proof": proof,
		"purpose":       gatewayCriticalRole,
		"expires_at":    expires.UTC().Format(time.RFC3339),
		"ttl_seconds":   int(gatewayStepUpProofTTL.Seconds()),
	})
}

// criticalClaimForRequest processes the one-time proof on a critical request and
// returns the claim the proxy Director applies. handled=false means the request
// carries no proof and is forwarded without any elevation.
func (g *gateway) criticalClaimForRequest(w http.ResponseWriter, r *http.Request, session *gatewaySession) (gatewayCriticalClaimHeaders, bool) {
	proof := strings.TrimSpace(r.Header.Get(gatewayStepUpProofHeader))
	if proof == "" {
		return gatewayCriticalClaimHeaders{}, false
	}
	if session == nil || session.id == "" {
		writeGatewayJSONError(w, http.StatusUnauthorized, "authorization required")
		return gatewayCriticalClaimHeaders{}, true
	}
	g.ensureStepUp()
	if !g.stepUp.consume(session.id, proof) {
		// The proof is bound to this session, this TTL and a single use. The
		// reason is not disclosed beyond that.
		writeGatewayJSONError(w, http.StatusForbidden, "step-up proof is invalid, expired or already used")
		return gatewayCriticalClaimHeaders{}, true
	}
	claim, err := newGatewayCriticalClaim(g.claimKey, time.Now())
	if err != nil {
		writeGatewayJSONError(w, http.StatusServiceUnavailable, "a step-up claim could not be produced")
		return gatewayCriticalClaimHeaders{}, true
	}
	return claim, true
}
