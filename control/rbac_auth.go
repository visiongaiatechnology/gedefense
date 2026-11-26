// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (R6): the credential machinery behind the management-API role
// model.
//
// Three claims are proven here and nowhere else:
//
//   1. which role a presented bearer credential carries (operator = the existing
//      dashboard token, observer = the optional adjacent credential file);
//   2. that a direct loopback step-up proof is authentic, fresh and unused;
//   3. that a gateway role claim was produced by the gateway over the backend
//      credential, is fresh and is not a replay.
//
// Every refusal is returned as a typed value; no verification function logs, writes
// or dereferences client-controlled state. The bounded brute-force guards live in
// rbac_guard.go because both the credential check and the step-up check share the
// same bound instead of each inventing one.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	errObserverUnavailable     = errors.New("observer credential is not provisioned")
	errCriticalUnavailable     = errors.New("critical step-up key is not provisioned")
	errGatewayClaimUnavailable = errors.New("gateway critical claim key is not provisioned")
)

// readRBACCredentialFile reads one adjacent credential file under the same
// strict policy the dashboard token uses: a regular, non-symlink file owned by
// the control-plane account (or root) with exactly owner-only permissions. The
// mode is what makes a credential path a trust decision, so it is enforced on
// every use - a file that becomes group-readable stops being a credential
// immediately, without a restart.
func readRBACCredentialFile(path string, minBytes, maxBytes int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("credential path is empty")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("credential path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("credential must be a regular non-symlink file")
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		return nil, fmt.Errorf("credential permissions are %#o, must be 0600", perm)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		owner := int(stat.Uid)
		if euid := os.Geteuid(); euid != 0 && owner != euid && owner != 0 {
			return nil, errors.New("credential must be owned by the control-plane account or root")
		}
	}
	if info.Size() < int64(minBytes) || info.Size() > int64(maxBytes) {
		return nil, errors.New("credential size is outside its bound")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < minBytes || len(raw) > maxBytes {
		return nil, errors.New("credential size is outside its bound")
	}
	return raw, nil
}

// adjacentCredentialPath derives a convention-based credential location from the
// existing dashboard token path. There is no configuration schema addition: if
// an operator wants an observer role, the file simply exists next to the token.
func (s *APIServer) adjacentCredentialPath(suffix string) (string, error) {
	if s == nil {
		return "", errors.New("server is unavailable")
	}
	base := strings.TrimSpace(s.cfg.Dashboard.TokenFile)
	if base == "" {
		return "", errObserverUnavailable
	}
	if !filepath.IsAbs(base) {
		return "", errors.New("dashboard token path must be absolute")
	}
	bounded := base + suffix
	if len(bounded) > rbacCredentialMaxBytes {
		return "", errors.New("adjacent credential path is oversized")
	}
	return bounded, nil
}

// observerToken returns the validated observer credential, or an error that
// states honestly why the role is unavailable. Absence is the normal, documented
// state and grants nothing.
func (s *APIServer) observerToken() (string, error) {
	path, err := s.adjacentCredentialPath(observerTokenSuffix)
	if err != nil {
		return "", err
	}
	raw, err := readRBACCredentialFile(path, 1, rbacCredentialMaxBytes)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.reportRBACEventOnce("observer-file:"+filepath.Base(path), "warning", "rbac.credential_rejected",
				"The optional observer credential file is present but does not meet the private-file policy; the observer role stays unavailable")
		}
		return "", fmt.Errorf("%w: %v", errObserverUnavailable, err)
	}
	token := strings.TrimSpace(string(raw))
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(token)
	if decodeErr != nil || len(decoded) != observerTokenRawBytes {
		s.reportRBACEventOnce("observer-token:"+filepath.Base(path), "warning", "rbac.credential_rejected",
			"The optional observer credential does not encode the required 256-bit token form; the observer role stays unavailable")
		return "", fmt.Errorf("%w: observer token is not 256 bits", errObserverUnavailable)
	}
	return token, nil
}

// criticalStepUpKey returns the HMAC key of the direct step-up path. Without the
// file the critical role is simply unavailable for direct loopback clients, which
// is an honest fact and not a silent fallback to an operator-only check.
func (s *APIServer) criticalStepUpKey() ([]byte, error) {
	path, err := s.adjacentCredentialPath(criticalKeySuffix)
	if err != nil {
		if errors.Is(err, errObserverUnavailable) {
			return nil, errCriticalUnavailable
		}
		return nil, err
	}
	raw, err := readRBACCredentialFile(path, criticalKeyMinBytes, rbacCredentialMaxBytes)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.reportRBACEventOnce("critical-key:"+filepath.Base(path), "warning", "rbac.credential_rejected",
				"The optional critical step-up key file is present but does not meet the private-file policy; the critical role stays unavailable")
		}
		return nil, fmt.Errorf("%w: %v", errCriticalUnavailable, err)
	}
	key := append([]byte(nil), raw...)
	return key, nil
}

// gatewayClaimKey returns the dedicated HMAC key shared strictly between the
// access gateway and the control plane for authenticating gateway role claims.
// It is kept separate from both the dashboard bearer token and the direct
// critical step-up key.
func (s *APIServer) gatewayClaimKey() ([]byte, error) {
	path, err := s.adjacentCredentialPath(gatewayClaimKeySuffix)
	if err != nil {
		if errors.Is(err, errObserverUnavailable) {
			return nil, errGatewayClaimUnavailable
		}
		return nil, err
	}
	raw, err := readRBACCredentialFile(path, criticalKeyMinBytes, rbacCredentialMaxBytes)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.reportRBACEventOnce("gateway-claim-key:"+filepath.Base(path), "warning", "rbac.credential_rejected",
				"The optional gateway claim key file is present but does not meet the private-file policy; gateway critical unlock stays unavailable")
		}
		return nil, fmt.Errorf("%w: %v", errGatewayClaimUnavailable, err)
	}
	key := append([]byte(nil), raw...)
	return key, nil
}

// rbacClock is the injectable clock of the role subsystem. Production uses
// time.Now, whose readings carry the monotonic clock.
func (s *APIServer) rbacClock() time.Time {
	if s != nil && s.rbacNow != nil {
		return s.rbacNow()
	}
	return time.Now()
}

// ensureRBACGuards lazily creates the bounded guards so a server built as a
// struct literal (several tests and some tooling do) keeps working unchanged.
func (s *APIServer) ensureRBACGuards() {
	s.rbacOnce.Do(func() {
		clock := func() time.Time { return s.rbacClock() }
		s.tokenAuthLockout = newAttemptLockout(authLockoutFailureLimit, authLockoutFailureWindow, authLockoutDuration, clock)
		s.stepUpAuthLockout = newAttemptLockout(authLockoutFailureLimit, authLockoutFailureWindow, authLockoutDuration, clock)
		s.directStepUpNonces = newNonceReplayCache(nonceReplayCacheMaxEntries)
		s.gatewayClaimNonces = newNonceReplayCache(nonceReplayCacheMaxEntries)
		s.rbacReported = make(map[string]time.Time)
	})
}

func (s *APIServer) tokenLockout() *attemptLockout {
	s.ensureRBACGuards()
	return s.tokenAuthLockout
}

func (s *APIServer) stepUpLockout() *attemptLockout {
	s.ensureRBACGuards()
	return s.stepUpAuthLockout
}

func (s *APIServer) directStepUpReplays() *nonceReplayCache {
	s.ensureRBACGuards()
	return s.directStepUpNonces
}

func (s *APIServer) gatewayClaimReplays() *nonceReplayCache {
	s.ensureRBACGuards()
	return s.gatewayClaimNonces
}

// reportRBACEvent writes one bounded operator event. The message never carries a
// credential, a MAC, a nonce or a path; events are the audit trail, not a secret
// store.
func (s *APIServer) reportRBACEvent(severity, kind, message string) {
	if s == nil {
		return
	}
	message = rbacBoundedText(message, 240)
	if s.state == nil {
		log.Printf("rbac event kind=%q severity=%q message=%q", kind, severity, message)
		return
	}
	s.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "access-gateway", Message: message})
}

// reportRBACEventOnce bounds a repeated condition to one event per cooldown. The
// condition itself is never suppressed - only the record of it.
func (s *APIServer) reportRBACEventOnce(key, severity, kind, message string) bool {
	if s == nil {
		return false
	}
	s.ensureRBACGuards()
	now := s.rbacClock()
	s.rbacMu.Lock()
	if last, ok := s.rbacReported[key]; ok && now.Sub(last) < rbacEventCooldown {
		s.rbacMu.Unlock()
		return false
	}
	if len(s.rbacReported) > 256 {
		for existing, at := range s.rbacReported {
			if now.Sub(at) > 2*rbacEventCooldown {
				delete(s.rbacReported, existing)
			}
		}
	}
	s.rbacReported[key] = now
	s.rbacMu.Unlock()
	s.reportRBACEvent(severity, kind, message)
	return true
}

func rbacBoundedText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	if max <= 1 {
		return value[:max]
	}
	return value[:max-1] + "..."
}

// --------------------------------------------------------- direct step-up proof

// issueCriticalStepUpProof mints one short-lived, single-purpose direct proof.
func issueCriticalStepUpProof(key []byte, now time.Time) (criticalStepUpProof, string, error) {
	if len(key) < criticalKeyMinBytes {
		return criticalStepUpProof{}, "", errCriticalUnavailable
	}
	nonce, err := randomBytesHex(criticalStepUpNonceBytes)
	if err != nil {
		return criticalStepUpProof{}, "", errors.New("step-up nonce could not be generated")
	}
	expires := now.UTC().Add(criticalStepUpTTL)
	payload := directStepUpTokenHead + "|" + formatUnix(expires.Unix()) + "|" + nonce
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(criticalStepUpDomain))
	mac.Write([]byte(payload))
	token := payload + "|" + hex.EncodeToString(mac.Sum(nil))
	return criticalStepUpProof{Nonce: nonce, ExpiresAt: expires}, token, nil
}

// verifyCriticalStepUpProof checks authenticity, the bounded expiry and the
// single use of one direct proof. Errors are deliberately undifferentiated at the
// API boundary; the reason is only for the internal verdict.
func verifyCriticalStepUpProof(token string, key []byte, now time.Time, nonces *nonceReplayCache) (criticalStepUpProof, error) {
	if len(key) < criticalKeyMinBytes {
		return criticalStepUpProof{}, errCriticalUnavailable
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 256 {
		return criticalStepUpProof{}, errors.New("step-up proof is empty or oversized")
	}
	parts := strings.Split(token, "|")
	if len(parts) != 4 || parts[0] != directStepUpTokenHead {
		return criticalStepUpProof{}, errors.New("step-up proof has an unknown shape")
	}
	expires, err := parseBoundedUnix(parts[1])
	if err != nil {
		return criticalStepUpProof{}, errors.New("step-up proof expiry is not a timestamp")
	}
	nonce := parts[2]
	if !isLowerHex(nonce, 2*criticalStepUpNonceBytes, 2*criticalStepUpNonceBytes) {
		return criticalStepUpProof{}, errors.New("step-up proof nonce is malformed")
	}
	if !isLowerHex(parts[3], sha256.Size*2, sha256.Size*2) {
		return criticalStepUpProof{}, errors.New("step-up proof MAC is malformed")
	}
	expiry := time.Unix(expires, 0).UTC()
	if !now.UTC().Before(expiry) {
		return criticalStepUpProof{}, errors.New("step-up proof has expired")
	}
	if expiry.After(now.UTC().Add(criticalStepUpMaxTTL)) {
		return criticalStepUpProof{}, errors.New("step-up proof expiry is outside its bound")
	}
	payload := directStepUpTokenHead + "|" + parts[1] + "|" + nonce
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(criticalStepUpDomain))
	mac.Write([]byte(payload))
	want := mac.Sum(nil)
	got, decodeErr := hex.DecodeString(parts[3])
	if decodeErr != nil || !hmac.Equal(got, want) {
		return criticalStepUpProof{}, errors.New("step-up proof MAC does not verify")
	}
	if nonces == nil || !nonces.claim(nonce, expiry, now.UTC()) {
		return criticalStepUpProof{}, errors.New("step-up proof was already used")
	}
	return criticalStepUpProof{Nonce: nonce, ExpiresAt: expiry}, nil
}

// ------------------------------------------------------- gateway role claim

// gatewayClaimMAC is the exact MAC the gateway produces and the control plane
// verifies: HMAC-SHA256 over the domain-separated bytes
// role|step-up|timestamp|nonce using the dedicated gateway claim key.
func gatewayClaimMAC(claimKey []byte, role, stepUp string, timestamp int64, nonce string) []byte {
	mac := hmac.New(sha256.New, claimKey)
	mac.Write([]byte(gatewayClaimDomain))
	mac.Write([]byte(role + "|" + stepUp + "|" + formatUnix(timestamp) + "|" + nonce))
	return mac.Sum(nil)
}

// verifyGatewayCriticalClaim verifies the four gateway headers as one claimed
// fact. A missing, malformed, stale, forged or replayed claim is refused; there
// is no fallback to the direct proof path, so the two trust boundaries cannot be
// mixed.
func (s *APIServer) verifyGatewayCriticalClaim(r *http.Request, claimKey []byte, now time.Time) (gatewayCriticalClaim, criticalAuthFailure) {
	if r == nil {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "claim requires a request"}
	}
	if len(claimKey) < criticalKeyMinBytes {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "gateway claim key is unavailable", unavailable: true}
	}
	role := strings.TrimSpace(r.Header.Get(gatewayRoleHeader))
	stepUpValue := strings.TrimSpace(r.Header.Get(gatewayStepUpHeader))
	tsValue := strings.TrimSpace(r.Header.Get(gatewayClaimTsHeader))
	macValue := strings.TrimSpace(r.Header.Get(gatewayClaimMACHeader))
	if role != criticalStepUpPurpose || stepUpValue == "" || tsValue == "" || macValue == "" {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "claim is incomplete"}
	}
	method, nonce, ok := strings.Cut(stepUpValue, ":")
	if !ok || method != "password" || !isLowerHex(nonce, gatewayClaimMinNonceBytes, gatewayClaimMaxNonceBytes) {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "claim purpose is not accepted"}
	}
	timestamp, err := parseBoundedUnix(tsValue)
	if err != nil {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "claim timestamp is not a timestamp"}
	}
	skew := now.UTC().Unix() - timestamp
	if skew > int64(gatewayClaimWindow/time.Second) || -skew > int64(gatewayClaimWindow/time.Second) {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "claim timestamp is outside the accepted window"}
	}
	if !isLowerHex(macValue, sha256.Size*2, sha256.Size*2) {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "claim MAC is malformed"}
	}
	got, decodeErr := hex.DecodeString(macValue)
	want := gatewayClaimMAC(claimKey, role, method, timestamp, nonce)
	if decodeErr != nil || !hmac.Equal(got, want) {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "claim MAC does not verify"}
	}
	if !s.gatewayClaimReplays().claim(nonce, now.UTC().Add(gatewayClaimWindow+time.Minute), now.UTC()) {
		return gatewayCriticalClaim{}, criticalAuthFailure{reason: "claim nonce was already used"}
	}
	return gatewayCriticalClaim{Role: role, StepUp: method, Timestamp: timestamp, Nonce: nonce}, criticalAuthFailure{}
}
