// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (R6): the gateway side of the Critical-Unlock role claim.
//
// The gateway terminates TLS publicly and holds the backend credential. It is the
// only component that can turn a browser's password re-entry into a role claim for
// the control plane, and it must never elevate a request just because a client
// asked. The claim is therefore:
//
//   - produced only after the gateway re-verified the operator password through
//     the existing Argon2id verifier (gateway/stepup.go), and only for a session
//     that exists in the server-side registry;
//   - bound to a one-time proof token that the browser presents on exactly one
//     request; the gateway consumes it and the control plane additionally
//     replay-bounds the claim nonce;
//   - MACed with the backend credential over
//     `critical|password|<timestamp>|<nonce>` and bounded to a 30-second window.
//
// The exact header set is shared with the control plane's verifier; the MAC
// domain separator and the field order are the contract (docs/V6.3.0-RBAC.md).
// The two step-up trust paths never mix: a request the gateway forwards may only
// carry the gateway claim, never a direct control-plane proof.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	// The claim header set the control plane verifies.
	gatewayRoleHeader     = "X-VGT-Role"
	gatewayStepUpHeader   = "X-VGT-Step-Up"
	gatewayClaimTsHeader  = "X-VGT-Claim-Ts"
	gatewayClaimMACHeader = "X-VGT-Claim-MAC"
	// gatewayStepUpProofHeader carries the one-time proof from the browser to the
	// gateway. It is never forwarded to the control plane.
	gatewayStepUpProofHeader = "X-VGT-Step-Up-Proof"

	// gatewayCriticalRole and gatewayStepUpMethodPassword are the only values the
	// claim produces and the control plane accepts.
	gatewayCriticalRole         = "critical"
	gatewayStepUpMethodPassword = "password"

	// gatewayClaimDomain is the domain separator of the claim MAC. It must be
	// byte-identical to the control plane's gatewayClaimDomain.
	gatewayClaimDomain = "VGT-GEDEFENSE-GATEWAY-CRITICAL-CLAIM-V1\x00"
	// gatewayClaimWindow must not exceed the control plane's accepted window.
	gatewayClaimWindow = 30 * time.Second

	// The step-up proof lifetime and the bounded store limits.
	gatewayStepUpProofTTL            = 2 * time.Minute
	gatewayStepUpAuthorityMaxEntries = 256
	gatewayStepUpProofTokenBytes     = 24

	// gatewayStepUpFailureLimit failures inside gatewayStepUpFailureWindow lock the
	// source out for gatewayStepUpLockoutDuration.
	gatewayStepUpFailureLimit        = 5
	gatewayStepUpFailureWindow       = 15 * time.Minute
	gatewayStepUpLockoutDuration     = 5 * time.Minute
	gatewayStepUpAuthorityMaxSources = 4096

	// gatewayStepUpPasswordMinBytes matches the sign-in password policy.
	gatewayStepUpPasswordMinBytes = 12
	gatewayStepUpPasswordMaxBytes = 1024
	// gatewayStepUpBodyLimit bounds the re-authentication body.
	gatewayStepUpBodyLimit = 4096
)

// gatewayCriticalClaimHeaders is the verified claim the proxy Director applies to
// an outbound request.
type gatewayCriticalClaimHeaders struct {
	Role      string
	StepUp    string
	Timestamp int64
	MAC       string
}

// gatewayCriticalClaimKey is the request-context key of the verified claim.
type gatewayCriticalClaimKey struct{}

// gatewayCriticalClaimMAC is the exact MAC the control plane recomputes:
// HMAC-SHA256 over the domain-separated bytes role|step-up|timestamp|nonce with
// the dedicated gateway critical claim key.
func gatewayCriticalClaimMAC(claimKey []byte, role, stepUp string, timestamp int64, nonce string) []byte {
	mac := hmac.New(sha256.New, claimKey)
	mac.Write([]byte(gatewayClaimDomain))
	mac.Write([]byte(role + "|" + stepUp + "|" + formatGatewayUnix(timestamp) + "|" + nonce))
	return mac.Sum(nil)
}

func formatGatewayUnix(value int64) string {
	// The claim timestamp is a small decimal; a fixed shape keeps the MAC input
	// canonical without pulling in strconv formatting choices.
	return formatGatewayInt(value)
}

func formatGatewayInt(value int64) string {
	if value <= 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

// newGatewayCriticalClaim produces the four header values for one verified
// step-up. The caller must already have consumed a valid proof for this session.
func newGatewayCriticalClaim(claimKey []byte, now time.Time) (gatewayCriticalClaimHeaders, error) {
	if len(claimKey) < 32 {
		return gatewayCriticalClaimHeaders{}, errors.New("gateway claim key is not provisioned")
	}
	nonce, err := randomLowerHex(gatewayStepUpProofTokenBytes)
	if err != nil {
		return gatewayCriticalClaimHeaders{}, errors.New("claim nonce could not be generated")
	}
	timestamp := now.UTC().Unix()
	mac := gatewayCriticalClaimMAC(claimKey, gatewayCriticalRole, gatewayStepUpMethodPassword, timestamp, nonce)
	return gatewayCriticalClaimHeaders{
		Role:      gatewayCriticalRole,
		StepUp:    gatewayStepUpMethodPassword + ":" + nonce,
		Timestamp: timestamp,
		MAC:       hex.EncodeToString(mac),
	}, nil
}

// randomLowerHex returns n random bytes as lowercase hex. The nonce shape is
// lowercase hex on both sides of the contract.
func randomLowerHex(size int) (string, error) {
	if size <= 0 || size > 64 {
		return "", errors.New("nonce size is outside its bound")
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// gatewayCriticalRoute mirrors the control plane's critical-action classifier.
// The gateway only attaches a role claim to one of these requests; a proof
// presented on any other request is refused rather than silently consumed.
//
// The three routes are the AP-7 destructive surface that exists today. The list
// is the documented sync point with control/rbac_types.go
// (criticalManagementAction): a new critical route must be added in both places,
// and docs/V6.3.0-RBAC.md states that rule.
func gatewayCriticalRoute(method, path string) bool {
	switch {
	case method == http.MethodPost && path == "/api/v1/quarantine/prune":
		return true
	case method == http.MethodPost && strings.HasPrefix(path, "/api/v1/xdr/review/") &&
		strings.HasSuffix(path, "/ack"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/xdr/review/"), "/ack")
		return id != "" && !strings.Contains(id, "/")
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/xdr/review/"):
		id := strings.TrimPrefix(path, "/api/v1/xdr/review/")
		return id != "" && !strings.Contains(id, "/")
	case method == http.MethodPost && path == "/api/v1/xdr/permits":
		return true
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/xdr/permits/"):
		id := strings.TrimPrefix(path, "/api/v1/xdr/permits/")
		return id != "" && !strings.Contains(id, "/")
	case method == http.MethodPost && path == "/api/v1/chameleon/reveal":
		return true
	case method == http.MethodPost && path == "/api/v1/xdr/update-window/override":
		return true
	}
	return false
}

// writeGatewayJSONError answers with a bounded JSON error. It never carries a
// build string, a credential or internal detail.
func writeGatewayJSONError(w http.ResponseWriter, status int, message string) {
	writeGatewayJSON(w, status, map[string]string{"error": message})
}

func writeGatewayJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// gatewayRetryAfterSeconds renders a Retry-After value from a bounded duration.
func gatewayRetryAfterSeconds(d time.Duration) string {
	seconds := int(d / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return formatGatewayInt(int64(seconds))
}
