// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (R6): management-API role model, step-up contracts and the
// brute-force bounds of the control plane.
//
// The role ladder is server-enforced. A role is never read from a client header:
// it is derived from the presented bearer credential (Operator = the existing
// dashboard token, Observer = the optional adjacent `<token_file>.observer`
// credential), and the most destructive actions additionally require a fresh
// step-up proof. Two step-up paths exist:
//
//   - direct loopback: a short-lived, single-use token
//     `critical|<expiry_unix>|<nonce>|<mac>` signed with the optional
//     `<token_file>.critical` key file (HMAC-SHA256, lowercase hex MAC);
//   - browser flow: the gateway re-verifies the operator password, consumes a
//     one-time proof and forwards an HMAC-signed role claim over the backend
//     token (`X-VGT-Role`, `X-VGT-Step-Up`, `X-VGT-Claim-Ts`, `X-VGT-Claim-MAC`).
//
// Neither proof is a credential of its own: both are bounded to at most five
// minutes, single-purpose and single-use, and both are verified server-side.

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Role is the ordered management-API role ladder. A credential satisfies a
// requirement when its role is >= the required role.
type Role int

const (
	// RoleObserver may read (GET/HEAD) and do nothing else.
	RoleObserver Role = iota
	// RoleOperator may perform ordinary policy and action mutations. It is the
	// existing operator bearer credential, so today's behaviour is preserved.
	RoleOperator
	// RoleCritical is the most destructive class (evidence/vault destruction and
	// finding dismissal). It is reachable only through a fresh step-up proof.
	RoleCritical
)

const (
	roleObserverName = "observer"
	roleOperatorName = "operator"
	roleCriticalName = "critical-unlock"

	// observerTokenSuffix and criticalKeySuffix are the convention-based adjacent
	// credential locations. No configuration schema change is required: both are
	// derived from the existing dashboard token file path.
	observerTokenSuffix = ".observer"
	criticalKeySuffix   = ".critical"

	// rbacCredentialMaxBytes bounds any adjacent credential file. A token file is
	// a few dozen bytes; anything larger is not one.
	rbacCredentialMaxBytes = 4096
	// observerTokenRawBytes is the decoded width of an observer credential; it is
	// the same 256-bit form the operator token uses.
	observerTokenRawBytes = 32
	// criticalKeyMinBytes is the minimum HMAC key material. A short key is a
	// configuration error, not something to accept silently.
	criticalKeyMinBytes = 32

	// directStepUpHeader carries the direct-loopback proof. The gateway claim uses
	// the header set the AP-9 contract names and is only accepted from the gateway.
	directStepUpHeader = "X-VGT-Step-Up-Proof"
	// gatewayProxiedHeader marks a request that was forwarded by the access
	// gateway. The two step-up trust paths are deliberately mutually exclusive.
	gatewayProxiedHeader  = "X-VGT-Gateway"
	gatewayProxiedValue   = "direct-access-v2"
	gatewayRoleHeader     = "X-VGT-Role"
	gatewayStepUpHeader   = "X-VGT-Step-Up"
	gatewayClaimTsHeader  = "X-VGT-Claim-Ts"
	gatewayClaimMACHeader = "X-VGT-Claim-MAC"

	// criticalStepUpPurpose is the only accepted purpose of a direct proof, and the
	// only MAC input ever produced by the gateway claim.
	criticalStepUpPurpose = "critical"
	// criticalStepUpTTL is the lifetime of a freshly minted direct proof. The
	// verifier additionally refuses anything further than criticalStepUpMaxTTL in
	// the future, so a leaked key cannot mint long-lived capabilities.
	criticalStepUpTTL    = 2 * time.Minute
	criticalStepUpMaxTTL = 5 * time.Minute
	// criticalStepUpNonceBytes is the random nonce width (hex-encoded on the wire).
	criticalStepUpNonceBytes = 16

	// gatewayClaimWindow is the maximum accepted clock skew of the gateway claim.
	gatewayClaimWindow = 30 * time.Second
	// gatewayClaimMaxNonceBytes bounds the claim nonce.
	gatewayClaimMaxNonceBytes = 64
	// gatewayClaimMinNonceBytes keeps a short value from being usable as a nonce.
	gatewayClaimMinNonceBytes = 16

	// nonceReplayCacheMaxEntries / nonceReplayCacheTTL bound both single-use
	// caches. A full cache evicts the oldest entry instead of failing closed for
	// every new proof (the same bounded-cache trade-off as the other guards).
	nonceReplayCacheMaxEntries = 4096
	nonceReplayCacheTTL        = 6 * time.Minute

	// The brute-force bound: five failures inside the window lock that source out
	// for authLockoutDuration. Entries are bounded and old failures are pruned.
	authLockoutFailureLimit  = 5
	authLockoutFailureWindow = 15 * time.Minute
	authLockoutDuration      = 5 * time.Minute
	authLockoutMaxEntries    = 4096

	// rbacEventCooldown bounds the one event a rejected credential, a lockout or an
	// unavailable capability may write. The rejection itself is never softened.
	rbacEventCooldown = 5 * time.Minute

	// Domain separators. They keep a step-up MAC from being valid as any other MAC
	// this process produces with the same key.
	criticalStepUpDomain  = "VGT-GEDEFENSE-CRITICAL-STEP-UP-V1\x00"
	gatewayClaimDomain    = "VGT-GEDEFENSE-GATEWAY-CRITICAL-CLAIM-V1\x00"
	directStepUpTokenHead = "critical"
)

// roleContextKey carries the authenticated role to handlers. Handlers keep
// working without it; it exists so a future surface can project the role it was
// actually granted instead of inferring it.
type roleContextKey struct{}

// RoleFromRequest returns the role the auth middleware granted this request.
func RoleFromRequest(r *http.Request) Role {
	if r == nil {
		return RoleObserver
	}
	if role, ok := r.Context().Value(roleContextKey{}).(Role); ok {
		return role
	}
	return RoleObserver
}

func withRole(r *http.Request, role Role) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), roleContextKey{}, role))
}

// String renders the operator-facing role name.
func (r Role) String() string {
	switch r {
	case RoleObserver:
		return roleObserverName
	case RoleOperator:
		return roleOperatorName
	case RoleCritical:
		return roleCriticalName
	default:
		return "unknown"
	}
}

// criticalManagementAction classifies a request as one of the destructive actions
// of the AP-9 critical class.
//
// The set is deliberately small and exact. The AP-7 quarantine prune and review
// ack/delete are the destructive routes that exist today; PermitV1 upsert/removal,
// a chameleon reveal and an update override have no HTTP route yet, and the helper
// is the single place a future route is added (documented in
// docs/V6.3.0-RBAC.md). Protection-removing routes that predate this work package
// keep their own typed-confirmation + undo + evidence contract and stay Operator;
// widening this list would lock behaviour that the existing API contract depends
// on out of its own tests.
func criticalManagementAction(method, path string) (string, bool) {
	switch {
	case method == http.MethodPost && path == "/api/v1/quarantine/prune":
		return "quarantine-prune", true
	case method == http.MethodPost && strings.HasPrefix(path, "/api/v1/xdr/review/") &&
		strings.HasSuffix(path, "/ack"):
		if reviewID := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/xdr/review/"), "/ack"); reviewID != "" && !strings.Contains(reviewID, "/") {
			return "review-ack", true
		}
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/xdr/review/"):
		if reviewID := strings.TrimPrefix(path, "/api/v1/xdr/review/"); reviewID != "" && !strings.Contains(reviewID, "/") {
			return "review-delete", true
		}
	}
	return "", false
}

// criticalStepUpProof is one verified direct proof.
type criticalStepUpProof struct {
	Nonce     string
	ExpiresAt time.Time
}

// gatewayCriticalClaim is the verified gateway role claim. It is never taken
// from a client header without a successful MAC over every field.
type gatewayCriticalClaim struct {
	Role      string
	StepUp    string
	Timestamp int64
	Nonce     string
}

// criticalAuthFailure is a typed refusal of the critical guard so the caller can
// choose an honest status without leaking which check failed.
type criticalAuthFailure struct {
	reason      string
	unavailable bool
}

func (f criticalAuthFailure) Error() string { return f.reason }

// requestIsGatewayProxied reports whether the request carries the gateway trust
// marker. The marker is not authority on its own: it only selects which of the
// two authenticated step-up paths is consulted.
func requestIsGatewayProxied(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.TrimSpace(r.Header.Get(gatewayProxiedHeader)) == gatewayProxiedValue
}

// remoteIsLoopback reports whether the request came from a loopback peer. The
// control dashboard listens on loopback and the gateway proxies from loopback;
// both step-up proof types are only accepted from that boundary.
func remoteIsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// formatUnix renders the canonical decimal claim timestamp.
func formatUnix(value int64) string { return strconv.FormatInt(value, 10) }
