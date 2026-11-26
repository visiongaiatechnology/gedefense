// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (R6): the management-API role model, step-up and brute-force
// regression suite. Every test here is offline: the handlers run in-process, the
// token/key files live in a temporary directory, and no listener is started.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	rbacOperatorToken = "0123456789abcdef0123456789abcdef"
)

var (
	rbacObserverBytes   = []byte(strings.Repeat("o", 32))
	rbacObserverSecret  = base64.RawURLEncoding.EncodeToString(rbacObserverBytes)
	rbacCriticalKey     = []byte(strings.Repeat("k", 32))
	rbacGatewayClaimKey = []byte("gway-claim-key-0123456789abcdef!")
)

// rbacTestServer builds a server whose adjacent credential files follow the exact
// convention of the production paths: `<token_file>.observer`,
// `<token_file>.critical` and `<token_file>.gateway-claim`, each mode 0600.
func rbacTestServer(t *testing.T, observer bool, critical bool) (*APIServer, string) {
	t.Helper()
	cfg := isolatedTokenConfig(t, rbacOperatorToken)
	tokenPath := cfg.Dashboard.TokenFile
	if observer {
		if err := os.WriteFile(tokenPath+observerTokenSuffix, []byte(rbacObserverSecret+"\n"), 0o600); err != nil {
			t.Fatalf("write observer token: %v", err)
		}
	}
	if critical {
		if err := os.WriteFile(tokenPath+criticalKeySuffix, rbacCriticalKey, 0o600); err != nil {
			t.Fatalf("write critical key: %v", err)
		}
		if err := os.WriteFile(tokenPath+gatewayClaimKeySuffix, rbacGatewayClaimKey, 0o600); err != nil {
			t.Fatalf("write gateway claim key: %v", err)
		}
	}
	server := NewAPIServer(cfg, NewState("rbac-test", cfg), nil, nil, nil, nil, nil, nil, rbacOperatorToken)
	return server, tokenPath
}

// rbacSink is a stand-in handler that records whether the request reached it.
func rbacSink(reached *bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusNoContent)
	}
}

// rbacRequest drives one handler with a loopback peer and a unique mutation id.
func rbacRequest(t *testing.T, handler http.HandlerFunc, method, path, token string, body []byte, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://127.0.0.1"+path, reader)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:40404"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("X-VGT-Request-ID", "rbac-"+randomID()+randomID())
	}
	if mutate != nil {
		mutate(req)
	}
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	return recorder
}

func rbacMintStepUp(t *testing.T, server *APIServer, token string) (string, int) {
	t.Helper()
	rec := rbacRequest(t, server.http.Handler.ServeHTTP, http.MethodPost, "/api/v1/auth/step-up", token,
		[]byte(`{"purpose":"critical"}`), nil)
	if rec.Code != http.StatusOK {
		return "", rec.Code
	}
	var payload struct {
		StepUp string `json:"step_up"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil || payload.StepUp == "" {
		t.Fatalf("step-up answer is not usable: %q", rec.Body.String())
	}
	return payload.StepUp, rec.Code
}

// TestRBACRoleClassificationFromCredentials covers the source of truth: the role
// is derived from the credential and never from a client header.
func TestRBACRoleClassificationFromCredentials(t *testing.T) {
	server, _ := rbacTestServer(t, true, true)
	if role, ok := server.classifyCredential(rbacOperatorToken); !ok || role != RoleOperator {
		t.Fatalf("operator token classified as %v/%v", role, ok)
	}
	if role, ok := server.classifyCredential(rbacObserverSecret); !ok || role != RoleObserver {
		t.Fatalf("observer token classified as %v/%v", role, ok)
	}
	if _, ok := server.classifyCredential("not-a-credential"); ok {
		t.Fatal("an unknown token was classified as a credential")
	}
	if _, ok := server.classifyCredential(""); ok {
		t.Fatal("the empty credential was classified as a credential")
	}

	// Absent observer file: the observer role is simply unavailable and the
	// credential grants nothing - there is no accidental elevation to operator.
	withoutObserver, _ := rbacTestServer(t, false, true)
	anonymousSink := false
	observerHandler := withoutObserver.auth(rbacSink(&anonymousSink))
	rec := rbacRequest(t, observerHandler, http.MethodGet, "/api/v1/status", rbacObserverSecret, nil, nil)
	if rec.Code != http.StatusUnauthorized || anonymousSink {
		t.Fatalf("an unprovisioned observer token was accepted: status=%d reached=%v", rec.Code, anonymousSink)
	}
	operatorRec := rbacRequest(t, observerHandler, http.MethodGet, "/api/v1/status", rbacOperatorToken, nil, nil)
	if operatorRec.Code != http.StatusNoContent {
		t.Fatalf("the operator token stopped working without an observer file: %d", operatorRec.Code)
	}
}

// TestRBACObserverCredentialFilePolicy proves the file policy is a trust decision:
// a readable-by-group, symlinked, oversized or malformed observer credential is
// refused and the role stays unavailable.
func TestRBACObserverCredentialFilePolicy(t *testing.T) {
	server, tokenPath := rbacTestServer(t, false, true)
	reached := false
	handler := server.auth(rbacSink(&reached))

	if err := os.WriteFile(tokenPath+observerTokenSuffix, []byte(rbacObserverSecret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacObserverSecret, nil, nil); rec.Code != http.StatusUnauthorized || reached {
		t.Fatalf("a world-readable observer credential was accepted: %d", rec.Code)
	}
	if err := os.Chmod(tokenPath+observerTokenSuffix, 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacObserverSecret, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("a correctly provisioned observer credential was refused: %d", rec.Code)
	}
	// A private file carrying the wrong token shape does not become a credential.
	if err := os.WriteFile(tokenPath+observerTokenSuffix, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacObserverSecret, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a malformed observer credential file was accepted: %d", rec.Code)
	}
	// A symlink is never a private regular file.
	if err := os.Remove(tokenPath + observerTokenSuffix); err != nil {
		t.Fatal(err)
	}
	target := tokenPath + ".observer-target"
	if err := os.WriteFile(target, []byte(rbacObserverSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, tokenPath+observerTokenSuffix); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacObserverSecret, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a symlinked observer credential was accepted: %d", rec.Code)
	}
	// The operator is never affected by an unusable auxiliary credential.
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacOperatorToken, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("an operator request was refused because of the observer file: %d", rec.Code)
	}
}

// TestRBACObserverIsReadOnly proves the read-only half of the role ladder.
func TestRBACObserverIsReadOnly(t *testing.T) {
	server, _ := rbacTestServer(t, true, true)
	reached := false
	handler := server.auth(rbacSink(&reached))
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacObserverSecret, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("observer GET refused: %d", rec.Code)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		reached = false
		rec := rbacRequest(t, handler, method, "/api/v1/settings/system/preview", rbacObserverSecret, nil, nil)
		if rec.Code != http.StatusForbidden || reached {
			t.Fatalf("observer %s was not refused: status=%d reached=%v", method, rec.Code, reached)
		}
	}
	reached = false
	if rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/settings/system/preview", rbacOperatorToken, nil, nil); rec.Code != http.StatusNoContent || !reached {
		t.Fatalf("operator mutation regressed: status=%d reached=%v", rec.Code, reached)
	}
}

// TestRBACObserverRotationIsHonoured proves the adjacent credential is re-read on
// every use, exactly like the operator token.
func TestRBACObserverRotationIsHonoured(t *testing.T) {
	server, tokenPath := rbacTestServer(t, true, true)
	handler := server.auth(rbacSink(new(bool)))
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacObserverSecret, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("observer credential not accepted before rotation: %d", rec.Code)
	}
	rotated := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("r", 32)))
	if err := os.WriteFile(tokenPath+observerTokenSuffix, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacObserverSecret, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the previous observer credential survived a rotation: %d", rec.Code)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rotated, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("the rotated observer credential was refused: %d", rec.Code)
	}
	if err := os.Remove(tokenPath + observerTokenSuffix); err != nil {
		t.Fatal(err)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rotated, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a removed observer credential still authenticated: %d", rec.Code)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacOperatorToken, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("the operator was affected by an observer removal: %d", rec.Code)
	}
}

// TestRBACCriticalActionsRequireStepUp covers the critical class end to end.
func TestRBACCriticalActionsRequireStepUp(t *testing.T) {
	server, _ := rbacTestServer(t, true, true)
	reached := false
	handler := server.auth(rbacSink(&reached))
	criticalRoutes := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/quarantine/prune"},
		{http.MethodPost, "/api/v1/xdr/review/0123456789abcdef/ack"},
		{http.MethodDelete, "/api/v1/xdr/review/0123456789abcdef"},
	}
	for _, route := range criticalRoutes {
		reached = false
		rec := rbacRequest(t, handler, route.method, route.path, rbacOperatorToken, nil, nil)
		if rec.Code != http.StatusForbidden || reached {
			t.Fatalf("%s %s without step-up: status=%d reached=%v", route.method, route.path, rec.Code, reached)
		}
	}
	// The operator remains fully authorized for non-critical mutations.
	reached = false
	if rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/settings/system/preview", rbacOperatorToken, nil, nil); rec.Code != http.StatusNoContent || !reached {
		t.Fatalf("operator non-critical mutation regressed: status=%d reached=%v", rec.Code, reached)
	}
	proof, status := rbacMintStepUp(t, server, rbacOperatorToken)
	if status != http.StatusOK || proof == "" {
		t.Fatalf("step-up mint failed: status=%d", status)
	}
	for _, route := range criticalRoutes {
		// Every proof is single use, so each action mints its own.
		fresh, mintStatus := rbacMintStepUp(t, server, rbacOperatorToken)
		if mintStatus != http.StatusOK || fresh == "" {
			t.Fatalf("step-up mint for %s failed: status=%d", route.path, mintStatus)
		}
		reached = false
		rec := rbacRequest(t, handler, route.method, route.path, rbacOperatorToken, nil, func(r *http.Request) {
			r.Header.Set(directStepUpHeader, fresh)
		})
		if rec.Code != http.StatusNoContent || !reached {
			t.Fatalf("%s %s with step-up: status=%d reached=%v", route.method, route.path, rec.Code, reached)
		}
		if route.method == http.MethodPost && route.path == "/api/v1/quarantine/prune" {
			// The same token replayed on a second action is refused.
			replay := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
				r.Header.Set(directStepUpHeader, fresh)
			})
			if replay.Code != http.StatusForbidden {
				t.Fatalf("a replayed step-up proof was accepted: %d", replay.Code)
			}
		}
	}
	// A second mint works again.
	second, _ := rbacMintStepUp(t, server, rbacOperatorToken)
	if second == "" || second == proof {
		t.Fatal("a second step-up mint did not produce a fresh proof")
	}
}

// TestStepUpDirectProofVerification covers the direct proof boundary: forged,
// expired, out-of-bound and wrong-key proofs are refused and the critical action
// stays locked; a key-less host reports the capability as unavailable.
func TestStepUpDirectProofVerification(t *testing.T) {
	now := time.Now().UTC()
	tampered := func(proof string) string {
		if strings.HasSuffix(proof, "0") {
			return proof[:len(proof)-1] + "1"
		}
		return proof[:len(proof)-1] + "0"
	}
	_, expiredToken, err := issueCriticalStepUpProof(rbacCriticalKey, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, farFutureToken, err := issueCriticalStepUpProof(rbacCriticalKey, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKeyToken, err := issueCriticalStepUpProof([]byte(strings.Repeat("z", 32)), now)
	if err != nil {
		t.Fatal(err)
	}
	_, valid, err := issueCriticalStepUpProof(rbacCriticalKey, now)
	if err != nil {
		t.Fatal(err)
	}

	server, _ := rbacTestServer(t, false, true)
	reached := false
	handler := server.auth(rbacSink(&reached))
	cases := []struct {
		name  string
		proof string
		want  int
	}{
		{"tampered", tampered(valid), http.StatusForbidden},
		{"expired", expiredToken, http.StatusForbidden},
		{"far future", farFutureToken, http.StatusForbidden},
		{"wrong key", wrongKeyToken, http.StatusForbidden},
		{"garbage", "critical|not-a-time|00|00", http.StatusForbidden},
	}
	for _, tc := range cases {
		reached = false
		rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
			r.Header.Set(directStepUpHeader, tc.proof)
		})
		if rec.Code != tc.want || reached {
			t.Fatalf("%s proof: status=%d want=%d reached=%v", tc.name, rec.Code, tc.want, reached)
		}
	}
	// A host without the optional key file reports the capability as unavailable,
	// not as a silent operator-only check.
	noKeyServer, _ := rbacTestServer(t, false, false)
	noKeyHandler := noKeyServer.auth(rbacSink(new(bool)))
	if rec := rbacRequest(t, noKeyHandler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a key-less host did not report the critical capability as unavailable: %d", rec.Code)
	}
}

// TestStepUpLockoutAndReset proves the bounded per-source brute-force guard on the
// step-up proof path.
func TestStepUpLockoutAndReset(t *testing.T) {
	current := time.Now().UTC()
	server, _ := rbacTestServer(t, true, true)
	server.rbacNow = func() time.Time { return current }
	reached := false
	handler := server.auth(rbacSink(&reached))
	for attempt := 0; attempt < authLockoutFailureLimit; attempt++ {
		rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
			r.Header.Set(directStepUpHeader, "critical|1|bad|bad")
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("invalid proof %d returned %d", attempt, rec.Code)
		}
	}
	proof, status := rbacMintStepUp(t, server, rbacOperatorToken)
	if status != http.StatusOK {
		t.Fatalf("step-up mint during lockout failed: %d", status)
	}
	lockedRec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		r.Header.Set(directStepUpHeader, proof)
	})
	if lockedRec.Code != http.StatusTooManyRequests || lockedRec.Header().Get("Retry-After") == "" || reached {
		t.Fatalf("a locked source was not refused with 429+Retry-After: status=%d", lockedRec.Code)
	}
	// After the fixed window the source is admitted again.
	current = current.Add(authLockoutDuration + time.Second)
	freshProof, status := rbacMintStepUp(t, server, rbacOperatorToken)
	if status != http.StatusOK {
		t.Fatalf("step-up mint after the lockout failed: %d", status)
	}
	rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		r.Header.Set(directStepUpHeader, freshProof)
	})
	if rec.Code != http.StatusNoContent || !reached {
		t.Fatalf("the source was not admitted after the lockout expired: %d", rec.Code)
	}
	// A successful verification clears the failure history, so an occasional typo
	// cannot accumulate into a lockout: four failures plus a success twice in a row
	// must never reach the threshold.
	badProof := func(r *http.Request) { r.Header.Set(directStepUpHeader, "critical|1|bad|bad") }
	for round := 0; round < 2; round++ {
		for attempt := 0; attempt < authLockoutFailureLimit-1; attempt++ {
			rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, badProof)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("round %d failure %d returned %d", round, attempt, rec.Code)
			}
		}
		successProof, status := rbacMintStepUp(t, server, rbacOperatorToken)
		if status != http.StatusOK {
			t.Fatalf("round %d step-up mint failed: %d", round, status)
		}
		rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
			r.Header.Set(directStepUpHeader, successProof)
		})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("round %d success did not clear the failure history: %d", round, rec.Code)
		}
	}
}

// rbacGatewayClaimHeaders builds the four claim headers exactly as the gateway does.
func rbacGatewayClaimHeaders(t *testing.T, claimKey []byte, timestamp int64, nonce string) map[string]string {
	t.Helper()
	mac := gatewayClaimMAC(claimKey, criticalStepUpPurpose, "password", timestamp, nonce)
	return map[string]string{
		gatewayProxiedHeader:  gatewayProxiedValue,
		gatewayRoleHeader:     criticalStepUpPurpose,
		gatewayStepUpHeader:   "password:" + nonce,
		gatewayClaimTsHeader:  formatUnix(timestamp),
		gatewayClaimMACHeader: hex.EncodeToString(mac),
	}
}

// TestRBACGatewayClaimVerification covers the gateway trust path: a MACed claim
// over the dedicated gateway claim key is accepted, and every forged, stale,
// replayed or bearer-token-signed variant is refused.
func TestRBACGatewayClaimVerification(t *testing.T) {
	server, _ := rbacTestServer(t, false, true)
	reached := false
	handler := server.auth(rbacSink(&reached))
	nonce := strings.Repeat("ab", 16)
	headers := rbacGatewayClaimHeaders(t, rbacGatewayClaimKey, time.Now().UTC().Unix(), nonce)
	rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		for name, value := range headers {
			r.Header.Set(name, value)
		}
	})
	if rec.Code != http.StatusNoContent || !reached {
		t.Fatalf("a valid gateway claim was refused: status=%d body=%s", rec.Code, rec.Body.String())
	}
	// A claim MAC signed with the operator bearer token (SEC-01 regression) MUST be refused.
	bearerSigned := rbacGatewayClaimHeaders(t, []byte(rbacOperatorToken), time.Now().UTC().Unix(), strings.Repeat("de", 16))
	if rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		for name, value := range bearerSigned {
			r.Header.Set(name, value)
		}
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("a gateway claim signed with the operator bearer token was accepted: %d", rec.Code)
	}
	// The same claim replayed is refused by the bounded nonce cache.
	replay := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		for name, value := range headers {
			r.Header.Set(name, value)
		}
	})
	if replay.Code != http.StatusForbidden {
		t.Fatalf("a replayed gateway claim was accepted: %d", replay.Code)
	}
	// A stale timestamp is outside the bounded window.
	stale := rbacGatewayClaimHeaders(t, rbacGatewayClaimKey, time.Now().UTC().Add(-gatewayClaimWindow-time.Minute).Unix(), strings.Repeat("cd", 16))
	if rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		for name, value := range stale {
			r.Header.Set(name, value)
		}
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("a stale gateway claim was accepted: %d", rec.Code)
	}
	// A MAC produced with another key does not verify.
	forged := rbacGatewayClaimHeaders(t, []byte(strings.Repeat("q", 40)), time.Now().UTC().Unix(), strings.Repeat("ef", 16))
	if rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		for name, value := range forged {
			r.Header.Set(name, value)
		}
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("a forged gateway claim was accepted: %d", rec.Code)
	}
	// A claim that is not for the critical role is refused even with a valid MAC.
	otherRole := rbacGatewayClaimHeaders(t, rbacGatewayClaimKey, time.Now().UTC().Unix(), strings.Repeat("12", 16))
	otherRole[gatewayRoleHeader] = roleOperatorName
	if rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		for name, value := range otherRole {
			r.Header.Set(name, value)
		}
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("an operator-role gateway claim unlocked a critical action: %d", rec.Code)
	}
	// Earlier negative cases share the fallback loopback failure budget, so advance past
	// the lockout window before testing trust-marker exclusion and path isolation (F-06).
	current := time.Now().UTC()
	server.rbacNow = func() time.Time { return current }
	current = current.Add(authLockoutDuration + time.Second)
	// Claim headers without the gateway marker do not select the claim path.
	unmarked := rbacGatewayClaimHeaders(t, rbacGatewayClaimKey, current.Unix(), strings.Repeat("34", 16))
	if rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		for name, value := range unmarked {
			if name == gatewayProxiedHeader {
				continue
			}
			r.Header.Set(name, value)
		}
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("claim headers without the gateway marker were accepted: %d", rec.Code)
	}
	// A host without a provisioned gateway claim key fails closed (503) even with bearer-signed headers.
	noClaimServer, _ := rbacTestServer(t, false, false)
	noClaimHandler := noClaimServer.auth(rbacSink(new(bool)))
	if rec := rbacRequest(t, noClaimHandler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		for name, value := range bearerSigned {
			r.Header.Set(name, value)
		}
	}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a host without .gateway-claim failed open or wrong code: %d", rec.Code)
	}
	// The two trust paths never mix: a gateway-marked request ignores a direct proof.
	_, direct, err := issueCriticalStepUpProof(rbacCriticalKey, current)
	if err != nil {
		t.Fatal(err)
	}
	if rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		r.Header.Set(gatewayProxiedHeader, gatewayProxiedValue)
		r.Header.Set(directStepUpHeader, direct)
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("a direct proof was accepted on the gateway trust path: %d", rec.Code)
	}
}

// TestRBACNonceReplayConcurrent verifies nonceReplayCache.claim is race-free under
// concurrent critical step-up probes (LIN-H01).
func TestRBACNonceReplayConcurrent(t *testing.T) {
	cache := newNonceReplayCache(64)
	now := time.Now().UTC()
	const workers = 16
	var wg sync.WaitGroup
	var won sync.Mutex
	winners := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if cache.claim("shared-nonce-0001", now.Add(time.Minute), now) {
				won.Lock()
				winners++
				won.Unlock()
			}
			_ = cache.claim("unique-"+string(rune('a'+idx)), now.Add(time.Minute), now)
		}(i)
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("expected exactly 1 concurrent winner for shared nonce, got %d", winners)
	}
}

// TestRBACGatewaySessionLockoutIsolation proves one attested gateway session exhausting
// its step-up failure budget does not lock out another session on 127.0.0.1 (F-10).
func TestRBACGatewaySessionLockoutIsolation(t *testing.T) {
	server, _ := rbacTestServer(t, false, true)
	handler := server.auth(rbacSink(new(bool)))
	attestedSessionHeader := func(id string) string {
		mac := hmac.New(sha256.New, []byte(rbacOperatorToken))
		mac.Write([]byte(gatewaySessionDomain))
		mac.Write([]byte(id))
		return id + "." + hex.EncodeToString(mac.Sum(nil))
	}
	sessionA := attestedSessionHeader("session-aaaaaaaaaaaaaaaa")
	sessionB := attestedSessionHeader("session-bbbbbbbbbbbbbbbb")

	for attempt := 0; attempt < authLockoutFailureLimit; attempt++ {
		forged := rbacGatewayClaimHeaders(t, []byte(strings.Repeat("z", 32)), time.Now().UTC().Unix(), strings.Repeat("55", 15)+string(rune('a'+attempt))+string(rune('0'+attempt)))
		rec := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
			r.Header.Set(gatewaySessionHeader, sessionA)
			for k, v := range forged {
				r.Header.Set(k, v)
			}
		})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("failure %d expected 403, got %d", attempt+1, rec.Code)
		}
	}
	// Session A is now locked out (429).
	recA := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		r.Header.Set(gatewaySessionHeader, sessionA)
		r.Header.Set(gatewayProxiedHeader, gatewayProxiedValue)
	})
	if recA.Code != http.StatusTooManyRequests {
		t.Fatalf("locked session A expected 429, got %d", recA.Code)
	}
	// Session B can still present a valid critical claim and succeed.
	validB := rbacGatewayClaimHeaders(t, rbacGatewayClaimKey, time.Now().UTC().Unix(), strings.Repeat("78", 16))
	recB := rbacRequest(t, handler, http.MethodPost, "/api/v1/quarantine/prune", rbacOperatorToken, nil, func(r *http.Request) {
		r.Header.Set(gatewaySessionHeader, sessionB)
		for k, v := range validB {
			r.Header.Set(k, v)
		}
	})
	if recB.Code != http.StatusNoContent {
		t.Fatalf("unrelated gateway session B was blocked by session A lockout: %d", recB.Code)
	}
}

// TestRBACStepUpMintRefusedForGatewayProxiedRequest proves a browser session
// cannot mint a direct proof through the proxy and skip the password step-up.
func TestRBACStepUpMintRefusedForGatewayProxiedRequest(t *testing.T) {
	server, _ := rbacTestServer(t, false, true)
	proxied := rbacRequest(t, server.http.Handler.ServeHTTP, http.MethodPost, "/api/v1/auth/step-up", rbacOperatorToken,
		[]byte(`{"purpose":"critical"}`), func(r *http.Request) {
			r.Header.Set(gatewayProxiedHeader, gatewayProxiedValue)
		})
	if proxied.Code != http.StatusForbidden {
		t.Fatalf("a gateway-proxied request minted a direct step-up proof: %d", proxied.Code)
	}
	direct := rbacRequest(t, server.http.Handler.ServeHTTP, http.MethodPost, "/api/v1/auth/step-up", rbacOperatorToken,
		[]byte(`{"purpose":"critical"}`), nil)
	if direct.Code != http.StatusOK {
		t.Fatalf("a direct loopback step-up mint failed: status=%d body=%s", direct.Code, direct.Body.String())
	}
	if strings.Contains(direct.Body.String(), string(rbacCriticalKey)) {
		t.Fatal("the step-up answer leaked key material")
	}
	var payload struct {
		StepUp    string `json:"step_up"`
		Purpose   string `json:"purpose"`
		TTL       int    `json:"ttl_seconds"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(direct.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Purpose != criticalStepUpPurpose || payload.TTL < 1 || payload.TTL > int(criticalStepUpMaxTTL/time.Second) || payload.ExpiresAt == "" {
		t.Fatalf("step-up answer violates the contract: %+v", payload)
	}
	if !strings.HasPrefix(payload.StepUp, directStepUpTokenHead+"|") {
		t.Fatalf("step-up token has an unexpected shape: %q", payload.StepUp)
	}
	// A body that does not name the one accepted purpose is refused.
	if rec := rbacRequest(t, server.http.Handler.ServeHTTP, http.MethodPost, "/api/v1/auth/step-up", rbacOperatorToken,
		[]byte(`{"purpose":"everything"}`), nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unaccepted step-up purpose was honoured: %d", rec.Code)
	}
}

// TestRBACLockoutBoundedAndReported proves the token lockout bounds guessing,
// reports one bounded event, never locks a valid credential out and prunes its
// table.
func TestRBACLockoutBoundedAndReported(t *testing.T) {
	server, _ := rbacTestServer(t, true, true)
	handler := server.auth(rbacSink(new(bool)))
	for attempt := 0; attempt < authLockoutFailureLimit; attempt++ {
		if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", "wrong-token-"+randomID(), nil, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("unknown credential %d returned %d", attempt, rec.Code)
		}
	}
	rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", "another-wrong-token", nil, nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("the source was not locked out: status=%d", rec.Code)
	}
	// The lockout bounds guessing, not possession: the real credential is never
	// locked out by another attempt (documented availability guarantee).
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacOperatorToken, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("the operator was locked out of their own platform: %d", rec.Code)
	}
	// The lockout was reported once as a bounded event that carries no secret.
	events := server.state.Snapshot().Events
	foundLockout := false
	for _, event := range events {
		if event.Kind == "rbac.lockout" {
			foundLockout = true
			if strings.Contains(event.Message, "wrong-token") || strings.Contains(event.Message, rbacOperatorToken) {
				t.Fatalf("the lockout event leaked a credential: %q", event.Message)
			}
		}
	}
	if !foundLockout {
		t.Fatal("the brute-force lockout was not reported")
	}

	// The lockout table itself is bounded: a flood of distinct sources evicts old
	// entries instead of growing without limit.
	guard := newAttemptLockout(authLockoutFailureLimit, authLockoutFailureWindow, authLockoutDuration, func() time.Time { return time.Now() })
	guard.maxEntries = 4
	for i := 0; i < 32; i++ {
		guard.fail("source-" + strings.Repeat("x", i%8) + string(rune('a'+i%26)))
	}
	guard.mu.Lock()
	size := len(guard.entries)
	guard.mu.Unlock()
	if size > guard.maxEntries {
		t.Fatalf("the lockout table grew past its bound: %d > %d", size, guard.maxEntries)
	}
	// A lockout expires on its own.
	current := time.Now()
	guard.now = func() time.Time { return current }
	guard.maxEntries = authLockoutMaxEntries
	for attempt := 0; attempt < authLockoutFailureLimit; attempt++ {
		guard.fail("expiring-source")
	}
	if locked, _ := guard.locked("expiring-source"); !locked {
		t.Fatal("the guard did not lock the source at the threshold")
	}
	current = current.Add(authLockoutDuration + time.Second)
	if locked, _ := guard.locked("expiring-source"); locked {
		t.Fatal("the lockout did not expire")
	}
	guard.success("expiring-source")
}

// TestRBACRolesEndpointReportsHonestAvailability proves the discovery surface is
// truthful and bounded, and carries no credential material.
func TestRBACRolesEndpointReportsHonestAvailability(t *testing.T) {
	server, _ := rbacTestServer(t, true, true)
	rec := rbacRequest(t, server.http.Handler.ServeHTTP, http.MethodGet, "/api/v1/auth/roles", rbacOperatorToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("roles endpoint status=%d", rec.Code)
	}
	body := rec.Body.String()
	for _, secret := range []string{rbacObserverSecret, rbacOperatorToken, string(rbacCriticalKey)} {
		if strings.Contains(body, secret) {
			t.Fatal("the roles endpoint leaked credential material")
		}
	}
	var payload struct {
		Role  string `json:"role"`
		Roles map[string]struct {
			Available bool `json:"available"`
		} `json:"roles"`
		UnavailableReasons []string `json:"unavailable_reasons"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Role != roleOperatorName {
		t.Fatalf("roles endpoint named the wrong caller role: %q", payload.Role)
	}
	if !payload.Roles["observer"].Available || !payload.Roles["critical_unlock"].Available {
		t.Fatalf("provisioned roles reported unavailable: %+v", payload.Roles)
	}
	// An observer sees its own role, and its answer is still bounded.
	observerRec := rbacRequest(t, server.http.Handler.ServeHTTP, http.MethodGet, "/api/v1/auth/roles", rbacObserverSecret, nil, nil)
	if observerRec.Code != http.StatusOK || !strings.Contains(observerRec.Body.String(), `"role":"observer"`) {
		t.Fatalf("observer roles answer=%d body=%q", observerRec.Code, observerRec.Body.String())
	}
	// A host without the optional files says so instead of pretending.
	plain, _ := rbacTestServer(t, false, false)
	plainRec := rbacRequest(t, plain.http.Handler.ServeHTTP, http.MethodGet, "/api/v1/auth/roles", rbacOperatorToken, nil, nil)
	if plainRec.Code != http.StatusOK {
		t.Fatalf("roles endpoint on a plain host status=%d", plainRec.Code)
	}
	var plainPayload struct {
		Roles map[string]struct {
			Available bool `json:"available"`
		} `json:"roles"`
		UnavailableReasons []string `json:"unavailable_reasons"`
	}
	if err := json.Unmarshal(plainRec.Body.Bytes(), &plainPayload); err != nil {
		t.Fatal(err)
	}
	if plainPayload.Roles["observer"].Available || plainPayload.Roles["critical_unlock"].Available {
		t.Fatal("a plain host reported optional roles as available")
	}
	if len(plainPayload.UnavailableReasons) != 2 {
		t.Fatalf("a plain host did not name both unavailable roles: %+v", plainPayload.UnavailableReasons)
	}
}

// TestRBACExistingOperatorBehaviourPreserved proves the role work did not weaken
// the existing authentication contract: operator token, origin check, empty
// credential and wrong credential behave exactly as before.
func TestRBACExistingOperatorBehaviourPreserved(t *testing.T) {
	server, _ := rbacTestServer(t, true, true)
	handler := server.auth(rbacSink(new(bool)))
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacOperatorToken, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("operator GET regressed: %d", rec.Code)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET was accepted: %d", rec.Code)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", "wrong", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential was accepted: %d", rec.Code)
	}
	if rec := rbacRequest(t, handler, http.MethodGet, "/api/v1/status", rbacOperatorToken, nil, func(r *http.Request) {
		r.Header.Set("Origin", "https://attacker.invalid")
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("a foreign origin was accepted: %d", rec.Code)
	}
	// The unaudited empty-token edge: an empty expected token never authenticates.
	emptyServer := &APIServer{token: ""}
	emptyHandler := emptyServer.auth(rbacSink(new(bool)))
	if rec := rbacRequest(t, emptyHandler, http.MethodGet, "/api/v1/status", "", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an empty credential authenticated against an empty expected token: %d", rec.Code)
	}
}

// TestRBACStepUpMACDomainSeparated proves the direct proof MAC is bound to its
// purpose: a MAC over a plain payload is not accepted as a step-up proof.
func TestRBACStepUpMACDomainSeparated(t *testing.T) {
	now := time.Now().UTC()
	expiry := now.Add(criticalStepUpTTL).Unix()
	nonce := strings.Repeat("ab", criticalStepUpNonceBytes)
	plain := hmac.New(sha256.New, rbacCriticalKey)
	plain.Write([]byte(directStepUpTokenHead + "|" + formatUnix(expiry) + "|" + nonce))
	token := directStepUpTokenHead + "|" + formatUnix(expiry) + "|" + nonce + "|" + hex.EncodeToString(plain.Sum(nil))
	if _, err := verifyCriticalStepUpProof(token, rbacCriticalKey, now, newNonceReplayCache(16)); err == nil {
		t.Fatal("a MAC without the domain separator was accepted as a step-up proof")
	}
}

// TestRBACGatewayClaimMACContractVector pins the cross-component claim MAC: the
// gateway producer and this verifier must reproduce the same bytes. A change to the
// domain separator, the field order or the timestamp encoding on either side would
// silently break the browser critical-action flow without breaking a local test.
func TestRBACGatewayClaimMACContractVector(t *testing.T) {
	const expected = "4ac29c78b0f3bc6fde1a802d90bccd02b7b689b8b58b28df0e670ec1aa7680df"
	got := hex.EncodeToString(gatewayClaimMAC([]byte("0123456789abcdef0123456789abcdef"), criticalStepUpPurpose, "password",
		1700000000, "abcdef0123456789abcdef0123456789"))
	if got != expected {
		t.Fatalf("the gateway claim MAC contract drifted: %s != %s", got, expected)
	}
}
