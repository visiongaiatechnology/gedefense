// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Request-security pipeline split out of server.go (refactoring wave 1a,
// structure-only): rate budgets, token read/rotation, gateway session attestation,
// authentication-denial evidence, the secure() header wrapper, auth(), the evidence
// gate and the dashboard CSP. The security audit reads the whole control/server*.go
// family for these literals; the mux registration and the JSON/error writers stay
// elsewhere (server.go / server_handlers_support.go).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// Rate budgets are split by trust state (F-08 / CHAIN-006):
//
//   - unauthenticated requests and failed authentication attempts consume a small
//     per-peer budget, so a local process cannot exhaust the operator budget;
//   - authenticated operator traffic consumes its own administered budget, keyed on
//     the gateway-attested session identity when the request came through the gateway
//     and on the credential fingerprint for direct loopback access;
//   - unauthenticated health/metrics probes have a separate budget and can never be
//     starved by, or starve, the operator console.
//
// None of these limits fails closed for identities that have no history: full visitor
// tables evict the least recently seen entry instead of denying every new client.
const (
	preAuthRatePerMinute = 30
	preAuthRateBurst     = 10
	healthRatePerMinute  = 120
	healthRateBurst      = 30
	// authDenialEvidenceGap bounds how often one peer can write an authentication
	// denial into the signed evidence chain. The denial is still always rejected;
	// the gap only keeps an unauthenticated flood from becoming a ledger-write DoS.
	authDenialEvidenceGap = 5 * time.Second
	gatewaySessionHeader  = "X-Gedefense-Gateway-Session"
	gatewaySessionDomain  = "VGT-GEDEFENSE-GATEWAY-SESSION\x00"
)

// ensureLimiters creates the split rate budgets for servers built without the
// constructor (several tests construct the struct directly) and for the production
// path. It is idempotent and concurrency safe.
func (s *APIServer) ensureLimiters() {
	s.limiterOnce.Do(func() {
		if s.limiter == nil {
			perMinute, burst := s.cfg.Dashboard.RateLimitPerMinute, s.cfg.Dashboard.RateLimitBurst
			if perMinute <= 0 {
				perMinute = 240
			}
			if burst <= 0 {
				burst = 40
			}
			s.limiter = NewRateLimiter(perMinute, burst)
		}
		if s.preAuthLimiter == nil {
			s.preAuthLimiter = NewRateLimiter(preAuthRatePerMinute, preAuthRateBurst)
		}
		if s.healthLimiter == nil {
			s.healthLimiter = NewRateLimiter(healthRatePerMinute, healthRateBurst)
		}
		if s.lockdownLimiter == nil {
			// One emergency trigger per minute is a deliberate ceiling, not a
			// suggestion: the latch is idempotent, so a second press changes nothing.
			s.lockdownLimiter = NewRateLimiter(1, 1)
		}
	})
}

func (s *APIServer) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if !s.hostAllowed(r.Host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		// Health and metrics probes have their own budget. The operator console and
		// unauthenticated retries are budgeted inside auth(), so a flood against a
		// health endpoint can never consume the operator's budget or vice versa.
		if isHealthSurface(r.URL.Path) {
			s.ensureLimiters()
			if !s.healthLimiter.Allow(remoteIdentity(r.RemoteAddr), time.Now()) {
				w.Header().Set("Retry-After", "2")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Origin-Agent-Cluster", "?1")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		// Every mutating body passes this ceiling before any handler sees it. A
		// handler that accepts less still accepts less; the administrable value can
		// only tighten, so one revision cannot widen every endpoint at once.
		//
		// POINT 2 / P2-T3: the parser-cell input route carries a document rather
		// than a control command and therefore has one explicit, fixed 12 MiB
		// base64 body bound (decoded <= MaxInputBytes <= 8 MiB). It is the only
		// exemption; every other mutating route keeps the global ceiling unchanged.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Body != nil {
			limit := s.apiPayloadLimit()
			if isParserCellInputRequest(r) {
				limit = parserCellInputBodyLimit
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			// HSTS is only meaningful on a TLS origin. Emitting it from a plain-HTTP
			// control port is noise that hides whether TLS is actually in effect.
			if r.TLS != nil {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isHealthSurface(path string) bool {
	switch path {
	case "/metrics", "/livez", "/readyz", "/healthz", "/bootz", "/panelz":
		return true
	}
	return false
}

func (s *APIServer) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	for _, allowed := range s.cfg.Dashboard.AllowedHosts {
		if strings.EqualFold(strings.Trim(allowed, "[]"), host) {
			return true
		}
	}
	return false
}

// evidenceGateExempt lists the endpoints that stay reachable while the evidence ledger
// is unavailable. Every entry is a route out of that condition, not an ordinary
// mutation; the audit guarantee is unchanged for everything else. See the call site for
// why each one is here.
func evidenceGateExempt(path string) bool {
	switch path {
	case "/api/v1/release/emergency-stop", // stopping the platform cannot need its audit trail
		"/api/v1/l7/selftest",        // a diagnostic must survive the condition it diagnoses
		"/api/v1/settings/integrity", // the remedy for a full ledger is itself a mutation
		// POINT 5 / P5-T3: an emergency lockdown trigger must not be blocked by a
		// broken audit trail, and the clear is the only way out of the latch the
		// trigger created. Both commit their own intent evidence before acting, so
		// the audit guarantee is documented-degraded rather than silently dropped.
		"/api/v1/lockdown/trigger",
		"/api/v1/lockdown/clear":
		return true
	}
	return false
}

// currentToken returns the token the dashboard has to present.
//
// The credential loaded at start-up stays in force; replacing the token file *afterwards* rotates it,
// and the change takes effect on the next request - no restart. That is the property a rotation needs,
// and it is also why a test that supplies its own token is not affected by whatever token file happens
// to exist on the machine running the tests.
//
// A file that cannot be read leaves the last known credential in force: an operator whose token file is
// temporarily unreadable must not be locked out of their own platform, and deleting the file grants no
// privilege - whoever can delete it can read it.
//
// The first authenticated request after a start reads the file instead of trusting the start-up value.
// Otherwise a rotation performed during the start-up window would be ignored: the old token would stay
// accepted and the freshly rotated one rejected, which silently defeats the only revocation a token
// rotation provides (F-21 / CHAIN-014). The stamp is only a fast path; the first read is always certified.
func (s *APIServer) currentToken() string {
	path := strings.TrimSpace(s.cfg.Dashboard.TokenFile)
	if path == "" {
		return s.token
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		if live := s.tokenLive.Load(); live != nil {
			return *live
		}
		return s.token
	}
	stamp := tokenFileStamp(info)
	if seen := s.tokenStamp.Load(); seen != 0 && seen == stamp {
		if live := s.tokenLive.Load(); live != nil {
			return *live
		}
		return s.token
	}
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	// Re-stat under the lock: a rotation that lands between the fast-path stat and this
	// point must still be observed.
	info, statErr = os.Stat(path)
	if statErr != nil {
		if live := s.tokenLive.Load(); live != nil {
			return *live
		}
		return s.token
	}
	stamp = tokenFileStamp(info)
	if seen := s.tokenStamp.Load(); seen != 0 && seen == stamp {
		if live := s.tokenLive.Load(); live != nil {
			return *live
		}
		return s.token
	}
	token, err := readDashboardToken(path)
	if err != nil {
		if live := s.tokenLive.Load(); live != nil {
			return *live
		}
		return s.token
	}
	s.tokenLive.Store(&token)
	s.tokenStamp.Store(stamp)
	return token
}

// tokenFileStamp folds the metadata a legitimate rotation changes into one comparable value.
func tokenFileStamp(info os.FileInfo) int64 {
	stamp := info.ModTime().UnixNano()
	stamp ^= info.Size() << 1
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp ^= int64(stat.Ino) << 17
		stamp ^= int64(stat.Ctim.Sec) << 3
		stamp ^= int64(stat.Ctim.Nsec) << 29
	}
	return stamp
}

// authenticatedRateIdentity keys the authenticated budget on what the gateway can attest.
//
// Dashboard traffic arrives from 127.0.0.1 at the loopback control plane and used to share one
// per-peer bucket, so one busy session could rate-limit every other session (G-WEB-01). The gateway
// now sets a session identifier bound to the backend credential; the control plane verifies the
// binding and keys the budget on it. Direct loopback clients fall back to a credential fingerprint.
func (s *APIServer) authenticatedRateIdentity(r *http.Request, token string) string {
	if sessionID, ok := s.attestedGatewaySession(r, token); ok {
		return "gateway:" + sessionID
	}
	digest := sha256.Sum256([]byte(token))
	return "operator:" + hex.EncodeToString(digest[:8])
}

// attestedGatewaySession verifies the gateway's HMAC binding of one session identifier. A forged or
// absent header simply falls back to the credential identity; it can never widen a budget.
func (s *APIServer) attestedGatewaySession(r *http.Request, token string) (string, bool) {
	value := strings.TrimSpace(r.Header.Get(gatewaySessionHeader))
	parts := strings.Split(value, ".")
	if len(parts) != 2 || len(parts[0]) < 16 || len(parts[0]) > 128 || len(parts[1]) != sha256.Size*2 {
		return "", false
	}
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(gatewaySessionDomain))
	mac.Write([]byte(parts[0]))
	expected, err := hex.DecodeString(parts[1])
	if err != nil || !hmac.Equal(expected, mac.Sum(nil)) {
		return "", false
	}
	return parts[0], true
}

// recordAuthDenial writes an authentication denial into the signed evidence trail (F-19).
//
// The write is bounded per peer: a denial is always rejected, but an unauthenticated flood must not
// turn into a ledger-write amplification. When no ledger is attached the denial is logged instead,
// so the operation is never silent.
func (s *APIServer) recordAuthDenial(r *http.Request, reason string) {
	identity := remoteIdentity(r.RemoteAddr)
	now := time.Now()
	s.denialMu.Lock()
	if s.denialSeen == nil {
		s.denialSeen = make(map[string]time.Time)
	}
	if last, ok := s.denialSeen[identity]; ok && now.Sub(last) < authDenialEvidenceGap {
		s.denialMu.Unlock()
		return
	}
	if len(s.denialSeen) >= 1024 {
		for key, at := range s.denialSeen {
			if now.Sub(at) > 10*authDenialEvidenceGap {
				delete(s.denialSeen, key)
			}
		}
	}
	s.denialSeen[identity] = now
	s.denialMu.Unlock()

	message := "Control-plane authentication denied: " + reason
	if s.state == nil || s.state.EvidenceLedger() == nil {
		log.Printf("auth denial remote=%q method=%q path=%q reason=%q", identity, r.Method, r.URL.Path, reason)
		return
	}
	if err := s.state.RecordEvidence(EvidenceRecord{
		Severity: "warning", Kind: "auth.denial", Source: "access-gateway",
		Message: message, Target: r.Method + " " + r.URL.Path,
		RequestID: r.Header.Get("X-VGT-Request-ID"),
	}); err != nil {
		log.Printf("auth denial evidence failed: %v", err)
	}
}

func (s *APIServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			expected := "http://" + r.Host
			if r.TLS != nil {
				expected = "https://" + r.Host
			}
			if o != expected {
				http.Error(w, "origin rejected", http.StatusForbidden)
				return
			}
		}
		s.ensureLimiters()
		now := time.Now()
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		// V6.3.0 AP-9 (R6): the presented credential classifies the role. The
		// operator token keeps its exact precedence and behaviour; the optional
		// observer credential is only consulted for a token that is not the
		// operator token. An empty credential is never a match, whatever the
		// expected token is: tokenEqual("", "") is true, so a request without an
		// Authorization header would otherwise authenticate the moment the expected
		// token became empty - which is exactly the state a token file that cannot
		// be read produces.
		role, credentialValid := s.classifyCredential(got)
		if got == "" || !credentialValid {
			remote := remoteIdentity(r.RemoteAddr)
			// V6.3.0 AP-9 (R6): bounded brute-force lockout. A source that keeps
			// presenting unknown credentials is refused with 429 for a fixed window
			// instead of being able to keep guessing. A valid credential never
			// reaches this branch, so another source's failures cannot lock the
			// operator out of their own platform: the lockout bounds guessing, it is
			// not a second factor.
			if locked, retryAfter := s.tokenLockout().locked(remote); locked {
				w.Header().Set("Retry-After", retryAfterSeconds(retryAfter))
				http.Error(w, "authentication temporarily locked", http.StatusTooManyRequests)
				return
			}
			// Unauthenticated requests and failed attempts draw from the pre-auth budget only.
			// Exhausting it can no longer lock an authenticated operator console out (F-08).
			if !s.preAuthLimiter.Allow(remote, now) {
				w.Header().Set("Retry-After", "5")
				s.recordAuthDenial(r, "authentication rate limit exceeded")
				http.Error(w, "authentication rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			if _, _, fresh := s.tokenLockout().fail(remote); fresh {
				s.reportRBACEvent("warning", "rbac.lockout",
					"Management-API authentication locked out a source after repeated unknown credentials")
			}
			s.recordAuthDenial(r, "authorization required")
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "authorization required", http.StatusUnauthorized)
			return
		}
		s.tokenLockout().success(remoteIdentity(r.RemoteAddr))
		if !s.limiter.Allow(s.authenticatedRateIdentity(r, got), now) {
			w.Header().Set("Retry-After", "2")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		// V6.3.0 AP-9 (R6): role and Critical-Unlock enforcement. It runs after the
		// credential and rate gates and before the mutation replay/evidence gates,
		// so a refused request records no operator-mutation intent.
		if !s.enforceManagementRole(w, r, role, s.currentToken()) {
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.replay.ClaimFor(s.authenticatedRateIdentity(r, got), r.Header.Get("X-VGT-Request-ID"), time.Now()) {
				http.Error(w, "request identifier missing or replayed", http.StatusConflict)
				return
			}
			if s.state != nil && s.state.EvidenceLedger() != nil {
				// A closed evidence gate must not seal the exits from its own condition.
				//
				// The gate exists so an operator mutation is never accepted without an
				// audit record, and that stays true for everything else. Three endpoints
				// have to remain reachable while the ledger is unavailable, because each
				// is a way out of the condition rather than an ordinary action:
				//
				//   emergency stop  - stopping the platform cannot depend on its audit
				//                     trail being writable.
				//   L7 self-test    - a diagnostic that cannot run while the platform is
				//                     degraded is not a diagnostic. Without this the
				//                     operator sees "mandatory evidence ledger unavailable"
				//                     reported as a traffic-path failure, which diagnoses
				//                     the wrong subsystem entirely.
				//   integrity apply - a full ledger is remedied by raising its budget or
				//                     rotating it, and both are mutations. Gating the
				//                     remedy behind the condition deadlocked the operator
				//                     with no route out through the interface at all.
				exempt := evidenceGateExempt(r.URL.Path)
				if message, err := s.state.EvidenceGateCondition(); err != nil && !exempt {
					apiError(w, http.StatusServiceUnavailable, message, err)
					return
				}
				if err := s.state.RecordEvidence(EvidenceRecord{
					Severity: "high", Kind: "operator.mutation.intent", Source: "access-gateway",
					Message: "Authenticated operator mutation accepted for processing",
					Target:  r.Method + " " + r.URL.Path, RequestID: r.Header.Get("X-VGT-Request-ID"),
				}); err != nil && !exempt {
					apiError(w, http.StatusServiceUnavailable, "mandatory evidence commit failed", err)
					return
				}
			}
		}
		next(w, withRole(r, role))
	}
}

// contentSecurityPolicy is the single source of truth for the dashboard policy.
//
// The application ships no inline script and no inline style, so neither
// 'unsafe-inline' nor 'unsafe-eval' is needed and neither is granted. Trusted
// Types makes the absence of DOM-XSS sinks a runtime invariant instead of a
// property that only a source scan checks: any future assignment to a script
// sink raises instead of executing.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"font-src 'none'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"manifest-src 'self'; " +
	"worker-src 'none'; " +
	"require-trusted-types-for 'script'"

// gatewayAuthDenials accepts authentication-denial reports from the access gateway. The
// gateway is the only component that sees the public remote address at the login form, and
// its failures belong in the same signed evidence trail as the control plane's own
// denials (F-19). The report is authenticated with the backend credential, bounded and
// de-duplicated before it reaches the ledger.
func (s *APIServer) gatewayAuthDenials(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Remote string `json:"remote"`
		Reason string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 4<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid gateway denial report", err)
		return
	}
	remote := strings.TrimSpace(in.Remote)
	reason := strings.TrimSpace(in.Reason)
	if len(remote) == 0 || len(remote) > 128 || len(reason) == 0 || len(reason) > 160 {
		apiError(w, http.StatusBadRequest, "invalid gateway denial report", nil)
		return
	}
	if s.state != nil {
		_ = s.state.RecordEvidence(EvidenceRecord{
			Severity: "warning", Kind: "auth.denial", Source: "access-gateway",
			Message: "Gateway operator authentication denied: " + reason,
			Target:  "remote=" + remote,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}
