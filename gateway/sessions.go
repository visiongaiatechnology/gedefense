package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The gateway session used to be a stateless HMAC cookie: validSession only checked the MAC
// and the expiry, so logout could delete the browser cookie but not the authority behind it,
// and a copied cookie stayed valid for its full 12-hour life (F-09 / CHAIN-007).
//
// A session is now a server-side record with an absolute lifetime, a sliding idle timeout and
// an explicit revocation list. The cookie carries only the random session id plus the signed
// expiry; every request is checked against the registry. Because the registry is in memory,
// a restart invalidates every existing session - the strongest form of revocation, and it
// means a killed session can never be resurrected from a cookie after a restart.
const (
	sessionAbsoluteLifetime = 8 * time.Hour
	sessionIdleTimeout      = 30 * time.Minute
	sessionRotationInterval = 15 * time.Minute
	sessionRotationGrace    = 30 * time.Second
	maxGatewaySessions      = 64
)

const gatewaySessionHeaderName = "X-Gedefense-Gateway-Session"

// gatewaySessionBinding binds one server-side session id to the backend credential. The
// control plane verifies this HMAC before it keys an authenticated rate budget on the id;
// a client-supplied value cannot widen its own budget.
func gatewaySessionBinding(backendToken, sessionID string) string {
	mac := hmac.New(sha256.New, []byte(backendToken))
	mac.Write([]byte("VGT-GEDEFENSE-GATEWAY-SESSION\x00"))
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

var errSessionCapacity = errors.New("gateway session capacity reached")

type gatewaySession struct {
	id                 string
	previousID         string
	previousValidUntil time.Time
	created            time.Time
	rotatedAt          time.Time
	lastSeen           time.Time
	expires            time.Time
}

type sessionRegistry struct {
	mu         sync.Mutex
	sessions   map[string]*gatewaySession
	maxEntries int
	absolute   time.Duration
	idle       time.Duration
	rotation   time.Duration
	now        func() time.Time
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions:   make(map[string]*gatewaySession),
		maxEntries: maxGatewaySessions,
		absolute:   sessionAbsoluteLifetime,
		idle:       sessionIdleTimeout,
		rotation:   sessionRotationInterval,
		now:        time.Now,
	}
}

func randomSessionID() (string, error) {
	raw := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// create registers a new session with the requested absolute expiry. An expiry in the past
// produces an already-dead record, which keeps the existing "expired cookie is rejected"
// contract without a special case.
func (r *sessionRegistry) create(expires time.Time) (*gatewaySession, error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked(now)
	if len(r.sessions) >= r.maxEntries {
		// Reclaim the least recently used record instead of refusing every new operator:
		// a full table must not become a denial of service against the sign-in page.
		var oldest *gatewaySession
		for _, session := range r.sessions {
			if oldest == nil || session.lastSeen.Before(oldest.lastSeen) {
				oldest = session
			}
		}
		if oldest != nil {
			r.deleteLocked(oldest)
		}
	}
	id, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	if expires.IsZero() || expires.After(now.Add(r.absolute)) {
		expires = now.Add(r.absolute)
	}
	session := &gatewaySession{
		id: id, created: now, rotatedAt: now, lastSeen: now, expires: expires,
	}
	r.sessions[id] = session
	return session, nil
}

func (r *sessionRegistry) gcLocked(now time.Time) {
	for id, session := range r.sessions {
		if !now.Before(session.expires) || now.Sub(session.lastSeen) > r.idle {
			r.deleteLocked(session)
			delete(r.sessions, id)
		}
	}
}

func (r *sessionRegistry) deleteLocked(session *gatewaySession) {
	if session == nil {
		return
	}
	delete(r.sessions, session.id)
	if session.previousID != "" {
		delete(r.sessions, session.previousID)
	}
}

// validate resolves the session id, enforces absolute and idle expiry, records activity and
// accepts the previous id inside the rotation grace window so concurrent requests do not fail
// in the middle of a rotation.
func (r *sessionRegistry) validate(id string) (*gatewaySession, bool) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[id]
	if !ok {
		return nil, false
	}
	if session.id != id {
		if session.previousID != id || !now.Before(session.previousValidUntil) {
			delete(r.sessions, id)
			return nil, false
		}
	}
	if !now.Before(session.expires) || now.Sub(session.lastSeen) > r.idle || now.Sub(session.created) > r.absolute {
		r.deleteLocked(session)
		return nil, false
	}
	session.lastSeen = now
	return session, true
}

// rotate issues a fresh session id for an existing session. The old id stays valid for a short
// grace window; the operator's cookie is replaced in the same response.
func (r *sessionRegistry) rotate(session *gatewaySession) (*gatewaySession, error) {
	if session == nil {
		return nil, errors.New("session is unavailable")
	}
	now := r.now()
	id, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session.previousID = session.id
	session.previousValidUntil = now.Add(sessionRotationGrace)
	delete(r.sessions, session.id)
	session.id = id
	session.rotatedAt = now
	session.lastSeen = now
	r.sessions[id] = session
	r.sessions[session.previousID] = session
	return session, nil
}

func (r *sessionRegistry) revoke(session *gatewaySession) {
	if session == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteLocked(session)
}

func (r *sessionRegistry) revokeAll() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	revoked := 0
	for _, session := range r.sessions {
		if session.id == "" {
			continue
		}
		revoked++
	}
	r.sessions = make(map[string]*gatewaySession)
	return revoked
}

func (r *sessionRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, session := range r.sessions {
		if session.id != "" {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------- cookies

type gatewaySessionContextKey struct{}

func sessionIDFromContext(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(gatewaySessionContextKey{}).(string)
	return value, ok && value != ""
}

// sessionCookiePayload is "expiryUnix.sessionID". The MAC binds both fields under a domain
// separator so a cookie cannot be replayed against another purpose.
func (g *gateway) sessionCookiePayload(session *gatewaySession) string {
	return strconv.FormatInt(session.expires.UTC().Unix(), 10) + "." + session.id
}

func (g *gateway) signSessionPayload(payload string) string {
	mac := hmac.New(sha256.New, g.sessionKey)
	mac.Write([]byte("VGT-GEDEFENSE-ACCESS-COOKIE-V3\x00"))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// parseSessionCookie verifies the MAC and returns the session id and expiry.
func (g *gateway) parseSessionCookie(r *http.Request) (string, time.Time, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", time.Time{}, false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return "", time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", time.Time{}, false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size {
		return "", time.Time{}, false
	}
	mac := hmac.New(sha256.New, g.sessionKey)
	mac.Write([]byte("VGT-GEDEFENSE-ACCESS-COOKIE-V3\x00"))
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", time.Time{}, false
	}
	fields := strings.Split(string(payload), ".")
	if len(fields) != 2 {
		return "", time.Time{}, false
	}
	expiry, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || len(fields[1]) < 16 || len(fields[1]) > 128 {
		return "", time.Time{}, false
	}
	now := time.Now()
	if now.Unix() > expiry || expiry > now.Add(sessionAbsoluteLifetime+time.Hour).Unix() {
		return "", time.Time{}, false
	}
	return fields[1], time.Unix(expiry, 0).UTC(), true
}

// validateSession resolves a cookie to a live server-side session (rotation-aware when a
// response writer is supplied) and returns the session for context attribution.
func (g *gateway) validateSession(w http.ResponseWriter, r *http.Request) (*gatewaySession, bool) {
	id, _, ok := g.parseSessionCookie(r)
	if !ok {
		return nil, false
	}
	g.ensureSessions()
	session, ok := g.sessions.validate(id)
	if !ok {
		return nil, false
	}
	if time.Since(session.rotatedAt) >= sessionRotationInterval {
		if rotated, err := g.sessions.rotate(session); err == nil {
			if w != nil {
				http.SetCookie(w, g.sessionCookie(rotated))
			}
			session = rotated
		}
	}
	return session, true
}

func (g *gateway) sessionCookie(session *gatewaySession) *http.Cookie {
	remaining := int(time.Until(session.expires).Seconds())
	if remaining < 60 {
		remaining = 60
	}
	return &http.Cookie{
		Name: cookieName, Value: g.signSessionPayload(g.sessionCookiePayload(session)),
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: remaining, Expires: session.expires,
	}
}

func (g *gateway) ensureSessions() {
	g.sessionsOnce.Do(func() {
		if g.sessions == nil {
			g.sessions = newSessionRegistry()
		}
	})
}

// sessionStatus reports this browser's server-side session facts.
func (g *gateway) sessionStatus(w http.ResponseWriter, r *http.Request) {
	session, ok := g.validateSession(w, r)
	if !ok {
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}
	payload := map[string]any{
		"authenticated":        true,
		"session_id":           shortSessionID(session.id),
		"created_utc":          session.created.UTC(),
		"last_seen_utc":        session.lastSeen.UTC(),
		"expires_utc":          session.expires.UTC(),
		"idle_seconds":         int(sessionIdleTimeout.Seconds()),
		"absolute_seconds":     int(sessionAbsoluteLifetime.Seconds()),
		"rotate_after_seconds": int(sessionRotationInterval.Seconds()),
		"sessions_total":       g.sessions.count(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// rotateSession handles an explicit rotation request. The control plane treats a rotated id
// as a new identity; the old id is only accepted for the grace window.
func (g *gateway) rotateSession(w http.ResponseWriter, r *http.Request) {
	session, ok := g.validateSession(nil, r)
	if !ok {
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}
	if !g.sameOriginRequired(r) {
		http.Error(w, "origin rejected", http.StatusForbidden)
		return
	}
	rotated, err := g.sessions.rotate(session)
	if err != nil {
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, g.sessionCookie(rotated))
	w.WriteHeader(http.StatusNoContent)
}

// revokeAllSessions is the incident-response switch: every browser session dies immediately,
// including the caller's own. It requires a typed confirmation and a reason, because it locks
// every operator out and is itself a security-relevant action.
func (g *gateway) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	session, ok := g.validateSession(nil, r)
	if !ok {
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}
	if !g.sameOriginRequired(r) {
		http.Error(w, "origin rejected", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var in struct {
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, `{"error":"confirmation required: REVOKE ALL SESSIONS"}`, http.StatusBadRequest)
		return
	}
	if in.Confirmation != "REVOKE ALL SESSIONS" || len([]rune(in.Reason)) < 8 || len([]rune(in.Reason)) > 240 {
		http.Error(w, `{"error":"confirmation required: REVOKE ALL SESSIONS"}`, http.StatusBadRequest)
		return
	}
	revoked := g.sessions.revokeAll()
	_ = session
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": false, "revoked": revoked})
}

func shortSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:6])
}
