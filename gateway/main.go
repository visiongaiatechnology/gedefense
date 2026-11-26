// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "6.3.0-access"
const cookieName = "__Host-vgt_gedefense_session"
const csrfCookieName = "vgt_gedefense_login_csrf"

var (
	listenFlag           = flag.String("listen", "0.0.0.0:9843", "public HTTPS listen address")
	backendFlag          = flag.String("backend", "http://127.0.0.1:9844", "internal GeDefense backend")
	publicHostFlag       = flag.String("public-host", "", "allowed public host or IP, optionally with port")
	passwordFileFlag     = flag.String("password-file", "/etc/vgt/gedefense/access-password", "password record")
	sessionKeyFileFlag   = flag.String("session-key-file", "/var/lib/vgt/gedefense/access-session.key", "session key")
	backendTokenFileFlag = flag.String("backend-token-file", "/var/lib/vgt/gedefense/dashboard.token", "backend bearer token")
	claimKeyFileFlag     = flag.String("claim-key-file", "", "dedicated HMAC key for gateway critical claims")
	tlsCertFlag          = flag.String("tls-cert", "/etc/vgt/gedefense/tls/access.crt", "TLS certificate")
	tlsKeyFlag           = flag.String("tls-key", "/etc/vgt/gedefense/tls/access.key", "TLS private key")
	showVersionFlag      = flag.Bool("version", false, "show version")
	generateCertFlag     = flag.Bool("generate-self-signed", false, "generate a self-signed certificate and exit")
	selfTestFlag         = flag.Bool("self-test-backend", false, "verify authenticated backend access and exit")
	hashPasswordFlag     = flag.Bool("hash-password-stdin", false, "read a password from stdin and print an Argon2id record")
	verifyPasswordFlag   = flag.Bool("verify-password-stdin", false, "verify a password from stdin against the record and exit")
)

type gateway struct {
	publicHost   string
	publicOrigin string
	backend      *url.URL
	passwordMu   sync.RWMutex
	password     passwordRecord
	passwordPath string
	sessionKey   []byte
	backendToken string
	claimKey     []byte
	proxy        *httputil.ReverseProxy
	limiter      *limiter
	// FIND-010: one process-wide admission gate in front of the memory-hard
	// password KDF. It is created lazily so gateway literals in tests keep working.
	kdf     *kdfGate
	kdfOnce sync.Once
	// sessions is the server-side registry that makes logout/revocation/idle timeouts
	// effective (F-09). It is created lazily so tests that build a gateway literal keep
	// working.
	sessions     *sessionRegistry
	sessionsOnce sync.Once
	// V6.3.0 AP-9 (R6): password step-up proofs and their bounded brute-force
	// lockout. Created lazily for the same reason as the session registry.
	stepUp     *stepUpAuthority
	stepUpOnce sync.Once
	// denial reporting to the control plane is de-duplicated so one flood cannot turn
	// into a request amplification (F-19).
	denialMu         sync.Mutex
	lastDenialReport time.Time
	// The public access gateway is a management plane, not a general-purpose reverse
	// proxy. Its source policy is the control plane's ManagementAllowlist, refreshed
	// from the authenticated backend status. It is fail-closed: until a valid list is
	// loaded, public clients are rejected; loopback health/operator access remains
	// available. Tests that construct a gateway literal leave allowlistEnforced false.
	allowlistMu       sync.RWMutex
	allowlist         []netip.Prefix
	allowlistEnforced bool
}

func main() {
	flag.Parse()
	if *hashPasswordFlag {
		password, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
		if err != nil {
			log.Fatal(err)
		}
		password = []byte(strings.TrimRight(string(password), "\r\n"))
		if len(password) < 12 || len(password) > 1024 {
			zero(password)
			log.Fatal("password must contain 12-1024 bytes")
		}
		record, err := createArgon2PasswordRecord(password)
		zero(password)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(record)
		return
	}
	if *showVersionFlag {
		fmt.Println(version)
		return
	}
	if *verifyPasswordFlag {
		// FIND-009: the privileged set-password helper uses this non-interactive
		// verification path to bind a password change to the current operator
		// credential before it overwrites the record. Only a generic verdict is
		// written; neither the password nor the record is echoed.
		password, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
		if err != nil {
			log.Fatal(err)
		}
		password = []byte(strings.TrimRight(string(password), "\r\n"))
		record, err := loadPasswordRecord(*passwordFileFlag)
		if err != nil {
			zero(password)
			fmt.Fprintln(os.Stderr, "password record is unavailable")
			os.Exit(1)
		}
		verified := verifyPassword(password, record)
		zero(password)
		if !verified {
			fmt.Fprintln(os.Stderr, "password verification failed")
			os.Exit(1)
		}
		return
	}
	if *publicHostFlag == "" {
		log.Fatal("public-host is required")
	}
	publicHost, err := canonicalHostPort(*publicHostFlag, *listenFlag)
	if err != nil {
		log.Fatal(err)
	}
	listenHost, _, err := net.SplitHostPort(*listenFlag)
	if err != nil {
		log.Fatal("invalid listen address")
	}
	loopbackListener := isLoopbackHost(strings.Trim(listenHost, "[]"))
	if *generateCertFlag {
		if err := generateSelfSigned(publicHost, *tlsCertFlag, *tlsKeyFlag); err != nil {
			log.Fatal(err)
		}
		return
	}
	backendURL, err := url.Parse(*backendFlag)
	if err != nil || backendURL.Scheme != "http" || backendURL.Host == "" || backendURL.Path != "" {
		log.Fatal("backend must be an absolute loopback HTTP URL without path")
	}
	if !isLoopbackHost(backendURL.Hostname()) {
		log.Fatal("backend must use a loopback address")
	}
	password, err := loadPasswordRecord(*passwordFileFlag)
	if err != nil {
		log.Fatalf("password record: %v", err)
	}
	sessionKey, err := readPrivateRegular(*sessionKeyFileFlag, 32, 32)
	if err != nil {
		log.Fatalf("session key: %v", err)
	}
	tokenBytes, err := readPrivateRegular(*backendTokenFileFlag, 32, 512)
	if err != nil {
		log.Fatalf("backend token: %v", err)
	}
	backendToken := strings.TrimSpace(string(tokenBytes))
	if len(backendToken) < 32 {
		log.Fatal("backend token too short")
	}
	var claimKey []byte
	if path := strings.TrimSpace(*claimKeyFileFlag); path != "" {
		claimKey, err = readPrivateRegular(path, 32, 4096)
		if err != nil {
			log.Fatalf("gateway claim key: %v", err)
		}
	} else {
		adjacent := *backendTokenFileFlag + ".gateway-claim"
		claimKey, err = readPrivateRegular(adjacent, 32, 4096)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Fatalf("adjacent gateway claim key: %v", err)
			}
			log.Printf("gateway critical claim key not provisioned (%s); browser critical-unlock will fail closed with 503", adjacent)
			claimKey = nil
		}
	}
	if err := validateTLSFiles(*tlsCertFlag, *tlsKeyFlag); err != nil {
		log.Fatal(err)
	}

	bootNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bootNonce); err != nil {
		log.Fatal(err)
	}
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write([]byte("VGT-GEDEFENSE-ACCESS-SESSION-V2\x00"))
	mac.Write(bootNonce)
	derivedSessionKey := mac.Sum(nil)

	g := &gateway{
		publicHost:        publicHost,
		publicOrigin:      "https://" + publicHost,
		backend:           backendURL,
		password:          password,
		passwordPath:      *passwordFileFlag,
		sessionKey:        derivedSessionKey,
		backendToken:      backendToken,
		claimKey:          claimKey,
		limiter:           newLimiter(),
		allowlistEnforced: true,
	}
	g.proxy = g.newProxy()
	// Load before the listener starts; a transient backend failure denies public clients
	// rather than opening a window in which the management gateway accepts everyone.
	if err := g.refreshManagementAllowlist(); err != nil {
		log.Printf("management allowlist unavailable at startup; public access denied until refresh: %v", err)
	}
	go g.refreshManagementAllowlistLoop()

	if *selfTestFlag {
		if err := g.selfTestBackend(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("backend authenticated proxy preflight: ok")
		return
	}

	mux := g.routes()

	server := &http.Server{
		Addr:              *listenFlag,
		Handler:           g.security(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         hardenedTLSConfig(loopbackListener),
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("GeDefense access gateway %s listening on %s for %s", version, *listenFlag, g.publicOrigin)
	err = server.ListenAndServeTLS(*tlsCertFlag, *tlsKeyFlag)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// routes builds the public gateway mux. There is deliberately no anonymous
// build/version surface (FIND-012): /gateway/livez answers only whether the process
// is up and carries no build metadata, and every other path except the branded
// sign-in page and its two static marks is resolved by the server-side session gate
// (or proxied behind it). The retired build path is answered as a plain not-found so
// no client can obtain a 200 or a version string from it.
func (g *gateway) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /gateway/livez", g.livez)
	// FIND-012: explicit removal marker for the retired anonymous build path. It only
	// ever produces a plain 404 - the same answer as any other unknown path - and
	// never a version string.
	mux.HandleFunc("GET /gateway/version", g.removed)
	mux.HandleFunc("GET /gateway/session", g.sessionStatus)
	mux.HandleFunc("POST /gateway/session/rotate", g.rotateSession)
	mux.HandleFunc("POST /gateway/session/revoke-all", g.revokeAllSessions)
	// V6.3.0 AP-9 (R6): password re-authentication for the destructive
	// control-plane actions. It returns an opaque, TTL-bounded, single-use proof
	// that the browser presents once on the critical request (gateway/stepup.go).
	mux.HandleFunc("POST /gateway/step-up", g.stepUpRoute)
	// The mark is served before authentication because the login page needs it. It is a
	// static embedded image with no user input in its path, so there is nothing to
	// validate and nothing it can disclose.
	mux.HandleFunc("GET /gateway/logo.png", g.logo)
	mux.HandleFunc("GET /gateway/sirdu.png", g.mascot)
	mux.HandleFunc("GET /login", g.loginPage)
	mux.HandleFunc("POST /login", g.login)
	mux.HandleFunc("POST /logout", g.logout)
	mux.HandleFunc("/", g.protectedProxy)
	return mux
}

// removed answers a retired endpoint without revealing anything about the build or
// the host. It is intentionally not a redirect: an anonymous client learns only that
// this path does not exist.
func (g *gateway) removed(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// stripHopByHopHeaders removes the RFC 7230 hop-by-hop set and, more
// importantly, every header the client nominated in Connection. Go's
// ReverseProxy performs the same removal after Director returns; if the
// nomination survived until then it would delete the attested Authorization and
// gateway-session headers this function's caller sets afterwards (FIND-005).
func stripHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if name := strings.TrimSpace(token); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

func (g *gateway) newProxy() *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(g.backend)
	original := proxy.Director
	proxy.Director = func(r *http.Request) {
		original(r)
		// FIND-005 (VGT-AUDIT-2026-11-19): strip hop-by-hop headers and every
		// header named by the client's Connection header *before* the attested
		// backend headers are set. Go's ReverseProxy removes Connection-named
		// headers after Director returns; without this, a client could nominate
		// Authorization or the gateway-session header for removal and collapse
		// every request into one backend rate bucket.
		stripHopByHopHeaders(r.Header)
		// V6.3.0 AP-9 (R6): the browser never controls the critical role claim or
		// the one-time step-up proof. They are always dropped here and the claim is
		// only re-added from the server-verified value in the request context.
		for _, header := range []string{
			gatewayRoleHeader, gatewayStepUpHeader, gatewayClaimTsHeader, gatewayClaimMACHeader, gatewayStepUpProofHeader,
		} {
			r.Header.Del(header)
		}
		// Trust-boundary reset: the internal backend must never see browser origin,
		// public cookies, or public forwarding metadata.
		r.Host = g.backend.Host
		for _, header := range []string{
			"Origin", "Referer", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
			"X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server", "X-Real-IP",
			"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User",
			"Authorization",
		} {
			r.Header.Del(header)
		}
		// A nil X-Forwarded-For slice tells net/http/httputil not to append the
		// public client address after Director returns. The internal control plane
		// receives no browser-controlled forwarding identity.
		r.Header["X-Forwarded-For"] = nil
		r.Header.Set("Authorization", "Bearer "+g.backendToken)
		r.Header.Set("X-VGT-Gateway", "direct-access-v2")
		// The backend keys its authenticated rate budget on the attested session identity.
		// The identifier is not client-controlled: it comes from the server-side registry
		// and is bound to the backend credential by an HMAC the control plane can verify
		// (F-08 / G-WEB-01). Without this header every dashboard request shares one
		// loopback bucket and one session can starve all others.
		if sessionID, ok := sessionIDFromContext(r.Context()); ok {
			r.Header.Set(gatewaySessionHeaderName, sessionID+"."+gatewaySessionBinding(g.backendToken, sessionID))
		}
		// V6.3.0 AP-9 (R6): the MACed role claim of a verified password step-up.
		// It is bound to the backend credential the control plane already verifies,
		// bounded to a 30-second window and replay-bounded by its nonce there.
		if claim, ok := r.Context().Value(gatewayCriticalClaimKey{}).(gatewayCriticalClaimHeaders); ok {
			r.Header.Set(gatewayRoleHeader, claim.Role)
			r.Header.Set(gatewayStepUpHeader, claim.StepUp)
			r.Header.Set(gatewayClaimTsHeader, formatGatewayUnix(claim.Timestamp))
			r.Header.Set(gatewayClaimMACHeader, claim.MAC)
		}
	}
	proxy.FlushInterval = -1
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("backend proxy failure path=%q: %v", r.URL.Path, err)
		http.Error(w, "backend unavailable", http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Set-Cookie")
		resp.Header.Del("Strict-Transport-Security")
		return nil
	}
	return proxy
}

func (g *gateway) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameHost(r.Host, g.publicHost) && !g.allowHost(r.Host) {
			http.Error(w, "host rejected", http.StatusBadRequest)
			return
		}
		if !g.managementAllowed(r.RemoteAddr) {
			http.Error(w, "request rejected", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Origin-Agent-Cluster", "?1")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (g *gateway) livez(w http.ResponseWriter, _ *http.Request) {
	// Unauthenticated liveness must not disclose the build or posture of the host. It
	// answers one question - the process is up - and nothing else (F-23 / CHAIN-007).
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"ok":true}`)
}

func clientIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

// These wrappers are defined in crypto_helpers.go to keep imports explicit.
