package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "1.0.0-beta.5-access"
const cookieName = "__Host-vgt_gedefense_session"
const csrfCookieName = "vgt_gedefense_login_csrf"
const languageCookieName = "vgt_gedefense_lang"

var (
	listenFlag           = flag.String("listen", "0.0.0.0:9843", "public HTTPS listen address")
	backendFlag          = flag.String("backend", "http://127.0.0.1:9844", "internal GeDefense backend")
	publicHostFlag       = flag.String("public-host", "", "allowed public host or IP, optionally with port")
	passwordFileFlag     = flag.String("password-file", "/etc/vgt/gedefense/access-password", "password record")
	sessionKeyFileFlag   = flag.String("session-key-file", "/var/lib/vgt/gedefense/access-session.key", "session key")
	backendTokenFileFlag = flag.String("backend-token-file", "/var/lib/vgt/gedefense/dashboard.token", "backend bearer token")
	tlsCertFlag          = flag.String("tls-cert", "/etc/vgt/gedefense/tls/access.crt", "TLS certificate")
	tlsKeyFlag           = flag.String("tls-key", "/etc/vgt/gedefense/tls/access.key", "TLS private key")
	showVersionFlag      = flag.Bool("version", false, "show version")
	generateCertFlag     = flag.Bool("generate-self-signed", false, "generate a self-signed certificate and exit")
	selfTestFlag         = flag.Bool("self-test-backend", false, "verify authenticated backend access and exit")
	hashPasswordFlag     = flag.Bool("hash-password-stdin", false, "read a password from stdin and print an Argon2id record")
)

type passwordRecord struct {
	algorithm   string
	iterations  int
	memoryKiB   uint32
	timeCost    uint32
	parallelism uint32
	salt        []byte
	digest      []byte
}

type attemptWindow struct {
	failures []time.Time
}

type limiter struct {
	mu         sync.Mutex
	entries    map[string]*attemptWindow
	maxEntries int
}

func newLimiter() *limiter {
	return &limiter{entries: make(map[string]*attemptWindow), maxEntries: 4096}
}

func (l *limiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-15 * time.Minute)
	w := l.entries[ip]
	if w == nil {
		if len(l.entries) >= l.maxEntries {
			for key, value := range l.entries {
				if len(value.failures) == 0 || value.failures[len(value.failures)-1].Before(cutoff) {
					delete(l.entries, key)
				}
			}
			if len(l.entries) >= l.maxEntries {
				return false
			}
		}
		w = &attemptWindow{}
		l.entries[ip] = w
	}
	kept := w.failures[:0]
	for _, t := range w.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	w.failures = kept
	return len(w.failures) < 5
}

func (l *limiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.entries[ip]
	if w == nil {
		w = &attemptWindow{}
		l.entries[ip] = w
	}
	w.failures = append(w.failures, now)
}

func (l *limiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

type gateway struct {
	publicHost   string
	publicOrigin string
	backend      *url.URL
	password     passwordRecord
	passwordPath string
	sessionKey   []byte
	backendToken string
	proxy        *httputil.ReverseProxy
	limiter      *limiter
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
	if *publicHostFlag == "" {
		log.Fatal("public-host is required")
	}
	publicHost, err := canonicalHostPort(*publicHostFlag, *listenFlag)
	if err != nil {
		log.Fatal(err)
	}
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
		publicHost:   publicHost,
		publicOrigin: "https://" + publicHost,
		backend:      backendURL,
		password:     password,
		passwordPath: *passwordFileFlag,
		sessionKey:   derivedSessionKey,
		backendToken: backendToken,
		limiter:      newLimiter(),
	}
	g.proxy = g.newProxy()

	if *selfTestFlag {
		if err := g.selfTestBackend(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("backend authenticated proxy preflight: ok")
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /gateway/livez", g.livez)
	mux.HandleFunc("GET /gateway/version", g.version)
	mux.HandleFunc("GET /login", g.loginPage)
	mux.HandleFunc("POST /login", g.login)
	mux.HandleFunc("POST /logout", g.logout)
	mux.HandleFunc("/", g.protectedProxy)

	server := &http.Server{
		Addr:              *listenFlag,
		Handler:           g.security(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
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

func (g *gateway) newProxy() *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(g.backend)
	original := proxy.Director
	proxy.Director = func(r *http.Request) {
		original(r)
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
		if !sameHost(r.Host, g.publicHost) {
			http.Error(w, "host rejected", http.StatusBadRequest)
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
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ok":true,"version":%q}`+"\n", version)
}
func (g *gateway) version(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, version) }

type loginCopy struct {
	SecurePlane, Title, Intro, Failed, PasswordLabel, Submit string
	Support, SupportIntro, HostLabel, Footer                 string
}

func validLanguage(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "de", "en", "ru":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func loginLanguage(r *http.Request) string {
	if value := validLanguage(r.FormValue("lang")); value != "" {
		return value
	}
	if value := validLanguage(r.URL.Query().Get("lang")); value != "" {
		return value
	}
	if cookie, err := r.Cookie(languageCookieName); err == nil {
		if value := validLanguage(cookie.Value); value != "" {
			return value
		}
	}
	accept := strings.ToLower(r.Header.Get("Accept-Language"))
	if strings.HasPrefix(accept, "ru") || strings.Contains(accept, ",ru") {
		return "ru"
	}
	if strings.HasPrefix(accept, "en") || strings.Contains(accept, ",en") {
		return "en"
	}
	return "de"
}

func copyForLanguage(lang string) loginCopy {
	switch lang {
	case "en":
		return loginCopy{
			SecurePlane: "SOVEREIGN SECURITY CONTROL PLANE", Title: "Operator access",
			Intro: "Authenticate to control the local Rust/XDP and XDR defense stack.", Failed: "Authentication failed.",
			PasswordLabel: "Operator password", Submit: "Open Command Center", Support: "Support VisionGaiaTechnology",
			SupportIntro: "GeDefense is developed independently. Your support funds sovereign open-source security.", HostLabel: "Protected node", Footer: "Local processing · No cloud dependency · Zero external assets",
		}
	case "ru":
		return loginCopy{
			SecurePlane: "СУВЕРЕННЫЙ ЦЕНТР УПРАВЛЕНИЯ ЗАЩИТОЙ", Title: "Доступ оператора",
			Intro: "Авторизуйтесь для управления локальным стеком защиты Rust/XDP и XDR.", Failed: "Ошибка авторизации.",
			PasswordLabel: "Пароль оператора", Submit: "Открыть центр управления", Support: "Поддержать VisionGaiaTechnology",
			SupportIntro: "GeDefense развивается независимо. Поддержка финансирует суверенную безопасность с открытым кодом.", HostLabel: "Защищённый узел", Footer: "Локальная обработка · Без облака · Без внешних ресурсов",
		}
	default:
		return loginCopy{
			SecurePlane: "SOUVERÄNE SECURITY CONTROL PLANE", Title: "Operator-Zugang",
			Intro: "Authentifiziere dich zur Steuerung des lokalen Rust/XDP- und XDR-Verteidigungsstacks.", Failed: "Anmeldung fehlgeschlagen.",
			PasswordLabel: "Operator-Passwort", Submit: "Command Center öffnen", Support: "VisionGaiaTechnology unterstützen",
			SupportIntro: "GeDefense wird unabhängig entwickelt. Deine Unterstützung finanziert souveräne Open-Source-Sicherheit.", HostLabel: "Geschützter Knoten", Footer: "Lokale Verarbeitung · Keine Cloud-Abhängigkeit · Keine externen Assets",
		}
	}
}

func (g *gateway) loginPage(w http.ResponseWriter, r *http.Request) {
	if g.validSession(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	lang := loginLanguage(r)
	if r.URL.Query().Get("lang") != "" {
		http.SetCookie(w, &http.Cookie{Name: languageCookieName, Value: lang, Path: "/", Secure: true, HttpOnly: false, SameSite: http.SameSiteStrictMode, MaxAge: 365 * 24 * 60 * 60})
	}
	csrf, err := randomToken(24)
	if err != nil {
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: csrf, Path: "/login", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
	nonce, _ := randomToken(18)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", lang)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	data := struct {
		CSRF, Nonce, Host, Lang, ProductVersion string
		Copy                                    loginCopy
		Failed                                  bool
	}{CSRF: csrf, Nonce: nonce, Host: g.publicHost, Lang: lang, ProductVersion: strings.TrimSuffix(version, "-access"), Copy: copyForLanguage(lang), Failed: r.URL.Query().Get("failed") == "1"}
	if err := loginTemplate.Execute(w, data); err != nil {
		log.Printf("login template: %v", err)
	}
}

func (g *gateway) login(w http.ResponseWriter, r *http.Request) {
	// Login CSRF is enforced by a random synchronizer token stored in an
	// HttpOnly, SameSite cookie and mirrored in the form. Some browsers use an
	// opaque Origin after accepting a self-signed IP certificate. Reject only
	// requests explicitly marked cross-site; do not make the certificate
	// interstitial an authentication oracle.
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		log.Printf("login rejected: cross-site request remote=%q origin=%q", clientIP(r.RemoteAddr), r.Header.Get("Origin"))
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" && origin != "null" && !g.sameOrigin(r) {
		log.Printf("login rejected: origin mismatch remote=%q origin=%q host=%q", clientIP(r.RemoteAddr), origin, r.Host)
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	ip := clientIP(r.RemoteAddr)
	now := time.Now()
	if !g.limiter.allow(ip, now) {
		w.Header().Set("Retry-After", "900")
		http.Error(w, "login temporarily locked", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil || csrfCookie.Value == "" || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(r.Form.Get("csrf"))) != 1 {
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	password := []byte(r.Form.Get("password"))
	ok := verifyPassword(password, g.password)
	if !ok {
		zero(password)
		g.limiter.fail(ip, now)
		time.Sleep(250 * time.Millisecond)
		lang := loginLanguage(r)
		http.Redirect(w, r, "/login?failed=1&lang="+lang, http.StatusSeeOther)
		return
	}
	if g.password.algorithm != "argon2id" && g.passwordPath != "" {
		if err := persistArgon2PasswordRecord(g.passwordPath, password); err != nil {
			log.Printf("password record migration to Argon2id failed: %v", err)
		} else {
			log.Printf("password record migrated to Argon2id")
		}
	}
	zero(password)
	g.limiter.success(ip)
	value, err := g.issueSession(now.Add(12 * time.Hour))
	if err != nil {
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 60 * 60, Expires: now.Add(12 * time.Hour)})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/login", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	lang := loginLanguage(r)
	http.SetCookie(w, &http.Cookie{Name: languageCookieName, Value: lang, Path: "/", Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 365 * 24 * 60 * 60})
	http.Redirect(w, r, "/?lang="+lang, http.StatusSeeOther)
}

func (g *gateway) logout(w http.ResponseWriter, r *http.Request) {
	if !g.sameOriginRequired(r) {
		http.Error(w, "origin rejected", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	http.SetCookie(w, &http.Cookie{Name: "vgt_gedefense_session", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (g *gateway) protectedProxy(w http.ResponseWriter, r *http.Request) {
	if !g.validSession(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// The public origin is validated here, never by the internal backend.
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !g.sameOriginRequired(r) {
		log.Printf("protected origin rejected method=%q path=%q remote=%q origin=%q host=%q sec_fetch_site=%q", r.Method, r.URL.Path, clientIP(r.RemoteAddr), r.Header.Get("Origin"), r.Host, r.Header.Get("Sec-Fetch-Site"))
		http.Error(w, "origin rejected", http.StatusForbidden)
		return
	}
	g.proxy.ServeHTTP(w, r)
}

func (g *gateway) sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return sameHost(parsed.Host, g.publicHost)
}

func (g *gateway) sameOriginRequired(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || origin == "null" {
		return false
	}
	return g.sameOrigin(r)
}

func (g *gateway) issueSession(exp time.Time) (string, error) {
	nonce := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	payload := strconv.FormatInt(exp.Unix(), 10) + "." + base64.RawURLEncoding.EncodeToString(nonce)
	mac := hmac.New(sha256.New, g.sessionKey)
	mac.Write([]byte("VGT-GEDEFENSE-ACCESS-COOKIE-V2\x00"))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (g *gateway) validSession(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return false
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(sig) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, g.sessionKey)
	mac.Write([]byte("VGT-GEDEFENSE-ACCESS-COOKIE-V2\x00"))
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	fields := strings.Split(string(payload), ".")
	if len(fields) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || time.Now().Unix() > exp || exp > time.Now().Add(13*time.Hour).Unix() {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(fields[1])
	return err == nil && len(nonce) == 18
}

func (g *gateway) selfTestBackend() error {
	endpoint := *g.backend
	endpoint.Path = "/api/v1/status"
	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	req.Host = g.backend.Host
	req.Header.Set("Authorization", "Bearer "+g.backendToken)
	req.Header.Set("Origin", g.publicOrigin)
	// Apply exactly the same trust-boundary cleanup as the reverse proxy.
	req.Header.Del("Origin")
	req.Header.Del("Referer")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("backend status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func canonicalHostPort(public, listen string) (string, error) {
	if strings.Contains(public, "://") || strings.ContainsAny(public, "/?#@") {
		return "", errors.New("public-host must be host[:port], without scheme or path")
	}
	host, port, err := net.SplitHostPort(public)
	if err == nil {
		if host == "" || port == "" {
			return "", errors.New("invalid public-host")
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
	}
	if strings.Count(public, ":") > 1 {
		return "", errors.New("IPv6 public-host requires brackets and port")
	}
	_, listenPort, err := net.SplitHostPort(listen)
	if err != nil {
		return "", errors.New("invalid listen address")
	}
	return net.JoinHostPort(public, listenPort), nil
}

func sameHost(a, b string) bool {
	ah, ap := splitHostDefault(a)
	bh, bp := splitHostDefault(b)
	return strings.EqualFold(strings.Trim(ah, "[]"), strings.Trim(bh, "[]")) && ap == bp
}

func splitHostDefault(value string) (string, string) {
	h, p, err := net.SplitHostPort(value)
	if err == nil {
		return h, p
	}
	return value, "443"
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func clientIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

func readPrivateRegular(path string, min, max int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("file must be private, regular and non-symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file permissions must be 0600 or stricter")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < min || len(data) > max {
		return nil, errors.New("file size outside accepted bounds")
	}
	return data, nil
}

func loadPasswordRecord(path string) (passwordRecord, error) {
	data, err := readPrivateRegular(path, 32, 2048)
	if err != nil {
		return passwordRecord{}, err
	}
	value := strings.TrimSpace(string(data))
	parts := strings.Split(value, "$")
	if len(parts) == 5 && parts[0] == "v1" && parts[1] == "pbkdf2-sha256" {
		iterations, err := strconv.Atoi(parts[2])
		if err != nil || iterations < 300000 || iterations > 2000000 {
			return passwordRecord{}, errors.New("invalid PBKDF2 iteration count")
		}
		salt, err := decodeBase64(parts[3])
		if err != nil || len(salt) < 16 || len(salt) > 64 {
			return passwordRecord{}, errors.New("invalid PBKDF2 salt")
		}
		digest, err := decodeBase64(parts[4])
		if err != nil || len(digest) != 32 {
			return passwordRecord{}, errors.New("invalid PBKDF2 digest")
		}
		return passwordRecord{algorithm: "pbkdf2-sha256", iterations: iterations, salt: salt, digest: digest}, nil
	}
	if len(parts) == 7 && parts[0] == "v2" && parts[1] == "argon2id" && parts[2] == "v=19" {
		var memory, timeCost, parallelism uint32
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism); err != nil {
			return passwordRecord{}, errors.New("invalid Argon2id parameters")
		}
		if memory < 32768 || memory > 262144 || timeCost < 2 || timeCost > 10 || parallelism < 1 || parallelism > 8 {
			return passwordRecord{}, errors.New("Argon2id parameters outside policy")
		}
		salt, err := decodeBase64(parts[4])
		if err != nil || len(salt) < 16 || len(salt) > 64 {
			return passwordRecord{}, errors.New("invalid Argon2id salt")
		}
		digest, err := decodeBase64(parts[5])
		if err != nil || len(digest) != 32 || parts[6] != "" {
			return passwordRecord{}, errors.New("invalid Argon2id digest")
		}
		return passwordRecord{algorithm: "argon2id", memoryKiB: memory, timeCost: timeCost, parallelism: parallelism, salt: salt, digest: digest}, nil
	}
	// Canonical v2 records do not end in '$'; accept exactly six fields.
	if len(parts) == 6 && parts[0] == "v2" && parts[1] == "argon2id" && parts[2] == "v=19" {
		var memory, timeCost, parallelism uint32
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism); err != nil {
			return passwordRecord{}, errors.New("invalid Argon2id parameters")
		}
		if memory < 32768 || memory > 262144 || timeCost < 2 || timeCost > 10 || parallelism < 1 || parallelism > 8 {
			return passwordRecord{}, errors.New("Argon2id parameters outside policy")
		}
		salt, err := decodeBase64(parts[4])
		if err != nil || len(salt) < 16 || len(salt) > 64 {
			return passwordRecord{}, errors.New("invalid Argon2id salt")
		}
		digest, err := decodeBase64(parts[5])
		if err != nil || len(digest) != 32 {
			return passwordRecord{}, errors.New("invalid Argon2id digest")
		}
		return passwordRecord{algorithm: "argon2id", memoryKiB: memory, timeCost: timeCost, parallelism: parallelism, salt: salt, digest: digest}, nil
	}
	return passwordRecord{}, errors.New("invalid password record format")
}

func decodeBase64(value string) ([]byte, error) {
	if out, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func verifyPassword(password []byte, rec passwordRecord) bool {
	var derived []byte
	var err error
	switch rec.algorithm {
	case "argon2id":
		derived, err = argon2IDKey(password, rec.salt, rec.timeCost, rec.memoryKiB, rec.parallelism, len(rec.digest))
	case "pbkdf2-sha256":
		derived = pbkdf2SHA256(password, rec.salt, rec.iterations, len(rec.digest))
	default:
		return false
	}
	if err != nil {
		return false
	}
	ok := subtle.ConstantTimeCompare(derived, rec.digest) == 1
	zero(derived)
	return ok
}

func createArgon2PasswordRecord(password []byte) (string, error) {
	const memoryKiB uint32 = 65536
	const timeCost uint32 = 3
	const parallelism uint32 = 1
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	digest, err := argon2IDKey(password, salt, timeCost, memoryKiB, parallelism, 32)
	if err != nil {
		return "", err
	}
	defer zero(digest)
	return fmt.Sprintf("v2$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memoryKiB, timeCost, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest)), nil
}

func persistArgon2PasswordRecord(path string, password []byte) error {
	record, err := createArgon2PasswordRecord(password)
	if err != nil {
		return err
	}
	return writeAtomic(path, []byte(record+"\n"), 0o600)
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	blocks := (keyLen + sha256.Size - 1) / sha256.Size
	result := make([]byte, 0, blocks*sha256.Size)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
		zero(u)
		zero(t)
	}
	return result[:keyLen]
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><meta name="theme-color" content="#05090f">
<title>GeDefense {{.ProductVersion}} · VisionGaiaTechnology</title><style nonce="{{.Nonce}}">
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--bg:#05090f;--panel:rgba(9,17,27,.94);--line:rgba(123,215,255,.16);--cyan:#6ee7ff;--green:#42ffd1;--muted:#7893a4;--text:#edfaff;--red:#ff647c}*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;min-height:100vh;background:radial-gradient(circle at 14% 18%,rgba(31,168,215,.13),transparent 28%),radial-gradient(circle at 86% 74%,rgba(21,255,187,.09),transparent 30%),var(--bg);color:var(--text);overflow-x:hidden}body:before{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(rgba(94,217,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(94,217,255,.035) 1px,transparent 1px);background-size:42px 42px;mask-image:radial-gradient(circle at center,#000,transparent 84%)}.shell{width:min(1180px,calc(100% - 32px));min-height:min(760px,calc(100vh - 48px));margin:24px auto;display:grid;grid-template-columns:minmax(0,1.08fr) minmax(390px,.72fr);border:1px solid var(--line);border-radius:28px;overflow:hidden;background:rgba(5,10,16,.78);box-shadow:0 44px 140px rgba(0,0,0,.62),inset 0 1px rgba(255,255,255,.025);backdrop-filter:blur(22px)}.visual{position:relative;padding:54px;display:flex;flex-direction:column;justify-content:space-between;min-height:650px;border-right:1px solid var(--line);overflow:hidden}.visual:after{content:"";position:absolute;width:420px;height:420px;right:-90px;bottom:-120px;border:1px solid rgba(110,231,255,.16);border-radius:50%;box-shadow:0 0 0 44px rgba(110,231,255,.025),0 0 0 88px rgba(66,255,209,.018),inset 0 0 80px rgba(110,231,255,.06)}.brand{display:flex;align-items:center;gap:15px;position:relative;z-index:1}.mark{width:48px;height:48px;position:relative;border:1px solid rgba(110,231,255,.7);transform:rotate(45deg);box-shadow:0 0 30px rgba(110,231,255,.2);border-radius:8px}.mark:before,.mark:after{content:"";position:absolute;inset:9px;border:1px solid rgba(66,255,209,.45);border-radius:50%}.mark:after{inset:18px;background:var(--green);border:0;box-shadow:0 0 22px var(--green)}.brand strong{display:block;font-size:1.08rem;letter-spacing:.01em}.brand small{display:block;color:var(--muted);font-size:.7rem;margin-top:4px}.hero{position:relative;z-index:1;max-width:650px}.eyebrow{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--cyan);font-size:.7rem;letter-spacing:.17em;font-weight:800}.hero h1{font-size:clamp(2.6rem,5vw,5.3rem);line-height:.96;margin:16px 0 24px;letter-spacing:-.055em}.hero h1 span{display:block;color:transparent;-webkit-text-stroke:1px rgba(110,231,255,.55)}.hero p{max-width:580px;color:#9bb2bf;line-height:1.75;font-size:.96rem}.stack{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;position:relative;z-index:1}.stack div{border:1px solid var(--line);background:rgba(7,15,23,.55);border-radius:14px;padding:15px}.stack b{display:block;font-size:.72rem;color:var(--green);letter-spacing:.08em}.stack span{display:block;color:var(--muted);font-size:.68rem;margin-top:5px}.access{padding:42px;display:flex;flex-direction:column;justify-content:center;background:linear-gradient(145deg,rgba(12,22,34,.92),rgba(6,12,18,.96))}.lang{display:flex;gap:7px;justify-content:flex-end;margin-bottom:34px}.lang a{color:var(--muted);text-decoration:none;border:1px solid var(--line);border-radius:9px;padding:7px 10px;font-size:.66rem;font-weight:800}.lang a.active,.lang a:hover{color:var(--cyan);border-color:rgba(110,231,255,.45);background:rgba(110,231,255,.06)}.access .eyebrow{margin:0}.access h2{font-size:2rem;margin:10px 0 12px;letter-spacing:-.03em}.intro{color:#91a7b4;line-height:1.65;margin:0 0 28px}.error{padding:12px 13px;margin-bottom:18px;border:1px solid rgba(255,100,124,.38);background:rgba(255,100,124,.08);border-radius:11px;color:#ff9bad;font-size:.82rem}label{display:block;color:#dfeef3;font-size:.76rem;font-weight:700;margin-bottom:9px}input{width:100%;height:54px;border-radius:12px;border:1px solid #243846;background:#071019;color:white;padding:0 15px;font-size:1rem;outline:none}input:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(110,231,255,.1)}button{width:100%;height:54px;border:1px solid rgba(66,255,209,.55);border-radius:12px;margin-top:16px;background:linear-gradient(135deg,#37e9bd,#68f7d5);color:#03120e;font-size:.84rem;font-weight:900;letter-spacing:.035em;cursor:pointer;box-shadow:0 14px 35px rgba(34,255,193,.12)}button:hover{filter:brightness(1.07);transform:translateY(-1px)}.node{margin-top:20px;padding:13px 14px;border:1px solid var(--line);border-radius:12px;background:rgba(4,10,15,.48)}.node span{display:block;color:var(--muted);text-transform:uppercase;font-size:.59rem;letter-spacing:.12em}.node code{display:block;color:var(--cyan);margin-top:7px;font-size:.73rem;word-break:break-all}.support{margin-top:14px;border:1px solid var(--line);border-radius:12px;background:rgba(4,10,15,.42)}.support summary{cursor:pointer;padding:14px;color:#b9d2de;font-size:.75rem;font-weight:800;list-style:none}.support summary::-webkit-details-marker{display:none}.support summary:after{content:"+";float:right;color:var(--cyan)}.support[open] summary:after{content:"−"}.support-body{border-top:1px solid var(--line);padding:14px}.support-body p{font-size:.7rem;color:var(--muted);line-height:1.55;margin:0 0 12px}.support-grid{display:grid;gap:8px}.support-grid a,.support-grid div{display:grid;grid-template-columns:62px 1fr;gap:8px;color:#b9ccd5;text-decoration:none;font-size:.62rem}.support-grid b{color:var(--green)}.support-grid code{overflow-wrap:anywhere;color:#7fa3b5}.footer{margin-top:22px;text-align:center;color:#5f7684;font-size:.6rem;line-height:1.5}.version{color:var(--cyan);font-family:ui-monospace,SFMono-Regular,Consolas,monospace}@media(max-width:850px){.shell{grid-template-columns:1fr}.visual{min-height:360px;padding:34px;border-right:0;border-bottom:1px solid var(--line)}.hero h1{font-size:3rem}.stack{display:none}.access{padding:34px}}@media(max-width:520px){.shell{width:min(100% - 18px,1180px);margin:9px auto;border-radius:20px}.visual{min-height:290px;padding:25px}.hero h1{font-size:2.45rem}.hero p{font-size:.82rem}.access{padding:26px}.lang{margin-bottom:25px}}@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body><main class="shell"><section class="visual"><div class="brand"><div class="mark" aria-hidden="true"></div><div><strong>GeDefense</strong><small>powered by VisionGaiaTechnology · <span class="version">{{.ProductVersion}}</span></small></div></div><div class="hero"><p class="eyebrow">{{.Copy.SecurePlane}}</p><h1>Host defense.<span>At kernel speed.</span></h1><p>Rust XDP · Linux XDR · AES-256-GCM · Signed policy state · Local control</p></div><div class="stack"><div><b>KERNEL</b><span>eBPF / XDP</span></div><div><b>RESPONSE</b><span>Rust Core / pidfd</span></div><div><b>CONTROL</b><span>Go / Same-Origin</span></div></div></section><section class="access"><nav class="lang" aria-label="Language"><a href="/login?lang=de" class="{{if eq .Lang "de"}}active{{end}}">DE</a><a href="/login?lang=en" class="{{if eq .Lang "en"}}active{{end}}">EN</a><a href="/login?lang=ru" class="{{if eq .Lang "ru"}}active{{end}}">RU</a></nav><p class="eyebrow">GEDEFENSE {{.ProductVersion}}</p><h2>{{.Copy.Title}}</h2><p class="intro">{{.Copy.Intro}}</p>{{if .Failed}}<div class="error" role="alert">{{.Copy.Failed}}</div>{{end}}<form method="post" action="/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="lang" value="{{.Lang}}"><label for="password">{{.Copy.PasswordLabel}}</label><input id="password" name="password" type="password" autocomplete="current-password" minlength="12" maxlength="1024" required autofocus><button type="submit">{{.Copy.Submit}}</button></form><div class="node"><span>{{.Copy.HostLabel}}</span><code>{{.Host}}</code></div><details class="support"><summary>{{.Copy.Support}}</summary><div class="support-body"><p>{{.Copy.SupportIntro}}</p><div class="support-grid"><a href="https://paypal.me/dergoldenelotus" rel="noreferrer noopener"><b>PayPal</b><code>paypal.me/dergoldenelotus</code></a><div><b>Bitcoin</b><code>bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm</code></div><div><b>ETH</b><code>0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85</code></div><div><b>USDT</b><code>ERC-20 · 0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85</code></div></div></div></details><div class="footer">{{.Copy.Footer}}<br>GeDefense powered by VisionGaiaTechnology</div></section></main></body></html>`))

// These wrappers are defined in crypto_helpers.go to keep imports explicit.
