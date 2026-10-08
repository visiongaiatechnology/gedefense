package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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

const version = "4.2.1-access"
const cookieName = "__Host-vgt_gedefense_session"
const csrfCookieName = "vgt_gedefense_login_csrf"

// loginCSRFMaxAgeSeconds bounds how long a rendered sign-in form stays usable.
//
// It was 600 seconds, which is shorter than the time an operator may reasonably take
// between opening the page and submitting it. The protection does not come from this
// number: the cookie is HttpOnly and SameSite=Strict so no cross-site page can submit
// it, and the synchronizer token is 24 random bytes. An hour only decides how long a
// stale form is worth honouring.
const loginCSRFMaxAgeSeconds = 3600
const languageCookieName = "vgt_gedefense_lang"

// noticeCookieName carries the reason a sign-in was refused from the POST that refused it
// to the page that explains it, once.
//
// It used to travel in the query string, which made the message a property of the URL
// rather than of what happened: an operator who reloaded - or who simply had the URL in
// their history - was told their form had expired even when it had just been issued fresh
// and worked. A one-shot cookie is consumed by the page that renders it, so the message
// appears exactly once and the next load tells the truth again.
const noticeCookieName = "vgt_gedefense_login_notice"
const noticeStale = "stale"
const noticeFailed = "failed"

// noticeCookie is deliberately short-lived: it only has to survive the redirect that
// carries it, and the page that reads it clears it in the same response.
func noticeCookie(value string) *http.Cookie {
	return &http.Cookie{Name: noticeCookieName, Value: value, Path: "/login", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 30}
}

func clearedNoticeCookie() *http.Cookie {
	return &http.Cookie{Name: noticeCookieName, Value: "", Path: "/login", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1}
}

func hardenedTLSConfig(loopbackListener bool) *tls.Config {
	// Post-quantum hybrid key exchange is prioritized (ML-KEM), followed by
	// standard TLS 1.3 curves (X25519, CurveP384) as a secure fallback for
	// classical browsers and system tools.
	curves := []tls.CurveID{
		tls.SecP384r1MLKEM1024,
		tls.X25519MLKEM768,
		tls.X25519,
		tls.CurveP384,
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	}
}

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
	// The mark is served before authentication because the login page needs it. It is a
	// static embedded image with no user input in its path, so there is nothing to
	// validate and nothing it can disclose.
	mux.HandleFunc("GET /gateway/logo.png", g.logo)
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
		if !sameHost(r.Host, g.publicHost) && !g.allowHost(r.Host) {
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

// loginCopy carries every operator-visible string. The attested facts are part of it
// because they are content, not decoration: each one is something this gateway can prove
// about itself before any credential is presented, and an operator reading a trust
// boundary deserves to read it in their own language.
type loginCopy struct {
	// Identity and the single action.
	ProductSub, Title, Intro, Failed, Stale, PasswordLabel, Submit string
	// Attested facts, in the order a trust decision needs them.
	FactsHeading, HostLabel, HostNote                   string
	ChannelLabel, ChannelTLS, ChannelPlain, ChannelNote string
	GrantLabel, GrantValue, CustodyLabel, CustodyValue  string
	// Reference material.
	Support, SupportIntro, Footer string
}

func validLanguage(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "de", "en", "ru":
		return strings.ToLower(strings.TrimSpace(value))
	case "zh", "zh-cn", "zh_cn":
		return "zh-CN"
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
	if strings.HasPrefix(accept, "zh") || strings.Contains(accept, ",zh") {
		return "zh-CN"
	}
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
			ProductSub: "Security Fabric Gateway", Title: "Operator access",
			Intro: "Prove your identity to reach the control plane on this node.", Failed: "Authentication failed. The attempt was recorded.",
			Stale:         "This sign-in page had expired. A fresh one has been issued - please try again.",
			PasswordLabel: "Operator password", Submit: "Open the control plane",
			FactsHeading: "Attested at this boundary",
			HostLabel:    "Node", HostNote: "The address this gateway answers on.",
			ChannelLabel: "Channel", ChannelTLS: "TLS, certificate verified", ChannelPlain: "unencrypted transport",
			ChannelNote: "The transport this page was served over.",
			GrantLabel:  "Grants", GrantValue: "Control-plane access for this session, scoped to the actions your role allows.",
			CustodyLabel: "Custody", CustodyValue: "The session lives in a cookie on this host only. Nothing is sent to a third party.",
			Support:      "Support VisionGaiaTechnology",
			SupportIntro: "GeDefense is developed independently. Your support funds sovereign open-source security.",
			Footer:       "Local processing · No cloud dependency · No external assets",
		}
	case "ru":
		return loginCopy{
			ProductSub: "Шлюз безопасности", Title: "Доступ оператора",
			Intro: "Подтвердите личность для доступа к центру управления на этом узле.", Failed: "Ошибка авторизации. Попытка зафиксирована.",
			Stale:         "Страница входа устарела. Выдана новая - попробуйте ещё раз.",
			PasswordLabel: "Пароль оператора", Submit: "Открыть центр управления",
			FactsHeading: "Подтверждено на этой границе",
			HostLabel:    "Узел", HostNote: "Адрес, на котором отвечает этот шлюз.",
			ChannelLabel: "Канал", ChannelTLS: "TLS, сертификат проверен", ChannelPlain: "незашифрованный канал",
			ChannelNote: "Транспорт, по которому отдана эта страница.",
			GrantLabel:  "Права", GrantValue: "Доступ к центру управления на время сессии, в пределах вашей роли.",
			CustodyLabel: "Хранение", CustodyValue: "Сессия хранится в cookie только на этом узле. Данные не передаются третьим лицам.",
			Support:      "Поддержать VisionGaiaTechnology",
			SupportIntro: "GeDefense развивается независимо. Поддержка финансирует суверенную безопасность с открытым кодом.",
			Footer:       "Локальная обработка · Без облака · Без внешних ресурсов",
		}
	case "zh", "zh-CN", "zh-cn":
		return loginCopy{
			ProductSub: "安全网关", Title: "操作员访问",
			Intro: "验证身份以访问本节点上的控制平面。", Failed: "身份验证失败。本次尝试已被记录。",
			Stale:         "此登录页面已过期。已签发新页面——请重试。",
			PasswordLabel: "操作员密码", Submit: "打开控制平面",
			FactsHeading: "此边界已确认的事实",
			HostLabel:    "节点", HostNote: "此网关应答的地址。",
			ChannelLabel: "通道", ChannelTLS: "TLS，证书已验证", ChannelPlain: "未加密传输",
			ChannelNote: "提供此页面所用的传输方式。",
			GrantLabel:  "权限", GrantValue: "本次会话可访问控制平面，范围限于你角色允许的操作。",
			CustodyLabel: "存储", CustodyValue: "会话仅保存在本节点的 Cookie 中，不会发送给第三方。",
			Support:      "支持 VisionGaiaTechnology",
			SupportIntro: "GeDefense 独立开发。您的支持将资助主权开源安全。",
			Footer:       "本地处理 · 无云依赖 · 零外部资产",
		}
	default:
		return loginCopy{
			ProductSub: "Security Fabric Gateway", Title: "Operator-Zugang",
			Intro: "Weise dich aus, um die Control Plane auf diesem Knoten zu erreichen.", Failed: "Anmeldung fehlgeschlagen. Der Versuch wurde aufgezeichnet.",
			Stale:         "Diese Anmeldeseite war abgelaufen. Eine neue wurde ausgestellt - bitte erneut versuchen.",
			PasswordLabel: "Operator-Passwort", Submit: "Control Plane öffnen",
			FactsHeading: "An dieser Grenze belegt",
			HostLabel:    "Knoten", HostNote: "Die Adresse, auf der dieses Gateway antwortet.",
			ChannelLabel: "Kanal", ChannelTLS: "TLS, Zertifikat geprüft", ChannelPlain: "unverschlüsselt",
			ChannelNote: "Der Transport, über den diese Seite ausgeliefert wurde.",
			GrantLabel:  "Umfang", GrantValue: "Zugang zur Control Plane für diese Sitzung, begrenzt auf die Aktionen deiner Rolle.",
			CustodyLabel: "Verwahrung", CustodyValue: "Die Sitzung liegt in einem Cookie ausschließlich auf diesem Knoten. Nichts geht an Dritte.",
			Support:      "VisionGaiaTechnology unterstützen",
			SupportIntro: "GeDefense wird unabhängig entwickelt. Deine Unterstützung finanziert souveräne Open-Source-Sicherheit.",
			Footer:       "Lokale Verarbeitung · Keine Cloud-Abhängigkeit · Keine externen Assets",
		}
	}
}

// loginToken returns the sign-in form token for this browser, reusing the one it already
// holds instead of minting a new one for every page view.
//
// Rotating the token per view turned the cookie into a single shared slot. Any second
// request for the sign-in page overwrote it - the language links the page itself carries
// are enough, because browsers prefetch and prerender them, and a second tab or a
// back/forward restore does the same - and the form the operator was looking at silently
// became stale. Submitting then compared a freshly written cookie against the token that
// page had been rendered with, which is how an operator who did nothing wrong was refused,
// and why reloading could not clear it. A third-party page could break an in-progress
// sign-in the same way, with nothing more than an <img> pointing at this endpoint.
//
// Reuse costs nothing in protection. The token is 24 random bytes bound to an HttpOnly,
// Secure, SameSite=Strict, host-only cookie that no other site can read or set, so a
// cross-site page can neither learn it nor supply it. Rotation was never what defended the
// form; the binding is.
func (g *gateway) loginToken(w http.ResponseWriter, r *http.Request) (string, error) {
	csrf := ""
	if c, err := r.Cookie(csrfCookieName); err == nil && validLoginToken(c.Value) {
		csrf = c.Value
	} else {
		fresh, err := randomToken(24)
		if err != nil {
			return "", err
		}
		csrf = fresh
	}
	// The lifetime is refreshed on every view, so a page that is opened, left and returned
	// to still submits. It bounds how long a rendered form stays usable; it is not what
	// protects it.
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: csrf, Path: "/login", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: loginCSRFMaxAgeSeconds})
	return csrf, nil
}

// validLoginToken accepts only the shape randomToken produces. Anything else is a value
// this host did not issue, and reusing it would put a token in the form that nothing
// meaningful can be compared against.
func validLoginToken(value string) bool {
	if len(value) != 32 {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
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
	csrf, err := g.loginToken(w, r)
	if err != nil {
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
		return
	}
	nonce, _ := randomToken(18)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", lang)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	// The reason travels with the request that produced it and is consumed here, so it is
	// shown once and a reload starts from a clean page.
	notice := ""
	if c, err := r.Cookie(noticeCookieName); err == nil {
		notice = c.Value
	}
	http.SetCookie(w, clearedNoticeCookie())
	data := struct {
		CSRF, Nonce, Host, Lang, ProductVersion string
		Copy                                    loginCopy
		Failed                                  bool
		Stale                                   bool
		// Secure reports the transport this page was actually served over. The page
		// states what it observed rather than asserting a policy, because a claim about
		// TLS that is not read from the connection is worth nothing at a trust boundary.
		Secure bool
	}{CSRF: csrf, Nonce: nonce, Host: g.publicHost, Lang: lang, ProductVersion: strings.TrimSuffix(version, "-access"), Copy: copyForLanguage(lang), Failed: notice == noticeFailed, Stale: notice == noticeStale, Secure: r.TLS != nil}
	// The issued fingerprint is what makes a later rejection diagnosable. Without it the
	// log says a token did not match; with it the log says whether the form carried the
	// token this host just issued, which separates a stale page from a missing cookie.
	log.Printf("login page rendered remote=%q host=%q csrf_fp=%s stale=%t", clientIP(r.RemoteAddr), r.Host, fingerprint(csrf), data.Stale)
	if err := loginTemplate.Execute(w, data); err != nil {
		log.Printf("login template: %v", err)
	}
}

// fingerprint names a token in the log without writing it down. Eight hex characters of
// its SHA-256 tell two values apart, and a 24-byte random token is not recoverable from
// that prefix. It exists because the log has to answer "were these the same value?" about
// secrets it must not contain.
func fingerprint(value string) string {
	if value == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:4])
}

// cookieNames lists which cookies arrived, never what they carried. A rejection caused by
// a cookie the browser did not send looks identical to one caused by a cookie it sent with
// an old value, and the two have different causes and different remedies.
func cookieNames(r *http.Request) string {
	cookies := r.Cookies()
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	return strings.Join(names, ",")
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
	csrfCookie, csrfErr := r.Cookie(csrfCookieName)
	csrfCookieValue := ""
	if csrfErr == nil && csrfCookie != nil {
		csrfCookieValue = csrfCookie.Value
	}
	csrfForm := r.Form.Get("csrf")
	csrfErrText := ""
	if csrfErr != nil {
		csrfErrText = csrfErr.Error()
	}
	if csrfErr != nil || csrfCookieValue == "" || subtle.ConstantTimeCompare([]byte(csrfCookieValue), []byte(csrfForm)) != 1 {
		// A stale form is sent back to a fresh one rather than refused outright.
		//
		// This used to return a bare 403 reading "request rejected", which is what an
		// operator saw after leaving the sign-in page open and coming back to it. The
		// message named neither the cause nor a way out, and the only recovery was to
		// guess that reloading the page would help. The page they land on carries a new
		// token, so reloading is exactly what it does - the difference is that it now
		// says so.
		//
		// The rejection itself is unchanged: without a matching token the request is not
		// authenticated, and no password is read.
		// A rejection is only actionable if it says which of the two it was. The
		// distinction that matters is "the browser sent no cookie" against "the browser
		// sent a value that no longer matches", because the first is a cookie-storage or
		// transport problem and the second is a stale or duplicated form. The token is
		// never written to the log; eight hex characters of its digest separate two
		// values without being recoverable, and the cookie names carry no secret.
		log.Printf("login rejected: csrf token rejected remote=%q host=%q cookie_error=%q cookie_present=%t cookie_len=%d cookie_fp=%s form_len=%d form_fp=%s received_cookies=%q raw_cookie_len=%d sec_fetch_site=%q origin=%q user_agent=%q",
			clientIP(r.RemoteAddr), r.Host, csrfErrText, csrfCookieValue != "",
			len(csrfCookieValue), fingerprint(csrfCookieValue),
			len(csrfForm), fingerprint(csrfForm),
			cookieNames(r), len(r.Header.Get("Cookie")),
			r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin"), r.Header.Get("User-Agent"))
		http.SetCookie(w, noticeCookie(noticeStale))
		http.Redirect(w, r, "/login?lang="+loginLanguage(r), http.StatusSeeOther)
		return
	}
	password := []byte(r.Form.Get("password"))
	ok := verifyPassword(password, g.password)
	if !ok {
		zero(password)
		g.limiter.fail(ip, now)
		time.Sleep(250 * time.Millisecond)
		lang := loginLanguage(r)
		http.SetCookie(w, noticeCookie(noticeFailed))
		http.Redirect(w, r, "/login?lang="+lang, http.StatusSeeOther)
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
	return g.allowHost(parsed.Host)
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

func (g *gateway) allowHost(host string) bool {
	if sameHost(host, g.publicHost) {
		return true
	}
	ah, ap := splitHostDefault(host)
	_, expectedPort := splitHostDefault(g.publicHost)
	return isLoopbackHost(strings.Trim(ah, "[]")) && ap == expectedPort
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
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--bg:#04080d;--plane:#070f17;--rail:rgba(126,196,232,.12);--ice:#6ee7ff;--text:#e9f5fb;--muted:#7d95a6;--dim:#5b7183;--red:#ff647c;--amber:#f4c76a;--green:#37d9ae;--radius-panel:16px;--radius-control:10px}*{box-sizing:border-box}html,body{height:100%}body{margin:0;background-color:var(--bg);color:var(--text);font-size:16px;background-image:radial-gradient(130% 100% at 6% 0%,rgba(22,70,99,.26),transparent 58%);-webkit-font-smoothing:antialiased}/* Full-bleed two-plane canvas rather than a centred rounded card floating on a gradient.   The composition is the page: one plane states what this gateway can attest before any   credential exists, the other holds the single action. There is no decorative grid, no   glow and no ambient motion, because none of those would answer a question an operator   has at an authentication boundary. */.shell{min-height:100vh;display:grid;grid-template-columns:minmax(0,1fr) minmax(360px,468px)}.plane{display:flex;flex-direction:column;padding:clamp(26px,4vw,58px)}.attest{background:linear-gradient(180deg,rgba(9,20,30,.66),rgba(5,11,17,.16))}
/* The brand sits at the top and the facts occupy the space below it as one block. The
   plane previously pushed them to opposite ends of the viewport, which left a dead band
   between them and read as two unrelated groups rather than one column. */
.facts{margin-top:auto;margin-bottom:auto}
/* The product statement closes the identity column. It sat under the support accordion
   on the action plane, where it belonged to nothing; it is a property of this gateway,
   so it belongs with the facts about this gateway, and it gives the column a foot. */
.attest-foot{margin:0;color:var(--dim);font-size:.68rem;letter-spacing:.02em}.act{border-left:1px solid var(--rail);background:var(--plane);gap:0}
.act-body{margin:auto 0;padding:34px 0}
.act-foot{margin-top:auto}/* Identity. The mark and the wordmark, and nothing competing with them. *//* The mark at signature size. Brand identity is one of the functions an element may
   serve, and it is served here as a first-class element on the identity plane rather
   than as a ghost behind the content: a faint oversized watermark would be wallpaper,
   which is the one thing a background must not be. */
.brand{display:flex;align-items:center;gap:18px}.mark{width:58px;height:58px;flex:0 0 58px;display:block;object-fit:contain}.brand strong{display:block;font-size:1.3rem;font-weight:690;letter-spacing:-.02em}.brand small{display:block;color:var(--dim);font-size:.74rem;margin-top:5px}/* Attested facts, in the same definition-list grammar as the control plane's telemetry   rails. Reusing that grammar is the point: the gateway and the dashboard read as one   product rather than two interfaces that happen to share a colour. *//* The measure uses the plane instead of floating inside it. The column was 620px wide in
   a 1324px plane, which is what made the space read as unused rather than as air. */
.facts{display:flex;flex-direction:column;gap:24px;max-width:820px}.facts h2{margin:0;color:var(--dim);font-size:.6rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase}.facts dl{display:flex;flex-direction:column;gap:16px;margin:0}.fact{display:grid;grid-template-columns:124px minmax(0,1fr);gap:20px;align-items:baseline}.fact dt{color:var(--dim);font-size:.6rem;font-weight:700;letter-spacing:.13em;text-transform:uppercase}.fact dd{margin:0;min-width:0;font-size:.92rem;line-height:1.55}.fact dd small{display:block;color:var(--muted);font-size:.7rem;margin-top:4px;line-height:1.45}/* Monospace carries the one technical identifier, not the whole page. */.fact code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.82rem;color:var(--ice);overflow-wrap:anywhere}/* The channel states its verdict in words as well; colour alone would exclude anybody   who cannot separate the two hues. */.fact dd[data-channel="secure"]{color:var(--green)}.fact dd[data-channel="plain"]{color:var(--amber)}/* The action plane. One job, one control, one primary button. */.lang{display:flex;gap:6px;justify-content:flex-end;margin:0 0 28px}.lang a{color:var(--dim);text-decoration:none;border:1px solid transparent;border-radius:7px;padding:6px 9px;font-size:.64rem;font-weight:700;letter-spacing:.06em}.lang a:hover{color:var(--text);border-color:var(--rail)}.lang a.active{color:var(--ice);border-color:rgba(110,231,255,.4);background:rgba(110,231,255,.07)}.lang a:focus-visible{outline:2px solid var(--ice);outline-offset:2px}.act h1{margin:0;font-size:1.5rem;font-weight:660;letter-spacing:-.025em}.act .intro{margin:9px 0 0;color:var(--muted);font-size:.83rem;line-height:1.6}form{display:flex;flex-direction:column;gap:14px;margin:24px 0 0}.field{display:flex;flex-direction:column;gap:8px}label{color:var(--muted);font-size:.6rem;font-weight:700;letter-spacing:.13em;text-transform:uppercase}input{width:100%;height:50px;border-radius:var(--radius-control);border:1px solid #223441;background:#061019;color:var(--text);padding:0 14px;font-size:.95rem;font-family:inherit}input:focus{border-color:var(--ice);box-shadow:0 0 0 3px rgba(110,231,255,.12);outline:none}/* The ice accent carries the primary action. Green is reserved for state - using it   here would spend the strongest signal in a security product on "click me". */button{height:50px;border:1px solid rgba(110,231,255,.5);border-radius:var(--radius-control);background:linear-gradient(180deg,rgba(110,231,255,.17),rgba(110,231,255,.09));color:#dff7ff;font-family:inherit;font-size:.82rem;font-weight:700;letter-spacing:.02em;cursor:pointer}button:hover{background:linear-gradient(180deg,rgba(110,231,255,.24),rgba(110,231,255,.13))}button:focus-visible{outline:2px solid var(--ice);outline-offset:2px}button:active{transform:translateY(1px)}/* Failure states say what happened and stay where the action is. */.error{padding:11px 13px;border:1px solid rgba(255,100,124,.38);background:rgba(255,100,124,.08);border-radius:var(--radius-control);color:#ff9bad;font-size:.8rem;line-height:1.5}/* Support is reference material and is disclosed on demand, not competing with the   single action. */.support{margin:36px 0 0;border-top:1px solid var(--rail);padding-top:16px}.support summary{cursor:pointer;color:var(--muted);font-size:.74rem;font-weight:650;list-style:none}.support summary::-webkit-details-marker{display:none}.support summary:after{content:"+";float:right;color:var(--ice)}.support[open] summary:after{content:"\2212"}.support summary:focus-visible{outline:2px solid var(--ice);outline-offset:3px;border-radius:5px}.support-body{padding-top:13px}.support-body p{margin:0 0 12px;color:var(--muted);font-size:.72rem;line-height:1.55}.support-grid{display:grid;gap:8px}.support-grid a,.support-grid div{display:grid;grid-template-columns:62px 1fr;gap:9px;color:#b9ccd5;text-decoration:none;font-size:.66rem}.support-grid a:hover code{color:var(--text)}.support-grid b{color:var(--ice);font-weight:650}.support-grid code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;color:#7fa3b5}/* Narrow: the composition is re-decided, not compressed. The credential comes first   because that is the task; the attested facts follow as the reference they are. */@media(max-width:900px){.shell{grid-template-columns:1fr}.act{order:1;border-left:0;border-bottom:1px solid var(--rail);padding-bottom:34px}.attest{order:2;gap:34px;padding-top:34px}.fact{grid-template-columns:92px minmax(0,1fr);gap:13px}}@media(max-width:520px){.plane{padding:22px}.fact{grid-template-columns:1fr;gap:3px}.act h1{font-size:1.3rem}}@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style></head><body><main class="shell"><section class="plane attest"><div class="brand"><img class="mark" src="/gateway/logo.png" alt="" aria-hidden="true"><div><strong>GeDefense</strong><small>{{.Copy.ProductSub}} · {{.ProductVersion}}</small></div></div><div class="facts"><h2>{{.Copy.FactsHeading}}</h2><dl><div class="fact"><dt>{{.Copy.HostLabel}}</dt><dd><code>{{.Host}}</code><small>{{.Copy.HostNote}}</small></dd></div><div class="fact"><dt>{{.Copy.ChannelLabel}}</dt><dd data-channel="{{if .Secure}}secure{{else}}plain{{end}}">{{if .Secure}}{{.Copy.ChannelTLS}}{{else}}{{.Copy.ChannelPlain}}{{end}}<small>{{.Copy.ChannelNote}}</small></dd></div><div class="fact"><dt>{{.Copy.GrantLabel}}</dt><dd>{{.Copy.GrantValue}}</dd></div><div class="fact"><dt>{{.Copy.CustodyLabel}}</dt><dd>{{.Copy.CustodyValue}}</dd></div></dl></div><p class="attest-foot">{{.Copy.Footer}}</p></section><section class="plane act"><nav class="lang" aria-label="Language"><a href="/login?lang=de" class="{{if eq .Lang "de"}}active{{end}}">DE</a><a href="/login?lang=en" class="{{if eq .Lang "en"}}active{{end}}">EN</a><a href="/login?lang=ru" class="{{if eq .Lang "ru"}}active{{end}}">RU</a><a href="/login?lang=zh-CN" class="{{if or (eq .Lang "zh") (eq .Lang "zh-CN")}}active{{end}}">ZH</a></nav><div class="act-body"><h1>{{.Copy.Title}}</h1><p class="intro">{{.Copy.Intro}}</p>{{if .Stale}}<div class="error" role="alert">{{.Copy.Stale}}</div>{{end}}{{if .Failed}}<div class="error" role="alert">{{.Copy.Failed}}</div>{{end}}<form method="post" action="/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="lang" value="{{.Lang}}"><div class="field"><label for="password">{{.Copy.PasswordLabel}}</label><input id="password" name="password" type="password" autocomplete="current-password" minlength="12" maxlength="1024" required autofocus></div><button type="submit">{{.Copy.Submit}}</button></form></div><div class="act-foot"><details class="support"><summary>{{.Copy.Support}}</summary><div class="support-body"><p>{{.Copy.SupportIntro}}</p><div class="support-grid"><a href="https://paypal.me/dergoldenelotus" rel="noreferrer noopener"><b>PayPal</b><code>paypal.me/dergoldenelotus</code></a><div><b>Bitcoin</b><code>bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm</code></div><div><b>ETH</b><code>0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85</code></div><div><b>USDT</b><code>ERC-20 · 0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85</code></div></div></div></details></div></section></main></body></html>`))

// These wrappers are defined in crypto_helpers.go to keep imports explicit.
