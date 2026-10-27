package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CMS detection and the trusted WordPress bridge.
//
// The bridge deliberately does not open a kernel path to WordPress. WordPress
// writes append-only, AES-256-GCM authenticated records to a file; the control
// plane is the only reader and the only component that can grant a short-lived
// L7 rate-limit exemption. A forged or replayed line is discarded without
// changing enforcement.

const (
	cmsBridgeAAD             = "GeDefense-Linux-WP-Bridge-V1"
	cmsBridgePrefix          = `GEDEFENSE-BRIDGE `
	cmsBridgeMaxLineBytes    = 64 << 10
	cmsBridgeReadBudget      = 1 << 20
	cmsBridgeMaxLeases       = 4096
	cmsBridgeMaxProfiles     = 2048
	cmsBridgeDefaultTTL      = 2 * time.Hour
	cmsDetectorTTL           = 30 * time.Minute
	cmsDetectorMinConfidence = 40
)

type CMSKind string

const (
	CMSWordPress CMSKind = "wordpress"
	CMSJoomla    CMSKind = "joomla"
	CMSTYPO3     CMSKind = "typo3"
	CMSLaravel   CMSKind = "laravel"
)

// cmsSettings is intentionally operator-simple: enable detection, decide how
// far a detected CMS may relax the dynamic client budget, and decide whether a
// verified WordPress master session may bypass the rate limiter for two hours.
type cmsSettings struct {
	Enabled                  bool   `json:"enabled"`
	AutoRelax                bool   `json:"auto_relax"`
	RelaxAdmin               bool   `json:"relax_admin"`
	RelaxClientRatePerMinute int    `json:"relax_client_rate_per_minute"`
	RelaxClientRateBurst     int    `json:"relax_client_rate_burst"`
	TrustedAdminTTLSeconds   int    `json:"trusted_admin_ttl_seconds"`
	BridgeEnabled            bool   `json:"bridge_enabled"`
	BridgeLogPath            string `json:"bridge_log_path"`
	BridgeMaxSkewSeconds     int    `json:"bridge_max_skew_seconds"`
}

type cmsDetection struct {
	Kind       CMSKind  `json:"kind"`
	Host       string   `json:"host"`
	Confidence int      `json:"confidence"`
	Evidence   []string `json:"evidence"`
	LastSeen   string   `json:"last_seen"`
}

type cmsLease struct {
	IP        string `json:"ip"`
	Host      string `json:"host"`
	User      string `json:"user"`
	Source    string `json:"source"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

type cmsStatus struct {
	Settings       cmsSettings    `json:"settings"`
	Detections     []cmsDetection `json:"detections"`
	BridgeKeySet   bool           `json:"bridge_key_set"`
	BridgeKeyFP    string         `json:"bridge_key_fingerprint,omitempty"`
	BridgeLastRead string         `json:"bridge_last_read,omitempty"`
	BridgeLastErr  string         `json:"bridge_last_error,omitempty"`
	Leases         []cmsLease     `json:"leases"`
}

type cmsProfile struct {
	kind       CMSKind
	confidence int
	evidence   map[string]struct{}
	lastSeen   time.Time
}

type cmsBridgeEvent struct {
	Version   int    `json:"v"`
	Event     string `json:"event"`
	SiteHost  string `json:"site_host"`
	IP        string `json:"ip"`
	User      string `json:"user"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	EventID   string `json:"event_id"`
}

type cmsBridgeEnvelope struct {
	Slug string `json:"slug"`
	IV   string `json:"iv"`
	Tag  string `json:"tag"`
	Data string `json:"data"`
}

// CMSEngine owns detection profiles, verified bridge leases and the bridge
// reader. All maps are bounded and all external file reads are budgeted.
type CMSEngine struct {
	mu           sync.RWMutex
	settings     cmsSettings
	profiles     map[string]*cmsProfile
	leases       map[string]cmsLease
	settingsPath string
	keyPath      string
	key          []byte
	bridgeMu     sync.Mutex
	bridgeOffset int64
	bridgeInode  uint64
	bridgeSeen   map[string]struct{}
	bridgeLast   time.Time
	bridgeErr    string
}

func defaultCMSSettings() cmsSettings {
	return cmsSettings{
		Enabled:                  true,
		AutoRelax:                true,
		RelaxAdmin:               true,
		RelaxClientRatePerMinute: 1200,
		RelaxClientRateBurst:     200,
		TrustedAdminTTLSeconds:   int(cmsBridgeDefaultTTL / time.Second),
		BridgeEnabled:            false,
		BridgeLogPath:            "/var/lib/vgt/gedefense/wp-bridge/events.log",
		BridgeMaxSkewSeconds:     300,
	}
}

// NewCMSEngine loads non-secret settings and the bridge key. A missing key does
// not disable CMS detection; it only keeps bridge leases inactive until the
// operator rotates a key from the dashboard.
func NewCMSEngine(settingsPath, keyPath string) *CMSEngine {
	engine := &CMSEngine{
		settings:     defaultCMSSettings(),
		profiles:     make(map[string]*cmsProfile),
		leases:       make(map[string]cmsLease),
		settingsPath: settingsPath,
		keyPath:      keyPath,
		bridgeSeen:   make(map[string]struct{}),
	}
	if raw, err := os.ReadFile(settingsPath); err == nil {
		var stored cmsSettings
		if json.Unmarshal(raw, &stored) == nil {
			engine.settings = sanitizeCMSSettings(stored)
		}
	}
	if key, err := readCMSBridgeKey(keyPath); err == nil {
		engine.key = key
	}
	return engine
}

func sanitizeCMSSettings(in cmsSettings) cmsSettings {
	out := defaultCMSSettings()
	out.Enabled = in.Enabled
	out.AutoRelax = in.AutoRelax
	out.RelaxAdmin = in.RelaxAdmin
	out.BridgeEnabled = in.BridgeEnabled
	if in.RelaxClientRatePerMinute >= 60 && in.RelaxClientRatePerMinute <= 60000 {
		out.RelaxClientRatePerMinute = in.RelaxClientRatePerMinute
	}
	if in.RelaxClientRateBurst >= 10 && in.RelaxClientRateBurst <= 10000 {
		out.RelaxClientRateBurst = in.RelaxClientRateBurst
	}
	if in.TrustedAdminTTLSeconds >= 60 && in.TrustedAdminTTLSeconds <= 7200 {
		out.TrustedAdminTTLSeconds = in.TrustedAdminTTLSeconds
	}
	if in.BridgeLogPath != "" && filepath.IsAbs(in.BridgeLogPath) && len(in.BridgeLogPath) <= 4096 {
		out.BridgeLogPath = filepath.Clean(in.BridgeLogPath)
	}
	if in.BridgeMaxSkewSeconds >= 30 && in.BridgeMaxSkewSeconds <= 3600 {
		out.BridgeMaxSkewSeconds = in.BridgeMaxSkewSeconds
	}
	return out
}

func (e *CMSEngine) Settings() cmsSettings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.settings
}

func (e *CMSEngine) UpdateSettings(next cmsSettings) error {
	next = sanitizeCMSSettings(next)
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.settingsPath), 0o750); err != nil {
		return err
	}
	if err := writeCMSFileAtomic(e.settingsPath, raw, 0o600); err != nil {
		return err
	}
	e.mu.Lock()
	e.settings = next
	e.mu.Unlock()
	return nil
}

func writeCMSFileAtomic(path string, raw []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cms-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func readCMSBridgeKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("bridge key must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("bridge key must not be group/world accessible")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 32 {
		return append([]byte(nil), raw...), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("bridge key must be 32 raw bytes or 32-byte base64")
	}
	return decoded, nil
}

func (e *CMSEngine) rotateBridgeKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(e.keyPath), 0o750); err != nil {
		return "", err
	}
	if err := writeCMSFileAtomic(e.keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		return "", err
	}
	e.mu.Lock()
	e.key = key
	e.mu.Unlock()
	return base64.StdEncoding.EncodeToString(key), nil
}

func (e *CMSEngine) bridgeFingerprint() string {
	e.mu.RLock()
	key := append([]byte(nil), e.key...)
	e.mu.RUnlock()
	if len(key) != 32 {
		return ""
	}
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// ObserveRequest updates the bounded per-host CMS profile from request shape.
// Cookie values are intentionally unavailable to the control plane; path,
// headers and response evidence are enough for operational detection.
func (e *CMSEngine) ObserveRequest(req l7NormalizedRequest) {
	e.mu.RLock()
	enabled := e.settings.Enabled
	e.mu.RUnlock()
	if !enabled {
		return
	}
	host := normalizeCMSHost(req.Host)
	if host == "" {
		return
	}
	kind, confidence, evidence := detectCMSRequest(req)
	if kind == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.profileLocked(host, kind, confidence, evidence)
}

func (e *CMSEngine) ObserveResponse(host string, headers http.Header, bodyPrefix []byte) {
	e.mu.RLock()
	enabled := e.settings.Enabled
	e.mu.RUnlock()
	if !enabled {
		return
	}
	host = normalizeCMSHost(host)
	if host == "" {
		return
	}
	kind, confidence, evidence := detectCMSResponse(headers, bodyPrefix)
	if kind == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.profileLocked(host, kind, confidence, evidence)
}

func (e *CMSEngine) profileLocked(host string, kind CMSKind, confidence int, evidence []string) {
	profile := e.profiles[host]
	if profile == nil {
		if len(e.profiles) >= cmsBridgeMaxProfiles {
			// Evict the oldest entry rather than unbounded growth.
			var oldestHost string
			var oldest time.Time
			for h, p := range e.profiles {
				if oldestHost == "" || p.lastSeen.Before(oldest) {
					oldestHost, oldest = h, p.lastSeen
				}
			}
			delete(e.profiles, oldestHost)
		}
		profile = &cmsProfile{evidence: make(map[string]struct{})}
		e.profiles[host] = profile
	}
	profile.kind = kind
	if confidence > profile.confidence {
		profile.confidence = confidence
	}
	for _, item := range evidence {
		profile.evidence[item] = struct{}{}
	}
	profile.lastSeen = time.Now().UTC()
}

func (e *CMSEngine) profileFor(host string, now time.Time) *cmsProfile {
	host = normalizeCMSHost(host)
	e.mu.RLock()
	defer e.mu.RUnlock()
	profile := e.profiles[host]
	if profile == nil || now.Sub(profile.lastSeen) > cmsDetectorTTL {
		return nil
	}
	copy := *profile
	copy.evidence = nil
	return &copy
}

func (e *CMSEngine) Trusted(remoteIP, host string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneLeasesLocked(now)
	_, ok := e.leases[cmsLeaseKey(remoteIP, host)]
	return ok
}

func (e *CMSEngine) ShouldRelax(req l7NormalizedRequest) bool {
	e.mu.RLock()
	settings := e.settings
	profile := e.profiles[normalizeCMSHost(req.Host)]
	e.mu.RUnlock()
	if !settings.Enabled || !settings.AutoRelax || !settings.RelaxAdmin || profile == nil {
		return false
	}
	return isCMSAdminPath(profile.kind, req.Path, req.Method)
}

func (e *CMSEngine) pruneLeasesLocked(now time.Time) {
	for key, lease := range e.leases {
		if now.Unix() >= lease.ExpiresAt {
			delete(e.leases, key)
		}
	}
}

func cmsLeaseKey(ip, host string) string {
	return strings.ToLower(strings.TrimSpace(ip)) + "|" + normalizeCMSHost(host)
}

func normalizeCMSHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

func isCMSAdminPath(kind CMSKind, path, method string) bool {
	path = strings.ToLower(path)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	switch kind {
	case CMSWordPress:
		if strings.HasPrefix(path, "/wp-admin/") && !strings.Contains(path, "admin-ajax.php") {
			return true
		}
		return path == "/wp-admin"
	case CMSJoomla:
		return strings.HasPrefix(path, "/administrator/") && method != "GET"
	case CMSTYPO3:
		return strings.HasPrefix(path, "/typo3/") && !strings.HasSuffix(path, "/login")
	case CMSLaravel:
		return strings.HasPrefix(path, "/admin/") && method != "GET"
	default:
		return false
	}
}

func detectCMSRequest(req l7NormalizedRequest) (CMSKind, int, []string) {
	path := strings.ToLower(req.Path)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	headers := lowerCMSHeaders(req.Headers)
	evidence := make([]string, 0, 3)
	// WordPress request shapes.
	if strings.HasPrefix(path, "/wp-admin/") || path == "/wp-login.php" || path == "/xmlrpc.php" ||
		strings.HasPrefix(path, "/wp-json/") || strings.HasPrefix(path, "/wp-content/") || strings.HasPrefix(path, "/wp-includes/") {
		evidence = append(evidence, "wordpress_path")
	}
	if headers["x-pingback"] != "" || strings.Contains(headers["link"], "/wp-json/") || headers["x-wp-nonce"] != "" {
		evidence = append(evidence, "wordpress_header")
	}
	if len(evidence) > 0 {
		return CMSWordPress, 95, evidence
	}
	// Joomla request shapes.
	if strings.HasPrefix(path, "/administrator/") || strings.HasPrefix(path, "/components/") ||
		strings.HasPrefix(path, "/modules/") || strings.HasPrefix(path, "/templates/") ||
		strings.HasPrefix(path, "/api/index.php/v1/") {
		return CMSJoomla, 85, []string{"joomla_path"}
	}
	// TYPO3 request shapes.
	if strings.HasPrefix(path, "/typo3/") || strings.HasPrefix(path, "/typo3temp/") ||
		strings.HasPrefix(path, "/typo3conf/") || strings.HasPrefix(path, "/fileadmin/") {
		return CMSTYPO3, 85, []string{"typo3_path"}
	}
	// Laravel cannot be identified from a single generic path with acceptable
	// confidence; explicit Laravel session/API evidence belongs in the response
	// path. This keeps the detector honest instead of treating every /api/ as Laravel.
	return "", 0, nil
}

func detectCMSResponse(headers http.Header, bodyPrefix []byte) (CMSKind, int, []string) {
	if headers == nil {
		return "", 0, nil
	}
	lower := make(map[string]string, len(headers))
	for name, values := range headers {
		if len(values) > 0 {
			lower[strings.ToLower(name)] = strings.Join(values, ",")
		}
	}
	body := strings.ToLower(string(bodyPrefix))
	evidence := make([]string, 0, 3)
	if strings.Contains(body, `<meta name="generator" content="wordpress`) || strings.Contains(lower["link"], "/wp-json/") || lower["x-pingback"] != "" {
		evidence = append(evidence, "wordpress_generator")
		if strings.Contains(lower["link"], "/wp-json/") {
			evidence = append(evidence, "wordpress_rest_link")
		}
		return CMSWordPress, 100, evidence
	}
	if strings.Contains(body, `<meta name="generator" content="joomla`) || strings.Contains(lower["x-content-encoded-by"], "joomla") {
		return CMSJoomla, 100, []string{"joomla_generator"}
	}
	if strings.Contains(body, `<meta name="generator" content="typo3`) || lower["x-typo3"] != "" {
		return CMSTYPO3, 100, []string{"typo3_generator"}
	}
	if strings.Contains(lower["set-cookie"], "laravel_session") || strings.Contains(lower["x-powered-by"], "laravel") {
		return CMSLaravel, 80, []string{"laravel_session"}
	}
	return "", 0, nil
}

func lowerCMSHeaders(headers map[string][]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, values := range headers {
		if len(values) > 0 {
			out[strings.ToLower(name)] = strings.Join(values, ",")
		}
	}
	return out
}

func (e *CMSEngine) Status() cmsStatus {
	e.mu.RLock()
	key := append([]byte(nil), e.key...)
	e.mu.RUnlock()
	bridgeKeySet := len(key) == 32
	bridgeFP := ""
	if bridgeKeySet {
		sum := sha256.Sum256(key)
		bridgeFP = hex.EncodeToString(sum[:8])
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now().UTC()
	e.pruneLeasesLocked(now)
	status := cmsStatus{
		Settings:     e.settings,
		BridgeKeySet: bridgeKeySet,
		BridgeKeyFP:  bridgeFP,
		Detections:   make([]cmsDetection, 0, len(e.profiles)),
		Leases:       make([]cmsLease, 0, len(e.leases)),
	}
	for host, profile := range e.profiles {
		if now.Sub(profile.lastSeen) > cmsDetectorTTL {
			continue
		}
		evidence := make([]string, 0, len(profile.evidence))
		for item := range profile.evidence {
			evidence = append(evidence, item)
		}
		status.Detections = append(status.Detections, cmsDetection{
			Kind: profile.kind, Host: host, Confidence: profile.confidence,
			Evidence: evidence, LastSeen: profile.lastSeen.Format(time.RFC3339),
		})
	}
	for _, lease := range e.leases {
		status.Leases = append(status.Leases, lease)
	}
	e.bridgeMu.Lock()
	if !e.bridgeLast.IsZero() {
		status.BridgeLastRead = e.bridgeLast.Format(time.RFC3339)
	}
	status.BridgeLastErr = e.bridgeErr
	e.bridgeMu.Unlock()
	return status
}

// Run polls the configured bridge file until ctx is cancelled. It is safe to
// call once; repeated calls are ignored by the caller.
func (e *CMSEngine) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		e.pollBridge()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *CMSEngine) pollBridge() {
	settings := e.Settings()
	if !settings.BridgeEnabled || settings.BridgeLogPath == "" || e.bridgeFingerprint() == "" {
		return
	}
	info, err := os.Stat(settings.BridgeLogPath)
	if err != nil {
		e.setBridgeError(fmt.Errorf("bridge log: %w", err))
		return
	}
	if !info.Mode().IsRegular() {
		e.setBridgeError(errors.New("bridge log must be a regular file"))
		return
	}
	inode := cmsFileInode(info)
	e.bridgeMu.Lock()
	if inode != 0 && e.bridgeInode != 0 && inode != e.bridgeInode {
		e.bridgeOffset = 0
		e.bridgeSeen = make(map[string]struct{})
	}
	if info.Size() < e.bridgeOffset {
		e.bridgeOffset = 0
	}
	offset := e.bridgeOffset
	e.bridgeInode = inode
	e.bridgeMu.Unlock()

	file, err := os.Open(settings.BridgeLogPath)
	if err != nil {
		e.setBridgeError(err)
		return
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		e.setBridgeError(err)
		return
	}
	reader := bufio.NewReaderSize(io.LimitReader(file, cmsBridgeReadBudget), cmsBridgeMaxLineBytes)
	consumed := int64(0)
	for {
		line, readErr := reader.ReadBytes('\n')
		consumed += int64(len(line))
		if len(line) > 0 {
			e.consumeBridgeLine(bytes.TrimSpace(line))
		}
		if readErr != nil {
			break
		}
	}
	e.bridgeMu.Lock()
	e.bridgeOffset += consumed
	e.bridgeLast = time.Now().UTC()
	e.bridgeMu.Unlock()
}

func (e *CMSEngine) consumeBridgeLine(line []byte) {
	if len(line) == 0 {
		return
	}
	if len(line) > cmsBridgeMaxLineBytes {
		return
	}
	if bytes.HasPrefix(line, []byte(cmsBridgePrefix)) {
		line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte(cmsBridgePrefix)))
	}
	event, err := e.decryptBridgeLine(line)
	if err != nil {
		e.setBridgeError(err)
		return
	}
	id := strings.TrimSpace(event.EventID)
	if id == "" {
		id = fmt.Sprintf("%s|%s|%d", event.IP, event.SiteHost, event.IssuedAt)
	}
	e.mu.Lock()
	if _, seen := e.bridgeSeen[id]; seen {
		e.mu.Unlock()
		return
	}
	if len(e.bridgeSeen) >= cmsBridgeMaxLeases*2 {
		e.bridgeSeen = make(map[string]struct{})
	}
	e.bridgeSeen[id] = struct{}{}
	ttl := time.Duration(e.settings.TrustedAdminTTLSeconds) * time.Second
	maxExpiry := time.Now().Add(ttl).Unix()
	if event.ExpiresAt > maxExpiry {
		event.ExpiresAt = maxExpiry
	}
	lease := cmsLease{IP: event.IP, Host: normalizeCMSHost(event.SiteHost), User: event.User, Source: "wordpress-bridge", IssuedAt: event.IssuedAt, ExpiresAt: event.ExpiresAt}
	e.leases[cmsLeaseKey(lease.IP, lease.Host)] = lease
	if host := lease.Host; host != "" {
		p := e.profiles[host]
		if p == nil {
			p = &cmsProfile{evidence: make(map[string]struct{})}
			e.profiles[host] = p
		}
		p.kind = CMSWordPress
		p.confidence = 100
		p.evidence["wordpress_bridge"] = struct{}{}
		p.lastSeen = time.Now().UTC()
	}
	e.mu.Unlock()
	e.setBridgeError(nil)
}

func (e *CMSEngine) decryptBridgeLine(line []byte) (cmsBridgeEvent, error) {
	e.mu.RLock()
	key := append([]byte(nil), e.key...)
	settings := e.settings
	e.mu.RUnlock()
	if len(key) != 32 {
		return cmsBridgeEvent{}, errors.New("bridge key unavailable")
	}
	var envelope cmsBridgeEnvelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return cmsBridgeEvent{}, fmt.Errorf("bridge envelope: %w", err)
	}
	if envelope.Slug != "GeDefense" {
		return cmsBridgeEvent{}, errors.New("bridge slug rejected")
	}
	iv, err := base64.StdEncoding.DecodeString(envelope.IV)
	if err != nil || len(iv) != 12 {
		return cmsBridgeEvent{}, errors.New("bridge nonce rejected")
	}
	tag, err := base64.StdEncoding.DecodeString(envelope.Tag)
	if err != nil || len(tag) != 16 {
		return cmsBridgeEvent{}, errors.New("bridge tag rejected")
	}
	data, err := base64.StdEncoding.DecodeString(envelope.Data)
	if err != nil {
		return cmsBridgeEvent{}, errors.New("bridge data rejected")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return cmsBridgeEvent{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return cmsBridgeEvent{}, err
	}
	plain, err := gcm.Open(nil, iv, append(data, tag...), []byte(cmsBridgeAAD))
	if err != nil {
		return cmsBridgeEvent{}, errors.New("bridge authentication failed")
	}
	var event cmsBridgeEvent
	if err := json.Unmarshal(plain, &event); err != nil {
		return cmsBridgeEvent{}, fmt.Errorf("bridge event JSON: %w", err)
	}
	now := time.Now().Unix()
	if event.Version != 1 || event.Event != "master_login" {
		return cmsBridgeEvent{}, errors.New("bridge event invalid")
	}
	if net.ParseIP(event.IP) == nil {
		return cmsBridgeEvent{}, errors.New("bridge event invalid")
	}
	if event.SiteHost == "" || event.ExpiresAt <= now || event.ExpiresAt > now+int64(settings.TrustedAdminTTLSeconds)+int64(settings.BridgeMaxSkewSeconds) {
		return cmsBridgeEvent{}, errors.New("bridge lease bounds rejected")
	}
	if event.IssuedAt > now+int64(settings.BridgeMaxSkewSeconds) || event.IssuedAt < now-86400 {
		return cmsBridgeEvent{}, errors.New("bridge timestamp rejected")
	}
	return event, nil
}

func (e *CMSEngine) setBridgeError(err error) {
	e.bridgeMu.Lock()
	defer e.bridgeMu.Unlock()
	if err == nil {
		e.bridgeErr = ""
		return
	}
	e.bridgeErr = err.Error()
}

func (e *CMSEngine) RevokeLeases() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	count := len(e.leases)
	e.leases = make(map[string]cmsLease)
	return count
}
