package edgeproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	StateStopped = "stopped"
	StateRunning = "running"
	StateError   = "error"
	recentBlocks = 64
)

// BlockEvent is one refused request. The path is truncated and never contains a
// body; the main package turns it into a medium incident.
type BlockEvent struct {
	At     time.Time `json:"at"`
	Peer   string    `json:"peer"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Reason string    `json:"reason"`
	Status int       `json:"status"`
}

// Counters are monotonic except Active, which is a gauge.
type Counters struct {
	Requests uint64 `json:"requests"`
	Blocked  uint64 `json:"blocked"`
	Active   int64  `json:"active"`
}

// H2Limits is the effective RFC-9113 envelope reported to the dashboard.
type H2Limits struct {
	MaxConcurrentStreams int   `json:"max_concurrent_streams"`
	MaxReadFrameSize     int   `json:"max_read_frame_size"`
	MaxHeaderBytes       int   `json:"max_header_bytes"`
	MaxBodyBytes         int64 `json:"max_body_bytes"`
}

// Status is the JSON contract consumed by the edge-proxy view.
type Status struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Enabled     bool         `json:"enabled"`
	State       string       `json:"state"`
	Listen      string       `json:"listen"`
	Upstream    string       `json:"upstream"`
	Fingerprint string       `json:"fingerprint"`
	MinTLS      string       `json:"min_tls"`
	H2          H2Limits     `json:"h2"`
	Counters    Counters     `json:"counters"`
	Recent      []BlockEvent `json:"recent"`
	Reason      string       `json:"reason"`
	StartedAt   *time.Time   `json:"started_at,omitempty"`
}

type runtimeState struct {
	cfg     Config
	methods map[string]bool
	proxy   *httputil.ReverseProxy
	limiter *limiter
}

// Manager owns the single edge listener. Apply/Sync is idempotent and only
// restarts when the effective configuration really changed.
type Manager struct {
	mu          sync.Mutex
	cfg         Config
	signature   string
	state       string
	reason      string
	fingerprint string
	started     time.Time
	server      *http.Server
	listener    net.Listener
	current     atomic.Pointer[runtimeState]
	requests    atomic.Uint64
	blocked     atomic.Uint64
	active      atomic.Int64
	recent      [recentBlocks]BlockEvent
	recentCount int
	recentNext  int
	onBlock     func(BlockEvent)
}

func NewManager() *Manager {
	return &Manager{state: StateStopped}
}

// OnBlock registers the incident sink. It must be cheap and must not call back
// into the manager.
func (m *Manager) OnBlock(sink func(BlockEvent)) {
	m.mu.Lock()
	m.onBlock = sink
	m.mu.Unlock()
}

// Sync converges the running listener to cfg. A disabled config stops it; an
// unchanged config is a no-op; enabling without a certificate fails closed.
func (m *Manager) Sync(cfg Config) error {
	cfg = cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		m.mu.Lock()
		m.stopLocked()
		m.state = StateError
		m.reason = "invalid configuration: " + err.Error()
		m.mu.Unlock()
		return err
	}
	signature := fmt.Sprintf("%+v", cfg)
	m.mu.Lock()
	defer m.mu.Unlock()
	if signature == m.signature && (m.state == StateRunning || (!cfg.Enabled && m.state == StateStopped)) {
		m.cfg = cfg
		return nil
	}
	m.stopLocked()
	m.cfg = cfg
	m.signature = signature
	m.reason = ""
	if !cfg.Enabled {
		m.state = StateStopped
		return nil
	}
	if err := m.startLocked(cfg); err != nil {
		m.state = StateError
		m.reason = err.Error()
		return err
	}
	m.state = StateRunning
	m.started = time.Now().UTC()
	return nil
}

// Stop terminates the listener and leaves the manager in the stopped state.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	m.signature = ""
	m.state = StateStopped
	m.reason = "stopped by operator"
}

func (m *Manager) startLocked(cfg Config) error {
	keyInfo, keyErr := os.Lstat(cfg.KeyFile)
	if keyErr != nil {
		return fmt.Errorf("inspect edge private key: %w", keyErr)
	}
	if keyInfo.Mode()&os.ModeSymlink != 0 || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("edge private key must be a non-symlink regular file without group/world access")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load edge certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse edge certificate: %w", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("bind edge listener: %w", err)
	}
	proxy, err := buildProxy(cfg)
	if err != nil {
		_ = listener.Close()
		return err
	}
	methods := make(map[string]bool, len(cfg.AllowedMethods))
	for _, method := range cfg.AllowedMethods {
		methods[method] = true
	}
	rt := &runtimeState{
		cfg:     cfg,
		methods: methods,
		proxy:   proxy,
		limiter: newLimiter(cfg.RateLimitPerMinute, 4096),
	}
	minVersion := uint16(tls.VersionTLS13)
	if cfg.MinTLSVersion == "TLS1.2" {
		minVersion = tls.VersionTLS12
	}
	server := &http.Server{
		Handler:           m,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Duration(cfg.RequestTimeoutSecond) * time.Second,
		IdleTimeout:       time.Duration(cfg.IdleTimeoutSeconds) * time.Second,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   minVersion,
		},
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          cfg.MaxConcurrentStreams,
			MaxReadFrameSize:              16 << 10,
			MaxDecoderHeaderTableSize:     8 << 10,
			MaxEncoderHeaderTableSize:     8 << 10,
			MaxReceiveBufferPerConnection: 1 << 20,
			MaxReceiveBufferPerStream:     256 << 10,
			PingTimeout:                   15 * time.Second,
			WriteByteTimeout:              30 * time.Second,
		},
	}
	m.fingerprint = hex.EncodeToString(sum[:])
	m.server = server
	m.listener = listener
	m.current.Store(rt)
	m.requests.Store(0)
	m.blocked.Store(0)
	m.recentCount, m.recentNext = 0, 0
	go func() {
		serveErr := server.ServeTLS(listener, "", "")
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			m.mu.Lock()
			if m.server == server {
				m.state = StateError
				m.reason = "listener stopped: " + serveErr.Error()
				m.current.Store(nil)
			}
			m.mu.Unlock()
		}
	}()
	return nil
}

func (m *Manager) stopLocked() {
	server, listener := m.server, m.listener
	m.server, m.listener = nil, nil
	m.current.Store(nil)
	if server == nil {
		if listener != nil {
			_ = listener.Close()
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	if listener != nil {
		_ = listener.Close()
	}
}

// GetStatus returns a consistent snapshot for the dashboard.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := Status{
		GeneratedAt: time.Now().UTC(),
		Enabled:     m.cfg.Enabled,
		State:       m.state,
		Listen:      m.cfg.Listen,
		Upstream:    m.cfg.Upstream,
		Fingerprint: m.fingerprint,
		MinTLS:      m.cfg.MinTLSVersion,
		H2: H2Limits{
			MaxConcurrentStreams: m.cfg.MaxConcurrentStreams,
			MaxReadFrameSize:     16 << 10,
			MaxHeaderBytes:       m.cfg.MaxHeaderBytes,
			MaxBodyBytes:         m.cfg.MaxBodyBytes,
		},
		Counters: Counters{
			Requests: m.requests.Load(),
			Blocked:  m.blocked.Load(),
			Active:   m.active.Load(),
		},
		Reason: m.reason,
	}
	if m.state == StateRunning && !m.started.IsZero() {
		started := m.started
		status.StartedAt = &started
	}
	status.Recent = make([]BlockEvent, 0, m.recentCount)
	for index := 0; index < m.recentCount; index++ {
		position := (m.recentNext - m.recentCount + index + recentBlocks) % recentBlocks
		status.Recent = append(status.Recent, m.recent[position])
	}
	return status
}

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt := m.current.Load()
	if rt == nil {
		http.Error(w, "edge proxy is not running", http.StatusServiceUnavailable)
		return
	}
	m.requests.Add(1)
	m.active.Add(1)
	defer m.active.Add(-1)
	peer := clientPeer(r.RemoteAddr)
	if !rt.limiter.allow(peer) {
		m.refuse(w, r, peer, Verdict{Blocked: true, Status: http.StatusTooManyRequests, Reason: "rate_limited"})
		return
	}
	if verdict := InspectRequest(r, rt.cfg, rt.methods); verdict.Blocked {
		m.refuse(w, r, peer, verdict)
		return
	}
	if rt.cfg.MaxBodyBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, rt.cfg.MaxBodyBytes)
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(rt.cfg.RequestTimeoutSecond)*time.Second)
	defer cancel()
	rt.proxy.ServeHTTP(w, r.WithContext(ctx))
}

func (m *Manager) refuse(w http.ResponseWriter, r *http.Request, peer string, verdict Verdict) {
	m.blocked.Add(1)
	event := BlockEvent{
		At:     time.Now().UTC(),
		Peer:   peer,
		Method: strings.ToUpper(r.Method),
		Path:   truncate(r.URL.Path, 128),
		Reason: verdict.Reason,
		Status: verdict.Status,
	}
	m.mu.Lock()
	m.recent[m.recentNext] = event
	m.recentNext = (m.recentNext + 1) % recentBlocks
	if m.recentCount < recentBlocks {
		m.recentCount++
	}
	sink := m.onBlock
	m.mu.Unlock()
	if sink != nil {
		sink(event)
	}
	http.Error(w, http.StatusText(verdict.Status), verdict.Status)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func buildProxy(cfg Config) (*httputil.ReverseProxy, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("parse edge upstream: %w", err)
	}
	target := &url.URL{Scheme: "http"}
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.RequestTimeoutSecond) * time.Second,
		DisableCompression:    false,
		ForceAttemptHTTP2:     false,
	}
	switch upstream.Scheme {
	case "unix":
		socket := upstream.Path
		target.Host = "unix"
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		}
	case "http":
		target.Host = upstream.Host
		transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	default:
		return nil, errors.New("unsupported edge upstream scheme")
	}
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: 100 * time.Millisecond,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			// SetXForwarded prepends the inbound X-Forwarded-For value. A client
			// must never be able to seed the upstream's forwarding chain, so the
			// inbound value (and the RFC 7239 Forwarded header) is removed before
			// the proxy writes its own peer-derived value.
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Real-IP")
			pr.Out.Header.Del("Forwarded")
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var maxBytes *http.MaxBytesError
			status := http.StatusBadGateway
			if errors.As(err, &maxBytes) {
				status = http.StatusRequestEntityTooLarge
			}
			if r.Context().Err() == context.DeadlineExceeded {
				status = http.StatusGatewayTimeout
			}
			http.Error(w, http.StatusText(status), status)
		},
	}
	return proxy, nil
}
