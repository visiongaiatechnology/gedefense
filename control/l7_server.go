// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type l7PeerContextKey struct{}

type l7BoundedListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newL7BoundedListener(listener net.Listener, maxConnections int) net.Listener {
	return &l7BoundedListener{Listener: listener, sem: make(chan struct{}, maxConnections), done: make(chan struct{})}
}

func l7ConnectionLimit(maxConcurrent int) int {
	limit := maxConcurrent * 4
	if limit < 32 {
		limit = 32
	}
	if limit > 2048 {
		limit = 2048
	}
	return limit
}

func (l *l7BoundedListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &l7LimitedConn{Conn: conn, release: func() { <-l.sem }}, nil
}

func (l *l7BoundedListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type l7LimitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *l7LimitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type L7Service struct {
	cfg       L7Config
	live      *l7Runtime
	engine    *L7Engine
	state     *State
	server    *http.Server
	listener  net.Listener
	errors    chan error
	started   atomic.Bool
	startedAt time.Time

	requests      atomic.Uint64
	findings      atomic.Uint64
	blocked       atomic.Uint64
	rateLimited   atomic.Uint64
	rejected      atomic.Uint64
	active        atomic.Int32
	lastUnix      atomic.Int64
	tlsHandshakes atomic.Uint64
	tlsFindings   atomic.Uint64
	tlsLastUnix   atomic.Int64
	tlsSinkMu     sync.RWMutex
	tlsSink       func(string, TLSClientHelloSummary, []L7Finding, time.Time)
	tlsLastErrMu  sync.RWMutex
	tlsLastErr    string
	lastErrMu     sync.RWMutex
	lastErr       string
}

func NewL7Service(cfg L7Config, engine *L7Engine, state *State) (*L7Service, error) {
	if engine == nil || state == nil {
		return nil, errors.New("l7 service requires engine and state")
	}
	if engine.live == nil {
		return nil, errors.New("l7 service requires a published runtime configuration")
	}
	return &L7Service{cfg: cfg, live: engine.live, engine: engine, state: state, errors: make(chan error, 1), startedAt: time.Now().UTC()}, nil
}

// snapshot returns the configuration the service must observe right now. The
// listener lifecycle still uses the boot configuration, which is the only
// configuration that can describe an already-bound socket.
func (s *L7Service) snapshot() *l7RuntimeSnapshot {
	if s.live == nil {
		return nil
	}
	return s.live.current()
}

func (s *L7Service) Start() error {
	if !s.cfg.Enabled {
		s.publishStatus(true)
		return nil
	}
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("l7 service already started")
	}
	listener, err := openL7UnixListener(s.cfg.Socket, s.cfg.SocketGroup)
	if err != nil {
		s.setError(err)
		return err
	}
	s.listener = newL7BoundedListener(listener, l7ConnectionLimit(s.cfg.MaxConcurrent))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/inspect", s.inspect)
	mux.HandleFunc("POST /v1/tls/clienthello", s.inspectTLSClientHello)
	mux.HandleFunc("GET /healthz", s.health)
	timeout := time.Duration(s.cfg.RequestTimeoutMillis) * time.Millisecond
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: timeout,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,
		IdleTimeout:       2 * timeout,
		MaxHeaderBytes:    8 << 10,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			credentials, err := l7PeerCredentialsFromConn(unwrapL7Conn(conn))
			if err != nil {
				return context.WithValue(ctx, l7PeerContextKey{}, l7PeerCredentials{})
			}
			return context.WithValue(ctx, l7PeerContextKey{}, credentials)
		},
	}
	s.publishStatus(true)
	go func() {
		err := s.server.Serve(s.listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.setError(err)
			select {
			case s.errors <- err:
			default:
			}
		}
	}()
	return nil
}

func unwrapL7Conn(conn net.Conn) net.Conn {
	if limited, ok := conn.(*l7LimitedConn); ok {
		return limited.Conn
	}
	return conn
}

func openL7UnixListener(path, groupName string) (net.Listener, error) {
	if err := prepareL7SocketPath(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on l7 unix socket: %w", err)
	}
	cleanup := func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		cleanup()
		return nil, fmt.Errorf("secure l7 unix socket permissions: %w", err)
	}
	if groupName == "" {
		return listener, nil
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("resolve l7 socket group: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		cleanup()
		return nil, errors.New("resolved l7 socket group has invalid gid")
	}
	if err := os.Chown(path, -1, gid); err != nil {
		cleanup()
		return nil, fmt.Errorf("assign l7 socket group: %w", err)
	}
	return listener, nil
}

func prepareL7SocketPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return errors.New("l7 socket path must be a clean absolute path of at most 100 bytes")
	}
	parent := filepath.Dir(path)
	if parent == "/" {
		return errors.New("l7 socket must reside in a dedicated runtime directory")
	}
	if err := validateL7RuntimeDirectory(parent); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace non-socket l7 path")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale l7 socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect l7 socket path: %w", err)
	}
	return nil
}

func validateL7RuntimeDirectory(parent string) error {
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return errors.New("l7 runtime directory must be a clean absolute path")
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("l7 runtime directory must be pre-provisioned: %s", current)
			}
			return fmt.Errorf("inspect l7 runtime directory component %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("l7 runtime directory contains non-directory or symlink component: %s", current)
		}
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect l7 runtime directory: %w", err)
	}
	if parentInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("l7 runtime directory must not be group- or world-writable")
	}
	return nil
}

func (s *L7Service) inspect(w http.ResponseWriter, r *http.Request) {
	s.active.Add(1)
	defer s.active.Add(-1)
	snapshot := s.snapshot()
	if snapshot == nil {
		s.rejected.Add(1)
		s.writeError(w, http.StatusServiceUnavailable, "request rejected")
		return
	}
	if !s.authorized(r.Context()) {
		s.rejected.Add(1)
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	timeout := time.Duration(s.cfg.RequestTimeoutMillis) * time.Millisecond
	admissionCtx, admissionCancel := context.WithTimeout(r.Context(), timeout)
	admissionErr := s.engine.acquireAdmission(admissionCtx)
	admissionCancel()
	if admissionErr != nil {
		s.rejected.Add(1)
		s.writeError(w, http.StatusServiceUnavailable, "inspection busy")
		return
	}
	defer s.engine.releaseAdmission()
	body := http.MaxBytesReader(w, r.Body, int64(snapshot.cfg.MaxEnvelopeBytes))
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request L7InspectionRequest
	if err := decoder.Decode(&request); err != nil {
		s.rejected.Add(1)
		s.writeError(w, http.StatusBadRequest, "invalid inspection envelope")
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		s.rejected.Add(1)
		s.writeError(w, http.StatusBadRequest, "invalid inspection envelope")
		return
	}
	if credentials, ok := r.Context().Value(l7PeerContextKey{}).(l7PeerCredentials); ok && credentials.PID > 0 {
		request.ServerPID = int(credentials.PID)
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	response, err := s.engine.Inspect(ctx, request)
	if err != nil {
		s.rejected.Add(1)
		status := http.StatusBadRequest
		if errors.Is(err, ErrL7ResourceLimit) {
			status = http.StatusRequestEntityTooLarge
		} else if errors.Is(err, ErrL7UnsupportedEncoding) {
			status = http.StatusUnsupportedMediaType
		} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = http.StatusServiceUnavailable
		}
		s.writeError(w, status, "inspection rejected")
		return
	}
	s.requests.Add(1)
	s.findings.Add(uint64(len(response.Findings)))
	if response.Decision == "block" {
		s.blocked.Add(1)
	}
	for _, finding := range response.Findings {
		if finding.Category == "rate-limit" {
			s.rateLimited.Add(1)
			break
		}
	}
	now := time.Now().UTC()
	s.lastUnix.Store(now.UnixNano())
	s.publishStatus(true)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(response); err != nil {
		s.setError(err)
	}
}

func (s *L7Service) SetTLSFindingSink(sink func(string, TLSClientHelloSummary, []L7Finding, time.Time)) {
	s.tlsSinkMu.Lock()
	s.tlsSink = sink
	s.tlsSinkMu.Unlock()
}

func (s *L7Service) inspectTLSClientHello(w http.ResponseWriter, r *http.Request) {
	s.active.Add(1)
	defer s.active.Add(-1)
	snapshot := s.snapshot()
	if snapshot == nil || !snapshot.cfg.TLSEnabled {
		s.writeError(w, http.StatusNotFound, "TLS inspection disabled")
		return
	}
	if !s.authorized(r.Context()) {
		s.rejected.Add(1)
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	maxEnvelope := int64(((snapshot.cfg.TLSMaxClientHelloBytes + 2) / 3 * 4) + (16 << 10))
	body := http.MaxBytesReader(w, r.Body, maxEnvelope)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request L7TLSClientHelloRequest
	if err := decoder.Decode(&request); err != nil || ensureJSONEOF(decoder) != nil {
		s.rejected.Add(1)
		s.setTLSError(errors.New("invalid TLS inspection envelope"))
		s.writeError(w, http.StatusBadRequest, "invalid TLS inspection envelope")
		return
	}
	if request.Version != l7ProtocolVersion || net.ParseIP(request.ClientIP) == nil {
		s.rejected.Add(1)
		s.setTLSError(errors.New("invalid TLS inspection metadata"))
		s.writeError(w, http.StatusBadRequest, "invalid TLS inspection metadata")
		return
	}
	decodedLen := base64.StdEncoding.DecodedLen(len(request.ClientHelloBase64))
	if decodedLen <= 0 || decodedLen > snapshot.cfg.TLSMaxClientHelloBytes {
		s.rejected.Add(1)
		s.setTLSError(ErrL7ResourceLimit)
		s.writeError(w, http.StatusRequestEntityTooLarge, "TLS ClientHello exceeds configured bound")
		return
	}
	payload := make([]byte, decodedLen)
	n, err := base64.StdEncoding.Strict().Decode(payload, []byte(request.ClientHelloBase64))
	if err != nil || n <= 0 || n > snapshot.cfg.TLSMaxClientHelloBytes {
		s.rejected.Add(1)
		s.setTLSError(errors.New("invalid TLS ClientHello base64"))
		s.writeError(w, http.StatusBadRequest, "invalid TLS ClientHello payload")
		return
	}
	payload = payload[:n]
	now := time.Now().UTC()
	summary, findings, err := s.engine.InspectTLSHandshake(request.ClientIP, payload, now)
	if err != nil {
		s.rejected.Add(1)
		s.setTLSError(err)
		status := http.StatusBadRequest
		if errors.Is(err, ErrL7ResourceLimit) {
			status = http.StatusRequestEntityTooLarge
		}
		s.writeError(w, status, "TLS inspection rejected")
		return
	}
	s.tlsHandshakes.Add(1)
	s.tlsFindings.Add(uint64(len(findings)))
	s.tlsLastUnix.Store(now.UnixNano())
	s.clearTLSError()
	s.publishStatus(true)

	s.tlsSinkMu.RLock()
	sink := s.tlsSink
	s.tlsSinkMu.RUnlock()
	if sink != nil && len(findings) > 0 {
		sink(net.ParseIP(request.ClientIP).String(), summary, findings, now)
	}

	decision := "allow"
	if len(findings) > 0 {
		decision = "observe"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(L7TLSClientHelloResponse{Decision: decision, Summary: summary, Findings: findings}); err != nil {
		s.setTLSError(err)
	}
}

func (s *L7Service) setTLSError(err error) {
	if err == nil {
		return
	}
	s.tlsLastErrMu.Lock()
	s.tlsLastErr = err.Error()
	s.tlsLastErrMu.Unlock()
	s.publishStatus(true)
}

func (s *L7Service) clearTLSError() {
	s.tlsLastErrMu.Lock()
	s.tlsLastErr = ""
	s.tlsLastErrMu.Unlock()
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple json values are not allowed")
}

func (s *L7Service) health(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r.Context()) {
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	status := s.state.Snapshot().L7
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok", "protocol": l7ProtocolVersion, "coverage": status.Coverage,
		"traffic_path_verified": status.TrafficPathVerified, "tls_enabled": status.TLSEnabled,
		"tls_path_verified": status.TLSPathVerified,
	})
}

func (s *L7Service) authorized(ctx context.Context) bool {
	snapshot := s.snapshot()
	if snapshot == nil {
		return false
	}
	return l7PeerAuthorized(snapshot.cfg, ctx)
}

func l7PeerAuthorized(cfg L7Config, ctx context.Context) bool {
	if !cfg.RequirePeerCredentials {
		return true
	}
	cred, ok := ctx.Value(l7PeerContextKey{}).(l7PeerCredentials)
	if !ok {
		return false
	}
	for _, uid := range cfg.AllowedPeerUIDs {
		if cred.UID == uid {
			return true
		}
	}
	for _, gid := range cfg.AllowedPeerGIDs {
		if cred.GID == gid {
			return true
		}
	}
	return false
}

func (s *L7Service) writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (s *L7Service) setError(err error) {
	if err == nil {
		return
	}
	s.lastErrMu.Lock()
	s.lastErr = err.Error()
	s.lastErrMu.Unlock()
	s.publishStatus(false)
}

// describeL7Coverage turns a coverage verdict into the sentence an operator reads. It is
// a pure function of the verdict alone, so the publisher and the snapshot can both derive
// the reason without one of them having to own it.
func describeL7Coverage(coverage string) string {
	switch coverage {
	case "OFFLINE":
		return "L7 service is not healthy"
	case "INLINE_DEGRADED":
		return "inline L7 listener is degraded"
	case "NO_TRAFFIC_WARNING":
		return "L7 service is alive but no HTTP or TLS inspection traffic has traversed it for more than five minutes"
	case "TLS_NOT_IN_PATH":
		return "HTTP inspection traffic is active, but TLS inspection is enabled and no ClientHello telemetry has reached the TLS sensor"
	case "READY_NOT_ATTACHED":
		return "L7 engine is healthy; no inline listener or producer is attached, so the engine is available but not in the traffic path"
	case "HEALTHY_AWAITING_TRAFFIC":
		return "L7 service is healthy and awaiting its first verified inspection"
	case "TRAFFIC_ACTIVE":
		return "verified application-layer inspection traffic is active"
	default:
		return "L7 subsystem disabled"
	}
}

func (s *L7Service) publishStatus(healthy bool) {
	if s.state == nil {
		return
	}
	s.lastErrMu.RLock()
	lastErr := s.lastErr
	s.lastErrMu.RUnlock()
	s.tlsLastErrMu.RLock()
	tlsLastErr := s.tlsLastErr
	s.tlsLastErrMu.RUnlock()
	var last *time.Time
	if raw := s.lastUnix.Load(); raw > 0 {
		t := time.Unix(0, raw).UTC()
		last = &t
	}
	var tlsLast *time.Time
	if raw := s.tlsLastUnix.Load(); raw > 0 {
		t := time.Unix(0, raw).UTC()
		tlsLast = &t
	}
	fpVersion, fpSource, fpSignatures, fpProfiles := s.engine.TLSFingerprintStatus()
	uptime := int64(time.Since(s.startedAt).Seconds())
	snapshot := s.snapshot()
	desired := s.cfg
	if snapshot != nil {
		desired = snapshot.cfg
	}
	s.state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = s.cfg.Enabled
		status.Mode = desired.Mode
		status.Healthy = healthy
		status.Socket = s.cfg.Socket
		status.RequestsTotal = s.requests.Load()
		status.FindingsTotal = s.findings.Load()
		status.BlockedTotal = s.blocked.Load()
		status.RateLimitedTotal = s.rateLimited.Load()
		status.RejectedTotal = s.rejected.Load()
		status.ActiveConnections = s.active.Load()
		status.LastInspection = last
		status.LastError = lastErr
		status.TLSEnabled = desired.TLSEnabled
		status.TLSHandshakesTotal = s.tlsHandshakes.Load()
		status.TLSFindingsTotal = s.tlsFindings.Load()
		status.TLSLastHandshake = tlsLast
		status.TLSLastError = tlsLastErr
		status.TLSFingerprintVersion = fpVersion
		status.TLSFingerprintSource = fpSource
		status.TLSFingerprintSignatures = fpSignatures
		status.TLSFingerprintProfiles = fpProfiles
		// The requirement is decided before the verdict, because the verdict consults
		// it: TLS silence is only a finding when coverage was asked for.
		status.CoverageRequired = l7CoverageRequired(s.cfg.CoverageRequired, s.cfg.Enabled,
			s.cfg.InlineEnabled || status.RequestsTotal+status.InlineRequestsTotal > 0 || status.TLSHandshakesTotal > 0)
		status.Coverage = EvaluateL7Coverage(*status, uptime)
		status.TrafficPathVerified = status.Coverage == "TRAFFIC_ACTIVE"
		status.TLSPathVerified = !status.TLSEnabled || status.TLSHandshakesTotal > 0
		// Attachment and producer presence are published separately from coverage, so
		// the interface can show engine health, path attachment and verified traffic as
		// three independent facts instead of one collapsed verdict.
		status.RequestsSeen = status.RequestsTotal + status.InlineRequestsTotal
		status.ProducerAttached = status.RequestsTotal > 0
		status.TrafficPathAttached = status.InlineEnabled || status.RequestsSeen > 0 || status.TLSHandshakesTotal > 0
		if status.LastInspection != nil {
			status.LastRequestAt = status.LastInspection
		}
		if status.ProducerAttached && status.LastInspection != nil {
			status.LastProducerSeen = status.LastInspection
		}
		status.CoverageReason = describeL7Coverage(status.Coverage)
		// The web surface is discovered here rather than at startup, so a server that
		// is installed after the service started is still seen on the next pass.
		status.WebSurface = discoverWebSurface()
		// MISWIRED is the state that matters most to an operator: this host serves web
		// traffic, L7 is enabled, and none of that traffic is reaching it. It is derived
		// from two observations and never asserted from configuration alone.
		status.Miswired = status.Enabled && status.WebSurface.ExpectsHTTP && !status.TrafficPathAttached
		status.WebSurfaceNote = describeWebSurface(status.WebSurface, status.TrafficPathAttached)
		if status.Miswired && status.Coverage != "OFFLINE" {
			status.CoverageReason = status.WebSurfaceNote
		}
	})

	// Whether the traffic path is mandatory is a separate question from whether the
	// engine is enabled. Treating `enabled` as `required` meant an operator who turned
	// the engine on before wiring a producer into it got a permanently degraded
	// platform for a deployment that was simply not finished yet.
	s.state.SetSensorCoverage(deriveL7SensorCoverage(s.state.Snapshot().L7, healthy))
}

// deriveL7SensorCoverage turns the L7 status into the Kinetic sensor entry.
//
// It is a pure function of the status, and it is called from two places: here, when the
// inspection service publishes, and from State.Snapshot, when the coverage is read.
//
// The second caller is the point. This entry was written only by the publisher, which runs
// on the inspection service's own events. The inline edge changes the L7 verdict without
// ever calling it - the edge has no access to this service - so the sensor entry recorded
// the verdict from the moment it was last written and kept it. A host was found serving
// coverage "HEALTHY_AWAITING_TRAFFIC" from the L7 status while the Kinetic summary beside
// it still read "inline L7 listener is degraded", and Kinetic reported the whole platform
// degraded on the strength of a sentence that had stopped being true.
// inlineDegradedReason names the listener's own report beside the verdict that it is
// degraded. Both are facts, and an operator needs both to decide what to do about it.
func inlineDegradedReason(status L7Status) string {
	if detail := strings.TrimSpace(status.InlineLastError); detail != "" {
		return status.CoverageReason + ": " + detail
	}
	return status.CoverageReason
}

func deriveL7SensorCoverage(status L7Status, healthy bool) SensorCoverage {
	coverageStatus := CoverageOnline
	coverageReason := "verified L7 inspection traffic active"
	selfTest := "pass"
	if !status.Enabled {
		coverageStatus, coverageReason, selfTest = CoverageDisabled, "L7 disabled by configuration", "disabled"
	} else if !healthy {
		coverageStatus, coverageReason, selfTest = CoverageOffline, "L7 service is offline", "failed"
	} else {
		switch {
		case status.Coverage == "INLINE_DEGRADED":
			// The verdict names the condition; the service also records what it reported.
			//
			// Keeping only the verdict left an operator with a degradation, no cause and no
			// trace: the error text is held for the lifetime of the process and the
			// transition is not logged, so "inline L7 listener is degraded" could describe
			// a transient accept error, a socket that would not bind, or a listener that
			// had genuinely stopped. Appending it changes no verdict and no gate - it stops
			// the panel from withholding the one fact that explains the sentence.
			coverageStatus, coverageReason, selfTest = CoverageDegraded, inlineDegradedReason(status), "failed"
		case status.Coverage == "READY_NOT_ATTACHED" && !status.CoverageRequired:
			// The engine is healthy and nothing is attached. Reporting this as
			// not_applicable is what allows the sidebar and Kinetic to agree: the
			// platform is nominal, and the L7 layer is available rather than failing.
			coverageStatus = CoverageNotApplicable
			coverageReason = "L7 engine is healthy; no traffic path is attached and coverage is not required"
			selfTest = "ready-not-attached"
		case status.Coverage == "HEALTHY_AWAITING_TRAFFIC" || status.Coverage == "NO_TRAFFIC_WARNING" || status.Coverage == "TLS_NOT_IN_PATH" || status.Coverage == "READY_NOT_ATTACHED":
			// Coverage is required, so silence from an attached path is a real fault.
			//
			// "Awaiting traffic" is included deliberately, and it does not mean the engine
			// is unwell. An operator who declared L7 mandatory has declared that no
			// verified request through the path is a gap, and the release gate refuses the
			// promotion from Canary to Enforce on exactly that condition (release_test.go,
			// which proves the fixture derives a mandatory gap so that a later change to
			// this branch cannot make it pass for the wrong reason).
			//
			// An attempt was made to treat a freshly attached path as nominal, on the
			// grounds that the traffic counters live in memory and a restart resets them.
			// It was reverted: it removed the gate. The contradiction an operator reported
			// was never this verdict. It was the sentence printed beside it, which belonged
			// to the ingress producer, and an inspected-request count that ignored the
			// inline listener.
			coverageStatus, coverageReason, selfTest = CoverageDegraded, status.CoverageReason, "awaiting-traffic"
		}
	}
	cov := SensorCoverage{Name: "l7_application", Layer: LayerApplicationL7, Status: coverageStatus, Required: status.CoverageRequired, SelfTest: selfTest, CoverageReason: coverageReason}
	// The timestamps are taken from the status rather than from the clock, so that a
	// derivation performed while reading reports the same observation as one performed
	// while publishing. Reading a snapshot must not look like a fresh measurement.
	if coverageStatus == CoverageOnline {
		observed := status.LastInspection
		if observed == nil {
			observed = status.LastRequestAt
		}
		cov.LastOK = observed
	} else if coverageStatus == CoverageOffline || coverageStatus == CoverageDegraded {
		cov.LastError = coverageReason
	}
	return cov
}

// l7CoverageRequired decides whether an idle L7 engine degrades the platform.
//
// Enabling the engine and wiring it into the traffic path are two decisions, and the
// earlier code treated them as one: `Required: cfg.Enabled` made every enabled engine
// mandatory, so an operator who turned L7 on before attaching a producer received a
// permanently degraded platform for a deployment that was simply not finished.
//
//	auto     - mandatory once something is actually attached
//	required - always mandatory
//	optional - never mandatory
//
// An unrecognised mode falls back to auto, which is the conservative reading: it
// degrades only when a path exists and has gone silent.
func l7CoverageRequired(mode string, enabled, attached bool) bool {
	if !enabled {
		return false
	}
	switch mode {
	case "required":
		return true
	case "optional":
		return false
	default:
		return attached
	}
}
func (s *L7Service) Errors() <-chan error { return s.errors }

func (s *L7Service) Shutdown(ctx context.Context) error {
	if !s.cfg.Enabled || s.server == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	removeErr := os.Remove(s.cfg.Socket)
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return errors.Join(err, removeErr)
	}
	return err
}
