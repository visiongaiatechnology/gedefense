// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
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
	cfg      L7Config
	engine   *L7Engine
	state    *State
	server   *http.Server
	listener net.Listener
	errors   chan error
	started  atomic.Bool

	requests    atomic.Uint64
	findings    atomic.Uint64
	blocked     atomic.Uint64
	rateLimited atomic.Uint64
	rejected    atomic.Uint64
	active      atomic.Int32
	lastUnix    atomic.Int64
	lastErrMu   sync.RWMutex
	lastErr     string
}

func NewL7Service(cfg L7Config, engine *L7Engine, state *State) (*L7Service, error) {
	if engine == nil || state == nil {
		return nil, errors.New("l7 service requires engine and state")
	}
	return &L7Service{cfg: cfg, engine: engine, state: state, errors: make(chan error, 1)}, nil
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
	if !s.authorized(r.Context()) {
		s.rejected.Add(1)
		s.writeError(w, http.StatusForbidden, "request rejected")
		return
	}
	admissionCtx, admissionCancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutMillis)*time.Millisecond)
	admissionErr := s.engine.acquireAdmission(admissionCtx)
	admissionCancel()
	if admissionErr != nil {
		s.rejected.Add(1)
		s.writeError(w, http.StatusServiceUnavailable, "inspection busy")
		return
	}
	defer s.engine.releaseAdmission()
	body := http.MaxBytesReader(w, r.Body, int64(s.cfg.MaxEnvelopeBytes))
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
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutMillis)*time.Millisecond)
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
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "protocol": l7ProtocolVersion})
}

func (s *L7Service) authorized(ctx context.Context) bool {
	return l7PeerAuthorized(s.cfg, ctx)
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

func (s *L7Service) publishStatus(healthy bool) {
	if s.state == nil {
		return
	}
	s.lastErrMu.RLock()
	lastErr := s.lastErr
	s.lastErrMu.RUnlock()
	var last *time.Time
	if raw := s.lastUnix.Load(); raw > 0 {
		t := time.Unix(0, raw).UTC()
		last = &t
	}
	s.state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = s.cfg.Enabled
		status.Mode = s.cfg.Mode
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
	})
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
