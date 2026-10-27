// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
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
	l7EdgeClientIPHeader = "X-Gedefense-Client-Ip"
	l7EdgeSchemeHeader   = "X-Gedefense-Original-Scheme"
)

type l7EdgeRequestContextKey struct{}

type L7EdgeService struct {
	cfg      L7Config
	live     *l7Runtime
	engine   *L7Engine
	state    *State
	proxy    *httputil.ReverseProxy
	server   *http.Server
	listener net.Listener
	errors   chan error
	started  atomic.Bool
	peerGID  uint32

	requests                 atomic.Uint64
	blocked                  atomic.Uint64
	findings                 atomic.Uint64
	upstreamErrors           atomic.Uint64
	responsesInspected       atomic.Uint64
	responseFindings         atomic.Uint64
	responseInspectionErrors atomic.Uint64
	lastRequestUnix          atomic.Int64
	lastErrMu                sync.RWMutex
	lastErr                  string
}

func NewL7EdgeService(cfg L7Config, engine *L7Engine, state *State) (*L7EdgeService, error) {
	if engine == nil || state == nil {
		return nil, errors.New("l7 inline service requires engine and state")
	}
	if !cfg.InlineEnabled {
		return &L7EdgeService{cfg: cfg, live: engine.live, engine: engine, state: state, errors: make(chan error, 1)}, nil
	}
	if err := validateL7InlineUpstream(cfg.InlineUpstream); err != nil {
		return nil, err
	}
	upstream, network, address, err := parseL7InlineUpstream(cfg.InlineUpstream)
	if err != nil {
		return nil, err
	}
	service := &L7EdgeService{cfg: cfg, live: engine.live, engine: engine, state: state, errors: make(chan error, 1)}
	service.proxy = service.newReverseProxy(upstream, network, address)
	return service, nil
}

// runtimeConfig returns the configuration the inline path must observe right
// now. The listener lifecycle still uses the boot configuration, which is the
// only configuration that can describe an already-bound socket.
func (s *L7EdgeService) runtimeConfig() L7Config {
	if s.live == nil {
		return s.cfg
	}
	snapshot := s.live.current()
	if snapshot == nil {
		return s.cfg
	}
	return snapshot.cfg
}

func (s *L7EdgeService) newReverseProxy(upstream *url.URL, network, address string) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			normalized, _ := request.In.Context().Value(l7EdgeRequestContextKey{}).(l7NormalizedRequest)
			request.SetURL(upstream)
			request.Out.Host = request.In.Host
			for _, header := range append([]string{
				l7EdgeClientIPHeader, l7EdgeSchemeHeader, "X-Gedefense-Request-Id",
				"Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-Ip",
			}, l7HopByHopHeaders(request.In.Header.Values("Connection"))...) {
				request.Out.Header.Del(header)
			}
			if normalized.RemoteIP != "" {
				request.Out.Header.Set("X-Forwarded-For", normalized.RemoteIP)
			}
			if normalized.Scheme != "" {
				request.Out.Header.Set("X-Forwarded-Proto", normalized.Scheme)
			}
			if normalized.Host != "" {
				request.Out.Header.Set("X-Forwarded-Host", normalized.Host)
			}
		},
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	proxy.Transport = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	proxy.ModifyResponse = s.inspectResponse
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		s.recordUpstreamError(fmt.Errorf("l7 inline upstream: %w", err))
		writeL7EdgeJSON(w, http.StatusBadGateway, "upstream unavailable")
	}
	return proxy
}

func (s *L7EdgeService) Start() error {
	if !s.cfg.InlineEnabled {
		s.publishStatus(true)
		return nil
	}
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("l7 inline service already started")
	}
	listener, err := openL7UnixListener(s.cfg.InlineSocket, s.cfg.SocketGroup)
	if err != nil {
		s.setError(err)
		return err
	}
	s.listener = newL7BoundedListener(listener, l7ConnectionLimit(s.cfg.MaxConcurrent))
	s.peerGID = resolveL7SocketGroupGID(s.cfg.SocketGroup)
	timeout := time.Duration(s.cfg.RequestTimeoutMillis) * time.Millisecond
	s.server = &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: timeout,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			credentials, credErr := l7PeerCredentialsFromConn(unwrapL7Conn(conn))
			if credErr != nil {
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

func (s *L7EdgeService) handle(w http.ResponseWriter, r *http.Request) {
	if !l7PeerAuthorizedWithGroup(s.cfg, r.Context(), s.peerGID) && !l7SelfTestPeerAuthorized(r.Context(), r) {
		writeL7EdgeJSON(w, http.StatusForbidden, "request rejected")
		return
	}
	// Client identity is peer-bound: only a SO_PEERCRED-authenticated producer
	// that passed the explicit identity policy may assert the original client
	// IP. Without peer credentials the header is never trusted (F-06 /
	// CHAIN-002).
	credentials, peerOK := r.Context().Value(l7PeerContextKey{}).(l7PeerCredentials)
	if !peerOK || credentials.PID <= 0 {
		writeL7EdgeJSON(w, http.StatusForbidden, "request rejected")
		return
	}
	// Enforce the configured header budget explicitly before touching the body or
	// contacting the upstream. Go's default server limit is far larger; without
	// this check an oversized header block reaches the engine (and would be
	// reported as a body error) instead of being refused at the edge.
	if max := s.runtimeConfig().MaxHeaderBytes; max > 0 && l7EdgeHeaderBytes(r) > max {
		writeL7EdgeJSON(w, http.StatusRequestHeaderFieldsTooLarge, "request headers rejected")
		return
	}
	admissionCtx, admissionCancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutMillis)*time.Millisecond)
	admissionErr := s.engine.acquireAdmission(admissionCtx)
	admissionCancel()
	if admissionErr != nil {
		writeL7EdgeJSON(w, http.StatusServiceUnavailable, "request inspection busy")
		return
	}
	defer s.engine.releaseAdmission()
	clientIP := net.ParseIP(strings.TrimSpace(r.Header.Get(l7EdgeClientIPHeader)))
	if clientIP == nil || clientIP.IsUnspecified() {
		writeL7EdgeJSON(w, http.StatusBadRequest, "invalid proxy metadata")
		return
	}
	scheme := strings.ToLower(strings.TrimSpace(r.Header.Get(l7EdgeSchemeHeader)))
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		writeL7EdgeJSON(w, http.StatusBadRequest, "invalid proxy metadata")
		return
	}

	rawBody, err := readL7EdgeBody(w, r, s.runtimeConfig().MaxBodyBytes)
	if err != nil {
		writeL7EdgeJSON(w, l7EdgeBodyErrorStatus(err), "request body rejected")
		return
	}
	inspection := L7InspectionRequest{
		Version: l7ProtocolVersion,
		Method:  r.Method, Scheme: scheme, Host: r.Host, URI: r.URL.RequestURI(), RemoteIP: clientIP.String(),
		Headers: l7HeadersFromHTTPRequest(r),
	}
	inspection.ServerPID = int(credentials.PID)
	inspection.ServerProcess = l7PeerProcessName(credentials.PID)
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutMillis)*time.Millisecond)
	response, normalized, inspectErr := s.engine.InspectRaw(ctx, inspection, rawBody)
	cancel()
	if inspectErr != nil {
		writeL7EdgeJSON(w, l7EdgeInspectionErrorStatus(inspectErr), "request inspection rejected")
		return
	}
	s.requests.Add(1)
	s.lastRequestUnix.Store(time.Now().UTC().UnixNano())
	if len(response.Findings) > 0 {
		s.findings.Add(uint64(len(response.Findings)))
	}
	if response.Enforced && response.Decision == "block" {
		s.blocked.Add(1)
		s.publishStatus(true)
		writeL7EdgeJSON(w, http.StatusForbidden, "request rejected")
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(rawBody))
	r.ContentLength = int64(len(rawBody))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(rawBody)), nil }
	r = r.WithContext(context.WithValue(r.Context(), l7EdgeRequestContextKey{}, normalized))
	s.publishStatus(true)
	s.proxy.ServeHTTP(w, r)
}

// l7EdgeHeaderBytes bounds the request head (request line plus headers) before
// the body is read. It is deliberately approximate but never underestimates the
// bytes an upstream would receive.
func l7EdgeHeaderBytes(r *http.Request) int {
	if r == nil {
		return 0
	}
	total := len(r.Method) + len(r.URL.RequestURI()) + len(r.Proto) + 4
	for name, values := range r.Header {
		total += len(name) + 2
		for _, value := range values {
			total += len(value) + 2
		}
	}
	return total
}

func readL7EdgeBody(w http.ResponseWriter, r *http.Request, maxBytes int) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	limited := http.MaxBytesReader(w, r.Body, int64(maxBytes))
	defer limited.Close()
	body, err := io.ReadAll(limited)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, fmt.Errorf("%w: request body exceeds configured limit", ErrL7ResourceLimit)
		}
		return nil, fmt.Errorf("%w: request body read failed", ErrL7InvalidRequest)
	}
	return body, nil
}

func l7HeadersFromHTTPRequest(r *http.Request) []L7Header {
	if r == nil {
		return nil
	}
	headers := make([]L7Header, 0, len(r.Header)+2)
	for name, values := range r.Header {
		if l7SensitiveHeader(name) || strings.EqualFold(name, l7EdgeClientIPHeader) || strings.EqualFold(name, l7EdgeSchemeHeader) || strings.EqualFold(name, "X-Gedefense-Request-Id") {
			continue
		}
		for _, value := range values {
			headers = append(headers, L7Header{Name: name, Value: value})
		}
	}
	// Go's server-side parser retains the incoming Content-Length in
	// Request.Header (net/http fixLength). Appending it again would create a
	// duplicate framing header that the L7 protocol-anomaly detector correctly
	// rejects as request-smuggling-shaped input, blocking every normal POST with
	// a body. Only synthesize the header for a request path that does not
	// already expose it.
	if r.ContentLength > 0 && r.Header.Get("Content-Length") == "" {
		headers = append(headers, L7Header{Name: "Content-Length", Value: fmt.Sprintf("%d", r.ContentLength)})
	}
	return headers
}

func l7SensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token":
		return true
	default:
		return false
	}
}

func (s *L7EdgeService) inspectResponse(response *http.Response) error {
	if response == nil || response.Request == nil || response.Body == nil {
		return nil
	}
	normalized, ok := response.Request.Context().Value(l7EdgeRequestContextKey{}).(l7NormalizedRequest)
	if !ok {
		return nil
	}
	limit := s.runtimeConfig().InlineMaxResponseBytes
	if limit <= 0 {
		return nil
	}
	prefix, replay, decoded := l7ResponseInspectionPrefix(response.Body, response.Header.Get("Content-Encoding"), limit)
	if replay != nil {
		response.Body = replay
	}
	if len(prefix) == 0 {
		return nil
	}
	headers := response.Header.Clone()
	if decoded {
		headers.Del("Content-Encoding")
	}
	ctx, cancel := context.WithTimeout(response.Request.Context(), time.Duration(s.cfg.RequestTimeoutMillis)*time.Millisecond)
	findings, inspectErr := s.engine.InspectResponse(ctx, normalized, response.StatusCode, map[string][]string(headers), prefix)
	cancel()
	if inspectErr != nil {
		s.responseInspectionErrors.Add(1)
		s.recordLastError(fmt.Errorf("l7 response inspection: %w", inspectErr))
		s.publishStatus(true)
		return nil
	}
	s.responsesInspected.Add(1)
	s.responseFindings.Add(uint64(len(findings)))
	s.publishStatus(true)
	return nil
}

func l7ResponseInspectionPrefix(body io.ReadCloser, contentEncoding string, maxDecoded int) ([]byte, io.ReadCloser, bool) {
	if body == nil || maxDecoded <= 0 {
		return nil, body, false
	}
	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))
	if encoding == "" || encoding == "identity" {
		consumed, err := io.ReadAll(io.LimitReader(body, int64(maxDecoded)+1))
		replay := &l7ReplayBody{Reader: io.MultiReader(bytes.NewReader(consumed), body), Closer: body}
		if err != nil {
			return nil, replay, false
		}
		if len(consumed) > maxDecoded {
			consumed = consumed[:maxDecoded]
		}
		return consumed, replay, false
	}
	if strings.Contains(encoding, ",") || (encoding != "gzip" && encoding != "x-gzip" && encoding != "deflate") {
		return nil, body, false
	}
	maxRaw := maxDecoded*4 + 64<<10
	if maxRaw > 1<<20 {
		maxRaw = 1 << 20
	}
	recorder := &l7RecordingReader{reader: io.LimitReader(body, int64(maxRaw))}
	var decoder io.ReadCloser
	var err error
	if encoding == "deflate" {
		decoder, err = zlib.NewReader(recorder)
	} else {
		decoder, err = gzip.NewReader(recorder)
	}
	if err != nil {
		replay := &l7ReplayBody{Reader: io.MultiReader(bytes.NewReader(recorder.Bytes()), body), Closer: body}
		return nil, replay, false
	}
	decoded, readErr := io.ReadAll(io.LimitReader(decoder, int64(maxDecoded)+1))
	_ = decoder.Close()
	replay := &l7ReplayBody{Reader: io.MultiReader(bytes.NewReader(recorder.Bytes()), body), Closer: body}
	if readErr != nil {
		return nil, replay, false
	}
	if len(decoded) > maxDecoded {
		decoded = decoded[:maxDecoded]
	}
	return decoded, replay, true
}

type l7RecordingReader struct {
	reader io.Reader
	buf    bytes.Buffer
}

func (r *l7RecordingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		_, _ = r.buf.Write(p[:n])
	}
	return n, err
}

func (r *l7RecordingReader) Bytes() []byte {
	return r.buf.Bytes()
}

type l7ReplayBody struct {
	io.Reader
	io.Closer
}

func l7EdgeBodyErrorStatus(err error) int {
	if errors.Is(err, ErrL7ResourceLimit) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func l7EdgeInspectionErrorStatus(err error) int {
	if errors.Is(err, ErrL7ResourceLimit) {
		return http.StatusRequestEntityTooLarge
	}
	if errors.Is(err, ErrL7UnsupportedEncoding) {
		return http.StatusUnsupportedMediaType
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

func writeL7EdgeJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+message+`"}`+"\n")
}

func l7PeerProcessName(pid int32) string {
	if pid <= 0 {
		return ""
	}
	path := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 256 {
		return ""
	}
	return safeProcessName(string(bytes.TrimSpace(data)))
}

func (s *L7EdgeService) setError(err error) {
	if err == nil {
		return
	}
	s.recordLastError(err)
	s.publishStatus(false)
}

func (s *L7EdgeService) recordUpstreamError(err error) {
	if err == nil {
		return
	}
	s.upstreamErrors.Add(1)
	s.recordLastError(err)
	s.publishStatus(true)
}

func (s *L7EdgeService) recordLastError(err error) {
	if err == nil {
		return
	}
	s.lastErrMu.Lock()
	s.lastErr = err.Error()
	s.lastErrMu.Unlock()
}

func (s *L7EdgeService) lastError() string {
	s.lastErrMu.RLock()
	defer s.lastErrMu.RUnlock()
	return s.lastErr
}

// l7HopByHopHeaders returns the headers that must never be forwarded to the upstream.
// Connection-nominated names are included because a proxy must not forward fields the
// client only asked its own hop to handle.
func l7HopByHopHeaders(connectionValues []string) []string {
	headers := []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	}
	for _, value := range connectionValues {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				headers = append(headers, token)
			}
		}
	}
	return headers
}

func (s *L7EdgeService) lastRequestAt() *time.Time {
	raw := s.lastRequestUnix.Load()
	if raw <= 0 {
		return nil
	}
	observed := time.Unix(0, raw).UTC()
	return &observed
}

func laterL7Time(current, candidate *time.Time) *time.Time {
	if candidate == nil {
		return current
	}
	if current == nil || candidate.After(*current) {
		return candidate
	}
	return current
}

// publishStatus publishes the inline edge's observation into the shared L7 status.
//
// The inline edge is a first-class producer: its counters are folded into the
// status-wide totals, and the attachment verdict is recomputed from observed counters
// rather than from "the listener was enabled". A listener that is bound but has not
// inspected a request is attached but not a producer; a listener that is enabled but
// unhealthy is neither, even if it inspected requests before the failure.
func (s *L7EdgeService) publishStatus(healthy bool) {
	if s.state == nil {
		return
	}
	s.state.UpdateL7Status(func(status *L7Status) {
		// The shared status may already carry inline counters from a previous publish.
		// Subtract them before adding the new values so aggregation is idempotent.
		previousInlineRequests := status.InlineRequestsTotal
		previousInlineBlocked := status.InlineBlockedTotal
		previousInlineFindings := status.InlineFindingsTotal
		previousResponseFindings := status.ResponseFindingsTotal

		socketRequests := status.RequestsTotal
		if socketRequests >= previousInlineRequests {
			socketRequests -= previousInlineRequests
		}
		socketBlocked := status.BlockedTotal
		if socketBlocked >= previousInlineBlocked {
			socketBlocked -= previousInlineBlocked
		}
		socketFindings := status.FindingsTotal
		inlineFindings := previousInlineFindings + previousResponseFindings
		if socketFindings >= inlineFindings {
			socketFindings -= inlineFindings
		}

		inlineRequests := s.requests.Load()
		inlineBlocked := s.blocked.Load()
		inlineFindingsNow := s.findings.Load()
		responseFindingsNow := s.responseFindings.Load()

		status.InlineEnabled = s.cfg.InlineEnabled
		status.InlineHealthy = healthy
		status.InlineSocket = s.cfg.InlineSocket
		status.InlineRequestsTotal = inlineRequests
		status.InlineBlockedTotal = inlineBlocked
		status.InlineFindingsTotal = inlineFindingsNow
		status.InlineUpstreamErrorsTotal = s.upstreamErrors.Load()
		status.InlineLastError = s.lastError()
		status.InlineLastRequestAt = s.lastRequestAt()
		status.ResponsesInspectedTotal = s.responsesInspected.Load()
		status.ResponseFindingsTotal = responseFindingsNow
		status.ResponseInspectionErrorsTotal = s.responseInspectionErrors.Load()

		if observed := s.lastRequestAt(); observed != nil {
			status.LastInspection = laterL7Time(status.LastInspection, observed)
			status.LastRequestAt = status.LastInspection
		}
		status.RequestsTotal = socketRequests + inlineRequests
		status.BlockedTotal = socketBlocked + inlineBlocked
		status.FindingsTotal = socketFindings + inlineFindingsNow + responseFindingsNow
		status.applyAttachmentSemantics()
		if status.ProducerAttached && status.LastInspection != nil {
			status.LastProducerSeen = status.LastInspection
		}
	})
}

func (s *L7EdgeService) Errors() <-chan error { return s.errors }

func (s *L7EdgeService) Shutdown(ctx context.Context) error {
	if !s.cfg.InlineEnabled || s.server == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	removeErr := os.Remove(s.cfg.InlineSocket)
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return errors.Join(err, removeErr)
	}
	return err
}
