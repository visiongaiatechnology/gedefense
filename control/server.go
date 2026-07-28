package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

//go:embed web/*
var webAssets embed.FS

type APIServer struct {
	cfg         Config
	state       *State
	core        *CoreClient
	feeds       *FeedManager
	policy      *PolicyStore
	xdr         *XDREngine
	release     *ReleaseController
	settings    *SettingsStore
	token       string
	http        *http.Server
	feedSyncing atomic.Bool
	limiter     *RateLimiter
	replay      *ReplayGuard
	sseClients  atomic.Int32
	bootTrust   *BootTrustCollector
}

func NewAPIServer(cfg Config, state *State, core *CoreClient, feeds *FeedManager, policy *PolicyStore, xdr *XDREngine, release *ReleaseController, settings *SettingsStore, token string) *APIServer {
	s := &APIServer{
		cfg: cfg, state: state, core: core, feeds: feeds, policy: policy, xdr: xdr, release: release, settings: settings, token: token,
		limiter: NewRateLimiter(cfg.Dashboard.RateLimitPerMinute, cfg.Dashboard.RateLimitBurst), replay: NewReplayGuard(10 * time.Minute),
		bootTrust: NewBootTrustCollector(5 * time.Minute),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /assets/{name}", s.asset)
	mux.HandleFunc("GET /api/v1/status", s.auth(s.status))
	mux.HandleFunc("GET /api/v1/boot-trust", s.auth(s.bootTrustStatus))
	mux.HandleFunc("GET /api/v1/evidence", s.auth(s.evidenceStatus))
	mux.HandleFunc("GET /api/v1/evidence/verify", s.auth(s.evidenceVerify))
	mux.HandleFunc("GET /api/v1/fim", s.auth(s.fimStatus))
	mux.HandleFunc("POST /api/v1/fim/scan", s.auth(s.fimScan))
	mux.HandleFunc("POST /api/v1/fim/baseline", s.auth(s.fimBaseline))
	mux.HandleFunc("GET /api/v1/transactions", s.auth(s.transactionStatus))
	mux.HandleFunc("POST /api/v1/transactions/preview", s.auth(s.transactionPreview))
	mux.HandleFunc("POST /api/v1/transactions/{id}/apply", s.auth(s.transactionApply))
	mux.HandleFunc("POST /api/v1/transactions/{id}/reverse", s.auth(s.transactionReverse))
	mux.HandleFunc("GET /api/v1/quarantine", s.auth(s.quarantineStatus))
	mux.HandleFunc("POST /api/v1/quarantine/preview", s.auth(s.quarantinePreview))
	mux.HandleFunc("GET /api/v1/cases", s.auth(s.caseStatus))
	mux.HandleFunc("POST /api/v1/cases/{id}/status", s.auth(s.caseSetStatus))
	mux.HandleFunc("GET /api/v1/cells", s.auth(s.cellsStatus))
	mux.HandleFunc("POST /api/v1/cells/preview", s.auth(s.cellsPreview))
	mux.HandleFunc("GET /api/v1/stream", s.auth(s.stream))
	mux.HandleFunc("GET /api/v1/policy", s.auth(s.policyStatus))
	mux.HandleFunc("GET /api/v1/xdr/profiles", s.auth(s.behaviorProfiles))
	mux.HandleFunc("GET /api/v1/forensics/export", s.auth(s.forensicsExport))
	mux.HandleFunc("GET /api/v1/release", s.auth(s.releaseStatus))
	mux.HandleFunc("POST /api/v1/release/transition", s.auth(s.releaseTransition))
	mux.HandleFunc("POST /api/v1/release/emergency-stop", s.auth(s.releaseEmergencyStop))
	mux.HandleFunc("POST /api/v1/release/emergency-stop/clear", s.auth(s.releaseEmergencyStopClear))
	mux.HandleFunc("GET /api/v1/settings", s.auth(s.settingsStatus))
	mux.HandleFunc("PUT /api/v1/settings", s.auth(s.updateSettings))
	mux.HandleFunc("POST /api/v1/allowlist", s.auth(s.addAllowlist))
	mux.HandleFunc("POST /api/v1/allowlist/remove", s.auth(s.removeAllowlist))
	mux.HandleFunc("POST /api/v1/blocks", s.auth(s.addBlock))
	mux.HandleFunc("DELETE /api/v1/blocks/{id}", s.auth(s.deleteBlock))
	mux.HandleFunc("POST /api/v1/feeds/sync", s.auth(s.syncFeeds))
	mux.HandleFunc("POST /api/v1/xdr/incidents/{id}/ack", s.auth(s.ackIncident))
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /livez", s.liveness)
	mux.HandleFunc("GET /readyz", s.readiness)
	mux.HandleFunc("GET /healthz", s.readiness)
	s.http = &http.Server{
		Addr: cfg.Dashboard.Listen, Handler: s.secure(mux), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	return s
}

func validateTLSMaterial(certPath, keyPath string) error {
	if certPath == "" && keyPath == "" {
		return nil
	}
	for label, path := range map[string]string{"TLS certificate": certPath, "TLS private key": keyPath} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be a regular non-symlink file", label)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must not be group/world writable", label)
		}
	}
	keyInfo, err := os.Lstat(keyPath)
	if err != nil {
		return err
	}
	if keyInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("TLS private key must not be group/world accessible")
	}
	return nil
}

func (s *APIServer) Run() error { return s.RunWithReady(nil) }

func (s *APIServer) RunWithReady(ready chan<- struct{}) error {
	if err := validateTLSMaterial(s.cfg.Dashboard.TLSCertFile, s.cfg.Dashboard.TLSKeyFile); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	if ready != nil {
		close(ready)
	}
	if s.cfg.Dashboard.TLSCertFile != "" {
		return s.http.ServeTLS(listener, s.cfg.Dashboard.TLSCertFile, s.cfg.Dashboard.TLSKeyFile)
	}
	return s.http.Serve(listener)
}

func (s *APIServer) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

func (s *APIServer) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics" || r.URL.Path == "/healthz" || r.URL.Path == "/livez" || r.URL.Path == "/readyz" {
			if !s.limiter.Allow(remoteIdentity(r.RemoteAddr), time.Now()) {
				w.Header().Set("Retry-After", "2")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Origin-Agent-Cluster", "?1")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; manifest-src 'self'; worker-src 'none'")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
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
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !tokenEqual(got, s.token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "authorization required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.replay.Claim(r.Header.Get("X-VGT-Request-ID"), time.Now()) {
				http.Error(w, "request identifier missing or replayed", http.StatusConflict)
				return
			}
			if s.state != nil && s.state.EvidenceLedger() != nil {
				emergencyStop := r.URL.Path == "/api/v1/release/emergency-stop"
				if err := s.state.EvidenceHealthy(); err != nil && !emergencyStop {
					apiError(w, http.StatusServiceUnavailable, "mandatory evidence ledger unavailable", err)
					return
				}
				if err := s.state.RecordEvidence(EvidenceRecord{
					Severity: "high", Kind: "operator.mutation.intent", Source: "access-gateway",
					Message: "Authenticated operator mutation accepted for processing",
					Target:  r.Method + " " + r.URL.Path, RequestID: r.Header.Get("X-VGT-Request-ID"),
				}); err != nil && !emergencyStop {
					apiError(w, http.StatusServiceUnavailable, "mandatory evidence commit failed", err)
					return
				}
			}
		}
		next(w, r)
	}
}

func (s *APIServer) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.serveEmbedded(w, r, "web/index.html", "text/html; charset=utf-8")
}

func (s *APIServer) asset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "\\/\x00") {
		http.NotFound(w, r)
		return
	}
	allowed := map[string]bool{
		"app.css": true, "api.js": true, "charts.js": true, "render.js": true, "i18n.js": true, "app.js": true,
	}
	if !allowed[name] {
		http.NotFound(w, r)
		return
	}
	contentType := mime.TypeByExtension(filepath.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	s.serveEmbedded(w, r, "web/"+name, contentType)
}

func (s *APIServer) serveEmbedded(w http.ResponseWriter, r *http.Request, name, contentType string) {
	b, err := webAssets.ReadFile(name)
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(digest[:16]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, publicMessage string, internal error) {
	id := randomID()
	if internal != nil {
		log.Printf("api fault id=%s status=%d: %v", id, status, internal)
	}
	writeJSON(w, status, map[string]string{"error": publicMessage, "error_id": id})
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func (s *APIServer) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.state.Snapshot())
}

func (s *APIServer) bootTrustStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.bootTrust.Collect())
}

func (s *APIServer) evidenceStatus(w http.ResponseWriter, r *http.Request) {
	ledger := s.state.EvidenceLedger()
	if ledger == nil {
		apiError(w, http.StatusServiceUnavailable, "evidence ledger unavailable", nil)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 500 {
			apiError(w, http.StatusBadRequest, "invalid evidence limit", err)
			return
		}
		limit = value
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": ledger.Status(), "records": ledger.Recent(limit)})
}

func (s *APIServer) evidenceVerify(w http.ResponseWriter, _ *http.Request) {
	ledger := s.state.EvidenceLedger()
	if ledger == nil {
		apiError(w, http.StatusServiceUnavailable, "evidence ledger unavailable", nil)
		return
	}
	if err := ledger.Verify(); err != nil {
		apiError(w, http.StatusServiceUnavailable, "evidence verification failed", err)
		return
	}
	writeJSON(w, http.StatusOK, ledger.Status())
}

func (s *APIServer) liveness(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version})
}

func (s *APIServer) readiness(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	ready, blockers := s.release.Ready()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	snap := s.state.Snapshot()
	writeJSON(w, status, map[string]any{"ok": ready, "release": snap.Release, "blockers": blockers, "core": snap.CoreConnected, "xdr": snap.XDR, "policy": snap.Policy})
}

func isLoopbackRemote(remote string) bool {
	host := remoteIdentity(remote)
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *APIServer) stream(w http.ResponseWriter, r *http.Request) {
	if s.sseClients.Add(1) > int32(s.cfg.Dashboard.MaxSSEClients) {
		s.sseClients.Add(-1)
		http.Error(w, "stream capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer s.sseClients.Add(-1)
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, cancel := s.state.Subscribe()
	defer cancel()
	fmt.Fprint(w, "event: snapshot\ndata: ")
	_ = json.NewEncoder(w).Encode(s.state.Snapshot())
	fmt.Fprint(w, "\n")
	fl.Flush()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprint(w, "event: event\ndata: ")
			_ = json.NewEncoder(w).Encode(e)
			fmt.Fprint(w, "\n")
			fl.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			fl.Flush()
		}
	}
}

func (s *APIServer) addBlock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target     string `json:"target"`
		Reason     string `json:"reason"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := decodeStrictJSON(w, r, 16<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request", err)
		return
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = s.cfg.Defense.DefaultTTLSeconds
	}
	if in.TTLSeconds < 60 || in.TTLSeconds > s.cfg.Defense.MaxTTLSeconds {
		apiError(w, http.StatusBadRequest, "TTL outside policy", nil)
		return
	}
	normalizedTarget, err := normalizeTarget(in.Target)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid target", err)
		return
	}
	in.Target = normalizedTarget
	enforced := false
	enforcement, _ := s.state.Modes()
	if enforcement == "enforce" {
		if err := s.core.Add(in.Target); err != nil {
			s.state.SetCore(false, "offline")
			apiError(w, http.StatusServiceUnavailable, "kernel core unavailable", err)
			return
		}
		enforced = true
	}
	b, err := s.state.AddBlock(in.Target, in.Reason, "manual", time.Duration(in.TTLSeconds)*time.Second, enforced, s.cfg.Defense.MaxBlockEntries)
	if err != nil {
		if enforced {
			if rollbackErr := s.core.Delete(in.Target); rollbackErr != nil {
				failSafeErr := s.release.FailSafe("manual block rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := persistPolicy(s.policy, s.cfg, s.state); err != nil {
		s.state.RemoveBlockByID(b.ID)
		if enforced {
			if rollbackErr := s.core.Delete(b.Target); rollbackErr != nil {
				failSafeErr := s.release.FailSafe("manual block policy rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiError(w, http.StatusInternalServerError, "signed policy persistence failed", err)
		return
	}
	s.state.AddEvent(Event{Severity: "high", Kind: "block.added", Source: "operator", Message: "Signed block rule activated", Target: b.Target})
	writeJSON(w, http.StatusCreated, b)
}

func (s *APIServer) deleteBlock(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		apiError(w, http.StatusBadRequest, "missing rule id", nil)
		return
	}
	b, ok := s.state.RemoveBlockByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if b.Enforced {
		if err := s.core.Delete(b.Target); err != nil {
			s.state.RestoreBlock(b)
			apiError(w, http.StatusServiceUnavailable, "kernel core rejected rule removal", err)
			return
		}
	}
	if err := persistPolicy(s.policy, s.cfg, s.state); err != nil {
		s.state.RestoreBlock(b)
		if b.Enforced {
			if rollbackErr := s.core.Add(b.Target); rollbackErr != nil {
				s.state.AddEvent(Event{Severity: "critical", Kind: "policy.rollback_failed", Source: "policy", Message: "Kernel rollback failed after signed policy persistence error", Target: b.Target})
				failSafeErr := s.release.FailSafe("block deletion policy rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiError(w, http.StatusInternalServerError, "signed policy persistence failed", err)
		return
	}
	s.state.AddEvent(Event{Severity: "info", Kind: "block.removed", Source: "operator", Message: "Signed block rule removed", Target: b.Target})
	w.WriteHeader(http.StatusNoContent)
}

func (s *APIServer) syncFeeds(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil || !s.settings.Get().FeedsEnabled {
		apiError(w, http.StatusConflict, "feed synchronization is disabled", nil)
		return
	}
	if !s.feedSyncing.CompareAndSwap(false, true) {
		apiError(w, http.StatusConflict, "feed synchronization already running", nil)
		return
	}
	defer s.feedSyncing.Store(false)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	items, errs := s.feeds.Sync(ctx)
	now := time.Now()
	s.state.SetFeedVectors(len(items), now)
	severity := "info"
	message := fmt.Sprintf("Threat feeds staged: %d unique public prefixes", len(items))
	if len(errs) > 0 {
		severity = "warning"
		message += fmt.Sprintf("; %d source errors", len(errs))
	}
	s.state.AddEvent(Event{Severity: severity, Kind: "feeds.synced", Source: "intelligence", Message: message})
	writeJSON(w, http.StatusOK, map[string]any{"vectors": len(items), "source_errors": len(errs), "auto_apply": false, "note": "Threat intelligence remains staged until local corroboration."})
}

func (s *APIServer) ackIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		apiError(w, http.StatusBadRequest, "missing incident id", nil)
		return
	}
	if !s.state.AcknowledgeIncident(id) {
		http.NotFound(w, r)
		return
	}
	s.state.AddEvent(Event{Severity: "info", Kind: "xdr.acknowledged", Source: "operator", Message: "XDR incident acknowledged", Target: id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *APIServer) policyStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": s.policy.Status(), "blocks": s.state.BlocksSnapshot()})
}

func (s *APIServer) behaviorProfiles(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 1 && value <= 500 {
			limit = value
		}
	}
	if s.xdr == nil || s.xdr.behavior == nil {
		writeJSON(w, http.StatusOK, map[string]any{"profiles": []any{}, "summary": BehaviorSummary{IntegrityOK: true}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": s.xdr.behavior.Snapshot(limit), "summary": s.xdr.behavior.Summary()})
}

func (s *APIServer) fimStatus(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, engine.Status())
}

func (s *APIServer) fimScan(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	summary, err := engine.Scan()
	if err != nil {
		apiError(w, http.StatusConflict, "file integrity scan rejected", err)
		return
	}
	severity := "info"
	kind := "fim.verified"
	if summary.Tampered > 0 || summary.Missing > 0 || summary.New > 0 || summary.Errors > 0 {
		severity = "critical"
		kind = "fim.deviation"
	}
	s.state.AddEvent(Event{
		Severity: severity, Kind: kind, Source: "operator",
		Message: fmt.Sprintf(
			"Manual FIM scan: verified=%d tampered=%d missing=%d new=%d errors=%d",
			summary.Verified, summary.Tampered, summary.Missing, summary.New, summary.Errors,
		),
	})
	writeJSON(w, http.StatusOK, summary)
}

func (s *APIServer) fimBaseline(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	status, err := engine.CreateBaseline()
	if err != nil {
		apiError(w, http.StatusConflict, "file integrity baseline rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "fim.baseline_created", Source: "operator",
		Message: fmt.Sprintf(
			"Encrypted FIM baseline generation %d committed for %d protected files",
			status.Generation, status.BaselineCount,
		),
	})
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) transactionStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			apiError(w, http.StatusBadRequest, "transaction limit is invalid", nil)
			return
		}
		limit = parsed
	}
	writeJSON(w, http.StatusOK, engine.Status(limit))
}

func (s *APIServer) quarantineStatus(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "quarantine unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, engine.QuarantineStatus())
}

func (s *APIServer) quarantinePreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "quarantine unavailable", nil)
		return
	}
	var request struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid quarantine preview request", err)
		return
	}
	payload, err := json.Marshal(quarantineRequest{Path: request.Path})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "quarantine preview unavailable", err)
		return
	}
	transaction, err := engine.Preview(
		quarantineTransactionType,
		"Quarantine file",
		request.Reason,
		payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "quarantine preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "quarantine.previewed", Source: "operator",
		Message: "File quarantine preview committed with immutable identity",
		Target:  transaction.ID,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) caseStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Cases()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "case engine unavailable", nil)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > caseListMaxLimit {
			apiError(w, http.StatusBadRequest, "case limit is invalid", nil)
			return
		}
		limit = parsed
	}
	writeJSON(w, http.StatusOK, engine.Status(limit))
}

func (s *APIServer) caseSetStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Cases()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "case engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validCaseID(id) {
		apiError(w, http.StatusBadRequest, "case identifier is invalid", nil)
		return
	}
	var request struct {
		Status     string `json:"status"`
		Resolution string `json:"resolution"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid case status request", err)
		return
	}
	record, err := engine.SetStatus(id, request.Status, request.Resolution)
	if err != nil {
		apiError(w, http.StatusConflict, "case status mutation rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "case.status_changed", Source: "operator",
		Message: "Security case status changed with durable evidence",
		Target:  record.ID + " " + record.Status,
	})
	writeJSON(w, http.StatusOK, record)
}

func (s *APIServer) cellsStatus(w http.ResponseWriter, _ *http.Request) {
	adapter := s.state.Cells()
	if adapter == nil {
		apiError(w, http.StatusServiceUnavailable, "Gaia Cells adapter unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, adapter.Status(true))
}

func (s *APIServer) cellsPreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	var request struct {
		UUID       string `json:"uuid"`
		Generation uint64 `json:"generation"`
		CgroupID   uint64 `json:"cgroup_id"`
		Action     string `json:"action"`
		Reason     string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid Gaia Cell preview request", err)
		return
	}
	payload, err := json.Marshal(cellIsolationRequest{
		UUID: request.UUID, Generation: request.Generation,
		CgroupID: request.CgroupID, Action: request.Action,
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "Gaia Cell preview unavailable", err)
		return
	}
	transaction, err := engine.Preview(
		cellTransactionType,
		"Gaia Cell "+request.Action,
		request.Reason,
		payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "Gaia Cell preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "cell.isolation_previewed", Source: "operator",
		Message: "Gaia Cell isolation preview bound to immutable cgroup identity",
		Target:  transaction.ID + " " + request.UUID,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) transactionPreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	var request struct {
		Type    string          `json:"type"`
		Summary string          `json:"summary"`
		Reason  string          `json:"reason"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := decodeStrictJSON(w, r, 32<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction preview request", err)
		return
	}
	transaction, err := engine.Preview(
		request.Type, request.Summary, request.Reason, request.Payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "info", Kind: "transaction.previewed", Source: "operator",
		Message: "Reversible security transaction preview committed",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) transactionApply(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validTransactionID(id) {
		apiError(w, http.StatusBadRequest, "transaction identifier is invalid", nil)
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeStrictJSON(w, r, 4<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction apply request", err)
		return
	}
	transaction, err := engine.Apply(id, request.Confirmation)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction apply rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "transaction.applied", Source: "operator",
		Message: "Security transaction applied and verified",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusOK, transaction)
}

func (s *APIServer) transactionReverse(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validTransactionID(id) {
		apiError(w, http.StatusBadRequest, "transaction identifier is invalid", nil)
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeStrictJSON(w, r, 4<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction reverse request", err)
		return
	}
	transaction, err := engine.Reverse(id, request.Confirmation)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction reverse rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "critical", Kind: "transaction.reversed", Source: "operator",
		Message: "Security transaction reversed and verified",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusOK, transaction)
}

func (s *APIServer) forensicsExport(w http.ResponseWriter, _ *http.Request) {
	document, err := s.policy.SignForensics(s.state.Snapshot())
	if err != nil {
		apiError(w, http.StatusInternalServerError, "forensics export unavailable", err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="gedefense-forensics.signed.json"`)
	writeJSON(w, http.StatusOK, document)
}

func (s *APIServer) releaseStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.release.Status())
}

func (s *APIServer) releaseTransition(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target       string `json:"target"`
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid release transition request", err)
		return
	}
	status, err := s.release.Transition(in.Target, in.Confirmation, in.Reason)
	if err != nil {
		apiError(w, http.StatusConflict, "release gate rejected transition", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) releaseEmergencyStop(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid emergency stop request", err)
		return
	}
	status, err := s.release.EmergencyStop(in.Reason)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "emergency stop failed", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) releaseEmergencyStopClear(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid emergency-stop clear request", err)
		return
	}
	status, err := s.release.ClearEmergencyStop(in.Confirmation, in.Reason)
	if err != nil {
		apiError(w, http.StatusConflict, "emergency stop could not be cleared", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) metrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	snap := s.state.Snapshot()
	core := 0
	if snap.CoreConnected {
		core = 1
	}
	xdrDegraded := 0
	if snap.XDR.Degraded {
		xdrDegraded = 1
	}
	policyVerified := 0
	if snap.Policy.Verified {
		policyVerified = 1
	}
	fmt.Fprintf(w, "# HELP gedefense_up Control plane health.\n# TYPE gedefense_up gauge\ngedefense_up 1\n")
	fmt.Fprintf(w, "# TYPE gedefense_core_connected gauge\ngedefense_core_connected %d\n", core)
	fmt.Fprintf(w, "# TYPE gedefense_policy_verified gauge\ngedefense_policy_verified %d\n", policyVerified)
	fmt.Fprintf(w, "# TYPE gedefense_policy_generation gauge\ngedefense_policy_generation %d\n", snap.Policy.Generation)
	fmt.Fprintf(w, "# TYPE gedefense_blocks_active gauge\ngedefense_blocks_active %d\n", len(snap.Blocks))
	fmt.Fprintf(w, "# TYPE gedefense_feed_vectors gauge\ngedefense_feed_vectors %d\n", snap.FeedVectors)
	fmt.Fprintf(w, "# TYPE gedefense_cpu_percent gauge\ngedefense_cpu_percent %.2f\n", snap.Telemetry.CPUPercent)
	fmt.Fprintf(w, "# TYPE gedefense_memory_percent gauge\ngedefense_memory_percent %.2f\n", snap.Telemetry.MemoryPercent)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_incidents_total counter\ngedefense_xdr_incidents_total %d\n", snap.XDR.IncidentsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_actions_total counter\ngedefense_xdr_actions_total %d\n", snap.XDR.ActionsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_degraded gauge\ngedefense_xdr_degraded %d\n", xdrDegraded)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_processes gauge\ngedefense_xdr_processes %d\n", snap.XDR.Processes)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_external_connections gauge\ngedefense_xdr_external_connections %d\n", snap.XDR.OpenConnections)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_evaluations_total counter\ngedefense_xdr_evaluations_total %d\n", snap.XDR.EvaluationsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_evaluation_drops_total counter\ngedefense_xdr_evaluation_drops_total %d\n", snap.XDR.EvaluationDrops)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_anomalies_total counter\ngedefense_xdr_anomalies_total %d\n", snap.XDR.AnomaliesTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_queue_depth gauge\ngedefense_xdr_queue_depth %d\n", snap.XDR.QueueDepth)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_behavior_profiles gauge\ngedefense_xdr_behavior_profiles %d\n", snap.XDR.Behavior.Profiles)
	releaseReady := 0
	if snap.Release.Ready {
		releaseReady = 1
	}
	fmt.Fprintf(w, "# TYPE gedefense_release_ready gauge\ngedefense_release_ready %d\n", releaseReady)
	fmt.Fprintf(w, "# TYPE gedefense_release_core_misses gauge\ngedefense_release_core_misses %d\n", snap.Release.CoreMisses)
}
