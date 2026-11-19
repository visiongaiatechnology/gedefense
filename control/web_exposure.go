// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 Module A: web-exposure posture handlers and status cache.
//
// The heavy lifting lives in internal/webposture (bounded /proc+ELF+config
// discovery, the loopback ALPN probe and the advisory matcher). This file owns
// the cache TTL, the API surface and the lifecycle:
//
//	GET  /api/v1/web-exposure/status
//	POST /api/v1/web-exposure/scan
//	GET  /api/v1/web-exposure/advisories
//
// The scan is read-only and needs no privileged helper. A disabled namespace
// performs no scan at all.

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/webposture"
)

const (
	webExposureScanTimeout = 3 * time.Second
	webExposureScanPerMin  = 6
	webExposureScanBurst   = 3
)

// WebExposureEngine caches the Module A report and enforces the scan budget.
type WebExposureEngine struct {
	settings *SettingsStore
	state    *State

	mu      sync.Mutex
	report  webposture.Report
	scanned time.Time
	scanMu  sync.Mutex
	limiter *RateLimiter
}

// NewWebExposureEngine constructs the Module A engine.
func NewWebExposureEngine(settings *SettingsStore, state *State) *WebExposureEngine {
	return &WebExposureEngine{
		settings: settings,
		state:    state,
		limiter:  NewRateLimiter(webExposureScanPerMin, webExposureScanBurst),
		report: webposture.Report{
			GeneratedAt: time.Now().UTC(),
			Servers:     []webposture.Server{}, Evidence: []string{},
			Reason: "the web exposure scan has not run yet",
		},
	}
}

// Run performs the initial scan and refreshes it on the administrable interval.
func (e *WebExposureEngine) Run(ctx context.Context) {
	if e == nil {
		return
	}
	e.refresh(ctx)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.refresh(ctx)
		}
	}
}

// refresh rescans only when the cached report is older than the configured
// interval. A disabled namespace clears the cache and stops touching the host.
func (e *WebExposureEngine) refresh(ctx context.Context) {
	if e == nil || e.settings == nil {
		return
	}
	settings := effectiveWebExposureSettings(e.settings.Get())
	if !settings.Enabled {
		e.mu.Lock()
		e.report = webposture.Report{
			GeneratedAt: time.Now().UTC(), Scanned: false,
			Reason:  "web exposure module is disabled; no scan is performed",
			Servers: []webposture.Server{}, Summary: webposture.Summary{}, Evidence: []string{},
		}
		e.scanned = time.Now().UTC()
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	fresh := !e.scanned.IsZero() && time.Since(e.scanned) < time.Duration(settings.ScanIntervalSeconds)*time.Second
	e.mu.Unlock()
	if fresh {
		return
	}
	_, _ = e.scan(ctx, settings, false)
}

// scan runs one measurement. force bypasses the rate budget (the periodic loop
// is already interval-bounded); an operator POST consumes the budget.
func (e *WebExposureEngine) scan(ctx context.Context, settings WebExposureFabricSettings, force bool) (webposture.Report, error) {
	if e == nil {
		return webposture.Report{}, errWebExposureUnavailable
	}
	if !settings.Enabled {
		report := webposture.Report{
			GeneratedAt: time.Now().UTC(), Scanned: false,
			Reason:  "web exposure module is disabled; no scan is performed",
			Servers: []webposture.Server{}, Evidence: []string{},
		}
		e.mu.Lock()
		e.report = report
		e.scanned = time.Now().UTC()
		e.mu.Unlock()
		return report, nil
	}
	e.scanMu.Lock()
	defer e.scanMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	advisories, err := webposture.ParseExtraAdvisories(settings.ExtraAdvisoriesJSON)
	if err != nil {
		return webposture.Report{}, err
	}
	options := webposture.Options{
		ProbeLoopback:   settings.ProbeLoopbackALPN,
		ProbeTimeout:    time.Duration(settings.ProbeTimeoutSeconds) * time.Second,
		ConfigRoots:     append([]string(nil), settings.ConfigRoots...),
		ExtraAdvisories: advisories,
		MaxServers:      settings.MaxServers,
	}
	scanCtx, cancel := context.WithTimeout(ctx, webExposureScanTimeout)
	defer cancel()
	report := webposture.Scan(scanCtx, options)
	if report.GeneratedAt.IsZero() {
		report.GeneratedAt = time.Now().UTC()
	}
	e.mu.Lock()
	e.report = report
	e.scanned = time.Now().UTC()
	e.mu.Unlock()
	if e.state != nil && report.Summary.Exposed > 0 {
		e.state.AddEvent(Event{
			Severity: "medium", Kind: "web_exposure.posture", Source: "webposture",
			Message: "web exposure scan: " + report.Summary.Grade + " grade, " +
				itoaSmall(report.Summary.Exposed) + " exposed server(s), " +
				itoaSmall(report.Summary.AffectedCVEs) + " reachable advisory match(es)",
		})
	}
	return report, nil
}

// ForceScan performs an operator-requested refresh. It returns the rate decision
// so the handler can answer 429 instead of silently rescanning. An engine without
// a settings store is unavailable, but the request itself is still admitted: the
// operator asked for a scan and must receive the concrete unavailability error,
// not a silent rate-limit refusal.
func (e *WebExposureEngine) ForceScan(ctx context.Context) (webposture.Report, bool, error) {
	if e == nil || e.settings == nil {
		return webposture.Report{}, true, errWebExposureUnavailable
	}
	if e.limiter != nil && !e.limiter.Allow("web-exposure-scan", time.Now()) {
		return e.Snapshot(), false, nil
	}
	settings := effectiveWebExposureSettings(e.settings.Get())
	report, err := e.scan(ctx, settings, true)
	return report, true, err
}

// Snapshot returns the cached report.
func (e *WebExposureEngine) Snapshot() webposture.Report {
	if e == nil {
		return webposture.Report{Servers: []webposture.Server{}, Evidence: []string{}, Reason: "engine unavailable"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	report := e.report
	report.Servers = append([]webposture.Server(nil), e.report.Servers...)
	report.Evidence = append([]string(nil), e.report.Evidence...)
	return report
}

// ApplyState maps the persisted revision onto the Fabric Settings vocabulary.
func (e *WebExposureEngine) ApplyState(settings RuntimeSettings) string {
	desired := effectiveWebExposureSettings(settings)
	if !desired.Enabled {
		return "disabled"
	}
	if e == nil {
		return "engine_unavailable"
	}
	return "applied"
}

// Details is the Settings-module runtime projection: counts and cache age only.
func (e *WebExposureEngine) Details() map[string]any {
	if e == nil {
		return map[string]any{"runtime": "unavailable"}
	}
	report := e.Snapshot()
	e.mu.Lock()
	scanned := e.scanned
	e.mu.Unlock()
	age := int64(0)
	if !scanned.IsZero() {
		age = int64(time.Since(scanned).Seconds())
	}
	return map[string]any{
		"runtime": map[string]any{
			"scanned": report.Scanned, "servers": len(report.Servers),
			"exposed": report.Summary.Exposed, "affected_cves": report.Summary.AffectedCVEs,
			"grade": report.Summary.Grade, "cache_age_seconds": age, "reason": report.Reason,
		},
	}
}

var errWebExposureUnavailable = &webExposureEngineError{}

type webExposureEngineError struct{}

func (*webExposureEngineError) Error() string { return "web exposure engine is unavailable" }

// ---------------------------------------------------------------- handlers

// webExposureStatus serves GET /api/v1/web-exposure/status.
func (s *APIServer) webExposureStatus(w http.ResponseWriter, _ *http.Request) {
	if s.v61 == nil || s.v61.webExposure == nil {
		writeJSON(w, http.StatusOK, emptyWebExposureReport("web exposure engine is not wired on this control plane"))
		return
	}
	writeJSON(w, http.StatusOK, s.v61.webExposure.Snapshot())
}

// webExposureScan serves POST /api/v1/web-exposure/scan.
func (s *APIServer) webExposureScan(w http.ResponseWriter, r *http.Request) {
	if s.v61 == nil || s.v61.webExposure == nil {
		writePublicError(w, http.StatusServiceUnavailable, "web exposure engine is not wired on this control plane")
		return
	}
	report, allowed, err := s.v61.webExposure.ForceScan(r.Context())
	if !allowed {
		writePublicError(w, http.StatusTooManyRequests, "web exposure scan rate limit reached")
		return
	}
	if err != nil {
		writePublicError(w, http.StatusConflict, "web exposure scan rejected: "+err.Error())
		return
	}
	if s.state != nil {
		s.state.AddEvent(Event{Severity: "info", Kind: "web_exposure.scanned", Source: "operator", Message: "manual web exposure scan completed"})
	}
	writeJSON(w, http.StatusOK, report)
}

// webExposureAdvisories serves GET /api/v1/web-exposure/advisories: the
// effective catalogue (compiled-in + operator entries) with the current matches.
func (s *APIServer) webExposureAdvisories(w http.ResponseWriter, _ *http.Request) {
	if s.settings == nil {
		writePublicError(w, http.StatusServiceUnavailable, "runtime settings unavailable")
		return
	}
	settings := effectiveWebExposureSettings(s.settings.Get())
	extra, err := webposture.ParseExtraAdvisories(settings.ExtraAdvisoriesJSON)
	if err != nil {
		writePublicError(w, http.StatusConflict, "web exposure advisory catalogue rejected: "+err.Error())
		return
	}
	catalogue := append(webposture.Catalogue(), extra...)
	matches := make([]map[string]any, 0)
	if s.v61 != nil && s.v61.webExposure != nil {
		for _, server := range s.v61.webExposure.Snapshot().Servers {
			for _, hit := range server.Affected {
				matches = append(matches, map[string]any{
					"id": hit.ID, "severity": hit.Severity, "server": server.Binary,
					"pid": server.PID, "posture": server.Posture,
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC(),
		"catalogue":    catalogue,
		"matches":      matches,
	})
}

// emptyWebExposureReport is the honest answer when the engine is not wired.
func emptyWebExposureReport(reason string) webposture.Report {
	return webposture.Report{
		GeneratedAt: time.Now().UTC(), Scanned: false, Reason: reason,
		Servers: []webposture.Server{}, Evidence: []string{},
	}
}

// itoaSmall renders a small non-negative int without pulling fmt into the hot
// status path.
func itoaSmall(value int) string {
	if value < 0 {
		return "0"
	}
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}
