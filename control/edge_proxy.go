package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/edgeproxy"
)

// 6.1.0 Module E: control-plane surface for the optional memory-safe edge
// terminator. The engine lives in internal/edgeproxy and is inert until the
// persisted `edge_proxy` namespace is enabled with a certificate.
//
// The route handlers are registered in server.go. This file owns the settings
// translation, the incident sink, the optional apply-state hook the settings
// module asks for, and the restart recovery path.

var v61Edge = edgeproxy.NewManager()

var (
	edgeSinkOnce sync.Once
	edgeDedupeMu sync.Mutex
	edgeDedupe   = map[string]time.Time{}
)

// edgeBlockIncidentGap bounds how often one reason+peer pair can write an
// incident. The refusal itself is always enforced; the gap only keeps a flood
// from turning the incident ledger into the amplifier.
const edgeBlockIncidentGap = 60 * time.Second

func (s *APIServer) ensureEdgeSink() {
	edgeSinkOnce.Do(func() {
		v61Edge.OnBlock(func(event edgeproxy.BlockEvent) {
			if s.state == nil {
				return
			}
			key := event.Reason + "|" + event.Peer
			edgeDedupeMu.Lock()
			now := time.Now().UTC()
			if last, seen := edgeDedupe[key]; seen && now.Sub(last) < edgeBlockIncidentGap {
				edgeDedupe[key] = now
				edgeDedupeMu.Unlock()
				return
			}
			if len(edgeDedupe) > 4096 {
				for candidate := range edgeDedupe {
					delete(edgeDedupe, candidate)
				}
			}
			edgeDedupe[key] = now
			edgeDedupeMu.Unlock()
			s.state.AddIncident(XDRIncident{
				Severity: "medium",
				Summary:  "Edge proxy refused a request (" + event.Reason + ")",
				Process:  "gedefense-edge-proxy",
				Remote:   event.Peer,
				Action:   "blocked",
				Outcome:  "denied",
				RuleIDs:  []string{"EDGE.PROXY_BLOCK"},
			})
		})
	})
}

// edgeProxyConfig translates the persisted namespace into the engine contract.
// The namespace is always seeded by the v18 migration/upgrade path, so the
// default is only a defensive fallback for a bare test server.
func (s *APIServer) edgeProxyConfig() edgeproxy.Config {
	settings := defaultEdgeProxyFabricSettings()
	if s.settings != nil {
		settings = effectiveEdgeProxySettings(s.settings.Get())
	}
	return edgeproxy.Config{
		Enabled:              settings.Enabled,
		Listen:               settings.Listen,
		Upstream:             settings.Upstream,
		CertFile:             settings.CertFile,
		KeyFile:              settings.KeyFile,
		MinTLSVersion:        settings.MinTLSVersion,
		MaxConcurrentStreams: settings.MaxConcurrentStreams,
		MaxHeaderBytes:       settings.MaxHeaderBytes,
		MaxBodyBytes:         int64(settings.MaxBodyBytes),
		IdleTimeoutSeconds:   settings.IdleTimeoutSeconds,
		RequestTimeoutSecond: settings.RequestTimeoutSeconds,
		AllowedMethods:       append([]string(nil), settings.AllowedMethods...),
		WAFInline:            settings.WAFInline,
		RateLimitPerMinute:   settings.RateLimitPerMinute,
	}
}

// edgeProxyRevision reports the settings revision the running listener was
// converged from. It is kept alongside the engine status so the dashboard can
// distinguish "running the current revision" from "running a stale listener".
func (s *APIServer) edgeProxyRevision() uint64 {
	if s.settings == nil {
		return 0
	}
	return s.settings.Get().Revision
}

// syncEdgeProxy converges the engine and reports the resulting state. It is
// idempotent: an unchanged configuration does not restart the listener.
func (s *APIServer) syncEdgeProxy() (edgeproxy.Status, string) {
	s.ensureEdgeSink()
	cfg := s.edgeProxyConfig()
	if err := v61Edge.Sync(cfg); err != nil {
		return v61Edge.Status(), err.Error()
	}
	return v61Edge.Status(), ""
}

// edgeProxyStatus is the read endpoint. Convergence on read means a control
// plane restart cannot leave an operator-enabled edge silently stopped: the
// first status poll re-applies the persisted namespace (no-op when unchanged).
func (s *APIServer) edgeProxyStatus(w http.ResponseWriter, _ *http.Request) {
	status, syncError := s.syncEdgeProxy()
	view := map[string]any{
		"generated_at":      status.GeneratedAt,
		"settings_revision": s.edgeProxyRevision(),
		"enabled":           status.Enabled,
		"state":             status.State,
		"listen":            status.Listen,
		"upstream":          status.Upstream,
		"fingerprint":       status.Fingerprint,
		"min_tls":           status.MinTLS,
		"h2":                status.H2,
		"counters":          status.Counters,
		"recent":            status.Recent,
		"reason":            status.Reason,
	}
	if status.StartedAt != nil {
		view["started_at"] = status.StartedAt
	}
	if syncError != "" {
		view["error"] = syncError
	}
	writeJSON(w, http.StatusOK, view)
}

// edgeProxyRestart forces a stop/start cycle with the persisted settings. It is
// the recovery path after a certificate rotation and never changes a setting.
func (s *APIServer) edgeProxyRestart(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength > 0 {
		if err := decodeStrictJSON(w, r, 4096, &request); err != nil {
			writePublicError(w, http.StatusBadRequest, "invalid edge proxy restart request")
			return
		}
	}
	reason := strings.TrimSpace(request.Reason)
	if len(reason) < 4 {
		writePublicError(w, http.StatusBadRequest, "edge proxy restart requires a reason")
		return
	}
	s.ensureEdgeSink()
	cfg := s.edgeProxyConfig()
	v61Edge.Stop()
	if err := v61Edge.Sync(cfg); err != nil {
		writePublicError(w, http.StatusConflict, "edge proxy restart failed: "+err.Error())
		return
	}
	status := v61Edge.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"restarted":   true,
		"state":       status.State,
		"listen":      status.Listen,
		"upstream":    status.Upstream,
		"fingerprint": status.Fingerprint,
		"reason":      reason,
	})
}

// EdgeProxySettingsApplyState is consumed by the settings module
// (module_settings_v61_edge.go) so the Settings tab reports what actually runs.
// It also converges the listener, which makes an enable/disable through the
// generic settings API effective without waiting for a status poll.
func (s *APIServer) EdgeProxySettingsApplyState() string {
	status, syncError := s.syncEdgeProxy()
	if !status.Enabled {
		return "disabled"
	}
	if syncError != "" || status.State == edgeproxy.StateError {
		return "engine_unavailable"
	}
	if status.State != edgeproxy.StateRunning {
		return "reload_pending"
	}
	return "applied"
}

// EdgeProxyModuleDetails projects the engine state into the settings module
// detail map. It contains no secrets: the fingerprint is a public certificate
// digest and recent refusals carry no request body.
func (s *APIServer) EdgeProxyModuleDetails() map[string]any {
	status := v61Edge.Status()
	details := map[string]any{
		"state":       status.State,
		"listen":      status.Listen,
		"upstream":    status.Upstream,
		"fingerprint": status.Fingerprint,
		"min_tls":     status.MinTLS,
		"h2":          status.H2,
		"counters":    status.Counters,
		"recent":      status.Recent,
		"reason":      status.Reason,
	}
	if status.StartedAt != nil {
		details["started_at"] = status.StartedAt
	}
	return details
}
