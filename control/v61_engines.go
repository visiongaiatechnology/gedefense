// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 module-engine attachment and Fabric Settings runtime views.
//
// The V61Engines bundle is constructed once from main after the L7 engine is
// attached; the API server reads the engines through this single attachment
// point and every engine polls the persisted settings on its own tick, so a
// disabled namespace stays completely inert.

import "context"

// V61Engines bundles the four 6.1.0 module engines. The edge-proxy engine stays
// with its own file.
type V61Engines struct {
	webExposure *WebExposureEngine
	workerGuard *WorkerGuardEngine
	tlsSensor   *TLSSensorEngine
	lpeGuard    *LPEGuardEngine
}

// Run starts every module loop.
func (e *V61Engines) Run(ctx context.Context) {
	if e == nil {
		return
	}
	go e.webExposure.Run(ctx)
	go e.workerGuard.Run(ctx)
	go e.tlsSensor.Run(ctx)
	go e.lpeGuard.Run(ctx)
}

// attachV61Engines constructs the 6.1.0 module engines. It is called once from
// main after the L7 engine is attached, so the TLS sensor can reuse the existing
// TLSSecurityEngine through the L7 engine.
func attachV61Engines(srv *APIServer, settings *SettingsStore, state *State, core *CoreClient, xdr *XDREngine, ctx context.Context) {
	if srv == nil || settings == nil || state == nil {
		return
	}
	engines := &V61Engines{
		webExposure: NewWebExposureEngine(settings, state),
		lpeGuard:    NewLPEGuardEngine(settings, state, core, xdr),
	}
	engines.tlsSensor = NewTLSSensorEngine(settings, srv.l7, state)
	engines.workerGuard = NewWorkerGuardEngine(settings, state, core, xdr, func() []string {
		if engines.tlsSensor == nil {
			return nil
		}
		return engines.tlsSensor.RecentPeers(8)
	})
	srv.v61 = engines
	engines.Run(ctx)
}

// v61ModuleApplyState maps the four 6.1.0 namespaces (+ edge_proxy) onto the
// Fabric Settings apply-state vocabulary. handled=false means the module does
// not belong to this layer.
func (s *APIServer) v61ModuleApplyState(settings RuntimeSettings, module string) (string, bool) {
	switch module {
	case "web_exposure":
		if !effectiveWebExposureSettings(settings).Enabled {
			return "disabled", true
		}
		if s.v61 == nil || s.v61.webExposure == nil {
			return "engine_unavailable", true
		}
		return s.v61.webExposure.ApplyState(settings), true
	case "worker_guard":
		if !effectiveWorkerGuardSettings(settings).Enabled {
			return "disabled", true
		}
		if s.v61 == nil || s.v61.workerGuard == nil {
			return "engine_unavailable", true
		}
		return s.v61.workerGuard.ApplyState(settings), true
	case "tls_sensor":
		if !effectiveTLSSensorSettings(settings).Enabled {
			return "disabled", true
		}
		if s.v61 == nil || s.v61.tlsSensor == nil {
			return "engine_unavailable", true
		}
		return s.v61.tlsSensor.ApplyState(settings), true
	case "lpe_guard":
		if !effectiveLPEGuardSettings(settings).Enabled {
			return "disabled", true
		}
		if s.v61 == nil || s.v61.lpeGuard == nil {
			return "engine_unavailable", true
		}
		return s.v61.lpeGuard.ApplyState(settings), true
	case "edge_proxy":
		if !effectiveEdgeProxySettings(settings).Enabled {
			return "disabled", true
		}
		if source, ok := any(s).(edgeProxySettingsStateSource); ok {
			return source.EdgeProxySettingsApplyState(), true
		}
		return "engine_unavailable", true
	default:
		return "", false
	}
}

// v61ModuleDetails returns the bounded runtime projection for one 6.1.0 module.
// An unwired engine reports "unavailable" instead of a fake empty runtime.
func (s *APIServer) v61ModuleDetails(module string) map[string]any {
	switch module {
	case "web_exposure":
		if s.v61 == nil || s.v61.webExposure == nil {
			return map[string]any{"runtime": "unavailable"}
		}
		return s.v61.webExposure.Details()
	case "worker_guard":
		if s.v61 == nil || s.v61.workerGuard == nil {
			return map[string]any{"runtime": "unavailable"}
		}
		return s.v61.workerGuard.Details()
	case "tls_sensor":
		if s.v61 == nil || s.v61.tlsSensor == nil {
			return map[string]any{"runtime": "unavailable"}
		}
		return s.v61.tlsSensor.Details()
	case "lpe_guard":
		if s.v61 == nil || s.v61.lpeGuard == nil {
			return map[string]any{"runtime": "unavailable"}
		}
		return s.v61.lpeGuard.Details()
	case "edge_proxy":
		if source, ok := any(s).(edgeProxySettingsStateSource); ok {
			return source.EdgeProxyModuleDetails()
		}
		return map[string]any{"runtime": "unavailable"}
	default:
		return nil
	}
}
