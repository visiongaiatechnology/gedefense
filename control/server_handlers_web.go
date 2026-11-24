// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Embedded dashboard shell and asset serving split out of server.go
// (refactoring wave 1a, structure-only). //go:embed web stays in server.go, as do
// the exact webAssetAllowlist and resolveWebAsset that the security audit and the
// identifier-contract test pin there; this file owns the allowlist data and the
// serving path.

import (
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"path"
	"strings"
)

func (s *APIServer) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.serveEmbedded(w, r, "web/index.html", "text/html; charset=utf-8")
}

// webAssetAllowlist is the complete set of dashboard assets the embedded HTTP
// handler is permitted to serve. Every ES module that app.js imports must be
// listed here: a missing entry breaks the whole module graph with a 404 rather
// than a single missing view, which is why serving is contract-tested against
// the real import graph.
// webAssetAllowlist is the exhaustive set of embedded files the network may reach.
//
// It is exact, not a prefix rule: a request is resolved against this map and
// nothing else. Files that ship for provenance but must never be served - the
// upstream licence, the readme, the upstream manifest and the Sass sources - are
// embedded because the embed directive covers the whole directory, and are kept out
// of the network by being absent here.
var webAssetAllowlist = map[string]bool{
	"api.js":             true,
	"app.js":             true,
	"charts.js":          true,
	"fabric-settings.js": true,
	"fabric-surface.js":  true,
	"gedefense-logo.png": true,
	"geo-map.js":         true,
	"i18n.js":            true,
	"i18n/de.js":         true,
	"i18n/en.js":         true,
	"i18n/ru.js":         true,
	"i18n/zh-CN.js":      true,
	"kinetic.js":         true,
	"l7-integration.js":  true, "l7.js": true,
	"operations.js": true,
	// The overview threat map: its module and its stylesheet. Both are part of the dashboard surface,
	// so they belong in the allowlist - the exhaustive test refuses a file that is embedded but not
	// reachable, and equally a file that is reachable but not embedded.
	"overview-map.css":         true,
	"overview-map.js":          true,
	"overview-map-data.js":     true,
	"overview-map-renderer.js": true,
	"protection.js":            true,
	"render.js":                true,
	"threat-intel.js":          true,
	// V6.3.0 refactoring wave 2: modularized dashboard modules/stylesheet.
	"js/state.js":             true,
	"js/navigation.js":        true,
	"js/views_overview.js":    true,
	"js/views_xdr_spyware.js": true,
	"js/views_titan_styx.js":  true,
	"js/views_logs_audit.js":  true,
	"css/tokens.css":          true,
	"css/layout.css":          true,
	"css/components.css":      true,
	"css/tables.css":          true,
	"css/modals.css":          true,
	"cms.js":                  true,
	"cms.css":                 true,
	"vendor/jsvectormap/js/components/base.js":                  true,
	"vendor/jsvectormap/js/components/concerns/interactable.js": true,
	"vendor/jsvectormap/js/components/line.js":                  true,
	"vendor/jsvectormap/js/components/marker.js":                true,
	"vendor/jsvectormap/js/components/region.js":                true,
	"vendor/jsvectormap/js/components/tooltip.js":               true,
	"vendor/jsvectormap/js/core/applyTransform.js":              true,
	"vendor/jsvectormap/js/core/coordsToPoint.js":               true,
	"vendor/jsvectormap/js/core/createLines.js":                 true,
	"vendor/jsvectormap/js/core/createMarkers.js":               true,
	"vendor/jsvectormap/js/core/createRegions.js":               true,
	"vendor/jsvectormap/js/core/createSeries.js":                true,
	"vendor/jsvectormap/js/core/getInsetForPoint.js":            true,
	"vendor/jsvectormap/js/core/getMarkerPosition.js":           true,
	"vendor/jsvectormap/js/core/index.js":                       true,
	"vendor/jsvectormap/js/core/repositionLabels.js":            true,
	"vendor/jsvectormap/js/core/repositionLines.js":             true,
	"vendor/jsvectormap/js/core/repositionMarkers.js":           true,
	"vendor/jsvectormap/js/core/resize.js":                      true,
	"vendor/jsvectormap/js/core/setFocus.js":                    true,
	"vendor/jsvectormap/js/core/setScale.js":                    true,
	"vendor/jsvectormap/js/core/setupContainerEvents.js":        true,
	"vendor/jsvectormap/js/core/setupContainerTouchEvents.js":   true,
	"vendor/jsvectormap/js/core/setupElementEvents.js":          true,
	"vendor/jsvectormap/js/core/setupZoomButtons.js":            true,
	"vendor/jsvectormap/js/core/updateSize.js":                  true,
	"vendor/jsvectormap/js/dataVisualization.js":                true,
	"vendor/jsvectormap/js/defaults/events.js":                  true,
	"vendor/jsvectormap/js/defaults/options.js":                 true,
	"vendor/jsvectormap/js/eventHandler.js":                     true,
	"vendor/jsvectormap/js/index.js":                            true,
	"vendor/jsvectormap/js/legend.js":                           true,
	"vendor/jsvectormap/js/map.js":                              true,
	"vendor/jsvectormap/js/maps.js":                             true,
	"vendor/jsvectormap/js/projection.js":                       true,
	"vendor/jsvectormap/js/scales/ordinalScale.js":              true,
	"vendor/jsvectormap/js/series.js":                           true,
	"vendor/jsvectormap/js/svg/baseElement.js":                  true,
	"vendor/jsvectormap/js/svg/canvasElement.js":                true,
	"vendor/jsvectormap/js/svg/imageElement.js":                 true,
	"vendor/jsvectormap/js/svg/shapeElement.js":                 true,
	"vendor/jsvectormap/js/svg/textElement.js":                  true,
	"vendor/jsvectormap/js/util/deepMerge.js":                   true,
	"vendor/jsvectormap/js/util/index.js":                       true,
	"vendor/jsvectormap/jsvectormap.css":                        true,
	"vendor/jsvectormap/maps/world-merc.js":                     true,
	"xdr.js":                                                    true,
	// GeDefense 6.1.0 dashboard (docs/V6.1.0-BLUEPRINT.md §5). The exact list the
	// UI agent delivers; the exhaustive contract test keeps this map and the
	// embedded tree in agreement in both directions.
	"v61/base.css":             true,
	"v61/exposure.js":          true,
	"v61/exposure.css":         true,
	"v61/workers.js":           true,
	"v61/workers.css":          true,
	"v61/tls.js":               true,
	"v61/tls.css":              true,
	"v61/lpe.js":               true,
	"v61/lpe.css":              true,
	"v61/edge.js":              true,
	"v61/edge.css":             true,
	"v61/v6.js":                true,
	"v61/v6.css":               true,
	"v61/v6-styx.js":           true,
	"v61/v6-titan.js":          true,
	"v61/v6-cells.js":          true,
	"v61/v6-lockdown.js":       true,
	"v61/v6-witness.js":        true,
	"overview-connections.js":  true,
	"overview-connections.css": true,
	"setup-wizard.js":          true,
	"setup-wizard.css":         true,
}

// webAssetNameAllowed validates a request path before any resolution happens. It
// accepts exactly one optional trailing slash and nothing else: no absolute path, no
// backslash, no NUL, no empty, dot or dot-dot segment, and no uncleaned form.
func webAssetNameAllowed(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	if strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return false
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || path.Clean(trimmed) != trimmed {
		return false
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (s *APIServer) asset(w http.ResponseWriter, r *http.Request) {
	name, redirect := resolveWebAsset(r.PathValue("name"))
	if redirect != "" {
		// The trailing slash is preserved in the Location so the browser re-resolves
		// relative imports against the directory rather than against a file URL.
		http.Redirect(w, r, "/assets/"+redirect, http.StatusMovedPermanently)
		return
	}
	if name == "" {
		http.NotFound(w, r)
		return
	}
	extension := path.Ext(name)
	contentType := mime.TypeByExtension(extension)
	switch extension {
	case ".js":
		contentType = "text/javascript; charset=utf-8"
	case ".css":
		contentType = "text/css; charset=utf-8"
	case ".png":
		contentType = "image/png"
	default:
		if contentType == "" {
			contentType = "application/octet-stream"
		}
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
