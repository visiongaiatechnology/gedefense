// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 Module C API payloads and handlers.
//
//	GET /api/v1/tls-sensor/status
//	GET /api/v1/tls-sensor/handshakes
//	GET /api/v1/tls-sensor/flows

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/flowguard"
)

// -------------------------------------------------------------- API payloads

type tlsSensorPredicateView struct {
	RxBytes   uint64  `json:"rx_bytes"`
	TxBytes   uint64  `json:"tx_bytes"`
	Ratio     float64 `json:"ratio"`
	AvgPktLen float64 `json:"avg_pkt_len"`
	PPSRatio  float64 `json:"pps_ratio"`
}

type tlsSensorStormView struct {
	Active             bool                   `json:"active"`
	Severity           string                 `json:"severity"`
	Peers              []string               `json:"peers"`
	Predicate          tlsSensorPredicateView `json:"predicate"`
	Response           string                 `json:"response,omitempty"`
	ThrottleTTLSeconds int                    `json:"throttle_ttl_seconds,omitempty"`
}

type tlsSensorEngineView struct {
	Findings uint64 `json:"findings"`
	Tracked  int    `json:"tracked"`
}

type tlsSensorStatusView struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Capture     string              `json:"capture"`
	Reason      string              `json:"reason"`
	Handshakes  uint64              `json:"handshakes"`
	ALPN        map[string]uint64   `json:"alpn"`
	QUICInitial uint64              `json:"quic_initial"`
	Flows       int                 `json:"flows"`
	Storm       tlsSensorStormView  `json:"storm"`
	TLSEngine   tlsSensorEngineView `json:"tls_engine"`
}

type tlsSensorHandshakeView struct {
	At         time.Time `json:"at"`
	Peer       string    `json:"peer"`
	SNI        string    `json:"sni"`
	ALPN       []string  `json:"alpn"`
	JA3        string    `json:"ja3"`
	TLSVersion uint16    `json:"tls_version"`
	Cipher     uint16    `json:"cipher"`
}

type tlsSensorFlowView struct {
	Peer       string  `json:"peer"`
	Port       uint16  `json:"port"`
	RxBytes    uint64  `json:"rx_bytes"`
	TxBytes    uint64  `json:"tx_bytes"`
	SegsIn     uint64  `json:"segs_in"`
	SegsOut    uint64  `json:"segs_out"`
	AvgPktLen  float64 `json:"avg_pkt_len"`
	AgeSeconds int64   `json:"age_seconds"`
	Verdict    string  `json:"verdict"`
}

// tlsSensorStatus serves GET /api/v1/tls-sensor/status.
func (s *APIServer) tlsSensorStatus(w http.ResponseWriter, _ *http.Request) {
	view := tlsSensorStatusView{
		GeneratedAt: time.Now().UTC(), Capture: "inactive",
		Reason: "tls sensor engine is not wired on this control plane",
		ALPN:   map[string]uint64{}, Storm: tlsSensorStormView{Peers: []string{}},
	}
	if s.v61 == nil || s.v61.tlsSensor == nil {
		writeJSON(w, http.StatusOK, view)
		return
	}
	engine := s.v61.tlsSensor
	engine.mu.Lock()
	view.Capture = engine.capture
	view.Reason = engine.reason
	view.Handshakes = engine.handshakeCnt
	view.QUICInitial = engine.quicInitial
	view.Storm = engine.storm
	view.TLSEngine = tlsSensorEngineView{Findings: engine.findings, Tracked: len(engine.trackedPeers)}
	for protocol, count := range engine.alpnCounts {
		view.ALPN[protocol] = count
	}
	if engine.flows != nil {
		_, used := engine.flows.Snapshot(1)
		view.Flows = used
	}
	engine.mu.Unlock()
	if view.Storm.Peers == nil {
		view.Storm.Peers = []string{}
	}
	writeJSON(w, http.StatusOK, view)
}

// tlsSensorHandshakes serves GET /api/v1/tls-sensor/handshakes.
func (s *APIServer) tlsSensorHandshakes(w http.ResponseWriter, r *http.Request) {
	events, next := tlsSensorRingPage(s, r.URL.Query().Get("limit"), r.URL.Query().Get("cursor"))
	writeJSON(w, http.StatusOK, map[string]any{"handshakes": events, "next": next})
}

// tlsSensorRingPage returns one page of the bounded handshake ring.
func tlsSensorRingPage(s *APIServer, rawLimit, rawCursor string) ([]tlsSensorHandshakeView, string) {
	if s.v61 == nil || s.v61.tlsSensor == nil {
		return []tlsSensorHandshakeView{}, "0"
	}
	limit := clampQueryInt(rawLimit, 100, 1, tlsSensorHandshakeRing)
	cursor := clampQueryInt(rawCursor, 0, 0, tlsSensorHandshakeRing)
	engine := s.v61.tlsSensor
	engine.mu.Lock()
	defer engine.mu.Unlock()
	total := len(engine.handshakes)
	if cursor > total {
		cursor = total
	}
	end := cursor + limit
	if end > total {
		end = total
	}
	return append([]tlsSensorHandshakeView(nil), engine.handshakes[cursor:end]...), strconv.Itoa(end)
}

// tlsSensorFlows serves GET /api/v1/tls-sensor/flows.
func (s *APIServer) tlsSensorFlows(w http.ResponseWriter, r *http.Request) {
	flows := []tlsSensorFlowView{}
	budget := tlsSensorBudgetView{MaxFlows: 0, Used: 0}
	if s.v61 != nil && s.v61.tlsSensor != nil {
		engine := s.v61.tlsSensor
		engine.mu.Lock()
		table := engine.flows
		engine.mu.Unlock()
		if table != nil {
			limit := clampQueryInt(r.URL.Query().Get("limit"), 256, 1, flowguard.FlowListLimit)
			now := time.Now().UTC()
			entries, used := table.Snapshot(limit)
			budget.MaxFlows = table.MaxFlows()
			budget.Used = used
			for _, entry := range entries {
				age := int64(0)
				if !entry.FirstSeen.IsZero() {
					age = int64(now.Sub(entry.FirstSeen).Seconds())
				}
				metrics := flowguard.Metrics(entry.Sample)
				flows = append(flows, tlsSensorFlowView{
					Peer: entry.Sample.Peer, Port: entry.Sample.Port,
					RxBytes: entry.Sample.RxBytes, TxBytes: entry.Sample.TxBytes,
					SegsIn: entry.Sample.SegsIn, SegsOut: entry.Sample.SegsOut,
					AvgPktLen: metrics.AvgPktLen, AgeSeconds: age, Verdict: entry.Verdict,
				})
			}
		}
	}
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].Peer != flows[j].Peer {
			return flows[i].Peer < flows[j].Peer
		}
		return flows[i].Port < flows[j].Port
	})
	writeJSON(w, http.StatusOK, map[string]any{"flows": flows, "budget": budget})
}

type tlsSensorBudgetView struct {
	MaxFlows int `json:"max_flows"`
	Used     int `json:"used"`
}
