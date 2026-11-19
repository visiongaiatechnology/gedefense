// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 Module C: TLS/ALPN sensor handlers and ticker.
//
//	GET /api/v1/tls-sensor/status
//	GET /api/v1/tls-sensor/handshakes
//	GET /api/v1/tls-sensor/flows
//
// The AF_PACKET capture and the INET_DIAG snapshot live in
// internal/flowguard; the parsed ClientHello is fed to the existing
// ParseClientHello / TLSSecurityEngine (through L7Engine.InspectTLSHandshake).
// The widget is off by default and the response is alert-only by default.

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/flowguard"
)

const (
	tlsSensorHandshakeRing = 256
	tlsSensorFlowTick      = time.Second
	tlsSensorStormTTL      = time.Minute

	// Untrusted ClientHello input must never grow the status maps without a
	// bound. The handshake ring is already bounded; the ALPN counters and the
	// peer set were not (VGT-AUDIT-2026-11-19 FIND-002).
	tlsSensorMaxALPNKeys     = 32
	tlsSensorMaxALPNBytes    = 32
	tlsSensorMaxALPNPerHello = 8
	tlsSensorALPNOther       = "(other)"
	tlsSensorMaxTrackedPeers = 4096
)

// TLSSensorEngine is the Module C runtime.
type TLSSensorEngine struct {
	settings *SettingsStore
	l7       *L7Engine
	state    *State

	mu           sync.Mutex
	capture      string
	captureStop  context.CancelFunc
	captureKey   string
	reason       string
	handshakes   []tlsSensorHandshakeView
	handshakeCnt uint64
	alpnCounts   map[string]uint64
	quicInitial  uint64
	findings     uint64
	trackedPeers map[string]struct{}
	flows        *flowguard.FlowTable
	flowsKey     int
	storm        tlsSensorStormView
	lastStormAt  time.Time
}

// NewTLSSensorEngine constructs the Module C engine.
func NewTLSSensorEngine(settings *SettingsStore, l7 *L7Engine, state *State) *TLSSensorEngine {
	return &TLSSensorEngine{
		settings: settings, l7: l7, state: state,
		capture: "inactive", reason: "tls sensor module is disabled; no capture is running",
		handshakes: make([]tlsSensorHandshakeView, 0, tlsSensorHandshakeRing),
		alpnCounts: make(map[string]uint64), trackedPeers: make(map[string]struct{}),
	}
}

// Run reconciles the capture and refreshes the flow snapshot on every tick.
func (e *TLSSensorEngine) Run(ctx context.Context) {
	if e == nil {
		return
	}
	ticker := time.NewTicker(tlsSensorFlowTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			e.stopCapture()
			return
		case <-ticker.C:
			e.reconcile(ctx)
		}
	}
}

// reconcile starts/stops the capture and refreshes the flow snapshot.
func (e *TLSSensorEngine) reconcile(ctx context.Context) {
	if e == nil || e.settings == nil {
		return
	}
	settings := effectiveTLSSensorSettings(e.settings.Get())
	if !settings.Enabled {
		e.stopCapture()
		e.mu.Lock()
		e.capture = "inactive"
		e.reason = "tls sensor module is disabled; no capture is running"
		e.mu.Unlock()
		return
	}
	e.ensureCapture(ctx, settings)
	e.sampleFlows(settings)
}

// captureSignature identifies the capture scope so a settings change reopens it.
func captureSignature(settings TLSSensorFabricSettings) string {
	var builder strings.Builder
	for _, name := range settings.Interfaces {
		builder.WriteString(name)
		builder.WriteByte(',')
	}
	builder.WriteByte('|')
	for _, port := range settings.Ports {
		builder.WriteString(strconv.Itoa(int(port)))
		builder.WriteByte(',')
	}
	builder.WriteByte('|')
	builder.WriteString(strconv.Itoa(settings.MaxPayloadBytes))
	return builder.String()
}

// ensureCapture opens the AF_PACKET capture when it is not running.
func (e *TLSSensorEngine) ensureCapture(ctx context.Context, settings TLSSensorFabricSettings) {
	key := captureSignature(settings)
	e.mu.Lock()
	running := e.capture == "active" && e.captureKey == key
	e.mu.Unlock()
	if running {
		return
	}
	e.stopCapture()
	captureCtx, cancel := context.WithCancel(ctx)
	capture, err := openPacketSource(captureCtx, flowguard.CaptureConfig{
		Interfaces:      append([]string(nil), settings.Interfaces...),
		Ports:           append([]uint16(nil), settings.Ports...),
		MaxPayloadBytes: settings.MaxPayloadBytes,
	})
	if err != nil {
		cancel()
		e.mu.Lock()
		if errors.Is(err, flowguard.ErrUnsupported) {
			e.capture = "unsupported"
		} else {
			e.capture = "inactive"
		}
		e.reason = err.Error()
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.capture = "active"
	e.captureKey = key
	e.captureStop = cancel
	e.reason = ""
	e.mu.Unlock()
	go func() {
		defer capture.Close()
		for {
			if captureCtx.Err() != nil {
				return
			}
			packet, readErr := capture.Read()
			if readErr != nil {
				if errors.Is(readErr, flowguard.ErrTimeout) {
					continue
				}
				e.mu.Lock()
				e.capture = "inactive"
				e.reason = "packet capture stopped: " + readErr.Error()
				e.mu.Unlock()
				return
			}
			e.handlePacket(packet)
		}
	}()
}

// stopCapture closes the running capture, if any.
func (e *TLSSensorEngine) stopCapture() {
	e.mu.Lock()
	stop := e.captureStop
	e.captureStop = nil
	if stop != nil {
		e.capture = "inactive"
	}
	e.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// handlePacket parses one ClientHello and feeds the existing TLS engine.
func (e *TLSSensorEngine) handlePacket(packet flowguard.Packet) {
	if e == nil || len(packet.Payload) == 0 {
		return
	}
	now := time.Now().UTC()
	hints := flowguard.ParseClientHelloHints(packet.Payload)
	var summary TLSClientHelloSummary
	var findings []L7Finding
	if e.l7 != nil {
		parsed, inspected, err := e.l7.InspectTLSHandshake(packet.Peer, packet.Payload, now)
		if err != nil {
			if !strings.Contains(err.Error(), "disabled") {
				return
			}
			// Keep Module C passive TLS telemetry active even when inline L7 TLS inspection is disabled.
			parsed, err = ParseClientHello(packet.Payload)
			if err != nil {
				return
			}
			inspected = nil
		}
		summary, findings = parsed, inspected
	} else {
		parsed, err := ParseClientHello(packet.Payload)
		if err != nil {
			return
		}
		summary = parsed
	}
	version := uint16(0)
	if len(hints.Versions) > 0 {
		version = hints.Versions[0]
		for _, candidate := range hints.Versions {
			if candidate > version {
				version = candidate
			}
		}
	}
	peer := packet.Peer + ":" + strconv.Itoa(int(packet.PeerPort))
	alpn := boundedALPN(hints.ALPN, tlsSensorMaxALPNPerHello, tlsSensorMaxALPNBytes)
	view := tlsSensorHandshakeView{
		At: now, Peer: peer, SNI: summary.SNI, ALPN: alpn,
		JA3: summary.JA3Hash, TLSVersion: version, Cipher: hints.Cipher,
	}
	e.mu.Lock()
	e.handshakes = append([]tlsSensorHandshakeView{view}, e.handshakes...)
	if len(e.handshakes) > tlsSensorHandshakeRing {
		e.handshakes = e.handshakes[:tlsSensorHandshakeRing]
	}
	e.handshakeCnt++
	if packet.UDP {
		e.quicInitial++
	}
	e.accountALPNLocked(alpn)
	e.findings += uint64(len(findings))
	e.trackPeerLocked(packet.Peer)
	e.mu.Unlock()
}

// boundedALPN removes empty, oversized and non-printable protocol names and
// caps both the per-handshake list and each name. A hostile ClientHello cannot
// turn the status payload into an unbounded blob (FIND-002).
func boundedALPN(protocols []string, maxItems, maxBytes int) []string {
	if len(protocols) == 0 {
		return []string{}
	}
	out := make([]string, 0, min(len(protocols), maxItems))
	seen := make(map[string]struct{}, len(protocols))
	for _, protocol := range protocols {
		if len(out) >= maxItems {
			break
		}
		if protocol == "" || len(protocol) > maxBytes || !printableASCII(protocol) {
			continue
		}
		if _, duplicate := seen[protocol]; duplicate {
			continue
		}
		seen[protocol] = struct{}{}
		out = append(out, protocol)
	}
	return out
}

func printableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

// accountALPNLocked bounds the counter map. New protocol names get a slot only
// while the reviewed key budget lasts; everything else is aggregated into one
// constant bucket, so the map size is capped and no handshake is silently lost.
func (e *TLSSensorEngine) accountALPNLocked(protocols []string) {
	if e.alpnCounts == nil {
		e.alpnCounts = make(map[string]uint64)
	}
	for _, protocol := range protocols {
		if _, known := e.alpnCounts[protocol]; known {
			e.alpnCounts[protocol]++
			continue
		}
		// Reserve the last slot for the aggregation bucket.
		if len(e.alpnCounts) < tlsSensorMaxALPNKeys-1 {
			e.alpnCounts[protocol] = 1
			continue
		}
		e.alpnCounts[tlsSensorALPNOther]++
	}
}

// trackPeerLocked caps the peer set. Once full, new peers are not inserted; the
// status reports the capped count and stays bounded (FIND-002).
func (e *TLSSensorEngine) trackPeerLocked(peer string) {
	if peer == "" {
		return
	}
	if e.trackedPeers == nil {
		e.trackedPeers = make(map[string]struct{})
	}
	if _, known := e.trackedPeers[peer]; known {
		return
	}
	if len(e.trackedPeers) >= tlsSensorMaxTrackedPeers {
		return
	}
	e.trackedPeers[peer] = struct{}{}
}

// sampleFlows reads the kernel per-socket counters and evaluates the predicate.
func (e *TLSSensorEngine) sampleFlows(settings TLSSensorFabricSettings) {
	e.mu.Lock()
	if e.flows == nil || e.flowsKey != settings.MaxTrackedFlows {
		e.flows = flowguard.NewFlowTable(settings.MaxTrackedFlows, func() time.Time { return time.Now().UTC() })
		e.flowsKey = settings.MaxTrackedFlows
	}
	table := e.flows
	e.mu.Unlock()
	samples, err := flowguard.ReadFlowSnapshot(settings.Ports, settings.MaxTrackedFlows)
	if err != nil {
		e.mu.Lock()
		e.reason = err.Error()
		e.mu.Unlock()
		return
	}
	predicate := flowguard.Predicate{
		RxThresholdBytes: uint64(settings.RxThresholdBytes),
		TxRatio:          settings.TxRatio,
		AvgPktLenBytes:   settings.AvgPktLenBytes,
		MinPPSRatio:      settings.MinPPSRatio,
	}
	table.Update(samples, predicate)
	entries, _ := table.Snapshot(flowguard.FlowListLimit)
	storm := tlsSensorStormView{Active: false, Severity: "", Peers: []string{}, Predicate: tlsSensorPredicateView{}, ThrottleTTLSeconds: settings.ThrottleTTLSeconds}
	var worst flowguard.FlowMetrics
	worstSet := false
	for _, entry := range entries {
		metrics, matched := flowguard.Evaluate(predicate, entry.Sample)
		if !worstSet || entry.Sample.RxBytes > worst.RxBytes {
			worst, worstSet = metrics, true
		}
		if !matched {
			continue
		}
		storm.Active = true
		storm.Peers = append(storm.Peers, entry.Sample.Peer)
		if len(storm.Peers) >= 8 {
			break
		}
	}
	storm.Predicate = tlsSensorPredicateView{
		RxBytes: worst.RxBytes, TxBytes: worst.TxBytes, Ratio: worst.Ratio,
		AvgPktLen: worst.AvgPktLen, PPSRatio: worst.PPSRatio,
	}
	if storm.Active {
		storm.Severity = "critical"
		storm.Response = responseStage(entries, settings.AlertOnly)
	} else {
		storm.Severity = ""
		storm.Response = "alert"
	}
	e.mu.Lock()
	e.storm = storm
	shouldAlert := storm.Active && time.Since(e.lastStormAt) >= tlsSensorStormTTL
	if shouldAlert {
		e.lastStormAt = time.Now().UTC()
	}
	e.mu.Unlock()
	if shouldAlert {
		e.raiseStormIncident(storm)
	}
}

// responseStage implements the staged response contract: alert-only never
// escalates; otherwise the first observation is a throttle plan and a flow that
// persists across two evaluations is a ban candidate. No kernel block is applied
// here; the plan is recorded for the operator and the existing response paths.
func responseStage(entries []flowguard.FlowEntry, alertOnly bool) string {
	if alertOnly {
		return flowguard.ResponseAlert
	}
	stage := flowguard.ResponseThrottle
	for _, entry := range entries {
		if entry.Verdict != flowguard.VerdictStorm {
			continue
		}
		stage = flowguard.StagedResponse(false, true, entry.Matches, false)
		if stage == flowguard.ResponseBan {
			return stage
		}
	}
	return stage
}

// raiseStormIncident records the control-storm incident.
func (e *TLSSensorEngine) raiseStormIncident(storm tlsSensorStormView) {
	if e == nil || e.state == nil {
		return
	}
	summary := "TLS control storm: " + strconv.Itoa(len(storm.Peers)) + " peer(s) exceed the rx/ratio/avg-length/pps predicate"
	remote := ""
	if len(storm.Peers) > 0 {
		remote = storm.Peers[0]
	}
	outcome := "alert-only: the storm was recorded and no kernel response was applied"
	if storm.Response == flowguard.ResponseThrottle {
		outcome = "throttle plan recorded (per-peer TTL " + strconv.Itoa(storm.ThrottleTTLSeconds) + " s); no kernel block was applied by the sensor"
	}
	if storm.Response == flowguard.ResponseBan {
		outcome = "ban candidate: the storm persisted across two evaluations; the existing response path must confirm the block"
	}
	incident := XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: storm.Severity, Score: 180, ResponseScore: 180,
		Remote: remote, RuleIDs: []string{"XDR.TLS.CONTROL_STORM"}, Categories: []string{"network", "tls-sensor"},
		Summary: summary, Decision: storm.Response, Action: "none", Outcome: outcome,
	}
	e.state.AddIncident(incident)
}

// RecentPeers returns the unique peers seen in the handshake ring.
func (e *TLSSensorEngine) RecentPeers(limit int) []string {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 || limit > tlsSensorHandshakeRing {
		limit = tlsSensorHandshakeRing
	}
	seen := make(map[string]struct{}, limit)
	out := make([]string, 0, limit)
	for _, handshake := range e.handshakes {
		peer := handshake.Peer
		if index := strings.LastIndex(peer, ":"); index > 0 {
			peer = peer[:index]
		}
		if peer == "" {
			continue
		}
		if _, dup := seen[peer]; dup {
			continue
		}
		seen[peer] = struct{}{}
		out = append(out, peer)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// ApplyState maps the persisted revision onto the Fabric Settings vocabulary.
func (e *TLSSensorEngine) ApplyState(settings RuntimeSettings) string {
	desired := effectiveTLSSensorSettings(settings)
	if !desired.Enabled {
		return "disabled"
	}
	if e == nil {
		return "engine_unavailable"
	}
	e.mu.Lock()
	capture := e.capture
	e.mu.Unlock()
	if capture == "active" {
		return "applied"
	}
	return "engine_unavailable"
}

// Details is the Settings-module runtime projection.
func (e *TLSSensorEngine) Details() map[string]any {
	if e == nil {
		return map[string]any{"runtime": "unavailable"}
	}
	e.mu.Lock()
	capture, reason, handshakes, flows := e.capture, e.reason, len(e.handshakes), len(e.trackedPeers)
	e.mu.Unlock()
	return map[string]any{"runtime": map[string]any{
		"capture": capture, "reason": reason, "handshakes": handshakes, "peers": flows,
	}}
}
