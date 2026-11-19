// Package flowguard is Module C of GeDefense 6.1.0: the TLS/ALPN sensor's
// bounded flow model and the exact control-storm predicate.
//
// The predicate is pure and unit-tested; the kernel-facing capture (AF_PACKET)
// and the socket-diag snapshot live in build-tagged files.
package flowguard

import (
	"errors"
	"time"
)

// Predicate is the administrable control-storm threshold set. The predicate is
// deliberately asymmetric: it fires on many small inbound packets that are
// answered with very little, which is what a control-channel storm looks like
// and what a large upload does not.
type Predicate struct {
	RxThresholdBytes uint64
	TxRatio          int
	AvgPktLenBytes   int
	MinPPSRatio      int
}

// DefaultPredicate mirrors the compiled-in settings defaults.
func DefaultPredicate() Predicate {
	return Predicate{
		RxThresholdBytes: 256 << 20,
		TxRatio:          4,
		AvgPktLenBytes:   240,
		MinPPSRatio:      8,
	}
}

// FlowSample is one kernel-maintained per-socket counter pair.
type FlowSample struct {
	Peer    string
	Port    uint16
	RxBytes uint64
	TxBytes uint64
	SegsIn  uint64
	SegsOut uint64
}

// FlowMetrics is the computed predicate input, published in the status payload.
type FlowMetrics struct {
	RxBytes   uint64  `json:"rx_bytes"`
	TxBytes   uint64  `json:"tx_bytes"`
	Ratio     float64 `json:"ratio"`
	AvgPktLen float64 `json:"avg_pkt_len"`
	PPSRatio  float64 `json:"pps_ratio"`
}

// Metrics computes the bounded, overflow-safe predicate metrics for one flow.
func Metrics(sample FlowSample) FlowMetrics {
	metrics := FlowMetrics{RxBytes: sample.RxBytes, TxBytes: sample.TxBytes}
	metrics.Ratio = float64(sample.RxBytes) / float64(maxUint64(sample.TxBytes, 1))
	metrics.AvgPktLen = float64(sample.RxBytes) / float64(maxUint64(sample.SegsIn, 1))
	metrics.PPSRatio = float64(sample.SegsIn) / float64(maxUint64(sample.SegsOut, 1))
	return metrics
}

// Evaluate applies the exact predicate from the 6.1.0 blueprint:
//
//	rx_bytes > threshold
//	&& rx_bytes > ratio * tx_bytes
//	&& avg_pkt_len < avg_limit
//	&& segs_in > min_pps_ratio * max(segs_out, 1)
//
// A large upload fails the average-packet-length test (the payload segments are
// full-sized) and therefore never triggers, which the module's negative test
// locks in.
func Evaluate(predicate Predicate, sample FlowSample) (FlowMetrics, bool) {
	metrics := Metrics(sample)
	if predicate.RxThresholdBytes == 0 {
		predicate = DefaultPredicate()
	}
	if sample.RxBytes <= predicate.RxThresholdBytes {
		return metrics, false
	}
	if predicate.TxRatio < 1 {
		predicate.TxRatio = 1
	}
	if predicate.AvgPktLenBytes <= 0 {
		predicate.AvgPktLenBytes = 240
	}
	if predicate.MinPPSRatio < 1 {
		predicate.MinPPSRatio = 1
	}
	if float64(sample.RxBytes) <= float64(predicate.TxRatio)*float64(maxUint64(sample.TxBytes, 1)) {
		return metrics, false
	}
	if metrics.AvgPktLen >= float64(predicate.AvgPktLenBytes) {
		return metrics, false
	}
	if float64(sample.SegsIn) <= float64(predicate.MinPPSRatio)*float64(maxUint64(sample.SegsOut, 1)) {
		return metrics, false
	}
	return metrics, true
}

// Verdict is the per-flow operator-facing class.
const (
	VerdictOK    = "ok"
	VerdictWatch = "watch"
	VerdictStorm = "storm"
)

// ClassifyFlow maps a flow to the published verdict. "watch" is the near-miss
// band: the flow is large and lopsided but still carries normal-sized packets,
// which is exactly the upload shape that must not be banned.
func ClassifyFlow(predicate Predicate, sample FlowSample, matched bool) string {
	if matched {
		return VerdictStorm
	}
	if predicate.RxThresholdBytes == 0 {
		predicate = DefaultPredicate()
	}
	// Watch only when the bytes condition is already met but a packet-shape or
	// ratio condition fails clearly, never for ordinary traffic.
	if sample.RxBytes <= predicate.RxThresholdBytes {
		return VerdictOK
	}
	metrics := Metrics(sample)
	if metrics.Ratio > float64(predicate.TxRatio) || metrics.AvgPktLen < 2*float64(predicate.AvgPktLenBytes) {
		return VerdictWatch
	}
	return VerdictOK
}

// Staged response vocabulary: alert -> throttle -> ban.
const (
	ResponseAlert    = "alert"
	ResponseThrottle = "throttle"
	ResponseBan      = "ban"
)

// StagedResponse decides the response stage. Alert-only is always alert. A
// matched flow first produces a throttle plan; a ban requires either a second
// consecutive matching evaluation or a correlated worker crash. A flow that
// fails the average-length test can never reach throttle or ban.
func StagedResponse(alertOnly bool, matched bool, previousMatches int, correlatedCrash bool) string {
	if alertOnly {
		return ResponseAlert
	}
	if !matched {
		return ResponseAlert
	}
	if correlatedCrash || previousMatches >= 2 {
		return ResponseBan
	}
	return ResponseThrottle
}

// ErrUnsupported reports a platform without AF_PACKET / NETLINK_SOCK_DIAG.
var ErrUnsupported = errors.New("flow sensor is only available on Linux")

// ErrTimeout reports a capture read without a packet inside the poll interval.
var ErrTimeout = errors.New("capture poll timed out")

// Packet is one bounded handshake candidate handed to the TLS parser.
type Packet struct {
	Peer     string
	PeerPort uint16
	Port     uint16
	Payload  []byte
	UDP      bool
	At       time.Time
}

// CaptureConfig is the administrable capture scope.
type CaptureConfig struct {
	Interfaces      []string
	Ports           []uint16
	MaxPayloadBytes int
}

// Normalize keeps the capture bounds inside the documented settings limits.
func (in CaptureConfig) Normalize() CaptureConfig {
	out := in
	if len(out.Ports) == 0 {
		out.Ports = []uint16{443, 8443}
	}
	if len(out.Ports) > 8 {
		out.Ports = out.Ports[:8]
	}
	if out.MaxPayloadBytes < 512 || out.MaxPayloadBytes > 2048 {
		out.MaxPayloadBytes = 1536
	}
	if len(out.Interfaces) > 8 {
		out.Interfaces = out.Interfaces[:8]
	}
	return out
}

// maxUint64 returns the larger of two unsigned values (used as the denominator
// floor so a zero counter never divides by zero or panics).
func maxUint64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}
