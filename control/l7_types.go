// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrL7InvalidRequest      = errors.New("l7 request validation failed")
	ErrL7ResourceLimit       = errors.New("l7 resource budget exceeded")
	ErrL7Unauthorized        = errors.New("l7 peer is not authorized")
	ErrL7UnsupportedEncoding = errors.New("l7 content encoding is unsupported")
)

const l7ProtocolVersion = 1

type L7Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type L7InspectionRequest struct {
	Version       int        `json:"version"`
	RequestID     string     `json:"request_id,omitempty"`
	Method        string     `json:"method"`
	Scheme        string     `json:"scheme,omitempty"`
	Host          string     `json:"host"`
	URI           string     `json:"uri"`
	RemoteIP      string     `json:"remote_ip"`
	Headers       []L7Header `json:"headers,omitempty"`
	BodyBase64    string     `json:"body_base64,omitempty"`
	ServerPID     int        `json:"server_pid,omitempty"`
	ServerProcess string     `json:"server_process,omitempty"`
}

type L7Finding struct {
	RuleID          string `json:"rule_id"`
	Category        string `json:"category"`
	Severity        string `json:"severity"`
	Score           int    `json:"score"`
	Confidence      int    `json:"confidence"`
	Location        string `json:"location"`
	EvidenceSHA256  string `json:"evidence_sha256"`
	FingerprintType string `json:"fingerprint_type,omitempty"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	Summary         string `json:"summary"`
}

type L7InspectionResponse struct {
	RequestID  string      `json:"request_id"`
	Decision   string      `json:"decision"`
	Score      int         `json:"score"`
	Confidence int         `json:"confidence"`
	Enforced   bool        `json:"enforced"`
	Reason     string      `json:"reason"`
	BodySHA256 string      `json:"body_sha256,omitempty"`
	Findings   []L7Finding `json:"findings"`
}

type L7TLSClientHelloRequest struct {
	Version           int    `json:"version"`
	ClientIP          string `json:"client_ip"`
	ClientHelloBase64 string `json:"client_hello_base64"`
}

type L7TLSClientHelloResponse struct {
	Decision string                `json:"decision"`
	Summary  TLSClientHelloSummary `json:"summary"`
	Findings []L7Finding           `json:"findings"`
}

type L7Status struct {
	Enabled           bool       `json:"enabled"`
	Mode              string     `json:"mode"`
	Healthy           bool       `json:"healthy"`
	Socket            string     `json:"socket,omitempty"`
	RequestsTotal     uint64     `json:"requests_total"`
	FindingsTotal     uint64     `json:"findings_total"`
	BlockedTotal      uint64     `json:"blocked_total"`
	RateLimitedTotal  uint64     `json:"rate_limited_total"`
	RejectedTotal     uint64     `json:"rejected_total"`
	ActiveConnections int32      `json:"active_connections"`
	LastInspection    *time.Time `json:"last_inspection,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	InlineEnabled     bool       `json:"inline_enabled"`
	InlineHealthy     bool       `json:"inline_healthy"`
	// SelfTestOutcome and SelfTestAt record the last time the inspection path was
	// measured end to end rather than inferred from events.
	//
	// InlineHealthy is event-driven and sticky: it is set when the listener starts and
	// when a request traverses it, and cleared by any error, but nothing ever re-derives
	// it. A single transient accept error therefore left the inline path reported as
	// degraded indefinitely, and no amount of evidence to the contrary changed that - a
	// passing self-test proved the path worked and had no influence on the verdict at
	// all. Recording the measurement lets the stronger evidence win, within a bounded
	// window so a stale pass cannot mask a path that has since broken.
	SelfTestOutcome           string     `json:"self_test_outcome,omitempty"`
	SelfTestAt                *time.Time `json:"self_test_at,omitempty"`
	InlineSocket              string     `json:"inline_socket,omitempty"`
	InlineRequestsTotal       uint64     `json:"inline_requests_total"`
	InlineBlockedTotal        uint64     `json:"inline_blocked_total"`
	InlineUpstreamErrorsTotal uint64     `json:"inline_upstream_errors_total"`
	InlineLastError           string     `json:"inline_last_error,omitempty"`
	// InlineFindingsTotal and InlineLastRequestAt make the inline edge a
	// first-class producer in the published status. Before they existed the only
	// inline facts were request/blocked counters, so a host that served all of its
	// traffic through the inline edge reported producer_attached=false.
	InlineFindingsTotal uint64     `json:"inline_findings_total"`
	InlineLastRequestAt *time.Time `json:"inline_last_request_at,omitempty"`
	// InlineProducerAttached states the inline edge's own verdict: the listener is
	// enabled, healthy and has inspected at least one request. It is published next
	// to ProducerAttached so a consumer never has to infer one from the other.
	InlineProducerAttached        bool   `json:"inline_producer_attached"`
	InlineAttachmentReason        string `json:"inline_attachment_reason,omitempty"`
	ResponsesInspectedTotal       uint64 `json:"responses_inspected_total"`
	ResponseFindingsTotal         uint64 `json:"response_findings_total"`
	ResponseInspectionErrorsTotal uint64 `json:"response_inspection_errors_total"`
	// Coverage, attachment and the discovered web surface are three separate facts and
	// are published as such, so a consumer can never derive one from another. An
	// operator sees engine health, whether a path is attached, and whether the host
	// even has web traffic to inspect.
	Coverage                 string     `json:"coverage"`
	TrafficPathAttached      bool       `json:"traffic_path_attached"`
	CoverageRequired         bool       `json:"coverage_required"`
	ProducerAttached         bool       `json:"producer_attached"`
	LastProducerSeen         *time.Time `json:"last_producer_seen,omitempty"`
	RequestsSeen             uint64     `json:"requests_seen"`
	LastRequestAt            *time.Time `json:"last_request_at,omitempty"`
	WebSurface               WebSurface `json:"web_surface"`
	WebSurfaceNote           string     `json:"web_surface_note,omitempty"`
	Miswired                 bool       `json:"miswired"`
	CoverageReason           string     `json:"coverage_reason,omitempty"`
	TrafficPathVerified      bool       `json:"traffic_path_verified"`
	TLSEnabled               bool       `json:"tls_enabled"`
	TLSPathVerified          bool       `json:"tls_path_verified"`
	TLSHandshakesTotal       uint64     `json:"tls_handshakes_total"`
	TLSFindingsTotal         uint64     `json:"tls_findings_total"`
	TLSLastHandshake         *time.Time `json:"tls_last_handshake,omitempty"`
	TLSLastError             string     `json:"tls_last_error,omitempty"`
	TLSFingerprintVersion    int        `json:"tls_fingerprint_version"`
	TLSFingerprintSource     string     `json:"tls_fingerprint_source,omitempty"`
	TLSFingerprintSignatures int        `json:"tls_fingerprint_signatures"`
	TLSFingerprintProfiles   int        `json:"tls_fingerprint_profiles"`
}

// L7 attachment semantics.
//
// Two independent traffic paths can feed the L7 engine: the envelope producer on the
// inspection socket and the inline edge, which proxies real HTTP through a Unix socket.
// The inline edge is not a fallback for the producer path; it is the first-class path
// for hosts whose web server cannot post envelopes, and it must be reported as a
// producer. Historically ProducerAttached was derived from the socket-producer counter
// alone, so an inline deployment kept reporting producer_attached=false while it was
// inspecting and blocking every request.
//
// The three facts stay separate and are each derived from observed counters:
//   - inline_producer_attached: the inline listener is enabled, healthy and has
//     inspected at least one request (a bound-but-silent socket is NOT a producer);
//   - traffic_path_attached: one of the paths is wired and usable (inline listener
//     bound and healthy, socket producer traffic, or TLS telemetry);
//   - traffic_path_verified: the derived coverage verdict says verified traffic exists,
//     and the inline path never claims verification without an inspected request.
const (
	l7InlineAttachmentDisabled  = "inline edge is disabled by configuration"
	l7InlineAttachmentUnhealthy = "inline listener is not healthy and has not been verified"
	l7InlineAttachmentAwaiting  = "inline listener is attached and healthy, awaiting the first inspected request"
	l7InlineAttachmentVerified  = "inline listener has inspected request traffic"
)

// l7InlineTrafficVerified reports whether the inline edge has actually inspected
// traffic: enabled, healthy and at least one request counted. Any one of those missing
// means the inline path is not a verified producer.
func l7InlineTrafficVerified(status L7Status) bool {
	return status.InlineEnabled && status.InlineHealthy && status.InlineRequestsTotal > 0
}

func l7InlineAttachmentReason(status L7Status) string {
	switch {
	case !status.InlineEnabled:
		return l7InlineAttachmentDisabled
	case !status.InlineHealthy:
		return l7InlineAttachmentUnhealthy
	case status.InlineRequestsTotal == 0:
		return l7InlineAttachmentAwaiting
	default:
		return fmt.Sprintf("%s (%d request(s) inspected)", l7InlineAttachmentVerified, status.InlineRequestsTotal)
	}
}

// l7SocketRequests derives the socket-producer request count from a status that may
// already carry inline traffic. The counters are additive and the publisher may have
// written either the raw producer count or the aggregate, so the difference is taken
// only when it cannot go negative. With several producers this is an estimate until the
// next inline publish rewrites the aggregate; for the inline-only deployment it is
// exact.
func l7SocketRequests(status L7Status) uint64 {
	if status.RequestsTotal >= status.InlineRequestsTotal {
		return status.RequestsTotal - status.InlineRequestsTotal
	}
	return status.RequestsTotal
}

func l7SocketBlocked(status L7Status) uint64 {
	if status.BlockedTotal >= status.InlineBlockedTotal {
		return status.BlockedTotal - status.InlineBlockedTotal
	}
	return status.BlockedTotal
}

func l7SocketFindings(status L7Status) uint64 {
	inlineFindings := status.InlineFindingsTotal + status.ResponseFindingsTotal
	if status.FindingsTotal >= inlineFindings {
		return status.FindingsTotal - inlineFindings
	}
	return status.FindingsTotal
}

// l7AttachmentFlags derives the attachment verdict purely from observed counters.
func l7AttachmentFlags(status L7Status) (inlineProducer, producerAttached, trafficPathAttached bool) {
	inlineProducer = l7InlineTrafficVerified(status)
	socketProducer := l7SocketRequests(status) > 0
	producerAttached = socketProducer || inlineProducer
	inlineAttached := status.InlineEnabled && status.InlineHealthy
	trafficPathAttached = inlineAttached || socketProducer || status.TLSHandshakesTotal > 0
	return inlineProducer, producerAttached, trafficPathAttached
}

// applyAttachmentSemantics rewrites the derived attachment fields in place. It is called
// by the inline edge publisher, which observes the inline counters directly.
func (status *L7Status) applyAttachmentSemantics() {
	if status == nil {
		return
	}
	inlineProducer, producerAttached, trafficPathAttached := l7AttachmentFlags(*status)
	status.InlineProducerAttached = inlineProducer
	status.ProducerAttached = producerAttached
	status.TrafficPathAttached = trafficPathAttached
	status.TrafficPathVerified = inlineProducer || l7SocketRequests(*status) > 0 || status.TLSHandshakesTotal > 0
	status.InlineAttachmentReason = l7InlineAttachmentReason(*status)
}

// MarshalJSON publishes the attachment verdict and the aggregated counters.
//
// The status has two publishers: the inspection service, which owns the socket-producer
// counters, and the inline edge, which owns the inline counters. Neither can see the
// other's atomics, and the last publisher wins. Deriving the verdict at serialization
// time keeps the wire format correct even when the other publisher wrote last, which is
// exactly the gap that made a live host report producer_attached=false with verified
// inline traffic.
//
// The four totals aggregate inline traffic: requests_total, findings_total,
// blocked_total and rate_limited_total are the numbers an operator and the JSON
// consumers read. rate_limited_total has no inline component because the inline edge
// has no rate limiter; it is passed through unchanged.
func (status L7Status) MarshalJSON() ([]byte, error) {
	type plain L7Status
	view := plain(status)

	inlineVerified := l7InlineTrafficVerified(status)
	socketRequests := l7SocketRequests(status)
	inlineAttached := status.InlineEnabled && status.InlineHealthy

	view.InlineProducerAttached = inlineVerified
	view.ProducerAttached = socketRequests > 0 || inlineVerified
	view.TrafficPathAttached = inlineAttached || socketRequests > 0 || status.TLSHandshakesTotal > 0
	view.InlineAttachmentReason = l7InlineAttachmentReason(status)
	view.RequestsTotal = socketRequests + status.InlineRequestsTotal
	view.BlockedTotal = l7SocketBlocked(status) + status.InlineBlockedTotal
	view.FindingsTotal = l7SocketFindings(status) + status.InlineFindingsTotal + status.ResponseFindingsTotal

	// No false "full": a verified path requires observed HTTP traffic. A stale flag
	// from an earlier computation must not survive an idle or degraded inline path.
	// The positive case must be derived here as well, because the wire contract is
	// what the dashboard and the protection status consume; a verified inline edge
	// that succeeded after the last socket publisher wrote the struct still counts.
	view.TrafficPathVerified = socketRequests > 0 || inlineVerified || status.TLSHandshakesTotal > 0
	if status.InlineEnabled && !status.InlineHealthy && socketRequests == 0 && status.TLSHandshakesTotal == 0 {
		view.TrafficPathVerified = false
	}

	return json.Marshal(view)
}

type l7Candidate struct {
	Location string
	Value    string
	// Depth is the number of decode layers applied to produce this candidate.
	// Depth >= 2 means the inspected value was multi-layer encoded, which is a
	// detection signal on its own (F-10 / CHAIN-008).
	Depth int
}

type l7NormalizedRequest struct {
	RequestID               string
	Method                  string
	Scheme                  string
	Host                    string
	Path                    string
	RatePath                string
	RemoteIP                string
	Headers                 map[string][]string
	Body                    []byte
	BodySHA256              string
	ContentType             string
	Candidates              []l7Candidate
	CandidateBytes          int
	CandidateBudgetExceeded bool
	ServerPID               int
	ServerProcess           string
}
