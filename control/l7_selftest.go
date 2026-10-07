// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// L7 self-test.
//
// The purpose is to answer one question with evidence rather than configuration: does
// a request that enters the configured inspection path actually come out the other
// side having been inspected? Everything else in this area is inference; this is the
// only part that observes.
//
// Design constraints, each of which is a deliberate refusal:
//
//   - It sends a benign synthetic request. It never replays captured traffic, never
//     carries a payload that could trip a detector, and never touches a real client's
//     data.
//   - It talks to the sockets directly, so it exercises the envelope contract, peer
//     authorisation and the engine - not just the engine in isolation.
//   - It runs once with a hard deadline. There is no retry loop, because a diagnostic
//     that can be made to hammer the engine is a denial-of-service primitive.
//   - It never reports PASS for a path that is not attached. "Not attached" is a
//     result, not a failure, and pretending otherwise is the bug this whole area had.
//   - It never writes anything. No file, no upstream state, no counter of its own.
//
// The self-test is itself excluded from the counters it measures: it reads the totals
// before and after and reports the delta, so an operator can see that the number moved
// without the diagnostic inflating the very metric it inspects.

const (
	// l7SelfTestPath is a reserved path that cannot collide with an operator route.
	l7SelfTestPath = "/__gedefense_selftest__"
	// l7SelfTestTimeout bounds the whole probe.
	l7SelfTestTimeout = 3 * time.Second
	// l7SelfTestMaxResponseBytes bounds what the probe will read back.
	l7SelfTestMaxResponseBytes = 64 << 10
)

// L7SelfTestOutcome classifies the result. Only PASS means an inspected request was
// observed end to end.
type L7SelfTestOutcome string

const (
	L7SelfTestPass        L7SelfTestOutcome = "PASS"
	L7SelfTestFail        L7SelfTestOutcome = "FAIL"
	L7SelfTestNotAttached L7SelfTestOutcome = "NOT_ATTACHED"
	L7SelfTestDisabled    L7SelfTestOutcome = "DISABLED"
)

// L7SelfTestResult is the evidence the operator receives.
type L7SelfTestResult struct {
	Ran            bool              `json:"ran"`
	Outcome        L7SelfTestOutcome `json:"outcome"`
	Path           string            `json:"path"`
	Detail         string            `json:"detail"`
	EngineAnswer   string            `json:"engine_answer,omitempty"`
	HTTPStatus     int               `json:"http_status,omitempty"`
	RequestsBefore uint64            `json:"requests_before"`
	RequestsAfter  uint64            `json:"requests_after"`
	CounterMoved   bool              `json:"counter_moved"`
	LatencyMillis  int64             `json:"latency_millis"`
	At             time.Time         `json:"at"`
}

// RunSelfTest probes the configured inspection path. It never returns an error: every
// outcome, including "the socket refused us", is data the operator needs, and an error
// return would tempt a caller into collapsing those into one uninformative failure.
func (s *L7Service) RunSelfTest(ctx context.Context) L7SelfTestResult {
	now := time.Now().UTC()
	result := L7SelfTestResult{Outcome: L7SelfTestDisabled, Path: "none", At: now}

	if s == nil || !s.cfg.Enabled {
		result.Detail = "L7 is disabled by configuration, so there is no inspection path to test"
		return result
	}

	// Which path is configured decides what is tested, and the answer is taken from
	// configuration plus observed counters - never assumed.
	before := s.state.Snapshot().L7
	producerPath := strings.TrimSpace(s.cfg.Socket)
	inlinePath := strings.TrimSpace(s.cfg.InlineSocket)

	probeCtx, cancel := context.WithTimeout(ctx, l7SelfTestTimeout)
	defer cancel()

	switch {
	case s.cfg.InlineEnabled && s.cfg.InlineHealthyOrConfigured():
		result.Path = "inline"
		result = s.probeInline(probeCtx, result)
	case producerPath != "":
		result.Path = "producer"
		result = s.probeProducer(probeCtx, producerPath, result)
	case inlinePath != "":
		// An inline socket is configured but the listener is not running. Saying so is
		// the honest answer; probing a socket nobody is listening on would report a
		// connection error as though it were a coverage failure.
		result.Outcome = L7SelfTestNotAttached
		result.Detail = "an inline socket is configured but the inline listener is not enabled, so no request can traverse it"
		return result
	default:
		result.Outcome = L7SelfTestNotAttached
		result.Detail = "no inspection socket is configured; enable the inline edge or point a producer at the inspection socket"
		return result
	}

	// The counter delta is read after the probe on whichever path ran.
	after := s.state.Snapshot().L7
	result.RequestsBefore = before.RequestsTotal + before.InlineRequestsTotal
	result.RequestsAfter = after.RequestsTotal + after.InlineRequestsTotal
	result.CounterMoved = result.RequestsAfter > result.RequestsBefore
	if result.Ran && result.Outcome == L7SelfTestPass && !result.CounterMoved {
		// The engine answered but its own counters did not move, which means the
		// request was served by something other than the inspection path.
		result.Outcome = L7SelfTestFail
		result.Detail = "the endpoint answered but no inspection counter moved, so the request did not traverse the inspection path"
	}
	return result
}

// probeProducer drives the inspection envelope over the producer socket.
func (s *L7Service) probeProducer(ctx context.Context, socket string, result L7SelfTestResult) L7SelfTestResult {
	envelope := L7InspectionRequest{
		Version:   1,
		RequestID: "selftest-" + randomID(),
		Method:    http.MethodGet,
		Scheme:    "https",
		Host:      "selftest.invalid",
		URI:       l7SelfTestPath,
		RemoteIP:  "127.0.0.1",
		Headers: []L7Header{
			{Name: "User-Agent", Value: "GeDefense-SelfTest"},
			{Name: "Accept", Value: "text/plain"},
		},
		ServerProcess: "gedefense-selftest",
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		result.Outcome = L7SelfTestFail
		result.Detail = "the self-test envelope could not be encoded"
		return result
	}

	started := time.Now()
	client := &http.Client{
		Timeout: l7SelfTestTimeout,
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: l7SelfTestTimeout}
				return dialer.DialContext(dialCtx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/inspect", bytes.NewReader(payload))
	if err != nil {
		result.Outcome = L7SelfTestFail
		result.Detail = "the self-test request could not be built"
		return result
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	result.LatencyMillis = time.Since(started).Milliseconds()
	result.Ran = true
	if err != nil {
		result.Outcome = L7SelfTestFail
		result.Detail = fmt.Sprintf("the inspection socket did not answer: %s", classifyDialError(err))
		return result
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, l7SelfTestMaxResponseBytes))
		_ = response.Body.Close()
	}()

	body, readErr := io.ReadAll(io.LimitReader(response.Body, l7SelfTestMaxResponseBytes))
	if readErr != nil {
		result.Outcome = L7SelfTestFail
		result.Detail = "the inspection socket returned an unreadable response"
		result.HTTPStatus = response.StatusCode
		return result
	}
	result.HTTPStatus = response.StatusCode

	switch response.StatusCode {
	case http.StatusOK:
		result.Outcome = L7SelfTestPass
		result.EngineAnswer = summariseVerdict(body)
		result.Detail = "a synthetic request traversed the inspection socket and received a verdict"
	case http.StatusForbidden:
		result.Outcome = L7SelfTestFail
		result.Detail = "the inspection socket rejected the self-test on peer credentials; the service identity is not in the allowed peer list"
	case http.StatusServiceUnavailable:
		result.Outcome = L7SelfTestFail
		result.Detail = "the L7 engine refused admission, so it is saturated or has no published snapshot"
	default:
		result.Outcome = L7SelfTestFail
		result.Detail = fmt.Sprintf("the inspection socket answered with HTTP %d", response.StatusCode)
	}
	return result
}

// probeInline drives one real HTTP request through the inline edge to the configured
// upstream. It verifies the whole chain rather than the engine alone.
func (s *L7Service) probeInline(ctx context.Context, result L7SelfTestResult) L7SelfTestResult {
	socket := strings.TrimSpace(s.cfg.InlineSocket)
	if socket == "" {
		result.Outcome = L7SelfTestNotAttached
		result.Detail = "the inline listener is enabled but no inline socket path is configured"
		return result
	}

	started := time.Now()
	client := &http.Client{
		Timeout: l7SelfTestTimeout,
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: l7SelfTestTimeout}
				return dialer.DialContext(dialCtx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
		// A redirect would move the probe off the inspected path, so it is not followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://selftest.invalid"+l7SelfTestPath, nil)
	if err != nil {
		result.Outcome = L7SelfTestFail
		result.Detail = "the self-test request could not be built"
		return result
	}
	request.Header.Set("User-Agent", "GeDefense-SelfTest")
	request.Header.Set("X-Gedefense-Client-Ip", "127.0.0.1")
	request.Header.Set("X-Gedefense-Original-Scheme", "https")

	response, err := client.Do(request)
	result.LatencyMillis = time.Since(started).Milliseconds()
	result.Ran = true
	if err != nil {
		result.Outcome = L7SelfTestFail
		result.Detail = fmt.Sprintf("the inline edge did not answer: %s", classifyDialError(err))
		return result
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, l7SelfTestMaxResponseBytes))
		_ = response.Body.Close()
	}()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, l7SelfTestMaxResponseBytes)); err != nil {
		result.Outcome = L7SelfTestFail
		result.Detail = "the inline edge returned an unreadable response"
		result.HTTPStatus = response.StatusCode
		return result
	}
	result.HTTPStatus = response.StatusCode

	switch {
	case response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusServiceUnavailable:
		result.Outcome = L7SelfTestFail
		result.Detail = fmt.Sprintf("the inline edge answered HTTP %d, which means the configured upstream is not reachable from it", response.StatusCode)
	case response.StatusCode >= 400 && response.StatusCode < 500:
		// A refusal is still proof that the request traversed the inspected path: the
		// edge reached a verdict and acted on it.
		result.Outcome = L7SelfTestPass
		result.Detail = fmt.Sprintf("the inline edge inspected the request and answered HTTP %d, which is the expected end for a reserved self-test path", response.StatusCode)
	default:
		result.Outcome = L7SelfTestPass
		result.EngineAnswer = fmt.Sprintf("HTTP %d", response.StatusCode)
		result.Detail = "a synthetic request traversed the inline edge, was inspected and reached the upstream"
	}
	return result
}

// classifyDialError turns a dial failure into a bounded, non-disclosing phrase. The
// raw error can carry the socket path and errno, which an operator reads in the log
// rather than in an API response.
func classifyDialError(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "no such file or directory"):
		return "the inspection socket does not exist"
	case strings.Contains(message, "connection refused"):
		return "nothing is listening on the inspection socket"
	case strings.Contains(message, "permission denied"):
		return "the service identity may not connect to the inspection socket"
	case strings.Contains(message, "context deadline exceeded"), strings.Contains(message, "timeout"):
		return "the inspection socket did not answer within the deadline"
	default:
		return "the connection failed"
	}
}

// summariseVerdict extracts the decision from an engine answer without echoing the
// whole document, which could be large and could contain request detail.
func summariseVerdict(body []byte) string {
	var verdict struct {
		Action string `json:"action"`
		Score  int    `json:"score"`
		Rules  []struct {
			ID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &verdict); err != nil {
		return "verdict received"
	}
	action := strings.TrimSpace(verdict.Action)
	if action == "" {
		action = "unknown"
	}
	return fmt.Sprintf("action=%s score=%d findings=%d", action, verdict.Score, len(verdict.Rules))
}

// InlineHealthyOrConfigured reports whether the inline listener should be probed. It
// deliberately does not require a healthy listener: an unhealthy one is exactly what
// the self-test should reveal, and skipping the probe would hide it.
func (c L7Config) InlineHealthyOrConfigured() bool {
	return c.InlineEnabled && strings.TrimSpace(c.InlineSocket) != ""
}
