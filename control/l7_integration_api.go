// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Self-test and integration endpoints.
//
// Both are read-only with respect to the host: the self-test sends one synthetic
// request over a local socket and the integration endpoint generates text. Neither
// writes a configuration file, reloads a service or changes L7 state.
//
// The self-test is rate limited on purpose. It consumes engine admission and moves the
// very counters an operator reads, so an unbounded caller could both saturate the
// inspection path and make the telemetry meaningless.
//
// Failures use apiFault rather than apiError: the operator-facing detail lives in the
// response body for the self-test (as structured data) and in the generated plan for
// the integration endpoint, so the HTTP error itself only needs to be opaque.

const (
	// l7SelfTestPerMinute bounds how often the probe may run.
	l7SelfTestPerMinute = 6
	// l7SelfTestBurst is the bucket size for the probe limiter.
	l7SelfTestBurst = 2
	// l7IntegrationRequestMaxBytes bounds the optional request body.
	l7IntegrationRequestMaxBytes = 8 << 10
)

var (
	l7SelfTestLimiterOnce sync.Once
	l7SelfTestLimiter     *RateLimiter
)

func (s *APIServer) l7SelfTestLimiter() *RateLimiter {
	l7SelfTestLimiterOnce.Do(func() {
		l7SelfTestLimiter = NewRateLimiter(l7SelfTestPerMinute, l7SelfTestBurst)
	})
	return l7SelfTestLimiter
}

// l7SelfTest runs the probe. It is a POST because it has an effect on the counters,
// even though it changes nothing else.
func (s *APIServer) l7SelfTest(w http.ResponseWriter, r *http.Request) {
	if s.l7Service == nil {
		apiFault(w, http.StatusServiceUnavailable, errors.New("l7 service is not attached"))
		return
	}
	if !s.l7SelfTestLimiter().Allow(remoteIdentity(r.RemoteAddr), time.Now()) {
		w.Header().Set("Retry-After", "10")
		apiFault(w, http.StatusTooManyRequests, errors.New("l7 self-test rate limit reached"))
		return
	}
	result := s.l7Service.RunSelfTest(r.Context())
	// Every outcome is a 200: the result document carries the verdict, including
	// NOT_ATTACHED, which is a finding rather than a transport failure.
	writeJSON(w, http.StatusOK, result)
}

// l7Integration generates the host integration plan.
func (s *APIServer) l7Integration(w http.ResponseWriter, r *http.Request) {
	if s.l7Service == nil {
		apiFault(w, http.StatusServiceUnavailable, errors.New("l7 service is not attached"))
		return
	}
	request := IntegrationRequest{}
	if r.Body != nil && r.ContentLength != 0 {
		body, err := readBoundedRequestBody(r, l7IntegrationRequestMaxBytes)
		if err != nil {
			apiFault(w, http.StatusBadRequest, err)
			return
		}
		if len(bytes.TrimSpace(body)) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				apiFault(w, http.StatusBadRequest, err)
				return
			}
		}
	}
	plan := s.l7Service.BuildIntegrationPlan(request)
	writeJSON(w, http.StatusOK, plan)
}
