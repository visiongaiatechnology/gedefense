// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
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
	RuleID         string `json:"rule_id"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Score          int    `json:"score"`
	Confidence     int    `json:"confidence"`
	Location       string `json:"location"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	Summary        string `json:"summary"`
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

type L7Status struct {
	Enabled                       bool       `json:"enabled"`
	Mode                          string     `json:"mode"`
	Healthy                       bool       `json:"healthy"`
	Socket                        string     `json:"socket,omitempty"`
	RequestsTotal                 uint64     `json:"requests_total"`
	FindingsTotal                 uint64     `json:"findings_total"`
	BlockedTotal                  uint64     `json:"blocked_total"`
	RateLimitedTotal              uint64     `json:"rate_limited_total"`
	RejectedTotal                 uint64     `json:"rejected_total"`
	ActiveConnections             int32      `json:"active_connections"`
	LastInspection                *time.Time `json:"last_inspection,omitempty"`
	LastError                     string     `json:"last_error,omitempty"`
	InlineEnabled                 bool       `json:"inline_enabled"`
	InlineHealthy                 bool       `json:"inline_healthy"`
	InlineSocket                  string     `json:"inline_socket,omitempty"`
	InlineRequestsTotal           uint64     `json:"inline_requests_total"`
	InlineBlockedTotal            uint64     `json:"inline_blocked_total"`
	InlineUpstreamErrorsTotal     uint64     `json:"inline_upstream_errors_total"`
	InlineLastError               string     `json:"inline_last_error,omitempty"`
	ResponsesInspectedTotal       uint64     `json:"responses_inspected_total"`
	ResponseFindingsTotal         uint64     `json:"response_findings_total"`
	ResponseInspectionErrorsTotal uint64     `json:"response_inspection_errors_total"`
}

type l7Candidate struct {
	Location string
	Value    string
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
