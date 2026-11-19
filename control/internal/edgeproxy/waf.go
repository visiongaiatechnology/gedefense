package edgeproxy

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Verdict is the bounded result of the inline request checks. The reasons are
// stable identifiers: they are written into the incident and the recent-blocked
// ring verbatim, so an operator can correlate a refusal with a rule instead of
// guessing from a generic 400.
type Verdict struct {
	Blocked bool
	Status  int
	Reason  string
}

const (
	maxRequestPathBytes  = 2048
	maxRequestQueryBytes = 4096
	maxRequestHeaders    = 64
	maxHeaderNameBytes   = 128
	maxHeaderValueBytes  = 4096
)

// InspectRequest applies the phase-1 WAF. It is deliberately structural: no
// signature matching, no body inspection, no false-positive-prone regexes. It
// rejects malformed or smuggling-shaped requests, not "suspicious" words.
func InspectRequest(r *http.Request, cfg Config, allowed map[string]bool) Verdict {
	method := strings.ToUpper(r.Method)
	if !allowed[method] {
		return Verdict{Blocked: true, Status: http.StatusMethodNotAllowed, Reason: "method_not_allowed"}
	}
	if r.URL == nil {
		return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "missing_url"}
	}
	if len(r.URL.Path) > maxRequestPathBytes || len(r.URL.RawQuery) > maxRequestQueryBytes {
		return Verdict{Blocked: true, Status: http.StatusRequestURITooLong, Reason: "request_target_too_long"}
	}
	if hasControlBytes(r.URL.Path) || hasControlBytes(r.URL.RawQuery) {
		return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "control_byte_in_target"}
	}
	if cfg.WAFInline {
		decoded, err := url.PathUnescape(r.URL.Path)
		if err != nil || hasControlBytes(decoded) || strings.Contains(decoded, "\\") {
			return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "invalid_percent_encoding"}
		}
		if strings.Contains(decoded, "\\") || hasTraversalSegment(decoded) {
			return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "path_traversal"}
		}
		if strings.Contains(strings.ToLower(r.URL.RawQuery), "%00") {
			return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "nul_in_query"}
		}
	}
	if len(r.Host) == 0 || len(r.Host) > 253 || hasControlBytes(r.Host) || strings.ContainsAny(r.Host, "/\\@") {
		return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "invalid_host"}
	}
	if len(r.Header) > maxRequestHeaders {
		return Verdict{Blocked: true, Status: http.StatusRequestHeaderFieldsTooLarge, Reason: "too_many_headers"}
	}
	headerBytes := 0
	for name, values := range r.Header {
		if len(name) == 0 || len(name) > maxHeaderNameBytes || hasControlBytes(name) {
			return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "invalid_header_name"}
		}
		for _, value := range values {
			if len(value) > maxHeaderValueBytes || hasControlBytes(value) {
				return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "invalid_header_value"}
			}
			headerBytes += len(name) + len(value)
		}
	}
	// http.Server already enforces MaxHeaderBytes at the parse layer; this is a
	// second, explicit ceiling for the forward path and for direct unit tests.
	if headerBytes > cfg.MaxHeaderBytes {
		return Verdict{Blocked: true, Status: http.StatusRequestHeaderFieldsTooLarge, Reason: "header_budget_exceeded"}
	}
	if r.ContentLength > cfg.MaxBodyBytes {
		return Verdict{Blocked: true, Status: http.StatusRequestEntityTooLarge, Reason: "body_too_large"}
	}
	if (method == http.MethodGet || method == http.MethodHead) && r.ContentLength > 0 {
		return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "body_on_safe_method"}
	}
	// Request smuggling shape: a request that carries both framings, or a
	// non-chunked Transfer-Encoding, is ambiguous and is refused rather than
	// forwarded. Go's parser already rejects most of these; the explicit check
	// keeps the edge verdict independent of parser version.
	if r.ProtoMajor == 1 && r.Header.Get("Transfer-Encoding") != "" {
		if r.ContentLength >= 0 || !strings.EqualFold(strings.TrimSpace(r.Header.Get("Transfer-Encoding")), "chunked") {
			return Verdict{Blocked: true, Status: http.StatusBadRequest, Reason: "ambiguous_body_framing"}
		}
	}
	return Verdict{Status: http.StatusOK}
}

func hasControlBytes(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

// hasTraversalSegment reports a real `..` path segment. A substring test would
// also reject legitimate names such as `/v1..2/file`, turning a traversal guard
// into an availability bug.
func hasTraversalSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

// clientPeer returns the network peer address without the ephemeral port. The
// value is used for the rate budget and the incident; X-Forwarded-For is never
// trusted here because this listener is the outermost edge.
func clientPeer(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil || host == "" {
		return remoteAddr
	}
	return host
}
