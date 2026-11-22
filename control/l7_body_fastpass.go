// STATUS: DIAMANT VGT SUPREME
package main

// M4.4: the large-body fast pass.
//
// A 780 KB body used to be cut into 16 KiB text chunks and each chunk was pushed
// through the full recursive decode expansion. Under the inline timeout that
// exceeded RequestTimeoutMillis and surfaced as a 503, i.e. an unscanned body.
//
// The fast pass scans the raw body directly (bounded chunks, no decode
// expansion) with the same read-only pattern rules and a small malware-marker
// scan. When the raw payload already crosses the block threshold the request is
// answered immediately (403, or 429 for a pure rate-limit decision). A benign
// large body simply falls through to the normal, budget-bounded pipeline, so
// nothing is silently skipped and no timeout is manufactured.

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
)

const (
	// l7FastPassMinBodyBytes is the body size above which the raw fast pass runs.
	l7FastPassMinBodyBytes = 64 << 10
	// l7FastPassChunkBytes / l7FastPassOverlap bound one raw scan window.
	l7FastPassChunkBytes = 16 << 10
	l7FastPassOverlap    = 512
	// l7ExpandedChunkBudget bounds how many candidate chunks per request may run
	// the full recursive decode expansion. Everything after that is inspected in
	// its raw/canonical form, which keeps a large request deterministic.
	l7ExpandedChunkBudget = 8
)

// l7MalwareMarkers are well-known AV-test object markers. They are not
// benchmark payloads: the EICAR marker is the industry-standard test signature
// for "the scanner sees file content at all".
var l7MalwareMarkers = [][]byte{
	[]byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"),
}

// l7LargeBodyFastPath answers a clearly malicious large raw body without the
// recursive decode pipeline. It returns handled=false when it cannot prove a
// block (the caller then runs the normal bounded inspection).
func (e *L7Engine) l7LargeBodyFastPath(req L7InspectionRequest, body []byte, snapshot *l7RuntimeSnapshot) (L7InspectionResponse, bool) {
	if len(body) < l7FastPassMinBodyBytes || snapshot == nil {
		return L7InspectionResponse{}, false
	}
	if !e.releaseGateAllowsBlock() || snapshot.cfg.Mode != "block" {
		return L7InspectionResponse{}, false
	}
	// The fast path still only applies a decision it can name: request identity
	// must be structurally valid, otherwise the normal validator owns the error.
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if !isHTTPToken(method, 32) {
		return L7InspectionResponse{}, false
	}
	host, err := normalizeL7Host(req.Host)
	if err != nil {
		return L7InspectionResponse{}, false
	}
	uri := strings.TrimSpace(req.URI)
	if uri == "" || len(uri) > snapshot.cfg.MaxURIBytes || !strings.HasPrefix(uri, "/") {
		return L7InspectionResponse{}, false
	}
	parsed, err := url.ParseRequestURI(uri)
	if err != nil || parsed.IsAbs() {
		return L7InspectionResponse{}, false
	}
	remoteIP := net.ParseIP(strings.TrimSpace(req.RemoteIP))
	if remoteIP == nil {
		return L7InspectionResponse{}, false
	}

	findings := l7RawBodyFindings(body)
	if len(findings) == 0 {
		return L7InspectionResponse{}, false
	}
	_, blockable := snapshot.applyRuleOverrides(findings)
	blockableScoped := make([]L7Finding, 0, len(blockable))
	for _, finding := range blockable {
		if snapshot.blockEligible(finding.RuleID) {
			blockableScoped = append(blockableScoped, finding)
		}
	}
	blockScore, confidence, unique := aggregateL7Findings(blockableScoped)
	if len(unique) == 0 || blockScore < snapshot.cfg.BlockScore {
		// Below the block threshold: the normal pipeline owns scoring/metrics.
		return L7InspectionResponse{}, false
	}

	requestID, idOK := validL7RequestID(req.RequestID)
	if !idOK {
		requestID, err = newL7RequestID()
		if err != nil {
			return L7InspectionResponse{}, false
		}
	}
	digest := sha256.Sum256(body)
	response := L7InspectionResponse{
		RequestID: requestID, Decision: "block", Enforced: true,
		Score: blockScore, Confidence: confidence, Reason: "request blocked by L7 large-body fast pass",
		BodySHA256: hex.EncodeToString(digest[:]), Findings: unique,
	}
	if l7OnlyRateLimitFindings(blockableScoped) {
		response.RateLimit = true
		response.Reason = "request rate limit exceeded"
		response.RetryAfterSeconds = l7RateLimitRetryAfterSeconds
	}
	// Evidence: the normalised projection is deliberately minimal (body digest and
	// request identity only) because the body decision was made on raw bytes.
	normalized := l7NormalizedRequest{
		RequestID: requestID, Method: method, Scheme: "https", Host: host,
		Path: parsed.EscapedPath(), RemoteIP: remoteIP.String(), BodySHA256: response.BodySHA256,
		ServerPID: req.ServerPID, ServerProcess: safeProcessName(req.ServerProcess),
	}
	if e.xdr != nil {
		e.xdr.RecordL7Inspection(normalized, response)
	}
	return response, true
}

// l7FastPassMarkers are generic attack-class literals. They are only a prefilter:
// if none is present, no direct (non-encoded) payload of the covered classes can
// be present either, so the raw pass can return immediately. When a marker is
// present the regex rules run only on a small window around it, which keeps the
// pass cheap even for a 2 MiB body.
var l7FastPassMarkers = []string{
	"<?php", "<?=", "<script", "onerror=", "onload=", "onfocus=", "javascript:",
	"union select", "/**/", " or 1=1", " or '1'='1", "information_schema", "group_concat(",
	"sleep(", "benchmark(", "pg_sleep(", "waitfor delay", "etc/passwd", "/proc/self/",
	"../", "..\\", ";cat ", "|sh", "&&", "$(", "`", "jndi:", "<!doctype", "<!entity",
	"php://", "phar://", "data:text/html", "os.system(", "cmd.exe", "powershell",
	"eicar-standard",
}

// l7RawBodyFindings scans a large body in bounded raw windows. It deliberately
// performs no decode expansion: the fast pass exists to catch direct payloads
// quickly, not to replace the normal pipeline.
func l7RawBodyFindings(body []byte) []L7Finding {
	lower := strings.ToLower(string(body))
	windows := make([][2]int, 0, 16)
	for _, marker := range l7FastPassMarkers {
		start := 0
		for len(windows) < 16 {
			index := strings.Index(lower[start:], marker)
			if index < 0 {
				break
			}
			index += start
			begin := index - l7FastPassOverlap
			if begin < 0 {
				begin = 0
			}
			end := index + len(marker) + l7FastPassOverlap
			if end > len(body) {
				end = len(body)
			}
			windows = append(windows, [2]int{begin, end})
			start = index + len(marker)
		}
	}
	if len(windows) == 0 {
		return nil
	}
	detector, err := newL7PatternDetector()
	if err != nil {
		return nil
	}
	findings := make([]L7Finding, 0, 8)
	seen := make(map[string]struct{}, 8)
	for _, window := range windows {
		chunk := strings.ToValidUTF8(string(body[window[0]:window[1]]), " ")
		for _, rule := range detector.rules {
			if _, exists := seen[rule.id]; exists {
				continue
			}
			if !l7SQLRuleGuarded(rule.category, chunk) {
				continue
			}
			if !rule.re.MatchString(chunk) {
				continue
			}
			seen[rule.id] = struct{}{}
			findings = append(findings, newL7Finding(rule.id, rule.category, rule.severity, rule.score, rule.confidence, "body.fastpass", chunk, rule.summary))
		}
		if len(findings) >= 8 {
			break
		}
	}
	for _, marker := range l7MalwareMarkers {
		if !strings.Contains(string(body), string(marker)) {
			continue
		}
		if _, exists := seen["L7.MALWARE.EICAR"]; !exists {
			seen["L7.MALWARE.EICAR"] = struct{}{}
			findings = append(findings, newL7Finding("L7.MALWARE.EICAR", "malware", "critical", 110, 99, "body.fastpass", "malware-marker", "Well-known antivirus test/malware marker detected in the request body"))
		}
	}
	return findings
}

// validL7RequestID accepts an upstream-supplied request id only in the documented
// shape; otherwise a fresh one is generated.
func validL7RequestID(raw string) (string, bool) {
	text := strings.TrimSpace(raw)
	if text == "" || !requestIDPattern.MatchString(text) {
		return "", false
	}
	return text, true
}

// l7BodyMarkerFindings scans an already-decoded body for well-known malware
// markers. It is linear and independent of the content type.
func l7BodyMarkerFindings(body []byte) []L7Finding {
	findings := make([]L7Finding, 0, len(l7MalwareMarkers))
	for _, marker := range l7MalwareMarkers {
		if !strings.Contains(string(body), string(marker)) {
			continue
		}
		findings = append(findings, newL7Finding("L7.MALWARE.EICAR", "malware", "critical", 110, 99,
			"body", "malware-marker", "Well-known antivirus test/malware marker detected in the request body"))
	}
	return findings
}

// l7OnlyRateLimitFindings reports whether every block-authorising finding is a
// rate-limit finding. Only then is the response a 429; any security finding keeps
// the response a deterministic 403.
func l7OnlyRateLimitFindings(findings []L7Finding) bool {
	if len(findings) == 0 {
		return false
	}
	for _, finding := range findings {
		if finding.Category != "rate-limit" {
			return false
		}
	}
	return true
}
