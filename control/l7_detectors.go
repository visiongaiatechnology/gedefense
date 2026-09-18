// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type l7Detector interface {
	Detect(context.Context, l7NormalizedRequest) ([]L7Finding, error)
}

type l7PatternRule struct {
	id         string
	category   string
	summary    string
	severity   string
	score      int
	confidence int
	re         *regexp.Regexp
}

type l7PatternDetector struct {
	rules []l7PatternRule
}

type l7PatternDefinition struct {
	id, category, summary, severity, pattern string
	score, confidence                        int
}

func newL7PatternDetector() (*l7PatternDetector, error) {
	definitions := []l7PatternDefinition{
		{"L7.SQLI.UNION_SELECT", "sqli", "SQL UNION-based injection syntax detected", "high", `(?i)(?:\bunion\s+(?:all\s+)?select\b|\bselect\b.{0,160}\bfrom\b.{0,160}(?:--|#|/\*))`, 90, 92},
		{"L7.SQLI.BOOLEAN_TAUTOLOGY", "sqli", "SQL boolean-tautology injection syntax detected", "high", `(?i)(?:['\"]\s*(?:or|and)\s+(?:['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|\d+\s*=\s*\d+)|\b(?:or|and)\s+1\s*=\s*1\b)`, 75, 82},
		{"L7.SQLI.TIME_DELAY", "sqli", "SQL time-delay primitive detected", "high", `(?i)\b(?:sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay\b)`, 85, 90},
		{"L7.SQLI.STACKED_QUERY", "sqli", "Stacked SQL statement syntax detected", "high", `(?i);\s*(?:select|insert|update|delete|drop|alter|create|exec(?:ute)?)\b`, 85, 88},
		{"L7.XSS.SCRIPT_TAG", "xss", "Executable script element detected", "high", `(?i)<\s*script\b`, 90, 96},
		{"L7.XSS.EVENT_HANDLER", "xss", "Inline browser event handler detected", "high", `(?i)\bon(?:error|load|click|mouseover|focus|animationstart|pointerenter)\s*=`, 80, 88},
		{"L7.XSS.ACTIVE_URI", "xss", "Active browser URI scheme detected", "high", `(?i)(?:javascript|vbscript|data\s*:\s*text/html)\s*:`, 85, 90},
		{"L7.XSS.IFRAME_SRCDOC", "xss", "Executable iframe srcdoc payload detected", "high", `(?is)<\s*iframe\b[^>]{0,512}\bsrcdoc\s*=`, 90, 94},
		{"L7.CMD.SHELL_CHAIN", "command-injection", "Shell command chaining syntax detected", "high", `(?i)(?:;|&&|\|\||\|)\s*(?:/bin/)?(?:ba|da|z|k)?sh\b|(?:;|&&|\|\||\|)\s*(?:curl|wget|nc|ncat|socat|python\d*|perl|php|ruby)\b`, 95, 92},
		{"L7.CMD.SUBSTITUTION", "command-injection", "Shell command substitution syntax detected", "high", `(?i)(?:\$\([^\r\n]{1,512}\)|` + "`" + `[^\r\n]{1,512}` + "`" + `)`, 75, 78},
		{"L7.CMD.WINDOWS_CHAIN", "command-injection", "Windows command-execution chain detected", "high", `(?i)(?:;|&&|\|\||\|)\s*(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?\s*/c|certutil(?:\.exe)?|bitsadmin(?:\.exe)?)\b`, 90, 90},
		{"L7.PATH.TRAVERSAL", "path-traversal", "Filesystem traversal sequence detected", "high", `(?i)(?:^|[\\/])\.\.(?:[\\/]|$)|(?:/etc/(?:passwd|shadow|hosts)|/proc/(?:self|[0-9]+)/(?:environ|cmdline))`, 85, 92},
		{"L7.FILE.STREAM_WRAPPER", "file-inclusion", "Server-side stream-wrapper reference detected", "high", `(?i)\b(?:php|phar|zip|expect|data)://`, 90, 91},
		{"L7.SSTI.TEMPLATE_EXPR", "ssti", "Server-side template expression syntax detected", "high", `(?s)(?:\{\{.{0,512}\}\}|\{%[^%]{0,512}%\}|\$\{[^}]{1,512}\}|#\{[^}]{1,512}\}|<%=.{0,512}%>)`, 75, 78},
		{"L7.XXE.DECLARATION", "xxe", "XML external-entity declaration detected", "critical", `(?i)<!\s*(?:DOCTYPE|ENTITY)\b`, 105, 96},
		{"L7.XXE.EXTERNAL_SYSTEM", "xxe", "XML external SYSTEM/PUBLIC entity detected", "critical", `(?i)\b(?:SYSTEM|PUBLIC)\s+[\"'][^\"']{1,1000}[\"']`, 105, 94},
		{"L7.DESERIALIZE.PHP", "deserialization", "PHP serialized object payload detected", "high", `(?s)(?:^|[^A-Za-z0-9])(?:O|C):[0-9]{1,8}:\"[^\"]{1,512}\"`, 80, 88},
		{"L7.DESERIALIZE.JAVA", "deserialization", "Java serialized-object marker detected", "high", `(?:rO0AB|\xac\xed\x00\x05)`, 80, 86},
		{"L7.SCANNER.PROBE", "scanner", "Common vulnerability-scanner probe detected", "medium", `(?i)(?:/\.git/(?:HEAD|config)|/\.env(?:$|[?&])|/wp-config\.php(?:\.bak)?|/phpinfo\.php|/server-status|/actuator/(?:env|heapdump)|/vendor/phpunit/)`, 55, 86},
		{"L7.CRLF.HEADER_SPLIT", "header-injection", "CRLF response-header injection syntax detected", "high", `(?i)\r?\n(?:set-cookie|location|content-length|transfer-encoding|x-[a-z0-9-]{1,64})\s*:`, 90, 92},
		{"L7.CODE.PHP_TAG", "code-injection", "Server-side PHP execution marker detected", "high", `(?i)<\?(?:php|=)`, 95, 94},
		{"L7.JNDI.LOOKUP", "injection", "JNDI lookup payload detected", "critical", `(?i)\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)\s*:`, 110, 98},
	}
	detector := &l7PatternDetector{rules: make([]l7PatternRule, 0, len(definitions))}
	for _, definition := range definitions {
		re, err := regexp.Compile(definition.pattern)
		if err != nil {
			return nil, fmt.Errorf("compile l7 rule %s: %w", definition.id, err)
		}
		detector.rules = append(detector.rules, l7PatternRule{
			id: definition.id, category: definition.category, summary: definition.summary,
			severity: definition.severity, score: definition.score, confidence: definition.confidence, re: re,
		})
	}
	return detector, nil
}

func (d *l7PatternDetector) Detect(ctx context.Context, req l7NormalizedRequest) ([]L7Finding, error) {
	findings := make([]L7Finding, 0, 8)
	seen := make(map[string]struct{}, len(d.rules))
	for index, candidate := range req.Candidates {
		if index&15 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		for _, rule := range d.rules {
			if _, exists := seen[rule.id]; exists {
				continue
			}
			if !rule.re.MatchString(candidate.Value) {
				continue
			}
			seen[rule.id] = struct{}{}
			findings = append(findings, newL7Finding(rule.id, rule.category, rule.severity, rule.score, rule.confidence, candidate.Location, candidate.Value, rule.summary))
		}
	}
	return findings, nil
}

type l7SSRFDetector struct {
	urlPattern *regexp.Regexp
}

func newL7SSRFDetector() (*l7SSRFDetector, error) {
	re, err := regexp.Compile(`(?i)(?:https?|ftp|file|gopher|dict|ldap|ldaps|smb|jar|netdoc)://[^\s<>"']{1,1000}`)
	if err != nil {
		return nil, fmt.Errorf("compile l7 ssrf url detector: %w", err)
	}
	return &l7SSRFDetector{urlPattern: re}, nil
}

func (d *l7SSRFDetector) Detect(ctx context.Context, req l7NormalizedRequest) ([]L7Finding, error) {
	findings := make([]L7Finding, 0, 2)
	seen := make(map[string]struct{}, 2)
	for index, candidate := range req.Candidates {
		if index&15 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		for _, raw := range d.urlPattern.FindAllString(candidate.Value, 16) {
			parsed, err := url.Parse(raw)
			if err != nil {
				continue
			}
			scheme := strings.ToLower(parsed.Scheme)
			if scheme != "http" && scheme != "https" {
				if _, exists := seen["scheme"]; !exists {
					seen["scheme"] = struct{}{}
					findings = append(findings, newL7Finding("L7.SSRF.DANGEROUS_SCHEME", "ssrf", "high", 80, 90, candidate.Location, raw, "Request parameter references a non-HTTP server-side URL scheme"))
				}
				continue
			}
			host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
			if host == "" {
				continue
			}
			if isSensitiveSSRFHost(host) {
				if _, exists := seen["target"]; !exists {
					seen["target"] = struct{}{}
					findings = append(findings, newL7Finding("L7.SSRF.INTERNAL_TARGET", "ssrf", "high", 85, 92, candidate.Location, raw, "Request parameter references a loopback, link-local, metadata, or private-network HTTP target"))
				}
			}
		}
	}
	return findings, nil
}

func isSensitiveSSRFHost(host string) bool {
	if host == "localhost" || host == "localhost.localdomain" || host == "metadata.google.internal" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if host == "100.100.100.200" || host == "168.63.129.16" || host == "192.0.0.192" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = parseFlexibleIPv4(host)
	}
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified()
}

func parseFlexibleIPv4(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		value, ok := parseIPv4Number(part)
		if !ok {
			return nil
		}
		values[i] = value
	}
	var numeric uint64
	switch len(values) {
	case 1:
		if values[0] > 0xffffffff {
			return nil
		}
		numeric = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return nil
		}
		numeric = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return nil
		}
		numeric = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, value := range values {
			if value > 0xff {
				return nil
			}
		}
		numeric = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}
	return net.IPv4(byte(numeric>>24), byte(numeric>>16), byte(numeric>>8), byte(numeric))
}

func parseIPv4Number(part string) (uint64, bool) {
	if part == "" || len(part) > 10 {
		return 0, false
	}
	base := 10
	digits := part
	if len(part) > 2 && (strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X")) {
		base = 16
		digits = part[2:]
	} else if len(part) > 1 && part[0] == '0' {
		base = 8
		digits = part[1:]
	}
	if digits == "" {
		digits = "0"
	}
	value, err := strconv.ParseUint(digits, base, 32)
	return value, err == nil
}

type l7ProtocolDetector struct{}

func (l7ProtocolDetector) Detect(ctx context.Context, req l7NormalizedRequest) ([]L7Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	findings := make([]L7Finding, 0, 5)
	contentLengths := req.Headers["content-length"]
	if len(contentLengths) > 1 {
		findings = append(findings, newL7Finding("L7.HTTP.DUPLICATE_CONTENT_LENGTH", "protocol-anomaly", "critical", 120, 98, "header.content-length", strings.Join(contentLengths, ","), "Multiple Content-Length headers were supplied"))
	}
	for _, value := range contentLengths {
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil || parsed < 0 {
			findings = append(findings, newL7Finding("L7.HTTP.INVALID_CONTENT_LENGTH", "protocol-anomaly", "critical", 120, 99, "header.content-length", value, "Invalid Content-Length framing was supplied"))
			break
		}
	}
	transferEncodings := req.Headers["transfer-encoding"]
	if len(contentLengths) > 0 && len(transferEncodings) > 0 {
		findings = append(findings, newL7Finding("L7.HTTP.CL_TE_AMBIGUITY", "protocol-anomaly", "critical", 125, 99, "headers", "content-length|transfer-encoding", "Content-Length and Transfer-Encoding are simultaneously present"))
	}
	for _, value := range transferEncodings {
		parts := strings.Split(strings.ToLower(value), ",")
		if len(parts) == 0 || strings.TrimSpace(parts[len(parts)-1]) != "chunked" {
			findings = append(findings, newL7Finding("L7.HTTP.INVALID_TRANSFER_ENCODING", "protocol-anomaly", "high", 90, 95, "header.transfer-encoding", value, "Transfer-Encoding framing did not terminate in chunked"))
			break
		}
	}
	if req.Method == "TRACE" {
		findings = append(findings, newL7Finding("L7.HTTP.TRACE_METHOD", "protocol-anomaly", "medium", 50, 98, "method", req.Method, "HTTP TRACE request observed"))
	}
	return findings, nil
}

type l7UploadDetector struct {
	cfg     L7Config
	airlock *AirlockInspector
}

func (d l7UploadDetector) Detect(ctx context.Context, req l7NormalizedRequest) ([]L7Finding, error) {
	if req.ContentType != "multipart/form-data" || len(req.Body) == 0 {
		return nil, nil
	}
	values := req.Headers["content-type"]
	if len(values) == 0 {
		return nil, nil
	}
	_, params, err := mime.ParseMediaType(values[0])
	if err != nil || params["boundary"] == "" || len(params["boundary"]) > 200 {
		return []L7Finding{newL7Finding("L7.UPLOAD.INVALID_MULTIPART", "file-upload", "high", 80, 92, "body.multipart", req.BodySHA256, "Malformed multipart upload framing detected")}, nil
	}
	reader := multipart.NewReader(bytes.NewReader(req.Body), params["boundary"])
	findings := make([]L7Finding, 0, 2)
	parts := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		part, nextErr := reader.NextPart()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			findings = append(findings, newL7Finding("L7.UPLOAD.INVALID_MULTIPART", "file-upload", "high", 80, 96, "body.multipart", req.BodySHA256, "Malformed multipart upload framing detected"))
			break
		}
		parts++
		if parts > d.cfg.MaxMultipartParts {
			findings = append(findings, newL7Finding("L7.UPLOAD.PART_BUDGET", "file-upload", "high", 75, 99, "body.multipart", req.BodySHA256, "Multipart part budget exceeded"))
			break
		}
		filename := part.FileName()
		if filename == "" {
			_ = part.Close()
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(part, int64(d.cfg.MaxUploadBytes)+1))
		_ = part.Close()
		if readErr != nil {
			continue
		}
		if len(data) > d.cfg.MaxUploadBytes {
			findings = append(findings, newL7Finding("L7.UPLOAD.SIZE_BUDGET", "file-upload", "high", 80, 99, "upload."+safeLocationKey(filename), req.BodySHA256, "Uploaded file exceeds the inline inspection budget"))
			continue
		}
		if d.airlock == nil {
			continue
		}
		result, inspectErr := d.airlock.InspectBytes(filename, data)
		if inspectErr != nil && result != nil {
			findings = append(findings, newL7Finding("L7.UPLOAD."+result.ThreatType, "file-upload", "critical", clampScore(result.RiskScore), 96, "upload."+safeLocationKey(filename), result.SHA256, "Airlock rejected an uploaded object"))
		}
		if len(findings) >= 8 {
			break
		}
	}
	return findings, nil
}

func newL7Finding(id, category, severity string, score, confidence int, location, evidence, summary string) L7Finding {
	digest := sha256.Sum256([]byte(evidence))
	return L7Finding{
		RuleID: id, Category: category, Severity: severity, Score: clampScore(score), Confidence: clampPercent(confidence),
		Location: location, EvidenceSHA256: hex.EncodeToString(digest[:]), Summary: summary,
	}
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 250 {
		return 250
	}
	return score
}

func clampPercent(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func aggregateL7Findings(findings []L7Finding) (int, int, []L7Finding) {
	if len(findings) == 0 {
		return 0, 0, []L7Finding{}
	}
	byRule := make(map[string]L7Finding, len(findings))
	for _, finding := range findings {
		if existing, ok := byRule[finding.RuleID]; !ok || finding.Score > existing.Score {
			byRule[finding.RuleID] = finding
		}
	}
	unique := make([]L7Finding, 0, len(byRule))
	categoryMax := make(map[string]int)
	confidence := 0
	for _, finding := range byRule {
		unique = append(unique, finding)
		if finding.Score > categoryMax[finding.Category] {
			categoryMax[finding.Category] = finding.Score
		}
		if finding.Confidence > confidence {
			confidence = finding.Confidence
		}
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Score == unique[j].Score {
			return unique[i].RuleID < unique[j].RuleID
		}
		return unique[i].Score > unique[j].Score
	})
	categoryScores := make([]int, 0, len(categoryMax))
	for _, score := range categoryMax {
		categoryScores = append(categoryScores, score)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(categoryScores)))
	score := 0
	weights := []int{1, 2, 4, 8}
	for i, value := range categoryScores {
		if i >= len(weights) {
			break
		}
		score += value / weights[i]
	}
	return clampScore(score), confidence, unique
}
