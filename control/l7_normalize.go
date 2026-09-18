// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net"
	"net/url"
	"strings"
)

type L7Normalizer struct {
	cfg L7Config
}

func NewL7Normalizer(cfg L7Config) *L7Normalizer {
	return &L7Normalizer{cfg: cfg}
}

func (n *L7Normalizer) Normalize(req L7InspectionRequest) (l7NormalizedRequest, error) {
	body, err := n.decodeBody(req.BodyBase64)
	if err != nil {
		return l7NormalizedRequest{}, err
	}
	return n.NormalizeRaw(req, body)
}

func (n *L7Normalizer) NormalizeRaw(req L7InspectionRequest, body []byte) (l7NormalizedRequest, error) {
	if req.Version != l7ProtocolVersion {
		return l7NormalizedRequest{}, fmt.Errorf("%w: unsupported protocol version", ErrL7InvalidRequest)
	}
	if len(body) > n.cfg.MaxBodyBytes {
		return l7NormalizedRequest{}, fmt.Errorf("%w: body exceeds budget", ErrL7ResourceLimit)
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if !isHTTPToken(method, 32) {
		return l7NormalizedRequest{}, fmt.Errorf("%w: invalid method", ErrL7InvalidRequest)
	}
	scheme := strings.ToLower(strings.TrimSpace(req.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return l7NormalizedRequest{}, fmt.Errorf("%w: invalid scheme", ErrL7InvalidRequest)
	}
	host, err := normalizeL7Host(req.Host)
	if err != nil {
		return l7NormalizedRequest{}, err
	}
	uri := strings.TrimSpace(req.URI)
	if uri == "" || len(uri) > n.cfg.MaxURIBytes || strings.ContainsRune(uri, '\x00') {
		return l7NormalizedRequest{}, fmt.Errorf("%w: invalid uri", ErrL7InvalidRequest)
	}
	if uri != "*" && !strings.HasPrefix(uri, "/") {
		return l7NormalizedRequest{}, fmt.Errorf("%w: request uri must use origin-form", ErrL7InvalidRequest)
	}
	if uri == "*" && method != "OPTIONS" {
		return l7NormalizedRequest{}, fmt.Errorf("%w: asterisk-form is only valid for OPTIONS", ErrL7InvalidRequest)
	}
	parsedURI, err := url.ParseRequestURI(uri)
	if err != nil || parsedURI.IsAbs() {
		return l7NormalizedRequest{}, fmt.Errorf("%w: malformed request uri", ErrL7InvalidRequest)
	}
	remoteIP := net.ParseIP(strings.TrimSpace(req.RemoteIP))
	if remoteIP == nil || remoteIP.IsUnspecified() {
		return l7NormalizedRequest{}, fmt.Errorf("%w: invalid remote ip", ErrL7InvalidRequest)
	}
	if req.ServerPID < 0 || req.ServerPID > 1<<30 {
		return l7NormalizedRequest{}, fmt.Errorf("%w: invalid server pid", ErrL7InvalidRequest)
	}
	requestID := strings.TrimSpace(req.RequestID)
	if requestID == "" {
		requestID, err = newL7RequestID()
		if err != nil {
			return l7NormalizedRequest{}, err
		}
	} else if !requestIDPattern.MatchString(requestID) {
		return l7NormalizedRequest{}, fmt.Errorf("%w: invalid request id", ErrL7InvalidRequest)
	}

	headers, contentType, err := n.normalizeHeaders(req.Headers)
	if err != nil {
		return l7NormalizedRequest{}, err
	}
	body, err = n.decodeContentEncoding(body, headers["content-encoding"])
	if err != nil {
		return l7NormalizedRequest{}, err
	}
	bodyDigest := ""
	if len(body) > 0 {
		digest := sha256.Sum256(body)
		bodyDigest = hex.EncodeToString(digest[:])
	}

	rawPath := parsedURI.EscapedPath()
	if uri == "*" {
		rawPath = "*"
	}
	normalized := l7NormalizedRequest{
		RequestID: requestID, Method: method, Scheme: scheme, Host: host,
		Path: rawPath, RatePath: canonicalL7RoutePath(parsedURI.Path, uri == "*"), RemoteIP: remoteIP.String(), Headers: headers,
		Body: body, BodySHA256: bodyDigest, ContentType: contentType,
		Candidates: make([]l7Candidate, 0, minInt(n.cfg.MaxDecodedValues, 128)),
		ServerPID:  req.ServerPID, ServerProcess: safeProcessName(req.ServerProcess),
	}
	n.addCandidate(&normalized, "uri.path", rawPath)
	if normalized.RatePath != rawPath {
		n.addCandidate(&normalized, "uri.path.canonical", normalized.RatePath)
	}
	if parsedURI.RawQuery != "" {
		n.addCandidate(&normalized, "uri.query.raw", parsedURI.RawQuery)
		if err := n.addQueryCandidates(&normalized, parsedURI.RawQuery); err != nil {
			return l7NormalizedRequest{}, err
		}
	}
	for _, headerName := range []string{"user-agent", "referer", "x-forwarded-host", "x-original-uri"} {
		for _, value := range headers[headerName] {
			n.addCandidate(&normalized, "header."+headerName, value)
		}
	}
	if len(body) > 0 {
		if err := n.addBodyCandidates(&normalized); err != nil {
			return l7NormalizedRequest{}, err
		}
	}
	if normalized.CandidateBudgetExceeded {
		return l7NormalizedRequest{}, fmt.Errorf("%w: inspection candidate budget exhausted", ErrL7ResourceLimit)
	}
	return normalized, nil
}

func newL7RequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate l7 request id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func (n *L7Normalizer) normalizeHeaders(in []L7Header) (map[string][]string, string, error) {
	if len(in) > n.cfg.MaxHeaders {
		return nil, "", fmt.Errorf("%w: too many headers", ErrL7ResourceLimit)
	}
	headers := make(map[string][]string, len(in))
	totalBytes := 0
	for _, h := range in {
		name := strings.ToLower(strings.TrimSpace(h.Name))
		if !isHTTPToken(name, 128) {
			return nil, "", fmt.Errorf("%w: invalid header name", ErrL7InvalidRequest)
		}
		if strings.ContainsAny(h.Value, "\r\n\x00") {
			return nil, "", fmt.Errorf("%w: invalid header value", ErrL7InvalidRequest)
		}
		totalBytes += len(name) + len(h.Value)
		if totalBytes > n.cfg.MaxHeaderBytes {
			return nil, "", fmt.Errorf("%w: header budget exceeded", ErrL7ResourceLimit)
		}
		if l7SensitiveHeader(name) {
			continue
		}
		headers[name] = append(headers[name], h.Value)
		if len(headers[name]) > 16 {
			return nil, "", fmt.Errorf("%w: duplicate header budget exceeded", ErrL7ResourceLimit)
		}
	}
	contentType := ""
	if values := headers["content-type"]; len(values) > 0 {
		if len(values) != 1 {
			return nil, "", fmt.Errorf("%w: duplicate content-type header", ErrL7InvalidRequest)
		}
		contentType = values[0]
		if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
			contentType = strings.ToLower(parsed)
		} else {
			return nil, "", fmt.Errorf("%w: malformed content type", ErrL7InvalidRequest)
		}
	}
	return headers, contentType, nil
}

func (n *L7Normalizer) decodeBody(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	maxEncoded := base64.StdEncoding.EncodedLen(n.cfg.MaxBodyBytes) + 8
	if len(encoded) > maxEncoded {
		return nil, fmt.Errorf("%w: encoded body exceeds budget", ErrL7ResourceLimit)
	}
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))
	limited := io.LimitReader(decoder, int64(n.cfg.MaxBodyBytes)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 body", ErrL7InvalidRequest)
	}
	if len(body) > n.cfg.MaxBodyBytes {
		return nil, fmt.Errorf("%w: body exceeds budget", ErrL7ResourceLimit)
	}
	return body, nil
}

func (n *L7Normalizer) decodeContentEncoding(body []byte, values []string) ([]byte, error) {
	if len(body) == 0 || len(values) == 0 {
		return body, nil
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("%w: multiple content-encoding headers", ErrL7InvalidRequest)
	}
	encoding := strings.ToLower(strings.TrimSpace(values[0]))
	if encoding == "" || encoding == "identity" {
		return body, nil
	}
	if strings.Contains(encoding, ",") {
		return nil, fmt.Errorf("%w: stacked content encoding", ErrL7UnsupportedEncoding)
	}
	var reader io.ReadCloser
	var err error
	switch encoding {
	case "gzip", "x-gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(body))
	default:
		return nil, fmt.Errorf("%w: %s", ErrL7UnsupportedEncoding, encoding)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: invalid compressed request body", ErrL7InvalidRequest)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(n.cfg.MaxBodyBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: compressed request decode failed", ErrL7InvalidRequest)
	}
	if len(decoded) > n.cfg.MaxBodyBytes {
		return nil, fmt.Errorf("%w: decoded request body exceeds budget", ErrL7ResourceLimit)
	}
	return decoded, nil
}
