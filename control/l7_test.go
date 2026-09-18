// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func l7TestConfig() L7Config {
	cfg := defaultConfig().L7
	cfg.Enabled = true
	cfg.Mode = "observe"
	cfg.SocketGroup = ""
	return cfg
}

func l7Request(uri string) L7InspectionRequest {
	return L7InspectionRequest{
		Version: l7ProtocolVersion, RequestID: "0123456789abcdef", Method: "GET", Scheme: "https",
		Host: "example.test", URI: uri, RemoteIP: "198.51.100.10",
	}
}

func findingByID(findings []L7Finding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}

func TestL7DoubleEncodedSQLiIsCanonicalized(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := engine.Inspect(context.Background(), l7Request("/search?q=%2527%2520OR%25201%253D1--"))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.SQLI.BOOLEAN_TAUTOLOGY") {
		t.Fatalf("expected boolean SQLi finding, got %#v", response.Findings)
	}
	if response.Decision != "observe" || response.Enforced {
		t.Fatalf("unexpected observe decision: %#v", response)
	}
}

func TestL7JSONXSSAndSSRFRemainIndependentCategories(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"html":"<script>alert(1)</script>","target":"http://169.254.169.254/latest/meta-data/"}`)
	req := l7Request("/api/render")
	req.Method = "POST"
	req.Headers = []L7Header{{Name: "Content-Type", Value: "application/json"}}
	req.BodyBase64 = base64.StdEncoding.EncodeToString(body)
	response, err := engine.Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.XSS.SCRIPT_TAG") || !findingByID(response.Findings, "L7.SSRF.INTERNAL_TARGET") {
		t.Fatalf("expected XSS and SSRF findings, got %#v", response.Findings)
	}
	if response.Score <= 90 {
		t.Fatalf("independent categories should raise weighted score, got %d", response.Score)
	}
}

func TestL7ProtocolAmbiguityIsHighConfidence(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := l7Request("/upload")
	req.Method = "POST"
	req.Headers = []L7Header{
		{Name: "Content-Length", Value: "12"},
		{Name: "Transfer-Encoding", Value: "chunked"},
	}
	response, err := engine.Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.HTTP.CL_TE_AMBIGUITY") || response.Confidence < 95 {
		t.Fatalf("expected CL/TE ambiguity finding, got %#v", response)
	}
}

func TestL7BlockRequiresReleaseGate(t *testing.T) {
	cfg := l7TestConfig()
	cfg.Mode = "block"
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := l7Request("/?x=%3Cscript%3Ealert(1)%3C/script%3E")
	response, err := engine.Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Decision != "observe" || response.Enforced {
		t.Fatalf("missing release gate must fail safe to observe: %#v", response)
	}
	engine.canBlock = func() bool { return true }
	response, err = engine.Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Decision != "block" || !response.Enforced {
		t.Fatalf("expected enforced block behind explicit gate: %#v", response)
	}
}

func TestL7RateLimiterIsBoundedAndProducesSignal(t *testing.T) {
	cfg := l7TestConfig()
	cfg.ClientRatePerMinute = 1
	cfg.ClientRateBurst = 1
	cfg.SensitiveRatePerMinute = 1
	cfg.SensitiveRateBurst = 1
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inspect(context.Background(), l7Request("/ordinary")); err != nil {
		t.Fatal(err)
	}
	response, err := engine.Inspect(context.Background(), l7Request("/ordinary"))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.RATE_LIMIT.CLIENT") {
		t.Fatalf("expected rate-limit finding, got %#v", response.Findings)
	}
}

func TestL7MultipartUploadUsesAirlockWithoutDiskStaging(t *testing.T) {
	cfg := l7TestConfig()
	airlock, err := NewAirlockInspector(t.TempDir(), int64(cfg.MaxUploadBytes))
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "avatar.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{'A'}, 128)...)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := l7Request("/upload")
	req.Method = "POST"
	req.Headers = []L7Header{{Name: "Content-Type", Value: writer.FormDataContentType()}}
	req.BodyBase64 = base64.StdEncoding.EncodeToString(body.Bytes())
	normalized, err := NewL7Normalizer(cfg).Normalize(req)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := (l7UploadDetector{cfg: cfg, airlock: airlock}).Detect(context.Background(), normalized)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 || !findingByID(findings, "L7.UPLOAD.DISGUISED_EXECUTABLE_PAYLOAD") {
		t.Fatalf("expected Airlock disguised executable finding, got %#v", findings)
	}
}

func TestL7CorrelationNeverCreatesKillEligibleSignal(t *testing.T) {
	store := NewL7CorrelationStore(30*time.Second, 128)
	now := time.Now().UTC()
	store.Observe(now, l7NormalizedRequest{RequestID: "0123456789abcdef", RemoteIP: "203.0.113.9", Host: "example.test", Path: "/upload"}, L7InspectionResponse{
		Score: 180, Findings: []L7Finding{{RuleID: "L7.XSS.SCRIPT_TAG", Category: "xss"}},
	})
	matches := store.Match([]NetConnection{{RemoteIP: "203.0.113.9", RemotePort: 4444}}, now.Add(time.Second))
	if len(matches) != 1 {
		t.Fatalf("expected one correlation match, got %#v", matches)
	}
	if matches[0].KillEligible {
		t.Fatal("L7 correlation must never be kill-eligible by itself")
	}
}

func TestL7NormalizerRejectsExcessiveJSONDepth(t *testing.T) {
	cfg := l7TestConfig()
	cfg.MaxJSONDepth = 4
	req := l7Request("/api")
	req.Method = "POST"
	req.Headers = []L7Header{{Name: "Content-Type", Value: "application/json"}}
	req.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(`[[[[["x"]]]]]`))
	_, err := NewL7Normalizer(cfg).Normalize(req)
	if err == nil || !errors.Is(err, ErrL7ResourceLimit) {
		t.Fatalf("expected resource limit, got %v", err)
	}
}

func TestL7NormalizerFailsClosedWhenCandidateBudgetIsExhausted(t *testing.T) {
	cfg := l7TestConfig()
	cfg.MaxInspectionBytes = 128
	cfg.MaxValueBytes = 128
	req := l7Request("/?a=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&b=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&c=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	_, err := NewL7Normalizer(cfg).Normalize(req)
	if err == nil || !errors.Is(err, ErrL7ResourceLimit) {
		t.Fatalf("expected fail-closed candidate budget error, got %v", err)
	}
}

func TestL7NormalizerRejectsMalformedAuthorityAndRequestID(t *testing.T) {
	cfg := l7TestConfig()
	normalizer := NewL7Normalizer(cfg)
	cases := []L7InspectionRequest{
		func() L7InspectionRequest { r := l7Request("/"); r.Host = "user@example.test"; return r }(),
		func() L7InspectionRequest { r := l7Request("/"); r.Host = "example.test:70000"; return r }(),
		func() L7InspectionRequest { r := l7Request("/"); r.RequestID = "bad id"; return r }(),
	}
	for _, req := range cases {
		if _, err := normalizer.Normalize(req); err == nil || !errors.Is(err, ErrL7InvalidRequest) {
			t.Fatalf("expected invalid request for %#v, got %v", req, err)
		}
	}
}

func TestL7SSRFFlexibleIPv4EncodingsAreCanonicalized(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"http://2130706433/admin",
		"http://0x7f000001/admin",
		"http://0177.0.0.1/admin",
	} {
		req := l7Request("/proxy?url=" + url.QueryEscape(target))
		response, inspectErr := engine.Inspect(context.Background(), req)
		if inspectErr != nil {
			t.Fatalf("inspect %q: %v", target, inspectErr)
		}
		if !findingByID(response.Findings, "L7.SSRF.INTERNAL_TARGET") {
			t.Fatalf("expected SSRF finding for %q, got %#v", target, response.Findings)
		}
	}
}

func TestL7MultipartGenericDetectionIgnoresFileContents(t *testing.T) {
	cfg := l7TestConfig()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	field, err := writer.CreateFormField("caption")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := field.Write([]byte("safe caption")); err != nil {
		t.Fatal(err)
	}
	file, err := writer.CreateFormFile("file", "query.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("' OR 1=1 --")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := l7Request("/upload")
	req.Method = "POST"
	req.Headers = []L7Header{{Name: "Content-Type", Value: writer.FormDataContentType()}}
	req.BodyBase64 = base64.StdEncoding.EncodeToString(body.Bytes())
	normalized, err := NewL7Normalizer(cfg).Normalize(req)
	if err != nil {
		t.Fatal(err)
	}
	patterns, err := newL7PatternDetector()
	if err != nil {
		t.Fatal(err)
	}
	if findings, detectErr := patterns.Detect(context.Background(), normalized); detectErr != nil {
		t.Fatal(detectErr)
	} else if findingByID(findings, "L7.SQLI.BOOLEAN_TAUTOLOGY") {
		t.Fatalf("file bytes must not be treated as generic form-field SQLi: %#v", findings)
	}
}

func TestL7CorrelationStoreRemainsBoundedUnderPeerFlood(t *testing.T) {
	store := NewL7CorrelationStore(time.Minute, 128)
	now := time.Now().UTC()
	for i := 0; i < 1024; i++ {
		remote := "198.51.100." + strconv.Itoa((i%254)+1) + ":" + strconv.Itoa(i)
		store.Observe(now, l7NormalizedRequest{RequestID: "0123456789abcdef", RemoteIP: remote, Host: "example.test", Path: "/"}, L7InspectionResponse{
			Score: 100, Findings: []L7Finding{{RuleID: "L7.TEST", Category: "test"}},
		})
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.byRemote) > store.maxPeers || len(store.slotByRemote) > store.maxPeers {
		t.Fatalf("correlation store escaped bound: remotes=%d slots=%d max=%d", len(store.byRemote), len(store.slotByRemote), store.maxPeers)
	}
}

func TestL7GlobalAdmissionGateIsSharedAndBounded(t *testing.T) {
	cfg := l7TestConfig()
	cfg.MaxConcurrent = 1
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.acquireAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := engine.acquireAdmission(ctx); !errors.Is(err, context.DeadlineExceeded) {
		engine.releaseAdmission()
		t.Fatalf("second admission unexpectedly succeeded or returned wrong error: %v", err)
	}
	engine.releaseAdmission()
	if err := engine.acquireAdmission(context.Background()); err != nil {
		t.Fatalf("admission slot was not released: %v", err)
	}
	engine.releaseAdmission()
}

func TestL7EscapedAndCompatibilityXSSCanonicalization(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"html":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}`,
		`{"html":"＜ｓｃｒｉｐｔ＞alert(1)＜／ｓｃｒｉｐｔ＞"}`,
	} {
		req := l7Request("/render")
		req.Method = http.MethodPost
		req.Headers = []L7Header{{Name: "Content-Type", Value: "application/json"}}
		req.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(body))
		response, inspectErr := engine.Inspect(context.Background(), req)
		if inspectErr != nil {
			t.Fatal(inspectErr)
		}
		if !findingByID(response.Findings, "L7.XSS.SCRIPT_TAG") {
			t.Fatalf("expected canonicalized XSS detection for %q, got %#v", body, response.Findings)
		}
	}
}

func TestL7UnpaddedBase64CandidateIsInspected(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte("<script>alert(1)</script>"))
	response, err := engine.Inspect(context.Background(), l7Request("/?payload="+url.QueryEscape(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.XSS.SCRIPT_TAG") {
		t.Fatalf("expected unpadded base64 XSS detection, got %#v", response.Findings)
	}
}

func TestL7CorrelationIsAlertOnlyForResponseScoring(t *testing.T) {
	decision := combineMatches([]RuleMatch{
		{ID: "L7.CORRELATED_REMOTE", Category: "web-correlation", Score: 55, AlertOnly: true},
		{ID: "XDR.LOW_SIGNAL", Category: "behavior", Score: 30, KillEligible: false},
	})
	if decision.Score != 85 {
		t.Fatalf("expected analytical score 85, got %d", decision.Score)
	}
	if decision.ResponseScore != 30 {
		t.Fatalf("L7 alert-only evidence must not increase response score: got %d", decision.ResponseScore)
	}
	if decision.Decision != "alert" {
		t.Fatalf("alert-only L7 evidence must not promote response decision: %s", decision.Decision)
	}
}

func TestL7LongParameterTailIsInspected(t *testing.T) {
	cfg := l7TestConfig()
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prefix := strings.Repeat("A", cfg.MaxValueBytes+2048)
	body := "q=" + url.QueryEscape(prefix+"' OR 1=1--")
	req := l7Request("/search")
	req.Method = http.MethodPost
	req.Headers = []L7Header{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}}
	req.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(body))
	response, err := engine.Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.SQLI.BOOLEAN_TAUTOLOGY") {
		t.Fatalf("expected SQLi finding beyond first candidate chunk, got %#v", response.Findings)
	}
}

func TestL7QueryCandidateOrderingIsDeterministic(t *testing.T) {
	cfg := l7TestConfig()
	req := l7Request("/?z=3&a=1&m=2")
	var baseline []l7Candidate
	for i := 0; i < 20; i++ {
		normalized, err := NewL7Normalizer(cfg).Normalize(req)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			baseline = append([]l7Candidate(nil), normalized.Candidates...)
			continue
		}
		if !reflect.DeepEqual(baseline, normalized.Candidates) {
			t.Fatalf("candidate ordering changed between runs")
		}
	}
}

func TestL7VendorJSONMediaTypeIsParsedStructurally(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := l7Request("/api")
	req.Method = http.MethodPost
	req.Headers = []L7Header{{Name: "Content-Type", Value: "application/vnd.vgt.event+json; charset=utf-8"}}
	req.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(`{"html":"<script>alert(1)</script>"}`))
	response, err := engine.Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.XSS.SCRIPT_TAG") {
		t.Fatalf("vendor +json body bypassed structured inspection: %#v", response.Findings)
	}
}

func TestL7RepeatedFormEntriesConsumeGlobalFieldBudget(t *testing.T) {
	cfg := l7TestConfig()
	cfg.MaxFormFields = 4
	values := url.Values{}
	values["a"] = []string{"1", "2", "3"}
	values["b"] = []string{"4", "5"}
	req := l7Request("/submit")
	req.Method = http.MethodPost
	req.Headers = []L7Header{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}}
	req.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(values.Encode()))
	_, err := NewL7Normalizer(cfg).Normalize(req)
	if !errors.Is(err, ErrL7ResourceLimit) {
		t.Fatalf("expected repeated values to exhaust form field budget, got %v", err)
	}
}

func TestL7PolicyPathCanonicalizationClosesEncodingAndDotSegmentVariants(t *testing.T) {
	cfg := l7TestConfig()
	for _, uri := range []string{"/%77p-login.php", "/admin/../wp-login.php", "/a/../../wp-login.php"} {
		normalized, err := NewL7Normalizer(cfg).Normalize(l7Request(uri))
		if err != nil {
			t.Fatalf("normalize %q: %v", uri, err)
		}
		if normalized.RatePath != "/wp-login.php" {
			t.Fatalf("canonical rate path mismatch for %q: %q", uri, normalized.RatePath)
		}
	}
}

func TestL7HostCanonicalizationClosesCaseDotAndIPVariants(t *testing.T) {
	cases := map[string]string{
		"EXAMPLE.TEST.":       "example.test",
		"EXAMPLE.TEST.:8443":  "example.test:8443",
		"[0:0:0:0:0:0:0:1]":   "[::1]",
		"[0:0:0:0:0:0:0:1]:9": "[::1]:9",
	}
	for raw, want := range cases {
		got, err := normalizeL7Host(raw)
		if err != nil {
			t.Fatalf("normalize host %q: %v", raw, err)
		}
		if got != want {
			t.Fatalf("normalize host %q = %q, want %q", raw, got, want)
		}
	}
}

func TestL7GeneratedRequestIDsAreOpaqueAndDistinct(t *testing.T) {
	cfg := l7TestConfig()
	req := l7Request("/")
	req.RequestID = ""
	first, err := NewL7Normalizer(cfg).Normalize(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewL7Normalizer(cfg).Normalize(req)
	if err != nil {
		t.Fatal(err)
	}
	if !requestIDPattern.MatchString(first.RequestID) || !requestIDPattern.MatchString(second.RequestID) {
		t.Fatalf("generated request id failed validation: %q %q", first.RequestID, second.RequestID)
	}
	if first.RequestID == second.RequestID {
		t.Fatal("generated request ids unexpectedly collided")
	}
}

func TestL7NormalizerNeverRetainsSensitiveHeaders(t *testing.T) {
	cfg := l7TestConfig()
	req := l7Request("/")
	req.Headers = []L7Header{
		{Name: "Authorization", Value: "Bearer super-secret"},
		{Name: "Cookie", Value: "session=top-secret"},
		{Name: "X-Api-Key", Value: "api-secret"},
		{Name: "User-Agent", Value: "vgt-test-agent"},
	}
	normalized, err := NewL7Normalizer(cfg).Normalize(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"authorization", "cookie", "x-api-key"} {
		if _, exists := normalized.Headers[name]; exists {
			t.Fatalf("sensitive header %q survived normalization", name)
		}
	}
	if got := normalized.Headers["user-agent"]; len(got) != 1 || got[0] != "vgt-test-agent" {
		t.Fatalf("non-sensitive header unexpectedly removed: %#v", got)
	}
}

func TestL7RawEntryBudgetFailsBeforeStructuredParsing(t *testing.T) {
	cfg := l7TestConfig()
	cfg.MaxFormFields = 4
	normalizer := NewL7Normalizer(cfg)

	queryReq := l7Request("/search?a=1&b=2&c=3&d=4&e=5")
	if _, err := normalizer.Normalize(queryReq); !errors.Is(err, ErrL7ResourceLimit) {
		t.Fatalf("expected query preflight budget rejection, got %v", err)
	}

	formReq := l7Request("/submit")
	formReq.Method = http.MethodPost
	formReq.Headers = []L7Header{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}}
	formReq.BodyBase64 = base64.StdEncoding.EncodeToString([]byte("a=1&b=2&c=3&d=4&e=5"))
	if _, err := normalizer.Normalize(formReq); !errors.Is(err, ErrL7ResourceLimit) {
		t.Fatalf("expected form preflight budget rejection, got %v", err)
	}
}
