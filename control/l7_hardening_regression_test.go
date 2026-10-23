// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// F-06 / CHAIN-002 — peer-attested L7 identity, fail-closed authorization.
// ---------------------------------------------------------------------------

func TestL7PeerAuthorizationIsFailClosed(t *testing.T) {
	makeContext := func(credentials l7PeerCredentials) context.Context {
		return context.WithValue(context.Background(), l7PeerContextKey{}, credentials)
	}
	cfg := L7Config{RequirePeerCredentials: true, AllowedPeerUIDs: []uint32{1000}}

	if l7PeerAuthorizedWithGroup(cfg, context.Background(), 0) {
		t.Fatal("peer without kernel-attested credentials was authorized")
	}
	if !l7PeerAuthorizedWithGroup(cfg, makeContext(l7PeerCredentials{PID: 42, UID: 1000, GID: 1000}), 0) {
		t.Fatal("allowlisted peer UID was rejected")
	}
	if l7PeerAuthorizedWithGroup(cfg, makeContext(l7PeerCredentials{PID: 42, UID: 1001, GID: 1001}), 0) {
		t.Fatal("foreign peer UID was authorized")
	}
	socketGroupCfg := L7Config{}
	if l7PeerAuthorizedWithGroup(socketGroupCfg, makeContext(l7PeerCredentials{PID: 42, UID: 1001, GID: 2000}), 2000) == false {
		t.Fatal("attested socket-group GID was not honored")
	}
	if l7PeerAuthorizedWithGroup(socketGroupCfg, makeContext(l7PeerCredentials{PID: 42, UID: 1001, GID: 2001}), 2000) {
		t.Fatal("peer whose attested GID differs from the socket group was authorized")
	}
	if l7PeerAuthorizedWithGroup(L7Config{}, makeContext(l7PeerCredentials{PID: 42, UID: 0, GID: 0}), 0) {
		t.Fatal("empty identity policy authorized a caller")
	}
}

func TestL7UnixSocketRejectsForeignPeerIdentity(t *testing.T) {
	cfg := l7TestConfig()
	cfg.Socket = filepath.Join(t.TempDir(), "inspect.sock")
	// Only an identity the test process cannot present is authorized.
	cfg.AllowedPeerUIDs = []uint32{uint32(os.Getuid()) + 1}
	cfg.AllowedPeerGIDs = nil
	cfg.SocketGroup = ""
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service, err := NewL7Service(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Shutdown(ctx)
	}()

	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", cfg.Socket)
	}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	envelope, err := json.Marshal(l7Request("/?q=1"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "http://unix/v1/inspect", bytes.NewReader(envelope))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign peer identity status=%d, want 403", response.StatusCode)
	}
}

func TestL7RawInspectSocketIgnoresIdentityHeaders(t *testing.T) {
	normalizer := NewL7Normalizer(l7TestConfig())
	request := l7Request("/demo")
	request.RemoteIP = "198.51.100.77"
	request.Headers = []L7Header{
		{Name: "X-Gedefense-Client-Ip", Value: "10.0.0.99"},
		{Name: "X-Gedefense-Original-Scheme", Value: "http"},
		{Name: "X-Gedefense-Request-Id", Value: "spoofed"},
		{Name: "Accept", Value: "text/plain"},
	}
	normalized, err := normalizer.Normalize(request)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.RemoteIP != "198.51.100.77" {
		t.Fatalf("client identity came from a spoofable header: %q", normalized.RemoteIP)
	}
	for name := range normalized.Headers {
		if l7GatewayMetadataHeader(name) {
			t.Fatalf("raw inspect socket retained identity metadata header %q", name)
		}
	}
	for _, candidate := range normalized.Candidates {
		if strings.Contains(strings.ToLower(candidate.Value), "x-gedefense-client-ip") ||
			strings.Contains(strings.ToLower(candidate.Value), "10.0.0.99") {
			t.Fatalf("spoiled identity header became an inspection candidate: %+v", candidate)
		}
	}
}

// ---------------------------------------------------------------------------
// F-10 / CHAIN-008 — recursive decode to fixpoint, decision on every layer.
// ---------------------------------------------------------------------------

func TestL7RecursiveDecodeDetectsDoubleBase64(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := "1 UNION SELECT password FROM users"
	first := base64.StdEncoding.EncodeToString([]byte(payload))
	second := base64.StdEncoding.EncodeToString([]byte(first))
	response, err := engine.Inspect(context.Background(), l7Request("/search?q="+url.QueryEscape(second)))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.SQLI.UNION_SELECT") {
		t.Fatalf("double-base64 payload escaped the SQLi detector: %#v", response.Findings)
	}
	if !findingByID(response.Findings, "L7.ENCODING.MULTI_LAYER") {
		t.Fatalf("layered encoding was not recorded as a detection signal: %#v", response.Findings)
	}
	if response.Decision == "allow" || response.Enforced {
		t.Fatalf("unexpected decision for layered encoding: %#v", response)
	}
}

func TestL7RecursiveDecodeDetectsSixURLLayers(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded := "1 UNION SELECT password FROM users"
	for layer := 0; layer < 7; layer++ {
		encoded = url.PathEscape(encoded)
	}
	response, err := engine.Inspect(context.Background(), l7Request("/search?q="+encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.SQLI.UNION_SELECT") {
		t.Fatalf("6+ layer URL encoding escaped the SQLi detector: %#v", response.Findings)
	}
}

// ---------------------------------------------------------------------------
// F-11 / CHAIN-010 — active-content uploads are detected through the real L7
// upload detector path (multipart -> Airlock -> finding).
// ---------------------------------------------------------------------------

func attachTestAirlock(t *testing.T, engine *L7Engine) {
	t.Helper()
	inspector, err := NewAirlockInspector(t.TempDir(), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	for index, detector := range engine.detectors {
		if _, ok := detector.(l7UploadDetector); ok {
			engine.detectors[index] = l7UploadDetector{live: engine.live, airlock: inspector}
		}
	}
}

func l7UploadInspection(t *testing.T, filename string, content []byte) L7InspectionRequest {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := l7Request("/upload")
	request.Method = http.MethodPost
	request.Headers = []L7Header{{Name: "Content-Type", Value: writer.FormDataContentType()}}
	request.BodyBase64 = base64.StdEncoding.EncodeToString(body.Bytes())
	return request
}

func TestL7UploadDetectorDetectsActiveContent(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	attachTestAirlock(t, engine)
	cases := []struct {
		name     string
		filename string
		content  []byte
		want     string
	}{
		{"env shebang bash", "shell.php", []byte("#!/usr/bin/env bash\nid\n"), "SCRIPT_SHEBANG_PAYLOAD"},
		{"env shebang python", "drop.phtml", []byte("#!/usr/bin/env python3\nprint(1)\n"), "SCRIPT_SHEBANG_PAYLOAD"},
		{"html event handler", "avatar.html", []byte(`<html><body><img src=x onerror=alert(1)></body></html>`), "HTML_ACTIVE_CONTENT"},
		{"html onload", "page.htm", []byte(`<html><body onload="alert(1)"></body></html>`), "HTML_ACTIVE_CONTENT"},
		{"svg smil", "logo.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="onload" to="alert(1)"/></svg>`), "SVG_ACTIVE_CONTENT"},
		{"svg data uri", "icon.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><use href="data:image/svg+xml;base64,PHN2Zz4="/></svg>`), "SVG_ACTIVE_CONTENT"},
	}
	for _, testCase := range cases {
		response, err := engine.Inspect(context.Background(), l7UploadInspection(t, testCase.filename, testCase.content))
		if err != nil {
			t.Fatalf("%s: inspection failed: %v", testCase.name, err)
		}
		expectedRule := "L7.UPLOAD." + testCase.want
		if !findingByID(response.Findings, expectedRule) {
			t.Fatalf("%s: expected %s, got %#v", testCase.name, expectedRule, response.Findings)
		}
	}

	// A benign image upload must stay clean.
	validPNG := make([]byte, 64)
	copy(validPNG, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	response, err := engine.Inspect(context.Background(), l7UploadInspection(t, "photo.png", validPNG))
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range response.Findings {
		if strings.HasPrefix(finding.RuleID, "L7.UPLOAD.") {
			t.Fatalf("benign PNG produced an upload finding: %#v", finding)
		}
	}
}
