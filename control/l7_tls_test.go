package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helper to construct a synthetic TLS ClientHello with custom SNI, Ciphers, and Extensions
func buildSyntheticClientHello(sni string, ciphers []uint16, extensions []uint16, grease bool) []byte {
	var payload []byte
	// 1. TLS Record Header: Type 22 (Handshake), Version 0x0303 (TLS 1.2), Length placeholder
	payload = append(payload, 22, 0x03, 0x03, 0x00, 0x00)

	// 2. Handshake Header: Type 1 (ClientHello), Length placeholder (3 bytes)
	hsStart := len(payload)
	payload = append(payload, 0x01, 0x00, 0x00, 0x00)

	// 3. Client Version: 0x0303
	payload = append(payload, 0x03, 0x03)

	// 4. Random: 32 bytes
	payload = append(payload, make([]byte, 32)...)

	// 5. Session ID: 0 length
	payload = append(payload, 0x00)

	// 6. Cipher Suites
	var cList []uint16
	if grease {
		cList = append(cList, 0x0a0a)
	}
	cList = append(cList, ciphers...)
	cBytes := make([]byte, 2+len(cList)*2)
	binary.BigEndian.PutUint16(cBytes[0:2], uint16(len(cList)*2))
	for i, c := range cList {
		binary.BigEndian.PutUint16(cBytes[2+i*2:4+i*2], c)
	}
	payload = append(payload, cBytes...)

	// 7. Compression: 1 byte length (1), 0 (null)
	payload = append(payload, 0x01, 0x00)

	// 8. Extensions
	var extPayload []byte
	// Add SNI if specified
	if sni != "" {
		sniBytes := []byte(sni)
		sData := make([]byte, 5+len(sniBytes))
		binary.BigEndian.PutUint16(sData[0:2], uint16(3+len(sniBytes))) // ServerNameList length
		sData[2] = 0x00                                                 // host_name type
		binary.BigEndian.PutUint16(sData[3:5], uint16(len(sniBytes)))
		copy(sData[5:], sniBytes)

		extEntry := make([]byte, 4+len(sData))
		binary.BigEndian.PutUint16(extEntry[0:2], 0) // SNI extension type 0
		binary.BigEndian.PutUint16(extEntry[2:4], uint16(len(sData)))
		copy(extEntry[4:], sData)
		extPayload = append(extPayload, extEntry...)
	}

	// Add other extensions
	for _, ext := range extensions {
		extEntry := make([]byte, 4)
		binary.BigEndian.PutUint16(extEntry[0:2], ext)
		binary.BigEndian.PutUint16(extEntry[2:4], 0) // 0 length for test
		extPayload = append(extPayload, extEntry...)
	}

	extHeader := make([]byte, 2)
	binary.BigEndian.PutUint16(extHeader, uint16(len(extPayload)))
	payload = append(payload, extHeader...)
	payload = append(payload, extPayload...)

	// Patch lengths
	totalLen := len(payload) - 5
	binary.BigEndian.PutUint16(payload[3:5], uint16(totalLen))

	hsLen := len(payload) - (hsStart + 4)
	payload[hsStart+1] = byte(hsLen >> 16)
	payload[hsStart+2] = byte(hsLen >> 8)
	payload[hsStart+3] = byte(hsLen)

	return payload
}

func TestL7TLSInvalidSNITrigger(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 10, true)
	// Direct IP literal in SNI
	pkt := buildSyntheticClientHello("198.51.100.22", []uint16{0x002f}, nil, false)

	findings := eng.InspectHandshake("203.0.113.1", pkt, time.Now().UTC())
	found := false
	for _, f := range findings {
		if f.RuleID == "TLS.SNI.INVALID" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected TLS.SNI.INVALID finding for direct IP in SNI, got: %+v", findings)
	}
}

func TestL7TLSForeignSNITrigger(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"authorized-domain.com"}, 15, 10, true)
	// Unauthorized foreign domain in SNI
	pkt := buildSyntheticClientHello("attacker-controlled.net", []uint16{0x002f}, nil, false)

	findings := eng.InspectHandshake("203.0.113.2", pkt, time.Now().UTC())
	found := false
	for _, f := range findings {
		if f.RuleID == "TLS.SNI.FOREIGN" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected TLS.SNI.FOREIGN finding for unauthorized domain, got: %+v", findings)
	}
}

func TestL7TLSHandshakeFloodDetection(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 10, true)
	pkt := buildSyntheticClientHello("example.com", []uint16{0x002f}, nil, false)
	now := time.Now().UTC()

	var floodFinding bool
	// Send 16 handshakes without any HTTP requests
	for i := 0; i < 16; i++ {
		findings := eng.InspectHandshake("203.0.113.5", pkt, now)
		for _, f := range findings {
			if f.RuleID == "TLS.HANDSHAKE.FLOOD" {
				floodFinding = true
				break
			}
		}
	}

	if !floodFinding {
		t.Fatalf("expected TLS.HANDSHAKE.FLOOD after 16 handshakes without HTTP requests")
	}

	// Now record an HTTP request and reset window, should not flood immediately
	eng.RecordHTTPRequest("203.0.113.5")
	resetTime := now.Add(12 * time.Second)
	findingsAfterReset := eng.InspectHandshake("203.0.113.5", pkt, resetTime)
	for _, f := range findingsAfterReset {
		if f.RuleID == "TLS.HANDSHAKE.FLOOD" {
			t.Fatalf("unexpected TLS.HANDSHAKE.FLOOD immediately after window reset")
		}
	}
}

func TestL7CoverageEvaluation(t *testing.T) {
	// 1. Disabled
	s1 := L7Status{Enabled: false}
	if res := EvaluateL7Coverage(s1, 100); res != "DISABLED" {
		t.Fatalf("expected DISABLED, got %s", res)
	}

	// 2. Offline
	s2 := L7Status{Enabled: true, Healthy: false}
	if res := EvaluateL7Coverage(s2, 100); res != "OFFLINE" {
		t.Fatalf("expected OFFLINE, got %s", res)
	}

	// 3. Healthy, nothing attached, no traffic after 500s uptime. This is the case
	// that used to report NO_TRAFFIC_WARNING and thereby degraded an intentionally
	// idle engine. No inline listener and not one request ever means the engine is
	// available but not in the traffic path - a different fact from a silent path.
	s3 := L7Status{Enabled: true, Healthy: true, RequestsTotal: 0}
	if res := EvaluateL7Coverage(s3, 500); res != "READY_NOT_ATTACHED" {
		t.Fatalf("expected READY_NOT_ATTACHED, got %s", res)
	}

	// 3b. The same engine with the inline path attached and silent IS a fault.
	s3b := L7Status{Enabled: true, Healthy: true, InlineEnabled: true, InlineHealthy: true}
	if res := EvaluateL7Coverage(s3b, 500); res != "NO_TRAFFIC_WARNING" {
		t.Fatalf("expected NO_TRAFFIC_WARNING for an attached but silent path, got %s", res)
	}

	// 4. Traffic active
	s4 := L7Status{Enabled: true, Healthy: true, RequestsTotal: 42}
	if res := EvaluateL7Coverage(s4, 500); res != "TRAFFIC_ACTIVE" {
		t.Fatalf("expected TRAFFIC_ACTIVE, got %s", res)
	}
}

func TestParseClientHelloRejectsFieldsPastHandshakeBoundary(t *testing.T) {
	pkt := buildSyntheticClientHello("example.com", []uint16{0x002f}, nil, false)
	// Claim that the ClientHello ends immediately after the session-id length
	// byte while leaving the rest of the TLS record present. A parser must never
	// borrow those trailing record bytes to complete a shorter handshake.
	handshakeLen := 35
	pkt[6] = byte(handshakeLen >> 16)
	pkt[7] = byte(handshakeLen >> 8)
	pkt[8] = byte(handshakeLen)
	if _, err := ParseClientHello(pkt); err == nil {
		t.Fatal("expected ClientHello parser to reject fields beyond handshake boundary")
	}
}

func TestParseClientHelloRejectsMalformedALPN(t *testing.T) {
	pkt := buildSyntheticClientHello("example.com", []uint16{0x002f}, []uint16{16}, false)
	if _, err := ParseClientHello(pkt); err == nil {
		t.Fatal("expected empty ALPN extension to be rejected")
	}
}

func TestTLSRepeatedInvalidSNIStrike(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 3, true)
	pkt := buildSyntheticClientHello("198.51.100.22", []uint16{0x002f}, nil, false)
	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		findings := eng.InspectHandshake("203.0.113.20", pkt, now.Add(time.Duration(i)*time.Second))
		for _, finding := range findings {
			if finding.RuleID == "TLS.SNI.REPEATED_INVALID" {
				t.Fatalf("strike fired before configured threshold on attempt %d", i+1)
			}
		}
	}
	findings := eng.InspectHandshake("203.0.113.20", pkt, now.Add(2*time.Second))
	found := false
	for _, finding := range findings {
		if finding.RuleID == "TLS.SNI.REPEATED_INVALID" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected repeated invalid SNI strike at configured threshold")
	}
}

func TestTLSRepeatedInvalidSNIWindowExpires(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 3, true)
	pkt := buildSyntheticClientHello("198.51.100.22", []uint16{0x002f}, nil, false)
	now := time.Now().UTC()
	eng.InspectHandshake("203.0.113.21", pkt, now)
	eng.InspectHandshake("203.0.113.21", pkt, now.Add(time.Second))
	findings := eng.InspectHandshake("203.0.113.21", pkt, now.Add(tlsSNIStrikeWindow+time.Second))
	for _, finding := range findings {
		if finding.RuleID == "TLS.SNI.REPEATED_INVALID" {
			t.Fatal("expired SNI violations leaked into the next strike window")
		}
	}
}

func TestTLSBehaviorTrackerEvictsInConstantRingOrder(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 10, true, 2)
	pkt := buildSyntheticClientHello("example.com", []uint16{0x002f}, nil, false)
	now := time.Now().UTC()
	eng.InspectHandshake("203.0.113.31", pkt, now)
	eng.InspectHandshake("203.0.113.32", pkt, now.Add(time.Second))
	eng.InspectHandshake("203.0.113.33", pkt, now.Add(2*time.Second))

	eng.mu.RLock()
	defer eng.mu.RUnlock()
	if len(eng.behavior) != 2 {
		t.Fatalf("expected bounded tracker size 2, got %d", len(eng.behavior))
	}
	if _, exists := eng.behavior["203.0.113.31"]; exists {
		t.Fatal("expected first ring slot to be evicted when bounded tracker is full")
	}
}

func TestTLSJA3FindingUsesFingerprintFieldsNotEvidenceDigest(t *testing.T) {
	pkt := buildSyntheticClientHello("example.com", []uint16{0x002f}, nil, false)
	summary, err := ParseClientHello(pkt)
	if err != nil {
		t.Fatalf("parse synthetic ClientHello: %v", err)
	}
	dir := t.TempDir()
	path := dir + "/ja3.json"
	body := []byte(`{"version":1,"signatures":[{"ja3":"` + summary.JA3Hash + `","name":"test-ja3","severity":"high"}],"profiles":[]}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write fingerprint set: %v", err)
	}
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 10, true)
	if err := eng.LoadFingerprintFile(path); err != nil {
		t.Fatalf("load fingerprint set: %v", err)
	}
	findings := eng.InspectHandshake("203.0.113.34", pkt, time.Now().UTC())
	for _, finding := range findings {
		if finding.RuleID != "TLS.JA3.MALICIOUS" {
			continue
		}
		if finding.EvidenceSHA256 != "" {
			t.Fatalf("JA3 MD5 must not be mislabeled as evidence SHA-256: %q", finding.EvidenceSHA256)
		}
		if finding.FingerprintType != "ja3" || finding.Fingerprint != summary.JA3Hash {
			t.Fatalf("unexpected fingerprint metadata: type=%q value=%q", finding.FingerprintType, finding.Fingerprint)
		}
		return
	}
	t.Fatal("expected malicious JA3 finding")
}

func TestL7CoverageReportsTLSNotInPath(t *testing.T) {
	// TLS silence is a finding only when TLS coverage was requested. Reporting it for
	// every host that happens to have tls_enabled set made a deliberate configuration
	// look like a broken path - the same over-reach as treating an idle engine as a
	// mandatory sensor. The first case is the real finding; the second proves the
	// requirement is what decides, not the flag.
	status := L7Status{Enabled: true, Healthy: true, TLSEnabled: true, RequestsTotal: 42, TLSHandshakesTotal: 0, CoverageRequired: true}
	if got := EvaluateL7Coverage(status, 500); got != "TLS_NOT_IN_PATH" {
		t.Fatalf("expected TLS_NOT_IN_PATH, got %s", got)
	}
	status.TLSHandshakesTotal = 1
	if got := EvaluateL7Coverage(status, 500); got != "TRAFFIC_ACTIVE" {
		t.Fatalf("expected TRAFFIC_ACTIVE after verified TLS telemetry, got %s", got)
	}

	// Coverage not required: the same silence is not a finding.
	notRequired := L7Status{Enabled: true, Healthy: true, TLSEnabled: true, RequestsTotal: 42, TLSHandshakesTotal: 0, CoverageRequired: false}
	if got := EvaluateL7Coverage(notRequired, 500); got == "TLS_NOT_IN_PATH" {
		t.Fatal("TLS silence was reported although TLS coverage was never required")
	}
}

func FuzzParseClientHelloNeverPanics(f *testing.F) {
	f.Add(buildSyntheticClientHello("example.com", []uint16{0x002f}, nil, false))
	f.Add([]byte{22, 3, 3, 0, 1, 1})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseClientHello(payload)
	})
}

func TestTLSFingerprintFileRejectsWritableAndDuplicatePolicy(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 10, true)
	dir := t.TempDir()
	writable := filepath.Join(dir, "writable.json")
	if err := os.WriteFile(writable, []byte(`{"version":1,"signatures":[],"profiles":[]}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := eng.LoadFingerprintFile(writable); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("expected writable fingerprint policy rejection, got %v", err)
	}

	dup := filepath.Join(dir, "dup.json")
	body := `{"version":1,"signatures":[` +
		`{"ja3":"00000000000000000000000000000000","name":"one"},` +
		`{"ja3":"00000000000000000000000000000000","name":"two"}],"profiles":[]}`
	if err := os.WriteFile(dup, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.LoadFingerprintFile(dup); err == nil || !strings.Contains(err.Error(), "duplicate TLS JA3 signature") {
		t.Fatalf("expected duplicate JA3 signature rejection, got %v", err)
	}
}

func TestTLSHandshakeFloodCannotBeBypassedByOneHTTPRequest(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 10, true)
	pkt := buildSyntheticClientHello("example.com", []uint16{0x002f}, nil, false)
	now := time.Now().UTC()
	eng.RecordHTTPRequestForHost("203.0.113.55", "example.com", now)

	found := false
	for i := 0; i < 24; i++ {
		findings := eng.InspectHandshake("203.0.113.55", pkt, now.Add(time.Duration(i)*time.Millisecond))
		for _, finding := range findings {
			if finding.RuleID == "TLS.HANDSHAKE.FLOOD" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("one correlated HTTP request must not suppress a sustained TLS handshake flood")
	}
}

func TestTLSRepeatedForeignSNIEntersStrikeWindow(t *testing.T) {
	eng := NewTLSSecurityEngine([]string{"example.com"}, 15, 3, true)
	pkt := buildSyntheticClientHello("foreign.example.net", []uint16{0x002f}, nil, false)
	now := time.Now().UTC()
	var repeated bool
	for i := 0; i < 3; i++ {
		findings := eng.InspectHandshake("203.0.113.56", pkt, now.Add(time.Duration(i)*time.Second))
		for _, finding := range findings {
			if finding.RuleID == "TLS.SNI.REPEATED_INVALID" {
				repeated = true
			}
		}
	}
	if !repeated {
		t.Fatal("repeated out-of-scope SNI should cross the configured strike threshold")
	}
}

func TestNormalizeTLSAllowedPatternStrictWildcardRules(t *testing.T) {
	for input, want := range map[string]string{
		"Example.COM.":   "example.com",
		"*.Example.COM.": "*.example.com",
	} {
		got, err := normalizeTLSAllowedPattern(input)
		if err != nil || got != want {
			t.Fatalf("normalizeTLSAllowedPattern(%q)=(%q,%v), want %q", input, got, err, want)
		}
	}
	for _, invalid := range []string{"*example.com", "foo.*.example.com", "203.0.113.5", "bad_domain.example"} {
		if _, err := normalizeTLSAllowedPattern(invalid); err == nil {
			t.Fatalf("expected invalid TLS allowed pattern %q to be rejected", invalid)
		}
	}
}

func TestL7EnabledCoverageSensorIsRequired(t *testing.T) {
	cfg := l7TestConfig()
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service, err := NewL7Service(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}
	service.publishStatus(true)
	cov, ok := state.SensorCoverage("l7_application")
	if !ok {
		t.Fatal("expected L7 sensor coverage")
	}
	// Enabling the engine and attaching it to the traffic path are two decisions.
	// Under the default `auto` mode an enabled engine with nothing attached is
	// available, not mandatory: treating it as mandatory is what produced a
	// permanently degraded platform for an unfinished deployment. The second half of
	// this test proves the fix is not a way to hide a path that really is broken.
	if cov.Required {
		t.Fatal("an enabled but unattached L7 engine must not be mandatory under auto mode")
	}
	if cov.Status != CoverageNotApplicable {
		t.Fatalf("unattached L7 coverage status = %q, want not_applicable", cov.Status)
	}

	// Explicitly requiring coverage restores the mandatory reading.
	cfg.CoverageRequired = "required"
	required, err := NewL7Service(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}
	required.publishStatus(true)
	strict, _ := state.SensorCoverage("l7_application")
	if !strict.Required {
		t.Fatal("coverage_required=required must make the L7 sensor mandatory")
	}
}

func TestTLSSignalCanOnlyResolveToNetworkResponse(t *testing.T) {
	cfg := defaultConfig().Kinetic
	cfg.EnforcementMode = "block"
	eng := NewKineticEngine(cfg, nil, NewKineticRuleRegistry(), nil)
	events := eng.IngestTLSFindings("203.0.113.57", TLSClientHelloSummary{SNI: "example.com", JA3Hash: "00000000000000000000000000000000"}, []L7Finding{{
		RuleID: "TLS.JA3.MALICIOUS", Score: 150, Confidence: 100, Summary: "fixture",
	}}, time.Now().UTC())
	if len(events) != 1 {
		t.Fatalf("expected one TLS event, got %d", len(events))
	}
	if events[0].Action != "block" {
		t.Fatalf("expected network block suggestion, got %q", events[0].Action)
	}
	if events[0].Action == "kill" {
		t.Fatal("TLS-only evidence must never authorize host process kill")
	}
}
