package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCMSDetectsWordPressAndRelaxesAdminWithoutLogin(t *testing.T) {
	dir := t.TempDir()
	engine := NewCMSEngine(filepath.Join(dir, "settings.json"), filepath.Join(dir, "bridge.key"))
	req := l7NormalizedRequest{Host: "example.test", Path: "/wp-admin/post.php", Method: http.MethodPost}
	engine.ObserveRequest(req)
	if !engine.ShouldRelax(req) {
		t.Fatal("detected WordPress admin POST was not relaxed")
	}
	login := l7NormalizedRequest{Host: "example.test", Path: "/wp-login.php", Method: http.MethodPost}
	if engine.ShouldRelax(login) {
		t.Fatal("login endpoint must stay on the sensitive rate-limit path")
	}
	status := engine.Status()
	if len(status.Detections) != 1 || status.Detections[0].Kind != CMSWordPress {
		t.Fatalf("unexpected detections: %#v", status.Detections)
	}
}

func TestCMSBridgeDecryptsLeaseAndRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "bridge.log")
	engine := NewCMSEngine(filepath.Join(dir, "settings.json"), filepath.Join(dir, "bridge.key"))
	secret, err := engine.rotateBridgeKey()
	if err != nil {
		t.Fatal(err)
	}
	settings := engine.Settings()
	settings.BridgeEnabled = true
	settings.BridgeLogPath = logPath
	settings.TrustedAdminTTLSeconds = 7200
	if err := engine.UpdateSettings(settings); err != nil {
		t.Fatal(err)
	}
	key, _ := base64.StdEncoding.DecodeString(secret)
	event := cmsBridgeEvent{
		Version: 1, Event: "master_login", SiteHost: "example.test", IP: "203.0.113.55",
		User: "master", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
		EventID: "event-1",
	}
	line := encryptCMSBridgeEventForTest(t, key, event)
	if err := os.WriteFile(logPath, append([]byte("GeDefense: "), append(line, '\n')...), 0o640); err != nil {
		t.Fatal(err)
	}
	engine.pollBridge()
	if !engine.Trusted(event.IP, event.SiteHost, time.Now()) {
		t.Fatal("valid encrypted lease was not trusted")
	}

	bad := append([]byte(nil), line...)
	bad[len(bad)-2] ^= 0x01
	badEvent := event
	badEvent.EventID = "event-2"
	bad = encryptCMSBridgeEventForTest(t, key, badEvent)
	bad[len(bad)-2] ^= 0x01
	if err := os.WriteFile(logPath, append([]byte("GeDefense: "), append(line, append(bad, '\n')...)...), 0o640); err != nil {
		t.Fatal(err)
	}
	engine.pollBridge()
	if engine.Trusted("198.51.100.99", event.SiteHost, time.Now()) {
		t.Fatal("tampered bridge line granted a lease")
	}
	if count := engine.RevokeLeases(); count != 1 {
		t.Fatalf("revoked=%d, want one lease", count)
	}
}

func encryptCMSBridgeEventForTest(t *testing.T, key []byte, event cmsBridgeEvent) []byte {
	t.Helper()
	plain, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, iv, plain, []byte(cmsBridgeAAD))
	tag := sealed[len(sealed)-gcm.Overhead():]
	data := sealed[:len(sealed)-gcm.Overhead()]
	envelope := cmsBridgeEnvelope{Slug: "GeDefense", IV: base64.StdEncoding.EncodeToString(iv), Tag: base64.StdEncoding.EncodeToString(tag), Data: base64.StdEncoding.EncodeToString(data)}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
