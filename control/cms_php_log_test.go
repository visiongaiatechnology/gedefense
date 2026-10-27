package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCMSBridgeReadsPhpErrorLogLineAndHello(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "php-fpm.log")
	engine := NewCMSEngine(filepath.Join(dir, "settings.json"), filepath.Join(dir, "bridge.key"))
	secret, err := engine.rotateBridgeKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	settings := engine.Settings()
	settings.BridgeEnabled = true
	settings.BridgeLogPath = logPath
	if err := engine.UpdateSettings(settings); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	hello := cmsBridgeEvent{Version: 1, Event: "bridge_hello", SiteHost: "example.test", IP: "127.0.0.1", IssuedAt: now + 2, ExpiresAt: now + 300, EventID: "hello-1"}
	helloLine := append([]byte("[27-Oct-2026 14:00:00 UTC] GeDefense: "), encryptCMSBridgeTestEvent(t, key, hello)...)
	if err := os.WriteFile(logPath, append(helloLine, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	engine.pollBridge()
	if status := engine.Status(); status.BridgeLastRead == "" {
		t.Fatalf("hello line was not observed: %#v", status)
	}
	if engine.Trusted("127.0.0.1", "example.test", time.Now()) {
		t.Fatal("hello event must not create a lease")
	}

	lease := cmsBridgeEvent{Version: 1, Event: "master_login", SiteHost: "example.test", IP: "203.0.113.77", User: "master", IssuedAt: now + 2, ExpiresAt: now + 7200, EventID: "lease-1"}
	leaseLine := append([]byte("[27-Oct-2026 14:01:00 UTC] GeDefense: "), encryptCMSBridgeTestEvent(t, key, lease)...)
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(leaseLine, '\n')); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	engine.pollBridge()
	if !engine.Trusted(lease.IP, lease.SiteHost, time.Now()) {
		t.Fatal("master lease from PHP error log prefix was not trusted")
	}
}

func encryptCMSBridgeTestEvent(t *testing.T, key []byte, event cmsBridgeEvent) []byte {
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
