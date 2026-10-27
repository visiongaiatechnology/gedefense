package main

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestTrustedCMSEditorRequestBypassesPatternDetector(t *testing.T) {
	cfg := l7TestConfig()
	cfg.Mode = "block"
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cms := NewCMSEngine(filepath.Join(t.TempDir(), "cms.json"), filepath.Join(t.TempDir(), "bridge.key"))
	settings := cms.Settings()
	settings.Enabled = true
	settings.BridgeEnabled = true
	if err := cms.UpdateSettings(settings); err != nil {
		t.Fatal(err)
	}
	lease := cmsLease{
		IP: "203.0.113.55", Host: "example.test", User: "master", Source: "wordpress-bridge",
		IssuedAt: time.Now().Add(-time.Minute).Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	cms.mu.Lock()
	cms.leases[cmsLeaseKey(lease.IP, lease.Host)] = lease
	cms.mu.Unlock()
	engine.AttachCMS(cms)

	body := []byte("action=vgt_render_preview&nonce=test&html=%3Cdiv%3Ehello%3Cscript%3Ealert(1)%3C%2Fscript%3E%3C%2Fdiv%3E")
	req := L7InspectionRequest{
		Version: l7ProtocolVersion, Method: http.MethodPost, Scheme: "https",
		Host: "example.test", URI: "/wp-admin/admin-ajax.php", RemoteIP: "203.0.113.55",
		Headers: []L7Header{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}},
	}
	response, _, err := engine.InspectRaw(context.Background(), req, body)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range response.Findings {
		if finding.RuleID == "L7.XSS.SCRIPT_TAG" {
			t.Fatalf("trusted editor request was still pattern-blocked: %#v", response.Findings)
		}
	}

	untrusted, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	untrusted.AttachCMS(NewCMSEngine(filepath.Join(t.TempDir(), "cms.json"), filepath.Join(t.TempDir(), "bridge.key")))
	response, _, err = untrusted.InspectRaw(context.Background(), req, body)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range response.Findings {
		if finding.RuleID == "L7.XSS.SCRIPT_TAG" {
			found = true
		}
	}
	if !found {
		t.Fatal("untrusted request no longer produces the XSS finding")
	}
}
