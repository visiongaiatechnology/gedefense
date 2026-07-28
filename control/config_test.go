package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigStrict(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "g.toml")
	data := `[node]
name = "test"
interface = "lo"
mode = "standalone"
[dashboard]
listen = "127.0.0.1:9843"
allow_remote = false
allowed_hosts = "127.0.0.1,localhost"
token_file = "/tmp/token"
tls_cert_file = ""
tls_key_file = ""
[core]
socket = "/tmp/core.sock"
[defense]
allowlist = "192.0.2.10,2001:db8::10/128"
enforcement = "observe"
default_ttl_seconds = 3600
max_ttl_seconds = 604800
max_block_entries = 1000
strict_asn_drop = false
dpi_enabled = false
[feeds]
enabled = false
auto_apply = false
refresh_minutes = 60
max_download_bytes = 1048576
max_entries = 1000
sources = "https://example.com/list.txt"
`
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Node.Name != "test" {
		t.Fatalf("wrong name")
	}
	if len(cfg.Defense.Allowlist) != 2 || cfg.Defense.Allowlist[0] != "192.0.2.10/32" {
		t.Fatalf("allowlist was not normalized: %v", cfg.Defense.Allowlist)
	}
}
func TestUnknownKeyRejected(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "g.toml")
	_ = os.WriteFile(p, []byte("[node]\nmagic = true\n"), 0600)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("expected error")
	}
}
