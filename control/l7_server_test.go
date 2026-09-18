// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestL7UnixSocketEndToEndWithPeerCredentials(t *testing.T) {
	cfg := l7TestConfig()
	cfg.Socket = filepath.Join(t.TempDir(), "inspect.sock")
	cfg.RequirePeerCredentials = true
	cfg.AllowedPeerUIDs = []uint32{uint32(os.Getuid())}
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

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", cfg.Socket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	envelope, err := json.Marshal(l7Request("/?q=%2527%2520OR%25201%253D1--"))
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
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %s", response.Status)
	}
	var result L7InspectionResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !findingByID(result.Findings, "L7.SQLI.BOOLEAN_TAUTOLOGY") {
		t.Fatalf("expected SQLi finding through Unix socket, got %#v", result)
	}
	status := state.L7Status()
	if !status.Healthy || status.RequestsTotal != 1 {
		t.Fatalf("unexpected L7 status: %#v", status)
	}
}

func TestPrepareL7SocketRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("do not remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "inspect.sock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := prepareL7SocketPath(path); err == nil {
		t.Fatal("expected symlink refusal")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target was modified: %v", err)
	}
}

func TestL7ServerRejectsUnknownEnvelopeFields(t *testing.T) {
	cfg := l7TestConfig()
	cfg.Socket = filepath.Join(t.TempDir(), "inspect.sock")
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
	conn, err := net.DialTimeout("unix", cfg.Socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := `{"version":1,"method":"GET","host":"example.test","uri":"/","remote_ip":"198.51.100.2","unexpected":true}`
	request := "POST /v1/inspect HTTP/1.1\r\nHost: unix\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(payload)) + "\r\nConnection: close\r\n\r\n" + payload
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatal(err)
	}
	if !bytes.Contains(buf[:n], []byte("400 Bad Request")) {
		t.Fatalf("expected 400 response, got %q", string(buf[:n]))
	}
}

func TestPrepareL7SocketRequiresPreprovisionedRuntimeDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "inspect.sock")
	if err := prepareL7SocketPath(path); err == nil {
		t.Fatal("expected missing runtime directory to be rejected")
	}
}

func TestPrepareL7SocketRejectsSymlinkRuntimeAncestor(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := prepareL7SocketPath(filepath.Join(linkDir, "inspect.sock")); err == nil {
		t.Fatal("expected symlink runtime ancestor to be rejected")
	}
}

func TestPrepareL7SocketRejectsWritableRuntimeDirectory(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeDir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := prepareL7SocketPath(filepath.Join(runtimeDir, "inspect.sock")); err == nil {
		t.Fatal("expected group-writable runtime directory to be rejected")
	}
}

func TestL7ConnectionLimitIsBounded(t *testing.T) {
	cases := []struct {
		concurrent int
		want       int
	}{
		{0, 32},
		{1, 32},
		{64, 256},
		{1024, 2048},
	}
	for _, tc := range cases {
		if got := l7ConnectionLimit(tc.concurrent); got != tc.want {
			t.Fatalf("l7ConnectionLimit(%d)=%d want=%d", tc.concurrent, got, tc.want)
		}
	}
}
