package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoreClientAuthenticatedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "core.key")
	socketPath := filepath.Join(dir, "core.sock")
	client, err := NewCoreClient(socketPath, keyPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		line, readErr := bufio.NewReader(conn).ReadString('\n')
		if readErr != nil {
			done <- readErr
			return
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 5 || fields[0] != coreProtocol || fields[3] != "PING" {
			done <- os.ErrInvalid
			return
		}
		if fields[4] != coreMAC(client.key, fields[:4]...) {
			done <- os.ErrPermission
			return
		}
		payload := base64.RawURLEncoding.EncodeToString([]byte("native"))
		responseTag := coreProtocol + "R"
		mac := coreMAC(client.key, responseTag, fields[2], "OK", payload)
		_, writeErr := conn.Write([]byte(strings.Join([]string{responseTag, fields[2], "OK", payload, mac}, " ") + "\n"))
		done <- writeErr
	}()
	mode, err := client.Ping()
	if err != nil {
		t.Fatal(err)
	}
	if mode != "native" {
		t.Fatalf("unexpected core mode %q", mode)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPolicySignatureRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	cfg := PolicyConfig{
		StateFile: filepath.Join(dir, "policy.json"), SigningKeyFile: filepath.Join(dir, "policy.key"),
		PublicKeyFile: filepath.Join(dir, "policy.pub"), RequireSigned: true,
	}
	store, err := NewPolicyStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	blocks := []BlockEntry{{ID: "rule-1", Target: "203.0.113.7/32", Source: "test", Reason: "test", ExpiresAt: time.Now().Add(time.Hour).UTC()}}
	if err := store.Persist("node", "observe", "observe", blocks); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.Blocks) != 1 {
		t.Fatalf("valid signed policy rejected: envelope=%+v err=%v", loaded, err)
	}
	raw, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "203.0.113.7/32", "203.0.113.8/32", 1))
	if err := os.WriteFile(cfg.StateFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewPolicyStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Load(); err == nil || fresh.Status().Verified {
		t.Fatal("tampered policy was accepted")
	}
}

func TestBehaviorProfileMACRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig().XDR
	cfg.StorageKeyFile = ""
	cfg.LogKeyFile = filepath.Join(dir, "xdr.key")
	cfg.BehaviorProfileFile = filepath.Join(dir, "behavior.json")
	cfg.BehaviorWarmupSamples = 2
	model, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := ProcessSample{Exe: "/usr/bin/example", Comm: "example"}
	now := time.Now().UTC()
	model.ObserveNetwork(p, []NetConnection{{RemoteIP: "203.0.113.1", RemotePort: 443}}, now)
	model.ObserveNetwork(p, []NetConnection{{RemoteIP: "203.0.113.2", RemotePort: 443}}, now.Add(time.Second))
	if err := model.Persist(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfg.BehaviorProfileFile)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"mean": 1`, `"mean": 999`, 1))
	if err := os.WriteFile(cfg.BehaviorProfileFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tampered.Summary().IntegrityOK {
		t.Fatal("tampered behavior profile was accepted")
	}
}

func TestBehaviorAnomalyIsNotKillEligible(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig().XDR
	cfg.StorageKeyFile = ""
	cfg.LogKeyFile = filepath.Join(dir, "xdr.key")
	cfg.BehaviorProfileFile = filepath.Join(dir, "behavior.json")
	cfg.BehaviorWarmupSamples = 3
	cfg.BehaviorZScoreMilli = 2000
	cfg.BehaviorMinConnections = 4
	model, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := ProcessSample{Exe: "/usr/bin/example", Comm: "example"}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		model.ObserveNetwork(p, []NetConnection{{RemoteIP: "203.0.113.1", RemotePort: 443}}, now.Add(time.Duration(i)*time.Second))
	}
	var burst []NetConnection
	for i := 0; i < 20; i++ {
		burst = append(burst, NetConnection{RemoteIP: "198.51.100." + string(rune('A'+i)), RemotePort: uint16(1000 + i)})
	}
	matches := model.ObserveNetwork(p, burst, now.Add(time.Minute))
	if len(matches) == 0 {
		t.Fatal("expected adaptive anomaly")
	}
	for _, match := range matches {
		if match.KillEligible {
			t.Fatalf("behavior-only anomaly became kill eligible: %+v", match)
		}
	}
}

func TestReplayGuardRejectsDuplicateAndMalformedIDs(t *testing.T) {
	guard := NewReplayGuard(time.Minute)
	now := time.Now()
	if guard.Claim("short", now) {
		t.Fatal("malformed request id accepted")
	}
	id := "request_0123456789abcdef"
	if !guard.Claim(id, now) || guard.Claim(id, now.Add(time.Second)) {
		t.Fatal("replay guard did not reject duplicate")
	}
	if !guard.Claim(id, now.Add(2*time.Minute)) {
		t.Fatal("expired replay id was not released")
	}
}

func TestPolicyLoadFailureMarksStatusUnverified(t *testing.T) {
	dir := t.TempDir()
	cfg := PolicyConfig{
		StateFile: filepath.Join(dir, "policy.json"), SigningKeyFile: filepath.Join(dir, "policy.key"),
		PublicKeyFile: filepath.Join(dir, "policy.pub"), RequireSigned: true,
	}
	store, err := NewPolicyStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StateFile, []byte(`{"envelope":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("malformed policy unexpectedly loaded")
	}
	status := store.Status()
	if status.Verified || status.Error == "" {
		t.Fatalf("malformed policy did not force an unverified status: %+v", status)
	}
}

func TestPolicyPersistSerializesGeneration(t *testing.T) {
	dir := t.TempDir()
	cfg := PolicyConfig{
		StateFile: filepath.Join(dir, "policy.json"), SigningKeyFile: filepath.Join(dir, "policy.key"),
		PublicKeyFile: filepath.Join(dir, "policy.pub"), RequireSigned: true,
	}
	store, err := NewPolicyStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 24
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func(index int) {
			blocks := []BlockEntry{{
				ID: fmt.Sprintf("rule-%02d", index), Target: fmt.Sprintf("203.0.113.%d/32", index+1),
				Source: "concurrency-test", Reason: "generation serialization", ExpiresAt: time.Now().Add(time.Hour).UTC(),
			}}
			errs <- store.Persist("node", "observe", "observe", blocks)
		}(i)
	}
	for i := 0; i < writers; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := store.Status().Generation; got != writers {
		t.Fatalf("generation=%d want=%d", got, writers)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Generation != writers {
		t.Fatalf("persisted generation=%d want=%d", loaded.Generation, writers)
	}
}

func TestBehaviorModelBudgetsBoundUntrustedCardinality(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig().XDR
	cfg.StorageKeyFile = ""
	cfg.LogKeyFile = filepath.Join(dir, "xdr.key")
	cfg.BehaviorProfileFile = filepath.Join(dir, "behavior.json")
	cfg.BehaviorMaxProfiles = 2
	cfg.BehaviorMaxPorts = 2
	cfg.BehaviorWarmupSamples = 5
	model, err := NewBehaviorModel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		process := ProcessSample{Exe: fmt.Sprintf("/usr/bin/profile-%d", i), Comm: "profile"}
		model.ObserveNetwork(process, []NetConnection{{RemoteIP: "203.0.113.1", RemotePort: uint16(1000 + i)}}, now)
	}
	first := ProcessSample{Exe: "/usr/bin/profile-0", Comm: "profile"}
	model.ObserveNetwork(first, []NetConnection{
		{RemoteIP: "203.0.113.1", RemotePort: 2001},
		{RemoteIP: "203.0.113.2", RemotePort: 2002},
		{RemoteIP: "203.0.113.3", RemotePort: 2003},
	}, now.Add(time.Second))
	summary := model.Summary()
	if summary.Profiles != 2 || !summary.Saturated || summary.DroppedObservations == 0 {
		t.Fatalf("behavior budget not enforced: %+v", summary)
	}
	profiles := model.Snapshot(10)
	for _, profile := range profiles {
		if len(profile.RemotePorts) > 2 {
			t.Fatalf("remote port budget exceeded: %+v", profile.RemotePorts)
		}
	}
}

func TestSignedStateDocumentsRejectTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	policyCfg := PolicyConfig{
		StateFile: filepath.Join(dir, "policy.json"), SigningKeyFile: filepath.Join(dir, "policy.key"),
		PublicKeyFile: filepath.Join(dir, "policy.pub"), RequireSigned: true,
	}
	store, err := NewPolicyStore(policyCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Persist("node", "observe", "observe", nil); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(policyCfg.StateFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewPolicyStore(policyCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Load(); err == nil {
		t.Fatal("policy with trailing JSON was accepted")
	}

	behaviorCfg := defaultConfig().XDR
	behaviorCfg.StorageKeyFile = ""
	behaviorCfg.LogKeyFile = filepath.Join(dir, "xdr.key")
	behaviorCfg.BehaviorProfileFile = filepath.Join(dir, "behavior.json")
	model, err := NewBehaviorModel(behaviorCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Persist(); err != nil {
		t.Fatal(err)
	}
	behaviorFile, err := os.OpenFile(behaviorCfg.BehaviorProfileFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := behaviorFile.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := behaviorFile.Close(); err != nil {
		t.Fatal(err)
	}
	tampered, err := NewBehaviorModel(behaviorCfg)
	if err != nil {
		t.Fatal(err)
	}
	if tampered.Summary().IntegrityOK {
		t.Fatal("behavior profile with trailing JSON was accepted")
	}
}

func TestCoreClientAuthenticatesAllowlistCommand(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "core.key")
	socketPath := filepath.Join(dir, "core.sock")
	client, err := NewCoreClient(socketPath, keyPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		line, readErr := bufio.NewReader(conn).ReadString('\n')
		if readErr != nil {
			done <- readErr
			return
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 6 || fields[0] != coreProtocol || fields[3] != "ALLOW_ADD" || fields[4] != "192.0.2.10/32" {
			done <- os.ErrInvalid
			return
		}
		if fields[5] != coreMAC(client.key, fields[:5]...) {
			done <- os.ErrPermission
			return
		}
		payload := base64.RawURLEncoding.EncodeToString([]byte("allowlisted"))
		responseTag := coreProtocol + "R"
		mac := coreMAC(client.key, responseTag, fields[2], "OK", payload)
		_, writeErr := conn.Write([]byte(strings.Join([]string{responseTag, fields[2], "OK", payload, mac}, " ") + "\n"))
		done <- writeErr
	}()
	if err := client.AllowAdd("192.0.2.10/32"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
