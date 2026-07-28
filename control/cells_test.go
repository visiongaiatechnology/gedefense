// STATUS: DIAMANT VGT SUPREME
//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockCellRuntime struct {
	mu   sync.Mutex
	cell GaiaCell
	key  []byte
}

func startMockCellRuntime(
	t *testing.T,
) (*GaiaCellsAdapter, *mockCellRuntime, func()) {
	t.Helper()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x52}, 32)
	keyPath := filepath.Join(dir, "cells.key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "cells.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &mockCellRuntime{
		key: key,
		cell: GaiaCell{
			Version: 1, UUID: "01234567-89ab-cdef-0123-456789abcdef",
			Label: "Browser", Class: "application",
			CgroupPath: "/sys/fs/cgroup/gaia-cells/browser", CgroupID: 4815,
			PolicyDigest: strings.Repeat("ab", 32), Generation: 7,
			State: "running", NetworkState: "normal",
			ObservedAt: time.Unix(1_700_000_000, 0).UTC(),
		},
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			runtime.handle(connection)
		}
	}()
	adapter := NewGaiaCellsAdapter(CellsConfig{
		Enabled: true, Socket: socket, AuthKeyFile: keyPath,
		RequestTimeoutMillis: 1000,
	})
	adapter.verifyPeer = func(net.Conn) error { return nil }
	cleanup := func() {
		_ = listener.Close()
		<-stopped
	}
	return adapter, runtime, cleanup
}

func (runtime *mockCellRuntime) handle(connection net.Conn) {
	defer connection.Close()
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		return
	}
	var request cellWireRequest
	if json.Unmarshal(bytes.TrimSpace(line), &request) != nil {
		return
	}
	want := coreMAC(
		runtime.key, request.Version, strconv.FormatInt(request.Timestamp, 10),
		request.Nonce, request.Command, request.Payload,
	)
	if !constantTimeBytesEqual([]byte(want), []byte(request.MAC)) {
		return
	}
	runtime.mu.Lock()
	var payload any
	status := "OK"
	switch request.Command {
	case "LIST":
		payload = []GaiaCell{runtime.cell}
	case "FREEZE":
		runtime.cell.State = "frozen"
		payload = map[string]string{"result": "applied"}
	case "UNFREEZE":
		runtime.cell.State = "running"
		payload = map[string]string{"result": "applied"}
	case "REVOKE_NETWORK":
		runtime.cell.NetworkState = "revoked"
		payload = map[string]string{"result": "applied"}
	case "RESTORE_NETWORK":
		runtime.cell.NetworkState = "normal"
		payload = map[string]string{"result": "applied"}
	default:
		status = "ERR"
		payload = map[string]string{"error": "rejected"}
	}
	runtime.mu.Unlock()
	encodedJSON, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(encodedJSON)
	response := cellWireResponse{
		Version: cellProtocol, Nonce: request.Nonce,
		Status: status, Payload: encoded,
	}
	response.MAC = coreMAC(
		runtime.key, response.Version, response.Nonce,
		response.Status, response.Payload,
	)
	message, _ := json.Marshal(response)
	_, _ = connection.Write(append(message, '\n'))
}

func TestGaiaCellsAdapterAuthenticatedLifecycle(t *testing.T) {
	adapter, runtime, cleanup := startMockCellRuntime(t)
	defer cleanup()
	status := adapter.Status(true)
	if !status.Healthy || status.Availability != "online" || len(status.Cells) != 1 {
		t.Fatalf("unexpected adapter status: %+v", status)
	}
	cell := status.Cells[0]
	if err := adapter.Action("FREEZE", cell.UUID, cell.Generation, cell.CgroupID); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	state := runtime.cell.State
	runtime.mu.Unlock()
	if state != "frozen" {
		t.Fatalf("typed freeze did not reach runtime: %s", state)
	}
}

func TestGaiaCellTransactionIsReversibleAndIdentityBound(t *testing.T) {
	adapter, runtime, cleanup := startMockCellRuntime(t)
	defer cleanup()
	applier := NewCellTransactionApplier(adapter)
	engine, _, _ := newTestTransactionEngine(
		t, applier, func(EvidenceRecord) error { return nil },
	)
	runtime.mu.Lock()
	cell := runtime.cell
	runtime.mu.Unlock()
	payload, err := json.Marshal(cellIsolationRequest{
		UUID: cell.UUID, Generation: cell.Generation,
		CgroupID: cell.CgroupID, Action: "revoke-network",
	})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := engine.Preview(
		cellTransactionType, "Revoke Gaia Cell network",
		"contain suspicious workspace", payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := engine.Apply(preview.ID, "APPLY "+preview.ID)
	if err != nil || applied.Status != "applied" {
		t.Fatalf("cell isolation failed: applied=%+v err=%v", applied, err)
	}
	runtime.mu.Lock()
	network := runtime.cell.NetworkState
	runtime.mu.Unlock()
	if network != "revoked" {
		t.Fatalf("network isolation not applied: %s", network)
	}
	if _, err := engine.Reverse(applied.ID, "REVERSE "+applied.ID); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	network = runtime.cell.NetworkState
	runtime.mu.Unlock()
	if network != "normal" {
		t.Fatalf("network isolation not reversed: %s", network)
	}
}

func TestGaiaCellsRejectsInvalidIdentityAndUnavailableRuntime(t *testing.T) {
	if validCellUUID("../not-a-cell") {
		t.Fatal("invalid Cell UUID accepted")
	}
	cell := GaiaCell{
		Version: 1, UUID: "01234567-89ab-cdef-0123-456789abcdef",
		Class: "application", CgroupPath: "/tmp/forged", CgroupID: 1,
		PolicyDigest: strings.Repeat("ab", 32), Generation: 1,
		State: "running", NetworkState: "normal", ObservedAt: time.Now().UTC(),
	}
	if err := validateGaiaCell(cell); err == nil {
		t.Fatal("Cell outside cgroup v2 jail was accepted")
	}
	adapter := NewGaiaCellsAdapter(CellsConfig{
		Enabled: false, Socket: "/run/gaia-cells/control.sock",
		AuthKeyFile: "/not/used", RequestTimeoutMillis: 1000,
	})
	status := adapter.Status(true)
	if status.Healthy || status.Availability != "disabled" {
		t.Fatalf("disabled runtime state is invalid: %+v", status)
	}
	if _, err := adapter.List(); err == nil {
		t.Fatal("disabled adapter unexpectedly listed cells")
	}
}
