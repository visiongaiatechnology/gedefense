//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/flowguard"
	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

type stubPacketSource struct {
	packets chan flowguard.Packet
	closed  atomic.Bool
}

func (s *stubPacketSource) Read() (flowguard.Packet, error) {
	select {
	case pkt, ok := <-s.packets:
		if !ok {
			return flowguard.Packet{}, errors.New("closed")
		}
		return pkt, nil
	case <-time.After(30 * time.Millisecond):
		return flowguard.Packet{}, flowguard.ErrTimeout
	}
}

func (s *stubPacketSource) Close() error {
	s.closed.Store(true)
	return nil
}

func TestCaptureHelperRefusesSymlinkSocketPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "capture.sock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := serveCaptureHelper(context.Background(), link, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink refusal, got %v", err)
	}
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("symlink target was modified: %v", statErr)
	}
}

func TestCaptureHelperStreamsPacketsAndProcExitsAndEnforcesBounds(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "capture.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pktSrc := &stubPacketSource{packets: make(chan flowguard.Packet, 2)}
	pktSrc.packets <- flowguard.Packet{
		Peer: "2001:db8::10", PeerPort: 54321, Port: 443,
		Payload: []byte{0x16, 0x03, 0x01, 0x00, 0x05}, At: time.Now().UTC(),
	}

	ready := make(chan struct{})
	srvDone := make(chan error, 1)
	go func() {
		srvDone <- serveCaptureHelper(ctx, sock,
			func(cfg flowguard.CaptureConfig) (packetSource, error) {
				if len(cfg.Ports) != 1 || cfg.Ports[0] != 443 {
					return nil, errors.New("unexpected ports")
				}
				return pktSrc, nil
			},
			func(pctx context.Context, onReady func(), emit func(workerguard.ExitRecord)) error {
				onReady()
				emit(workerguard.ExitRecord{PID: 4242, Signal: 11, ExitCode: 139, At: time.Now().UTC()})
				<-pctx.Done()
				return pctx.Err()
			},
			func() { close(ready) },
		)
	}()
	<-ready

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %o, want 0600", perm)
	}

	// Unknown operation rejected cleanly.
	if _, _, err := dialCaptureHelper(ctx, sock, captureHelperRequest{Op: "inject"}); err == nil {
		t.Fatal("unknown helper op unexpectedly accepted")
	}

	// Packet capture stream roundtrip.
	client, err := openCaptureHelperStream(ctx, sock, flowguard.CaptureConfig{Ports: []uint16{443}, MaxPayloadBytes: 1536})
	if err != nil {
		t.Fatalf("openCaptureHelperStream: %v", err)
	}
	pkt, err := client.Read()
	if err != nil {
		t.Fatalf("client.Read: %v", err)
	}
	if pkt.Peer != "2001:db8::10" || pkt.Port != 443 || len(pkt.Payload) != 5 || pkt.Payload[0] != 0x16 {
		t.Fatalf("unexpected packet = %+v", pkt)
	}
	_ = client.Close()

	// Proc exit stream roundtrip.
	exitCtx, exitCancel := context.WithCancel(ctx)
	gotReady := false
	gotExit := make(chan workerguard.ExitRecord, 1)
	go func() {
		_ = runProcExitHelperStream(exitCtx, sock, func() { gotReady = true }, func(rec workerguard.ExitRecord) {
			gotExit <- rec
			exitCancel()
		})
	}()
	select {
	case rec := <-gotExit:
		if !gotReady || rec.PID != 4242 || rec.Signal != 11 {
			t.Fatalf("unexpected exit record = %+v (ready=%t)", rec, gotReady)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for proc_exit record from capture helper")
	}

	// Concurrency cap enforcement (4 active + 5th refused). Slots of the
	// previous sessions are released asynchronously once the server observes
	// the peer close, so each held dial retries only on the cap error.
	var held []net.Conn
	for i := 0; i < maxCaptureHelperConns; i++ {
		var c net.Conn
		var dialErr error
		deadline := time.Now().Add(3 * time.Second)
		for {
			c, _, dialErr = dialCaptureHelper(ctx, sock, captureHelperRequest{Op: "proc_exit"})
			if dialErr == nil || !strings.Contains(dialErr.Error(), "connection limit reached") || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if dialErr != nil {
			t.Fatalf("conn %d failed: %v", i, dialErr)
		}
		held = append(held, c)
	}
	if _, _, overErr := dialCaptureHelper(ctx, sock, captureHelperRequest{Op: "proc_exit"}); overErr == nil || !strings.Contains(overErr.Error(), "connection limit reached") {
		t.Fatalf("expected connection cap error on 5th concurrent connection, got %v", overErr)
	}
	for _, c := range held {
		_ = c.Close()
	}

	cancel()
	if srvErr := <-srvDone; srvErr != nil {
		t.Fatalf("serveCaptureHelper exit: %v", srvErr)
	}
}

func TestCaptureHelperRecoversAfterReadTimeout(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "capture.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := &stubPacketSource{packets: make(chan flowguard.Packet, 1)}
	openFn := func(flowguard.CaptureConfig) (packetSource, error) { return src, nil }
	procFn := func(ctx context.Context, onReady func(), emit func(workerguard.ExitRecord)) error {
		<-ctx.Done()
		return nil
	}
	ready := make(chan struct{})
	srvDone := make(chan error, 1)
	go func() {
		srvDone <- serveCaptureHelper(ctx, sock, openFn, procFn, func() { close(ready) })
	}()
	<-ready

	client, err := openCaptureHelperStream(ctx, sock, flowguard.CaptureConfig{Ports: []uint16{443}, MaxPayloadBytes: 1536})
	if err != nil {
		t.Fatalf("openCaptureHelperStream: %v", err)
	}
	defer client.Close()

	// Wait through one idle Read timeout (500ms), then push a delayed packet.
	if _, timeoutErr := client.Read(); !errors.Is(timeoutErr, flowguard.ErrTimeout) {
		t.Fatalf("expected ErrTimeout on idle stream, got %v", timeoutErr)
	}
	src.packets <- flowguard.Packet{Peer: "198.51.100.42", PeerPort: 41234, Port: 443, Payload: []byte{0x16, 0x03, 0x01, 0x00, 0x02}, At: time.Now().UTC()}
	pkt, err := client.Read()
	if err != nil {
		t.Fatalf("client.Read after ErrTimeout failed: %v", err)
	}
	if pkt.Peer != "198.51.100.42" || pkt.Port != 443 {
		t.Fatalf("unexpected post-timeout packet: %+v", pkt)
	}
	cancel()
	<-srvDone
}
