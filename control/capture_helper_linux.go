//go:build linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/flowguard"
	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

const (
	maxCaptureHelperConns    = 4
	captureHelperWriteBudget = 5 * time.Second
)

type captureOpener func(flowguard.CaptureConfig) (packetSource, error)
type procExitRunner func(ctx context.Context, onReady func(), emit func(workerguard.ExitRecord)) error

func runCaptureHelper(socketPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	opener := func(cfg flowguard.CaptureConfig) (packetSource, error) {
		return flowguard.OpenCapture(cfg)
	}
	return serveCaptureHelper(ctx, socketPath, opener, workerguard.RunProcConnector, func() {
		_ = sdNotify("READY=1\nSTATUS=GeDefense capture helper online")
	})
}

func serveCaptureHelper(ctx context.Context, socketPath string, openCapture captureOpener, runProc procExitRunner, onListening func()) error {
	if !validHelperSocketPath(socketPath) {
		return errors.New("capture helper socket path must be clean and absolute")
	}
	dir := filepath.Dir(socketPath)
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("capture helper socket directory %q is missing or invalid", dir)
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket or symlink path %q", socketPath)
		}
		if rmErr := os.Remove(socketPath); rmErr != nil {
			return fmt.Errorf("remove stale capture helper socket: %w", rmErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen capture helper socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod capture helper socket: %w", err)
	}
	if onListening != nil {
		onListening()
	}
	log.Printf("capture helper listening on %s (mode=0600, uid=%d)", socketPath, os.Getuid())

	sem := make(chan struct{}, maxCaptureHelperConns)
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				break
			}
			var netErr net.Error
			if errors.As(acceptErr, &netErr) && netErr.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return acceptErr
		}
		if peerErr := verifyCaptureHelperPeer(conn); peerErr != nil {
			log.Printf("capture helper refused peer: %v", peerErr)
			_ = conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = writeHelperJSONLine(conn, captureHelperAck{OK: false, Error: "capture helper connection limit reached"})
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			defer c.Close()
			handleCaptureHelperConn(ctx, c, openCapture, runProc)
		}(conn)
	}
	wg.Wait()
	return nil
}

func verifyCaptureHelperPeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("connection is not a Unix domain socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("inspect peer credentials: %w", err)
	}
	var cred *syscall.Ucred
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	if sockErr != nil {
		return sockErr
	}
	selfUID := uint32(os.Getuid())
	if cred.Uid != selfUID && cred.Uid != 0 {
		return fmt.Errorf("peer uid %d is not permitted (expected %d)", cred.Uid, selfUID)
	}
	return nil
}

func handleCaptureHelperConn(ctx context.Context, conn net.Conn, openCapture captureOpener, runProc procExitRunner) {
	_ = conn.SetReadDeadline(time.Now().Add(captureHelperAckTimeout))
	reader := bufio.NewReader(io.LimitReader(conn, captureHelperMaxReqBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		_ = writeHelperJSONLine(conn, captureHelperAck{OK: false, Error: "invalid request read"})
		return
	}
	if len(line) == 0 || len(line) > captureHelperMaxReqBytes {
		_ = writeHelperJSONLine(conn, captureHelperAck{OK: false, Error: "request empty or oversized"})
		return
	}
	var req captureHelperRequest
	decoder := json.NewDecoder(bufio.NewReader(io.NewSectionReader(bytesReaderAt(line), 0, int64(len(line)))))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		_ = writeHelperJSONLine(conn, captureHelperAck{OK: false, Error: "malformed JSON request"})
		return
	}
	if err := validateCaptureHelperRequest(&req); err != nil {
		_ = writeHelperJSONLine(conn, captureHelperAck{OK: false, Error: err.Error()})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		// Detect peer close or unexpected extra client writes immediately.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		cancel()
	}()

	switch req.Op {
	case "capture":
		streamCaptureSession(connCtx, conn, req, openCapture)
	case "proc_exit":
		streamProcExitSession(connCtx, conn, runProc)
	}
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func streamCaptureSession(ctx context.Context, conn net.Conn, req captureHelperRequest, openCapture captureOpener) {
	source, err := openCapture(flowguard.CaptureConfig{
		Interfaces:      req.Interfaces,
		Ports:           req.Ports,
		MaxPayloadBytes: req.MaxPayloadBytes,
	})
	if err != nil {
		_ = writeHelperJSONLine(conn, captureHelperAck{OK: false, Error: err.Error()})
		return
	}
	defer source.Close()
	if err := writeHelperJSONLine(conn, captureHelperAck{OK: true}); err != nil {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		packet, readErr := source.Read()
		if readErr != nil {
			if errors.Is(readErr, flowguard.ErrTimeout) {
				continue
			}
			return
		}
		wire := captureHelperPacket{
			Peer:       packet.Peer,
			PeerPort:   packet.PeerPort,
			Port:       packet.Port,
			PayloadB64: base64.StdEncoding.EncodeToString(packet.Payload),
			UDP:        packet.UDP,
			At:         packet.At,
		}
		if err := writeHelperJSONLine(conn, wire); err != nil {
			return
		}
	}
}

func streamProcExitSession(ctx context.Context, conn net.Conn, runProc procExitRunner) {
	var writeMu sync.Mutex
	acked := false
	err := runProc(ctx, func() {
		writeMu.Lock()
		defer writeMu.Unlock()
		if !acked {
			acked = true
			_ = writeHelperJSONLine(conn, captureHelperAck{OK: true})
		}
	}, func(record workerguard.ExitRecord) {
		writeMu.Lock()
		defer writeMu.Unlock()
		if !acked {
			return
		}
		_ = writeHelperJSONLine(conn, captureHelperExit{
			PID:      record.PID,
			Signal:   record.Signal,
			ExitCode: record.ExitCode,
			At:       record.At,
		})
	})
	writeMu.Lock()
	wasAcked := acked
	writeMu.Unlock()
	if !wasAcked && err != nil && ctx.Err() == nil {
		_ = writeHelperJSONLine(conn, captureHelperAck{OK: false, Error: err.Error()})
	}
}

func writeHelperJSONLine(conn net.Conn, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(captureHelperWriteBudget))
	_, err = conn.Write(encoded)
	return err
}
