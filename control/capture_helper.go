// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 FIND-008: dedicated read-only capture helper wire contract and
// unprivileged control-plane clients.
//
// The helper process (`gedefense-capture-helper.service`, running
// `gedefense-control --capture-helper`) holds the two network capabilities
// (`CAP_NET_RAW`, `CAP_NET_ADMIN`) and `AF_PACKET` in an isolated sandbox with
// `IPAddressDeny=any`, no AF_INET/AF_INET6, and no access to secrets or state.
// The control plane (`gedefense-control.service`) holds zero Linux capabilities
// and consumes strictly read-only bounded telemetry records over a 0600,
// SO_PEERCRED-verified Unix socket.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/flowguard"
	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

const (
	defaultCaptureHelperSocket = "/run/vgt-gedefense-capture/capture.sock"
	captureHelperSocketEnv     = "GEDEFENSE_CAPTURE_HELPER_SOCKET"
	captureHelperMaxReqBytes   = 4096
	captureHelperMaxLineBytes  = 16 << 10
	captureHelperDialTimeout   = 2 * time.Second
	captureHelperAckTimeout    = 5 * time.Second
	captureHelperReadTimeout   = 500 * time.Millisecond
)

type captureHelperRequest struct {
	Op              string   `json:"op"`
	Interfaces      []string `json:"interfaces,omitempty"`
	Ports           []uint16 `json:"ports,omitempty"`
	MaxPayloadBytes int      `json:"max_payload_bytes,omitempty"`
}

type captureHelperAck struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type captureHelperPacket struct {
	Peer       string    `json:"peer"`
	PeerPort   uint16    `json:"peer_port"`
	Port       uint16    `json:"port"`
	PayloadB64 string    `json:"payload_b64"`
	UDP        bool      `json:"udp,omitempty"`
	At         time.Time `json:"at"`
}

type captureHelperExit struct {
	PID      int       `json:"pid"`
	Signal   int       `json:"signal"`
	ExitCode int       `json:"exit_code"`
	At       time.Time `json:"at"`
}

// packetSource abstracts local AF_PACKET capture and the Unix-socket helper
// stream behind the same minimal Read/Close contract.
type packetSource interface {
	Read() (flowguard.Packet, error)
	Close() error
}

// captureHelperSocketPath resolves the helper Unix socket path. An empty env
// uses the canonical systemd runtime socket.
func captureHelperSocketPath() string {
	raw := strings.TrimSpace(os.Getenv(captureHelperSocketEnv))
	if raw == "" {
		return defaultCaptureHelperSocket
	}
	if !validHelperSocketPath(raw) {
		return defaultCaptureHelperSocket
	}
	return raw
}

func validHelperSocketPath(raw string) bool {
	if raw == "" || len(raw) > 256 || strings.ContainsAny(raw, "\x00\r\n") {
		return false
	}
	if !filepath.IsAbs(raw) {
		return false
	}
	cleaned := filepath.Clean(raw)
	return cleaned == raw && !strings.Contains(cleaned, "..")
}

func helperSocketPresent(socketPath string) bool {
	if !validHelperSocketPath(socketPath) {
		return false
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}

func validateCaptureHelperRequest(req *captureHelperRequest) error {
	if req == nil {
		return errors.New("empty capture helper request")
	}
	switch req.Op {
	case "proc_exit":
		if len(req.Interfaces) > 0 || len(req.Ports) > 0 || req.MaxPayloadBytes != 0 {
			return errors.New("proc_exit does not accept capture parameters")
		}
		return nil
	case "capture":
		if len(req.Interfaces) > 8 {
			return errors.New("capture interfaces exceed 8 entries")
		}
		for _, iface := range req.Interfaces {
			if iface == "" || len(iface) > 15 || strings.ContainsAny(iface, "\x00\r\n/ \t") {
				return fmt.Errorf("invalid capture interface %q", iface)
			}
		}
		if len(req.Ports) == 0 || len(req.Ports) > 8 {
			return errors.New("capture requires 1..8 ports")
		}
		for _, port := range req.Ports {
			if port == 0 {
				return errors.New("capture port must be non-zero")
			}
		}
		if req.MaxPayloadBytes < 512 || req.MaxPayloadBytes > 2048 {
			return errors.New("capture max_payload_bytes must be between 512 and 2048")
		}
		return nil
	default:
		return errors.New("unknown capture helper operation")
	}
}

// openPacketSource prefers the dedicated capture helper socket when present so
// gedefense-control needs zero capabilities; otherwise it falls back to direct
// AF_PACKET (e.g. direct root execution or local tests).
func openPacketSource(ctx context.Context, cfg flowguard.CaptureConfig) (packetSource, error) {
	socketPath := captureHelperSocketPath()
	if helperSocketPresent(socketPath) {
		return openCaptureHelperStream(ctx, socketPath, cfg)
	}
	capture, err := flowguard.OpenCapture(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w (capture helper socket %s absent)", err, socketPath)
	}
	return capture, nil
}

// runProcExitSource prefers the dedicated capture helper for CN_PROC netlink
// events when present and falls back to in-process RunProcConnector otherwise.
func runProcExitSource(ctx context.Context, onReady func(), emit func(workerguard.ExitRecord)) error {
	socketPath := captureHelperSocketPath()
	if helperSocketPresent(socketPath) {
		return runProcExitHelperStream(ctx, socketPath, onReady, emit)
	}
	return workerguard.RunProcConnector(ctx, onReady, emit)
}

type captureHelperClient struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
	closed bool
}

// readHelperLine reads one newline-delimited JSON line without latching errors across Read timeouts.
func readHelperLine(conn net.Conn, reader *bufio.Reader, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	var line []byte
	for {
		frag, err := reader.ReadSlice('\n')
		if len(frag) > 0 {
			if len(line)+len(frag) > captureHelperMaxLineBytes {
				return nil, errors.New("capture helper line exceeds bound")
			}
			line = append(line, frag...)
		}
		if err == nil {
			return line, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) > 0 && errors.Is(err, io.EOF) {
			return line, nil
		}
		return nil, err
	}
}

func dialCaptureHelper(ctx context.Context, socketPath string, req captureHelperRequest) (net.Conn, *bufio.Reader, error) {
	if !validHelperSocketPath(socketPath) {
		return nil, nil, errors.New("invalid capture helper socket path")
	}
	dialer := &net.Dialer{Timeout: captureHelperDialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: capture helper dial: %v", flowguard.ErrUnsupported, err)
	}
	payload, err := json.Marshal(req)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	payload = append(payload, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(captureHelperAckTimeout))
	_, writeErr := conn.Write(payload)
	reader := bufio.NewReaderSize(conn, 4096)
	line, readErr := readHelperLine(conn, reader, captureHelperAckTimeout)
	if readErr == nil && len(line) > 0 {
		var ack captureHelperAck
		if err := json.Unmarshal(line, &ack); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("capture helper malformed ack: %w", err)
		}
		if !ack.OK {
			_ = conn.Close()
			if ack.Error == "" {
				ack.Error = "request rejected"
			}
			return nil, nil, fmt.Errorf("%w: capture helper: %s", flowguard.ErrUnsupported, ack.Error)
		}
		if writeErr != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("capture helper request write: %w", writeErr)
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, reader, nil
	}
	_ = conn.Close()
	if writeErr != nil {
		return nil, nil, fmt.Errorf("capture helper request write: %w", writeErr)
	}
	return nil, nil, fmt.Errorf("capture helper ack: %w", readErr)
}

func openCaptureHelperStream(ctx context.Context, socketPath string, cfg flowguard.CaptureConfig) (packetSource, error) {
	normalized := cfg.Normalize()
	req := captureHelperRequest{
		Op:              "capture",
		Interfaces:      append([]string(nil), normalized.Interfaces...),
		Ports:           append([]uint16(nil), normalized.Ports...),
		MaxPayloadBytes: normalized.MaxPayloadBytes,
	}
	conn, reader, err := dialCaptureHelper(ctx, socketPath, req)
	if err != nil {
		return nil, err
	}
	return &captureHelperClient{conn: conn, reader: reader}, nil
}

func (c *captureHelperClient) Read() (flowguard.Packet, error) {
	if c == nil || c.conn == nil || c.reader == nil {
		return flowguard.Packet{}, flowguard.ErrUnsupported
	}
	line, err := readHelperLine(c.conn, c.reader, captureHelperReadTimeout)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return flowguard.Packet{}, flowguard.ErrTimeout
		}
		return flowguard.Packet{}, err
	}
	var wire captureHelperPacket
	if err := json.Unmarshal(line, &wire); err != nil {
		return flowguard.Packet{}, flowguard.ErrTimeout
	}
	raw, err := base64.StdEncoding.DecodeString(wire.PayloadB64)
	if err != nil || len(raw) == 0 || len(raw) > 2048 {
		return flowguard.Packet{}, flowguard.ErrTimeout
	}
	return flowguard.Packet{
		Peer:     wire.Peer,
		PeerPort: wire.PeerPort,
		Port:     wire.Port,
		Payload:  raw,
		UDP:      wire.UDP,
		At:       wire.At,
	}, nil
}

func (c *captureHelperClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func runProcExitHelperStream(ctx context.Context, socketPath string, onReady func(), emit func(workerguard.ExitRecord)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, reader, err := dialCaptureHelper(ctx, socketPath, captureHelperRequest{Op: "proc_exit"})
	if err != nil {
		return fmt.Errorf("%w: %v", workerguard.ErrProcConnectorUnsupported, err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	if onReady != nil {
		onReady()
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, readErr := readHelperLine(conn, reader, captureHelperReadTimeout)
		if readErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(readErr, &netErr) && netErr.Timeout() {
				continue
			}
			if errors.Is(readErr, io.EOF) {
				return errors.New("capture helper closed proc_exit stream")
			}
			return readErr
		}
		var wire captureHelperExit
		if err := json.Unmarshal(line, &wire); err != nil {
			continue
		}
		if wire.PID <= 0 {
			continue
		}
		emit(workerguard.ExitRecord{
			PID:      wire.PID,
			Signal:   wire.Signal,
			ExitCode: wire.ExitCode,
			At:       wire.At,
		})
	}
}
