// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: the VGTGC2 client for `gedefense-cell-helper` (§3), transport
// and framing layer. The command codec is in parser_cells_client_codec.go.
//
// The control plane is unprivileged (CapEff=0); every lifecycle action is one
// authenticated text request to the privileged helper over the Unix socket.
// Wire: fields separated by 0x1f, payload base64url (no padding), HMAC-SHA256 tag
// over the exact bytes. A missing helper is a capability fact
// (ErrParserCellsRuntimeUnavailable), never a mode to be papered over.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	parserCellRequestMaxBytes   = 8 << 10
	parserCellResponseMaxBytes  = 64 << 10
	parserCellFrameTag          = "VGTGC2"
	parserCellResponseTag       = "VGTGC2R"
	parserCellSep               = "\x1f"
	parserCellMaxFields         = 24
	parserCellMaxValueBytes     = 4096
	parserCellMaxListCells      = 64
	parserCellKeyBytes          = 32
	parserCellIDBytes           = 8
	parserCellTimestampSkewSecs = 30
	parserCellCommandCreate     = "CELL_CREATE"
	parserCellCommandExportRead = "CELL_EXPORT_READ"
	// Bounded resource caps handed to the helper; the helper clamps them against
	// the package-managed profile (§4).
	parserCellCreateMaxRSSBytes int64 = 512 << 20
	parserCellCreateMaxPIDs           = 64
)

var (
	// ErrParserCellsRuntimeUnavailable is the capability-missing fact: no helper
	// socket, an unreadable key, an unreachable/restarting helper or an unsupported
	// ABI. Callers refuse a create with 503 and never claim a cell.
	ErrParserCellsRuntimeUnavailable = errors.New("parser cell runtime unavailable")
	// ErrParserCellsProtocol is a malformed or hostile frame/peer. It is never
	// retried silently as if the helper were merely absent.
	ErrParserCellsProtocol = errors.New("parser cell protocol violation")
	// ErrParserCellsPeer rejects a helper whose SO_PEERCRED uid is not the
	// configured privileged owner.
	ErrParserCellsPeer = errors.New("parser cell helper peer rejected")
	// parserCellErrorCodes is the closed §3 error set; a code outside it is a
	// protocol violation, not an operator-visible helper message.
	parserCellErrorCodes = map[string]struct{}{
		"bad-request": {}, "bad-mac": {}, "stale": {}, "replay": {},
		"unknown-command": {}, "capability-missing": {}, "profile-unknown": {},
		"profile-invalid": {}, "input-invalid": {}, "input-missing": {},
		"sandbox-unavailable": {}, "cell-limit": {}, "unknown-cell": {},
		"stale-generation": {}, "export-missing": {}, "export-overflow": {},
		"burn-failed": {}, "internal": {},
	}
)

// ParserCellError is one helper ERR line. Only the closed code crosses the wire;
// the helper must not send internal paths and the client accepts none.
type ParserCellError struct{ Code string }

func (e *ParserCellError) Error() string {
	if e == nil {
		return "parser cell helper error"
	}
	return "parser cell helper rejected the request: " + e.Code
}

func parserCellErrorCode(err error) string {
	var helperErr *ParserCellError
	if errors.As(err, &helperErr) {
		return helperErr.Code
	}
	if errors.Is(err, ErrParserCellsRuntimeUnavailable) {
		return "capability-missing"
	}
	return "internal"
}

// ParserCellCapabilities is the negotiated CELL_CAPABILITIES answer (§3).
type ParserCellCapabilities struct {
	ABI           string
	Sandbox       bool
	Profiles      []string
	MaxConcurrent int
	InputBytes    int64
	ExportBytes   int64
	TTLMax        int
	BPFLSM        bool
	// Wayland is an additive capability: the phase-1 helper does not advertise it,
	// so a missing field is an honest false (session-socket display is unsupported).
	Wayland bool
}

// ParserCellCreateRequest carries only operator-chosen, bounded values. Binary,
// argv and environment come from the helper's root-owned profile table (§1.2).
type ParserCellCreateRequest struct {
	Profile     string
	InputToken  string
	InputSHA256 string
	InputSize   int64
	TTLSeconds  int
	MaxRSSBytes int64
	MaxPIDs     int
}

// ParserCellCreateResult is the helper's attestation of one spawned cell.
type ParserCellCreateResult struct {
	UUID       string
	Generation uint64
	CgroupID   uint64
	CgroupPath string
	PID        int
	ExpiresAt  int64
	Sandbox    bool
	NetNS      bool
}

// ParserCellRemote is one CELL_LIST row.
type ParserCellRemote struct {
	UUID       string
	Generation uint64
	CgroupID   uint64
	Profile    string
	State      string
	ExpiresAt  int64
	PID        int
	ExportSize int64
}

// ParserCellBurnResult is the idempotent CELL_BURN answer.
type ParserCellBurnResult struct {
	Burned     bool
	ExportSize int64
	ExportSHA  string
}

// ParserCellHealth is the CELL_HEALTH answer.
type ParserCellHealth struct {
	State       string
	ActiveCells int
	BurnedTotal uint64
	LastError   string
	StartedAt   int64
	ABI         string
}

// parserCellTransport is the complete helper surface the manager needs. It exists
// as an interface so the lifecycle contract is testable against a real Unix
// listener speaking the wire protocol (P2-T3 test plan §9.3).
type parserCellTransport interface {
	Capabilities() (ParserCellCapabilities, error)
	Create(ParserCellCreateRequest) (ParserCellCreateResult, error)
	List() ([]ParserCellRemote, error)
	Freeze(uuid string, generation, cgroupID uint64) error
	Unfreeze(uuid string, generation, cgroupID uint64) error
	Burn(uuid string, generation, cgroupID uint64, evidenceID, reason string) (ParserCellBurnResult, error)
	ExportRead(uuid string, generation uint64, maxBytes int64) (*os.File, ParserCellExportMeta, error)
	Health() (ParserCellHealth, error)
}

type parserCellClient struct {
	path    string
	key     []byte
	timeout time.Duration
	peerUID int
	now     func() time.Time
}

// newParserCellClient builds the client from the bootstrap section only. A missing
// or unreadable key is runtime-unavailable; it must never stop the control plane
// from starting (§8).
func newParserCellClient(cfg ParserCellsConfig) (*parserCellClient, error) {
	if strings.TrimSpace(cfg.Socket) == "" {
		return nil, fmt.Errorf("%w: helper socket is not configured", ErrParserCellsRuntimeUnavailable)
	}
	key, err := loadParserCellKey(cfg.AuthKeyFile)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(cfg.RequestTimeoutMillis) * time.Millisecond
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	return &parserCellClient{path: cfg.Socket, key: key, timeout: timeout, peerUID: cfg.PeerUID,
		now: func() time.Time { return time.Now() }}, nil
}

// loadParserCellKey reads the 32-byte VGTGC2 key. The packaged mode is 0640
// root:gedefense, so group read is allowed; world access is refused and the file
// must be regular and not a symlink.
func loadParserCellKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: helper key is not configured", ErrParserCellsRuntimeUnavailable)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: helper key: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: helper key must be a regular non-symlink file", ErrParserCellsProtocol)
	}
	if info.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("%w: helper key must not be world accessible", ErrParserCellsProtocol)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: helper key: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	if len(data) != parserCellKeyBytes {
		return nil, fmt.Errorf("%w: helper key must contain exactly %d bytes", ErrParserCellsProtocol, parserCellKeyBytes)
	}
	return data, nil
}

// request performs one authenticated round trip. Every request carries a fresh
// 64-bit random id, a current Unix timestamp and the command payload; the answer
// must echo the id, authenticate and carry no trailing data (replay/stray-answer
// defence). The caller owns a returned export descriptor and must close it.
func (c *parserCellClient) request(command string, fields []string) ([]byte, int, error) {
	if !parserCellCommandValid(command) {
		return nil, -1, parserCellProtocol("unknown command")
	}
	payload, err := buildParserCellPayload(fields)
	if err != nil {
		return nil, -1, err
	}
	b64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	idBytes := make([]byte, parserCellIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, -1, fmt.Errorf("parser cell request id: %w", err)
	}
	id := hex.EncodeToString(idBytes)
	ts := strconv.FormatInt(c.now().Unix(), 10)
	macInput := strings.Join([]string{parserCellFrameTag, id, ts, command, b64}, parserCellSep)
	line := macInput + parserCellSep + hex.EncodeToString(parserCellMAC(c.key, macInput)) + "\n"
	if len(line) > parserCellRequestMaxBytes {
		return nil, -1, parserCellProtocol("request line exceeds the 8 KiB bound")
	}
	sock, err := c.dial()
	if err != nil {
		return nil, -1, err
	}
	defer syscall.Close(sock)
	response, fds, err := parserCellRoundTrip(sock, []byte(line))
	if err != nil {
		parserCellCloseFDs(fds)
		return nil, -1, err
	}
	if len(fds) > 1 {
		parserCellCloseFDs(fds)
		return nil, -1, parserCellProtocol("answer carries more than one descriptor")
	}
	raw, err := parseParserCellResponse(response, id, c.key)
	if err != nil {
		parserCellCloseFDs(fds)
		return nil, -1, err
	}
	if len(fds) == 1 && command != parserCellCommandExportRead {
		parserCellCloseFDs(fds)
		return nil, -1, parserCellProtocol("descriptor on a non-export answer")
	}
	fd := -1
	if len(fds) == 1 {
		fd = fds[0]
	}
	return raw, fd, nil
}

func (c *parserCellClient) dial() (int, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	for {
		err = syscall.Connect(fd, &syscall.SockaddrUnix{Name: c.path})
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EISCONN) {
			err = nil
		}
		break
	}
	if err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	if c.peerUID >= 0 {
		cred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			_ = syscall.Close(fd)
			return -1, parserCellProtocol("peer credentials unavailable")
		}
		if int(cred.Uid) != c.peerUID {
			_ = syscall.Close(fd)
			return -1, fmt.Errorf("%w: uid %d", ErrParserCellsPeer, cred.Uid)
		}
	}
	timeout := syscall.NsecToTimeval(c.timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &timeout); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, err)
	}
	return fd, nil
}

func parserCellRoundTrip(sock int, line []byte) (string, []int, error) {
	for offset := 0; offset < len(line); {
		written, err := syscall.Write(sock, line[offset:])
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return "", nil, fmt.Errorf("%w: write: %v", ErrParserCellsRuntimeUnavailable, err)
		}
		offset += written
	}
	buffer := make([]byte, 4096)
	data := make([]byte, 0, 4096)
	fds := make([]int, 0, 1)
	for {
		oob := make([]byte, syscall.CmsgSpace(4))
		n, oobn, _, _, err := syscall.Recvmsg(sock, buffer, oob, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				// The Go runtime delivers signals for asynchronous preemption; a
				// blocking recvmsg must be resumed, not reported as a helper failure.
				continue
			}
			parserCellCloseFDs(fds)
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return "", nil, fmt.Errorf("%w: response timeout", ErrParserCellsRuntimeUnavailable)
			}
			return "", nil, fmt.Errorf("%w: read: %v", ErrParserCellsRuntimeUnavailable, err)
		}
		if n > 0 {
			if len(data)+n > parserCellResponseMaxBytes {
				parserCellCloseFDs(fds)
				return "", nil, parserCellProtocol("response exceeds the 64 KiB bound")
			}
			data = append(data, buffer[:n]...)
		}
		if oobn > 0 {
			received, err := parserCellRights(oob[:oobn])
			if err != nil {
				parserCellCloseFDs(fds)
				return "", nil, err
			}
			fds = append(fds, received...)
		}
		if index := bytes.IndexByte(data, '\n'); index >= 0 {
			if index+1 != len(data) {
				parserCellCloseFDs(fds)
				return "", nil, parserCellProtocol("trailing data after the response line")
			}
			return string(data[:index]), fds, nil
		}
		if n == 0 {
			parserCellCloseFDs(fds)
			return "", nil, parserCellProtocol("connection closed before a response line")
		}
	}
}

func parserCellRights(oob []byte) ([]int, error) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, parserCellProtocol("unparseable control message")
	}
	fds := make([]int, 0, 1)
	for index := range messages {
		rights, err := syscall.ParseUnixRights(&messages[index])
		if err != nil || len(rights) == 0 {
			parserCellCloseFDs(fds)
			return nil, parserCellProtocol("invalid SCM_RIGHTS control message")
		}
		fds = append(fds, rights...)
		if len(fds) > 1 {
			parserCellCloseFDs(fds)
			return nil, parserCellProtocol("more than one SCM_RIGHTS descriptor")
		}
	}
	return fds, nil
}

// parseParserCellResponse authenticates one answer and enforces the replay
// contract: the id must be the one just sent, the tag must verify, the payload
// must be canonical base64url and no trailing frame may follow.
func parseParserCellResponse(line, id string, key []byte) ([]byte, error) {
	fields := strings.Split(line, parserCellSep)
	if len(fields) != 5 || fields[0] != parserCellResponseTag {
		return nil, parserCellProtocol("malformed response frame")
	}
	if fields[1] != id {
		return nil, parserCellProtocol("response id does not match the request")
	}
	if fields[2] != "OK" && fields[2] != "ERR" {
		return nil, parserCellProtocol("invalid response status")
	}
	if len(fields[4]) != sha256.Size*2 {
		return nil, parserCellProtocol("invalid response authentication tag")
	}
	provided, err := hex.DecodeString(fields[4])
	if err != nil {
		return nil, parserCellProtocol("invalid response authentication tag")
	}
	if !hmac.Equal(provided, parserCellMAC(key, strings.Join(fields[:4], parserCellSep))) {
		return nil, parserCellProtocol("response authentication failed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(fields[3])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != fields[3] {
		return nil, parserCellProtocol("non-canonical base64url payload")
	}
	if len(payload) > parserCellResponseMaxBytes {
		return nil, parserCellProtocol("response payload exceeds the 64 KiB bound")
	}
	if fields[2] == "ERR" {
		return nil, parseParserCellError(payload)
	}
	return payload, nil
}

func parseParserCellError(payload []byte) error {
	parts := strings.Split(string(payload), parserCellSep)
	if len(parts) > 2 {
		return parserCellProtocol("malformed error payload")
	}
	key, value, ok := strings.Cut(parts[0], "=")
	if !ok || key != "code" {
		return parserCellProtocol("error payload must carry a code")
	}
	if _, known := parserCellErrorCodes[value]; !known {
		return parserCellProtocol("unknown helper error code")
	}
	return &ParserCellError{Code: value}
}

func parserCellMAC(key []byte, input string) []byte {
	mack := hmac.New(sha256.New, key)
	mack.Write([]byte(input))
	return mack.Sum(nil)
}

// ---------------------------------------------------------------- helpers

func parserCellProtocol(detail string) error {
	return fmt.Errorf("%w: %s", ErrParserCellsProtocol, detail)
}

func parserCellCloseFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}
}

func parserCellCommandValid(command string) bool {
	switch command {
	case "CELL_CAPABILITIES", parserCellCommandCreate, "CELL_LIST", "CELL_FREEZE",
		"CELL_UNFREEZE", "CELL_BURN", parserCellCommandExportRead, "CELL_HEALTH":
		return true
	}
	return false
}
