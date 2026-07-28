// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	cellProtocol         = "VGTGC1"
	cellMaxMessageBytes  = 64 << 10
	cellMaxCount         = 4096
	cellClockWindow      = 30 * time.Second
	cellIdentityVersion  = 1
	cellRuntimeRootUID   = 0
	cellPolicyDigestSize = 64
)

type GaiaCell struct {
	Version      int       `json:"version"`
	UUID         string    `json:"uuid"`
	Label        string    `json:"label"`
	Class        string    `json:"class"`
	CgroupPath   string    `json:"cgroup_path"`
	CgroupID     uint64    `json:"cgroup_id"`
	PolicyDigest string    `json:"policy_digest"`
	Generation   uint64    `json:"generation"`
	State        string    `json:"state"`
	NetworkState string    `json:"network_state"`
	ObservedAt   time.Time `json:"observed_at"`
}

type GaiaCellsStatus struct {
	Enabled      bool       `json:"enabled"`
	Healthy      bool       `json:"healthy"`
	Availability string     `json:"availability"`
	Socket       string     `json:"socket"`
	GeneratedAt  time.Time  `json:"generated_at"`
	Cells        []GaiaCell `json:"cells"`
	Error        string     `json:"error,omitempty"`
}

type cellWireRequest struct {
	Version   string `json:"version"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Command   string `json:"command"`
	Payload   string `json:"payload"`
	MAC       string `json:"mac"`
}

type cellWireResponse struct {
	Version string `json:"version"`
	Nonce   string `json:"nonce"`
	Status  string `json:"status"`
	Payload string `json:"payload"`
	MAC     string `json:"mac"`
}

type GaiaCellsAdapter struct {
	mu         sync.Mutex
	cfg        CellsConfig
	key        []byte
	keyErr     error
	now        func() time.Time
	dial       func(string, time.Duration) (net.Conn, error)
	verifyPeer func(net.Conn) error
	last       GaiaCellsStatus
	expires    time.Time
}

func NewGaiaCellsAdapter(cfg CellsConfig) *GaiaCellsAdapter {
	adapter := &GaiaCellsAdapter{
		cfg: cfg, now: func() time.Time { return time.Now().UTC() },
		dial: func(path string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", path, timeout)
		},
		verifyPeer: verifyGaiaCellsPeer,
	}
	if cfg.Enabled {
		adapter.key, adapter.keyErr = loadGaiaCellsKey(cfg.AuthKeyFile)
	}
	return adapter
}

func loadGaiaCellsKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("Gaia Cells authentication key path must be absolute")
	}
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return nil, errors.New("Gaia Cells authentication key must be a regular file")
	}
	mode := info.Mode().Perm()
	production := stat.Uid == 0 && stat.Gid == uint32(os.Getegid()) && mode == 0o640
	local := stat.Uid == uint32(os.Geteuid()) && mode == 0o600
	if !production && !local {
		return nil, errors.New("Gaia Cells authentication key ownership or mode is invalid")
	}
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("Gaia Cells authentication key must contain exactly 32 bytes")
	}
	return append([]byte(nil), key...), nil
}

func (a *GaiaCellsAdapter) Status(force bool) GaiaCellsStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if !force && now.Before(a.expires) {
		return cloneGaiaCellsStatus(a.last)
	}
	status := GaiaCellsStatus{
		Enabled: a.cfg.Enabled, Socket: a.cfg.Socket, GeneratedAt: now,
		Cells: []GaiaCell{},
	}
	switch {
	case !a.cfg.Enabled:
		status.Availability = "disabled"
	case a.keyErr != nil:
		status.Availability = "authentication_unavailable"
		status.Error = "Gaia Cells authentication is unavailable"
	default:
		cells, err := a.listLocked()
		if err == nil {
			status.Healthy = true
			status.Availability = "online"
			status.Cells = cells
		} else if errors.Is(err, os.ErrNotExist) ||
			errors.Is(err, syscall.ECONNREFUSED) {
			status.Availability = "runtime_not_installed"
		} else {
			status.Availability = "runtime_unavailable"
			status.Error = "Gaia Cells runtime verification failed"
		}
	}
	a.last = cloneGaiaCellsStatus(status)
	a.expires = now.Add(5 * time.Second)
	return status
}

func (a *GaiaCellsAdapter) List() ([]GaiaCell, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cfg.Enabled {
		return nil, errors.New("Gaia Cells integration is disabled")
	}
	if a.keyErr != nil {
		return nil, a.keyErr
	}
	return a.listLocked()
}

func (a *GaiaCellsAdapter) listLocked() ([]GaiaCell, error) {
	var cells []GaiaCell
	if err := a.commandLocked("LIST", struct{}{}, &cells); err != nil {
		return nil, err
	}
	if len(cells) > cellMaxCount {
		return nil, errors.New("Gaia Cells runtime exceeded cell count boundary")
	}
	seen := make(map[string]struct{}, len(cells))
	for index := range cells {
		if err := validateGaiaCell(cells[index]); err != nil {
			return nil, err
		}
		key := cells[index].UUID + ":" + strconv.FormatUint(cells[index].Generation, 10)
		if _, exists := seen[key]; exists {
			return nil, errors.New("Gaia Cells runtime returned duplicate identity")
		}
		seen[key] = struct{}{}
	}
	return cells, nil
}

func (a *GaiaCellsAdapter) Action(
	command, uuid string,
	generation uint64,
	cgroupID uint64,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cfg.Enabled || a.keyErr != nil {
		return errors.New("Gaia Cells runtime is unavailable")
	}
	if !validCellUUID(uuid) || generation == 0 || cgroupID == 0 {
		return errors.New("Gaia Cell action identity is invalid")
	}
	switch command {
	case "FREEZE", "UNFREEZE", "REVOKE_NETWORK", "RESTORE_NETWORK", "SNAPSHOT_EVIDENCE":
	default:
		return errors.New("Gaia Cell action is not allowlisted")
	}
	payload := struct {
		UUID       string `json:"uuid"`
		Generation uint64 `json:"generation"`
		CgroupID   uint64 `json:"cgroup_id"`
	}{UUID: uuid, Generation: generation, CgroupID: cgroupID}
	var response struct {
		Result string `json:"result"`
	}
	if err := a.commandLocked(command, payload, &response); err != nil {
		return err
	}
	if response.Result != "applied" {
		return errors.New("Gaia Cells runtime returned an invalid action state")
	}
	a.expires = time.Time{}
	return nil
}

func (a *GaiaCellsAdapter) commandLocked(command string, payload, destination any) error {
	if len(command) < 3 || len(command) > 32 {
		return errors.New("Gaia Cells command is invalid")
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(payloadJSON) > 16<<10 {
		return errors.New("Gaia Cells payload exceeds boundary")
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	timestamp := a.now().Unix()
	timestampText := strconv.FormatInt(timestamp, 10)
	request := cellWireRequest{
		Version: cellProtocol, Timestamp: timestamp, Nonce: nonce,
		Command: command, Payload: encodedPayload,
	}
	request.MAC = coreMAC(
		a.key, request.Version, timestampText, request.Nonce,
		request.Command, request.Payload,
	)
	message, err := json.Marshal(request)
	if err != nil || len(message) > cellMaxMessageBytes {
		return errors.New("Gaia Cells request encoding failed")
	}
	timeout := time.Duration(a.cfg.RequestTimeoutMillis) * time.Millisecond
	connection, err := a.dial(a.cfg.Socket, timeout)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := a.verifyPeer(connection); err != nil {
		return err
	}
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := connection.Write(append(message, '\n')); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(
		io.LimitReader(connection, cellMaxMessageBytes+1),
		cellMaxMessageBytes+1,
	)
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > cellMaxMessageBytes {
		return errors.New("Gaia Cells response is malformed")
	}
	var response cellWireResponse
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(line)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return errors.New("Gaia Cells response decoding failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Gaia Cells response contains trailing data")
	}
	if response.Version != cellProtocol || response.Nonce != nonce ||
		(response.Status != "OK" && response.Status != "ERR") {
		return errors.New("Gaia Cells response header is invalid")
	}
	wantMAC := coreMAC(
		a.key, response.Version, response.Nonce, response.Status, response.Payload,
	)
	got, gotErr := hex.DecodeString(response.MAC)
	want, wantErr := hex.DecodeString(wantMAC)
	if gotErr != nil || wantErr != nil || !constantTimeBytesEqual(got, want) {
		return errors.New("Gaia Cells response authentication failed")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(response.Payload)
	if err != nil || len(decoded) > 32<<10 {
		return errors.New("Gaia Cells response payload is invalid")
	}
	if response.Status != "OK" {
		return errors.New("Gaia Cells runtime rejected the typed request")
	}
	payloadDecoder := json.NewDecoder(bytes.NewReader(decoded))
	payloadDecoder.DisallowUnknownFields()
	if err := payloadDecoder.Decode(destination); err != nil {
		return errors.New("Gaia Cells response payload decoding failed")
	}
	if err := payloadDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Gaia Cells response payload contains trailing data")
	}
	return nil
}

func verifyGaiaCellsPeer(connection net.Conn) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("Gaia Cells transport is not an AF_UNIX connection")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return err
	}
	var credential *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = syscall.GetsockoptUcred(
			int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED,
		)
	}); err != nil {
		return err
	}
	if socketErr != nil {
		return socketErr
	}
	if credential == nil || credential.Uid != cellRuntimeRootUID {
		return errors.New("Gaia Cells peer credential was rejected")
	}
	return nil
}

func validateGaiaCell(cell GaiaCell) error {
	if cell.Version != cellIdentityVersion || !validCellUUID(cell.UUID) ||
		len(cell.Label) > 128 || strings.ContainsRune(cell.Label, '\x00') ||
		cell.CgroupID == 0 || cell.Generation == 0 ||
		len(cell.PolicyDigest) != cellPolicyDigestSize ||
		!filepath.IsAbs(cell.CgroupPath) ||
		!strings.HasPrefix(filepath.Clean(cell.CgroupPath), "/sys/fs/cgroup/") ||
		cell.ObservedAt.IsZero() {
		return errors.New("Gaia Cell identity violates the versioned contract")
	}
	if _, err := hex.DecodeString(cell.PolicyDigest); err != nil {
		return errors.New("Gaia Cell policy digest is invalid")
	}
	switch cell.Class {
	case "application", "workspace", "vault":
	default:
		return errors.New("Gaia Cell class is invalid")
	}
	switch cell.State {
	case "created", "running", "frozen", "stopped":
	default:
		return errors.New("Gaia Cell state is invalid")
	}
	switch cell.NetworkState {
	case "normal", "revoked", "none":
	default:
		return errors.New("Gaia Cell network state is invalid")
	}
	return nil
}

func validCellUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func constantTimeBytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func cloneGaiaCellsStatus(status GaiaCellsStatus) GaiaCellsStatus {
	status.Cells = append([]GaiaCell(nil), status.Cells...)
	return status
}
