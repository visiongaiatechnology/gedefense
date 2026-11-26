// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	coreProtocol = "VGT3"
	// maxCoreResponseBytes bounds one authenticated VGT3 response line. V6.2
	// raises the StyX flow batch to 64 records / 16 KiB payload, so the old 4 KiB
	// line bound would truncate and reject every full burst batch. The value stays
	// a hard, bounded ceiling for every command family.
	maxCoreResponseBytes = 64 << 10
	// maxCoreResponsePayloadBytes mirrors MAX_RESPONSE_BYTES (24 KiB) in
	// rust/gedefense-core/src/main.rs before base64url encoding.
	maxCoreResponsePayloadBytes           = 24 << 10
	maxCoreIngressEventsPerResponse       = 12
	cellLSMDenyNonUnixSocket        uint8 = 1
)

type CoreClient struct {
	socket string
	// timeoutNanos is read on every command, so it is held in an atomic rather
	// than behind a mutex on the IPC hot path. The administrable System namespace
	// can retune it without a restart.
	timeoutNanos atomic.Int64
	peerPID      atomic.Int64
	key          []byte
}

// CorePID returns the kernel-verified peer PID (SO_PEERCRED) of the connected
// gedefense-core daemon, or 0 before the first successful IPC exchange.
func (c *CoreClient) CorePID() int {
	if c == nil {
		return 0
	}
	return int(c.peerPID.Load())
}

func NewCoreClient(socket, keyPath string, timeout time.Duration) (*CoreClient, error) {
	key, err := loadCoreIPCKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("core IPC key: %w", err)
	}
	client := &CoreClient{socket: socket, key: key}
	client.timeoutNanos.Store(int64(timeout))
	return client, nil
}

func loadCoreIPCKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("core IPC key path must be absolute")
	}
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		// Development and unit-test path. Production installers create the key
		// beforehand with the strict root:gedefense 0640 shared-secret profile.
		return loadOrCreateBinaryKey(path)
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("core IPC key descriptor is invalid")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return nil, errors.New("core IPC key must be a regular file")
	}
	mode := info.Mode().Perm()
	productionProfile := stat.Uid == 0 && mode == 0o640 && (stat.Gid == uint32(os.Getegid()) || os.Geteuid() == 0)
	localProfile := stat.Uid == uint32(os.Geteuid()) && mode == 0o600
	if !productionProfile && !localProfile {
		return nil, fmt.Errorf("core IPC key ownership/mode invalid: uid=%d gid=%d mode=%#o", stat.Uid, stat.Gid, mode)
	}
	b, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("core IPC key must contain exactly 32 bytes")
	}
	return append([]byte(nil), b...), nil
}

func protocolFieldValid(v string) bool {
	return v != "" && len(v) <= 3072 && !strings.ContainsAny(v, " \t\r\n\x00\x1f")
}

func randomNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func coreMAC(key []byte, fields ...string) string {
	mac := hmac.New(sha256.New, key)
	for i, field := range fields {
		if i > 0 {
			_, _ = mac.Write([]byte{0x1f})
		}
		_, _ = mac.Write([]byte(field))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// deadline returns the active command deadline.
func (c *CoreClient) deadline() time.Duration {
	value := time.Duration(c.timeoutNanos.Load())
	if value <= 0 {
		return 2 * time.Second
	}
	return value
}

func (c *CoreClient) command(parts ...string) (string, error) {
	if len(parts) == 0 || len(parts) > 16 {
		return "", errors.New("invalid core command arity")
	}
	for _, p := range parts {
		if !protocolFieldValid(p) {
			return "", errors.New("invalid core protocol field")
		}
	}
	nonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	requestFields := append([]string{coreProtocol, stamp, nonce}, parts...)
	mac := coreMAC(c.key, requestFields...)

	conn, err := net.DialTimeout("unix", c.socket, c.deadline())
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if unixConn, ok := conn.(*net.UnixConn); ok {
		if rawConn, rawErr := unixConn.SyscallConn(); rawErr == nil {
			_ = rawConn.Control(func(fd uintptr) {
				if ucred, uerr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); uerr == nil && ucred.Pid > 0 {
					c.peerPID.Store(int64(ucred.Pid))
				}
			})
		}
	}
	if err := conn.SetDeadline(time.Now().Add(c.deadline())); err != nil {
		return "", fmt.Errorf("core IPC deadline configuration failed: %w", err)
	}
	line := strings.Join(append(requestFields, mac), " ") + "\n"
	if len(line) > 4096 {
		return "", errors.New("core request exceeds protocol limit")
	}
	if _, err = conn.Write([]byte(line)); err != nil {
		return "", err
	}
	responseReader := bufio.NewReaderSize(io.LimitReader(conn, maxCoreResponseBytes+1), maxCoreResponseBytes+1)
	response, err := responseReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return parseCoreResponse(response, nonce, c.key)
}

func parseCoreResponse(response, nonce string, key []byte) (string, error) {
	if len(response) > maxCoreResponseBytes || !strings.HasSuffix(response, "\n") {
		return "", errors.New("core response exceeds protocol limit or is unterminated")
	}
	response = strings.TrimSpace(response)
	fields := strings.Fields(response)
	if len(fields) != 5 || fields[0] != coreProtocol+"R" || fields[1] != nonce {
		return "", errors.New("invalid authenticated core response")
	}
	status, encoded, gotMAC := fields[2], fields[3], fields[4]
	wantMAC := coreMAC(key, fields[0], fields[1], status, encoded)
	gotBytes, err1 := hex.DecodeString(gotMAC)
	wantBytes, err2 := hex.DecodeString(wantMAC)
	if err1 != nil || err2 != nil || !hmac.Equal(gotBytes, wantBytes) {
		return "", errors.New("core response authentication failed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(payload) > maxCoreResponsePayloadBytes {
		return "", errors.New("invalid core response payload")
	}
	message := string(payload)
	if status != "OK" {
		if message == "" {
			message = "request rejected"
		}
		return "", fmt.Errorf("core rejected command: %s", message)
	}
	return message, nil
}

func (c *CoreClient) ClearBlocklist() error {
	state, err := c.command("CLEAR_BLOCKLIST")
	if err != nil {
		return err
	}
	if state != "cleared" {
		return fmt.Errorf("core returned unexpected blocklist clear state %q", state)
	}
	return nil
}
func (c *CoreClient) VerifyBlocklistEmpty() error {
	state, err := c.command("VERIFY_EMPTY")
	if err != nil {
		return err
	}
	if state != "empty" {
		return fmt.Errorf("core returned unexpected blocklist state %q", state)
	}
	return nil
}

func (c *CoreClient) ExecEvents() ([]CoreExecEvent, error) {
	response, err := c.command("EXEC_EVENTS")
	if err != nil {
		return nil, err
	}
	return parseCoreExecEvents(response)
}

func (c *CoreClient) EgressEvents() ([]CoreEgressDropEvent, error) {
	response, err := c.command("EGRESS_EVENTS")
	if err != nil {
		return nil, err
	}
	return parseCoreEgressDropEvents(response)
}

func (c *CoreClient) CellPolicyEpoch() (string, error) {
	response, err := c.command("CELL_POLICY_EPOCH")
	if err != nil {
		return "", err
	}
	decoded, decodeErr := hex.DecodeString(response)
	if decodeErr != nil || len(decoded) != 16 || len(response) != 32 {
		return "", errors.New("core returned an invalid Cell policy epoch")
	}
	return response, nil
}

func (c *CoreClient) CellPolicySet(cgroupID uint64, flags uint8) error {
	if cgroupID == 0 || flags != cellLSMDenyNonUnixSocket {
		return errors.New("Cell LSM policy identity or flags are invalid")
	}
	response, err := c.command("CELL_POLICY_SET", strconv.FormatUint(cgroupID, 10), strconv.FormatUint(uint64(flags), 10))
	if err != nil {
		return err
	}
	if response != "applied" {
		return errors.New("core returned an invalid Cell policy state")
	}
	return nil
}

func (c *CoreClient) CellPolicyDelete(cgroupID uint64) error {
	if cgroupID == 0 {
		return errors.New("Cell LSM policy identity is invalid")
	}
	response, err := c.command("CELL_POLICY_DEL", strconv.FormatUint(cgroupID, 10))
	if err != nil {
		return err
	}
	if response != "deleted" {
		return errors.New("core returned an invalid Cell policy deletion state")
	}
	return nil
}

func (c *CoreClient) CellLSMEvents() ([]CoreCellLSMDenyEvent, error) {
	response, err := c.command("CELL_LSM_EVENTS")
	if err != nil {
		return nil, err
	}
	return parseCoreCellLSMDenyEvents(response)
}

type CoreMalwareStatus struct {
	State     string
	Failures  uint64
	Dropped   uint64
	LastError string
}

func (c *CoreClient) MalwareEvents() (CoreMalwareEventBatch, error) {
	response, err := c.command("MALWARE_EVENTS")
	if err != nil {
		return CoreMalwareEventBatch{}, err
	}
	return parseCoreMalwareEvents(response)
}

func (c *CoreClient) MalwareStatus() (CoreMalwareStatus, error) {
	response, err := c.command("MALWARE_STATUS")
	if err != nil {
		return CoreMalwareStatus{}, err
	}
	return parseCoreMalwareStatus(response)
}

func parseCoreMalwareStatus(response string) (CoreMalwareStatus, error) {
	if len(response) == 0 || len(response) > 1024 {
		return CoreMalwareStatus{}, errors.New("core returned an invalid malware status length")
	}
	parts := strings.Split(response, "|")
	if len(parts) != 4 {
		return CoreMalwareStatus{}, errors.New("core returned a malformed malware status")
	}
	kv := make(map[string]string, 4)
	for _, part := range parts {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return CoreMalwareStatus{}, errors.New("core returned a malformed malware status field")
		}
		kv[k] = v
	}
	switch kv["state"] {
	case "starting", "online", "degraded":
	default:
		return CoreMalwareStatus{}, errors.New("core returned an unknown malware status state")
	}
	failures, err := strconv.ParseUint(kv["failures"], 10, 64)
	if err != nil {
		return CoreMalwareStatus{}, errors.New("core returned invalid malware failure count")
	}
	dropped, err := strconv.ParseUint(kv["dropped"], 10, 64)
	if err != nil {
		return CoreMalwareStatus{}, errors.New("core returned invalid malware dropped count")
	}
	errBytes, err := hex.DecodeString(kv["error"])
	if err != nil || len(errBytes) > 256 {
		return CoreMalwareStatus{}, errors.New("core returned invalid malware error string")
	}
	return CoreMalwareStatus{
		State:     kv["state"],
		Failures:  failures,
		Dropped:   dropped,
		LastError: string(errBytes),
	}, nil
}

func UserMalwareScan(socketPath, path string, timeout time.Duration) (MalwareScanResult, error) {
	if socketPath != "/run/gedefense-scan/scan.sock" || timeout < time.Second || timeout > time.Minute {
		return MalwareScanResult{}, errors.New("user malware scan endpoint rejected")
	}
	if err := validateQuarantinePathBuiltin(path); err != nil {
		return MalwareScanResult{}, errors.New("user malware scan path rejected")
	}
	token, err := quarantinePathToken(path)
	if err != nil {
		return MalwareScanResult{}, err
	}
	connection, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return MalwareScanResult{}, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return MalwareScanResult{}, err
	}
	if _, err := io.WriteString(connection, "VGTSCAN1 "+token+"\n"); err != nil {
		return MalwareScanResult{}, err
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return MalwareScanResult{}, err
		}
	}
	reader := bufio.NewReaderSize(io.LimitReader(connection, maxCoreResponseBytes+1), maxCoreResponseBytes+1)
	response, err := reader.ReadString('\n')
	if err != nil || len(response) > maxCoreResponseBytes {
		return MalwareScanResult{}, errors.New("user malware scan response rejected")
	}
	response = strings.TrimSpace(response)
	encoded, ok := strings.CutPrefix(response, "OK ")
	if !ok {
		return MalwareScanResult{}, errors.New("user malware scan was rejected")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) > 2048 {
		return MalwareScanResult{}, errors.New("user malware scan response encoding rejected")
	}
	return parseMalwareScanResult(string(decoded))
}

// ------------------------------------------------------------------ styx egress
//
// POINT 3 (docs/POINT3-EGRESS-BEACON.md, ABI-3): the privileged core owns the
// per-cgroup egress maps; the unprivileged control plane may only reach them
// through the authenticated VGT3 channel. Everything below is additive. A core
// that predates the STYX_* command family answers "ERR unknown command"; that
// maps onto the ErrStyxUnavailable sentinel so the caller can report the sensor
// as capability-missing instead of treating an old core as an XDR outage.

const (
	// maxStyxFlowEventsPerResponse mirrors the core's own batch ceiling (V6.2:
	// MAX_STYX_FLOW_EVENTS_PER_RESPONSE = 64, raised from 8 so one drain can clear
	// a burst). The control plane enforces the raised ceiling independently and
	// defensively: a buggy or hostile core must not be able to force unbounded
	// parsing work per poll.
	maxStyxFlowEventsPerResponse = 64
	// maxStyxFlowPayloadBytes bounds the text-wire payload before it is split
	// (V6.2: MAX_STYX_FLOW_PAYLOAD_BYTES = 16 KiB, raised from 2 KiB).
	maxStyxFlowPayloadBytes = 16 << 10
	// maxStyxFlowRecordBytes bounds one record before it is split into fields; the
	// fixed wire record is far below this, so an oversized record is corruption.
	maxStyxFlowRecordBytes = 512
)

// ErrStyxUnavailable marks the backwards-compatible answer of a core that does
// not implement the STYX_* command family yet. It is a capability fact, not an
// XDR degradation.
var ErrStyxUnavailable = errors.New("styx capability unavailable")

// StyxVersion negotiates the Styx ABI. A pre-STYX core yields ErrStyxUnavailable.
func (c *CoreClient) StyxVersion() (string, error) {
	version, err := c.styxCommand("STYX_VERSION")
	if err != nil {
		return "", err
	}
	if version != "styx-v1" {
		return "", fmt.Errorf("core returned unsupported styx version %q", version)
	}
	return version, nil
}

// StyxGlobal applies the host-wide default mode (0..2) and flags.
func (c *CoreClient) StyxGlobal(mode, flags uint8) error {
	if mode > 2 {
		return errors.New("styx global mode is out of range")
	}
	return c.styxExpect("applied", "STYX_GLOBAL",
		strconv.FormatUint(uint64(mode), 10), strconv.FormatUint(uint64(flags), 10))
}

// StyxModeSet applies a per-cgroup mode (0..2) and flags.
func (c *CoreClient) StyxModeSet(cgroupID uint64, mode, flags uint8) error {
	if cgroupID == 0 {
		return errors.New("styx mode cgroup id is invalid")
	}
	if mode > 2 {
		return errors.New("styx mode is out of range")
	}
	return c.styxExpect("applied", "STYX_MODE_SET", strconv.FormatUint(cgroupID, 10),
		strconv.FormatUint(uint64(mode), 10), strconv.FormatUint(uint64(flags), 10))
}

// StyxFlowEvents drains one bounded batch of aggregated flow events. The second
// return value is the core's saturating ring-drop delta since the last poll; a
// positive value is a visibility loss, never a silent success.
func (c *CoreClient) StyxFlowEvents() ([]CoreStyxFlowEvent, uint64, error) {
	response, err := c.styxCommand("STYX_FLOW_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreStyxFlowEvents(response)
}

// parseCoreStyxFlowEvents decodes the §3.3 text wire. It is all-or-nothing: one
// malformed record rejects the whole batch so the caller never acts on a
// partially parsed aggregate. It never panics.
func parseCoreStyxFlowEvents(response string) ([]CoreStyxFlowEvent, uint64, error) {
	if len(response) > maxStyxFlowPayloadBytes {
		return nil, 0, errors.New("core returned an oversized styx flow batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed styx flow batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed styx flow batch")
	}
	dropped, err := parseStyxUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid styx flow drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxStyxFlowEventsPerResponse {
		return nil, 0, errors.New("core returned too many styx flow events")
	}
	events := make([]CoreStyxFlowEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxStyxFlowRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty styx flow record")
		}
		event, err := parseCoreStyxFlowEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

// --------------------------------------------------------------- titan exec gate
//
// POINT 1 (docs/POINT1-TITAN-EXEC-GATE.md, ABI-3 §5): the privileged core owns the
// Titan exec-gate maps; the unprivileged control plane may only reach them through
// the authenticated VGT3 channel. Everything below is additive. A core that
// predates the TITAN_EXEC_* command family answers "ERR unknown command"; that maps
// onto ErrTitanExecUnavailable so the caller reports the capability as missing
// instead of treating an old core as an XDR outage. The event text wire (§3.3) is
// deliberately NOT parsed here: P1-T5 owns the bounded all-or-nothing parser and
// consumes the raw payload this client returns.

// ErrTitanExecUnavailable marks the backwards-compatible answer of a core that
// does not implement the TITAN_EXEC_* command family yet. It is a capability fact,
// not an XDR degradation.
var ErrTitanExecUnavailable = errors.New("titan-exec capability unavailable")

// TitanExecStatus reports the kernel-side state, mode and capability facts.
func (c *CoreClient) TitanExecStatus() (TitanExecCoreStatus, error) {
	response, err := c.titanExecCommand("TITAN_EXEC_STATUS")
	if err != nil {
		return TitanExecCoreStatus{}, err
	}
	return parseTitanExecCoreStatus(response)
}

// TitanExecEvents returns the raw §3.3 text wire ("empty" or
// "<dropped>|<record>[,<record>...]"). Parsing is owned by P1-T5
// (control/titan_exec_events.go) so the client stays a transport.
func (c *CoreClient) TitanExecEvents() (string, error) {
	return c.titanExecCommand("TITAN_EXEC_EVENTS")
}

// parseTitanExecCoreStatus decodes the fixed §5 status key list. Key order and the
// closed value vocabularies are part of the ABI; anything else is rejected instead
// of being interpreted.
func parseTitanExecCoreStatus(payload string) (TitanExecCoreStatus, error) {
	if len(payload) == 0 || len(payload) > titanExecMaxStatusPayloadBytes {
		return TitanExecCoreStatus{}, errors.New("core returned an oversized titan exec status")
	}
	order := []string{"status", "mode", "flags", "path", "lsm", "offsets", "entries", "scopes", "epoch"}
	fields := strings.Split(payload, ";")
	if len(fields) != len(order) {
		return TitanExecCoreStatus{}, errors.New("core returned a malformed titan exec status")
	}
	values := make(map[string]string, len(order))
	for index, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key != order[index] {
			return TitanExecCoreStatus{}, errors.New("core returned a malformed titan exec status")
		}
		values[key] = value
	}
	switch values["status"] {
	case "applied", "pending", "failed", "inactive", "unavailable":
	default:
		return TitanExecCoreStatus{}, errors.New("core returned an unknown titan exec status state")
	}
	mode, err := titanExecParseUint(values["mode"], 8)
	if err != nil || mode > 4 {
		return TitanExecCoreStatus{}, errors.New("core returned an invalid titan exec status mode")
	}
	flags, err := titanExecParseUint(values["flags"], 8)
	if err != nil {
		return TitanExecCoreStatus{}, errors.New("core returned invalid titan exec status flags")
	}
	if values["path"] != "bpf-lsm" && values["path"] != "none" {
		return TitanExecCoreStatus{}, errors.New("core returned an invalid titan exec status path")
	}
	if values["lsm"] != "active" && values["lsm"] != "inactive" {
		return TitanExecCoreStatus{}, errors.New("core returned an invalid titan exec status lsm")
	}
	if values["offsets"] != "valid" && values["offsets"] != "invalid" {
		return TitanExecCoreStatus{}, errors.New("core returned an invalid titan exec status offsets")
	}
	entries, err := titanExecParseUint(values["entries"], 32)
	if err != nil || entries > titanExecMaxPolicyEntries {
		return TitanExecCoreStatus{}, errors.New("core returned an invalid titan exec status entry count")
	}
	scopes, err := titanExecParseUint(values["scopes"], 32)
	if err != nil || scopes > titanExecMaxPolicyScopes {
		return TitanExecCoreStatus{}, errors.New("core returned an invalid titan exec status scope count")
	}
	if !titanExecValidEpoch(values["epoch"]) {
		return TitanExecCoreStatus{}, errors.New("core returned an invalid titan exec status epoch")
	}
	return TitanExecCoreStatus{
		State: values["status"], Mode: uint8(mode), Flags: uint8(flags),
		Path: values["path"], LSM: values["lsm"], Offsets: values["offsets"],
		Entries: int(entries), Scopes: int(scopes), Epoch: strings.ToLower(values["epoch"]),
	}, nil
}

// ErrLockdownUnavailable marks the backwards-compatible answer of a core that
// does not implement the LOCKDOWN_* command family yet. It is a capability
// fact, not a degraded XDR sensor.
var ErrLockdownUnavailable = errors.New("lockdown capability unavailable")

// parseLockdownCSV parses one bounded csv token list of a LOCKDOWN_* answer.
// The core encodes the empty list as "-"; unknown tokens are rejected because
// the answer is a closed vocabulary. LOCKDOWN_STATUS may additionally name the
// delegated cells phase and the honestly unsupported sessions/dm phases.
func parseLockdownCSV(field, kind string) ([]string, error) {
	if field == "" || field == "-" {
		return nil, nil
	}
	fields := strings.Split(field, ",")
	if len(fields) > lockdownMaxUnsupportedPhases {
		return nil, errors.New("core returned too many lockdown " + kind + " tokens")
	}
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, token := range fields {
		// The core may spell the delegated cells phase as "cells=delegated"; the
		// control plane normalises it to the closed phase token.
		if token == "cells=delegated" {
			token = lockdownPhaseNameCells
		}
		if !lockdownStatusPhaseValid(token) {
			return nil, errors.New("core returned an unknown lockdown " + kind + " token")
		}
		if _, duplicate := seen[token]; duplicate {
			return nil, errors.New("core returned a duplicate lockdown " + kind + " token")
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	return out, nil
}

// parseCoreLockdownStatus decodes the exact §5 status wire. It is strict: key
// order, key set and every value are part of the contract.
func parseCoreLockdownStatus(payload string) (CoreLockdownStatus, error) {
	if len(payload) == 0 || len(payload) > maxLockdownPayloadBytes {
		return CoreLockdownStatus{}, errors.New("core returned an oversized lockdown status")
	}
	fields := strings.Split(payload, ";")
	if len(fields) != 6 {
		return CoreLockdownStatus{}, errors.New("core returned a malformed lockdown status")
	}
	keys := []string{"state=", "epoch=", "mode=", "flags=", "phases=", "unsupported="}
	values := make([]string, len(fields))
	for index, field := range fields {
		if !strings.HasPrefix(field, keys[index]) {
			return CoreLockdownStatus{}, errors.New("core returned a malformed lockdown status field")
		}
		values[index] = strings.TrimPrefix(field, keys[index])
	}
	switch values[0] {
	case "off", "armed", "active", "degraded":
	default:
		return CoreLockdownStatus{}, errors.New("core returned an unknown lockdown state")
	}
	if !validLockdownEpoch(values[1]) {
		return CoreLockdownStatus{}, errors.New("core returned an invalid lockdown epoch")
	}
	if values[2] != lockdownModeLocked && values[2] != lockdownModeUnlocked {
		return CoreLockdownStatus{}, errors.New("core returned an invalid lockdown mode")
	}
	flags, err := parseLockdownUint8(values[3])
	if err != nil {
		return CoreLockdownStatus{}, err
	}
	applied, err := parseLockdownCSV(values[4], "phase")
	if err != nil {
		return CoreLockdownStatus{}, err
	}
	unsupported, err := parseLockdownCSV(values[5], "phase")
	if err != nil {
		return CoreLockdownStatus{}, err
	}
	return CoreLockdownStatus{State: values[0], Epoch: values[1], Mode: values[2], Flags: flags,
		Applied: applied, Unsupported: unsupported}, nil
}

// LockdownStatus reports the kernel arm/latch state, the applied phase set and
// the honestly unsupported phase set.
func (c *CoreClient) LockdownStatus() (CoreLockdownStatus, error) {
	payload, err := c.lockdownCommand("LOCKDOWN_STATUS")
	if err != nil {
		return CoreLockdownStatus{}, err
	}
	return parseCoreLockdownStatus(payload)
}

// LockdownTrigger asks the core to execute the kernel-side phases (§6).
func (c *CoreClient) LockdownTrigger(source, reason string, flags uint8) (CoreLockdownTriggerResult, error) {
	sourceToken, err := lockdownSourceToken(source)
	if err != nil {
		return CoreLockdownTriggerResult{}, err
	}
	reasonToken, err := lockdownReasonToken(reason)
	if err != nil {
		return CoreLockdownTriggerResult{}, err
	}
	payload, err := c.lockdownCommand("LOCKDOWN_TRIGGER", sourceToken, reasonToken, strconv.FormatUint(uint64(flags), 10))
	if err != nil {
		return CoreLockdownTriggerResult{}, err
	}
	return parseCoreLockdownTrigger(payload)
}

// LockdownClear releases the kernel-side lockdown with compare-set semantics:
// an expected_epoch that no longer matches the core is rejected by the core
// (ERR) and the caller must stay latched.
func (c *CoreClient) LockdownClear(expectedEpoch, reason string) (string, error) {
	if !validLockdownEpoch(expectedEpoch) {
		return "", errors.New("lockdown clear epoch must be 8 hex characters")
	}
	reasonToken, err := lockdownReasonToken(reason)
	if err != nil {
		return "", err
	}
	payload, err := c.lockdownCommand("LOCKDOWN_CLEAR", expectedEpoch, reasonToken)
	if err != nil {
		return "", err
	}
	if payload != "cleared" && payload != "already-off" {
		return "", errors.New("core returned an unexpected lockdown clear answer")
	}
	return payload, nil
}
