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
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	coreProtocol                          = "VGT3"
	maxCoreResponseBytes                  = 4096
	maxCoreIngressEventsPerResponse       = 12
	cellLSMDenyNonUnixSocket        uint8 = 1
)

type CoreClient struct {
	socket string
	// timeoutNanos is read on every command, so it is held in an atomic rather
	// than behind a mutex on the IPC hot path. The administrable System namespace
	// can retune it without a restart.
	timeoutNanos atomic.Int64
	key          []byte
}

type CoreExecEvent struct {
	PID  int
	UID  uint32
	GID  uint32
	Comm string
}

type CoreIngressEvent struct {
	Family       uint8
	Protocol     uint8
	TCPFlags     uint8
	AttemptCount uint8
	SrcPort      uint16
	DstPort      uint16
	Packets      uint32
	Bytes        uint32
	SYNCount     uint32
	ACKCount     uint32
	WindowEpoch  uint64
	Source       net.IP
	Destination  net.IP
}

type CoreIngressHealth struct {
	EventsEmitted       uint64
	RingDrops           uint64
	TrackInsertFailures uint64
	// Mode names the hook that is actually enforcing ingress: "native" for XDP in the
	// driver path, "generic" for XDP in the generic path, and "tc-ingress" when neither
	// was available and the kernel enforces at the traffic-control layer instead. The
	// core decides this at attach time and it is the only honest answer to whether this
	// host's hardware is doing the work.
	//
	// Empty means the core is older than the field, which is reported as unknown rather
	// than assumed to be native.
	Mode string
}

type CoreEgressDropEvent struct {
	PID         int
	UID         uint32
	Family      uint8
	Protocol    uint8
	Destination net.IP
	Comm        string
}

type CoreCellLSMDenyEvent struct {
	CgroupID uint64
	PID      int
	UID      uint32
	Family   int32
}

type CoreMalwareEvent struct {
	PID            int
	UID            uint32
	Path           string
	State          string
	Reason         string
	SHA256         string
	Size           uint64
	Classification string
}

type CoreMalwareEventBatch struct {
	Dropped uint64
	Events  []CoreMalwareEvent
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
	if err != nil || len(payload) > 2048 {
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

func syncCoreAllowlist(core *CoreClient, targets []string) error {
	if core == nil {
		return errors.New("core client is unavailable")
	}
	if len(targets) == 0 {
		return errors.New("management allowlist is empty")
	}
	for _, target := range targets {
		if err := core.AllowAdd(target); err != nil {
			return fmt.Errorf("allowlist synchronization failed for %s: %w", target, err)
		}
	}
	return nil
}

func (c *CoreClient) AllowAdd(target string) error {
	_, err := c.command("ALLOW_ADD", target)
	return err
}
func (c *CoreClient) AllowDelete(target string) error {
	_, err := c.command("ALLOW_DEL", target)
	return err
}

func (c *CoreClient) Ping() (string, error)      { return c.command("PING") }
func (c *CoreClient) Add(target string) error    { _, err := c.command("ADD", target); return err }
func (c *CoreClient) Delete(target string) error { _, err := c.command("DEL", target); return err }
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
func (c *CoreClient) Stop(pid int, startTicks uint64, rule string) error {
	_, err := c.command("XDR_STOP", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	return err
}
func (c *CoreClient) Resume(pid int, startTicks uint64, rule string) error {
	_, err := c.command("XDR_CONT", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	return err
}
func (c *CoreClient) Kill(pid int, startTicks uint64, rule string) error {
	_, err := c.command("XDR_KILL", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	return err
}

// CoreActionDispatcher implementation
func (c *CoreClient) BlockIP(ip string) error {
	return c.Add(ip)
}

func (c *CoreClient) UnblockIP(ip string) error {
	return c.Delete(ip)
}

func (c *CoreClient) FreezeProcess(pid int, startTicks uint64, reason string) error {
	return c.Stop(pid, startTicks, reason)
}

func (c *CoreClient) UnfreezeProcess(pid int, startTicks uint64) error {
	return c.Resume(pid, startTicks, "RESPONSE_TTL_ROLLBACK")
}

func (c *CoreClient) SetCellPolicy(cgroupID uint64, flags uint8) error {
	return c.CellPolicySet(cgroupID, flags)
}

func (c *CoreClient) DeleteCellPolicy(cgroupID uint64) error {
	return c.CellPolicyDelete(cgroupID)
}

func (c *CoreClient) ExecEvents() ([]CoreExecEvent, error) {
	response, err := c.command("EXEC_EVENTS")
	if err != nil {
		return nil, err
	}
	return parseCoreExecEvents(response)
}

func parseCoreExecEvents(response string) ([]CoreExecEvent, error) {
	if response == "empty" {
		return nil, nil
	}
	records := strings.Split(response, ",")
	if len(records) > 24 {
		return nil, errors.New("core returned too many exec events")
	}
	events := make([]CoreExecEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 4 {
			return nil, errors.New("core returned malformed exec event")
		}
		pid64, pidErr := strconv.ParseInt(fields[0], 10, 32)
		uid64, uidErr := strconv.ParseUint(fields[1], 10, 32)
		gid64, gidErr := strconv.ParseUint(fields[2], 10, 32)
		comm, commErr := hex.DecodeString(fields[3])
		if pidErr != nil || uidErr != nil || gidErr != nil || commErr != nil ||
			pid64 <= 0 || len(comm) > 16 || strings.ContainsRune(string(comm), '\x00') {
			return nil, errors.New("core returned invalid exec event fields")
		}
		events = append(events, CoreExecEvent{
			PID:  int(pid64),
			UID:  uint32(uid64),
			GID:  uint32(gid64),
			Comm: string(comm),
		})
	}
	return events, nil
}

func (c *CoreClient) IngressEvents() ([]CoreIngressEvent, error) {
	response, err := c.command("INGRESS_EVENTS")
	if err != nil {
		return nil, err
	}
	return parseCoreIngressEvents(response)
}

func (c *CoreClient) IngressHealth() (CoreIngressHealth, error) {
	response, err := c.command("INGRESS_HEALTH")
	if err != nil {
		return CoreIngressHealth{}, err
	}
	return parseCoreIngressHealth(response)
}

func parseCoreIngressHealth(response string) (CoreIngressHealth, error) {
	fields := strings.Split(response, ":")
	// Three fields before the enforcement mode was reported, four after. Both are
	// accepted so a newer control plane can talk to an older core and the reverse: a
	// version mismatch must not read as a broken kernel.
	if len(fields) != 3 && len(fields) != 4 {
		return CoreIngressHealth{}, errors.New("core returned malformed ingress health")
	}
	emitted, err1 := strconv.ParseUint(fields[0], 10, 64)
	ringDrops, err2 := strconv.ParseUint(fields[1], 10, 64)
	trackFailures, err3 := strconv.ParseUint(fields[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return CoreIngressHealth{}, errors.New("core returned invalid ingress health counters")
	}
	mode := ""
	if len(fields) == 4 {
		mode = normalizeIngressMode(fields[3])
	}
	return CoreIngressHealth{
		EventsEmitted: emitted, RingDrops: ringDrops, TrackInsertFailures: trackFailures,
		Mode: mode,
	}, nil
}

// normalizeIngressMode maps the core's own spelling onto the vocabulary the interface
// uses. An unrecognised value is preserved verbatim rather than dropped: if a future core
// reports a mode this build does not know, the operator should see it, not "unknown".
func normalizeIngressMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "native":
		return "NATIVE_XDP"
	case "generic":
		return "GENERIC_XDP"
	case "tc-ingress", "tc":
		return "TC_INGRESS"
	case "":
		return ""
	default:
		return strings.ToUpper(strings.TrimSpace(raw))
	}
}

func parseCoreIngressEvents(response string) ([]CoreIngressEvent, error) {
	if response == "empty" {
		return nil, nil
	}
	records := strings.Split(response, ",")
	if len(records) > maxCoreIngressEventsPerResponse {
		return nil, errors.New("core returned too many ingress events")
	}
	events := make([]CoreIngressEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 13 {
			return nil, errors.New("core returned malformed ingress event")
		}
		family64, familyErr := strconv.ParseUint(fields[0], 10, 8)
		protocol64, protocolErr := strconv.ParseUint(fields[1], 10, 8)
		flags64, flagsErr := strconv.ParseUint(fields[2], 10, 8)
		attempt64, attemptErr := strconv.ParseUint(fields[3], 10, 8)
		srcPort64, srcPortErr := strconv.ParseUint(fields[4], 10, 16)
		dstPort64, dstPortErr := strconv.ParseUint(fields[5], 10, 16)
		packets64, packetsErr := strconv.ParseUint(fields[6], 10, 32)
		bytes64, bytesErr := strconv.ParseUint(fields[7], 10, 32)
		syn64, synErr := strconv.ParseUint(fields[8], 10, 32)
		ack64, ackErr := strconv.ParseUint(fields[9], 10, 32)
		windowEpoch, epochErr := strconv.ParseUint(fields[10], 10, 64)
		source, sourceErr := hex.DecodeString(fields[11])
		destination, destinationErr := hex.DecodeString(fields[12])
		family := uint8(family64)
		expectedAddressBytes := 16
		if family == 4 {
			expectedAddressBytes = 4
		}
		if familyErr != nil || protocolErr != nil || flagsErr != nil || attemptErr != nil || srcPortErr != nil ||
			dstPortErr != nil || packetsErr != nil || bytesErr != nil || synErr != nil || ackErr != nil || epochErr != nil ||
			sourceErr != nil || destinationErr != nil || (family != 4 && family != 6) ||
			packets64 == 0 || syn64 > packets64 || ack64 > packets64 || attempt64 > packets64 ||
			(protocol64 == 6 && attempt64 != syn64) || windowEpoch == 0 || len(source) != expectedAddressBytes ||
			len(destination) != expectedAddressBytes {
			return nil, errors.New("core returned invalid ingress event fields")
		}
		srcIP := make(net.IP, len(source))
		dstIP := make(net.IP, len(destination))
		copy(srcIP, source)
		copy(dstIP, destination)
		events = append(events, CoreIngressEvent{
			Family: family, Protocol: uint8(protocol64), TCPFlags: uint8(flags64), AttemptCount: uint8(attempt64),
			SrcPort: uint16(srcPort64), DstPort: uint16(dstPort64),
			Packets: uint32(packets64), Bytes: uint32(bytes64), SYNCount: uint32(syn64), ACKCount: uint32(ack64),
			WindowEpoch: windowEpoch, Source: srcIP, Destination: dstIP,
		})
	}
	return events, nil
}

func (c *CoreClient) EgressEvents() ([]CoreEgressDropEvent, error) {
	response, err := c.command("EGRESS_EVENTS")
	if err != nil {
		return nil, err
	}
	return parseCoreEgressDropEvents(response)
}

func parseCoreEgressDropEvents(response string) ([]CoreEgressDropEvent, error) {
	if response == "empty" {
		return nil, nil
	}
	records := strings.Split(response, ",")
	if len(records) > 24 {
		return nil, errors.New("core returned too many egress events")
	}
	events := make([]CoreEgressDropEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 6 {
			return nil, errors.New("core returned malformed egress event")
		}
		pid64, pidErr := strconv.ParseUint(fields[0], 10, 32)
		uid64, uidErr := strconv.ParseUint(fields[1], 10, 32)
		family64, familyErr := strconv.ParseUint(fields[2], 10, 8)
		protocol64, protocolErr := strconv.ParseUint(fields[3], 10, 8)
		address, addressErr := hex.DecodeString(fields[4])
		comm, commErr := hex.DecodeString(fields[5])
		family := uint8(family64)
		expectedAddressBytes := 16
		if family == 4 {
			expectedAddressBytes = 4
		}
		if pidErr != nil || uidErr != nil || familyErr != nil || protocolErr != nil ||
			addressErr != nil || commErr != nil || (family != 4 && family != 6) ||
			len(address) != expectedAddressBytes || len(comm) > 16 ||
			strings.ContainsRune(string(comm), '\x00') {
			return nil, errors.New("core returned invalid egress event fields")
		}
		destination := make(net.IP, len(address))
		copy(destination, address)
		events = append(events, CoreEgressDropEvent{
			PID:         int(pid64),
			UID:         uint32(uid64),
			Family:      family,
			Protocol:    uint8(protocol64),
			Destination: destination,
			Comm:        string(comm),
		})
	}
	return events, nil
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

func parseCoreCellLSMDenyEvents(response string) ([]CoreCellLSMDenyEvent, error) {
	if response == "empty" {
		return nil, nil
	}
	records := strings.Split(response, ",")
	if len(records) > 24 {
		return nil, errors.New("core returned too many Cell LSM events")
	}
	events := make([]CoreCellLSMDenyEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 4 {
			return nil, errors.New("core returned a malformed Cell LSM event")
		}
		cgroupID, cgroupErr := strconv.ParseUint(fields[0], 10, 64)
		pid64, pidErr := strconv.ParseInt(fields[1], 10, 32)
		uid64, uidErr := strconv.ParseUint(fields[2], 10, 32)
		family64, familyErr := strconv.ParseInt(fields[3], 10, 32)
		if cgroupErr != nil || pidErr != nil || uidErr != nil || familyErr != nil ||
			cgroupID == 0 || pid64 <= 0 || family64 <= 0 || family64 > 255 || family64 == syscall.AF_UNIX {
			return nil, errors.New("core returned invalid Cell LSM event fields")
		}
		events = append(events, CoreCellLSMDenyEvent{
			CgroupID: cgroupID,
			PID:      int(pid64),
			UID:      uint32(uid64),
			Family:   int32(family64),
		})
	}
	return events, nil
}

func (c *CoreClient) MalwareEvents() (CoreMalwareEventBatch, error) {
	response, err := c.command("MALWARE_EVENTS")
	if err != nil {
		return CoreMalwareEventBatch{}, err
	}
	return parseCoreMalwareEvents(response)
}

func parseCoreMalwareEvents(response string) (CoreMalwareEventBatch, error) {
	if response == "empty" {
		return CoreMalwareEventBatch{}, nil
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return CoreMalwareEventBatch{}, errors.New("core returned malformed malware event batch")
	}
	dropped, err := strconv.ParseUint(droppedText, 10, 64)
	if err != nil {
		return CoreMalwareEventBatch{}, errors.New("core returned invalid malware event drop count")
	}
	batch := CoreMalwareEventBatch{Dropped: dropped}
	if recordsText == "" {
		return batch, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > 4 {
		return CoreMalwareEventBatch{}, errors.New("core returned too many malware events")
	}
	batch.Events = make([]CoreMalwareEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 8 {
			return CoreMalwareEventBatch{}, errors.New("core returned malformed malware event")
		}
		pid64, pidErr := strconv.ParseInt(fields[0], 10, 32)
		uid64, uidErr := strconv.ParseUint(fields[1], 10, 32)
		size, sizeErr := strconv.ParseUint(fields[6], 10, 64)
		digest, digestErr := hex.DecodeString(fields[5])
		stateOK := fields[3] == "malicious" || fields[3] == "suspicious" || fields[3] == "blocked"
		if pidErr != nil || uidErr != nil || sizeErr != nil || digestErr != nil || pid64 <= 0 ||
			len(digest) != sha256.Size || size > 256<<20 || !stateOK ||
			!validMalwareEventLabel(fields[4], 96) || !validMalwareEventLabel(fields[7], 32) {
			return CoreMalwareEventBatch{}, errors.New("core returned invalid malware event fields")
		}
		path := "unknown"
		if fields[2] != "-" {
			decoded, decodeErr := base64.RawURLEncoding.DecodeString(fields[2])
			if decodeErr != nil || len(decoded) == 0 || len(decoded) > 192 || !utf8.Valid(decoded) || !filepath.IsAbs(string(decoded)) ||
				strings.IndexFunc(string(decoded), func(value rune) bool { return value < 0x20 || value == 0x7f }) >= 0 {
				return CoreMalwareEventBatch{}, errors.New("core returned invalid malware event path")
			}
			path = string(decoded)
		}
		batch.Events = append(batch.Events, CoreMalwareEvent{
			PID: int(pid64), UID: uint32(uid64), Path: path, State: fields[3], Reason: fields[4],
			SHA256: fields[5], Size: size, Classification: fields[7],
		})
	}
	return batch, nil
}

func validMalwareEventLabel(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validSysctlToken(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func (c *CoreClient) SysctlGet(key string) (string, error) {
	if !validSysctlKey(key) {
		return "", errors.New("invalid sysctl key")
	}
	value, err := c.command("SYSCTL_GET", key)
	if err != nil {
		return "", err
	}
	if !validSysctlToken(value) {
		return "", errors.New("core returned an invalid sysctl value")
	}
	return value, nil
}

func (c *CoreClient) SysctlCompareSet(key, expected, desired string) error {
	if !validSysctlKey(key) || !validSysctlToken(expected) || !validSysctlToken(desired) {
		return errors.New("invalid sysctl compare-set request")
	}
	state, err := c.command("SYSCTL_SET", key, expected, desired)
	if err != nil {
		return err
	}
	if state != desired {
		return fmt.Errorf("core returned unexpected sysctl state %q", state)
	}
	return nil
}

func validHardeningState(value string) bool {
	switch value {
	case "absent", "linux-server-balanced", "astraeaos-workstation-strict":
		return true
	}
	const prefix = "astraeaos-custom-"
	if len(value) != len(prefix)+4 || !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 16, 16)
	return err == nil && decoded > 0 && decoded&^uint64(0x03ff) == 0
}

func (c *CoreClient) HardeningProfileState() (string, error) {
	state, err := c.command("HARDENING_GET")
	if err != nil {
		return "", err
	}
	if !validHardeningState(state) {
		return "", errors.New("core returned an invalid persistent hardening state")
	}
	return state, nil
}

func (c *CoreClient) HardeningProfileCompareSet(expected, desired string) error {
	if !validHardeningState(expected) || !validHardeningState(desired) {
		return errors.New("invalid persistent hardening compare-set request")
	}
	state, err := c.command("HARDENING_SET", expected, desired)
	if err != nil {
		return err
	}
	if state != desired {
		return fmt.Errorf("core returned unexpected persistent hardening state %q", state)
	}
	return nil
}

func validSysctlKey(key string) bool {
	if key == "" || len(key) > 96 || strings.HasPrefix(key, ".") || strings.HasSuffix(key, ".") {
		return false
	}
	for _, character := range key {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '.' {
			return false
		}
	}
	return true
}

type QuarantineIdentity struct {
	Size          uint64 `json:"size"`
	Mode          uint32 `json:"mode"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	ModifiedNanos int64  `json:"modified_nanos"`
	SHA256        string `json:"sha256"`
}

func (identity QuarantineIdentity) protocolToken() (string, error) {
	if err := validateQuarantineIdentity(identity); err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"v1:%d:%d:%d:%d:%d:%d:%d:%s",
		identity.Size,
		identity.Mode,
		identity.UID,
		identity.GID,
		identity.Device,
		identity.Inode,
		identity.ModifiedNanos,
		identity.SHA256,
	), nil
}

func parseQuarantineIdentity(value string) (QuarantineIdentity, error) {
	fields := strings.Split(value, ":")
	if len(fields) != 9 || fields[0] != "v1" {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine identity")
	}
	parseUint := func(index, bits int) (uint64, error) {
		return strconv.ParseUint(fields[index], 10, bits)
	}
	size, err := parseUint(1, 64)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine size")
	}
	mode, err := parseUint(2, 32)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine mode")
	}
	uid, err := parseUint(3, 32)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine uid")
	}
	gid, err := parseUint(4, 32)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine gid")
	}
	device, err := parseUint(5, 64)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine device")
	}
	inode, err := parseUint(6, 64)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine inode")
	}
	modifiedNanos, err := strconv.ParseInt(fields[7], 10, 64)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine timestamp")
	}
	identity := QuarantineIdentity{
		Size: size, Mode: uint32(mode), UID: uint32(uid), GID: uint32(gid),
		Device: device, Inode: inode, ModifiedNanos: modifiedNanos,
		SHA256: fields[8],
	}
	if err := validateQuarantineIdentity(identity); err != nil {
		return QuarantineIdentity{}, err
	}
	return identity, nil
}

func validateQuarantineIdentity(identity QuarantineIdentity) error {
	if identity.Size > 256<<20 || identity.Mode > 0o7777 ||
		len(identity.SHA256) != sha256.Size*2 {
		return errors.New("quarantine identity violates typed bounds")
	}
	digest, err := hex.DecodeString(identity.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("quarantine identity digest is invalid")
	}
	return nil
}

func validQuarantineObjectID(value string) bool {
	if len(value) != 19 || !strings.HasPrefix(value, "QV-") {
		return false
	}
	for _, character := range value[3:] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func quarantinePathToken(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		len(path) == 0 || len(path) > 2048 || strings.ContainsRune(path, '\x00') {
		return "", errors.New("quarantine path is invalid")
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(path))
	if !protocolFieldValid(token) {
		return "", errors.New("quarantine path token exceeds protocol bounds")
	}
	return token, nil
}

type MalwareScanResult struct {
	State          string `json:"state"`
	Reason         string `json:"reason"`
	SHA256         string `json:"sha256"`
	Size           uint64 `json:"size"`
	Classification string `json:"classification"`
}

func parseMalwareScanResult(value string) (MalwareScanResult, error) {
	fields := strings.Split(value, ":")
	if len(fields) != 5 || (fields[0] != "clean" && fields[0] != "suspicious" && fields[0] != "malicious") ||
		len(fields[1]) == 0 || len(fields[1]) > 96 || len(fields[2]) != sha256.Size*2 || len(fields[4]) == 0 || len(fields[4]) > 32 {
		return MalwareScanResult{}, errors.New("core returned malformed malware scan result")
	}
	for _, value := range []string{fields[1], fields[4]} {
		for _, character := range value {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
				return MalwareScanResult{}, errors.New("core returned unsafe malware scan fields")
			}
		}
	}
	digest, digestErr := hex.DecodeString(fields[2])
	size, sizeErr := strconv.ParseUint(fields[3], 10, 64)
	if digestErr != nil || len(digest) != sha256.Size || sizeErr != nil || size > 256<<20 {
		return MalwareScanResult{}, errors.New("core returned invalid malware scan bounds")
	}
	return MalwareScanResult{State: fields[0], Reason: fields[1], SHA256: fields[2], Size: size, Classification: fields[4]}, nil
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

func (c *CoreClient) MalwareScan(path string) (MalwareScanResult, error) {
	if err := validateQuarantinePathBuiltin(path); err != nil {
		return MalwareScanResult{}, errors.New("malware scan path is outside the permitted boundary")
	}
	token, err := quarantinePathToken(path)
	if err != nil {
		return MalwareScanResult{}, err
	}
	value, err := c.command("MALWARE_SCAN", token)
	if err != nil {
		return MalwareScanResult{}, err
	}
	return parseMalwareScanResult(value)
}

func (c *CoreClient) QuarantineInspect(path string) (QuarantineIdentity, error) {
	token, err := quarantinePathToken(path)
	if err != nil {
		return QuarantineIdentity{}, err
	}
	value, err := c.command("QUARANTINE_INSPECT", token)
	if err != nil {
		return QuarantineIdentity{}, err
	}
	return parseQuarantineIdentity(value)
}

func (c *CoreClient) QuarantineApply(
	path, objectID string,
	identity QuarantineIdentity,
) error {
	token, err := quarantinePathToken(path)
	if err != nil {
		return err
	}
	if !validQuarantineObjectID(objectID) {
		return errors.New("quarantine object ID is invalid")
	}
	identityToken, err := identity.protocolToken()
	if err != nil {
		return err
	}
	state, err := c.command("QUARANTINE_APPLY", token, objectID, identityToken)
	if err != nil {
		return err
	}
	return verifyQuarantineIdentityResponse(state, identity)
}

func (c *CoreClient) QuarantineVerify(
	objectID string,
	identity QuarantineIdentity,
) error {
	if !validQuarantineObjectID(objectID) {
		return errors.New("quarantine object ID is invalid")
	}
	identityToken, err := identity.protocolToken()
	if err != nil {
		return err
	}
	state, err := c.command("QUARANTINE_VERIFY", objectID, identityToken)
	if err != nil {
		return err
	}
	if state != "verified" {
		return errors.New("core returned an invalid quarantine verification state")
	}
	return nil
}

func (c *CoreClient) QuarantineRestore(
	path, objectID string,
	identity QuarantineIdentity,
) error {
	token, err := quarantinePathToken(path)
	if err != nil {
		return err
	}
	if !validQuarantineObjectID(objectID) {
		return errors.New("quarantine object ID is invalid")
	}
	identityToken, err := identity.protocolToken()
	if err != nil {
		return err
	}
	state, err := c.command("QUARANTINE_RESTORE", token, objectID, identityToken)
	if err != nil {
		return err
	}
	if state != "restored" {
		return errors.New("core returned an invalid quarantine restore state")
	}
	return nil
}

func verifyQuarantineIdentityResponse(
	value string,
	expected QuarantineIdentity,
) error {
	actual, err := parseQuarantineIdentity(value)
	if err != nil {
		return err
	}
	expectedToken, err := expected.protocolToken()
	if err != nil {
		return err
	}
	actualToken, err := actual.protocolToken()
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(actualToken), []byte(expectedToken)) {
		return errors.New("core returned a mismatched quarantine identity")
	}
	return nil
}

// ------------------------------------------------------------------ canaries
//
// The privileged core owns decoy deployment and the fanotify sensor because the
// unprivileged control plane can neither create files outside its sandbox nor
// observe host accesses. All values crossing this boundary are typed, bounded
// and encoded; the core re-validates every one of them.

const (
	maxCanaryPathBytes     = 256
	maxCanaryContentBytes  = 1024
	maxCanaryEventsPerPoll = 64
)

var canaryTypes = map[string]bool{
	string(CanarySSHKey):    true,
	string(CanaryCloudCred): true,
	string(CanaryShadow):    true,
	string(CanaryDotEnv):    true,
}

func validCanaryTargetPath(path string) bool {
	if path == "" || len(path) > maxCanaryPathBytes || strings.ContainsRune(path, '\x00') {
		return false
	}
	if !filepath.IsAbs(path) || path == "/" || filepath.Clean(path) != path {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

// CanaryDeploy creates one decoy through the privileged broker. The broker
// writes it atomically inside a validated canary root and installs the fanotify
// mark before the call returns; a watcher that cannot be armed fails the
// deployment instead of leaving an unmonitored decoy behind.
func (c *CoreClient) CanaryDeploy(path, canaryType string, mode uint32, content []byte) error {
	if !validCanaryTargetPath(path) {
		return errors.New("canary path is invalid")
	}
	if !canaryTypes[canaryType] {
		return errors.New("canary type is invalid")
	}
	if mode != 0o600 && mode != 0o640 {
		return errors.New("canary file mode must be 0600 or 0640")
	}
	if len(content) == 0 || len(content) > maxCanaryContentBytes || strings.IndexByte(string(content), 0) >= 0 {
		return errors.New("canary content is outside the accepted bounds")
	}
	pathToken := base64.RawURLEncoding.EncodeToString([]byte(path))
	contentToken := base64.RawURLEncoding.EncodeToString(content)
	response, err := c.command("CANARY_DEPLOY", pathToken, canaryType, strconv.FormatUint(uint64(mode), 8), contentToken)
	if err != nil {
		return err
	}
	if response != "deployed" && response != "exists" {
		return fmt.Errorf("core returned an invalid canary deploy state %q", response)
	}
	return nil
}

// CanaryRemove removes one registered decoy inside the canary jail. A missing
// decoy reports "absent", which is not an error (the policy may be converging).
func (c *CoreClient) CanaryRemove(path string) error {
	if !validCanaryTargetPath(path) {
		return errors.New("canary path is invalid")
	}
	pathToken := base64.RawURLEncoding.EncodeToString([]byte(path))
	response, err := c.command("CANARY_REMOVE", pathToken)
	if err != nil {
		return err
	}
	if response != "removed" && response != "absent" {
		return fmt.Errorf("core returned an invalid canary removal state %q", response)
	}
	return nil
}

// CanaryEvents drains at most four bounded access events per poll.
func (c *CoreClient) CanaryEvents() (CanaryEventBatch, error) {
	response, err := c.command("CANARY_EVENTS")
	if err != nil {
		return CanaryEventBatch{}, err
	}
	return parseCanaryEvents(response)
}

func parseCanaryEvents(response string) (CanaryEventBatch, error) {
	batch := CanaryEventBatch{}
	if response == "empty" {
		return batch, nil
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return CanaryEventBatch{}, errors.New("core returned malformed canary event batch")
	}
	dropped, err := strconv.ParseUint(droppedText, 10, 64)
	if err != nil {
		return CanaryEventBatch{}, errors.New("core returned invalid canary drop count")
	}
	batch.Dropped = dropped
	if recordsText == "" {
		return batch, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxCanaryEventsPerPoll {
		return CanaryEventBatch{}, errors.New("core returned too many canary events")
	}
	batch.Events = make([]CanaryAccessEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 5 {
			return CanaryEventBatch{}, errors.New("core returned malformed canary event")
		}
		pid, pidErr := strconv.ParseInt(fields[0], 10, 32)
		uid, uidErr := strconv.ParseUint(fields[1], 10, 32)
		execFlag, execErr := strconv.ParseUint(fields[4], 10, 8)
		rawPath, pathErr := base64.RawURLEncoding.DecodeString(fields[2])
		if pidErr != nil || uidErr != nil || execErr != nil || pathErr != nil ||
			pid <= 0 || execFlag > 1 || !canaryTypes[fields[3]] ||
			len(rawPath) == 0 || len(rawPath) > maxCanaryPathBytes || !validCanaryTargetPath(string(rawPath)) {
			return CanaryEventBatch{}, errors.New("core returned invalid canary event fields")
		}
		batch.Events = append(batch.Events, CanaryAccessEvent{
			PID:  int(pid),
			UID:  uint32(uid),
			Path: string(rawPath),
			Type: fields[3],
			Exec: execFlag == 1,
		})
	}
	return batch, nil
}

// CanaryStatus reports bounded broker sensor health (no paths, no content).
func (c *CoreClient) CanaryStatus() (CanaryBrokerStatus, error) {
	response, err := c.command("CANARY_STATUS")
	if err != nil {
		return CanaryBrokerStatus{}, err
	}
	return parseCanaryBrokerStatus(response)
}

func parseCanaryBrokerStatus(response string) (CanaryBrokerStatus, error) {
	status := CanaryBrokerStatus{}
	fields := strings.Split(strings.TrimSpace(response), ":")
	if len(fields) != 7 {
		return CanaryBrokerStatus{}, errors.New("core returned malformed canary status")
	}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "" || value == "" {
			return CanaryBrokerStatus{}, errors.New("core returned malformed canary status field")
		}
		values[key] = value
	}
	parseInt := func(key string, bits int) (uint64, error) {
		raw, exists := values[key]
		if !exists {
			return 0, fmt.Errorf("core canary status lacks %q", key)
		}
		return strconv.ParseUint(raw, 10, bits)
	}
	roots, rootErr := parseInt("roots", 32)
	registered, registeredErr := parseInt("registered", 32)
	queued, queuedErr := parseInt("queued", 32)
	dropped, droppedErr := parseInt("dropped", 64)
	markFailures, markErr := parseInt("mark_failures", 64)
	if rootErr != nil || registeredErr != nil || queuedErr != nil || droppedErr != nil || markErr != nil {
		return CanaryBrokerStatus{}, errors.New("core returned invalid canary status counters")
	}
	watcher := values["watcher"]
	if watcher != "active" && watcher != "degraded" {
		return CanaryBrokerStatus{}, errors.New("core returned invalid canary watcher state")
	}
	status = CanaryBrokerStatus{
		Roots:        int(roots),
		Registered:   int(registered),
		Queued:       int(queued),
		Dropped:      dropped,
		MarkFailures: markFailures,
		Watcher:      watcher,
	}
	return status, nil
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
	// maxStyxFlowEventsPerResponse mirrors the core's own batch ceiling. The
	// control plane enforces it independently: a buggy or hostile core must not
	// be able to force unbounded parsing work per poll.
	maxStyxFlowEventsPerResponse = 8
	// maxStyxFlowPayloadBytes bounds the text-wire payload before it is split.
	maxStyxFlowPayloadBytes = 2048
)

// ErrStyxUnavailable marks the backwards-compatible answer of a core that does
// not implement the STYX_* command family yet. It is a capability fact, not an
// XDR degradation.
var ErrStyxUnavailable = errors.New("styx capability unavailable")

// CoreStyxFlowEvent mirrors one decoded STYX_FLOW_EVENTS record (ABI-1 §3.2,
// text wire §3.3). DstIP is normalised the way the kernel normalises it: an
// IPv4 destination is a 4-byte net.IP, an IPv6 destination 16 bytes.
type CoreStyxFlowEvent struct {
	CgroupID    uint64
	TimestampNS uint64
	TxBytes     uint64
	RxBytes     uint64
	PID         int
	UID         uint32
	DstIP       net.IP
	DstPort     uint16
	SrcPort     uint16
	Packets     uint32
	Family      uint8
	Proto       uint8
	Direction   uint8
	TCPFlags    uint8
	Verdict     uint8
	Comm        string
}

// CoreStyxFlowHealth mirrors the fixed six-counter STYX_FLOW_HEALTH payload.
type CoreStyxFlowHealth struct {
	Emitted           uint64
	RingDrops         uint64
	AggInsertFailures uint64
	ParseErrors       uint64
	DropsTotal        uint64
	PolicyDrops       uint64
}

// styxCommand issues one STYX_* command and classifies the backwards-compatible
// "unknown command" rejection as ErrStyxUnavailable.
func (c *CoreClient) styxCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrStyxUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// styxExpect issues a command and requires one exact OK payload from the core.
func (c *CoreClient) styxExpect(expected string, parts ...string) error {
	response, err := c.styxCommand(parts...)
	if err != nil {
		return err
	}
	if response != expected {
		return fmt.Errorf("core returned unexpected styx state %q", response)
	}
	return nil
}

func validStyxFamily(family uint8) bool {
	return family == 4 || family == 6
}

// styxCanonicalCIDR validates one block/allow/resolver target the way the core
// does: family-correct, canonical (host bits zero), no whitespace or NUL, and
// never an IPv4-mapped IPv6 form (the kernel would have to unmap it, and a
// mismatch here is exactly the kind of bypass §6.3 documents).
func styxCanonicalCIDR(family uint8, cidr string) (string, error) {
	if !validStyxFamily(family) {
		return "", errors.New("styx family must be 4 or 6")
	}
	if cidr == "" || len(cidr) > 128 || strings.ContainsAny(cidr, " \t\r\n\x00") {
		return "", errors.New("styx cidr contains rejected characters")
	}
	var addr netip.Addr
	prefixBits := 128
	if family == 4 {
		prefixBits = 32
	}
	if strings.Contains(cidr, "/") {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return "", errors.New("styx cidr is not a valid prefix")
		}
		if prefix != prefix.Masked() {
			return "", errors.New("styx cidr is not canonical")
		}
		addr = prefix.Addr()
		prefixBits = prefix.Bits()
	} else {
		parsed, err := netip.ParseAddr(cidr)
		if err != nil {
			return "", errors.New("styx cidr is not a valid address")
		}
		addr = parsed
	}
	if addr.Is4In6() {
		return "", errors.New("styx cidr must not be an IPv4-mapped IPv6 address")
	}
	if family == 4 {
		if !addr.Is4() {
			return "", errors.New("styx cidr family mismatch")
		}
		if prefixBits < 4 || prefixBits > 32 {
			return "", errors.New("styx cidr prefix length out of range")
		}
	} else {
		if !addr.Is6() {
			return "", errors.New("styx cidr family mismatch")
		}
		if prefixBits < 8 || prefixBits > 128 {
			return "", errors.New("styx cidr prefix length out of range")
		}
	}
	if addr.IsUnspecified() {
		return "", errors.New("styx cidr is unspecified")
	}
	return netip.PrefixFrom(addr, prefixBits).String(), nil
}

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

// StyxCapabilities is the capability gate from §8.1: it reports the advertised
// version and ErrStyxUnavailable for a core without the command family.
func (c *CoreClient) StyxCapabilities() (string, error) {
	return c.StyxVersion()
}

// StyxEpoch returns the 16-hex-character epoch that changes on every core start.
func (c *CoreClient) StyxEpoch() (string, error) {
	epoch, err := c.styxCommand("STYX_EPOCH")
	if err != nil {
		return "", err
	}
	if len(epoch) != 16 || !validStyxHexText(epoch) {
		return "", errors.New("core returned an invalid styx epoch")
	}
	return strings.ToLower(epoch), nil
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

// StyxModeDel removes one per-cgroup mode entry (idempotent on the core).
func (c *CoreClient) StyxModeDel(cgroupID uint64) error {
	if cgroupID == 0 {
		return errors.New("styx mode cgroup id is invalid")
	}
	return c.styxExpect("deleted", "STYX_MODE_DEL", strconv.FormatUint(cgroupID, 10))
}

func (c *CoreClient) styxAllow(verb, expected string, family uint8, scope string, cgroupID uint64, cidr string, portLo, portHi uint16, protoMask uint8) error {
	canonical, err := styxCanonicalCIDR(family, cidr)
	if err != nil {
		return err
	}
	switch scope {
	case "cell":
		if cgroupID == 0 {
			return errors.New("styx cell scope requires a cgroup id")
		}
	case "global":
		if cgroupID != 0 {
			return errors.New("styx global scope must not carry a cgroup id")
		}
	default:
		return errors.New("styx scope must be cell or global")
	}
	if portLo > portHi {
		return errors.New("styx port range is inverted")
	}
	if protoMask > 3 {
		return errors.New("styx proto mask is out of range")
	}
	return c.styxExpect(expected, verb,
		strconv.FormatUint(uint64(family), 10), scope, strconv.FormatUint(cgroupID, 10), canonical,
		strconv.FormatUint(uint64(portLo), 10), strconv.FormatUint(uint64(portHi), 10),
		strconv.FormatUint(uint64(protoMask), 10))
}

// StyxAllowAdd adds one allowlist rule (cell or global scope).
func (c *CoreClient) StyxAllowAdd(family uint8, scope string, cgroupID uint64, cidr string, portLo, portHi uint16, protoMask uint8) error {
	return c.styxAllow("STYX_ALLOW_ADD", "added", family, scope, cgroupID, cidr, portLo, portHi, protoMask)
}

// StyxAllowDel removes one allowlist rule.
func (c *CoreClient) StyxAllowDel(family uint8, scope string, cgroupID uint64, cidr string, portLo, portHi uint16, protoMask uint8) error {
	return c.styxAllow("STYX_ALLOW_DEL", "deleted", family, scope, cgroupID, cidr, portLo, portHi, protoMask)
}

func (c *CoreClient) styxCIDROp(verb, expected string, family uint8, cidr string) error {
	canonical, err := styxCanonicalCIDR(family, cidr)
	if err != nil {
		return err
	}
	return c.styxExpect(expected, verb, strconv.FormatUint(uint64(family), 10), canonical)
}

// StyxBlockAdd adds one mandatory-veto block target.
func (c *CoreClient) StyxBlockAdd(family uint8, cidr string) error {
	return c.styxCIDROp("STYX_BLOCK_ADD", "added", family, cidr)
}

// StyxBlockDel removes one mandatory-veto block target.
func (c *CoreClient) StyxBlockDel(family uint8, cidr string) error {
	return c.styxCIDROp("STYX_BLOCK_DEL", "deleted", family, cidr)
}

// StyxResolverAdd adds one DNS/DoT resolver target.
func (c *CoreClient) StyxResolverAdd(family uint8, cidr string) error {
	return c.styxCIDROp("STYX_RESOLVER_ADD", "added", family, cidr)
}

// StyxResolverDel removes one DNS/DoT resolver target.
func (c *CoreClient) StyxResolverDel(family uint8, cidr string) error {
	return c.styxCIDROp("STYX_RESOLVER_DEL", "deleted", family, cidr)
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

// StyxFlowHealth reports the six kernel-side flow counters.
func (c *CoreClient) StyxFlowHealth() (CoreStyxFlowHealth, error) {
	response, err := c.styxCommand("STYX_FLOW_HEALTH")
	if err != nil {
		return CoreStyxFlowHealth{}, err
	}
	return parseCoreStyxFlowHealth(response)
}

func parseStyxUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized styx counter")
	}
	for i := 0; i < len(field); i++ {
		if field[i] < '0' || field[i] > '9' {
			return 0, errors.New("core returned a non-decimal styx counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range styx counter")
	}
	return value, nil
}

func validStyxHexText(field string) bool {
	if len(field) == 0 || len(field)%2 != 0 {
		return false
	}
	for i := 0; i < len(field); i++ {
		character := field[i]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func decodeStyxHex(field string, maxBytes int) ([]byte, error) {
	if len(field) > maxBytes*2 || !validStyxHexText(field) {
		return nil, errors.New("core returned a malformed styx hex field")
	}
	decoded, err := hex.DecodeString(field)
	if err != nil || len(decoded) > maxBytes {
		return nil, errors.New("core returned a malformed styx hex field")
	}
	return decoded, nil
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
		event, err := parseCoreStyxFlowEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

func parseCoreStyxFlowEvent(record string) (CoreStyxFlowEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 16 {
		return CoreStyxFlowEvent{}, errors.New("core returned a malformed styx flow event")
	}
	cgroupBytes, cgroupErr := decodeStyxHex(fields[0], 8)
	tsNS, tsErr := parseStyxUint(fields[1], 64)
	txBytes, txErr := parseStyxUint(fields[2], 64)
	rxBytes, rxErr := parseStyxUint(fields[3], 64)
	pid, pidErr := parseStyxUint(fields[4], 32)
	uid, uidErr := parseStyxUint(fields[5], 32)
	dstPort, dstPortErr := parseStyxUint(fields[7], 16)
	srcPort, srcPortErr := parseStyxUint(fields[8], 16)
	packets, packetsErr := parseStyxUint(fields[9], 32)
	family, familyErr := parseStyxUint(fields[10], 8)
	proto, protoErr := parseStyxUint(fields[11], 8)
	direction, directionErr := parseStyxUint(fields[12], 8)
	tcpFlags, tcpFlagsErr := parseStyxUint(fields[13], 8)
	verdict, verdictErr := parseStyxUint(fields[14], 8)
	if cgroupErr != nil || len(cgroupBytes) != 8 || tsErr != nil || txErr != nil || rxErr != nil ||
		pidErr != nil || uidErr != nil || dstPortErr != nil || srcPortErr != nil || packetsErr != nil ||
		familyErr != nil || protoErr != nil || directionErr != nil || tcpFlagsErr != nil || verdictErr != nil {
		return CoreStyxFlowEvent{}, errors.New("core returned invalid styx flow event fields")
	}
	if family != 4 && family != 6 {
		return CoreStyxFlowEvent{}, errors.New("core returned an invalid styx flow family")
	}
	if proto != 0 && proto != 6 && proto != 17 {
		return CoreStyxFlowEvent{}, errors.New("core returned an invalid styx flow protocol")
	}
	if direction != 1 && direction != 2 {
		return CoreStyxFlowEvent{}, errors.New("core returned an invalid styx flow direction")
	}
	if verdict > 5 || tsNS == 0 || packets == 0 {
		return CoreStyxFlowEvent{}, errors.New("core returned out-of-range styx flow counters")
	}
	// A kernel PID fits a signed 32-bit pid_t; a larger wire value is corruption,
	// not a process. Zero is accepted (a flow aggregate whose first packet had no
	// readable task context stays attributable by cgroup).
	if pid > 1<<31-1 {
		return CoreStyxFlowEvent{}, errors.New("core returned an out-of-range styx flow pid")
	}
	if proto == 0 && (dstPort != 0 || srcPort != 0) {
		return CoreStyxFlowEvent{}, errors.New("core returned styx ports for a neutral protocol")
	}
	if proto != 6 && tcpFlags != 0 {
		return CoreStyxFlowEvent{}, errors.New("core returned TCP flags for a non-TCP flow")
	}
	dstBytes, dstErr := decodeStyxHex(fields[6], 16)
	if dstErr != nil {
		return CoreStyxFlowEvent{}, errors.New("core returned a malformed styx flow destination")
	}
	// Canonical family address: 4 bytes for IPv4, 16 for IPv6. A 16-byte
	// "IPv4" record (e.g. an IPv4-mapped form) is rejected instead of un-mapped,
	// because the canonical form is part of the ABI contract.
	expectedAddressBytes := 16
	if family == 4 {
		expectedAddressBytes = 4
	}
	if len(dstBytes) != expectedAddressBytes {
		return CoreStyxFlowEvent{}, errors.New("core returned a non-canonical styx flow destination")
	}
	dstAddr, addrOK := netip.AddrFromSlice(dstBytes)
	if !addrOK || dstAddr.IsUnspecified() || (family == 4) != dstAddr.Is4() {
		return CoreStyxFlowEvent{}, errors.New("core returned an invalid styx flow destination")
	}
	var comm string
	if fields[15] != "" {
		commBytes, commErr := decodeStyxHex(fields[15], 16)
		if commErr != nil || len(commBytes) == 0 {
			return CoreStyxFlowEvent{}, errors.New("core returned an invalid styx flow comm")
		}
		for _, character := range commBytes {
			if character < 0x20 || character == 0x7f || character == ' ' {
				return CoreStyxFlowEvent{}, errors.New("core returned a styx flow comm with rejected characters")
			}
		}
		comm = string(commBytes)
	}
	return CoreStyxFlowEvent{
		CgroupID: uint64(cgroupBytes[0])<<56 | uint64(cgroupBytes[1])<<48 | uint64(cgroupBytes[2])<<40 | uint64(cgroupBytes[3])<<32 |
			uint64(cgroupBytes[4])<<24 | uint64(cgroupBytes[5])<<16 | uint64(cgroupBytes[6])<<8 | uint64(cgroupBytes[7]),
		TimestampNS: tsNS,
		TxBytes:     txBytes,
		RxBytes:     rxBytes,
		PID:         int(pid),
		UID:         uint32(uid),
		DstIP:       net.IP(dstAddr.AsSlice()),
		DstPort:     uint16(dstPort),
		SrcPort:     uint16(srcPort),
		Packets:     uint32(packets),
		Family:      uint8(family),
		Proto:       uint8(proto),
		Direction:   uint8(direction),
		TCPFlags:    uint8(tcpFlags),
		Verdict:     uint8(verdict),
		Comm:        comm,
	}, nil
}

func parseCoreStyxFlowHealth(response string) (CoreStyxFlowHealth, error) {
	if len(response) > 160 {
		return CoreStyxFlowHealth{}, errors.New("core returned an oversized styx flow health payload")
	}
	fields := strings.Split(response, ":")
	if len(fields) != 6 {
		return CoreStyxFlowHealth{}, errors.New("core returned malformed styx flow health")
	}
	values := make([]uint64, len(fields))
	for i, field := range fields {
		value, err := parseStyxUint(field, 64)
		if err != nil {
			return CoreStyxFlowHealth{}, errors.New("core returned invalid styx flow health counters")
		}
		values[i] = value
	}
	return CoreStyxFlowHealth{
		Emitted:           values[0],
		RingDrops:         values[1],
		AggInsertFailures: values[2],
		ParseErrors:       values[3],
		DropsTotal:        values[4],
		PolicyDrops:       values[5],
	}, nil
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

const (
	// Allowed batch shape (§5): the core decodes at most 256 newline-separated
	// paths and at most 2048 bytes; the control plane refuses anything larger
	// before dialling, so a policy can never fail halfway through a batch.
	titanExecMaxBatchPaths = 200
	titanExecMaxBatchBytes = 2048

	titanExecMaxStatusPayloadBytes = 512
	titanExecMaxHealthPayloadBytes = 160
	titanExecMaxVersionBytes       = 32
)

// ErrTitanExecUnavailable marks the backwards-compatible answer of a core that
// does not implement the TITAN_EXEC_* command family yet. It is a capability fact,
// not an XDR degradation.
var ErrTitanExecUnavailable = errors.New("titan-exec capability unavailable")

// TitanExecAllowIdentity is the parsed ALLOW_ADD answer: the core-resolved kernel
// identity of one allowlisted path. Go never derives this identity itself.
type TitanExecAllowIdentity struct {
	// State is "added" or "exists" (idempotent re-add on a retry).
	State string
	Dev   uint32
	Ino   uint64
}

// TitanExecBatchResult is the parsed ALLOW_ADD_BATCH answer. Error is the core's
// closed error token ("none" on success, a specific reason when Rejected>0); a
// non-zero Rejected count means the sync failed even if some paths were accepted (§5).
type TitanExecBatchResult struct {
	Added    int
	Rejected int
	Error    string
}

// TitanExecCoreStatus is the parsed TITAN_EXEC_STATUS answer (§5). State/Path/LSM/
// Offsets are the kernel-side facts; they are reported verbatim, never inferred.
type TitanExecCoreStatus struct {
	State   string
	Mode    uint8
	Flags   uint8
	Path    string
	LSM     string
	Offsets string
	Entries int
	Scopes  int
	Epoch   string
}

// CoreTitanExecHealth mirrors the fixed six-counter TITAN_EXEC_HEALTH payload.
type CoreTitanExecHealth struct {
	Emitted      uint64
	RingDrops    uint64
	ReadFailures uint64
	Denies       uint64
	Audits       uint64
	CtimeRejects uint64
}

// titanExecCommand issues one TITAN_EXEC_* command and classifies the
// backwards-compatible "unknown command" rejection as ErrTitanExecUnavailable.
func (c *CoreClient) titanExecCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrTitanExecUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// titanExecExpect issues a command and requires one exact OK payload.
func (c *CoreClient) titanExecExpect(expected string, parts ...string) error {
	response, err := c.titanExecCommand(parts...)
	if err != nil {
		return err
	}
	if response != expected {
		return fmt.Errorf("core returned unexpected titan exec state %q", response)
	}
	return nil
}

func titanExecParseUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized titan exec counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal titan exec counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range titan exec counter")
	}
	return value, nil
}

func titanExecValidEpoch(field string) bool {
	if len(field) != 16 {
		return false
	}
	for index := 0; index < len(field); index++ {
		character := field[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

// TitanExecVersion negotiates the TitanExec ABI. A pre-TitanExec core yields
// ErrTitanExecUnavailable.
func (c *CoreClient) TitanExecVersion() (string, error) {
	version, err := c.titanExecCommand("TITAN_EXEC_VERSION")
	if err != nil {
		return "", err
	}
	if len(version) > titanExecMaxVersionBytes || version != titanExecSupportedVersion {
		return "", fmt.Errorf("core returned unsupported titan exec version %q", version)
	}
	return version, nil
}

// TitanExecEpoch returns the 16-hex-character epoch that changes on every core
// start; a changed epoch means the maps were lost and a full re-sync is required.
func (c *CoreClient) TitanExecEpoch() (string, error) {
	epoch, err := c.titanExecCommand("TITAN_EXEC_EPOCH")
	if err != nil {
		return "", err
	}
	if !titanExecValidEpoch(epoch) {
		return "", errors.New("core returned an invalid titan exec epoch")
	}
	return strings.ToLower(epoch), nil
}

// TitanExecStatus reports the kernel-side state, mode and capability facts.
func (c *CoreClient) TitanExecStatus() (TitanExecCoreStatus, error) {
	response, err := c.titanExecCommand("TITAN_EXEC_STATUS")
	if err != nil {
		return TitanExecCoreStatus{}, err
	}
	return parseTitanExecCoreStatus(response)
}

// TitanExecSetGlobal applies the host-wide mode (0..3) and the REQUIRE_CTIME flag.
// The core answers with Err "enforcement-unavailable" when mode>0 and the BPF-LSM
// hook is not attached; the caller reports that as inactive, never as applied.
func (c *CoreClient) TitanExecSetGlobal(mode, flags uint8) error {
	if mode > 3 {
		return errors.New("titan exec global mode is out of range")
	}
	if flags&^uint8(titanExecGlobalFlagRequireCtime) != 0 {
		return errors.New("titan exec global flags are out of range")
	}
	return c.titanExecExpect("applied", "TITAN_EXEC_SET_GLOBAL",
		strconv.FormatUint(uint64(mode), 10), strconv.FormatUint(uint64(flags), 10))
}

// TitanExecAllowAdd allowlists one canonical absolute path. The core resolves and
// returns the kernel identity (dev, ino); a symlink, non-regular file, non
// executable file or read failure is an error, not a silent skip.
func (c *CoreClient) TitanExecAllowAdd(path string) (TitanExecAllowIdentity, error) {
	canonical, err := titanExecCanonicalPath(path)
	if err != nil {
		return TitanExecAllowIdentity{}, err
	}
	response, err := c.titanExecCommand("TITAN_EXEC_ALLOW_ADD", canonical)
	if err != nil {
		return TitanExecAllowIdentity{}, err
	}
	return parseTitanExecAllowIdentity(response)
}

// TitanExecAllowAddBatch adds a bounded set of canonical paths in one command. The
// decoded wire form is the newline-separated path list, base64url encoded (§5).
func (c *CoreClient) TitanExecAllowAddBatch(paths []string) (TitanExecBatchResult, error) {
	if len(paths) == 0 || len(paths) > titanExecMaxBatchPaths {
		return TitanExecBatchResult{}, fmt.Errorf("titan exec batch must carry 1..%d paths", titanExecMaxBatchPaths)
	}
	canonical := make([]string, 0, len(paths))
	decodedBytes := 0
	for _, path := range paths {
		value, err := titanExecCanonicalPath(path)
		if err != nil {
			return TitanExecBatchResult{}, err
		}
		decodedBytes += len(value) + 1
		if decodedBytes-1 > titanExecMaxBatchBytes {
			return TitanExecBatchResult{}, fmt.Errorf("titan exec batch exceeds %d decoded bytes", titanExecMaxBatchBytes)
		}
		canonical = append(canonical, value)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(canonical, "\n")))
	response, err := c.titanExecCommand("TITAN_EXEC_ALLOW_ADD_BATCH", payload)
	if err != nil {
		return TitanExecBatchResult{}, err
	}
	result, err := parseTitanExecBatchResult(response)
	if err != nil {
		return TitanExecBatchResult{}, err
	}
	if result.Added+result.Rejected > len(canonical) {
		return TitanExecBatchResult{}, errors.New("core reported more batch results than submitted paths")
	}
	return result, nil
}

// TitanExecAllowDel removes one allowlisted kernel identity. Deletion is idempotent
// on the core (KeyNotFound still answers "deleted").
func (c *CoreClient) TitanExecAllowDel(dev uint32, ino uint64) error {
	if dev == 0 || ino == 0 {
		return errors.New("titan exec delete requires a non-zero dev and ino")
	}
	return c.titanExecExpect("deleted", "TITAN_EXEC_ALLOW_DEL",
		strconv.FormatUint(uint64(dev), 10), strconv.FormatUint(ino, 10))
}

// TitanExecClear removes every allowlist entry. It is only issued while the global
// mode is off (fail-safe ordering), because an empty map denies in STRICT mode.
func (c *CoreClient) TitanExecClear() error {
	return c.titanExecExpect("cleared", "TITAN_EXEC_CLEAR")
}

// TitanExecScopeSet applies one per-cgroup mode/flags override.
func (c *CoreClient) TitanExecScopeSet(cgroupID uint64, mode, flags uint8) error {
	if cgroupID == 0 {
		return errors.New("titan exec scope cgroup id is invalid")
	}
	if mode > 3 {
		return errors.New("titan exec scope mode is out of range")
	}
	if flags&^uint8(titanExecScopeFlagJitAllow) != 0 {
		return errors.New("titan exec scope flags are out of range")
	}
	return c.titanExecExpect("applied", "TITAN_EXEC_SCOPE_SET", strconv.FormatUint(cgroupID, 10),
		strconv.FormatUint(uint64(mode), 10), strconv.FormatUint(uint64(flags), 10))
}

// TitanExecScopeDel removes one per-cgroup override (idempotent on the core).
func (c *CoreClient) TitanExecScopeDel(cgroupID uint64) error {
	if cgroupID == 0 {
		return errors.New("titan exec scope cgroup id is invalid")
	}
	return c.titanExecExpect("deleted", "TITAN_EXEC_SCOPE_DEL", strconv.FormatUint(cgroupID, 10))
}

// TitanExecEvents returns the raw §3.3 text wire ("empty" or
// "<dropped>|<record>[,<record>...]"). Parsing is owned by P1-T5
// (control/titan_exec_events.go) so the client stays a transport.
func (c *CoreClient) TitanExecEvents() (string, error) {
	return c.titanExecCommand("TITAN_EXEC_EVENTS")
}

// TitanExecHealth reports the six kernel-side exec-gate counters.
func (c *CoreClient) TitanExecHealth() (CoreTitanExecHealth, error) {
	response, err := c.titanExecCommand("TITAN_EXEC_HEALTH")
	if err != nil {
		return CoreTitanExecHealth{}, err
	}
	return parseCoreTitanExecHealth(response)
}

// parseTitanExecAllowIdentity decodes "added:<dev>:<ino>" / "exists:<dev>:<ino>".
func parseTitanExecAllowIdentity(payload string) (TitanExecAllowIdentity, error) {
	if len(payload) > 64 || strings.TrimSpace(payload) != payload {
		return TitanExecAllowIdentity{}, errors.New("core returned a malformed titan exec allow identity")
	}
	fields := strings.Split(payload, ":")
	if len(fields) != 3 || (fields[0] != "added" && fields[0] != "exists") {
		return TitanExecAllowIdentity{}, errors.New("core returned a malformed titan exec allow identity")
	}
	dev, devErr := titanExecParseUint(fields[1], 32)
	ino, inoErr := titanExecParseUint(fields[2], 64)
	if devErr != nil || inoErr != nil || dev == 0 || ino == 0 {
		return TitanExecAllowIdentity{}, errors.New("core returned an invalid titan exec allow identity")
	}
	return TitanExecAllowIdentity{State: fields[0], Dev: uint32(dev), Ino: ino}, nil
}

// titanExecBatchErrorTokens is the closed reason vocabulary of the Rust core's
// ALLOW_ADD_BATCH answer (P1-T3). "none" is the success token; a rejection always
// carries its specific reason instead.
var titanExecBatchErrorTokens = map[string]bool{
	"none": true, "empty": true, "too-long": true, "nul": true,
	"not-absolute": true, "not-canonical": true, "open-failed": true,
	"symlink": true, "not-regular": true, "not-executable": true,
	"device-out-of-range": true, "clock-out-of-range": true,
	"cap-reached": true, "map-write-failed": true, "store-write-failed": true,
}

// parseTitanExecBatchResult decodes "added:<n>;rejected:<n>;error=<token>". The
// token is a closed core vocabulary: "none" without a rejection, a specific reason
// with one. Anything else is a protocol violation and never a successful sync.
func parseTitanExecBatchResult(payload string) (TitanExecBatchResult, error) {
	if len(payload) > 256 || strings.ContainsAny(payload, "\x00\r\n") {
		return TitanExecBatchResult{}, errors.New("core returned a malformed titan exec batch result")
	}
	fields := strings.Split(payload, ";")
	if len(fields) != 3 ||
		!strings.HasPrefix(fields[0], "added:") ||
		!strings.HasPrefix(fields[1], "rejected:") ||
		!strings.HasPrefix(fields[2], "error=") {
		return TitanExecBatchResult{}, errors.New("core returned a malformed titan exec batch result")
	}
	added, addedErr := titanExecParseUint(strings.TrimPrefix(fields[0], "added:"), 16)
	rejected, rejectedErr := titanExecParseUint(strings.TrimPrefix(fields[1], "rejected:"), 16)
	if addedErr != nil || rejectedErr != nil || added > titanExecMaxBatchPaths || rejected > titanExecMaxBatchPaths {
		return TitanExecBatchResult{}, errors.New("core returned invalid titan exec batch counters")
	}
	token := strings.TrimPrefix(fields[2], "error=")
	if !titanExecBatchErrorTokens[token] {
		return TitanExecBatchResult{}, errors.New("core returned an unknown titan exec batch error token")
	}
	// "none" and "empty" describe the absence of a rejection; a rejection must name
	// its specific reason, otherwise the sync would fail without saying why.
	if rejected == 0 && token != "none" {
		return TitanExecBatchResult{}, errors.New("core returned an inconsistent titan exec batch result")
	}
	if rejected > 0 && (token == "none" || token == "empty") {
		return TitanExecBatchResult{}, errors.New("core returned an inconsistent titan exec batch result")
	}
	return TitanExecBatchResult{Added: int(added), Rejected: int(rejected), Error: token}, nil
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
	if err != nil || mode > 3 {
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

// parseCoreTitanExecHealth decodes the fixed six-counter payload
// "emitted:ring_drops:read_failures:denies:audits:ctime_rejects".
func parseCoreTitanExecHealth(payload string) (CoreTitanExecHealth, error) {
	if len(payload) == 0 || len(payload) > titanExecMaxHealthPayloadBytes {
		return CoreTitanExecHealth{}, errors.New("core returned an oversized titan exec health payload")
	}
	fields := strings.Split(payload, ":")
	if len(fields) != 6 {
		return CoreTitanExecHealth{}, errors.New("core returned malformed titan exec health")
	}
	values := make([]uint64, len(fields))
	for index, field := range fields {
		value, err := titanExecParseUint(field, 64)
		if err != nil {
			return CoreTitanExecHealth{}, errors.New("core returned invalid titan exec health counters")
		}
		values[index] = value
	}
	return CoreTitanExecHealth{
		Emitted: values[0], RingDrops: values[1], ReadFailures: values[2],
		Denies: values[3], Audits: values[4], CtimeRejects: values[5],
	}, nil
}

// ------------------------------------------------------------------ lockdown
//
// POINT 5 / P5-T3 (docs/POINT5-LOCKDOWN.md §5, ABI-3): the privileged core owns
// the LOCKDOWN_STATE word, the USB/Thunderbolt policy, the broker SIGSTOP and
// the hardening allowlist. The unprivileged control plane reaches them only
// through the authenticated VGT3 channel; everything below is additive and a
// core that predates the command family answers "ERR unknown command", which
// maps onto ErrLockdownUnavailable so the caller reports a capability fact
// instead of an XDR outage.
//
// Wire vocabulary (closed tokens, no free text, no paths), finalized with the
// P5-T2 core implementation):
//   mode   = "locked" | "unlocked"
//   source = "manual" | "uevent" | "policy" | "timer"  (§3 LOCKDOWN_SOURCE_*)
//   reason = "manual" | "usb-unknown" | "tb-unknown" | "screen-lock" | "tamper"
//            | "xdr-critical" | "boot-trust-drift" | "policy"
//   phase  = "net" | "usb" | "tb" | "hardening" | "brokers" | "cells"
//            | "sessions" | "dm"
//   state  = "off" | "armed" | "active" | "degraded"
//   list   = a bounded csv in a fixed order, or "-" for the empty list
// Every answer is ≤2048 B (already enforced by parseCoreResponse/payload bound).

const (
	lockdownCoreVersion = "lockdown-v1"
	// maxLockdownEventsPerResponse mirrors the core's own batch ceiling (§5).
	maxLockdownEventsPerResponse = 16
	// maxLockdownPayloadBytes bounds the text-wire payload before it is split.
	maxLockdownPayloadBytes = 2048
	// lockdownEpochChars is the documented 8-hex u32 epoch.
	lockdownEpochChars = 8
	// lockdownMaxUnsupportedPhases bounds the unsupported csv of an answer.
	lockdownMaxUnsupportedPhases = maxLockdownEventsPerResponse + 8
)

// ErrLockdownUnavailable marks the backwards-compatible answer of a core that
// does not implement the LOCKDOWN_* command family yet. It is a capability
// fact, not a degraded XDR sensor.
var ErrLockdownUnavailable = errors.New("lockdown capability unavailable")

// CoreLockdownStatus mirrors the LOCKDOWN_STATUS payload (§5):
// state=<off|armed|active|degraded>;epoch=<8hex>;mode=<locked|unlocked>;
// flags=<u8>;phases=<csv-applied>;unsupported=<csv>.
type CoreLockdownStatus struct {
	State       string
	Epoch       string
	Mode        string
	Flags       uint8
	Applied     []string
	Unsupported []string
}

// CoreLockdownTriggerResult mirrors the LOCKDOWN_TRIGGER payload:
// triggered:<epoch8>;phases=<applied-csv>;unsupported=<csv>.
type CoreLockdownTriggerResult struct {
	Epoch       string
	Applied     []string
	Unsupported []string
}

// CoreLockdownHealth mirrors the fixed six-counter LOCKDOWN_HEALTH payload
// "net_drops:witness_passes:uevent_events:usb_blocks:tb_blocks:broker_frozen".
type CoreLockdownHealth struct {
	NetDrops      uint64 `json:"net_drops"`
	WitnessPasses uint64 `json:"witness_passes"`
	UeventEvents  uint64 `json:"uevent_events"`
	USBBlocks     uint64 `json:"usb_blocks"`
	TBBlocks      uint64 `json:"tb_blocks"`
	BrokerFrozen  uint64 `json:"broker_frozen"`
}

// CoreLockdownEvent is one decoded LOCKDOWN_EVENTS record (text wire §5,
// Alles-oder-Nichts). Only closed tokens are carried; there is no path, IP or
// human free text on the wire.
type CoreLockdownEvent struct {
	Seq       uint64
	Timestamp uint64
	Source    uint8
	Reason    uint8
	Phase     uint8
	Outcome   uint8
}

// CoreLockdownPhaseResult is the LOCKDOWN_PHASE answer:
// applied:<phase> | unsupported:<phase>:<reason> | failed:<phase>:<reason>.
type CoreLockdownPhaseResult struct {
	Phase  string
	Status string
	Reason string
}

// lockdownCommand issues one LOCKDOWN_* command and classifies the
// backwards-compatible "unknown command" rejection as ErrLockdownUnavailable.
func (c *CoreClient) lockdownCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrLockdownUnavailable, err)
		}
		return "", err
	}
	if len(response) > maxLockdownPayloadBytes {
		return "", errors.New("core returned an oversized lockdown payload")
	}
	return response, nil
}

func lockdownModeToken(mode string) (string, error) {
	switch mode {
	case lockdownModeLocked, lockdownModeUnlocked:
		return mode, nil
	}
	return "", errors.New("lockdown mode must be locked or unlocked")
}

func lockdownSourceToken(source string) (string, error) {
	if !lockdownSourceValid(source) {
		return "", errors.New("lockdown source token is not in the closed vocabulary")
	}
	return source, nil
}

func lockdownReasonToken(reason string) (string, error) {
	// POINT 4 / P4-T2: the frozen P5 core ABI has no separate witness reason. A
	// proven ledger equivocation is tampering with the evidence chain, so it is
	// reported to the kernel under that reason; the local evidence and the event
	// keep the precise "witness-equivocation" spelling.
	if reason == lockdownReasonWitnessEquivocation {
		return lockdownReasonTamper, nil
	}
	if !lockdownReasonValid(reason) {
		return "", errors.New("lockdown reason token is not in the closed vocabulary")
	}
	return reason, nil
}

// validLockdownEpoch accepts exactly the documented 8 hex characters.
func validLockdownEpoch(value string) bool {
	if len(value) != lockdownEpochChars {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

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

func parseLockdownUint8(field string) (uint8, error) {
	if field == "" || len(field) > 3 {
		return 0, errors.New("core returned an invalid lockdown flags byte")
	}
	value, err := strconv.ParseUint(field, 10, 8)
	if err != nil {
		return 0, errors.New("core returned an invalid lockdown flags byte")
	}
	return uint8(value), nil
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

// parseCoreLockdownTrigger decodes "triggered:<epoch8>;phases=<csv>;unsupported=<csv>".
func parseCoreLockdownTrigger(payload string) (CoreLockdownTriggerResult, error) {
	if len(payload) == 0 || len(payload) > maxLockdownPayloadBytes {
		return CoreLockdownTriggerResult{}, errors.New("core returned an oversized lockdown trigger answer")
	}
	fields := strings.Split(payload, ";")
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "triggered:") ||
		!strings.HasPrefix(fields[1], "phases=") || !strings.HasPrefix(fields[2], "unsupported=") {
		return CoreLockdownTriggerResult{}, errors.New("core returned a malformed lockdown trigger answer")
	}
	epoch := strings.TrimPrefix(fields[0], "triggered:")
	if !validLockdownEpoch(epoch) {
		return CoreLockdownTriggerResult{}, errors.New("core returned an invalid lockdown trigger epoch")
	}
	applied, err := parseLockdownCSV(strings.TrimPrefix(fields[1], "phases="), "phase")
	if err != nil {
		return CoreLockdownTriggerResult{}, err
	}
	unsupported, err := parseLockdownCSV(strings.TrimPrefix(fields[2], "unsupported="), "phase")
	if err != nil {
		return CoreLockdownTriggerResult{}, err
	}
	return CoreLockdownTriggerResult{Epoch: epoch, Applied: applied, Unsupported: unsupported}, nil
}

// parseCoreLockdownHealth decodes the fixed six-counter payload.
func parseCoreLockdownHealth(payload string) (CoreLockdownHealth, error) {
	if len(payload) == 0 || len(payload) > maxLockdownPayloadBytes {
		return CoreLockdownHealth{}, errors.New("core returned an oversized lockdown health payload")
	}
	fields := strings.Split(payload, ":")
	if len(fields) != 6 {
		return CoreLockdownHealth{}, errors.New("core returned malformed lockdown health")
	}
	counters := make([]uint64, len(fields))
	for index, field := range fields {
		value, err := parseStyxUint(field, 64)
		if err != nil {
			return CoreLockdownHealth{}, errors.New("core returned invalid lockdown health counters")
		}
		counters[index] = value
	}
	return CoreLockdownHealth{
		NetDrops: counters[0], WitnessPasses: counters[1], UeventEvents: counters[2],
		USBBlocks: counters[3], TBBlocks: counters[4], BrokerFrozen: counters[5],
	}, nil
}

// parseCoreLockdownPhase decodes the operator single-phase answer.
func parseCoreLockdownPhase(payload string) (CoreLockdownPhaseResult, error) {
	if len(payload) == 0 || len(payload) > maxLockdownPayloadBytes {
		return CoreLockdownPhaseResult{}, errors.New("core returned an oversized lockdown phase answer")
	}
	fields := strings.Split(payload, ":")
	if len(fields) < 2 || len(fields) > 3 {
		return CoreLockdownPhaseResult{}, errors.New("core returned a malformed lockdown phase answer")
	}
	phase := fields[1]
	if !lockdownCorePhaseValid(phase) && phase != lockdownPhaseNameCells {
		return CoreLockdownPhaseResult{}, errors.New("core returned an unknown lockdown phase")
	}
	result := CoreLockdownPhaseResult{Phase: phase, Status: fields[0]}
	switch fields[0] {
	case "applied":
		if len(fields) != 2 {
			return CoreLockdownPhaseResult{}, errors.New("core returned an unexpected lockdown phase reason")
		}
	case "unsupported", "failed":
		if len(fields) != 3 || fields[2] == "" || len(fields[2]) > 96 || !protocolFieldValid(fields[2]) {
			return CoreLockdownPhaseResult{}, errors.New("core returned an invalid lockdown phase reason")
		}
		result.Reason = fields[2]
	default:
		return CoreLockdownPhaseResult{}, errors.New("core returned an unknown lockdown phase status")
	}
	return result, nil
}

// LockdownVersion negotiates the lockdown ABI. A pre-POINT5 core yields
// ErrLockdownUnavailable.
func (c *CoreClient) LockdownVersion() (string, error) {
	version, err := c.lockdownCommand("LOCKDOWN_VERSION")
	if err != nil {
		return "", err
	}
	if version != lockdownCoreVersion {
		return "", fmt.Errorf("core returned unsupported lockdown version %q", version)
	}
	return version, nil
}

// LockdownEpoch returns the 8-hex epoch that changes on every core start and
// every trigger (§5).
func (c *CoreClient) LockdownEpoch() (string, error) {
	epoch, err := c.lockdownCommand("LOCKDOWN_EPOCH")
	if err != nil {
		return "", err
	}
	if !validLockdownEpoch(epoch) {
		return "", errors.New("core returned an invalid lockdown epoch")
	}
	return epoch, nil
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

// LockdownArm applies the arm mode, the closed reason token and the four
// documented LOCKDOWN_TRIGGER flags. It returns the core epoch from the
// idempotent "armed:<epoch8>"/"armed-unchanged:<epoch8>" answer.
func (c *CoreClient) LockdownArm(mode, reason string, flags uint8) (string, error) {
	modeToken, err := lockdownModeToken(mode)
	if err != nil {
		return "", err
	}
	reasonToken, err := lockdownReasonToken(reason)
	if err != nil {
		return "", err
	}
	payload, err := c.lockdownCommand("LOCKDOWN_ARM", modeToken, reasonToken, strconv.FormatUint(uint64(flags), 10))
	if err != nil {
		return "", err
	}
	for _, prefix := range []string{"armed:", "armed-unchanged:"} {
		if strings.HasPrefix(payload, prefix) {
			epoch := strings.TrimPrefix(payload, prefix)
			if !validLockdownEpoch(epoch) {
				return "", errors.New("core returned an invalid lockdown arm epoch")
			}
			return epoch, nil
		}
	}
	return "", errors.New("core returned an unexpected lockdown arm answer")
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

// LockdownSetMode changes only the arm mode (LOCKDOWN_SET_MODE) without a
// trigger. It is the idempotent companion of LOCKDOWN_ARM.
func (c *CoreClient) LockdownSetMode(mode string) error {
	modeToken, err := lockdownModeToken(mode)
	if err != nil {
		return err
	}
	payload, err := c.lockdownCommand("LOCKDOWN_SET_MODE", modeToken)
	if err != nil {
		return err
	}
	if payload != "applied" {
		return fmt.Errorf("core returned unexpected lockdown set-mode answer %q", payload)
	}
	return nil
}

// LockdownEvents drains one bounded lifecycle-event batch plus the saturating
// ring-drop delta since the previous poll.
func (c *CoreClient) LockdownEvents() ([]CoreLockdownEvent, uint64, error) {
	payload, err := c.lockdownCommand("LOCKDOWN_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreLockdownEvents(payload)
}

// LockdownHealth reports the six kernel-side lockdown counters.
func (c *CoreClient) LockdownHealth() (CoreLockdownHealth, error) {
	payload, err := c.lockdownCommand("LOCKDOWN_HEALTH")
	if err != nil {
		return CoreLockdownHealth{}, err
	}
	return parseCoreLockdownHealth(payload)
}

// LockdownPhase applies or releases one single phase for an operator test.
func (c *CoreClient) LockdownPhase(phase string, on bool) (CoreLockdownPhaseResult, error) {
	if !lockdownCorePhaseValid(phase) && phase != lockdownPhaseNameCells {
		return CoreLockdownPhaseResult{}, errors.New("lockdown phase is not in the closed vocabulary")
	}
	state := "off"
	if on {
		state = "on"
	}
	payload, err := c.lockdownCommand("LOCKDOWN_PHASE", phase, state)
	if err != nil {
		return CoreLockdownPhaseResult{}, err
	}
	return parseCoreLockdownPhase(payload)
}
