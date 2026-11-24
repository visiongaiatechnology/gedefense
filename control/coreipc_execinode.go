// V6.3.0 AP-1: authenticated transport for the executable-inode trust family
// (`EXEC_INODE_*`, `MALWARE_INODE_*`). The kernel guard denies by `(s_dev,
// i_ino)` of the real executable; this file only frames and validates the
// VGT3 records. Path tokens are base64url-encoded absolute paths.
//
// Wire vocabulary (additive; a core that predates the family answers "unknown
// command" and the capability is reported as missing, never as an XDR outage):
//
//	EXEC_INODE_STATUS                        -> enabled=..:offsets=..:trusted=..:...
//	EXEC_INODE_EVENTS                        -> empty | <dropped>|<record>[,<record>...]
//	EXEC_INODE_ALLOW_ADD <path_b64> <flags>  -> applied
//	EXEC_INODE_ALLOW_DEL <dev> <ino>         -> deleted
//	EXEC_INODE_CLEAR                         -> cleared
//	MALWARE_INODE_LOCK <dev> <ino> <ttl>     -> locked
//	MALWARE_INODE_UNLOCK <dev> <ino>         -> unlocked
//
// Every parser is all-or-nothing and bounded. The event action values are
// 1=OBSERVED_MISMATCH (comm/executable divergence), 2=DENIED_UNTRUSTED (the
// inode gate denied) and 3=FALLBACK_COMM (the weaker comm allowlist decided
// because BTF/offsets were unavailable). Observe/evidence only.

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	maxExecInodeEventsPerResponse = 16
	maxExecInodePayloadBytes      = 4096
	maxExecInodeRecordBytes       = 256
	maxExecInodeStatusBytes       = 512
	maxExecInodePathBytes         = 1024
)

// Exec-inode event actions (mirrors gedefense-common::EXEC_INODE_ACTION_*).
const (
	ExecInodeActionObservedMismatch uint8 = 1
	ExecInodeActionDeniedUntrusted  uint8 = 2
	ExecInodeActionFallbackComm     uint8 = 3
)

// Exec-inode trust flag bits (mirrors gedefense-common::EXEC_INODE_ALLOW_*).
const (
	ExecInodeAllowCredRead     uint8 = 1
	ExecInodeAllowRansomFull   uint8 = 2
	ExecInodeAllowRansomPoolMe uint8 = 4
	ExecInodeAllowAll          uint8 = ExecInodeAllowCredRead | ExecInodeAllowRansomFull | ExecInodeAllowRansomPoolMe
)

// ErrExecInodeUnavailable marks a core without the EXEC_INODE_* command family.
// It is a capability fact, never a deliverable degradation of the XDR sensor.
var ErrExecInodeUnavailable = errors.New("exec-inode capability unavailable")

// CoreExecInodeStatus is the strict projection of EXEC_INODE_STATUS.
type CoreExecInodeStatus struct {
	Enabled      bool
	OffsetsOK    bool
	Trusted      uint64
	Missing      uint64
	Allowed      uint64
	Denied       uint64
	Events       uint64
	Drops        uint64
	Fallbacks    uint64
	MalwareLocks uint64
	ExpiredLocks uint64
}

// CoreExecInodeEvent is one name/path mismatch evidence record.
type CoreExecInodeEvent struct {
	TsNS       uint64
	PID        int
	TGID       int
	UID        uint32
	ExeDev     uint32
	ExeIno     uint64
	TrustFlags uint32
	Action     uint8
	Comm       string
}

// execInodeCommand runs one command of the EXEC_INODE_*/MALWARE_INODE_* family
// and maps an "unknown command" rejection onto ErrExecInodeUnavailable so an
// old core is a capability fact instead of an outage.
func (c *CoreClient) execInodeCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrExecInodeUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// ExecInodeStatus queries the executable-inode trust gate health.
func (c *CoreClient) ExecInodeStatus() (CoreExecInodeStatus, error) {
	response, err := c.execInodeCommand("EXEC_INODE_STATUS")
	if err != nil {
		return CoreExecInodeStatus{}, err
	}
	return parseCoreExecInodeStatus(response)
}

// ExecInodeEvents drains bounded name/path mismatch records.
func (c *CoreClient) ExecInodeEvents() ([]CoreExecInodeEvent, uint64, error) {
	response, err := c.execInodeCommand("EXEC_INODE_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreExecInodeEvents(response)
}

// ExecInodeAllowAdd marks one resolved executable path as trusted with flags.
func (c *CoreClient) ExecInodeAllowAdd(path string, flags uint8) error {
	if err := validateExecInodePath(path); err != nil {
		return err
	}
	if flags == 0 || flags&^ExecInodeAllowAll != 0 {
		return errors.New("exec-inode flags must be a non-zero subset of 1|2|4")
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(path))
	response, err := c.execInodeCommand("EXEC_INODE_ALLOW_ADD", token, strconv.Itoa(int(flags)))
	if err != nil {
		return err
	}
	switch response {
	case "applied", "ok", "added":
		return nil
	default:
		return fmt.Errorf("core returned unexpected exec-inode allow-add state %q", response)
	}
}

// ExecInodeAllowDelete removes one trusted executable identity.
func (c *CoreClient) ExecInodeAllowDelete(dev uint32, ino uint64) error {
	if dev == 0 || ino == 0 {
		return errors.New("exec-inode identity must be non-zero")
	}
	response, err := c.execInodeCommand(
		"EXEC_INODE_ALLOW_DEL",
		strconv.FormatUint(uint64(dev), 10),
		strconv.FormatUint(ino, 10),
	)
	if err != nil {
		return err
	}
	switch response {
	case "deleted", "ok", "removed":
		return nil
	default:
		return fmt.Errorf("core returned unexpected exec-inode allow-delete state %q", response)
	}
}

// ExecInodeClear empties the explicit trust additions (defaults are re-seeded
// by the core on the next load).
func (c *CoreClient) ExecInodeClear() error {
	response, err := c.execInodeCommand("EXEC_INODE_CLEAR")
	if err != nil {
		return err
	}
	switch response {
	case "cleared", "ok", "empty":
		return nil
	default:
		return fmt.Errorf("core returned unexpected exec-inode clear state %q", response)
	}
}

// MalwareInodeLock TTL-locks one behaviour carrier inode.
func (c *CoreClient) MalwareInodeLock(dev uint32, ino uint64, ttlSeconds uint32) error {
	if dev == 0 || ino == 0 {
		return errors.New("malware inode lock identity must be non-zero")
	}
	if ttlSeconds < 1 || ttlSeconds > 86400 {
		return errors.New("malware inode lock TTL must be within 1..=86400 seconds")
	}
	response, err := c.execInodeCommand(
		"MALWARE_INODE_LOCK",
		strconv.FormatUint(uint64(dev), 10),
		strconv.FormatUint(ino, 10),
		strconv.FormatUint(uint64(ttlSeconds), 10),
	)
	if err != nil {
		return err
	}
	switch response {
	case "locked", "applied", "ok":
		return nil
	default:
		return fmt.Errorf("core returned unexpected malware inode lock state %q", response)
	}
}

// MalwareInodeUnlock releases one TTL lock early.
func (c *CoreClient) MalwareInodeUnlock(dev uint32, ino uint64) error {
	if dev == 0 || ino == 0 {
		return errors.New("malware inode unlock identity must be non-zero")
	}
	response, err := c.execInodeCommand(
		"MALWARE_INODE_UNLOCK",
		strconv.FormatUint(uint64(dev), 10),
		strconv.FormatUint(ino, 10),
	)
	if err != nil {
		return err
	}
	switch response {
	case "unlocked", "ok", "removed":
		return nil
	default:
		return fmt.Errorf("core returned unexpected malware inode unlock state %q", response)
	}
}

// validateExecInodePath enforces the bounded absolute-path contract the core
// re-validates after base64 decoding.
func validateExecInodePath(path string) error {
	if len(path) == 0 || len(path) > maxExecInodePathBytes {
		return errors.New("exec-inode path is empty or exceeds the path bound")
	}
	if !strings.HasPrefix(path, "/") {
		return errors.New("exec-inode path must be absolute")
	}
	for index := 0; index < len(path); index++ {
		character := path[index]
		if character == 0 || character < 0x20 || character == 0x7f {
			return errors.New("exec-inode path contains a control character")
		}
	}
	if strings.HasSuffix(path, "/") || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") {
		return errors.New("exec-inode path contains a rejected component")
	}
	return nil
}

func parseExecInodeUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized exec-inode counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal exec-inode counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range exec-inode counter")
	}
	return value, nil
}

// parseCoreExecInodeStatus decodes the bounded `key=value:...` status record.
// The key order is part of the contract; an unknown/duplicate/reordered key is
// rejected instead of being silently ignored.
func parseCoreExecInodeStatus(response string) (CoreExecInodeStatus, error) {
	if response == "" || len(response) > maxExecInodeStatusBytes ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreExecInodeStatus{}, errors.New("core returned a malformed exec-inode status")
	}
	keys := []string{
		"enabled", "offsets", "trusted", "missing", "allowed", "denied",
		"events", "drops", "fallbacks", "locks", "expired",
	}
	fields := strings.Split(response, ":")
	if len(fields) != len(keys) {
		return CoreExecInodeStatus{}, errors.New("core returned a malformed exec-inode status")
	}
	values := make([]uint64, len(keys))
	for index, field := range fields {
		name, valueText, ok := strings.Cut(field, "=")
		if !ok || name != keys[index] || valueText == "" {
			return CoreExecInodeStatus{}, errors.New("core returned an unexpected exec-inode status field")
		}
		value, err := parseExecInodeUint(valueText, 64)
		if err != nil {
			return CoreExecInodeStatus{}, errors.New("core returned invalid exec-inode status counters")
		}
		values[index] = value
	}
	if values[0] > 1 || values[1] > 1 {
		return CoreExecInodeStatus{}, errors.New("core returned invalid exec-inode status flags")
	}
	return CoreExecInodeStatus{
		Enabled:      values[0] == 1,
		OffsetsOK:    values[1] == 1,
		Trusted:      values[2],
		Missing:      values[3],
		Allowed:      values[4],
		Denied:       values[5],
		Events:       values[6],
		Drops:        values[7],
		Fallbacks:    values[8],
		MalwareLocks: values[9],
		ExpiredLocks: values[10],
	}, nil
}

// parseCoreExecInodeEvents decodes "empty" or
// "<dropped>|<record>,<record>...". The decoder is all-or-nothing: one
// malformed record rejects the whole batch so the caller never acts on a
// partially parsed evidence set.
func parseCoreExecInodeEvents(response string) ([]CoreExecInodeEvent, uint64, error) {
	if len(response) > maxExecInodePayloadBytes {
		return nil, 0, errors.New("core returned an oversized exec-inode event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed exec-inode batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed exec-inode batch")
	}
	dropped, err := parseExecInodeUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid exec-inode drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxExecInodeEventsPerResponse {
		return nil, 0, errors.New("core returned too many exec-inode events")
	}
	events := make([]CoreExecInodeEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxExecInodeRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty exec-inode record")
		}
		event, err := parseCoreExecInodeEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

func parseCoreExecInodeEvent(record string) (CoreExecInodeEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 9 {
		return CoreExecInodeEvent{}, errors.New("core returned a malformed exec-inode event")
	}
	tsNS, tsErr := parseExecInodeUint(fields[0], 64)
	pid, pidErr := parseExecInodeUint(fields[1], 31)
	tgid, tgidErr := parseExecInodeUint(fields[2], 31)
	uid, uidErr := parseExecInodeUint(fields[3], 32)
	exeDev, devErr := parseExecInodeUint(fields[4], 32)
	exeIno, inoErr := parseExecInodeUint(fields[5], 64)
	trustFlags, flagsErr := parseExecInodeUint(fields[6], 32)
	action, actionErr := parseExecInodeUint(fields[7], 8)
	if tsErr != nil || pidErr != nil || tgidErr != nil || uidErr != nil || devErr != nil ||
		inoErr != nil || flagsErr != nil || actionErr != nil {
		return CoreExecInodeEvent{}, errors.New("core returned invalid exec-inode event fields")
	}
	if tsNS == 0 || pid == 0 || tgid == 0 {
		return CoreExecInodeEvent{}, errors.New("core returned an exec-inode event without a producer identity")
	}
	if action != uint64(ExecInodeActionObservedMismatch) &&
		action != uint64(ExecInodeActionDeniedUntrusted) &&
		action != uint64(ExecInodeActionFallbackComm) {
		return CoreExecInodeEvent{}, errors.New("core returned an unknown exec-inode action")
	}
	if trustFlags&^uint64(ExecInodeAllowAll) != 0 {
		return CoreExecInodeEvent{}, errors.New("core returned undefined exec-inode trust flags")
	}
	// The kernel only emits a mismatch/deny record after it resolved the real
	// executable identity; the fallback record is the single action that may
	// carry a zero identity (the offsets/state needed to resolve it were absent).
	if action != uint64(ExecInodeActionFallbackComm) && (exeDev == 0 || exeIno == 0) {
		return CoreExecInodeEvent{}, errors.New("core returned an exec-inode decision without a resolved identity")
	}
	comm := ""
	if fields[8] != "" {
		if !validStyxHexText(fields[8]) || len(fields[8]) > 32 {
			return CoreExecInodeEvent{}, errors.New("core returned a malformed exec-inode comm")
		}
		decoded, err := decodeStyxHex(fields[8], 16)
		if err != nil || len(decoded) == 0 {
			return CoreExecInodeEvent{}, errors.New("core returned a malformed exec-inode comm")
		}
		for _, character := range decoded {
			if character < 0x20 || character == 0x7f || character == ' ' {
				return CoreExecInodeEvent{}, errors.New("core returned an exec-inode comm with rejected characters")
			}
		}
		comm = string(decoded)
	}
	if comm == "" {
		return CoreExecInodeEvent{}, errors.New("core returned an exec-inode event without a task name")
	}
	return CoreExecInodeEvent{
		TsNS:       tsNS,
		PID:        int(pid),
		TGID:       int(tgid),
		UID:        uint32(uid),
		ExeDev:     uint32(exeDev),
		ExeIno:     exeIno,
		TrustFlags: uint32(trustFlags),
		Action:     uint8(action),
		Comm:       comm,
	}, nil
}
