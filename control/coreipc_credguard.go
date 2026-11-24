// STATUS: DIAMANT VGT SUPREME
package main

// M2.4 core IPC: the credential-file LSM guard.
//
// The Rust core denies reads of protected credential objects (/etc/shadow,
// secret stores) for non-allowlisted processes and reports the decision as a
// bounded event. Parsers are all-or-nothing and bounded; a core that predates the
// CRED_GUARD_* family answers "unknown command", which maps onto
// ErrCredGuardUnavailable and is a capability fact, not an XDR outage.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	maxCredGuardEventsPerResponse = 8
	maxCredGuardPayloadBytes      = 2048
	maxCredGuardRecordBytes       = 256
)

// CoreCredGuardEvent mirrors one decoded CRED_GUARD_EVENTS record. Action 1 is a
// kernel DENY (the read never returned bytes), action 2 is an AUDIT record.
type CoreCredGuardEvent struct {
	PID    int
	TGID   int
	UID    uint32
	Dev    uint32
	Ino    uint64
	Action uint8
	TsNS   uint64
	Comm   string
}

const (
	CredGuardActionDeny  uint8 = 1
	CredGuardActionAudit uint8 = 2
	// CredGuardActionDenyInode (V6.3.0 AP-1) is the same kernel -EACCES deny, but
	// decided by the executable-inode trust gate instead of the comm allowlist.
	// The control plane labels such a denial as an inode-gate denial.
	CredGuardActionDenyInode uint8 = 3
)

// CoreCredGuardStatus mirrors the nine fixed CRED_GUARD_STATUS fields.
type CoreCredGuardStatus struct {
	Active       bool
	Attached     bool
	Armed        bool
	Files        uint64
	Dirs         uint64
	Emitted      uint64
	Drops        uint64
	Denied       uint64
	ReadFailures uint64
}

// ErrCredGuardUnavailable marks a core without the CRED_GUARD_* command family.
var ErrCredGuardUnavailable = errors.New("credential guard capability unavailable")

func (c *CoreClient) credGuardCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrCredGuardUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// CredGuardSet arms (1) or disarms (0) the kernel credential guard. It only
// switches the observation/deny policy of the LSM hook; no PAM or login surface
// is modified.
func (c *CoreClient) CredGuardSet(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	response, err := c.credGuardCommand("CRED_GUARD_SET", value)
	if err != nil {
		return err
	}
	switch response {
	case "applied", "ok", "armed", "disarmed", "enabled", "disabled":
		return nil
	default:
		return fmt.Errorf("core returned unexpected credential guard set state %q", response)
	}
}

// CredGuardEvents drains one bounded batch of kernel credential decisions. The
// second return value is the saturating drop delta since the previous poll.
func (c *CoreClient) CredGuardEvents() ([]CoreCredGuardEvent, uint64, error) {
	response, err := c.credGuardCommand("CRED_GUARD_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreCredGuardEvents(response)
}

// CredGuardStatus reports the nine fixed kernel-side credential guard counters.
func (c *CoreClient) CredGuardStatus() (CoreCredGuardStatus, error) {
	response, err := c.credGuardCommand("CRED_GUARD_STATUS")
	if err != nil {
		return CoreCredGuardStatus{}, err
	}
	return parseCoreCredGuardStatus(response)
}

func parseCredGuardUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized credential guard counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal credential guard counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range credential guard counter")
	}
	return value, nil
}

// parseCoreCredGuardEvents decodes "empty" or "<dropped>|<record>,<record>...".
func parseCoreCredGuardEvents(response string) ([]CoreCredGuardEvent, uint64, error) {
	if len(response) > maxCredGuardPayloadBytes {
		return nil, 0, errors.New("core returned an oversized credential guard event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed credential guard batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed credential guard batch")
	}
	dropped, err := parseCredGuardUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid credential guard drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxCredGuardEventsPerResponse {
		return nil, 0, errors.New("core returned too many credential guard events")
	}
	events := make([]CoreCredGuardEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxCredGuardRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty credential guard record")
		}
		event, err := parseCoreCredGuardEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

func parseCoreCredGuardEvent(record string) (CoreCredGuardEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 8 {
		return CoreCredGuardEvent{}, errors.New("core returned a malformed credential guard event")
	}
	pid, pidErr := parseCredGuardUint(fields[0], 31)
	tgid, tgidErr := parseCredGuardUint(fields[1], 31)
	uid, uidErr := parseCredGuardUint(fields[2], 32)
	dev, devErr := parseCredGuardUint(fields[3], 32)
	ino, inoErr := parseCredGuardUint(fields[4], 64)
	action, actionErr := parseCredGuardUint(fields[5], 8)
	tsNS, tsErr := parseCredGuardUint(fields[6], 64)
	if pidErr != nil || tgidErr != nil || uidErr != nil || devErr != nil || inoErr != nil ||
		actionErr != nil || tsErr != nil || pid == 0 || tgid == 0 || ino == 0 || tsNS == 0 {
		return CoreCredGuardEvent{}, errors.New("core returned invalid credential guard event fields")
	}
	if action != uint64(CredGuardActionDeny) && action != uint64(CredGuardActionAudit) &&
		action != uint64(CredGuardActionDenyInode) {
		return CoreCredGuardEvent{}, errors.New("core returned an unknown credential guard action")
	}
	comm := ""
	if fields[7] != "" {
		if !validStyxHexText(fields[7]) || len(fields[7]) > 32 {
			return CoreCredGuardEvent{}, errors.New("core returned a malformed credential guard comm")
		}
		decoded, err := decodeStyxHex(fields[7], 16)
		if err != nil || len(decoded) == 0 {
			return CoreCredGuardEvent{}, errors.New("core returned a malformed credential guard comm")
		}
		for _, character := range decoded {
			if character < 0x20 || character == 0x7f || character == ' ' {
				return CoreCredGuardEvent{}, errors.New("core returned a credential guard comm with rejected characters")
			}
		}
		comm = string(decoded)
	}
	return CoreCredGuardEvent{
		PID: int(pid), TGID: int(tgid), UID: uint32(uid), Dev: uint32(dev), Ino: ino,
		Action: uint8(action), TsNS: tsNS, Comm: comm,
	}, nil
}

func parseCoreCredGuardStatus(response string) (CoreCredGuardStatus, error) {
	if len(response) > 256 || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreCredGuardStatus{}, errors.New("core returned a malformed credential guard status")
	}
	fields := strings.Split(response, ":")
	if len(fields) != 9 {
		return CoreCredGuardStatus{}, errors.New("core returned a malformed credential guard status")
	}
	values := make([]uint64, 9)
	for index, field := range fields {
		value, err := parseCredGuardUint(field, 64)
		if err != nil {
			return CoreCredGuardStatus{}, errors.New("core returned invalid credential guard status counters")
		}
		values[index] = value
	}
	if values[0] > 1 || values[1] > 1 || values[2] > 1 {
		return CoreCredGuardStatus{}, errors.New("core returned invalid credential guard flags")
	}
	return CoreCredGuardStatus{
		Active: values[0] == 1, Attached: values[1] == 1, Armed: values[2] == 1,
		Files: values[3], Dirs: values[4], Emitted: values[5], Drops: values[6],
		Denied: values[7], ReadFailures: values[8],
	}, nil
}
