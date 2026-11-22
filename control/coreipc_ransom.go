// STATUS: DIAMANT VGT SUPREME
package main

// M2.3 / M2.2 core IPC: process-tree kill, process-group freeze/resume and the
// kernel ransomware sensor (RANSOM_* command family).
//
// Every parser in this file is all-or-nothing and bounded: a malformed or
// oversized core answer is rejected instead of being partially trusted. Rule
// tokens sent with a kill/stop command are restricted to the documented control
// plane prefixes, so a rule id can never smuggle arguments into the core command
// line. A core that predates the RANSOM_* family answers "unknown command"; that
// maps onto ErrRansomUnavailable and is reported as a capability fact.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// maxRansomEventsPerResponse mirrors the core's own batch ceiling.
	maxRansomEventsPerResponse = 8
	// maxRansomPayloadBytes bounds the complete text-wire answer.
	maxRansomPayloadBytes = 2048
	// maxRansomRecordBytes bounds one record before field splitting.
	maxRansomRecordBytes = 256
	// maxTreeKillProcesses bounds the count a KILL_TREE answer may report.
	maxTreeKillProcesses = 4096
)

// ErrRansomUnavailable marks the backwards-compatible answer of a core that does
// not implement the RANSOM_* family. It is a capability fact, not an XDR outage.
var ErrRansomUnavailable = errors.New("ransom sensor capability unavailable")

// CoreRansomEvent mirrors one decoded RANSOM_EVENTS record. The kernel has
// already SIGSTOPped the process group when this record is produced.
type CoreRansomEvent struct {
	TGID   int
	PGID   int
	UID    uint32
	Signal uint8
	Reason string
	TsNS   uint64
	Count  uint64
	Comm   string
}

// RansomReason values come from the closed kernel vocabulary. The mapping onto
// the XDR rule ids is done in xdr_ransom.go.
const (
	RansomReasonEntropyBurst = "entropy_burst"
	RansomReasonRenameStorm  = "rename_storm"
)

func validXDRRuleToken(rule string) bool {
	if len(rule) < 3 || len(rule) > 64 {
		return false
	}
	for index := 0; index < len(rule); index++ {
		character := rule[index]
		switch {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '.', character == '_', character == '-':
		default:
			return false
		}
	}
	for _, prefix := range []string{"XDR.", "KD.LINUX.", "BASELINE.", "L7."} {
		if strings.HasPrefix(rule, prefix) {
			return true
		}
	}
	return false
}

func validTreeKillPid(pid int) bool    { return pid > 0 && pid <= 1<<30 }
func validTreeKillTicks(t uint64) bool { return t <= 1<<62 }

// KillTree asks the core to SIGKILL the process tree rooted at pid (M2.3). A
// startTicks of 0 is accepted on purpose: a kernel ransom record carries no
// start time, and the core re-validates the identity itself; a rejected tree kill
// is surfaced to the caller instead of being retried with a guessed tick value.
func (c *CoreClient) KillTree(pid int, startTicks uint64, rule string) (int, error) {
	if !validTreeKillPid(pid) {
		return 0, errors.New("xdr tree kill pid is out of range")
	}
	if !validTreeKillTicks(startTicks) {
		return 0, errors.New("xdr tree kill start ticks are out of range")
	}
	if !validXDRRuleToken(rule) {
		return 0, errors.New("xdr tree kill rule token is invalid")
	}
	response, err := c.command("XDR_KILL_TREE", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	if err != nil {
		return 0, err
	}
	if len(response) > 32 || !strings.HasPrefix(response, "killed:") {
		return 0, errors.New("core returned a malformed xdr tree kill answer")
	}
	killed, err := parseRansomUint(strings.TrimPrefix(response, "killed:"), 32)
	if err != nil || killed > maxTreeKillProcesses {
		return 0, errors.New("core returned an invalid xdr tree kill count")
	}
	return int(killed), nil
}

// StopGroup freezes one whole process group (M2.2/M2.3). The kernel ransom
// sensor already emits its own SIGSTOP; this is the control-plane ownership path
// for deliberate freezes/resumes.
func (c *CoreClient) StopGroup(pgid int, rule string) error {
	if !validTreeKillPid(pgid) {
		return errors.New("xdr group stop pgid is out of range")
	}
	if !validXDRRuleToken(rule) {
		return errors.New("xdr group stop rule token is invalid")
	}
	response, err := c.command("XDR_GROUP_STOP", strconv.Itoa(pgid), rule)
	if err != nil {
		return err
	}
	if response != "stopped" {
		return fmt.Errorf("core returned unexpected xdr group stop state %q", response)
	}
	return nil
}

// ResumeGroup releases a freeze started by the core or by StopGroup.
func (c *CoreClient) ResumeGroup(pgid int, rule string) error {
	if !validTreeKillPid(pgid) {
		return errors.New("xdr group resume pgid is out of range")
	}
	if !validXDRRuleToken(rule) {
		return errors.New("xdr group resume rule token is invalid")
	}
	response, err := c.command("XDR_GROUP_CONT", strconv.Itoa(pgid), rule)
	if err != nil {
		return err
	}
	if response != "resumed" {
		return fmt.Errorf("core returned unexpected xdr group resume state %q", response)
	}
	return nil
}

// RansomSet arms (1) or disarms (0) the kernel ransomware sensor.
func (c *CoreClient) RansomSet(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	response, err := c.ransomCommand("RANSOM_SET", value)
	if err != nil {
		return err
	}
	switch response {
	case "applied", "ok", "armed", "disarmed", "enabled", "disabled":
		return nil
	default:
		return fmt.Errorf("core returned unexpected ransom set state %q", response)
	}
}

// RansomEvents drains one bounded batch of kernel freeze records. The second
// return value is the saturating drop delta since the last poll.
func (c *CoreClient) RansomEvents() ([]CoreRansomEvent, uint64, error) {
	response, err := c.ransomCommand("RANSOM_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreRansomEvents(response)
}

// RansomStatus reports the eight fixed kernel-side ransomware counters.
func (c *CoreClient) RansomStatus() (CoreRansomStatus, error) {
	response, err := c.ransomCommand("RANSOM_STATUS")
	if err != nil {
		return CoreRansomStatus{}, err
	}
	return parseCoreRansomStatus(response)
}

// CoreRansomStatus mirrors RANSOM_STATUS (fixed order, eight decimal fields).
type CoreRansomStatus struct {
	Armed         bool
	Attached      bool
	Emitted       uint64
	Drops         uint64
	StopsOK       uint64
	StopsFailed   uint64
	StopsSkipped  uint64
	TrackFailures uint64
}

func (c *CoreClient) ransomCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrRansomUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

func parseRansomUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized ransom counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal ransom counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range ransom counter")
	}
	return value, nil
}

// parseCoreRansomEvents decodes "empty" or "<dropped>|<record>,<record>...".
func parseCoreRansomEvents(response string) ([]CoreRansomEvent, uint64, error) {
	if len(response) > maxRansomPayloadBytes {
		return nil, 0, errors.New("core returned an oversized ransom event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed ransom event batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed ransom event batch")
	}
	dropped, err := parseRansomUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid ransom drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxRansomEventsPerResponse {
		return nil, 0, errors.New("core returned too many ransom events")
	}
	events := make([]CoreRansomEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxRansomRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty ransom event record")
		}
		event, err := parseCoreRansomEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

func parseCoreRansomEvent(record string) (CoreRansomEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 8 {
		return CoreRansomEvent{}, errors.New("core returned a malformed ransom event")
	}
	tgid, tgidErr := parseRansomUint(fields[0], 31)
	pgid, pgidErr := parseRansomUint(fields[1], 31)
	uid, uidErr := parseRansomUint(fields[2], 32)
	signal, signalErr := parseRansomUint(fields[3], 8)
	tsNS, tsErr := parseRansomUint(fields[5], 64)
	count, countErr := parseRansomUint(fields[6], 32)
	if tgidErr != nil || pgidErr != nil || uidErr != nil || signalErr != nil || tsErr != nil || countErr != nil ||
		tgid == 0 || pgid == 0 || signal == 0 || signal > 64 || tsNS == 0 || count == 0 {
		return CoreRansomEvent{}, errors.New("core returned invalid ransom event fields")
	}
	reason := strings.ToLower(fields[4])
	if reason != RansomReasonEntropyBurst && reason != RansomReasonRenameStorm {
		return CoreRansomEvent{}, errors.New("core returned an unknown ransom reason")
	}
	comm := ""
	if fields[7] != "" {
		if !validStyxHexText(fields[7]) || len(fields[7]) > 32 {
			return CoreRansomEvent{}, errors.New("core returned a malformed ransom comm")
		}
		decoded, err := decodeStyxHex(fields[7], 16)
		if err != nil || len(decoded) == 0 {
			return CoreRansomEvent{}, errors.New("core returned a malformed ransom comm")
		}
		for _, character := range decoded {
			if character < 0x20 || character == 0x7f || character == ' ' {
				return CoreRansomEvent{}, errors.New("core returned a ransom comm with rejected characters")
			}
		}
		comm = string(decoded)
	}
	return CoreRansomEvent{
		TGID: int(tgid), PGID: int(pgid), UID: uint32(uid), Signal: uint8(signal),
		Reason: reason, TsNS: tsNS, Count: count, Comm: comm,
	}, nil
}

// parseCoreRansomStatus decodes the fixed eight-field RANSOM_STATUS answer.
func parseCoreRansomStatus(response string) (CoreRansomStatus, error) {
	if len(response) > 256 || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreRansomStatus{}, errors.New("core returned a malformed ransom status")
	}
	fields := strings.Split(response, ":")
	if len(fields) != 8 {
		return CoreRansomStatus{}, errors.New("core returned a malformed ransom status")
	}
	values := make([]uint64, 8)
	for index, field := range fields {
		value, err := parseRansomUint(field, 64)
		if err != nil {
			return CoreRansomStatus{}, errors.New("core returned invalid ransom status counters")
		}
		values[index] = value
	}
	if values[0] > 1 || values[1] > 1 {
		return CoreRansomStatus{}, errors.New("core returned invalid ransom arm/attach flags")
	}
	return CoreRansomStatus{
		Armed: values[0] == 1, Attached: values[1] == 1,
		Emitted: values[2], Drops: values[3],
		StopsOK: values[4], StopsFailed: values[5], StopsSkipped: values[6], TrackFailures: values[7],
	}, nil
}
