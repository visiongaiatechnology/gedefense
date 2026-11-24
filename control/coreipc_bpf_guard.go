// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-2: authenticated transport for the attach-time eBPF guard family
// (`BPF_GUARD_*`).
//
// The kernel guard observes `security_bpf_prog` (`lsm/bpf_prog`),
// `syscalls/sys_enter_bpf` and (BTF/kallsyms-gated) `check_helper_call`; this
// file frames and validates the VGT3 records. It is a strict transport: every
// answer is parsed all-or-nothing with bounded counters, bounded payloads and a
// closed action/program-type/helper-bit set, and a core that predates the family
// answers "unknown command", which maps onto ErrBpfGuardUnavailable (a
// capability fact, not an XDR outage).

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Core-side bounds (mirror `rust/gedefense-core/src/bpf_guard.rs`).
const (
	maxBpfGuardEventsPerResponse = 16
	maxBpfGuardPayloadBytes      = 4096
	maxBpfGuardRecordBytes       = 320
	maxBpfGuardStatusBytes       = 512
	bpfGuardEpochHexLen          = 16
)

// Event actions (`BPF_GUARD_ACTION_*`).
const (
	BpfGuardActionObserved   uint8 = 1
	BpfGuardActionHelperRisk uint8 = 2
	BpfGuardActionDenied     uint8 = 3
)

// UAPI `enum bpf_cmd` values (stable numbering).
const (
	BpfGuardCommandMapCreate         uint8 = 0
	BpfGuardCommandProgLoad          uint8 = 5
	BpfGuardCommandProgAttach        uint8 = 8
	BpfGuardCommandRawTracepointOpen uint8 = 17
	BpfGuardCommandLinkCreate        uint8 = 28
)

// UAPI `enum bpf_prog_type` values (stable numbering; STRUCT_OPS=27 and
// TRACING=26 — the PLAN text swapped those two, the UAPI binding is authoritative).
const (
	BpfGuardProgTypeUnknown       uint8 = 0
	BpfGuardProgTypeKprobe        uint8 = 2
	BpfGuardProgTypeTracepoint    uint8 = 5
	BpfGuardProgTypeRawTracepoint uint8 = 17
	BpfGuardProgTypeTracing       uint8 = 26
	BpfGuardProgTypeStructOps     uint8 = 27
	BpfGuardProgTypeLSM           uint8 = 29
	BpfGuardProgTypeSkLookup      uint8 = 30
	BpfGuardProgTypeSyscall       uint8 = 31
	// BpfGuardProgTypeMax bounds the wire field: a future kernel program type is
	// representable up to this value and is never rejected by the decoder.
	BpfGuardProgTypeMax uint8 = 63
)

// Helper-risk bitmap bits (`HELPER_BIT_*`).
const (
	BpfGuardHelperBitProbeWriteUser uint32 = 1 << 0
	BpfGuardHelperBitOverrideReturn uint32 = 1 << 1
	BpfGuardHelperBitSendSignal     uint32 = 1 << 2
	BpfGuardHelperMaskAll           uint32 = BpfGuardHelperBitProbeWriteUser |
		BpfGuardHelperBitOverrideReturn | BpfGuardHelperBitSendSignal
	// BpfGuardHelperBitsPerEvent is the number of raw helper-id lanes per record.
	BpfGuardHelperBitsPerEvent = 4
	// BpfGuardMaxHelperID bounds a representable raw helper id.
	BpfGuardMaxHelperID uint32 = 1024
)

// Stable helper ids (`include/uapi/linux/bpf.h` `__BPF_FUNC_MAPPER`).
const (
	BpfGuardHelperIDProbeWriteUser uint32 = 36
	BpfGuardHelperIDOverrideReturn uint32 = 58
	BpfGuardHelperIDSendSignal     uint32 = 109
	BpfGuardHelperIDSendSignalThre uint32 = 117
)

// ErrBpfGuardUnavailable marks a core without the BPF_GUARD_* command family.
var ErrBpfGuardUnavailable = errors.New("bpf-guard capability unavailable")

// BpfGuardHelperIDToBit maps one raw helper id to its risk bit; 0 for every
// helper outside the rootkit-relevant set.
func BpfGuardHelperIDToBit(helperID uint32) uint32 {
	switch helperID {
	case BpfGuardHelperIDProbeWriteUser:
		return BpfGuardHelperBitProbeWriteUser
	case BpfGuardHelperIDOverrideReturn:
		return BpfGuardHelperBitOverrideReturn
	case BpfGuardHelperIDSendSignal, BpfGuardHelperIDSendSignalThre:
		return BpfGuardHelperBitSendSignal
	default:
		return 0
	}
}

// CoreBpfGuardStatus is the strict projection of BPF_GUARD_STATUS: the ten
// documented `key=value` fields.
type CoreBpfGuardStatus struct {
	Enabled        bool
	Attached       bool
	LSMAttached    bool
	TPAttached     bool
	KprobeAttached bool
	Events         uint64
	Drops          uint64
	ReadFailures   uint64
	Loads          uint64
	HelperRisk     uint64
}

// CoreBpfGuardEvent is one decoded attach-time eBPF guard record.
type CoreBpfGuardEvent struct {
	TsNS       uint64
	PID        int
	TGID       int
	UID        uint32
	Action     uint8
	Command    uint8
	ProgType   uint8
	HelperMask uint32
	HelperIDs  [BpfGuardHelperBitsPerEvent]uint32
	ExeDev     uint32
	ExeIno     uint64
	Comm       string
}

func (c *CoreClient) bpfGuardCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrBpfGuardUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// BpfGuardEpoch returns the random per-boot guard epoch (16 lowercase hex chars).
func (c *CoreClient) BpfGuardEpoch() (string, error) {
	response, err := c.bpfGuardCommand("BPF_GUARD_EPOCH")
	if err != nil {
		return "", err
	}
	return parseBpfGuardEpoch(response)
}

func parseBpfGuardEpoch(response string) (string, error) {
	epoch := response
	if len(epoch) != bpfGuardEpochHexLen {
		return "", errors.New("core returned a malformed bpf-guard epoch")
	}
	for index := 0; index < len(epoch); index++ {
		character := epoch[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "", errors.New("core returned a malformed bpf-guard epoch")
		}
	}
	return epoch, nil
}

// BpfGuardStatus queries the attach-time guard health.
func (c *CoreClient) BpfGuardStatus() (CoreBpfGuardStatus, error) {
	response, err := c.bpfGuardCommand("BPF_GUARD_STATUS")
	if err != nil {
		return CoreBpfGuardStatus{}, err
	}
	return parseCoreBpfGuardStatus(response)
}

// BpfGuardEvents drains one bounded batch of attach-time records. The second
// return value is the saturating ring-drop delta since the previous poll.
func (c *CoreClient) BpfGuardEvents() ([]CoreBpfGuardEvent, uint64, error) {
	response, err := c.bpfGuardCommand("BPF_GUARD_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreBpfGuardEvents(response)
}

// BpfGuardSet arms (1) or disarms (0) the observe-only guard.
func (c *CoreClient) BpfGuardSet(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	response, err := c.bpfGuardCommand("BPF_GUARD_SET", value)
	if err != nil {
		return err
	}
	switch response {
	case "armed", "disarmed":
		return nil
	default:
		return fmt.Errorf("core returned unexpected bpf-guard set state %q", response)
	}
}

func parseBpfGuardUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized bpf-guard counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal bpf-guard counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range bpf-guard counter")
	}
	return value, nil
}

// parseCoreBpfGuardStatus decodes the exactly-ten `key=value` status fields.
func parseCoreBpfGuardStatus(response string) (CoreBpfGuardStatus, error) {
	if len(response) > maxBpfGuardStatusBytes || response == "" ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreBpfGuardStatus{}, errors.New("core returned a malformed bpf-guard status")
	}
	expected := []string{
		"enabled", "attached", "lsm", "tp", "kprobe", "events", "drops",
		"read_failures", "loads", "helper_risk",
	}
	fields := strings.Split(response, ":")
	if len(fields) != len(expected) {
		return CoreBpfGuardStatus{}, errors.New("core returned a malformed bpf-guard status")
	}
	values := make([]uint64, len(expected))
	for index, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key != expected[index] {
			return CoreBpfGuardStatus{}, errors.New("core returned an unknown bpf-guard status field")
		}
		parsed, err := parseBpfGuardUint(value, 64)
		if err != nil {
			return CoreBpfGuardStatus{}, errors.New("core returned invalid bpf-guard status counters")
		}
		values[index] = parsed
	}
	for index := 0; index < 5; index++ {
		if values[index] > 1 {
			return CoreBpfGuardStatus{}, errors.New("core returned invalid bpf-guard status flags")
		}
	}
	return CoreBpfGuardStatus{
		Enabled:        values[0] == 1,
		Attached:       values[1] == 1,
		LSMAttached:    values[2] == 1,
		TPAttached:     values[3] == 1,
		KprobeAttached: values[4] == 1,
		Events:         values[5],
		Drops:          values[6],
		ReadFailures:   values[7],
		Loads:          values[8],
		HelperRisk:     values[9],
	}, nil
}

// parseCoreBpfGuardEvents decodes "empty" or "<dropped>|<record>,<record>...".
func parseCoreBpfGuardEvents(response string) ([]CoreBpfGuardEvent, uint64, error) {
	if len(response) > maxBpfGuardPayloadBytes {
		return nil, 0, errors.New("core returned an oversized bpf-guard event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed bpf-guard batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed bpf-guard batch")
	}
	dropped, err := parseBpfGuardUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid bpf-guard drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxBpfGuardEventsPerResponse {
		return nil, 0, errors.New("core returned too many bpf-guard events")
	}
	events := make([]CoreBpfGuardEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxBpfGuardRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty bpf-guard record")
		}
		event, err := parseCoreBpfGuardEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

func parseCoreBpfGuardEvent(record string) (CoreBpfGuardEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 15 {
		return CoreBpfGuardEvent{}, errors.New("core returned a malformed bpf-guard event")
	}
	tsNS, tsErr := parseBpfGuardUint(fields[0], 64)
	pid, pidErr := parseBpfGuardUint(fields[1], 31)
	tgid, tgidErr := parseBpfGuardUint(fields[2], 31)
	uid, uidErr := parseBpfGuardUint(fields[3], 32)
	action, actionErr := parseBpfGuardUint(fields[4], 8)
	command, commandErr := parseBpfGuardUint(fields[5], 8)
	progType, progTypeErr := parseBpfGuardUint(fields[6], 8)
	helperMask, maskErr := parseBpfGuardUint(fields[7], 32)
	if tsErr != nil || pidErr != nil || tgidErr != nil || uidErr != nil ||
		actionErr != nil || commandErr != nil || progTypeErr != nil || maskErr != nil ||
		tsNS == 0 || pid == 0 || tgid == 0 {
		return CoreBpfGuardEvent{}, errors.New("core returned invalid bpf-guard event fields")
	}
	if action != uint64(BpfGuardActionObserved) && action != uint64(BpfGuardActionHelperRisk) &&
		action != uint64(BpfGuardActionDenied) {
		return CoreBpfGuardEvent{}, errors.New("core returned an unknown bpf-guard action")
	}
	if progType > uint64(BpfGuardProgTypeMax) {
		return CoreBpfGuardEvent{}, errors.New("core returned an out-of-range bpf-guard program type")
	}
	if helperMask > uint64(BpfGuardHelperMaskAll) || uint32(helperMask)&^BpfGuardHelperMaskAll != 0 {
		return CoreBpfGuardEvent{}, errors.New("core returned an unknown bpf-guard helper bit")
	}
	var helperIDs [BpfGuardHelperBitsPerEvent]uint32
	zeroSeen := false
	nonZeroIDs := 0
	for index := 0; index < BpfGuardHelperBitsPerEvent; index++ {
		identifier, identifierErr := parseBpfGuardUint(fields[8+index], 16)
		if identifierErr != nil || identifier > uint64(BpfGuardMaxHelperID) {
			return CoreBpfGuardEvent{}, errors.New("core returned an invalid bpf-guard helper id")
		}
		if identifier == 0 {
			zeroSeen = true
		} else if zeroSeen {
			return CoreBpfGuardEvent{}, errors.New("core returned non-compact bpf-guard helper ids")
		} else {
			if BpfGuardHelperIDToBit(uint32(identifier)) == 0 {
				return CoreBpfGuardEvent{}, errors.New("core returned a non-risk bpf-guard helper id")
			}
			nonZeroIDs++
		}
		helperIDs[index] = uint32(identifier)
	}
	if action == uint64(BpfGuardActionHelperRisk) {
		if helperMask == 0 || nonZeroIDs == 0 {
			return CoreBpfGuardEvent{}, errors.New("core returned a helper-risk event without helpers")
		}
	} else if helperMask != 0 || nonZeroIDs != 0 {
		return CoreBpfGuardEvent{}, errors.New("core returned an observed event with helper metadata")
	}
	exeDev, devErr := parseBpfGuardUint(fields[12], 32)
	exeIno, inoErr := parseBpfGuardUint(fields[13], 64)
	if devErr != nil || inoErr != nil || (exeDev == 0) != (exeIno == 0) {
		return CoreBpfGuardEvent{}, errors.New("core returned an invalid bpf-guard executable identity")
	}
	comm := ""
	if fields[14] != "" {
		if len(fields[14]) > 32 || len(fields[14])%2 != 0 {
			return CoreBpfGuardEvent{}, errors.New("core returned a malformed bpf-guard comm")
		}
		decoded, err := decodeStyxHex(fields[14], 16)
		if err != nil || len(decoded) == 0 {
			return CoreBpfGuardEvent{}, errors.New("core returned a malformed bpf-guard comm")
		}
		for _, character := range decoded {
			if character == 0 || character < 0x20 || character == 0x7f {
				return CoreBpfGuardEvent{}, errors.New("core returned a bpf-guard comm with rejected characters")
			}
		}
		comm = string(decoded)
	}
	return CoreBpfGuardEvent{
		TsNS:       tsNS,
		PID:        int(pid),
		TGID:       int(tgid),
		UID:        uint32(uid),
		Action:     uint8(action),
		Command:    uint8(command),
		ProgType:   uint8(progType),
		HelperMask: uint32(helperMask),
		HelperIDs:  helperIDs,
		ExeDev:     uint32(exeDev),
		ExeIno:     exeIno,
		Comm:       comm,
	}, nil
}
