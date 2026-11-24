// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-4: authenticated transport for the `io_uring`/LKM hook family
// (`KERNEL_HOOK_*`).
//
// The kernel half observes `io_uring` ring creation/registration/submission,
// module loads (tracepoint + pre-stealth kprobes) and the BTF-optional
// `uring_override_creds`/`uring_sqpoll`/`uring_cmd` LSM hooks; this file frames
// and validates the VGT3 records. It is a strict transport: every answer is
// parsed all-or-nothing with bounded counters, bounded payloads and a closed
// kind/action set, and a core that predates the family answers "unknown
// command", which maps onto ErrKernelHooksUnavailable (a capability fact, not an
// XDR outage).
//
// Wire formats (mirrored from `rust/gedefense-core/src/kernel_hooks.rs`):
//
//	KERNEL_HOOK_EPOCH       16 lowercase hex characters
//	KERNEL_HOOK_STATUS      enabled,attached,io_uring,module_trace,kprobes,
//	                        lsm_extra,events,drops,loads,ring_creates
//	KERNEL_HOOK_EVENTS      "empty" | "<dropped>|<record>[,<record>…]"
//	KERNEL_HOOK_SET         0|1 -> "armed"|"disarmed"
//
//	<record> = <ts>:<pid>:<tgid>:<uid>:<kind>:<action>:<detail_code>:<comm_hex>:<detail_hex>
//
// The event `comm` bytes are printable ASCII; the bounded `detail` bytes are
// kind-specific (the io_uring-create setup flags are native-endian u32, module
// details are the module name). Both are hex-transported so a record can never
// inject terminal control characters into an operator surface.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Core-side bounds (mirror `rust/gedefense-core/src/kernel_hooks.rs` and
// `rust/gedefense-common/src/kernel_hooks.rs`).
const (
	maxKernelHookEventsPerResponse = 16
	maxKernelHookPayloadBytes      = 4096
	maxKernelHookRecordBytes       = 320
	maxKernelHookStatusBytes       = 512
	kernelHookEpochHexLen          = 16
	// KernelHookDetailBytes is the bounded `detail` payload per record.
	KernelHookDetailBytes = 20
	// KernelHookCommBytes is the bounded NUL-padded `comm` per record.
	KernelHookCommBytes = 16
)

// Event kinds (`KERNEL_HOOK_KIND_*`). The set is closed and contiguous.
const (
	KernelHookKindIoUringCreate        uint8 = 1
	KernelHookKindIoUringRegister      uint8 = 2
	KernelHookKindIoUringSubmit        uint8 = 3
	KernelHookKindModuleLoad           uint8 = 4
	KernelHookKindModuleFinit          uint8 = 5
	KernelHookKindModuleDelete         uint8 = 6
	KernelHookKindLsmUringOverrideCred uint8 = 7
	KernelHookKindLsmUringSQPoll       uint8 = 8
	KernelHookKindLsmUringCmd          uint8 = 9
	KernelHookKindLkmTaint             uint8 = 10
	// KernelHookKindMax bounds the wire field: no producer can emit above it.
	KernelHookKindMax uint8 = 10
)

// Event actions (`KERNEL_HOOK_ACTION_*`).
const (
	// KernelHookActionAudit is the only action the observe-only producer emits.
	KernelHookActionAudit uint8 = 1
	// KernelHookActionDeny is a reserved token the shipped hooks never emit.
	KernelHookActionDeny uint8 = 2
)

// ErrKernelHooksUnavailable marks a core without the KERNEL_HOOK_* command family.
var ErrKernelHooksUnavailable = errors.New("kernel-hooks capability unavailable")

// CoreKernelHookStatus is the strict projection of KERNEL_HOOK_STATUS. The two
// ladder counts are reported as counts (0..3), not booleans, so an operator can
// see a partially attached ladder instead of only "true".
type CoreKernelHookStatus struct {
	Enabled     bool
	Attached    bool
	IoUring     bool
	ModuleTrace bool
	Kprobes     uint8
	LsmExtra    uint8
	Events      uint64
	Drops       uint64
	Loads       uint64
	RingCreates uint64
}

// CoreKernelHookEvent is one bounded kernel-hook observation.
type CoreKernelHookEvent struct {
	TsNS       uint64
	PID        int
	TGID       int
	UID        uint32
	Kind       uint8
	Action     uint8
	DetailCode uint32
	Detail     string
	Comm       string
}

// KernelHookKindName returns the stable operator name of one record kind.
func KernelHookKindName(kind uint8) string {
	switch kind {
	case KernelHookKindIoUringCreate:
		return "io_uring_create"
	case KernelHookKindIoUringRegister:
		return "io_uring_register"
	case KernelHookKindIoUringSubmit:
		return "io_uring_submit_req"
	case KernelHookKindModuleLoad:
		return "module_load"
	case KernelHookKindModuleFinit:
		return "finit_module"
	case KernelHookKindModuleDelete:
		return "delete_module"
	case KernelHookKindLsmUringOverrideCred:
		return "lsm_uring_override_creds"
	case KernelHookKindLsmUringSQPoll:
		return "lsm_uring_sqpoll"
	case KernelHookKindLsmUringCmd:
		return "lsm_uring_cmd"
	case KernelHookKindLkmTaint:
		return "lkm_taint"
	default:
		return fmt.Sprintf("kind_%d", kind)
	}
}

// KernelHookActionName returns the stable operator name of one record action.
func KernelHookActionName(action uint8) string {
	switch action {
	case KernelHookActionAudit:
		return "audit"
	case KernelHookActionDeny:
		return "deny"
	default:
		return fmt.Sprintf("action_%d", action)
	}
}

// KernelHookKindIsModule reports whether one kind belongs to the LKM family.
func KernelHookKindIsModule(kind uint8) bool {
	switch kind {
	case KernelHookKindModuleLoad, KernelHookKindModuleFinit,
		KernelHookKindModuleDelete, KernelHookKindLkmTaint:
		return true
	default:
		return false
	}
}

// KernelHookKindIsIoUring reports whether one kind belongs to the io_uring family.
func KernelHookKindIsIoUring(kind uint8) bool {
	switch kind {
	case KernelHookKindIoUringCreate, KernelHookKindIoUringRegister,
		KernelHookKindIoUringSubmit, KernelHookKindLsmUringOverrideCred,
		KernelHookKindLsmUringSQPoll, KernelHookKindLsmUringCmd:
		return true
	default:
		return false
	}
}

func (c *CoreClient) kernelHookCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrKernelHooksUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// KernelHookEpoch returns the random per-boot hook epoch (16 lowercase hex chars).
func (c *CoreClient) KernelHookEpoch() (string, error) {
	response, err := c.kernelHookCommand("KERNEL_HOOK_EPOCH")
	if err != nil {
		return "", err
	}
	return parseKernelHookEpoch(response)
}

func parseKernelHookEpoch(response string) (string, error) {
	if len(response) != kernelHookEpochHexLen {
		return "", errors.New("core returned a malformed kernel-hook epoch")
	}
	for index := 0; index < len(response); index++ {
		character := response[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "", errors.New("core returned a malformed kernel-hook epoch")
		}
	}
	return response, nil
}

// KernelHookStatus queries the hook health (capability + arm state + counters).
func (c *CoreClient) KernelHookStatus() (CoreKernelHookStatus, error) {
	response, err := c.kernelHookCommand("KERNEL_HOOK_STATUS")
	if err != nil {
		return CoreKernelHookStatus{}, err
	}
	return parseCoreKernelHookStatus(response)
}

// KernelHookEvents drains one bounded batch of hook records. The second return
// value is the saturating ring-drop delta since the previous poll.
func (c *CoreClient) KernelHookEvents() ([]CoreKernelHookEvent, uint64, error) {
	response, err := c.kernelHookCommand("KERNEL_HOOK_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreKernelHookEvents(response)
}

// KernelHookSet arms (1) or disarms (0) the observe-only hook family.
func (c *CoreClient) KernelHookSet(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	response, err := c.kernelHookCommand("KERNEL_HOOK_SET", value)
	if err != nil {
		return err
	}
	switch response {
	case "armed", "disarmed":
		return nil
	default:
		return fmt.Errorf("core returned unexpected kernel-hook set state %q", response)
	}
}

func parseKernelHookUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized kernel-hook counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal kernel-hook counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range kernel-hook counter")
	}
	return value, nil
}

// parseCoreKernelHookStatus decodes the exactly-ten `key=value` status fields.
func parseCoreKernelHookStatus(response string) (CoreKernelHookStatus, error) {
	if len(response) > maxKernelHookStatusBytes || response == "" ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreKernelHookStatus{}, errors.New("core returned a malformed kernel-hook status")
	}
	expected := []string{
		"enabled", "attached", "io_uring", "module_trace", "kprobes",
		"lsm_extra", "events", "drops", "loads", "ring_creates",
	}
	fields := strings.Split(response, ":")
	if len(fields) != len(expected) {
		return CoreKernelHookStatus{}, errors.New("core returned a malformed kernel-hook status")
	}
	values := make([]uint64, len(expected))
	for index, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key != expected[index] {
			return CoreKernelHookStatus{}, errors.New("core returned an unknown kernel-hook status field")
		}
		parsed, err := parseKernelHookUint(value, 64)
		if err != nil {
			return CoreKernelHookStatus{}, errors.New("core returned invalid kernel-hook status counters")
		}
		values[index] = parsed
	}
	// The two attach booleans are 0/1; the two ladder counts are bounded to the
	// three probes/hooks the core can attach.
	if values[0] > 1 || values[1] > 1 || values[2] > 1 || values[3] > 1 {
		return CoreKernelHookStatus{}, errors.New("core returned invalid kernel-hook status flags")
	}
	if values[4] > 3 || values[5] > 3 {
		return CoreKernelHookStatus{}, errors.New("core returned invalid kernel-hook attach counters")
	}
	return CoreKernelHookStatus{
		Enabled:     values[0] == 1,
		Attached:    values[1] == 1,
		IoUring:     values[2] == 1,
		ModuleTrace: values[3] == 1,
		Kprobes:     uint8(values[4]),
		LsmExtra:    uint8(values[5]),
		Events:      values[6],
		Drops:       values[7],
		Loads:       values[8],
		RingCreates: values[9],
	}, nil
}

// parseCoreKernelHookEvents decodes "empty" or "<dropped>|<record>,<record>...".
func parseCoreKernelHookEvents(response string) ([]CoreKernelHookEvent, uint64, error) {
	if len(response) > maxKernelHookPayloadBytes {
		return nil, 0, errors.New("core returned an oversized kernel-hook event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed kernel-hook batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed kernel-hook batch")
	}
	dropped, err := parseKernelHookUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid kernel-hook drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxKernelHookEventsPerResponse {
		return nil, 0, errors.New("core returned too many kernel-hook events")
	}
	events := make([]CoreKernelHookEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxKernelHookRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty kernel-hook record")
		}
		event, err := parseCoreKernelHookEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

func parseCoreKernelHookEvent(record string) (CoreKernelHookEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 9 {
		return CoreKernelHookEvent{}, errors.New("core returned a malformed kernel-hook event")
	}
	tsNS, tsErr := parseKernelHookUint(fields[0], 64)
	pid, pidErr := parseKernelHookUint(fields[1], 31)
	tgid, tgidErr := parseKernelHookUint(fields[2], 31)
	uid, uidErr := parseKernelHookUint(fields[3], 32)
	kind, kindErr := parseKernelHookUint(fields[4], 8)
	action, actionErr := parseKernelHookUint(fields[5], 8)
	detailCode, detailCodeErr := parseKernelHookUint(fields[6], 32)
	if tsErr != nil || pidErr != nil || tgidErr != nil || uidErr != nil ||
		kindErr != nil || actionErr != nil || detailCodeErr != nil ||
		tsNS == 0 || pid == 0 || tgid == 0 {
		return CoreKernelHookEvent{}, errors.New("core returned invalid kernel-hook event fields")
	}
	if kind == 0 || kind > uint64(KernelHookKindMax) {
		return CoreKernelHookEvent{}, errors.New("core returned an unknown kernel-hook kind")
	}
	if action != uint64(KernelHookActionAudit) && action != uint64(KernelHookActionDeny) {
		return CoreKernelHookEvent{}, errors.New("core returned an unknown kernel-hook action")
	}
	comm, err := parseKernelHookComm(fields[7])
	if err != nil {
		return CoreKernelHookEvent{}, err
	}
	detail, err := parseKernelHookDetail(fields[8])
	if err != nil {
		return CoreKernelHookEvent{}, err
	}
	return CoreKernelHookEvent{
		TsNS:       tsNS,
		PID:        int(pid),
		TGID:       int(tgid),
		UID:        uint32(uid),
		Kind:       uint8(kind),
		Action:     uint8(action),
		DetailCode: uint32(detailCode),
		Detail:     string(detail),
		Comm:       string(comm),
	}, nil
}

// parseKernelHookComm validates the hex-transported, NUL-free printable task
// name. An empty name is legal (the BPF comm helper can fail and the producer
// then emits a zeroed name).
func parseKernelHookComm(field string) ([]byte, error) {
	if field == "" {
		return nil, nil
	}
	if len(field) > KernelHookCommBytes*2 || len(field)%2 != 0 {
		return nil, errors.New("core returned a malformed kernel-hook comm")
	}
	decoded, err := decodeStyxHex(field, KernelHookCommBytes)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("core returned a malformed kernel-hook comm")
	}
	for _, character := range decoded {
		if character < 0x20 || character > 0x7e {
			return nil, errors.New("core returned a kernel-hook comm with rejected characters")
		}
	}
	return decoded, nil
}

// parseKernelHookDetail validates the bounded, kind-specific detail payload.
// The bytes are intentionally not restricted to printable characters: the
// io_uring-create setup flags are binary. Operators only ever see them
// hex-escaped, so a control byte cannot reach a terminal.
func parseKernelHookDetail(field string) ([]byte, error) {
	if field == "" {
		return nil, nil
	}
	if len(field) > KernelHookDetailBytes*2 || len(field)%2 != 0 {
		return nil, errors.New("core returned a malformed kernel-hook detail")
	}
	decoded, err := decodeStyxHex(field, KernelHookDetailBytes)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("core returned a malformed kernel-hook detail")
	}
	return decoded, nil
}
