// STATUS: V6.3.0 AP-9 (S12)
package main

// V6.3.0 AP-9 (S12): authenticated transport for the independent high-priority
// security evidence ring (`SEC_CRIT_*`).
//
// The kernel side (`rust/gedefense-ebpf/src/sec_crit.rs`) owns two classes of
// telemetry: bulk rings (exec argv, kernel probe, flow, DNS) pass a
// per-(class, cgroup, uid) token bucket, while critical security evidence
// (credential denies, attach-time eBPF helper risk, LKM loads, critical
// persistence records) is duplicated into the separate `SEC_CRIT_EVENTS` ring.
// This file is the strict transport for that family:
//
//   - every answer is parsed all-or-nothing: closed source/kind/action sets,
//     bounded counters, bounded payloads, exact field names/order, printable
//     `comm` and source-specific payload invariants. A single malformed record
//     rejects the whole batch (the caller then reports the drain as degraded
//     instead of acting on a partially parsed batch);
//   - a core that predates the family answers "unknown command", which maps
//     onto ErrSecCritUnavailable: a capability fact, never an XDR outage;
//   - the status wire is exactly the seven documented `key=value` fields.
//
// Wire contracts (mirrored from the core, see
// `rust/gedefense-core/src/sec_crit.rs`):
//
//	status: enabled=<0|1>:events=<u64>:drops=<u64>:refused_unarmed=<u64>:
//	        read_failures=<u64>:suppressed=<u64>:bucket_capacity=<u64>
//	events: "empty" | "<dropped>|<record>[,<record>]"
//	record: <ts>:<source>:<kind>:<action>:<detail_code>:<pid>:<tgid>:<uid>:
//	        <dev>:<ino>:<comm_hex>:<extra_hex>
//
// `bucket_capacity` is the flood-bucket map's documented capability bound
// (4096), deliberately labelled capacity and not "live buckets": the core does
// not enumerate live keys, so a live-count label would be a lie.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Core-side bounds (mirror `rust/gedefense-core/src/sec_crit.rs`).
const (
	maxSecCritEventsPerResponse = 16
	maxSecCritPayloadBytes      = 4096
	maxSecCritRecordBytes       = 320
	maxSecCritStatusBytes       = 512
	maxSecCritCommBytes         = 16
	maxSecCritExtraBytes        = 8
)

// Sources carried in `source` (`SEC_CRIT_SOURCE_*` in gedefense-common).
//
// The producer contract of this work package emits sources 1 (credential
// guard), 2 (attach-time eBPF guard), 3 (kernel hooks / LKM) and 7
// (persistence). Sources 4..6 are defined by the shared ABI for future
// producers and are accepted generically (closed range, same comm/action
// bounds) so an added producer does not require a control-plane release; their
// payload semantics are not invented here.
const (
	SecCritSourceCredGuard   uint8 = 1
	SecCritSourceBpfGuard    uint8 = 2
	SecCritSourceKernelHooks uint8 = 3
	SecCritSourceCrossView   uint8 = 4
	SecCritSourceSelfTamper  uint8 = 5
	SecCritSourceRansom      uint8 = 6
	SecCritSourcePersistence uint8 = 7
	SecCritSourceMax         uint8 = SecCritSourcePersistence
)

// Actions carried in `action` (`SEC_CRIT_ACTION_*`).
const (
	SecCritActionObserve uint8 = 1
	SecCritActionEnforce uint8 = 2
	SecCritActionMax     uint8 = SecCritActionEnforce
)

// Critical-record kinds (`kind` is namespaced by `source`; the documented
// producer contract uses kind 1 for every family, see the eBPF module table).
const (
	SecCritKindCredDeny      uint8 = 1
	SecCritKindBpfHelperRisk uint8 = 1
	SecCritKindLkmLoad       uint8 = 1
	SecCritKindPersistCrit   uint8 = 1
	SecCritKindMax           uint8 = SecCritKindLkmLoad
)

// Persistence class/kind payload bounds (`detail_code = class << 8 | kind`).
const (
	secCritPersistClassMin      uint32 = 1  // PERSIST_CLASS_LD_PRELOAD
	secCritPersistClassMax      uint32 = 11 // PERSIST_CLASS_SHELL_PROFILE
	secCritPersistKindIntegrity uint32 = 1  // PERSIST_KIND_INTEGRITY_WRITE
	secCritPersistKindLibrary   uint32 = 2  // PERSIST_KIND_LIBRARY_MMAP
	// secCritBpfHelperMaskAll is the closed helper-risk mask set produced by the
	// attach-time guard (probe_write_user | override_return | send_signal).
	secCritBpfHelperMaskAll uint32 = 0b111
)

// ErrSecCritUnavailable marks a core without the SEC_CRIT_* command family.
// It is a capability fact, not an XDR outage.
var ErrSecCritUnavailable = errors.New("sec-crit capability unavailable")

// CoreSecCritStatus is the strict projection of SEC_CRIT_STATUS: the exactly
// seven documented fields.
type CoreSecCritStatus struct {
	Enabled        bool
	Events         uint64
	Drops          uint64
	RefusedUnarmed uint64
	ReadFailures   uint64
	Suppressed     uint64
	BucketCapacity uint64
}

// CoreSecCritEvent is one decoded high-priority security evidence record.
// `Comm` is the decoded printable task name; `Extra` is the lowercase hex of
// the bounded 8-byte family payload (source-specific, documented in the eBPF
// module).
type CoreSecCritEvent struct {
	TsNS       uint64
	Source     uint8
	Kind       uint8
	Action     uint8
	DetailCode uint32
	PID        int
	TGID       int
	UID        uint32
	Dev        uint32
	Ino        uint64
	Comm       string
	Extra      string
}

// mapSecCritCommandError narrows a rejected VGT3 command to the capability
// sentinel: "unknown command"/"unsupported command" means the privileged core
// predates the SEC_CRIT_* family (a capability fact), every other error is a
// real transport/command failure and stays distinguishable.
func mapSecCritCommandError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
		return fmt.Errorf("%w: %v", ErrSecCritUnavailable, err)
	}
	return err
}

// secCritCommand runs one command and narrows a pre-S12 core to the capability
// sentinel instead of an XDR outage.
func (c *CoreClient) secCritCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		return "", mapSecCritCommandError(err)
	}
	return response, nil
}

// SecCritSet arms (1) or disarms (0) the high-priority observer. The core arms
// itself at load; this covers an explicitly disarmed core and makes a later
// operator disarm authoritative (the request latches in the engine).
func (c *CoreClient) SecCritSet(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	response, err := c.secCritCommand("SEC_CRIT_SET", value)
	if err != nil {
		return err
	}
	switch response {
	case "armed", "disarmed":
		return nil
	default:
		return fmt.Errorf("core returned unexpected sec-crit set state %q", response)
	}
}

// SecCritEvents drains one bounded batch of high-priority records. The second
// return value is the saturating ring-drop delta since the previous poll.
func (c *CoreClient) SecCritEvents() ([]CoreSecCritEvent, uint64, error) {
	response, err := c.secCritCommand("SEC_CRIT_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreSecCritEvents(response)
}

// SecCritStatus queries the high-priority ring and flood-bucket health.
func (c *CoreClient) SecCritStatus() (CoreSecCritStatus, error) {
	response, err := c.secCritCommand("SEC_CRIT_STATUS")
	if err != nil {
		return CoreSecCritStatus{}, err
	}
	return parseCoreSecCritStatus(response)
}

// parseSecCritUint is the shared bounded decimal parser for every numeric wire
// field (no signs, no whitespace, no exponent, 20-digit bound).
func parseSecCritUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized sec-crit counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal sec-crit counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range sec-crit counter")
	}
	return value, nil
}

// parseCoreSecCritStatus decodes the exactly-seven `key=value` status fields in
// the documented order. Unknown, missing, duplicated or reordered fields and
// non-binary flags are rejected: the status is a capability/health fact and
// must never be guessed.
func parseCoreSecCritStatus(response string) (CoreSecCritStatus, error) {
	if len(response) > maxSecCritStatusBytes || response == "" ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreSecCritStatus{}, errors.New("core returned a malformed sec-crit status")
	}
	expected := []string{
		"enabled", "events", "drops", "refused_unarmed",
		"read_failures", "suppressed", "bucket_capacity",
	}
	fields := strings.Split(response, ":")
	if len(fields) != len(expected) {
		return CoreSecCritStatus{}, errors.New("core returned a malformed sec-crit status")
	}
	values := make([]uint64, len(expected))
	for index, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key != expected[index] {
			return CoreSecCritStatus{}, errors.New("core returned an unknown sec-crit status field")
		}
		parsed, err := parseSecCritUint(value, 64)
		if err != nil {
			return CoreSecCritStatus{}, errors.New("core returned invalid sec-crit status counters")
		}
		values[index] = parsed
	}
	if values[0] > 1 {
		return CoreSecCritStatus{}, errors.New("core returned an invalid sec-crit enabled flag")
	}
	return CoreSecCritStatus{
		Enabled:        values[0] == 1,
		Events:         values[1],
		Drops:          values[2],
		RefusedUnarmed: values[3],
		ReadFailures:   values[4],
		Suppressed:     values[5],
		BucketCapacity: values[6],
	}, nil
}

// parseCoreSecCritEvents decodes "empty" or "<dropped>|<record>,<record>…".
// It is all-or-nothing: one malformed record rejects the whole batch.
func parseCoreSecCritEvents(response string) ([]CoreSecCritEvent, uint64, error) {
	if len(response) > maxSecCritPayloadBytes {
		return nil, 0, errors.New("core returned an oversized sec-crit event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed sec-crit batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed sec-crit batch")
	}
	dropped, err := parseSecCritUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid sec-crit drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxSecCritEventsPerResponse {
		return nil, 0, errors.New("core returned too many sec-crit events")
	}
	events := make([]CoreSecCritEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxSecCritRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty sec-crit record")
		}
		event, err := parseCoreSecCritEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

// secCritExtraIsZero reports whether the 8-byte `extra` payload is present in
// its documented zero form. The kernel emitter always writes the full 8-byte
// slot, so families without a payload must send eight zero bytes.
func secCritExtraIsZero(extra []byte) bool {
	if len(extra) != maxSecCritExtraBytes {
		return false
	}
	for _, value := range extra {
		if value != 0 {
			return false
		}
	}
	return true
}

// parseCoreSecCritEvent decodes one 12-field record and enforces the closed
// source/kind/action sets plus the documented per-source payload invariants.
// Every check is structural: a value the kernel producer cannot emit rejects
// the record (and with it the batch).
func parseCoreSecCritEvent(record string) (CoreSecCritEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 12 {
		return CoreSecCritEvent{}, errors.New("core returned a malformed sec-crit event")
	}
	tsNS, tsErr := parseSecCritUint(fields[0], 64)
	source, sourceErr := parseSecCritUint(fields[1], 8)
	kind, kindErr := parseSecCritUint(fields[2], 8)
	action, actionErr := parseSecCritUint(fields[3], 8)
	detailCode, detailErr := parseSecCritUint(fields[4], 32)
	pid, pidErr := parseSecCritUint(fields[5], 31)
	tgid, tgidErr := parseSecCritUint(fields[6], 31)
	uid, uidErr := parseSecCritUint(fields[7], 32)
	dev, devErr := parseSecCritUint(fields[8], 32)
	ino, inoErr := parseSecCritUint(fields[9], 64)
	if tsErr != nil || sourceErr != nil || kindErr != nil || actionErr != nil ||
		detailErr != nil || pidErr != nil || tgidErr != nil || uidErr != nil ||
		devErr != nil || inoErr != nil {
		return CoreSecCritEvent{}, errors.New("core returned invalid sec-crit event fields")
	}
	if tsNS == 0 || pid == 0 || tgid == 0 {
		return CoreSecCritEvent{}, errors.New("core returned a sec-crit event without identity")
	}
	if source == 0 || source > uint64(SecCritSourceMax) {
		return CoreSecCritEvent{}, errors.New("core returned an unknown sec-crit source")
	}
	if kind == 0 || kind > uint64(SecCritKindMax) {
		return CoreSecCritEvent{}, errors.New("core returned an unknown sec-crit kind")
	}
	if action == 0 || action > uint64(SecCritActionMax) {
		return CoreSecCritEvent{}, errors.New("core returned an unknown sec-crit action")
	}
	if len(fields[10]) > maxSecCritCommBytes*2 || len(fields[10])%2 != 0 || fields[10] == "" {
		return CoreSecCritEvent{}, errors.New("core returned a malformed sec-crit comm")
	}
	commBytes, err := decodeStyxHex(fields[10], maxSecCritCommBytes)
	if err != nil || len(commBytes) == 0 {
		return CoreSecCritEvent{}, errors.New("core returned a malformed sec-crit comm")
	}
	for _, character := range commBytes {
		if character < 0x20 || character > 0x7e {
			return CoreSecCritEvent{}, errors.New("core returned a sec-crit comm with rejected characters")
		}
	}
	extraBytes, err := decodeStyxHex(fields[11], maxSecCritExtraBytes)
	if err != nil {
		return CoreSecCritEvent{}, errors.New("core returned a malformed sec-crit extra payload")
	}

	// Source-specific payload invariants: the kernel producer documents exactly
	// these shapes, so anything else is a protocol violation, not "new data".
	switch uint8(source) {
	case SecCritSourceCredGuard:
		// Kernel-enforced credential deny: ENFORCE, real dev/ino, no extra.
		if uint8(action) != SecCritActionEnforce || dev == 0 || ino == 0 {
			return CoreSecCritEvent{}, errors.New("core returned an inconsistent credential-deny record")
		}
		if !secCritExtraIsZero(extraBytes) {
			return CoreSecCritEvent{}, errors.New("core returned a credential-deny record with extra payload")
		}
	case SecCritSourceBpfGuard:
		// Observe-only helper-risk verdict: OBSERVE, known mask, comm identity.
		if uint8(action) != SecCritActionObserve || detailCode == 0 ||
			detailCode > uint64(secCritBpfHelperMaskAll) || dev != 0 || ino != 0 {
			return CoreSecCritEvent{}, errors.New("core returned an inconsistent bpf-guard record")
		}
		if !secCritExtraIsZero(extraBytes) {
			return CoreSecCritEvent{}, errors.New("core returned a bpf-guard record with extra payload")
		}
	case SecCritSourceKernelHooks:
		// Module load/unload: OBSERVE, no file identity, taints/name in extra.
		if uint8(action) != SecCritActionObserve || dev != 0 || ino != 0 {
			return CoreSecCritEvent{}, errors.New("core returned an inconsistent lkm record")
		}
		if len(extraBytes) != maxSecCritExtraBytes {
			return CoreSecCritEvent{}, errors.New("core returned an lkm record without the documented extra payload")
		}
	case SecCritSourcePersistence:
		// Critical persistence record: OBSERVE, real dev/ino, class/kind pair.
		if uint8(action) != SecCritActionObserve || dev == 0 || ino == 0 {
			return CoreSecCritEvent{}, errors.New("core returned an inconsistent persistence record")
		}
		class := uint32(detailCode >> 8)
		recordKind := uint32(detailCode & 0xff)
		if class < secCritPersistClassMin || class > secCritPersistClassMax ||
			(recordKind != secCritPersistKindIntegrity && recordKind != secCritPersistKindLibrary) {
			return CoreSecCritEvent{}, errors.New("core returned an unknown persistence class/kind")
		}
		if len(extraBytes) != maxSecCritExtraBytes {
			return CoreSecCritEvent{}, errors.New("core returned a persistence record without the documented extra payload")
		}
	default:
		// Reserved sources 4..6: the shared ABI bounds are enforced above; no
		// payload semantic is invented for a family without a producer here.
	}
	if dev == 0 && ino != 0 || dev != 0 && ino == 0 {
		return CoreSecCritEvent{}, errors.New("core returned a partial sec-crit file identity")
	}
	return CoreSecCritEvent{
		TsNS:       tsNS,
		Source:     uint8(source),
		Kind:       uint8(kind),
		Action:     uint8(action),
		DetailCode: uint32(detailCode),
		PID:        int(pid),
		TGID:       int(tgid),
		UID:        uint32(uid),
		Dev:        uint32(dev),
		Ino:        ino,
		Comm:       string(commBytes),
		Extra:      strings.ToLower(fields[11]),
	}, nil
}
