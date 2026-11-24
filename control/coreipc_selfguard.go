// STATUS: V6.3.0 AP-0
package main

// V6.3.0 AP-0: authenticated transport for the kernel sensor self-protection
// family (`SELF_GUARD_STATUS` / `SELF_TAMPER_EVENTS` / `SELF_GUARD_SET`).
//
// The privileged Rust core owns the eBPF pin manifest, the synthetic canary
// self-test and a bounded self-tamper evidence queue. This file only frames and
// strictly validates the VGT3 records; the XDR semantics live in
// xdr_selfguard.go.
//
// Wire contracts (exact, all-or-nothing):
//
//	SELF_GUARD_STATUS  -> "enabled=<0|1>:pins=<unavailable|0..4096>:missing=<u64>:
//	                       replaced=<u64>:canary=<active|degraded|unknown>:
//	                       canary_runs=<u64>:canary_failures=<u64>:
//	                       events=<u64>:dropped=<u64>"
//	SELF_TAMPER_EVENTS -> "empty" | "<dropped>|<ts_ms>:<kind>:<detail_code>:<detail_hex>[,<record>...]"
//	                       (<= 8 records, <= 2048 bytes, kind 1..6, detail <= 32 bytes)
//	SELF_GUARD_SET     -> "armed" (token 1) | "disarmed" (token 0)
//
// A core that predates the family answers "unknown command"; that maps onto
// ErrSelfGuardUnavailable, a capability fact and never an XDR degradation.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// maxSelfGuardStatusBytes bounds one SELF_GUARD_STATUS payload before it is
	// split. The core's own formatter is well below this; anything above it is
	// corruption rather than a longer legit answer.
	maxSelfGuardStatusBytes = 512
	// maxSelfGuardPayloadBytes bounds one SELF_TAMPER_EVENTS payload (AP-0
	// contract: <= 2 KiB).
	maxSelfGuardPayloadBytes = 2048
	// maxSelfGuardEventsPerResponse mirrors the core's drain ceiling.
	maxSelfGuardEventsPerResponse = 8
	// maxSelfGuardRecordBytes bounds one self-tamper record before it is split.
	maxSelfGuardRecordBytes = 128
	// maxSelfGuardDetailBytes bounds the decoded detail (hex-encoded on the wire).
	maxSelfGuardDetailBytes = 32
	// maxSelfGuardPins bounds the expected pin count; the core never pins more
	// than its critical-map manifest.
	maxSelfGuardPins = 4096
	// maxSelfGuardCounter rejects absurd monotone counters that would only be
	// produced by a corrupt or hostile core.
	maxSelfGuardCounter = 1 << 62
)

// Self-tamper record kinds (AP-0 wire contract).
const (
	SelfGuardKindPinMissing       uint8 = 1
	SelfGuardKindPinReplaced      uint8 = 2
	SelfGuardKindCanaryDead       uint8 = 3
	SelfGuardKindBpffsUnavailable uint8 = 4
	SelfGuardKindPinRestored      uint8 = 5
	SelfGuardKindCanaryRecovered  uint8 = 6
)

// ErrSelfGuardUnavailable marks a core without the SELF_GUARD_* command family.
// It is a capability fact, not an XDR degradation.
var ErrSelfGuardUnavailable = errors.New("self-guard capability unavailable")

// CoreSelfGuardStatus is the strict projection of SELF_GUARD_STATUS.
//
// All counters are monotonic (they count observations, not current state):
// PinsMissing/PinsReplaced count pin transitions, Events counts enqueued
// self-tamper records and QueueDropped counts records lost to queue overflow.
// PinsAvailable is false when the core reported `pins=unavailable` (no BPF
// filesystem at the pin root); PinsExpected is 0 in that case. Paths are never
// part of this wire.
type CoreSelfGuardStatus struct {
	Enabled        bool
	Armed          bool
	PinsAvailable  bool
	PinsExpected   uint64
	PinsMissing    uint64
	PinsReplaced   uint64
	CanaryState    string
	CanaryRuns     uint64
	CanaryFailures uint64
	Events         uint64
	QueueDropped   uint64
}

// CoreSelfTamperEvent is one bounded self-tamper record. TsMS is the core's
// wall-clock timestamp in milliseconds; Detail is the decoded, printable
// <= 32-byte machine label (never a path).
type CoreSelfTamperEvent struct {
	TsMS       uint64
	Kind       uint8
	DetailCode uint32
	Detail     string
}

// selfGuardCommand issues one SELF_GUARD_* command and classifies the
// backwards-compatible "unknown command" rejection as ErrSelfGuardUnavailable.
func (c *CoreClient) selfGuardCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		return "", mapSelfGuardCommandError(err)
	}
	return response, nil
}

// mapSelfGuardCommandError narrows a rejected VGT3 command to the capability
// sentinel. Any other transport or authentication error is returned unchanged.
func mapSelfGuardCommandError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
		return fmt.Errorf("%w: %v", ErrSelfGuardUnavailable, err)
	}
	return err
}

// SelfGuardStatus queries the core self-protection health.
func (c *CoreClient) SelfGuardStatus() (CoreSelfGuardStatus, error) {
	response, err := c.selfGuardCommand("SELF_GUARD_STATUS")
	if err != nil {
		return CoreSelfGuardStatus{}, err
	}
	return parseCoreSelfGuardStatus(response)
}

// SelfTamperEvents drains bounded self-tamper records. The second return value
// is the queue-overflow delta since the previous drain.
func (c *CoreClient) SelfTamperEvents() ([]CoreSelfTamperEvent, uint64, error) {
	response, err := c.selfGuardCommand("SELF_TAMPER_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreSelfTamperEvents(response)
}

// SelfGuardSet arms or disarms the self-protection observers.
func (c *CoreClient) SelfGuardSet(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	response, err := c.selfGuardCommand("SELF_GUARD_SET", value)
	if err != nil {
		return err
	}
	return parseCoreSelfGuardSetResponse(enabled, response)
}

// parseCoreSelfGuardSetResponse requires the exact closed token for the
// requested state; a core that answers anything else has not applied the arm.
func parseCoreSelfGuardSetResponse(enabled bool, response string) error {
	expected := "disarmed"
	if enabled {
		expected = "armed"
	}
	if response != expected {
		return fmt.Errorf("core returned unexpected self-guard set state %q", response)
	}
	return nil
}

// validSelfGuardWireText rejects empty, oversized and control-character-bearing
// payloads. The core never emits a newline, NUL or C0 control on this wire.
func validSelfGuardWireText(response string, maxBytes int) error {
	if len(response) == 0 || len(response) > maxBytes {
		return errors.New("core returned an empty or oversized self-guard payload")
	}
	for index := 0; index < len(response); index++ {
		character := response[index]
		if character < 0x20 || character > 0x7e {
			return errors.New("core returned a self-guard payload with rejected characters")
		}
	}
	if strings.TrimSpace(response) != response {
		return errors.New("core returned a self-guard payload with rejected padding")
	}
	return nil
}

// parseSelfGuardUint accepts only plain decimal digits, bounded in length and
// range; it never trusts strconv's permissiveness with signs or whitespace.
func parseSelfGuardUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized self-guard counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal self-guard counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range self-guard counter")
	}
	return value, nil
}

// parseCoreSelfGuardStatus decodes the nine fixed key=value fields.
func parseCoreSelfGuardStatus(response string) (CoreSelfGuardStatus, error) {
	status := CoreSelfGuardStatus{}
	if err := validSelfGuardWireText(response, maxSelfGuardStatusBytes); err != nil {
		return status, err
	}
	fields := strings.Split(response, ":")
	if len(fields) != 9 {
		return status, errors.New("core returned a malformed self-guard status")
	}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "" || value == "" {
			return status, errors.New("core returned a malformed self-guard status field")
		}
		switch key {
		case "enabled", "pins", "missing", "replaced", "canary", "canary_runs",
			"canary_failures", "events", "dropped":
		default:
			return status, errors.New("core returned an unknown self-guard status field")
		}
		if _, duplicate := values[key]; duplicate {
			return status, errors.New("core returned a duplicate self-guard status field")
		}
		values[key] = value
	}
	if len(values) != 9 {
		return status, errors.New("core returned an incomplete self-guard status")
	}

	switch values["enabled"] {
	case "0":
		status.Enabled = false
	case "1":
		status.Enabled = true
	default:
		return status, errors.New("core returned an invalid self-guard enabled flag")
	}
	status.Armed = status.Enabled

	if values["pins"] == "unavailable" {
		status.PinsAvailable = false
	} else {
		pins, err := parseSelfGuardUint(values["pins"], 32)
		if err != nil || pins > maxSelfGuardPins {
			return status, errors.New("core returned an invalid self-guard pin count")
		}
		status.PinsAvailable = true
		status.PinsExpected = pins
	}

	counters := []struct {
		key  string
		dest *uint64
	}{
		{"missing", &status.PinsMissing},
		{"replaced", &status.PinsReplaced},
		{"canary_runs", &status.CanaryRuns},
		{"canary_failures", &status.CanaryFailures},
		{"events", &status.Events},
		{"dropped", &status.QueueDropped},
	}
	for _, counter := range counters {
		value, err := parseSelfGuardUint(values[counter.key], 64)
		if err != nil || value > maxSelfGuardCounter {
			return status, errors.New("core returned an invalid self-guard status counter")
		}
		*counter.dest = value
	}

	switch values["canary"] {
	case "active", "degraded", "unknown":
		status.CanaryState = values["canary"]
	default:
		return status, errors.New("core returned an invalid self-guard canary state")
	}

	// Pin observations are a subset of all enqueued records; a core that claims
	// more pin facts than records is corrupt and is rejected, not repaired.
	if status.PinsMissing > status.Events || status.PinsReplaced > status.Events ||
		status.PinsMissing+status.PinsReplaced > status.Events {
		return status, errors.New("core returned inconsistent self-guard status counters")
	}
	return status, nil
}

// parseCoreSelfTamperEvents decodes "empty" or
// "<dropped>|<ts_ms>:<kind>:<detail_code>:<detail_hex>[,<record>...]".
func parseCoreSelfTamperEvents(response string) ([]CoreSelfTamperEvent, uint64, error) {
	if len(response) > maxSelfGuardPayloadBytes {
		return nil, 0, errors.New("core returned an oversized self-tamper batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if err := validSelfGuardWireText(response, maxSelfGuardPayloadBytes); err != nil {
		return nil, 0, err
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed self-tamper batch")
	}
	dropped, err := parseSelfGuardUint(droppedText, 64)
	if err != nil || dropped > maxSelfGuardCounter {
		return nil, 0, errors.New("core returned an invalid self-tamper drop counter")
	}
	if recordsText == "" {
		// A drop-only answer is valid: the queue overflowed between drains.
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxSelfGuardEventsPerResponse {
		return nil, 0, errors.New("core returned too many self-tamper records")
	}
	events := make([]CoreSelfTamperEvent, 0, len(records))
	var previousTS uint64
	for _, record := range records {
		event, err := parseCoreSelfTamperRecord(record)
		if err != nil {
			return nil, 0, err
		}
		// The core drains its FIFO queue in order; a decreasing timestamp means
		// the record stream is not the one the core produced.
		if event.TsMS < previousTS {
			return nil, 0, errors.New("core returned out-of-order self-tamper records")
		}
		previousTS = event.TsMS
		events = append(events, event)
	}
	return events, dropped, nil
}

// parseCoreSelfTamperRecord decodes one four-field record.
func parseCoreSelfTamperRecord(record string) (CoreSelfTamperEvent, error) {
	event := CoreSelfTamperEvent{}
	if len(record) == 0 || len(record) > maxSelfGuardRecordBytes {
		return event, errors.New("core returned an empty or oversized self-tamper record")
	}
	fields := strings.Split(record, ":")
	if len(fields) != 4 {
		return event, errors.New("core returned a malformed self-tamper record")
	}
	tsMS, tsErr := parseSelfGuardUint(fields[0], 64)
	kind, kindErr := parseSelfGuardUint(fields[1], 8)
	detailCode, codeErr := parseSelfGuardUint(fields[2], 32)
	if tsErr != nil || tsMS == 0 || tsMS > maxSelfGuardCounter {
		return event, errors.New("core returned an invalid self-tamper timestamp")
	}
	if kindErr != nil || kind < uint64(SelfGuardKindPinMissing) || kind > uint64(SelfGuardKindCanaryRecovered) {
		return event, errors.New("core returned an unknown self-tamper kind")
	}
	if codeErr != nil {
		return event, errors.New("core returned an invalid self-tamper detail code")
	}
	detail := ""
	if fields[3] != "" {
		decoded, err := decodeStyxHex(fields[3], maxSelfGuardDetailBytes)
		if err != nil || len(decoded) == 0 {
			return event, errors.New("core returned a malformed self-tamper detail")
		}
		for _, character := range decoded {
			if character < 0x20 || character > 0x7e {
				return event, errors.New("core returned a self-tamper detail with rejected characters")
			}
		}
		detail = string(decoded)
	}
	return CoreSelfTamperEvent{
		TsMS:       tsMS,
		Kind:       uint8(kind),
		DetailCode: uint32(detailCode),
		Detail:     detail,
	}, nil
}
