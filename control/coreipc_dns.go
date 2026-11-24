// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-6: authenticated transport for the bounded DNS query capture
// (`DNS_EVENTS` / `DNS_STATUS` / `DNS_SET`).
//
// The kernel copies at most a bounded DNS header + QNAME window into the
// 64-byte `DNS_CAPTURE_EVENTS` record; this file frames and strictly validates
// the core's text projection. It is a strict transport:
//
//   - every answer is parsed all-or-nothing with bounded counters and payloads,
//   - the eight text fields are the exact core contract
//     `<ts_ns>:<pid>:<tgid>:<uid>:<qtype>:<comm_hex>:<qname_hex>:<fqdn_len>`,
//   - a core that predates the family answers "unknown command", which maps
//     onto ErrDnsUnavailable (a capability fact, not an XDR degradation),
//   - no field is repaired: a record that fails validation rejects the whole
//     batch so the analyser can never act on a partially parsed observation.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Core-side bounds (mirror `rust/gedefense-core/src/dns_capture.rs` and
// `rust/gedefense-common/src/dns_capture.rs`).
const (
	maxDnsEventsPerResponse = 16
	maxDnsPayloadBytes      = 4096
	maxDnsRecordBytes       = 160
	maxDnsStatusBytes       = 512
	// DNS wire text bounds: reconstructed query name (12-byte subdomain slot +
	// dot + 15-char suffix slot) and full presentation FQDN length.
	maxDnsQueryNameBytes = 28
	maxDnsFQDNLength     = 62
	maxDnsCommBytes      = 8
	dnsStatusFieldCount  = 5
)

// ErrDnsUnavailable marks a core without the DNS_CAPTURE_* command family.
var ErrDnsUnavailable = errors.New("dns capture capability unavailable")

// CoreDnsStatus is the strict projection of DNS_STATUS:
// `enabled=..:attached=..:events=..:drops=..:read_failures=..`.
//
// `AttachMask` is the raw core bitmask (bit0 = sys_enter_sendto attached,
// bit1 = sys_enter_sendmsg attached); `Attached` is only true when at least one
// hook is visible. A partial ladder is reported, never rounded up.
type CoreDnsStatus struct {
	Enabled      bool
	Attached     bool
	AttachMask   uint8
	Events       uint64
	Drops        uint64
	ReadFailures uint64
}

// CoreDnsEvent is one bounded DNS query observation.
//
// `QName` is the reconstructed grouping view (subdomain + "." + label-aligned
// suffix); `FQDNLen` is the full presentation length of the query name, so a
// clipped capture still carries the exact length that the `FQDN > 50`
// tunnelling signal needs. `Resolved` is true only when the capture stored the
// complete name (`len(QName) == FQDNLen`).
type CoreDnsEvent struct {
	TsNS     uint64
	PID      int
	TGID     int
	UID      uint32
	QType    uint16
	QName    string
	Comm     string
	Resolved bool
	FQDNLen  int
}

func (c *CoreClient) dnsCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrDnsUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// DnsSet arms (1) or disarms (0) the observe-only DNS capture.
func (c *CoreClient) DnsSet(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	response, err := c.dnsCommand("DNS_SET", value)
	if err != nil {
		return err
	}
	switch response {
	case "armed", "disarmed":
		return nil
	default:
		return fmt.Errorf("core returned unexpected dns set state %q", response)
	}
}

// DnsEvents drains one bounded batch of DNS query observations. The second
// return value is the saturating ring-drop delta since the previous poll.
func (c *CoreClient) DnsEvents() ([]CoreDnsEvent, uint64, error) {
	response, err := c.dnsCommand("DNS_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreDnsEvents(response)
}

// DnsStatus queries the DNS capture health.
func (c *CoreClient) DnsStatus() (CoreDnsStatus, error) {
	response, err := c.dnsCommand("DNS_STATUS")
	if err != nil {
		return CoreDnsStatus{}, err
	}
	return parseCoreDnsStatus(response)
}

func parseDnsUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized dns counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal dns counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range dns counter")
	}
	return value, nil
}

// parseCoreDnsStatus decodes the exactly-five `key=value` status fields.
func parseCoreDnsStatus(response string) (CoreDnsStatus, error) {
	if len(response) > maxDnsStatusBytes || response == "" ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreDnsStatus{}, errors.New("core returned a malformed dns status")
	}
	expected := []string{"enabled", "attached", "events", "drops", "read_failures"}
	fields := strings.Split(response, ":")
	if len(fields) != len(expected) {
		return CoreDnsStatus{}, errors.New("core returned a malformed dns status")
	}
	values := make([]uint64, len(expected))
	for index, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key != expected[index] {
			return CoreDnsStatus{}, errors.New("core returned an unknown dns status field")
		}
		parsed, err := parseDnsUint(value, 64)
		if err != nil {
			return CoreDnsStatus{}, errors.New("core returned invalid dns status counters")
		}
		values[index] = parsed
	}
	if values[0] > 1 {
		return CoreDnsStatus{}, errors.New("core returned an invalid dns enabled flag")
	}
	// attached is a bitmask over the two tracepoints (0..3).
	if values[1] > 3 {
		return CoreDnsStatus{}, errors.New("core returned an invalid dns attach mask")
	}
	return CoreDnsStatus{
		Enabled:      values[0] == 1,
		Attached:     values[1] != 0,
		AttachMask:   uint8(values[1]),
		Events:       values[2],
		Drops:        values[3],
		ReadFailures: values[4],
	}, nil
}

// parseCoreDnsEvents decodes "empty" or "<dropped>|<record>,<record>...".
// All-or-nothing: one malformed record rejects the whole batch.
func parseCoreDnsEvents(response string) ([]CoreDnsEvent, uint64, error) {
	if len(response) > maxDnsPayloadBytes {
		return nil, 0, errors.New("core returned an oversized dns event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed dns batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed dns batch")
	}
	dropped, err := parseDnsUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid dns drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxDnsEventsPerResponse {
		return nil, 0, errors.New("core returned too many dns events")
	}
	events := make([]CoreDnsEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxDnsRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty dns record")
		}
		event, parseErr := parseCoreDnsEvent(record)
		if parseErr != nil {
			return nil, 0, parseErr
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

func parseCoreDnsEvent(record string) (CoreDnsEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 8 {
		return CoreDnsEvent{}, errors.New("core returned a malformed dns event")
	}
	tsNS, tsErr := parseDnsUint(fields[0], 64)
	pid, pidErr := parseDnsUint(fields[1], 31)
	tgid, tgidErr := parseDnsUint(fields[2], 31)
	uid, uidErr := parseDnsUint(fields[3], 32)
	qtype, qtypeErr := parseDnsUint(fields[4], 16)
	if tsErr != nil || pidErr != nil || tgidErr != nil || uidErr != nil || qtypeErr != nil ||
		tsNS == 0 || pid == 0 || tgid == 0 || qtype == 0 {
		return CoreDnsEvent{}, errors.New("core returned invalid dns event fields")
	}
	comm, commErr := parseDnsComm(fields[5])
	if commErr != nil {
		return CoreDnsEvent{}, commErr
	}
	qname, qnameErr := parseDnsQName(fields[6])
	if qnameErr != nil {
		return CoreDnsEvent{}, qnameErr
	}
	fqdnLen, fqdnErr := parseDnsUint(fields[7], 8)
	if fqdnErr != nil || fqdnLen == 0 || fqdnLen > maxDnsFQDNLength {
		return CoreDnsEvent{}, errors.New("core returned an invalid dns fqdn length")
	}
	// The reconstructed grouping view can never be longer than the observed
	// full name; when it is shorter the capture was clipped (the truncation
	// flags are not needed on the wire — the length relation is the evidence).
	if len(qname) > int(fqdnLen) {
		return CoreDnsEvent{}, errors.New("core returned a dns qname longer than its fqdn")
	}
	return CoreDnsEvent{
		TsNS:     tsNS,
		PID:      int(pid),
		TGID:     int(tgid),
		UID:      uint32(uid),
		QType:    uint16(qtype),
		QName:    qname,
		Comm:     comm,
		Resolved: len(qname) == int(fqdnLen),
		FQDNLen:  int(fqdnLen),
	}, nil
}

// parseDnsComm validates the bounded task-name hex field.
func parseDnsComm(field string) (string, error) {
	if len(field) == 0 || len(field)%2 != 0 || len(field) > maxDnsCommBytes*2 {
		return "", errors.New("core returned a malformed dns comm")
	}
	decoded, err := decodeStyxHex(field, maxDnsCommBytes)
	if err != nil || len(decoded) == 0 {
		return "", errors.New("core returned a malformed dns comm")
	}
	for _, character := range decoded {
		if character < 0x20 || character > 0x7e {
			return "", errors.New("core returned a dns comm with rejected characters")
		}
	}
	return string(decoded), nil
}

// parseDnsQName validates the bounded query-name hex field: printable
// hostname bytes, no empty label, no leading/trailing dot.
func parseDnsQName(field string) (string, error) {
	if len(field) == 0 || len(field)%2 != 0 || len(field) > maxDnsQueryNameBytes*2 {
		return "", errors.New("core returned a malformed dns qname")
	}
	decoded, err := decodeStyxHex(field, maxDnsQueryNameBytes)
	if err != nil || len(decoded) == 0 {
		return "", errors.New("core returned a malformed dns qname")
	}
	if decoded[0] == '.' || decoded[len(decoded)-1] == '.' {
		return "", errors.New("core returned a dns qname with an empty label")
	}
	previousDot := false
	for _, character := range decoded {
		if character == '.' {
			if previousDot {
				return "", errors.New("core returned a dns qname with an empty label")
			}
			previousDot = true
			continue
		}
		previousDot = false
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return "", errors.New("core returned a dns qname with rejected characters")
	}
	return string(decoded), nil
}
