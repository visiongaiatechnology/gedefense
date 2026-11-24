// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

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

// CoreActionDispatcher implementation
func (c *CoreClient) BlockIP(ip string) error {
	return c.Add(ip)
}

func (c *CoreClient) UnblockIP(ip string) error {
	return c.Delete(ip)
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
