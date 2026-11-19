//go:build linux

package flowguard

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

// runClassicBPF is a small userspace cBPF interpreter. It follows the documented
// kernel semantics for the opcodes the generated handshake prefilter uses:
// loads are bounded (out-of-bounds bytes read as 0), BPF_MSH sets
// X = 4*(P[k]&0xf), a conditional jump advances 1+offset, and BPF_RET returns
// the instruction constant. This lets the filter be exercised without root,
// CAP_NET_RAW or a real interface.
func runClassicBPF(program []syscall.SockFilter, frame []byte) uint32 {
	var accumulator, index uint32
	pc := 0
	for step := 0; step < 4096; step++ {
		if pc < 0 || pc >= len(program) {
			return 0
		}
		instruction := program[pc]
		switch instruction.Code {
		case syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS:
			accumulator = bpfLoadHalf(frame, instruction.K)
		case syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS:
			accumulator = bpfLoadByte(frame, instruction.K)
		case syscall.BPF_LDX | syscall.BPF_B | syscall.BPF_MSH:
			index = 4 * (bpfLoadByte(frame, instruction.K) & 0x0f)
		case syscall.BPF_LD | syscall.BPF_H | syscall.BPF_IND:
			accumulator = bpfLoadHalf(frame, index+instruction.K)
		case syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K:
			if accumulator == instruction.K {
				pc += int(instruction.Jt) + 1
			} else {
				pc += int(instruction.Jf) + 1
			}
			continue
		case syscall.BPF_RET | syscall.BPF_K:
			return instruction.K
		default:
			// Any opcode outside the generated subset: the test fails closed.
			return 0
		}
		pc++
	}
	return 0
}

func bpfLoadByte(frame []byte, offset uint32) uint32 {
	if int(offset) >= len(frame) {
		return 0
	}
	return uint32(frame[offset])
}

func bpfLoadHalf(frame []byte, offset uint32) uint32 {
	if int(offset)+1 >= len(frame) {
		return 0
	}
	return uint32(binary.BigEndian.Uint16(frame[offset : offset+2]))
}

// TestHandshakeBPFAcceptsConfiguredPorts runs the generated program against
// synthetic IPv4 and IPv6 TCP/UDP frames for every configured port.
func TestHandshakeBPFAcceptsConfiguredPorts(t *testing.T) {
	t.Parallel()
	ports := []uint16{443, 8443, 9443}
	program, err := handshakeBPF(ports)
	if err != nil {
		t.Fatalf("handshakeBPF: %v", err)
	}
	dst := net.ParseIP("2001:db8::1").To16()
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x20}
	quicInitial := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}
	for _, port := range ports {
		frames := map[string][]byte{
			"ipv4-tcp": ethernetFrame(ethPIPv4, ipv4Packet(ipProtoTCP, [4]byte{192, 0, 2, 1}, tcpSegment(port, clientHello), 0)),
			"ipv4-udp": ethernetFrame(ethPIPv4, ipv4Packet(ipProtoUDP, [4]byte{192, 0, 2, 1}, udpDatagram(port, quicInitial), 0)),
			"ipv6-tcp": ethernetFrame(ethPIPv6, ipv6Packet(ipProtoTCP, net.ParseIP("2001:db8::1").To16(), dst, tcpSegment(port, clientHello))),
			"ipv6-udp": ethernetFrame(ethPIPv6, ipv6Packet(ipProtoUDP, net.ParseIP("2001:db8::1").To16(), dst, udpDatagram(port, quicInitial))),
		}
		for name, frame := range frames {
			if verdict := runClassicBPF(program, frame); verdict != bpfAcceptVerdict {
				t.Fatalf("port %d %s frame was not accepted: verdict=%d", port, name, verdict)
			}
		}
	}
	// IPv4 header options: the IHL trick must still locate the TCP header.
	withOptions := ethernetFrame(ethPIPv4, ipv4Packet(ipProtoTCP, [4]byte{192, 0, 2, 1}, tcpSegment(443, clientHello), 4))
	if verdict := runClassicBPF(program, withOptions); verdict != bpfAcceptVerdict {
		t.Fatalf("IPv4 frame with header options was not accepted: verdict=%d", verdict)
	}
}

// TestHandshakeBPFRejectsNonCandidates proves the prefilter narrows to the
// configured handshake ports and the two supported network protocols only.
func TestHandshakeBPFRejectsNonCandidates(t *testing.T) {
	t.Parallel()
	program, err := handshakeBPF([]uint16{443})
	if err != nil {
		t.Fatalf("handshakeBPF: %v", err)
	}
	dst := net.ParseIP("2001:db8::1").To16()
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x20}
	cases := map[string][]byte{
		"ipv4-tcp-port-80": ethernetFrame(ethPIPv4, ipv4Packet(ipProtoTCP, [4]byte{192, 0, 2, 1}, tcpSegment(80, clientHello), 0)),
		"ipv4-udp-port-80": ethernetFrame(ethPIPv4, ipv4Packet(ipProtoUDP, [4]byte{192, 0, 2, 1}, udpDatagram(80, clientHello), 0)),
		"ipv6-tcp-port-80": ethernetFrame(ethPIPv6, ipv6Packet(ipProtoTCP, net.ParseIP("2001:db8::1").To16(), dst, tcpSegment(80, clientHello))),
		"ipv6-udp-port-80": ethernetFrame(ethPIPv6, ipv6Packet(ipProtoUDP, net.ParseIP("2001:db8::1").To16(), dst, udpDatagram(80, clientHello))),
		"ipv4-icmp":        ethernetFrame(ethPIPv4, ipv4Packet(1, [4]byte{192, 0, 2, 1}, make([]byte, 8), 0)),
		"ipv6-hop-by-hop":  ethernetFrame(ethPIPv6, ipv6Packet(0, net.ParseIP("2001:db8::1").To16(), dst, tcpSegment(443, clientHello))),
		"non-ip-ethertype": ethernetFrame(0x0806, make([]byte, 28)),
	}
	for name, frame := range cases {
		if verdict := runClassicBPF(program, frame); verdict != bpfDropVerdict {
			t.Fatalf("%s was accepted: verdict=%d", name, verdict)
		}
	}
}

// TestHandshakeBPFIsGeneratedFromPorts locks the FIND-003 contract: the program
// is not the old fixed 14-instruction 443/8443 constant, it is generated per
// configured port and stays well inside the kernel's instruction budget.
func TestHandshakeBPFIsGeneratedFromPorts(t *testing.T) {
	t.Parallel()
	onePort, err := handshakeBPF([]uint16{443})
	if err != nil {
		t.Fatalf("handshakeBPF(1): %v", err)
	}
	eightPorts, err := handshakeBPF([]uint16{443, 8443, 9443, 10443, 11443, 12443, 13443, 14443})
	if err != nil {
		t.Fatalf("handshakeBPF(8): %v", err)
	}
	deduplicated, err := handshakeBPF([]uint16{443, 443, 443})
	if err != nil {
		t.Fatalf("handshakeBPF(dup): %v", err)
	}
	if len(onePort) == 14 {
		t.Fatal("the filter is still the fixed 14-instruction program")
	}
	if len(deduplicated) != len(onePort) {
		t.Fatalf("duplicate ports changed the program: %d vs %d instructions", len(deduplicated), len(onePort))
	}
	if len(eightPorts) <= len(onePort) {
		t.Fatalf("more ports did not grow the program: %d vs %d instructions", len(eightPorts), len(onePort))
	}
	if len(eightPorts) > syscall.BPF_MAXINSNS {
		t.Fatalf("generated program has %d instructions, above BPF_MAXINSNS", len(eightPorts))
	}
	if _, err := handshakeBPF(nil); err == nil {
		t.Fatal("handshakeBPF accepted an empty port list")
	}
}

// ethernetFrame wraps a network-layer payload in a minimal Ethernet header.
func ethernetFrame(etherType uint16, payload []byte) []byte {
	frame := make([]byte, ethernetHeaderBytes+len(payload))
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[ethernetHeaderBytes:], payload)
	return frame
}

// ipv4Packet builds a minimal IPv4 packet with an optional 4-byte-multiple
// options area, so the BPF IHL trick can be exercised.
func ipv4Packet(protocol uint8, dst [4]byte, transport []byte, optionsBytes int) []byte {
	headerBytes := ipv4MinHeaderBytes + optionsBytes
	header := make([]byte, headerBytes)
	header[0] = 0x40 | byte(headerBytes/4)
	binary.BigEndian.PutUint16(header[2:4], uint16(headerBytes+len(transport)))
	header[8] = 64
	header[9] = protocol
	copy(header[16:20], dst[:])
	return append(header, transport...)
}

// ipv6Packet builds a minimal IPv6 packet with a direct next header.
func ipv6Packet(nextHeader uint8, src, dst net.IP, transport []byte) []byte {
	header := make([]byte, ipv6HeaderBytes)
	header[0] = 0x60
	binary.BigEndian.PutUint16(header[4:6], uint16(len(transport)))
	header[6] = nextHeader
	header[7] = 64
	copy(header[8:24], src.To16())
	copy(header[24:40], dst.To16())
	return append(header, transport...)
}

// tcpSegment builds a minimal TCP header (20 bytes) with the given destination
// port and payload.
func tcpSegment(dstPort uint16, payload []byte) []byte {
	segment := make([]byte, tcpMinHeaderBytes)
	binary.BigEndian.PutUint16(segment[0:2], 40000)
	binary.BigEndian.PutUint16(segment[2:4], dstPort)
	segment[12] = 5 << 4
	segment[13] = 0x02
	return append(segment, payload...)
}

// udpDatagram builds a minimal UDP header with the given destination port.
func udpDatagram(dstPort uint16, payload []byte) []byte {
	datagram := make([]byte, udpHeaderBytes)
	binary.BigEndian.PutUint16(datagram[0:2], 40000)
	binary.BigEndian.PutUint16(datagram[2:4], dstPort)
	binary.BigEndian.PutUint16(datagram[4:6], uint16(udpHeaderBytes+len(payload)))
	return append(datagram, payload...)
}
