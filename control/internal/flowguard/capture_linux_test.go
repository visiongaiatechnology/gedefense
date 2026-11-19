//go:build linux

package flowguard

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

// TestDecodeFrameIPv6TCP proves the IPv6 TCP ClientHello path that the old
// decoder could not see: a plain 40-byte IPv6 header and a TLS record of 0x16 on
// a configured port must be returned with the 16-byte source address.
func TestDecodeFrameIPv6TCP(t *testing.T) {
	t.Parallel()
	config := CaptureConfig{Ports: []uint16{443}, MaxPayloadBytes: 1536}
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x20}
	payload := tcpSegment(443, clientHello)
	packet, ok := decodeFrame(ethernetFrame(ethPIPv6, ipv6Packet(ipProtoTCP, net.ParseIP("2001:db8::1").To16(), net.ParseIP("2001:db8::2").To16(), payload)), config)
	if !ok {
		t.Fatal("IPv6 TCP ClientHello was not decoded")
	}
	if packet.Peer != "2001:db8::1" || packet.PeerPort != 40000 || packet.Port != 443 {
		t.Fatalf("decoded IPv6 packet = %+v", packet)
	}
	if len(packet.Payload) == 0 || packet.Payload[0] != 0x16 || packet.UDP {
		t.Fatalf("decoded IPv6 payload = %+v", packet)
	}
}

// TestDecodeFrameUsesConfiguredPorts locks the port contract for both
// transports: TCP and UDP are checked against config.Ports, never a hard-coded
// 443. Port 80 and a non-configured UDP port are dropped.
func TestDecodeFrameUsesConfiguredPorts(t *testing.T) {
	t.Parallel()
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x20}
	quicInitial := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}
	dst4 := [4]byte{192, 0, 2, 10}
	dst6 := net.ParseIP("2001:db8::2").To16()

	cases := []struct {
		name   string
		config CaptureConfig
		frame  []byte
		accept bool
		udp    bool
		port   uint16
	}{
		{
			name:   "ipv4 tcp custom port",
			config: CaptureConfig{Ports: []uint16{10443}, MaxPayloadBytes: 1536},
			frame:  ethernetFrame(ethPIPv4, ipv4Packet(ipProtoTCP, dst4, tcpSegment(10443, clientHello), 0)),
			accept: true, port: 10443,
		},
		{
			name:   "ipv6 tcp 8443",
			config: CaptureConfig{Ports: []uint16{443, 8443}, MaxPayloadBytes: 1536},
			frame:  ethernetFrame(ethPIPv6, ipv6Packet(ipProtoTCP, net.ParseIP("2001:db8::1").To16(), dst6, tcpSegment(8443, clientHello))),
			accept: true, port: 8443,
		},
		{
			name:   "ipv4 udp custom port",
			config: CaptureConfig{Ports: []uint16{9443}, MaxPayloadBytes: 1536},
			frame:  ethernetFrame(ethPIPv4, ipv4Packet(ipProtoUDP, dst4, udpDatagram(9443, quicInitial), 0)),
			accept: true, udp: true, port: 9443,
		},
		{
			name:   "ipv6 udp 443",
			config: CaptureConfig{Ports: []uint16{443}, MaxPayloadBytes: 1536},
			frame:  ethernetFrame(ethPIPv6, ipv6Packet(ipProtoUDP, net.ParseIP("2001:db8::1").To16(), dst6, udpDatagram(443, quicInitial))),
			accept: true, udp: true, port: 443,
		},
		{
			name:   "ipv4 tcp port 80",
			config: CaptureConfig{Ports: []uint16{443, 8443}, MaxPayloadBytes: 1536},
			frame:  ethernetFrame(ethPIPv4, ipv4Packet(ipProtoTCP, dst4, tcpSegment(80, clientHello), 0)),
		},
		{
			name:   "ipv6 tcp port 80",
			config: CaptureConfig{Ports: []uint16{443}, MaxPayloadBytes: 1536},
			frame:  ethernetFrame(ethPIPv6, ipv6Packet(ipProtoTCP, net.ParseIP("2001:db8::1").To16(), dst6, tcpSegment(80, clientHello))),
		},
		{
			name:   "ipv4 udp port 443 without config",
			config: CaptureConfig{Ports: []uint16{8443}, MaxPayloadBytes: 1536},
			frame:  ethernetFrame(ethPIPv4, ipv4Packet(ipProtoUDP, dst4, udpDatagram(443, quicInitial), 0)),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			packet, ok := decodeFrame(tc.frame, tc.config)
			if ok != tc.accept {
				t.Fatalf("accepted=%t, want %t (packet %+v)", ok, tc.accept, packet)
			}
			if !tc.accept {
				return
			}
			if packet.Port != tc.port || packet.UDP != tc.udp {
				t.Fatalf("packet = %+v, want port %d udp=%t", packet, tc.port, tc.udp)
			}
		})
	}
}

// TestDecodeFrameIPv4HeaderOptions proves the decoder honours the IPv4 IHL, so a
// ClientHello behind a header with options is still parsed.
func TestDecodeFrameIPv4HeaderOptions(t *testing.T) {
	t.Parallel()
	config := CaptureConfig{Ports: []uint16{443}, MaxPayloadBytes: 1536}
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x20}
	frame := ethernetFrame(ethPIPv4, ipv4Packet(ipProtoTCP, [4]byte{192, 0, 2, 10}, tcpSegment(443, clientHello), 8))
	packet, ok := decodeFrame(frame, config)
	if !ok || packet.Port != 443 {
		t.Fatalf("IPv4 options frame was not decoded: ok=%t packet=%+v", ok, packet)
	}
}

// TestDecodeFrameIPv6Limitations locks the documented bounded limitation: IPv6
// with an extension header is rejected instead of being misread as TCP/UDP.
func TestDecodeFrameIPv6Limitations(t *testing.T) {
	t.Parallel()
	config := CaptureConfig{Ports: []uint16{443}, MaxPayloadBytes: 1536}
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x20}
	dst6 := net.ParseIP("2001:db8::2").To16()
	for name, nextHeader := range map[string]uint8{"hop-by-hop": 0, "routing": 43, "fragment": 44} {
		frame := ethernetFrame(ethPIPv6, ipv6Packet(nextHeader, net.ParseIP("2001:db8::1").To16(), dst6, tcpSegment(443, clientHello)))
		if _, ok := decodeFrame(frame, config); ok {
			t.Fatalf("IPv6 %s extension header frame was accepted", name)
		}
	}
}

// TestDecodeFrameRejectsTruncatedFrames keeps every short frame a clean
// rejection instead of a panic (the UDP length check used to slice past the end).
func TestDecodeFrameRejectsTruncatedFrames(t *testing.T) {
	t.Parallel()
	config := CaptureConfig{Ports: []uint16{443}, MaxPayloadBytes: 1536}
	frames := [][]byte{
		nil,
		make([]byte, 10),
		ethernetFrame(ethPIPv4, make([]byte, 4)),
		ethernetFrame(ethPIPv6, make([]byte, 20)),
		// IPv4 UDP header without the 8-byte UDP header.
		ethernetFrame(ethPIPv4, ipv4Packet(ipProtoUDP, [4]byte{192, 0, 2, 1}, []byte{0, 0, 1, 187}, 0)),
		// IPv6 TCP header shorter than the minimum TCP header.
		ethernetFrame(ethPIPv6, ipv6Packet(ipProtoTCP, net.ParseIP("2001:db8::1").To16(), net.ParseIP("2001:db8::2").To16(), []byte{0, 0, 1, 187})),
		ethernetFrame(0x0806, make([]byte, 28)),
	}
	for index, frame := range frames {
		if packet, ok := decodeFrame(frame, config); ok {
			t.Fatalf("truncated frame %d was accepted: %+v", index, packet)
		}
	}
}

// TestParseInetDiagMessagesMergesBothFamilies builds synthetic netlink dump
// answers for an IPv4 and an IPv6 socket and proves both are decoded with the
// right peer address and tcp_info counters.
func TestParseInetDiagMessagesMergesBothFamilies(t *testing.T) {
	t.Parallel()
	v4 := net.IPv4(192, 0, 2, 55).To4()
	v6 := net.ParseIP("2001:db8::55").To16()
	message := append(inetDiagRecord(syscall.AF_INET, 443, v4, 1000, 2000, 10, 20), inetDiagRecord(syscall.AF_INET6, 8443, v6, 3000, 4000, 30, 40)...)
	message = append(message, netlinkDone(1)...)
	samples, done, err := parseInetDiagMessages(message, 1, []uint16{443, 8443})
	if err != nil {
		t.Fatalf("parseInetDiagMessages: %v", err)
	}
	if !done || len(samples) != 2 {
		t.Fatalf("done=%t samples=%+v", done, samples)
	}
	if samples[0].Peer != "192.0.2.55" || samples[0].Port != 443 || samples[0].RxBytes != 2000 || samples[0].TxBytes != 1000 {
		t.Fatalf("IPv4 sample = %+v", samples[0])
	}
	if samples[1].Peer != "2001:db8::55" || samples[1].Port != 8443 || samples[1].SegsIn != 40 || samples[1].SegsOut != 30 {
		t.Fatalf("IPv6 sample = %+v", samples[1])
	}
	// An unconfigured local port is not published as a flow.
	if filtered, _, err := parseInetDiagMessages(inetDiagRecord(syscall.AF_INET, 80, v4, 1, 1, 1, 1), 1, []uint16{443}); err != nil || len(filtered) != 0 {
		t.Fatalf("port 80 leaked into the flow snapshot: %+v err=%v", filtered, err)
	}
}

// TestParseInetDiagMessagesSurfacesErrors keeps a refused dump honest: an
// NLMSG_ERROR record is an error, not an empty healthy result.
func TestParseInetDiagMessagesSurfacesErrors(t *testing.T) {
	t.Parallel()
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[0:], 16)
	binary.LittleEndian.PutUint16(record[4:], nlmsgError)
	binary.LittleEndian.PutUint32(record[8:], 1)
	if _, _, err := parseInetDiagMessages(record, 1, []uint16{443}); err == nil {
		t.Fatal("a netlink error record was swallowed")
	}
}

// TestBuildInetDiagRequestUsesFamily locks the requested address family.
func TestBuildInetDiagRequestUsesFamily(t *testing.T) {
	t.Parallel()
	request := buildInetDiagRequest(syscall.AF_INET6, 2)
	if len(request) != inetDiagRequestLen || int(request[16]) != syscall.AF_INET6 || request[17] != ipProtoTCP {
		t.Fatalf("request = %x", request)
	}
	if binary.LittleEndian.Uint32(request[8:]) != 2 {
		t.Fatalf("request sequence = %d", binary.LittleEndian.Uint32(request[8:]))
	}
	if v4 := buildInetDiagRequest(syscall.AF_INET, 1); int(v4[16]) != syscall.AF_INET {
		t.Fatalf("IPv4 request family byte = %d", v4[16])
	}
}

// inetDiagRecord builds one aligned SOCK_DIAG_BY_FAMILY message with an
// INET_DIAG_INFO attribute carrying the tcp_info counters.
func inetDiagRecord(family uint8, localPort uint16, peer net.IP, txBytes, rxBytes uint64, segsOut, segsIn uint32) []byte {
	const infoAttributeLen = 4 + 144
	payload := make([]byte, inetDiagMsgLen+infoAttributeLen)
	payload[0] = family
	binary.BigEndian.PutUint16(payload[4:6], localPort) // local (sport)
	binary.BigEndian.PutUint16(payload[6:8], 40000)     // peer (dport)
	if family == syscall.AF_INET {
		copy(payload[24:28], peer.To4())
	} else {
		copy(payload[24:40], peer.To16())
	}
	binary.LittleEndian.PutUint16(payload[72:74], infoAttributeLen)
	binary.LittleEndian.PutUint16(payload[74:76], inetDiagInfo)
	info := payload[76:]
	binary.NativeEndian.PutUint64(info[120:128], txBytes)
	binary.NativeEndian.PutUint64(info[128:136], rxBytes)
	binary.NativeEndian.PutUint32(info[136:140], segsOut)
	binary.NativeEndian.PutUint32(info[140:144], segsIn)
	message := make([]byte, 16+len(payload))
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.LittleEndian.PutUint16(message[4:6], sockDiagByFamily)
	binary.LittleEndian.PutUint32(message[8:12], 1)
	copy(message[16:], payload)
	return message
}

// netlinkDone builds the NLMSG_DONE terminator for a dump.
func netlinkDone(seq uint32) []byte {
	message := make([]byte, 16)
	binary.LittleEndian.PutUint32(message[0:4], 16)
	binary.LittleEndian.PutUint16(message[4:6], nlmsgDone)
	binary.LittleEndian.PutUint32(message[8:12], seq)
	return message
}
