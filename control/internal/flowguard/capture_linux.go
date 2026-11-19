//go:build linux

package flowguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// Packet-socket and Ethernet constants (linux/if_packet.h, if_ether.h).
const (
	ethPAll        = 0x0003
	ethPIPv4       = 0x0800
	ethPIPv6       = 0x86dd
	soAttachFilter = 26
	maxSockets     = 8
	maxFrameBytes  = 1 << 16
)

// Link/network/transport header sizes used by the frame decoder.
const (
	ethernetHeaderBytes = 14
	ipv4MinHeaderBytes  = 20
	ipv6HeaderBytes     = 40
	tcpMinHeaderBytes   = 20
	udpHeaderBytes      = 8
)

// OpenCapture opens one AF_PACKET raw socket per configured interface with the
// classic BPF prefilter generated from the configured ports (up to 8, TCP and
// UDP, IPv4 and IPv6). The exact payload predicate (TLS handshake byte 0x16 /
// QUIC long header) is applied in userspace because it needs the variable IP and
// TCP header lengths.
func OpenCapture(config CaptureConfig) (*Capture, error) {
	cfg := config.Normalize()
	program, err := handshakeBPF(cfg.Ports)
	if err != nil {
		return nil, fmt.Errorf("flowguard: build capture filter: %w", err)
	}
	capture := &Capture{config: cfg, buffer: make([]byte, maxFrameBytes)}
	interfaces := cfg.Interfaces
	if len(interfaces) == 0 {
		// An empty list means "every interface"; binding with ifindex 0 receives
		// from all of them through one socket.
		fd, err := openPacketSocket(0, program)
		if err != nil {
			return nil, err
		}
		capture.fds = append(capture.fds, fd)
		return capture, nil
	}
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			capture.Close()
			return nil, fmt.Errorf("capture interface %q: %w", name, err)
		}
		fd, err := openPacketSocket(iface.Index, program)
		if err != nil {
			capture.Close()
			return nil, err
		}
		capture.fds = append(capture.fds, fd)
		if len(capture.fds) >= maxSockets {
			break
		}
	}
	if len(capture.fds) == 0 {
		return nil, ErrUnsupported
	}
	return capture, nil
}

// openPacketSocket creates, binds and filters one AF_PACKET socket.
func openPacketSocket(ifindex int, program []syscall.SockFilter) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(ethPAll)))
	if err != nil {
		return -1, fmt.Errorf("%w: packet socket: %v", ErrUnsupported, err)
	}
	address := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifindex}
	if err := syscall.Bind(fd, address); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("%w: bind packet socket: %v", ErrUnsupported, err)
	}
	timeout := syscall.Timeval{Usec: 200000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	if err := attachPacketFilter(fd, program); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("%w: attach BPF filter: %v", ErrUnsupported, err)
	}
	return fd, nil
}

// attachPacketFilter installs a classic BPF program with SO_ATTACH_FILTER. The
// syscall package has no typed helper for sock_fprog, so the call is issued
// directly; the structure lives on the stack for the duration of the call and
// the kernel copies the program when it validates it.
func attachPacketFilter(fd int, program []syscall.SockFilter) error {
	if len(program) == 0 || len(program) > syscall.BPF_MAXINSNS {
		return errors.New("invalid BPF program length")
	}
	filter := syscall.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(soAttachFilter),
		uintptr(unsafe.Pointer(&filter)),
		unsafe.Sizeof(filter),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// Read blocks for at most one poll interval and returns the next bounded
// handshake candidate. Non-candidate frames are consumed and skipped.
func (c *Capture) Read() (Packet, error) {
	if c == nil || len(c.fds) == 0 {
		return Packet{}, ErrUnsupported
	}
	for index, fd := range c.fds {
		read, _, err := syscall.Recvfrom(fd, c.buffer, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				if index == len(c.fds)-1 {
					return Packet{}, ErrTimeout
				}
				continue
			}
			return Packet{}, err
		}
		if read <= 0 {
			continue
		}
		if packet, ok := decodeFrame(c.buffer[:read], c.config); ok {
			return packet, nil
		}
	}
	return Packet{}, ErrTimeout
}

// Close closes every packet socket.
func (c *Capture) Close() error {
	if c == nil {
		return nil
	}
	var result error
	for _, fd := range c.fds {
		if err := syscall.Close(fd); err != nil {
			result = err
		}
	}
	c.fds = nil
	return result
}

// decodeFrame parses the Ethernet/IP headers and applies the exact payload
// predicate: TCP TLS handshake record (0x16) or a QUIC long header (0x80 set and
// fixed bit 0x40 set).
//
// IPv4 and IPv6 are both decoded. IPv6 is bounded to a plain 40-byte header with
// a direct TCP/UDP next header: extension headers are rejected instead of being
// misread as a transport header, which is the same limitation the generated cBPF
// prefilter has, so userspace and kernel agree about what the sensor sees.
func decodeFrame(frame []byte, config CaptureConfig) (Packet, bool) {
	if len(frame) < ethernetHeaderBytes {
		return Packet{}, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	var (
		protocol  uint8
		srcIP     net.IP
		transport []byte
	)
	switch etherType {
	case ethPIPv4:
		network := frame[ethernetHeaderBytes:]
		if len(network) < ipv4MinHeaderBytes {
			return Packet{}, false
		}
		ipHeaderLen := int(network[0]&0x0f) * 4
		if ipHeaderLen < ipv4MinHeaderBytes || len(network) < ipHeaderLen+4 {
			return Packet{}, false
		}
		protocol = network[9]
		srcIP = net.IP(network[12:16])
		transport = network[ipHeaderLen:]
	case ethPIPv6:
		network := frame[ethernetHeaderBytes:]
		if len(network) < ipv6HeaderBytes+4 {
			return Packet{}, false
		}
		protocol = network[6]
		srcIP = net.IP(network[8:24])
		transport = network[ipv6HeaderBytes:]
	default:
		return Packet{}, false
	}
	srcPort := binary.BigEndian.Uint16(transport[0:2])
	dstPort := binary.BigEndian.Uint16(transport[2:4])
	switch protocol {
	case ipProtoTCP:
		if !containsPortValue(config.Ports, dstPort) {
			return Packet{}, false
		}
		if len(transport) < tcpMinHeaderBytes {
			return Packet{}, false
		}
		tcpHeaderLen := int(transport[12]>>4) * 4
		if tcpHeaderLen < tcpMinHeaderBytes || len(transport) < tcpHeaderLen {
			return Packet{}, false
		}
		tlsPayload := transport[tcpHeaderLen:]
		// The kernel filter already matched the destination port; a server-bound
		// ClientHello arrives with dstPort in the configured set.
		if len(tlsPayload) == 0 || tlsPayload[0] != 0x16 {
			return Packet{}, false
		}
		size := len(tlsPayload)
		if size > config.MaxPayloadBytes {
			size = config.MaxPayloadBytes
		}
		return Packet{
			Peer: srcIP.String(), PeerPort: srcPort, Port: dstPort,
			Payload: append([]byte(nil), tlsPayload[:size]...), At: time.Now().UTC(),
		}, true
	case ipProtoUDP:
		if !containsPortValue(config.Ports, dstPort) {
			return Packet{}, false
		}
		if len(transport) < udpHeaderBytes {
			return Packet{}, false
		}
		udpPayload := transport[udpHeaderBytes:]
		if len(udpPayload) < 1 || udpPayload[0]&0xc0 != 0xc0 {
			return Packet{}, false
		}
		size := len(udpPayload)
		if size > config.MaxPayloadBytes {
			size = config.MaxPayloadBytes
		}
		return Packet{
			Peer: srcIP.String(), PeerPort: srcPort, Port: dstPort,
			Payload: append([]byte(nil), udpPayload[:size]...), UDP: true, At: time.Now().UTC(),
		}, true
	default:
		return Packet{}, false
	}
}

// containsPortValue reports whether port is in ports.
func containsPortValue(ports []uint16, port uint16) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

// htons converts a 16-bit value to network byte order.
func htons(value uint16) uint16 { return value<<8 | value>>8 }
