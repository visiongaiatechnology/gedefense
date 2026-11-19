//go:build linux

package flowguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// NETLINK_SOCK_DIAG / INET_DIAG ABI constants (linux/sock_diag.h,
// linux/netlink.h, linux/inet_diag.h).
const (
	netlinkSockDiag    = 4
	sockDiagByFamily   = 20
	inetDiagInfo       = 2
	inetDiagMsgLen     = 72
	nlmsgDone          = 3
	nlmsgError         = 2
	nlmFRequest        = 0x1
	nlmFDump           = 0x300
	ipProtoTCP         = 6
	ipProtoUDP         = 17
	tcpListenAllStates = 0xfff
	// inet_diag_req_v2 (56 bytes) behind the 16-byte nlmsghdr.
	inetDiagRequestLen = 16 + 56
	// One bounded netlink receive buffer for a socket-dump answer.
	maxSockDiagFrameBytes = 64 << 10
)

// ReadFlowSnapshot reads the per-socket counters through NETLINK_SOCK_DIAG for
// both address families and merges the results.
//
// Dumping only AF_INET hid every dual-stack socket: a listener on `[::]:443`
// (which also serves IPv4-mapped clients) only appears in the AF_INET6 dump and
// was therefore invisible to the control-storm predicate. Both families are
// queried; a family whose dump fails is reported as an error (a blind spot the
// caller publishes as a reason) instead of returning a silently truncated view.
func ReadFlowSnapshot(ports []uint16, limit int) ([]FlowSample, error) {
	if len(ports) == 0 {
		ports = CaptureConfig{}.Normalize().Ports
	}
	if limit <= 0 || limit > 65536 {
		limit = 4096
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkSockDiag)
	if err != nil {
		return nil, fmt.Errorf("%w: sock_diag socket: %v", ErrUnsupported, err)
	}
	defer syscall.Close(fd)
	timeout := syscall.Timeval{Usec: 500000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	families := [...]int{syscall.AF_INET, syscall.AF_INET6}
	samples := make([]FlowSample, 0, 64)
	var failures []error
	for index, family := range families {
		if len(samples) >= limit {
			break
		}
		batch, familyErr := readInetDiagFamily(fd, family, uint32(index+1), ports, limit-len(samples))
		if familyErr != nil {
			failures = append(failures, fmt.Errorf("inet_diag family %d: %w", family, familyErr))
			continue
		}
		samples = append(samples, batch...)
	}
	if len(samples) > limit {
		samples = samples[:limit]
	}
	if len(failures) > 0 {
		return samples, errors.Join(failures...)
	}
	return samples, nil
}

// readInetDiagFamily sends one SOCK_DIAG_BY_FAMILY dump and collects its answer.
func readInetDiagFamily(fd, family int, seq uint32, ports []uint16, limit int) ([]FlowSample, error) {
	request := buildInetDiagRequest(family, seq)
	if err := syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("inet_diag request: %w", err)
	}
	samples := make([]FlowSample, 0, 16)
	buffer := make([]byte, maxSockDiagFrameBytes)
	for {
		read, _, recvErr := syscall.Recvfrom(fd, buffer, 0)
		if recvErr != nil {
			if errors.Is(recvErr, syscall.EAGAIN) || errors.Is(recvErr, syscall.EWOULDBLOCK) || errors.Is(recvErr, syscall.EINTR) {
				// The dump timer expired; the kernel sent everything it had.
				break
			}
			return samples, fmt.Errorf("inet_diag receive: %w", recvErr)
		}
		if read <= 0 {
			break
		}
		batch, done, parseErr := parseInetDiagMessages(buffer[:read], seq, ports)
		samples = append(samples, batch...)
		if parseErr != nil {
			return samples, parseErr
		}
		if done || len(samples) >= limit {
			return samples, nil
		}
	}
	return samples, nil
}

// buildInetDiagRequest builds the SOCK_DIAG_BY_FAMILY dump request for one
// address family.
func buildInetDiagRequest(family int, seq uint32) []byte {
	request := make([]byte, inetDiagRequestLen)
	binary.LittleEndian.PutUint32(request[0:], uint32(inetDiagRequestLen))
	binary.LittleEndian.PutUint16(request[4:], sockDiagByFamily)
	binary.LittleEndian.PutUint16(request[6:], nlmFRequest|nlmFDump)
	binary.LittleEndian.PutUint32(request[8:], seq)
	request[16] = byte(family) // idiag_family
	request[17] = ipProtoTCP   // idiag_protocol
	request[18] = inetDiagInfo // idiag_ext
	binary.LittleEndian.PutUint32(request[20:], tcpListenAllStates)
	return request
}

// parseInetDiagMessages walks one netlink datagram and returns the flow samples.
// Records with a foreign sequence number are skipped, so a timeout that left a
// previous family's answer queued can never be merged into the next family's
// snapshot. An NLMSG_ERROR record is returned as an error, so a refused dump (for
// example a kernel without the AF_INET6 diag handler) is never mistaken for
// "no flows".
func parseInetDiagMessages(data []byte, sequence uint32, ports []uint16) ([]FlowSample, bool, error) {
	samples := make([]FlowSample, 0, 16)
	done := false
	offset := 0
	for offset+16 <= len(data) {
		start := offset
		length := int(binary.LittleEndian.Uint32(data[start:]))
		if length < 16 || start+length > len(data) {
			break
		}
		if binary.LittleEndian.Uint32(data[start+8:]) != sequence {
			offset = start + align4(length)
			continue
		}
		messageType := binary.LittleEndian.Uint16(data[start+4:])
		if messageType == nlmsgDone {
			done = true
			break
		}
		if messageType == nlmsgError {
			return samples, false, parseNetlinkError(data[start+16 : start+length])
		}
		if messageType == sockDiagByFamily {
			payload := data[start+16 : start+length]
			if len(payload) >= inetDiagMsgLen {
				if sample, ok := parseInetDiagMessage(payload, ports); ok {
					samples = append(samples, sample)
				}
			}
		}
		offset = start + align4(length)
	}
	return samples, done, nil
}

// parseNetlinkError decodes the int32 errno payload of an NLMSG_ERROR record.
func parseNetlinkError(payload []byte) error {
	if len(payload) < 4 {
		return errors.New("inet_diag returned a truncated error record")
	}
	code := int32(binary.LittleEndian.Uint32(payload[0:4]))
	if code == 0 {
		// An ACK, not an error.
		return nil
	}
	return fmt.Errorf("inet_diag refused the dump: %w", syscall.Errno(-code))
}

// parseInetDiagMessage extracts one inet_diag_msg + TCP_INFO attribute. The
// address family is taken from the message itself (idiag_family), so an AF_INET6
// answer is decoded as 16-byte addresses and an AF_INET answer as 4-byte ones.
func parseInetDiagMessage(message []byte, ports []uint16) (FlowSample, bool) {
	if len(message) < inetDiagMsgLen {
		return FlowSample{}, false
	}
	localPort := binary.BigEndian.Uint16(message[4:6])
	if !containsPortValue(ports, localPort) {
		return FlowSample{}, false
	}
	// inet_diag_msg layout: family(1), state(1), timer(1), retrans(1),
	// sport(2), dport(2), src[16], dst[16], if(4), cookie[2](8),
	// expires/rqueue/wqueue/uid/inode(20) = 72 bytes.
	var peer net.IP
	switch message[0] {
	case syscall.AF_INET:
		peer = net.IP(message[24:28])
	case syscall.AF_INET6:
		peer = net.IP(message[24:40])
	default:
		return FlowSample{}, false
	}
	sample := FlowSample{Peer: peer.String(), Port: localPort}
	attributes := message[inetDiagMsgLen:]
	for len(attributes) >= 4 {
		attributeLen := int(binary.LittleEndian.Uint16(attributes[0:2]))
		attributeType := binary.LittleEndian.Uint16(attributes[2:4])
		if attributeLen < 4 || attributeLen > len(attributes) {
			break
		}
		if attributeType == inetDiagInfo {
			info := attributes[4:attributeLen]
			if len(info) >= 144 {
				// tcp_info offsets: bytes_acked 120, bytes_received 128,
				// segs_out 136, segs_in 140 (u64/u64/u32/u32, native order).
				sample.TxBytes = binary.NativeEndian.Uint64(info[120:128])
				sample.RxBytes = binary.NativeEndian.Uint64(info[128:136])
				sample.SegsOut = uint64(binary.NativeEndian.Uint32(info[136:140]))
				sample.SegsIn = uint64(binary.NativeEndian.Uint32(info[140:144]))
			}
		}
		attributes = attributes[align4(attributeLen):]
	}
	return sample, true
}

// align4 rounds a netlink message length up to the 4-byte alignment.
func align4(value int) int { return (value + 3) &^ 3 }
