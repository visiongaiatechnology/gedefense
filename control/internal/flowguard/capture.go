package flowguard

// Capture is the AF_PACKET handshake capture. It is opened with OpenCapture,
// which is implemented per platform: the sensor needs CAP_NET_RAW and the Linux
// packet-socket ABI, so a non-Linux host reports the capability as unsupported
// instead of pretending to observe traffic.
//
// This file exists so both kernel-facing entry points share one documented
// contract:
//
//   - OpenCapture never opens more than eight packet sockets and never blocks;
//     an empty interface list means "every interface". The classic-BPF prefilter
//     is generated from the configured ports (up to 8, TCP and UDP, IPv4 and
//     IPv6) instead of a fixed 443/8443 program.
//   - Read blocks for at most one poll interval and returns a Packet only for a
//     bounded candidate (configured port, TLS handshake first byte 0x16 or QUIC
//     long-header bit set); other frames are skipped inside the loop.
//   - ReadFlowSnapshot dumps AF_INET and AF_INET6 through NETLINK_SOCK_DIAG and
//     merges both answers, so a dual-stack `[::]:443` socket is visible. A
//     family whose dump is refused is reported as a reason instead of silently
//     shrinking the flow view.
type Capture struct {
	fds    []int
	config CaptureConfig
	buffer []byte
}
