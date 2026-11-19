//go:build !linux

package flowguard

// OpenCapture reports the platform limitation: AF_PACKET requires Linux.
func OpenCapture(_ CaptureConfig) (*Capture, error) {
	return nil, ErrUnsupported
}

// Read reports the platform limitation on a capture that could not be opened.
func (c *Capture) Read() (Packet, error) {
	return Packet{}, ErrUnsupported
}

// Close is a no-op on a platform without the packet socket.
func (c *Capture) Close() error { return nil }

// ReadFlowSnapshot reports the platform limitation: NETLINK_SOCK_DIAG is a
// Linux socket-diag facility.
func ReadFlowSnapshot(_ []uint16, _ int) ([]FlowSample, error) {
	return nil, ErrUnsupported
}
