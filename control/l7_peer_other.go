//go:build !linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"net"
)

type l7PeerCredentials struct {
	PID int32
	UID uint32
	GID uint32
}

func l7PeerCredentialsFromConn(net.Conn) (l7PeerCredentials, error) {
	return l7PeerCredentials{}, fmt.Errorf("%w: peer credentials unsupported on this platform", ErrL7Unauthorized)
}
