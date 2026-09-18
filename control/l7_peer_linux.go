//go:build linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"net"
	"syscall"
)

type l7PeerCredentials struct {
	PID int32
	UID uint32
	GID uint32
}

func l7PeerCredentialsFromConn(conn net.Conn) (l7PeerCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return l7PeerCredentials{}, fmt.Errorf("%w: non-unix connection", ErrL7Unauthorized)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return l7PeerCredentials{}, fmt.Errorf("peer syscall handle: %w", err)
	}
	var cred *syscall.Ucred
	var socketErr error
	if controlErr := raw.Control(func(fd uintptr) {
		cred, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); controlErr != nil {
		return l7PeerCredentials{}, fmt.Errorf("peer credential control: %w", controlErr)
	}
	if socketErr != nil || cred == nil {
		return l7PeerCredentials{}, fmt.Errorf("peer credential query: %w", socketErr)
	}
	return l7PeerCredentials{PID: cred.Pid, UID: cred.Uid, GID: cred.Gid}, nil
}
