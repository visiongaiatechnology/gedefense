//go:build linux

package main

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"time"
)

func watchIntegrityChanges(ctx context.Context, paths []string) (<-chan struct{}, func(), error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, func() {}, err
	}
	mask := uint32(syscall.IN_ATTRIB | syscall.IN_CLOSE_WRITE | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF | syscall.IN_MOVED_TO | syscall.IN_CREATE | syscall.IN_DELETE)
	watched := make(map[string]struct{}, len(paths)*2)
	for _, path := range paths {
		for _, target := range []string{path, filepath.Dir(path)} {
			if _, exists := watched[target]; exists {
				continue
			}
			if _, addErr := syscall.InotifyAddWatch(fd, target, mask); addErr == nil {
				watched[target] = struct{}{}
			}
		}
	}
	if len(watched) == 0 {
		_ = syscall.Close(fd)
		return nil, func() {}, errors.New("no protected object could be watched with inotify")
	}
	changes := make(chan struct{}, 1)
	stopped := make(chan struct{})
	stop := func() {
		select {
		case <-stopped:
			return
		default:
			close(stopped)
			_ = syscall.Close(fd)
		}
	}
	go func() {
		defer close(changes)
		buffer := make([]byte, 16*1024)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopped:
				return
			default:
			}
			n, readErr := syscall.Read(fd, buffer)
			if n > 0 {
				select {
				case changes <- struct{}{}:
				default:
				}
			}
			if readErr != nil && readErr != syscall.EAGAIN && readErr != syscall.EINTR && readErr != syscall.EBADF {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	return changes, stop, nil
}
