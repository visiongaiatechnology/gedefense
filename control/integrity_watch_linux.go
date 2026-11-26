//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const inotifyDebounceInterval = 1 * time.Second

func inotifyBufferMatchesWatch(buf []byte, dirTargets map[int32]map[string]struct{}, fileWds map[int32]struct{}) bool {
	for offset := 0; offset+syscall.SizeofInotifyEvent <= len(buf); {
		wd := int32(binary.NativeEndian.Uint32(buf[offset : offset+4]))
		nameLen := int(binary.NativeEndian.Uint32(buf[offset+12 : offset+16]))
		next := offset + syscall.SizeofInotifyEvent + nameLen
		if next > len(buf) || next <= offset {
			break
		}
		if _, isFile := fileWds[wd]; isFile {
			return true
		}
		if names, isDir := dirTargets[wd]; isDir {
			if nameLen == 0 {
				return true
			}
			rawName := buf[offset+syscall.SizeofInotifyEvent : next]
			if nul := bytes.IndexByte(rawName, 0); nul >= 0 {
				rawName = rawName[:nul]
			}
			if _, wanted := names[string(rawName)]; wanted {
				return true
			}
		}
		offset = next
	}
	return false
}

func watchIntegrityChanges(ctx context.Context, paths []string) (<-chan struct{}, func(), error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, func() {}, err
	}
	fileMask := uint32(syscall.IN_ATTRIB | syscall.IN_CLOSE_WRITE | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF)
	dirMask := uint32(syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF)
	fileWds := make(map[int32]struct{}, len(paths))
	dirWds := make(map[string]int32, len(paths))
	dirTargets := make(map[int32]map[string]struct{}, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if wd, addErr := syscall.InotifyAddWatch(fd, clean, fileMask); addErr == nil {
			fileWds[int32(wd)] = struct{}{}
		}
		dir := filepath.Dir(clean)
		wd, hasDir := dirWds[dir]
		if !hasDir {
			addedWd, addErr := syscall.InotifyAddWatch(fd, dir, dirMask)
			if addErr != nil {
				continue
			}
			wd = int32(addedWd)
			dirWds[dir] = wd
		}
		if dirTargets[wd] == nil {
			dirTargets[wd] = make(map[string]struct{})
		}
		dirTargets[wd][filepath.Base(clean)] = struct{}{}
	}
	if len(fileWds) == 0 && len(dirWds) == 0 {
		_ = syscall.Close(fd)
		return nil, func() {}, errors.New("no protected object could be watched with inotify")
	}
	changes := make(chan struct{}, 1)
	stopped := make(chan struct{})
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			close(stopped)
			_ = syscall.Close(fd)
		})
	}
	go func() {
		defer close(changes)
		defer stop()
		buffer := make([]byte, 16*1024)
		var lastNotify time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopped:
				return
			default:
			}
			n, readErr := syscall.Read(fd, buffer)
			if n > 0 && inotifyBufferMatchesWatch(buffer[:n], dirTargets, fileWds) {
				now := time.Now()
				if lastNotify.IsZero() || now.Sub(lastNotify) >= inotifyDebounceInterval {
					lastNotify = now
					select {
					case changes <- struct{}{}:
					default:
					}
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
