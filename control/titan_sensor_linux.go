// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Linux inotify sensor for Titan.
//
// The watcher is deliberately bounded: a maximum number of roots, a maximum
// number of directory watches, a fixed read buffer and a hard cap on events per
// read. Reaching a bound is reported as a sensor error (and therefore a degraded
// Titan status) instead of silently dropping coverage.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	titanInotifyBufferBytes = 64 << 10
	titanInotifyMaxWatchDir = 512
	titanInotifyMaxDepth    = 8
)

type titanLinuxObserver struct{}

func newTitanPlatformObserver() titanObserver { return &titanLinuxObserver{} }

type titanWatch struct {
	directory string
}

// Run watches the configured roots until the context is cancelled. It returns
// an error only for conditions that reduce or stop coverage; a clean stop after
// cancellation returns nil.
func (o *titanLinuxObserver) Run(ctx context.Context, roots []string, out chan<- titanObservation) error {
	if len(roots) == 0 {
		return errors.New("no Titan roots configured")
	}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return errors.New("inotify is unavailable on this kernel")
	}
	defer syscall.Close(fd)
	watches := make(map[int]titanWatch, titanInotifyMaxWatchDir)
	watched := make(map[string]struct{}, titanInotifyMaxWatchDir)
	mask := uint32(syscall.IN_CREATE | syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_CLOSE_WRITE |
		syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF)
	addWatch := func(directory string) error {
		clean := filepath.Clean(directory)
		if _, exists := watched[clean]; exists {
			return nil
		}
		if len(watched) >= titanInotifyMaxWatchDir {
			return errors.New("inotify watch budget exhausted")
		}
		wd, addErr := syscall.InotifyAddWatch(fd, clean, mask)
		if addErr != nil {
			return addErr
		}
		watched[clean] = struct{}{}
		watches[wd] = titanWatch{directory: clean}
		return nil
	}
	addTree := func(root string) error {
		info, statErr := os.Lstat(root)
		if statErr != nil {
			return errors.New("configured Titan root is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("configured Titan root is a symlink")
		}
		if info.Mode().IsRegular() {
			return addWatch(root)
		}
		if !info.IsDir() {
			return errors.New("configured Titan root has an unsupported type")
		}
		depth := 0
		return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			depth = 0
			if relative != "." {
				depth = len(strings.Split(relative, string(filepath.Separator)))
			}
			if depth > titanInotifyMaxDepth {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return addWatch(path)
			}
			return nil
		})
	}
	for _, root := range roots {
		if err := addTree(root); err != nil {
			return err
		}
	}
	if len(watched) == 0 {
		return errors.New("no Titan object could be watched")
	}
	buffer := make([]byte, titanInotifyBufferBytes)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, readErr := syscall.Read(fd, buffer)
		if n > 0 {
			offset := 0
			for offset+syscall.SizeofInotifyEvent <= n {
				event := (*syscall.InotifyEvent)(unsafe.Pointer(&buffer[offset]))
				offset += syscall.SizeofInotifyEvent
				name := ""
				if int(event.Len) > 0 && offset+int(event.Len) <= n {
					rawName := buffer[offset : offset+int(event.Len)]
					name = strings.TrimRight(string(rawName), "\x00")
					offset += int(event.Len)
				}
				watch, exists := watches[int(event.Wd)]
				if !exists {
					continue
				}
				path := watch.directory
				if name != "" {
					path = filepath.Join(watch.directory, name)
				}
				change, createdDirectory := titanChangeFromMask(event.Mask)
				if change == "" {
					continue
				}
				if createdDirectory {
					_ = addWatch(path)
				}
				observation := titanObservation{
					Path: path, ChangeType: change, ObservedUTC: time.Now().UTC(),
					Sensor: "linux-inotify", Live: true,
				}
				select {
				case out <- observation:
				case <-ctx.Done():
					return nil
				default:
					return errors.New("Titan sensor event queue exhausted")
				}
			}
			continue
		}
		if readErr != nil && readErr != syscall.EAGAIN && readErr != syscall.EINTR {
			return errors.New("inotify read failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func titanChangeFromMask(mask uint32) (TitanChangeType, bool) {
	createdDirectory := mask&syscall.IN_ISDIR != 0 && mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0
	switch {
	case mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0:
		return TitanChangeCreated, createdDirectory
	case mask&(syscall.IN_DELETE|syscall.IN_DELETE_SELF|syscall.IN_MOVED_FROM) != 0:
		return TitanChangeRemoved, false
	case mask&(syscall.IN_MODIFY|syscall.IN_CLOSE_WRITE) != 0:
		return TitanChangeModified, false
	case mask&syscall.IN_ATTRIB != 0:
		return TitanChangeAttributes, false
	default:
		return "", false
	}
}
