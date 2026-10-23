// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// A second control-plane process on the same state directory would race the revision-bound
// stores (policy generation, settings revision, evidence head) and could clobber a newer
// revision with its own view. The service manager normally prevents this, but a manual
// start, a rotated unit or a container restart can overlap. The lock is an exclusive,
// non-blocking flock next to the policy state, held for the lifetime of the process
// (G-STATE-08).
type instanceLock struct {
	file *os.File
}

func acquireInstanceLock(stateFile string) (*instanceLock, error) {
	if !filepath.IsAbs(stateFile) {
		return nil, errors.New("instance lock requires an absolute state path")
	}
	directory := filepath.Dir(stateFile)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "control-plane.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another control-plane instance already owns the state directory %s", directory)
		}
		return nil, err
	}
	return &instanceLock{file: file}, nil
}

// Release drops the lock. It is idempotent and safe to defer.
func (l *instanceLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}
