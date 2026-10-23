// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTitanInotifyMaskMapping(t *testing.T) {
	cases := []struct {
		mask         uint32
		want         TitanChangeType
		wantDirWatch bool
	}{
		{syscall.IN_CREATE, TitanChangeCreated, false},
		{syscall.IN_CREATE | syscall.IN_ISDIR, TitanChangeCreated, true},
		{syscall.IN_MOVED_TO, TitanChangeCreated, false},
		{syscall.IN_MODIFY, TitanChangeModified, false},
		{syscall.IN_CLOSE_WRITE, TitanChangeModified, false},
		{syscall.IN_ATTRIB, TitanChangeAttributes, false},
		{syscall.IN_DELETE, TitanChangeRemoved, false},
		{syscall.IN_DELETE_SELF, TitanChangeRemoved, false},
		{syscall.IN_MOVED_FROM, TitanChangeRemoved, false},
		{syscall.IN_IGNORED, "", false},
	}
	for _, testCase := range cases {
		change, directory := titanChangeFromMask(testCase.mask)
		if change != testCase.want || directory != testCase.wantDirWatch {
			t.Fatalf("mask %#x -> (%q,%t), want (%q,%t)", testCase.mask, change, directory, testCase.want, testCase.wantDirWatch)
		}
	}
}

func TestTitanLinuxObserverReportsCreation(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observations := make(chan titanObservation, 32)
	observer := &titanLinuxObserver{}
	errs := make(chan error, 1)
	go func() { errs <- observer.Run(ctx, []string{root}, observations) }()
	time.Sleep(200 * time.Millisecond)
	target := filepath.Join(root, "dropped.txt")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(8 * time.Second)
	for {
		select {
		case observation := <-observations:
			if observation.Path == target || filepath.Base(observation.Path) == filepath.Base(target) {
				if observation.ChangeType != TitanChangeCreated && observation.ChangeType != TitanChangeModified {
					// inotify may report close-write or modify first; both are
					// genuine observations of the same change.
					continue
				}
				if !observation.Live || observation.Sensor != "linux-inotify" {
					t.Fatalf("observation provenance is wrong: %+v", observation)
				}
				cancel()
				return
			}
		case err := <-errs:
			if err != nil {
				t.Skipf("inotify unavailable in this environment: %v", err)
			}
			t.Skip("inotify observer stopped without reporting")
		case <-deadline:
			cancel()
			t.Fatal("inotify observer did not report the created file")
		}
	}
}

func TestTitanLinuxObserverRejectsUnsafeRoots(t *testing.T) {
	observer := &titanLinuxObserver{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	observations := make(chan titanObservation, 4)
	if err := observer.Run(ctx, nil, observations); err == nil {
		t.Fatal("empty root set accepted")
	}
	symlinkRoot := filepath.Join(t.TempDir(), "link-root")
	target := t.TempDir()
	if err := os.Symlink(target, symlinkRoot); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	if err := observer.Run(ctx, []string{symlinkRoot}, observations); err == nil {
		t.Fatal("symlinked root accepted")
	}
	if err := observer.Run(ctx, []string{filepath.Join(t.TempDir(), "missing")}, observations); err == nil {
		t.Fatal("missing root accepted")
	}
}
