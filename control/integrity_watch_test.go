//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIntegrityWatcherSignalsProtectedFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "protected.bin")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, stop, err := watchIntegrityChanges(ctx, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := os.WriteFile(path, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Fatal("inotify watcher did not report protected-file mutation")
	}
}
