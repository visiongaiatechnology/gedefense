// STATUS: DIAMANT VGT SUPREME
//go:build linux

package main

// M3 test: the real resolver derives the cgroup id from the kernfs inode of the
// path below a unified-hierarchy root. The test fakes the hierarchy root, so it
// needs no privileges and no host cgroup v2 mount.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStyxSystemCgroupResolverUsesKernfsInode(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(root, "system.slice", "php8.3-fpm.service")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(unitDir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("kernel inode is not exposed in this environment")
	}
	resolver := styxSystemCgroupResolver{root: root}
	id, err := resolver.Resolve("/system.slice/php8.3-fpm.service")
	if err != nil {
		t.Fatalf("resolver rejected a valid path: %v", err)
	}
	if id != uint64(stat.Ino) {
		t.Fatalf("resolved cgroup id %d, want kernfs inode %d", id, stat.Ino)
	}

	// A missing path and a symlink are both rejected: no silent fallback.
	if _, err := resolver.Resolve("/system.slice/missing.service"); err == nil {
		t.Fatal("a missing cgroup path was accepted")
	}
	symlink := filepath.Join(root, "system.slice", "link.service")
	if err := os.Symlink(unitDir, symlink); err != nil {
		t.Skipf("symlinks are not supported here: %v", err)
	}
	if _, err := resolver.Resolve("/system.slice/link.service"); err == nil {
		t.Fatal("a symlinked cgroup path was accepted")
	}

	// Without the unified hierarchy attributes the resolver must refuse, not guess.
	plainRoot := t.TempDir()
	plain := styxSystemCgroupResolver{root: plainRoot}
	if _, err := plain.Resolve("/system.slice/php8.3-fpm.service"); err == nil {
		t.Fatal("a root without cgroup.controllers was treated as cgroup v2")
	}
}
