// STATUS: DIAMANT VGT SUPREME
//go:build linux

package main

import (
	"os"
	"strings"
	"syscall"
)

// resolveToleratedPathByInode maps a tolerated comm plus kernel-verified (dev, ino)
// back to a standard system executable path when cross-UID /proc/<pid>/exe readlink
// fails without CAP_SYS_PTRACE.
func resolveToleratedPathByInode(comm string, dev uint32, ino uint64) string {
	if dev == 0 || ino == 0 || comm == "" || comm == "." || comm == ".." || strings.ContainsAny(comm, "/\\\x00") {
		return ""
	}
	if _, ok := bpfGuardToleratedComms[comm]; !ok {
		return ""
	}
	for _, prefix := range bpfGuardToleratedPathPrefixes {
		candidate := prefix + comm
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if uint32(stat.Dev) == dev && uint64(stat.Ino) == ino {
			return candidate
		}
	}
	return ""
}
