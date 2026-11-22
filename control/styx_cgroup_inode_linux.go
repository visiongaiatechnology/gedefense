// STATUS: DIAMANT VGT SUPREME
//go:build linux

package main

// M3.1: on Linux the kernfs inode number of a cgroup directory is the cgroup id
// the kernel and BPF see (bpf_get_current_cgroup_id), so it is the only value
// that may be written into STYX_MODE_SET/STYX_ALLOW_ADD.

import (
	"os"
	"syscall"
)

func styxCgroupInode(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Ino), true
}
