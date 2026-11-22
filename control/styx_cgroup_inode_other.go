// STATUS: DIAMANT VGT SUPREME
//go:build !linux

package main

// M3.1: no kernel cgroup identity is observable on this platform. The resolver
// therefore reports every path as unresolved instead of inventing a value.

import "os"

func styxCgroupInode(os.FileInfo) (uint64, bool) { return 0, false }
