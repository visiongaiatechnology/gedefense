//go:build !linux

package main

import "os"

func cmsFileInode(os.FileInfo) uint64 { return 0 }
