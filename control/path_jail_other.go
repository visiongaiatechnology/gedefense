//go:build !linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"os"
)

// The component-wise jail is built on openat(2) and O_NOFOLLOW, which exist only
// on Linux. The other platforms are development hosts for this control plane, not
// deployment targets, so the honest behaviour is to refuse rather than to fall
// back to a path-based write whose guarantee would be weaker exactly where it
// matters. A silent downgrade of a security boundary is worse than a clear error.

const noFollowFlag = 0

var errJailUnsupported = errors.New("component-wise path resolution requires Linux")

func ensureCanaryDirectory(string) error { return errJailUnsupported }

func openBeneath(string, string, int, uint32) (*os.File, error) {
	return nil, errJailUnsupported
}

func removeBeneath(string, string) error {
	return errJailUnsupported
}

func renameBeneath(string, string, string) error { return errJailUnsupported }

func jailPathIsSymlinked(string, string) bool { return false }
