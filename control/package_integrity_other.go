//go:build !linux

// STATUS: DIAMANT VGT SUPREME
package main

import "errors"

func packageIntegritySupported() bool { return false }

func scanPackageIntegrity(string, string) (PackageIntegrityStatus, error) {
	return PackageIntegrityStatus{Available: false, Findings: []PackageIntegrityFinding{}}, errors.New("pacman integrity is only available on Linux")
}
