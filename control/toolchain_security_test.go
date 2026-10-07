// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// toolchainSecurityFloor is the oldest Go toolchain this product may be built with.
//
// It is not a preference. `govulncheck` reported six standard-library
// vulnerabilities that are reachable from this code when it is built with
// go1.26.4, every one of them fixed in go1.26.5 or go1.26.6:
//
//	GO-2026-6218  net/url       quadratic complexity in resolvePath
//	GO-2026-6090  crypto/tls    post-handshake message limit
//	GO-2026-5856  crypto/tls    (fixed in go1.26.5)
//	GO-2026-6089  net/http      ReadHeaderTimeout in the h2c check
//	GO-2026-5972  encoding/asn1 recursion depth
//	GO-2026-5026  net/http      (fixed in go1.26.6)
//
// The reachable traces include the two most exposed paths in the product: the L7
// ingress reverse proxy (`l7_edge.go` -> `httputil.ReverseProxy`) and the threat
// intelligence feed fetcher (`feeds.go` -> `http.Client.Do`), plus the API server
// itself. A toolchain is part of the attack surface, and a build that silently uses
// a vulnerable one ships the vulnerability.
//
// This test cannot run on every developer host, which is the point: it is a CI
// gate. It fails loudly rather than allowing a vulnerable artefact to be produced.
const toolchainSecurityFloor = "go1.26.6"

// goVersionOlder reports whether version is strictly older than floor. Both are
// expected in the `go1.26.4` form that runtime.Version() and the go directive use.
func goVersionOlder(version, floor string) bool {
	parse := func(value string) (int, int, int, bool) {
		trimmed := strings.TrimPrefix(strings.TrimSpace(value), "go")
		// A release candidate or a development build carries a suffix; the numeric
		// prefix is still the comparable part.
		if index := strings.IndexAny(trimmed, "-+ "); index >= 0 {
			trimmed = trimmed[:index]
		}
		parts := strings.Split(trimmed, ".")
		if len(parts) != 3 {
			return 0, 0, 0, false
		}
		major, errMajor := strconv.Atoi(parts[0])
		minor, errMinor := strconv.Atoi(parts[1])
		patch, errPatch := strconv.Atoi(parts[2])
		if errMajor != nil || errMinor != nil || errPatch != nil {
			return 0, 0, 0, false
		}
		return major, minor, patch, true
	}

	currentMajor, currentMinor, currentPatch, okCurrent := parse(version)
	floorMajor, floorMinor, floorPatch, okFloor := parse(floor)
	if !okCurrent || !okFloor {
		// An unparseable version is not evidence of safety, but it is also not
		// evidence of a vulnerable build. The test reports it so the floor can be
		// re-checked against whatever the toolchain now reports.
		return false
	}
	if currentMajor != floorMajor {
		return currentMajor < floorMajor
	}
	if currentMinor != floorMinor {
		return currentMinor < floorMinor
	}
	return currentPatch < floorPatch
}

// TestToolchainMeetsSecurityFloor blocks a release built with a toolchain that
// carries the reachable standard-library vulnerabilities listed above.
func TestToolchainMeetsSecurityFloor(t *testing.T) {
	version := runtime.Version()
	if !strings.HasPrefix(version, "go") {
		t.Fatalf("unrecognised toolchain version %q", version)
	}
	if goVersionOlder(version, toolchainSecurityFloor) {
		t.Fatalf("toolchain %s is older than the security floor %s: govulncheck reports reachable standard-library vulnerabilities (GO-2026-6218, GO-2026-6090, GO-2026-5856, GO-2026-6089, GO-2026-5972, GO-2026-5026) below it", version, toolchainSecurityFloor)
	}
}

// TestToolchainFloorIsDeclaredInGoMod keeps the declared toolchain and the enforced
// floor in step, so a build that pins an older toolchain cannot pass by ignoring the
// test's constant.
func TestToolchainFloorIsDeclaredInGoMod(t *testing.T) {
	declared := declaredToolchain(t)
	if declared == "" {
		t.Fatalf("go.mod no longer declares a toolchain floor; the security floor is %s", toolchainSecurityFloor)
	}
	if goVersionOlder(declared, toolchainSecurityFloor) {
		t.Fatalf("go.mod declares toolchain %s, which is below the security floor %s", declared, toolchainSecurityFloor)
	}
}

// declaredToolchain reads the toolchain directive out of the module file. The go
// command runs a package's tests with the package directory as the working
// directory, so the module file sits beside the test that inspects it.
func declaredToolchain(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	body := string(raw)
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "toolchain ") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(trimmed, "toolchain "))
	}
	return ""
}
