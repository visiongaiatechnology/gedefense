// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The release toolchain policy is declared once, in TOOLCHAINS.lock, and this
// test derives every expectation from that file. A hard-coded floor used to
// drift behind the lock (go1.26.6 while the lock and control/go.mod already
// pinned go1.27.3), which made the gate approve stale release toolchains.
const (
	toolchainLockPath = "../TOOLCHAINS.lock"
	lockGoReleaseKey  = "Go release validation"
	lockNodeKey       = "Node.js syntax validation"
	lockRustStableKey = "Rust stable"
	lockRustEBPFKey   = "Rust eBPF nightly"
)

var (
	releaseVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	nightlyPattern        = regexp.MustCompile(`^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// toolchainLock is the parsed `key = value` release toolchain lock.
type toolchainLock map[string]string

// readToolchainLock loads TOOLCHAINS.lock relative to the package directory.
// The go command runs a package's tests with the package directory as the
// working directory, and the file read is local only: this test never touches
// the network and never invokes a package manager or a toolchain download.
func readToolchainLock(t *testing.T) toolchainLock {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "TOOLCHAINS.lock"))
	if err != nil {
		t.Fatalf("read TOOLCHAINS.lock: %v", err)
	}
	values := make(toolchainLock)
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, " = ")
		if !found {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return values
}

// required returns a lock value and fails the test when it is missing.
func (lock toolchainLock) required(t *testing.T, key string) string {
	t.Helper()
	value := lock[key]
	if value == "" {
		t.Fatalf("TOOLCHAINS.lock no longer declares %q", key)
	}
	return value
}

// goFloor returns the security floor in the `go1.27.3` form used by
// runtime.Version() and the go.mod toolchain directive.
func (lock toolchainLock) goFloor(t *testing.T) string {
	t.Helper()
	version := lock.required(t, lockGoReleaseKey)
	if !releaseVersionPattern.MatchString(version) {
		t.Fatalf("TOOLCHAINS.lock Go release validation %q is not a release version", version)
	}
	return "go" + version
}

// goVersionOlder reports whether version is strictly older than floor. Both are
// expected in the `go1.27.3` form that runtime.Version() and the go directive
// use.
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
// is older than the Go release validated in TOOLCHAINS.lock and pinned in
// control/go.mod.
func TestToolchainMeetsSecurityFloor(t *testing.T) {
	floor := readToolchainLock(t).goFloor(t)
	version := runtime.Version()
	if !strings.HasPrefix(version, "go") {
		t.Fatalf("unrecognised toolchain version %q", version)
	}
	if goVersionOlder(version, floor) {
		t.Fatalf("toolchain %s is older than the TOOLCHAINS.lock release validation %s: the release gate must use the validated Go release (govulncheck evidence in SECURITY.md)", version, floor)
	}
}

// declaredToolchain reads the toolchain directive out of the given module file.
func declaredToolchain(t *testing.T, moduleFile string) string {
	t.Helper()
	raw, err := os.ReadFile(moduleFile)
	if err != nil {
		t.Fatalf("read %s: %v", moduleFile, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "toolchain ") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(trimmed, "toolchain "))
	}
	return ""
}

// TestToolchainFloorIsDeclaredInGoMod keeps the declared control toolchain and
// the TOOLCHAINS.lock release validation in step, so a build that pins an older
// toolchain cannot pass by ignoring the lock.
func TestToolchainFloorIsDeclaredInGoMod(t *testing.T) {
	lock := readToolchainLock(t)
	floor := lock.goFloor(t)
	declared := declaredToolchain(t, "go.mod")
	if declared == "" {
		t.Fatalf("control/go.mod no longer declares a toolchain floor; TOOLCHAINS.lock pins %s", floor)
	}
	if declared != floor {
		t.Fatalf("control/go.mod declares toolchain %s but TOOLCHAINS.lock validates %s", declared, floor)
	}
	if goVersionOlder(declared, floor) {
		t.Fatalf("control/go.mod declares toolchain %s, which is below the security floor %s", declared, floor)
	}
}

// TestGatewayGoModDeclaresToolchain verifies the gateway module carries the
// same explicit toolchain pin as the control module. A gateway module without a
// toolchain directive would let a release build silently fall back to a newer
// or older host toolchain than the validated release (FIND-004).
func TestGatewayGoModDeclaresToolchain(t *testing.T) {
	lock := readToolchainLock(t)
	floor := lock.goFloor(t)
	declared := declaredToolchain(t, filepath.Join("..", "gateway", "go.mod"))
	if declared == "" {
		t.Fatalf("gateway/go.mod no longer declares a toolchain; TOOLCHAINS.lock validates %s", floor)
	}
	if declared != floor {
		t.Fatalf("gateway/go.mod declares toolchain %s but TOOLCHAINS.lock validates %s", declared, floor)
	}
}

// TestToolchainLockDeclaresNodeAndRustPins validates the remaining release
// toolchain pins parsed from TOOLCHAINS.lock, so removing or malforming a pin
// fails the test gate instead of being discovered at packaging time.
func TestToolchainLockDeclaresNodeAndRustPins(t *testing.T) {
	lock := readToolchainLock(t)
	if version := lock.required(t, lockNodeKey); !releaseVersionPattern.MatchString(version) {
		t.Fatalf("TOOLCHAINS.lock Node.js syntax validation %q is not a release version", version)
	}
	if version := lock.required(t, lockRustStableKey); !releaseVersionPattern.MatchString(version) {
		t.Fatalf("TOOLCHAINS.lock Rust stable %q is not a release version", version)
	}
	if nightly := lock.required(t, lockRustEBPFKey); !nightlyPattern.MatchString(nightly) {
		t.Fatalf("TOOLCHAINS.lock Rust eBPF nightly %q is not a pinned nightly toolchain", nightly)
	}
	lock.goFloor(t) // Go release validation must be a release version as well.
}
