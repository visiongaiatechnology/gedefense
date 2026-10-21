// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeExposureSource is a synthetic host: every fact the engine reads is set explicitly, so a test
// states the host it means instead of depending on the machine that runs the suite.
type fakeExposureSource struct {
	files map[string]string
	dirs  map[string][]string
	modes map[string]os.FileMode
}

func newFakeExposureSource() *fakeExposureSource {
	return &fakeExposureSource{
		files: map[string]string{},
		dirs:  map[string][]string{},
		modes: map[string]os.FileMode{},
	}
}

func (f *fakeExposureSource) ReadFile(path string) ([]byte, error) {
	value, ok := f.files[path]
	if !ok {
		return nil, errors.New("no such file")
	}
	return []byte(value), nil
}

func (f *fakeExposureSource) ReadDir(path string) ([]string, error) {
	names, ok := f.dirs[path]
	if !ok {
		return nil, errors.New("no such directory")
	}
	return names, nil
}

func (f *fakeExposureSource) Exists(path string) bool {
	_, inFiles := f.files[path]
	if inFiles {
		return true
	}
	_, inModes := f.modes[path]
	return inModes
}

func (f *fakeExposureSource) Mode(path string) (os.FileMode, bool) {
	mode, ok := f.modes[path]
	return mode, ok
}

// TestParseKernelVersionStates covers the shapes the engine has to read without guessing: an Ubuntu
// build suffix, a Debian revision, a plain mainline version and input that must be rejected instead
// of defaulted to zero.
func TestParseKernelVersionStates(t *testing.T) {
	cases := []struct {
		raw      string
		major    int
		minor    int
		patch    int
		build    int
		hasBuild bool
		ok       bool
	}{
		{"7.0.0-31-generic", 7, 0, 0, 31, true, true},
		{"6.1.190-1", 6, 1, 190, 1, true, true},
		{"5.15.223", 5, 15, 223, 0, false, true},
		{"7.2.11-1", 7, 2, 11, 1, true, true},
		{"7.0.0-31-generic #31~24.04.1-Ubuntu SMP", 7, 0, 0, 31, true, true},
		{"", 0, 0, 0, 0, false, false},
		{"linux", 0, 0, 0, 0, false, false},
	}
	for _, tc := range cases {
		version, ok := parseKernelVersion(tc.raw)
		if ok != tc.ok {
			t.Fatalf("%q parsed=%v want %v", tc.raw, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if version.Major != tc.major || version.Minor != tc.minor || version.Patch != tc.patch {
			t.Fatalf("%q -> %+v", tc.raw, version)
		}
		if version.Build != tc.build || version.HasBuild != tc.hasBuild {
			t.Fatalf("%q build -> %d/%v", tc.raw, version.Build, version.HasBuild)
		}
	}
}

func TestCompareKernelVersionAcrossBuilds(t *testing.T) {
	order := []string{"6.1.176-1", "6.1.190-1", "6.12.107-1", "6.12.113-1", "7.0.0", "7.0.0-31", "7.0.0-38", "7.3"}
	for index := 1; index < len(order); index++ {
		left, leftOK := parseKernelVersion(order[index-1])
		right, rightOK := parseKernelVersion(order[index])
		if !leftOK || !rightOK {
			t.Fatalf("unparsable fixture %q / %q", order[index-1], order[index])
		}
		if compareKernelVersion(left, right) >= 0 {
			t.Fatalf("%s should sort before %s", order[index-1], order[index])
		}
		if compareKernelVersion(right, left) <= 0 {
			t.Fatalf("%s should sort after %s", order[index], order[index-1])
		}
	}
}

// TestClassifyAdvisoryNeverInventsUnaffected pins the honesty rule: a distribution build without a
// published fixed version is unknown, never "safe", because distributions backport.
func TestClassifyAdvisoryNeverInventsUnaffected(t *testing.T) {
	advisory := kernelAdvisories()[0]
	if advisory.ID != "CVE-2026-99999" {
		t.Fatalf("catalogue order changed, first entry is %q", advisory.ID)
	}
	cases := []struct {
		name     string
		release  string
		channel  string
		expected KernelVerdict
		reason   string
	}{
		{"the fixed debian build is unaffected", "6.1.190-1", "debian-bookworm", kernelVerdictUnaffected, "at or above"},
		{"an older debian build is vulnerable", "6.1.176-1", "debian-bookworm", kernelVerdictVulnerable, "below"},
		{"ubuntu carries no fixed build yet", "7.0.0-31-generic", "ubuntu-noble", kernelVerdictUnknown, "backport cannot be excluded"},
		{"mainline above the fix is unaffected", "7.3.0-1", "mainline", kernelVerdictUnaffected, "mainline fix"},
		{"a build without suffix is not a fixed build", "7.2", "mainline", kernelVerdictUnknown, "backport cannot be excluded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			match := classifyAdvisory(advisory, KernelIdentity{Release: tc.release, Channel: tc.channel})
			if match.Verdict != tc.expected {
				t.Fatalf("verdict = %q want %q (%s)", match.Verdict, tc.expected, match.Reason)
			}
			if !strings.Contains(match.Reason, tc.reason) {
				t.Fatalf("reason %q does not name %q", match.Reason, tc.reason)
			}
		})
	}
	if _, ok := parseKernelVersion("7.2"); !ok {
		t.Fatal("the fixture for a two-component version is not parsable")
	}
}

func TestKernelReachabilityIsWeighted(t *testing.T) {
	none := readKernelPreconditions(newFakeExposureSource())
	for _, precondition := range none {
		if precondition.Present {
			t.Fatalf("an empty host reported %s as reachable", precondition.ID)
		}
	}
	if reach := kernelReachability(none); reach != 0 {
		t.Fatalf("empty host reachability = %d", reach)
	}
	source := newFakeExposureSource()
	source.files["/usr/bin/docker"] = ""
	source.modes["/dev/net/tun"] = 0o666
	source.files["/proc/sys/kernel/unprivileged_userns_clone"] = "1\n"
	source.dirs["/sys/bus/virtio/devices"] = []string{"virtio0"}
	source.modes["/dev/kvm"] = 0o660
	all := readKernelPreconditions(source)
	if reach := kernelReachability(all); reach != 100 {
		t.Fatalf("fully reachable host = %d, want 100", reach)
	}
	// Disabling the user namespace removes only its share, it does not zero the measurement.
	source.files["/proc/sys/kernel/unprivileged_userns_clone"] = "0\n"
	partial := readKernelReachability(t, source)
	if partial <= 0 || partial >= 100 {
		t.Fatalf("partial reachability = %d, want a value between 1 and 99", partial)
	}
}

func readKernelReachability(t *testing.T, source *fakeExposureSource) int {
	t.Helper()
	return kernelReachability(readKernelPreconditions(source))
}

// TestScoreKernelExposureModulatesAndCaps pins the two scoring rules that keep the number honest:
// reachability modulates instead of gating, and an unknown verdict never scores better than a known
// one at the same reachability.
func TestScoreKernelExposureModulatesAndCaps(t *testing.T) {
	if score := scoreKernelExposure(kernelVerdictUnaffected, "critical", 100); score != 0 {
		t.Fatalf("an unaffected host scored %d", score)
	}
	if score := scoreKernelExposure(kernelVerdictVulnerable, "critical", 100); score != 100 {
		t.Fatalf("fully reachable critical = %d, want 100", score)
	}
	if score := scoreKernelExposure(kernelVerdictVulnerable, "critical", 0); score != 40 {
		t.Fatalf("unreachable critical = %d, want the 40%% floor", score)
	}
	vulnerable := scoreKernelExposure(kernelVerdictVulnerable, "critical", 50)
	unknown := scoreKernelExposure(kernelVerdictUnknown, "critical", 50)
	if unknown > vulnerable {
		t.Fatalf("unknown (%d) scored better than vulnerable (%d)", unknown, vulnerable)
	}
	if capped := scoreKernelExposure(kernelVerdictUnknown, "critical", 100); capped != kernelSeverityBase("critical") {
		t.Fatalf("unknown at full reachability = %d, want the severity base %d", capped, kernelSeverityBase("critical"))
	}
}

// TestEvaluateKernelExposureOnTwoHosts states the two cases an operator has to be able to tell
// apart: a patched, closed host and an unpatchable, wide-open one.
func TestEvaluateKernelExposureOnTwoHosts(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()

	closed := newFakeExposureSource()
	closed.files["/proc/sys/kernel/osrelease"] = "6.1.190-1\n"
	closed.files["/etc/os-release"] = "ID=debian\nVERSION_CODENAME=bookworm\nVERSION_ID=\"12\"\n"
	closed.modes["/dev/net/tun"] = 0o600
	closed.files["/proc/sys/kernel/unprivileged_userns_clone"] = "0\n"
	exposure := evaluateKernelExposure(closed, kernelAdvisories(), now)
	if exposure.Verdict != kernelVerdictUnaffected || exposure.Score != 0 || exposure.Grade != "HARDENED" {
		t.Fatalf("closed host = %s/%d/%s (%s)", exposure.Verdict, exposure.Score, exposure.Grade, exposure.UnknownReason)
	}
	if exposure.Kernel.Channel != "debian-bookworm" {
		t.Fatalf("channel = %q", exposure.Kernel.Channel)
	}

	open := newFakeExposureSource()
	open.files["/proc/sys/kernel/osrelease"] = "7.0.0-31-generic\n"
	open.files["/etc/os-release"] = "ID=ubuntu\nVERSION_CODENAME=noble\nVERSION_ID=\"24.04\"\n"
	open.modes["/dev/net/tun"] = 0o666
	open.files["/proc/sys/kernel/unprivileged_userns_clone"] = "1\n"
	open.files["/usr/bin/docker"] = ""
	open.dirs["/sys/bus/virtio/devices"] = []string{"virtio0", "virtio1"}
	open.modes["/dev/kvm"] = 0o660
	exposure = evaluateKernelExposure(open, kernelAdvisories(), now)
	if exposure.Verdict != kernelVerdictUnknown {
		t.Fatalf("unpatched-channel verdict = %q", exposure.Verdict)
	}
	if exposure.Score < 80 || exposure.Grade != "EXPOSED" {
		t.Fatalf("wide-open host scored %d/%s", exposure.Score, exposure.Grade)
	}
	if exposure.Reachability != 100 {
		t.Fatalf("reachability = %d", exposure.Reachability)
	}
	if exposure.UnknownReason == "" || !strings.Contains(exposure.UnknownReason, "CVE-2026-99999") {
		t.Fatalf("unknown reason does not name the advisory: %q", exposure.UnknownReason)
	}
	// The recommendation must be the action that closes the widest door, not a generic "update".
	if !strings.Contains(exposure.Recommendation, "cell") {
		t.Fatalf("recommendation = %q", exposure.Recommendation)
	}
}

// TestKernelAdvisoryCatalogueIsComplete refuses a catalogue entry that cannot be acted on: every
// entry point must be measurable, every mitigation must name a tradeoff, and the guard commit must be
// a real reference. This is what makes "add another CVE" a data edit with a gate instead of prose.
func TestKernelAdvisoryCatalogueIsComplete(t *testing.T) {
	known := map[string]bool{}
	for _, entry := range kernelPreconditionCatalogue() {
		known[entry.ID] = true
	}
	seen := map[string]bool{}
	for _, advisory := range kernelAdvisories() {
		if advisory.ID == "" || seen[advisory.ID] {
			t.Fatalf("duplicate or empty advisory id %q", advisory.ID)
		}
		seen[advisory.ID] = true
		if advisory.Title == "" || advisory.Class == "" {
			t.Fatalf("%s lacks a title or class", advisory.ID)
		}
		switch advisory.Severity {
		case "critical", "high", "medium", "low":
		default:
			t.Fatalf("%s has an unknown severity %q", advisory.ID, advisory.Severity)
		}
		if len(advisory.GuardCommit) < 12 || len(advisory.Reference) == 0 {
			t.Fatalf("%s has no verifiable guard commit or reference", advisory.ID)
		}
		if len(advisory.EntryPoints) == 0 {
			t.Fatalf("%s names no entry point", advisory.ID)
		}
		for _, entryPoint := range advisory.EntryPoints {
			if !known[entryPoint] {
				t.Fatalf("%s names the unmeasurable entry point %q", advisory.ID, entryPoint)
			}
		}
		if len(advisory.Mitigations) == 0 {
			t.Fatalf("%s has no mitigation", advisory.ID)
		}
		for _, mitigation := range advisory.Mitigations {
			if mitigation.Command == "" || mitigation.Tradeoff == "" {
				t.Fatalf("%s mitigation for %q lacks a command or tradeoff", advisory.ID, mitigation.Precondition)
			}
		}
		if advisory.Detects == "" {
			t.Fatalf("%s does not state what GeDefense can see of it", advisory.ID)
		}
	}
	if ids := sortedAdvisoryIDs(kernelAdvisories()); len(ids) != len(seen) {
		t.Fatalf("catalogue listing is inconsistent: %v", ids)
	}
}

// minimalAdvisoryConfig is the smallest configuration loadConfig accepts, so the advisory section can
// be tested without a host.
const minimalAdvisoryConfig = `[node]
name = "test"
interface = "lo"
mode = "standalone"
[dashboard]
listen = "127.0.0.1:9843"
allow_remote = false
allowed_hosts = "127.0.0.1"
token_file = "/tmp/token"
tls_cert_file = ""
tls_key_file = ""
[core]
socket = "/tmp/core.sock"
[defense]
allowlist = "192.0.2.10"
enforcement = "observe"
default_ttl_seconds = 3600
max_ttl_seconds = 604800
max_block_entries = 1000
strict_asn_drop = false
dpi_enabled = false
[feeds]
enabled = false
auto_apply = false
refresh_minutes = 60
max_download_bytes = 1048576
max_entries = 1000
sources = "https://example.com/list.txt"
`

// TestAdvisoryConfigModeIsParsedAndValidated keeps the two-mode contract honest: a typo in the mode
// must stop the start, not silently fall back to report.
func TestAdvisoryConfigModeIsParsedAndValidated(t *testing.T) {
	write := func(t *testing.T, section string) (Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "g.toml")
		if err := os.WriteFile(path, []byte(minimalAdvisoryConfig+section), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadConfig(path)
	}
	cfg, err := write(t, "[advisories]\nenabled = true\nmode = \"strict\"\nmax_exposure = 70\n")
	if err != nil {
		t.Fatalf("valid advisory section rejected: %v", err)
	}
	if !cfg.Advisories.Enabled || cfg.Advisories.Mode != advisoryModeStrict || cfg.Advisories.MaxExposure != 70 {
		t.Fatalf("parsed advisories = %+v", cfg.Advisories)
	}
	// The defaults must be the conservative ones: measuring, not vetoing.
	defaults := defaultConfig()
	if !defaults.Advisories.Enabled || defaults.Advisories.Mode != advisoryModeReport {
		t.Fatalf("default advisories = %+v", defaults.Advisories)
	}
	if _, err := write(t, "[advisories]\nmode = \"paranoid\"\n"); err == nil {
		t.Fatal("an unknown advisory mode was accepted")
	}
	if _, err := write(t, "[advisories]\nmax_exposure = 101\n"); err == nil {
		t.Fatal("an exposure limit above 100 was accepted")
	}
}

// TestShippedConfigCarriesTheAdvisorySection keeps the documented sample honest. A section that is
// described in the config file but rejected by the parser is a first-start failure for every operator
// who copies it.
func TestShippedConfigCarriesTheAdvisorySection(t *testing.T) {
	path := filepath.Join("..", "gedefense.toml")
	if _, err := os.Stat(path); err != nil {
		t.Skip("the shipped config is not part of this build context")
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the shipped gedefense.toml does not load: %v", err)
	}
	if !cfg.Advisories.Enabled || cfg.Advisories.Mode != advisoryModeReport {
		t.Fatalf("shipped advisories = %+v", cfg.Advisories)
	}
}

// TestKernelAdvisoryBlockerVetoesPromotionsOnly pins the boundary of the strict mode: it must veto a
// promotion and must never be the reason an already protecting host is degraded.
func TestKernelAdvisoryBlockerVetoesPromotionsOnly(t *testing.T) {
	exposed := KernelExposure{Verdict: kernelVerdictUnknown, Score: 82, Highest: "CVE-2026-99999"}
	strict := AdvisoryConfig{Enabled: true, Mode: advisoryModeStrict, MaxExposure: 80}
	report := AdvisoryConfig{Enabled: true, Mode: advisoryModeReport, MaxExposure: 80}

	if blocker := kernelAdvisoryBlocker(ReleasePhaseEnforce, ReleasePhaseDegraded, strict, exposed); !strings.Contains(blocker, "strict limit") {
		t.Fatalf("strict mode did not veto a promotion: %q", blocker)
	}
	if blocker := kernelAdvisoryBlocker(ReleasePhaseCanary, ReleasePhaseDegraded, strict, exposed); blocker == "" {
		t.Fatal("strict mode did not veto a promotion to canary")
	}
	// Evaluating the phase the platform is already in must never demote it.
	if blocker := kernelAdvisoryBlocker(ReleasePhaseEnforce, ReleasePhaseEnforce, strict, exposed); blocker != "" {
		t.Fatalf("an enforcing host was demoted by an advisory: %q", blocker)
	}
	if blocker := kernelAdvisoryBlocker(ReleasePhaseEnforce, ReleasePhaseDegraded, report, exposed); blocker != "" {
		t.Fatalf("report mode changed a release decision: %q", blocker)
	}
	if blocker := kernelAdvisoryBlocker(ReleasePhaseEnforce, ReleasePhaseDegraded, strict, KernelExposure{Verdict: kernelVerdictUnaffected}); blocker != "" {
		t.Fatalf("an unaffected host was vetoed: %q", blocker)
	}
	if blocker := kernelAdvisoryBlocker(ReleasePhaseEnforce, ReleasePhaseDegraded, strict, KernelExposure{Verdict: kernelVerdictVulnerable, Score: 40}); blocker != "" {
		t.Fatalf("an exposure below the limit was vetoed: %q", blocker)
	}
}

// TestKernelExposureNeverTreatsABlindSpotAsClosed is the lesson from the first live run on the
// production host: PrivateDevices hides /dev from the control plane, and the entry points that live
// there must be reported as unmeasured instead of absent.
func TestKernelExposureNeverTreatsABlindSpotAsClosed(t *testing.T) {
	source := newFakeExposureSource()
	source.files["/proc/sys/kernel/osrelease"] = "7.0.0-31-generic\n"
	source.files["/etc/os-release"] = "ID=ubuntu\nVERSION_CODENAME=noble\n"
	source.files["/usr/bin/docker"] = ""
	source.files["/proc/sys/kernel/unprivileged_userns_clone"] = "1\n"
	source.files["/proc/misc"] = " 10 tun\n232 kvm\n"
	source.dirs["/sys/bus/virtio/devices"] = []string{"virtio0"}
	exposure := evaluateKernelExposure(source, kernelAdvisories(), time.Unix(1_800_000_000, 0).UTC())
	joined := strings.Join(exposure.Unmeasured, ",")
	if !strings.Contains(joined, "tun-writable") || !strings.Contains(joined, "kvm-host") {
		t.Fatalf("unmeasured entry points = %v", exposure.Unmeasured)
	}
	// The measured entry points are all reachable here, so the reachability must be 100 rather than
	// diluted by the two the sandbox cannot see.
	if exposure.Reachability != 100 {
		t.Fatalf("reachability = %d, want 100 of the measured entry points", exposure.Reachability)
	}
	for _, precondition := range exposure.Preconditions {
		if precondition.ID == "tun-writable" && (precondition.Measured || precondition.Present) {
			t.Fatalf("a hidden device was reported as measured/present: %+v", precondition)
		}
	}
}

// TestClosingAnEntryPointMovesTheScore is the end-to-end claim of the mitigation path: the number the
// operator sees must change when a door is actually closed, and it must change for the advisory that
// needs that door.
func TestClosingAnEntryPointMovesTheScore(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	base := newFakeExposureSource()
	base.files["/proc/sys/kernel/osrelease"] = "7.0.0-31-generic\n"
	base.files["/etc/os-release"] = "ID=ubuntu\nVERSION_CODENAME=noble\n"
	base.files["/usr/bin/docker"] = ""
	base.modes["/dev/net/tun"] = 0o600
	base.dirs["/sys/bus/virtio/devices"] = []string{"virtio0"}

	open := newFakeExposureSource()
	open.files = map[string]string{}
	for key, value := range base.files {
		open.files[key] = value
	}
	open.modes = map[string]os.FileMode{}
	for key, value := range base.modes {
		open.modes[key] = value
	}
	open.dirs = base.dirs
	open.files["/proc/sys/kernel/unprivileged_userns_clone"] = "1\n"
	closed := newFakeExposureSource()
	closed.files = map[string]string{}
	for key, value := range base.files {
		closed.files[key] = value
	}
	closed.modes = base.modes
	closed.dirs = base.dirs
	closed.files["/proc/sys/kernel/unprivileged_userns_clone"] = "0\n"

	openExposure := evaluateKernelExposure(open, kernelAdvisories(), now)
	closedExposure := evaluateKernelExposure(closed, kernelAdvisories(), now)
	if closedExposure.Score >= openExposure.Score {
		t.Fatalf("closing the namespace door did not lower the score: open=%d closed=%d",
			openExposure.Score, closedExposure.Score)
	}
	if openExposure.Highest != "CVE-2026-99999" {
		t.Fatalf("highest advisory = %q", openExposure.Highest)
	}
	// The per-advisory reachability must be a statement about *this* advisory's doors: the packet
	// socket is open, the namespace door is what the score reacts to.
	var match KernelAdvisoryMatch
	for _, candidate := range openExposure.Advisories {
		if candidate.ID == "CVE-2026-99999" {
			match = candidate
		}
	}
	if match.Reachability <= 0 || match.Reachability >= 100 {
		t.Fatalf("the advisory reachability = %d, want a partial value", match.Reachability)
	}
	if len(match.EntryPoints) == 0 {
		t.Fatal("the advisory match carries no entry points")
	}
	if openExposure.Reachability <= 0 {
		t.Fatal("the global reachability was not measured")
	}
}

// TestKernelExposureCacheServesOneMeasurement proves the cache is what keeps the release gate from
// re-reading the file system on every evaluation, and that a refresh really re-measures.
func TestKernelExposureCacheServesOneMeasurement(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	reads := 0
	source := newFakeExposureSource()
	source.files["/proc/sys/kernel/osrelease"] = "6.1.190-1\n"
	source.files["/etc/os-release"] = "ID=debian\nVERSION_CODENAME=bookworm\n"
	cache := newKernelExposureCache(func() time.Time { return now }, func() kernelExposureSource {
		reads++
		return source
	})
	first := cache.Current()
	second := cache.Current()
	if reads != 1 {
		t.Fatalf("cache re-read the host %d times", reads)
	}
	if first.Score != second.Score || first.Kernel.Release != second.Kernel.Release {
		t.Fatal("cache returned two different measurements")
	}
	now = now.Add(time.Minute)
	cache.Current()
	if reads != 2 {
		t.Fatalf("cache did not expire, reads = %d", reads)
	}
	cache.Refresh()
	if reads != 3 {
		t.Fatalf("refresh did not re-measure, reads = %d", reads)
	}
}
