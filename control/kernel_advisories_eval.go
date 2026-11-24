// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kernel advisory matching, reachability measurement, exposure scoring and the
// recommendation/blocker engine split out of kernel_advisories.go
// (refactoring wave 1b, structure-only).

// kernelExposureSource is the file surface the engine is allowed to look at. It exists so the
// classification can be tested against synthetic hosts and so the production path never grows a
// second way of reading the same facts.
type kernelExposureSource interface {
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]string, error)
	Exists(path string) bool
	// Mode reports the permission bits of a path. It is part of the interface because the reachability
	// of the tun entry point is a permission statement, and a report must not guess it.
	Mode(path string) (os.FileMode, bool)
}

type osExposureSource struct{ root string }

func (s osExposureSource) qualify(path string) string {
	return filepath.Join(s.root, filepath.FromSlash(strings.TrimPrefix(path, "/")))
}

func (s osExposureSource) ReadFile(path string) ([]byte, error) {
	file, err := os.Open(s.qualify(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 1<<20))
}

func (s osExposureSource) ReadDir(path string) ([]string, error) {
	entries, err := os.ReadDir(s.qualify(path))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func (s osExposureSource) Exists(path string) bool {
	_, err := os.Stat(s.qualify(path))
	return err == nil
}

func (s osExposureSource) Mode(path string) (os.FileMode, bool) {
	info, err := os.Stat(s.qualify(path))
	if err != nil {
		return 0, false
	}
	return info.Mode().Perm(), true
}

// readKernelIdentity combines the running release with the distribution channel, because a version
// range is only meaningful inside a channel: "6.1.190" is fixed on Debian bookworm and unknown
// elsewhere until that channel publishes its own build.
func readKernelIdentity(src kernelExposureSource) KernelIdentity {
	identity := KernelIdentity{Channel: "unknown"}
	if raw, err := src.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		identity.Release = strings.TrimSpace(string(raw))
	}
	if identity.Release == "" {
		if raw, err := src.ReadFile("/proc/version"); err == nil {
			fields := strings.Fields(string(raw))
			if len(fields) >= 3 {
				identity.Release = fields[2]
			}
		}
	}
	identity.Version = identity.Release
	if version, ok := parseKernelVersion(identity.Release); ok {
		identity.VersionNumeric = fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.Patch)
	}
	id, codename := "", ""
	if raw, err := src.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			value = strings.Trim(value, `"'`)
			switch key {
			case "ID":
				id = strings.ToLower(value)
			case "VERSION_CODENAME":
				codename = strings.ToLower(value)
			case "VERSION_ID":
				identity.DistroRelease = value
			}
		}
	}
	identity.Distro = id
	switch {
	case id != "" && codename != "":
		identity.Channel = id + "-" + codename
	case id != "":
		identity.Channel = id
	}
	return identity
}

// classifyAdvisory decides what this build can honestly say about one advisory.
func classifyAdvisory(advisory KernelAdvisory, identity KernelIdentity) KernelAdvisoryMatch {
	match := KernelAdvisoryMatch{
		ID: advisory.ID, Title: advisory.Title, Class: string(advisory.Class),
		Severity: advisory.Severity, CVSS: advisory.CVSS, GuardCommit: advisory.GuardCommit,
		Reference: advisory.Reference, Detects: advisory.Detects,
		EntryPoints: append([]string(nil), advisory.EntryPoints...),
	}
	for _, mitigation := range advisory.Mitigations {
		match.Mitigations = append(match.Mitigations, mitigation.Precondition+": "+mitigation.Command)
	}
	version, ok := parseKernelVersion(identity.Release)
	if !ok {
		match.Verdict = kernelVerdictUnknown
		match.Reason = "the running kernel release could not be parsed"
		return match
	}
	// A distribution build that has published a fixed version for this channel is decisive: it is
	// the only statement that accounts for backports.
	if fixed, exists := advisory.DistroFix[identity.Channel]; exists {
		fixedVersion, fixedOK := parseKernelVersion(fixed)
		if !fixedOK {
			match.Verdict = kernelVerdictUnknown
			match.Reason = fmt.Sprintf("the catalogue carries an unparsable fixed version %q for %s", fixed, identity.Channel)
			return match
		}
		match.FixedIn = fixed
		if compareKernelVersion(version, fixedVersion) >= 0 {
			match.Verdict = kernelVerdictUnaffected
			match.Reason = fmt.Sprintf("%s %s is at or above the fixed build %s for %s", identity.Distro, identity.Release, fixed, identity.Channel)
			return match
		}
		match.Verdict = kernelVerdictVulnerable
		match.Reason = fmt.Sprintf("%s %s is below the fixed build %s for %s", identity.Distro, identity.Release, fixed, identity.Channel)
		return match
	}
	// A vendor can publish the last build it has explicitly marked unfixed even when the fixed
	// package is not available yet. That is a bounded "known affected" statement: only the same
	// kernel series is covered, and a build above the bound is not declared safe.
	if lastVulnerable, exists := advisory.DistroVulnerableThrough[identity.Channel]; exists {
		boundVersion, boundOK := parseKernelVersion(lastVulnerable)
		if !boundOK {
			match.Verdict = kernelVerdictUnknown
			match.Reason = fmt.Sprintf("the catalogue carries an unparsable known-vulnerable bound %q for %s", lastVulnerable, identity.Channel)
			return match
		}
		if version.Major == boundVersion.Major && version.Minor == boundVersion.Minor && compareKernelVersion(version, boundVersion) <= 0 {
			match.Verdict = kernelVerdictVulnerable
			match.Reason = fmt.Sprintf("%s %s is at or below the last build marked unfixed (%s) for %s", identity.Distro, identity.Release, lastVulnerable, identity.Channel)
			return match
		}
	}
	// No statement for this channel. A mainline fix point is still useful evidence, but it cannot
	// prove a distribution kernel unaffected: distributions backport. That asymmetry is why the
	// unknown verdict exists instead of being folded into "unaffected".
	if advisory.UpstreamFix != "" {
		if fixedVersion, fixedOK := parseKernelVersion(advisory.UpstreamFix); fixedOK {
			match.FixedIn = advisory.UpstreamFix
			if compareKernelVersion(version, fixedVersion) >= 0 {
				match.Verdict = kernelVerdictUnaffected
				match.Reason = fmt.Sprintf("%s is at or above the mainline fix %s", identity.Release, advisory.UpstreamFix)
				return match
			}
			match.Verdict = kernelVerdictUnknown
			match.Reason = fmt.Sprintf("%s is below the mainline fix %s and channel %q has published no fixed build; a distribution backport cannot be excluded", identity.Release, advisory.UpstreamFix, identity.Channel)
			return match
		}
	}
	match.Verdict = kernelVerdictUnknown
	match.Reason = fmt.Sprintf("no fixed version is known for channel %q", identity.Channel)
	return match
}

// ---------------------------------------------------------------- reachability

func readKernelPreconditions(src kernelExposureSource) []KernelPrecondition {
	catalogue := kernelPreconditionCatalogue()
	preconditions := make([]KernelPrecondition, 0, len(catalogue))
	for _, entry := range catalogue {
		precondition := KernelPrecondition{ID: entry.ID, Title: entry.Title, Weight: entry.Weight}
		switch entry.ID {
		case "container-packet-socket":
			precondition.Measured = true
			runtime := ""
			for _, candidate := range []struct{ id, path string }{
				{"docker", "/usr/bin/docker"},
				{"podman", "/usr/bin/podman"},
				{"lxc", "/usr/sbin/lxc"},
			} {
				if src.Exists(candidate.path) {
					runtime = candidate.id
					break
				}
			}
			if runtime == "" {
				precondition.Evidence = "no container runtime binary is installed"
				break
			}
			// A container runtime's default capability set includes NET_RAW, which is the permission
			// that creates AF_PACKET sockets. The runtime being installed is the reachable case that
			// needs no additional misconfiguration.
			precondition.Present = true
			precondition.Evidence = runtime + " is installed; its default capability set includes NET_RAW"
		case "tun-writable":
			mode, ok := src.Mode("/dev/net/tun")
			if !ok {
				// Under PrivateDevices=true the control plane sees a private /dev. The driver can still
				// be proven present through /proc/misc, but the permission bits cannot be read from
				// here - so this entry point is reported as unmeasured, never as closed.
				driver := ""
				if raw, readErr := src.ReadFile("/proc/misc"); readErr == nil && strings.Contains(string(raw), "tun") {
					driver = "; the tun driver is present in /proc/misc"
				}
				precondition.Evidence = "/dev/net/tun is not visible to the control plane (private /dev)" + driver
				break
			}
			precondition.Measured = true
			if mode&0o002 != 0 {
				precondition.Present = true
				precondition.Evidence = fmt.Sprintf("/dev/net/tun is world-writable (mode %04o)", mode)
			} else {
				precondition.Evidence = fmt.Sprintf("/dev/net/tun is not world-writable (mode %04o)", mode)
			}
		case "user-namespace":
			if raw, err := src.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
				precondition.Measured = true
				if strings.TrimSpace(string(raw)) == "1" {
					precondition.Present = true
					precondition.Evidence = "kernel.unprivileged_userns_clone=1"
				} else {
					precondition.Evidence = "kernel.unprivileged_userns_clone=0"
				}
				break
			}
			if raw, err := src.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
				precondition.Measured = true
				if value, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); convErr == nil && value > 0 {
					precondition.Present = true
					precondition.Evidence = fmt.Sprintf("user.max_user_namespaces=%d", value)
				} else {
					precondition.Evidence = "user namespaces are disabled"
				}
				break
			}
			precondition.Evidence = "the user-namespace boundary could not be measured"
		case "mptcp-enabled":
			if raw, err := src.ReadFile("/proc/sys/net/mptcp/enabled"); err == nil {
				precondition.Measured = true
				if strings.TrimSpace(string(raw)) == "1" {
					precondition.Present = true
					precondition.Evidence = "net.mptcp.enabled=1"
				} else {
					precondition.Evidence = "net.mptcp.enabled=0"
				}
			} else {
				precondition.Evidence = "the MPTCP sysctl is not visible to the control plane"
			}
		case "tcp-listener":
			if raw, err := src.ReadFile("/proc/net/tcp"); err == nil {
				precondition.Measured = true
				total, beyondLoopback := countIPv4TCPListeners(raw)
				if total > 0 {
					precondition.Present = true
				}
				precondition.Evidence = fmt.Sprintf("%d IPv4 TCP listener(s), %d bound beyond loopback", total, beyondLoopback)
			} else {
				precondition.Evidence = "/proc/net/tcp is not readable by the control plane"
			}
		case "virtio-guest":
			names, err := src.ReadDir("/sys/bus/virtio/devices")
			if err != nil {
				precondition.Evidence = "the virtio device list could not be read"
				break
			}
			precondition.Measured = true
			if len(names) > 0 {
				precondition.Present = true
				precondition.Evidence = fmt.Sprintf("%d virtio device(s) present; this host is a guest", len(names))
			} else {
				precondition.Evidence = "no virtio devices; this host is not a virtual machine"
			}
		case "kvm-host":
			if _, ok := src.Mode("/dev/kvm"); !ok {
				precondition.Evidence = "/dev/kvm is not visible to the control plane (private /dev)"
				break
			}
			precondition.Measured = true
			precondition.Present = true
			precondition.Evidence = "/dev/kvm is present; this host can run guests"
		}
		preconditions = append(preconditions, precondition)
	}
	return preconditions
}

// countIPv4TCPListeners reads the kernel's /proc/net/tcp table and counts sockets in state 0A
// (LISTEN). It also reports how many of those are bound beyond the IPv4 loopback so a loopback-only
// debug port is not presented as remotely reachable. The parser is deliberately narrow: a malformed
// row is ignored, never treated as an open door.
func countIPv4TCPListeners(raw []byte) (total, beyondLoopback int) {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		total++
		local := fields[1]
		address, _, ok := strings.Cut(local, ":")
		if !ok || !ipv4ProcAddressIsLoopback(address) {
			beyondLoopback++
		}
	}
	return total, beyondLoopback
}

// ipv4ProcAddressIsLoopback decodes the little-endian IPv4 address representation used by
// /proc/net/tcp and tests the whole 127.0.0.0/8 range, not only 127.0.0.1. A malformed address is
// reported as non-loopback (the conservative choice for an exposure count).
func ipv4ProcAddressIsLoopback(address string) bool {
	value, err := strconv.ParseUint(strings.TrimSpace(address), 16, 32)
	if err != nil {
		return false
	}
	return value&0xFF == 127
}

// kernelReachability returns the 0-100 share of the weighted, measurable entry points that are
// reachable. Unmeasured entry points are excluded rather than counted as absent: a sandbox that hides
// /dev must not turn into a clean bill of health.
func kernelReachability(preconditions []KernelPrecondition) int {
	total, present := 0, 0
	for _, precondition := range preconditions {
		if !precondition.Measured {
			continue
		}
		total += precondition.Weight
		if precondition.Present {
			present += precondition.Weight
		}
	}
	if total == 0 {
		return 0
	}
	return int(math.Round(float64(present) / float64(total) * 100))
}

// kernelSeverityBase maps a severity class to the exposure weight it carries when the host is fully
// reachable. It is deliberately not a re-derivation of CVSS: the CVSS vector measures the defect in
// the abstract, this number measures what a successful use costs the host.
func kernelSeverityBase(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 100
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	}
	return 60
}

// scoreKernelExposure combines affectedness with reachability.
//
// A vulnerable kernel that nothing can reach is still a vulnerable kernel, so reachability modulates
// rather than gates: the floor is 40% of the severity weight. An unknown verdict is capped at the
// severity weight and never benefits from a low reachability score, because "we could not decide"
// must not read better than "we decided it is fixed".
func scoreKernelExposure(verdict KernelVerdict, severity string, reachability int) int {
	if verdict == kernelVerdictUnaffected {
		return 0
	}
	base := float64(kernelSeverityBase(severity))
	reach := float64(reachability) / 100
	score := math.Round(base * (0.4 + 0.6*reach))
	if verdict == kernelVerdictUnknown && score > base {
		score = base
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return int(score)
}

func kernelExposureGrade(verdict KernelVerdict, score int) string {
	switch {
	case verdict == kernelVerdictUnaffected:
		return "HARDENED"
	case score >= 80:
		return "EXPOSED"
	case score >= 50:
		return "ELEVATED"
	case verdict == kernelVerdictUnknown:
		return "UNKNOWN"
	default:
		return "GUARDED"
	}
}

// evaluateKernelExposure is the single entry point: read, classify every advisory, measure the
// entry points, score, and name the one action that would help most.
func evaluateKernelExposure(src kernelExposureSource, catalogue []KernelAdvisory, now time.Time) KernelExposure {
	identity := readKernelIdentity(src)
	preconditions := readKernelPreconditions(src)
	reachability := kernelReachability(preconditions)
	exposure := KernelExposure{
		CollectedAt:   now.UTC(),
		Kernel:        identity,
		Verdict:       kernelVerdictUnaffected,
		Preconditions: preconditions,
		Reachability:  reachability,
	}
	for _, precondition := range preconditions {
		if !precondition.Measured {
			exposure.Unmeasured = append(exposure.Unmeasured, precondition.ID)
		}
	}
	unknownReasons := make([]string, 0, 2)
	best := 0
	for _, advisory := range catalogue {
		match := classifyAdvisory(advisory, identity)
		// Each advisory is scored against its *own* entry points. A defect that needs only an
		// unprivileged user namespace is not made worse by an open packet-socket door, and a defect
		// that needs a packet socket is not made safer by a closed namespace door. Scoring both with
		// one global reachability number would invent a relationship between them.
		relevant := preconditionsForEntryPoints(advisory.EntryPoints, preconditions)
		match.Reachability = kernelReachability(relevant)
		exposure.Advisories = append(exposure.Advisories, match)
		score := scoreKernelExposure(match.Verdict, match.Severity, match.Reachability)
		switch match.Verdict {
		case kernelVerdictVulnerable:
			exposure.Verdict = kernelVerdictVulnerable
			if score > best {
				best = score
				exposure.Highest = match.ID
			}
		case kernelVerdictUnknown:
			if exposure.Verdict == kernelVerdictUnaffected {
				exposure.Verdict = kernelVerdictUnknown
			}
			unknownReasons = append(unknownReasons, match.ID+": "+match.Reason)
			if score > best {
				best = score
				exposure.Highest = match.ID
			}
		}
	}
	exposure.Score = best
	exposure.Grade = kernelExposureGrade(exposure.Verdict, exposure.Score)
	if len(unknownReasons) > 0 {
		exposure.UnknownReason = strings.Join(unknownReasons, "; ")
	}
	exposure.Recommendation = kernelExposureRecommendation(exposure)
	return exposure
}

// preconditionsForEntryPoints selects the doors one advisory actually needs.
func preconditionsForEntryPoints(entryPoints []string, all []KernelPrecondition) []KernelPrecondition {
	if len(entryPoints) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(entryPoints))
	for _, entryPoint := range entryPoints {
		wanted[entryPoint] = true
	}
	selected := make([]KernelPrecondition, 0, len(entryPoints))
	for _, precondition := range all {
		if wanted[precondition.ID] {
			selected = append(selected, precondition)
		}
	}
	return selected
}

// kernelExposureRecommendation names the single highest-value action. A report that lists five
// equal options leaves the operator with the decision the product was supposed to make.
//
// The action is chosen from the entry points of the *worst* advisory, not from every door the host
// happens to have open: closing a door that the relevant defect does not need buys nothing and
// distracts from the one that matters.
func kernelExposureRecommendation(exposure KernelExposure) string {
	if exposure.Verdict == kernelVerdictUnaffected {
		return "No known kernel advisory applies to this build."
	}
	var relevant []KernelPrecondition
	for _, match := range exposure.Advisories {
		if match.ID == exposure.Highest {
			relevant = preconditionsForEntryPoints(match.EntryPoints, exposure.Preconditions)
			break
		}
	}
	if len(relevant) == 0 {
		relevant = exposure.Preconditions
	}
	for _, precondition := range relevant {
		if precondition.ID == "container-packet-socket" && precondition.Present {
			return "Confine container workloads to a cell that denies non-unix sockets; that closes the " +
				"protocol-packet entry point this class needs and does not require waiting for a kernel build."
		}
	}
	for _, precondition := range relevant {
		if precondition.ID == "tun-writable" && precondition.Present {
			return "Restrict /dev/net/tun to root (mode 0600); it is the entry point that needs no container at all."
		}
	}
	for _, precondition := range relevant {
		if precondition.ID == "user-namespace" && precondition.Present {
			return "Disable unprivileged user namespaces (kernel.unprivileged_userns_clone=0) or install the fixed kernel build."
		}
	}
	for _, precondition := range relevant {
		if precondition.ID == "tcp-listener" && precondition.Present {
			return "Restrict exposed IPv4 TCP listeners to required sources; keep MPTCP disabled if unused and install the fixed kernel build."
		}
	}
	for _, precondition := range relevant {
		if precondition.ID == "mptcp-enabled" && precondition.Present {
			return "Disable MPTCP (sysctl -w net.mptcp.enabled=0) if unused and install the fixed kernel build."
		}
	}
	return "Install the fixed kernel build for this release channel."
}

// kernelAdvisoryBlocker returns the strict-mode veto message, or "" when the advisory layer must not
// influence this evaluation.
//
// The veto applies to a *promotion* only: it is skipped when the evaluator is asking about the phase
// the platform is already in. Pausing automatic response because the kernel is old would remove
// protection in the name of protection - the exact failure mode this platform already had to recover
// from. A degraded host that wants to return to enforce *is* a promotion and stays vetoed in strict
// mode, so the operator's choice still has teeth where it matters.
func kernelAdvisoryBlocker(target, currentPhase string, cfg AdvisoryConfig, exposure KernelExposure) string {
	if !cfg.Enabled || cfg.Mode != advisoryModeStrict {
		return ""
	}
	if target == currentPhase {
		return ""
	}
	if exposure.Verdict == kernelVerdictUnaffected {
		return ""
	}
	if exposure.Score < cfg.MaxExposure {
		return ""
	}
	return fmt.Sprintf("kernel advisory exposure %d of 100 exceeds the strict limit %d (%s)",
		exposure.Score, cfg.MaxExposure, exposure.Highest)
}

// ---------------------------------------------------------------- state plumbing

// kernelExposureCache keeps the last measurement so the release gate and the API do not each re-read
// the file system on every evaluation.
type kernelExposureCache struct {
	mu       sync.RWMutex
	exposure KernelExposure
	valid    bool
	at       time.Time
	ttl      time.Duration
	now      func() time.Time
	source   func() kernelExposureSource
}

func newKernelExposureCache(now func() time.Time, source func() kernelExposureSource) *kernelExposureCache {
	return &kernelExposureCache{
		ttl: 30 * time.Second, now: now, source: source,
	}
}

func (c *kernelExposureCache) Current() KernelExposure {
	c.mu.RLock()
	fresh := c.valid && c.now().Sub(c.at) < c.ttl
	exposure := c.exposure
	c.mu.RUnlock()
	if fresh {
		return exposure
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.valid && c.now().Sub(c.at) < c.ttl {
		return c.exposure
	}
	source := c.source()
	c.exposure = evaluateKernelExposure(source, kernelAdvisories(), c.now())
	c.valid = true
	c.at = c.now()
	return c.exposure
}

func (c *kernelExposureCache) Refresh() KernelExposure {
	c.mu.Lock()
	c.valid = false
	c.mu.Unlock()
	return c.Current()
}

// sortedAdvisoryIDs returns the catalogue ids in a stable order, for evidence and tests.
func sortedAdvisoryIDs(catalogue []KernelAdvisory) []string {
	ids := make([]string, 0, len(catalogue))
	for _, advisory := range catalogue {
		ids = append(ids, advisory.ID)
	}
	sort.Strings(ids)
	return ids
}
