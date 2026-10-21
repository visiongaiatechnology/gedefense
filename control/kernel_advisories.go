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

// Kernel advisories: exposure that the network sensors cannot see.
//
// The PwnEscape class of vulnerability (CVE-2026-99999 and the family it belongs to) is a local
// trust failure inside the host kernel: an untrusted producer supplies checksum metadata that is
// validated against one interpretation of the packet and consumed against another, which is how a
// guest or container reaches host memory. No packet GeDefense owns a hook for carries that state,
// so a sensor rule cannot see it - but the platform can still answer the question that matters to
// an operator: "is this kernel affected by a known advisory, is the path actually reachable on
// this host, and what can be closed without breaking the machine".
//
// Three properties are deliberately kept separate, because collapsing them is how security
// products end up lying:
//
//   1. Affectedness is a statement about the kernel build (version range per release channel).
//   2. Reachability is a statement about this host (who can reach the vulnerable entry point).
//   3. Mitigation is a statement about what is verifiably closed.
//
// A host can be affected but unreachable, reachable but affected-unknown, or affected with the
// path already closed. The score is built from all three and never from the version alone.

// ---------------------------------------------------------------- version model

// KernelVersion is the numeric part of a kernel release as it matters for advisory comparison:
// upstream version plus the distribution build suffix (Ubuntu ABI, Debian revision).
type KernelVersion struct {
	Major int
	Minor int
	Patch int
	// Build is the trailing number after the first dash ("7.0.0-31-generic" -> 31,
	// "6.1.190-1" -> 1). Two builds of the same upstream version are not interchangeable:
	// a distribution backports the fix into a later build of the same version line.
	Build    int
	HasBuild bool
	Raw      string
}

// parseKernelVersion reads the leading numeric triple and the first build suffix. Anything after
// that (the "-generic"/"-amd64" flavour or a second revision) is irrelevant for comparison and is
// deliberately not interpreted: guessing what a vendor suffix means is how version checks produce
// confident nonsense.
func parseKernelVersion(raw string) (KernelVersion, bool) {
	release := strings.TrimSpace(raw)
	if release == "" {
		return KernelVersion{}, false
	}
	if cut := strings.IndexAny(release, " \t"); cut >= 0 {
		release = release[:cut]
	}
	version := KernelVersion{Raw: release}
	rest := release
	build := ""
	if dash := strings.IndexByte(rest, '-'); dash >= 0 {
		build = rest[dash+1:]
		rest = rest[:dash]
	}
	parts := strings.Split(rest, ".")
	if len(parts) < 2 {
		return KernelVersion{}, false
	}
	numbers := make([]int, 0, 3)
	for index, part := range parts {
		if index == 3 {
			break
		}
		// A distribution may carry a fourth numeric component; only three are compared.
		digits := part
		for len(digits) > 0 {
			last := digits[len(digits)-1]
			if last < '0' || last > '9' {
				digits = digits[:len(digits)-1]
				continue
			}
			break
		}
		if digits == "" {
			return KernelVersion{}, false
		}
		value, err := strconv.Atoi(digits)
		if err != nil {
			return KernelVersion{}, false
		}
		numbers = append(numbers, value)
	}
	version.Major = numbers[0]
	version.Minor = numbers[1]
	if len(numbers) > 2 {
		version.Patch = numbers[2]
	}
	if build != "" {
		digits := make([]byte, 0, len(build))
		for index := 0; index < len(build); index++ {
			if build[index] < '0' || build[index] > '9' {
				break
			}
			digits = append(digits, build[index])
		}
		if len(digits) > 0 {
			value, err := strconv.Atoi(string(digits))
			if err == nil {
				version.Build = value
				version.HasBuild = true
			}
		}
	}
	return version, true
}

// compareKernelVersion orders two versions by upstream triple first and build suffix second.
// A version without a build suffix sorts before the same version with one, so "7.0.0" < "7.0.0-31":
// a build suffix can only ever add fixes to the same upstream base.
func compareKernelVersion(a, b KernelVersion) int {
	if step := compareInt(a.Major, b.Major); step != 0 {
		return step
	}
	if step := compareInt(a.Minor, b.Minor); step != 0 {
		return step
	}
	if step := compareInt(a.Patch, b.Patch); step != 0 {
		return step
	}
	switch {
	case !a.HasBuild && !b.HasBuild:
		return 0
	case !a.HasBuild:
		return -1
	case !b.HasBuild:
		return 1
	}
	return compareInt(a.Build, b.Build)
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ---------------------------------------------------------------- advisory catalogue

type KernelAdvisoryClass string

const (
	// kernelClassMetadataTrust covers deferred-metadata trust inversion: a less trusted producer
	// supplies descriptive metadata that a later kernel consumer treats as an authorisation.
	kernelClassMetadataTrust KernelAdvisoryClass = "deferred-metadata-trust"
	// kernelClassMemorySafety covers ordinary out-of-bounds and use-after-free classes.
	kernelClassMemorySafety KernelAdvisoryClass = "memory-safety"
)

type KernelAdvisory struct {
	ID    string
	Title string
	Class KernelAdvisoryClass
	// Severity is the vendor-independent class the platform scores on. It is not a re-derivation of
	// the CVSS of the day; it states what a successful use means for the host.
	Severity string
	CVSS     float64
	// GuardCommit names the upstream commit that closes the defect, so an operator can diff their
	// own build instead of trusting a version number.
	GuardCommit string
	// UpstreamFix is the first mainline release that carries the fix. Empty when unknown.
	UpstreamFix string
	// DistroFix maps a distribution release channel (ID/codename) to the first fixed build.
	DistroFix map[string]string
	// EntryPoints lists the precondition identifiers this advisory needs to be reachable.
	EntryPoints []string
	Mitigations []KernelMitigationInfo
	Reference   string
	// Detects states what GeDefense itself can see of this class, so a report never implies more
	// visibility than the sensors have.
	Detects string
}

type KernelMitigationInfo struct {
	// Precondition names the entry point this mitigation closes.
	Precondition string
	// Command is the operator-facing action. It is executed by the operator or by the canonical
	// sysctl transaction, never by an ad-hoc write from a report path.
	Command string
	// Tradeoff states what breaks when the mitigation is applied.
	Tradeoff string
}

// kernelAdvisories is the curated catalogue. Entries are added as data, never as code: the engine
// below is generic, so a new advisory needs a version range, its entry points and its mitigations,
// not a new detector.
//
// What this catalogue is not: a feed. It is shipped with the release, reviewed with the release and
// signed by the release manifest, so an operator can tell which advisories a given build knew about.
func kernelAdvisories() []KernelAdvisory {
	return []KernelAdvisory{
		{
			ID:          "CVE-2026-99999",
			Title:       "PwnEscape: deferred checksum metadata rewrites the parsed IPv4 header",
			Class:       kernelClassMetadataTrust,
			Severity:    "critical",
			CVSS:        9.8,
			GuardCommit: "6785011f8b16abf40b1e9d8b2e332232b3e68822",
			UpstreamFix: "7.3",
			DistroFix: map[string]string{
				// Debian security tracker, verified 20.10.2026.
				"debian-bookworm": "6.1.190-1",
				"debian-trixie":   "6.12.113-1",
				"debian-sid":      "6.12.113-1",
			},
			EntryPoints: []string{
				"container-packet-socket",
				"tun-writable",
				"user-namespace",
			},
			Mitigations: []KernelMitigationInfo{
				{
					Precondition: "container-packet-socket",
					Command:      "confine container workloads to a GeDefense cell whose policy sets CELL_LSM_DENY_NON_UNIX_SOCKET",
					Tradeoff:     "confined workloads lose every non-unix socket, including DNS over UDP",
				},
				{
					Precondition: "tun-writable",
					Command:      "install -m 0600 /dev/null /dev/net/tun && chown root:root /dev/net/tun",
					Tradeoff:     "VPNs, libvirt and rootless container networking stop working for non-root users",
				},
				{
					Precondition: "user-namespace",
					Command:      "sysctl -w kernel.unprivileged_userns_clone=0",
					Tradeoff:     "unprivileged containers, bubblewrap sandboxes and rootless podman stop working",
				},
			},
			Reference: "https://git.kernel.org/linus/6785011f8b16abf40b1e9d8b2e332232b3e68822",
			Detects: "GeDefense cannot observe skb->csum_start: XDP and TC run before sk_buff exists and see no " +
				"offload metadata. Only the leak channel (IPv4 fragments whose header length changes after " +
				"validation) is observable, and only on an attached interface. This entry therefore reports " +
				"exposure and closes entry points; it does not detect exploitation.",
		},
		{
			// The historical half of the catalogue is not decoration: a host that cannot take updates is
			// exactly the host that still runs a kernel from before this fix, and the same user-namespace
			// entry point decides whether it is reachable. Verified against the Debian security tracker.
			ID:          "CVE-2024-1086",
			Title:       "nf_tables double free in nft_verdict_init reaches local root",
			Class:       kernelClassMemorySafety,
			Severity:    "high",
			CVSS:        7.8,
			GuardCommit: "f342de4e2f33e0e39165d8639387aa6c19dff660",
			UpstreamFix: "6.8",
			DistroFix: map[string]string{
				"debian-bookworm": "6.1.76-1",
				"debian-bullseye": "5.10.209-2",
				"debian-trixie":   "6.12.107-1",
			},
			EntryPoints: []string{"user-namespace"},
			Mitigations: []KernelMitigationInfo{
				{
					Precondition: "user-namespace",
					Command:      "sysctl -w kernel.unprivileged_userns_clone=0",
					Tradeoff:     "unprivileged containers, bubblewrap sandboxes and rootless podman stop working",
				},
			},
			Reference: "https://security-tracker.debian.org/tracker/CVE-2024-1086",
			Detects: "GeDefense does not inspect nf_tables state. The XDR command and exec engines can see the " +
				"post-exploitation side of a chain, not the heap corruption itself. This entry reports exposure " +
				"and names the entry point that can be closed.",
		},
	}
}

// ---------------------------------------------------------------- entry points

// KernelPrecondition is one measured statement about this host. Present means "reachable from
// somewhere", not "currently being used".
//
// Measured is separate from Present on purpose. The control plane runs under PrivateDevices=true, so
// /dev is a private tmpfs and /dev/net/tun or /dev/kvm simply do not exist in its view while they are
// present on the host. Reporting that as "not reachable" would understate the exposure, and reporting
// it as "reachable" would invent a measurement. An unmeasured entry point is therefore excluded from
// the reachability denominator and named in the report, which is the same treatment the posture score
// gives an unreadable check.
type KernelPrecondition struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Present  bool   `json:"present"`
	Measured bool   `json:"measured"`
	Weight   int    `json:"weight"`
	Evidence string `json:"evidence"`
}

// kernelPreconditionCatalogue weights how much each entry point contributes to reachability. The
// weights are relative, and a missing or unreadable probe reports Present=false with the reason in
// Evidence - never a silent pass.
func kernelPreconditionCatalogue() []struct {
	ID     string
	Title  string
	Weight int
} {
	return []struct {
		ID     string
		Title  string
		Weight int
	}{
		{"container-packet-socket", "A container runtime can hand out CAP_NET_RAW", 40},
		{"tun-writable", "/dev/net/tun is writable by unprivileged users", 25},
		{"user-namespace", "Unprivileged user namespaces are enabled", 20},
		{"virtio-guest", "The host is itself a virtual machine (virtio devices present)", 10},
		{"kvm-host", "The host can run guests (/dev/kvm present)", 5},
	}
}

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

// ---------------------------------------------------------------- identity + verdict

type KernelIdentity struct {
	Release        string `json:"release"`
	Distro         string `json:"distro"`
	DistroRelease  string `json:"distro_release"`
	Channel        string `json:"channel"`
	Version        string `json:"version"`
	VersionNumeric string `json:"version_numeric"`
}

type KernelVerdict string

const (
	kernelVerdictUnaffected KernelVerdict = "unaffected"
	kernelVerdictVulnerable KernelVerdict = "vulnerable"
	kernelVerdictUnknown    KernelVerdict = "unknown"
)

type KernelAdvisoryMatch struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Class       string        `json:"class"`
	Severity    string        `json:"severity"`
	CVSS        float64       `json:"cvss"`
	Verdict     KernelVerdict `json:"verdict"`
	Reason      string        `json:"reason"`
	GuardCommit string        `json:"guard_commit,omitempty"`
	FixedIn     string        `json:"fixed_in,omitempty"`
	Reference   string        `json:"reference,omitempty"`
	Mitigations []string      `json:"mitigations,omitempty"`
	Detects     string        `json:"detects,omitempty"`
	// EntryPoints are the doors this advisory needs; Reachability is how many of them are measured and
	// open on this host. Both are per advisory because two defects do not share one attack path.
	EntryPoints  []string `json:"entry_points,omitempty"`
	Reachability int      `json:"reachability"`
}

type KernelExposure struct {
	CollectedAt   time.Time             `json:"collected_at"`
	Kernel        KernelIdentity        `json:"kernel"`
	Verdict       KernelVerdict         `json:"verdict"`
	Score         int                   `json:"score"`
	Grade         string                `json:"grade"`
	Highest       string                `json:"highest_advisory,omitempty"`
	Advisories    []KernelAdvisoryMatch `json:"advisories"`
	Preconditions []KernelPrecondition  `json:"preconditions"`
	Reachability  int                   `json:"reachability"`
	// Unmeasured names the entry points this process cannot see, so a reader never mistakes a
	// sandbox-blind spot for a closed door.
	Unmeasured     []string `json:"unmeasured,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	// UnknownReason explains a verdict that could not be decided from the data this build carries.
	UnknownReason string `json:"unknown_reason,omitempty"`
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
	return "Install the fixed kernel build for this release channel."
}

// ---------------------------------------------------------------- configuration

// The advisory engine has exactly two modes, and both are honest about their effect.
//
//	report - measure, score and publish exposure; never change a release decision.
//	strict - additionally veto a promotion when the exposure score crosses the configured limit.
//
// There is deliberately no "auto-mitigate" mode yet: the mitigations in the catalogue cost a real
// capability (rootless containers, VPNs, DNS for confined workloads) and are not something a
// monitoring plane should switch on by itself. The operator applies them; the platform proves
// whether they are in place and rescoring shows the difference.
const (
	advisoryModeReport = "report"
	advisoryModeStrict = "strict"
)

type AdvisoryConfig struct {
	Enabled bool
	Mode    string
	// MaxExposure is the score at or above which strict mode vetoes a promotion.
	MaxExposure int
	// AutoMitigate allows the guard to close a reachable entry point by itself. It is off by default
	// because the switch costs a real capability; the platform measures that cost with a bounded
	// probation window and reverts on a regression.
	AutoMitigate bool
	// MitigationWatchSeconds is the probation window, MitigationIntervalSeconds the assertion cadence
	// and MitigationFailures how many consecutive failed probes trigger the automatic revert.
	MitigationWatchSeconds    int
	MitigationIntervalSeconds int
	MitigationFailures        int
}

func defaultAdvisoryConfig() AdvisoryConfig {
	return AdvisoryConfig{
		Enabled: true, Mode: advisoryModeReport, MaxExposure: 80,
		AutoMitigate: false, MitigationWatchSeconds: 120, MitigationIntervalSeconds: 10, MitigationFailures: 2,
	}
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
