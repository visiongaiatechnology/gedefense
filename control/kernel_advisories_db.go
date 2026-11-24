// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strconv"
	"strings"
	"time"
)

// Curated kernel advisory catalogue and the version/report data model split
// out of kernel_advisories.go (refactoring wave 1b, structure-only).

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
	// DistroVulnerableThrough names the last build a vendor has explicitly marked unfixed for a
	// channel (for example an Ubuntu "needed" CVE state). It is deliberately a bounded statement:
	// a build above the bound is not declared safe, only no-longer-known-vulnerable.
	DistroVulnerableThrough map[string]string
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
		{
			// Verified against the Linux CVE announcement, the Debian security tracker and the Ubuntu CVE
			// status on 29.10.2026. Ubuntu 24.04 HWE 7.0 is "needed" (no fixed package); the 7.0.0-42
			// candidate changelog does not contain the fix. The bound below is a vendor statement, not a
			// claim that 7.0.0-43 is safe.
			ID:          "CVE-2026-98432",
			Title:       "IPv4 TCP inet_opt/ireq_opt use-after-free after an RCU grace period",
			Class:       kernelClassMemorySafety,
			Severity:    "critical",
			CVSS:        9.8,
			GuardCommit: "e3f33b0a1d89d738e2b913dab519226eaf76e15b",
			UpstreamFix: "7.3",
			DistroFix: map[string]string{
				"debian-bookworm": "6.1.190-1",
				"debian-trixie":   "6.12.113-1",
				"debian-sid":      "7.2.13-1",
			},
			DistroVulnerableThrough: map[string]string{
				"ubuntu-noble": "7.0.0-42",
			},
			EntryPoints: []string{"mptcp-enabled", "tcp-listener"},
			Mitigations: []KernelMitigationInfo{
				{
					Precondition: "mptcp-enabled",
					Command:      "sysctl -w net.mptcp.enabled=0",
					Tradeoff:     "MPTCP applications lose multipath transport; the kernel remains affected by the UAF until patched",
				},
				{
					Precondition: "tcp-listener",
					Command:      "restrict Internet-facing TCP listeners to required sources and install the fixed kernel build",
					Tradeoff:     "unused remote services become unreachable; this reduces exposure but does not fix the UAF",
				},
			},
			Reference: "https://lists.openwall.net/linux-cve-announce/2026/10/15/1",
			Detects: "GeDefense reads the running kernel release, whether MPTCP is enabled and whether at least " +
				"one TCP socket is listening. It cannot detect the internal request-socket race or prove that a " +
				"specific listener uses MPTCP: the version/fix state is decisive, the entry points only describe " +
				"whether the documented path is reachable. XDP/eBPF can reduce exposure, never repair the UAF.",
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
		{"mptcp-enabled", "MPTCP is enabled in the kernel", 30},
		{"tcp-listener", "At least one IPv4 TCP socket is listening", 35},
		{"virtio-guest", "The host is itself a virtual machine (virtio devices present)", 10},
		{"kvm-host", "The host can run guests (/dev/kvm present)", 5},
	}
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
