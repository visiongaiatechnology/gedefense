// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	hardeningStateProtected   = "PROTECTED"
	hardeningStatePartial     = "PARTIAL"
	hardeningStateUnprotected = "UNPROTECTED"
	hardeningStateUnavailable = "UNAVAILABLE"
)

type HardeningCheck struct {
	ID             string `json:"id"`
	Domain         string `json:"domain"`
	Title          string `json:"title"`
	State          string `json:"state"`
	Weight         int    `json:"weight"`
	Managed        bool   `json:"managed"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation,omitempty"`
}

type HardeningDomain struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Score     int    `json:"score"`
	Protected int    `json:"protected"`
	Total     int    `json:"total"`
}

type HardeningPosture struct {
	CollectedAt time.Time         `json:"collected_at"`
	Score       int               `json:"score"`
	Level       string            `json:"level"`
	Checks      []HardeningCheck  `json:"checks"`
	Domains     []HardeningDomain `json:"domains"`
}

type HardeningCollector struct {
	root string
	now  func() time.Time
}

func NewHardeningCollector() *HardeningCollector {
	return &HardeningCollector{root: string(filepath.Separator), now: func() time.Time { return time.Now().UTC() }}
}

func newHardeningCollectorForTest(root string, now func() time.Time) *HardeningCollector {
	return &HardeningCollector{root: root, now: now}
}

func (c *HardeningCollector) Collect(snapshot Snapshot, boot BootTrustReport) HardeningPosture {
	checks := []HardeningCheck{
		c.kernelReleaseCheck(),
		c.integerCheck("kernel.aslr", "kernel", "Address Space Layout Randomization", "proc/sys/kernel/randomize_va_space", 2, 10, true, "Set kernel.randomize_va_space=2."),
		c.minimumCheck("kernel.kptr", "kernel", "Kernel pointer restriction", "proc/sys/kernel/kptr_restrict", 2, 8, true, "Set kernel.kptr_restrict=2."),
		c.minimumCheck("kernel.dmesg", "kernel", "Kernel log restriction", "proc/sys/kernel/dmesg_restrict", 1, 7, true, "Set kernel.dmesg_restrict=1."),
		c.minimumCheck("kernel.ptrace", "kernel", "Process tracing boundary", "proc/sys/kernel/yama/ptrace_scope", 1, 8, true, "Set kernel.yama.ptrace_scope to at least 1."),
		c.minimumCheck("kernel.bpf", "kernel", "Unprivileged BPF restriction", "proc/sys/kernel/unprivileged_bpf_disabled", 1, 10, true, "Disable unprivileged BPF."),
		c.pairedMinimumCheck("filesystem.protected-links", "filesystem", "Protected FIFOs and regular files", "proc/sys/fs/protected_fifos", "proc/sys/fs/protected_regular", 2, 7, "Protect privileged FIFO and regular-file creation."),
		c.integerCheck("filesystem.suid-dumps", "filesystem", "SUID core-dump suppression", "proc/sys/fs/suid_dumpable", 0, 7, true, "Disable core dumps for privileged executables."),
		c.integerCheck("network.syn-cookies", "network", "TCP SYN cookie protection", "proc/sys/net/ipv4/tcp_syncookies", 1, 6, true, "Enable TCP SYN cookies."),
		c.redirectCheck("network.ipv4-redirects", "IPv4 redirect rejection", []string{"proc/sys/net/ipv4/conf/all/accept_redirects", "proc/sys/net/ipv4/conf/default/accept_redirects", "proc/sys/net/ipv4/conf/all/send_redirects", "proc/sys/net/ipv4/conf/default/send_redirects"}, 7),
		c.redirectCheck("network.ipv6-redirects", "IPv6 redirect rejection", []string{"proc/sys/net/ipv6/conf/all/accept_redirects", "proc/sys/net/ipv6/conf/default/accept_redirects"}, 6),
		c.moduleSignatureCheck(),
		c.apparmorCheck(),
		c.apparmorProfilesCheck(),
		c.rootEncryptionCheck(),
		c.rootFilesystemCheck(),
		bootPostureCheck(boot, "secure-boot", "boot.secure", "boot", "UEFI Secure Boot", 9, "Enable Secure Boot and enroll the AstraeaOS signing trust chain."),
		bootPostureCheck(boot, "kernel-lockdown", "boot.lockdown", "boot", "Kernel lockdown", 7, "Enable kernel lockdown in integrity or confidentiality mode."),
		bootPostureCheck(boot, "tpm", "crypto.tpm", "encryption", "Trusted Platform Module", 4, "Enable TPM 2.0 for measured boot and sealed-key support."),
		c.firewallCheck(),
		statePostureCheck("integrity.fim", "integrity", "File Integrity Monitoring", 8, snapshot.FIM.Enabled, snapshot.FIM.Health == "HEALTHY", snapshot.FIM.Health, "Create and continuously verify the encrypted FIM baseline."),
		statePostureCheck("integrity.evidence", "integrity", "Signed Evidence Ledger", 8, snapshot.Evidence.Enabled, snapshot.Evidence.Healthy, evidenceHealth(snapshot.Evidence), "Restore the encrypted and signed evidence ledger before mutations."),
	}
	return summarizeHardening(c.now(), checks)
}

func (c *HardeningCollector) pairedMinimumCheck(id, domain, title, first, second string, minimum, weight int, recommendation string) HardeningCheck {
	check := baseHardeningCheck(id, domain, title, weight, true)
	firstRaw, firstErr := c.regularText(first, 64)
	secondRaw, secondErr := c.regularText(second, 64)
	firstValue, firstParseErr := strconv.Atoi(firstRaw)
	secondValue, secondParseErr := strconv.Atoi(secondRaw)
	if firstErr != nil || secondErr != nil || firstParseErr != nil || secondParseErr != nil {
		return unavailableHardening(check)
	}
	check.Evidence = "live values=" + strconv.Itoa(firstValue) + "," + strconv.Itoa(secondValue)
	if firstValue >= minimum && secondValue >= minimum {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStateUnprotected
	check.Recommendation = recommendation
	return check
}

func (c *HardeningCollector) redirectCheck(id, title string, paths []string, weight int) HardeningCheck {
	check := baseHardeningCheck(id, "network", title, weight, true)
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		raw, err := c.regularText(path, 64)
		if err != nil || (raw != "0" && raw != "1") {
			return unavailableHardening(check)
		}
		values = append(values, raw)
	}
	check.Evidence = "live values=" + strings.Join(values, ",")
	for _, value := range values {
		if value != "0" {
			check.State = hardeningStateUnprotected
			check.Recommendation = "Reject ICMP redirects on all current and future interfaces."
			return check
		}
	}
	check.State = hardeningStateProtected
	return check
}

func (c *HardeningCollector) path(relative string) string {
	return filepath.Join(c.root, filepath.FromSlash(relative))
}

func (c *HardeningCollector) regularText(relative string, maxBytes int64) (string, error) {
	path := c.path(relative)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maxBytes {
		return "", errors.New("hardening evidence is not a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (c *HardeningCollector) kernelReleaseCheck() HardeningCheck {
	value, err := c.regularText("proc/sys/kernel/osrelease", 512)
	check := baseHardeningCheck("kernel.release", "kernel", "Hardened kernel", 10, false)
	if err != nil {
		return unavailableHardening(check)
	}
	check.Evidence = "kernel identity measured"
	if strings.Contains(strings.ToLower(value), "hardened") {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStateUnprotected
	check.Recommendation = "Boot the AstraeaOS linux-hardened kernel."
	return check
}

func (c *HardeningCollector) integerCheck(id, domain, title, relative string, expected, weight int, managed bool, recommendation string) HardeningCheck {
	return c.numericCheck(id, domain, title, relative, expected, weight, managed, recommendation, false)
}

func (c *HardeningCollector) minimumCheck(id, domain, title, relative string, minimum, weight int, managed bool, recommendation string) HardeningCheck {
	return c.numericCheck(id, domain, title, relative, minimum, weight, managed, recommendation, true)
}

func (c *HardeningCollector) numericCheck(id, domain, title, relative string, boundary, weight int, managed bool, recommendation string, minimum bool) HardeningCheck {
	check := baseHardeningCheck(id, domain, title, weight, managed)
	raw, err := c.regularText(relative, 64)
	if err != nil {
		return unavailableHardening(check)
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return unavailableHardening(check)
	}
	check.Evidence = "live value=" + strconv.Itoa(value)
	protected := value == boundary
	if minimum {
		protected = value >= boundary
	}
	if protected {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStateUnprotected
	check.Recommendation = recommendation
	return check
}

func (c *HardeningCollector) moduleSignatureCheck() HardeningCheck {
	check := baseHardeningCheck("kernel.module-signatures", "kernel", "Kernel module signature enforcement", 9, true)
	if value, err := c.regularText("proc/sys/kernel/module_sig_enforce", 64); err == nil {
		check.Evidence = "live kernel enforcement measured"
		if value == "1" {
			check.State = hardeningStateProtected
			return check
		}
	}
	cmdline, err := c.regularText("proc/cmdline", 32<<10)
	if err == nil && containsKernelArgument(cmdline, "module.sig_enforce=1") {
		check.State = hardeningStateProtected
		check.Evidence = "boot policy enforcement measured"
		return check
	}
	check.State = hardeningStateUnprotected
	check.Evidence = "signature enforcement not observed"
	check.Recommendation = "Enforce signatures for all loadable kernel modules."
	return check
}

func (c *HardeningCollector) apparmorCheck() HardeningCheck {
	check := baseHardeningCheck("mac.apparmor", "application-control", "AppArmor kernel enforcement", 9, false)
	value, err := c.regularText("sys/module/apparmor/parameters/enabled", 64)
	if err != nil {
		return unavailableHardening(check)
	}
	check.Evidence = "kernel parameter measured"
	if strings.EqualFold(value, "Y") {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStateUnprotected
	check.Recommendation = "Enable AppArmor in the kernel command line and initramfs."
	return check
}

func (c *HardeningCollector) apparmorProfilesCheck() HardeningCheck {
	check := baseHardeningCheck("mac.apparmor-profiles", "application-control", "AppArmor enforced profiles", 7, false)
	raw, err := c.regularText("sys/kernel/security/apparmor/profiles", 4<<20)
	if err != nil {
		return unavailableHardening(check)
	}
	total, enforced := 0, 0
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		total++
		if strings.HasSuffix(strings.TrimSpace(line), "(enforce)") {
			enforced++
		}
	}
	check.Evidence = "profiles=" + strconv.Itoa(total) + ", enforce=" + strconv.Itoa(enforced)
	switch {
	case total > 0 && enforced == total:
		check.State = hardeningStateProtected
	case enforced > 0:
		check.State = hardeningStatePartial
		check.Recommendation = "Move remaining AppArmor profiles from complain to enforce mode."
	default:
		check.State = hardeningStateUnprotected
		check.Recommendation = "Load AstraeaOS AppArmor profiles in enforce mode."
	}
	return check
}

func (c *HardeningCollector) rootEncryptionCheck() HardeningCheck {
	check := baseHardeningCheck("crypto.root", "encryption", "Encrypted root filesystem", 10, false)
	cmdline, err := c.regularText("proc/cmdline", 32<<10)
	if err != nil {
		return unavailableHardening(check)
	}
	protected := false
	for _, token := range strings.Fields(cmdline) {
		if strings.HasPrefix(token, "cryptdevice=") || strings.HasPrefix(token, "rd.luks.") ||
			strings.HasPrefix(token, "root=/dev/mapper/") {
			protected = true
			break
		}
	}
	check.Evidence = "boot storage mapping measured"
	if protected {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStateUnprotected
	check.Recommendation = "Install AstraeaOS with LUKS2 full-disk encryption."
	return check
}

func (c *HardeningCollector) rootFilesystemCheck() HardeningCheck {
	check := baseHardeningCheck("storage.root-fs", "encryption", "Resilient root filesystem", 4, false)
	raw, err := c.regularText("proc/self/mounts", 4<<20)
	if err != nil {
		return unavailableHardening(check)
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "/" {
			check.Evidence = "root filesystem=" + fields[2]
			if fields[2] == "btrfs" {
				check.State = hardeningStateProtected
			} else {
				check.State = hardeningStatePartial
				check.Recommendation = "Use the AstraeaOS Btrfs layout with isolated snapshots."
			}
			return check
		}
	}
	return unavailableHardening(check)
}

func (c *HardeningCollector) firewallCheck() HardeningCheck {
	check := baseHardeningCheck("network.firewall", "network", "nftables policy", 8, false)
	raw, err := c.regularText("etc/nftables.conf", 4<<20)
	if err != nil {
		return unavailableHardening(check)
	}
	check.Evidence = "bounded nftables policy present"
	if strings.Contains(raw, "table inet") && strings.Contains(raw, "hook input") {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStatePartial
	check.Recommendation = "Install the AstraeaOS nftables inet input policy."
	return check
}

func bootPostureCheck(report BootTrustReport, sourceID, id, domain, title string, weight int, recommendation string) HardeningCheck {
	check := baseHardeningCheck(id, domain, title, weight, false)
	for _, item := range report.Items {
		if item.ID != sourceID {
			continue
		}
		check.Evidence = item.Summary
		switch item.State {
		case bootStateEnabled, bootStateObserved:
			check.State = hardeningStateProtected
		case bootStateDisabled:
			check.State = hardeningStateUnprotected
			check.Recommendation = recommendation
		default:
			check.State = hardeningStateUnavailable
		}
		return check
	}
	return unavailableHardening(check)
}

func statePostureCheck(id, domain, title string, weight int, enabled, healthy bool, evidence, recommendation string) HardeningCheck {
	check := baseHardeningCheck(id, domain, title, weight, false)
	check.Evidence = evidence
	switch {
	case enabled && healthy:
		check.State = hardeningStateProtected
	case enabled:
		check.State = hardeningStatePartial
		check.Recommendation = recommendation
	default:
		check.State = hardeningStateUnprotected
		check.Recommendation = recommendation
	}
	return check
}

func evidenceHealth(status EvidenceStatus) string {
	if status.Healthy {
		return "HEALTHY"
	}
	if status.Error != "" {
		return "DEGRADED"
	}
	return "UNAVAILABLE"
}

func packageIntegrityPostureCheck(status PackageIntegrityStatus) HardeningCheck {
	check := baseHardeningCheck("integrity.packages", "integrity", "Signed package file integrity", 9, false)
	switch {
	case !status.Available:
		return unavailableHardening(check)
	case status.Running:
		check.State = hardeningStatePartial
		check.Evidence = "package verification in progress"
	case status.LastScan == nil:
		check.State = hardeningStateUnprotected
		check.Evidence = "package manifests not yet verified"
		check.Recommendation = "Run the local Pacman MTREE integrity scan."
	case status.Modified == 0 && status.Missing == 0 && status.Errors == 0:
		check.State = hardeningStateProtected
		check.Evidence = "verified files=" + strconv.Itoa(status.Verified)
	default:
		check.State = hardeningStateUnprotected
		check.Evidence = "modified=" + strconv.Itoa(status.Modified) + ", missing=" + strconv.Itoa(status.Missing) + ", errors=" + strconv.Itoa(status.Errors)
		check.Recommendation = "Investigate package deviations and reinstall affected signed packages."
	}
	return check
}

func baseHardeningCheck(id, domain, title string, weight int, managed bool) HardeningCheck {
	return HardeningCheck{ID: id, Domain: domain, Title: title, State: hardeningStateUnavailable, Weight: weight, Managed: managed}
}

func unavailableHardening(check HardeningCheck) HardeningCheck {
	check.State = hardeningStateUnavailable
	check.Evidence = "evidence unavailable"
	return check
}

func containsKernelArgument(cmdline, expected string) bool {
	for _, token := range strings.Fields(cmdline) {
		if token == expected {
			return true
		}
	}
	return false
}

func summarizeHardening(now time.Time, checks []HardeningCheck) HardeningPosture {
	totalWeight, protectedWeight := 0, 0
	type aggregate struct{ score, total, protected, count int }
	domains := make(map[string]*aggregate)
	for _, check := range checks {
		if check.State == hardeningStateUnavailable {
			continue
		}
		totalWeight += check.Weight
		value := 0
		switch check.State {
		case hardeningStateProtected:
			value = check.Weight
		case hardeningStatePartial:
			value = check.Weight / 2
		}
		protectedWeight += value
		entry := domains[check.Domain]
		if entry == nil {
			entry = &aggregate{}
			domains[check.Domain] = entry
		}
		entry.score += value
		entry.total += check.Weight
		entry.count++
		if check.State == hardeningStateProtected {
			entry.protected++
		}
	}
	score := 0
	if totalWeight > 0 {
		score = protectedWeight * 100 / totalWeight
	}
	level := "CRITICAL"
	switch {
	case score >= 90:
		level = "HARDENED"
	case score >= 75:
		level = "STRONG"
	case score >= 50:
		level = "BASIC"
	}
	domainIDs := make([]string, 0, len(domains))
	for id := range domains {
		domainIDs = append(domainIDs, id)
	}
	sort.Strings(domainIDs)
	summaries := make([]HardeningDomain, 0, len(domainIDs))
	for _, id := range domainIDs {
		entry := domains[id]
		domainScore := 0
		if entry.total > 0 {
			domainScore = entry.score * 100 / entry.total
		}
		summaries = append(summaries, HardeningDomain{
			ID: id, Title: hardeningDomainTitle(id), Score: domainScore,
			Protected: entry.protected, Total: entry.count,
		})
	}
	return HardeningPosture{CollectedAt: now, Score: score, Level: level, Checks: checks, Domains: summaries}
}

func hardeningDomainTitle(id string) string {
	switch id {
	case "kernel":
		return "Kernel"
	case "application-control":
		return "Application Control"
	case "encryption":
		return "Encryption & Storage"
	case "boot":
		return "Boot Trust"
	case "network":
		return "Network"
	case "filesystem":
		return "Filesystem"
	case "integrity":
		return "Integrity & Evidence"
	default:
		return id
	}
}
