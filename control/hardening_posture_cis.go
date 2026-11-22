// STATUS: DIAMANT VGT SUPREME
package main

// M5.1: CIS/Lynis Level-1 posture checks.
//
// The sysctl transaction engine applies the managed kernel switches; this file
// makes the extended catalogue measurable and adds read-only posture checks for
// the userland hardening that is provisioned by packaging/scripts/
// gedefense-provision (SSHD drop-in, login.defs UMASK, legal banner, modprobe
// blacklist, auditd rules). Nothing here changes a file: the checks only report
// what is present, so an operator can see the gap before opting into the
// provisioning profile. A host without sshd/auditd reports UNAVAILABLE instead
// of a fake pass.

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// --------------------------------------------------------------- sysctls

// cisSysctlMinimumCheck measures a paired "at least N" sysctl pair.
func (c *HardeningCollector) cisSysctlMinimumCheck(id, domain, title, first, second string, minimum, weight int, recommendation string) HardeningCheck {
	return c.pairedMinimumCheck(id, domain, title, first, second, minimum, weight, recommendation)
}

// swappinessCheck measures "vm.swappiness at most 10". numericCheck only knows
// exact and minimum comparisons; a swap-heavy server may legitimately run a
// higher value, so the check reports PARTIAL instead of UNPROTECTED above 10.
func (c *HardeningCollector) swappinessCheck() HardeningCheck {
	check := baseHardeningCheck("memory.swappiness", "kernel", "Swap aggressiveness", 3, true)
	raw, err := c.regularText("proc/sys/vm/swappiness", 64)
	if err != nil {
		return unavailableHardening(check)
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return unavailableHardening(check)
	}
	check.Evidence = "live value=" + strconv.Itoa(value)
	if value <= 10 {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStatePartial
	check.Recommendation = "Set vm.swappiness=10 (CIS L1) unless the host has a deliberate swap workload."
	return check
}

// ipv6DisableCheck reports the context-dependent IPv6 switch. It never claims
// "protected" merely because IPv6 exists: the recommendation is explicit, and a
// host with IPv6 enabled is reported PARTIAL so the operator decides.
func (c *HardeningCollector) ipv6DisableCheck() HardeningCheck {
	check := baseHardeningCheck("network.ipv6-disable", "network", "IPv6 disabled (context-dependent)", 3, false)
	allRaw, allErr := c.regularText("proc/sys/net/ipv6/conf/all/disable_ipv6", 64)
	defaultRaw, defaultErr := c.regularText("proc/sys/net/ipv6/conf/default/disable_ipv6", 64)
	if allErr != nil || defaultErr != nil {
		return unavailableHardening(check)
	}
	check.Evidence = "live values=" + allRaw + "," + defaultRaw
	if allRaw == "1" && defaultRaw == "1" {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStatePartial
	check.Recommendation = "Only disable IPv6 where the host does not use it; select network.ipv6-disable explicitly, never by default."
	return check
}

// cisSysctlChecks returns the extended M5.1 sysctl posture checks.
func (c *HardeningCollector) cisSysctlChecks() []HardeningCheck {
	return []HardeningCheck{
		c.cisSysctlMinimumCheck("network.rp-filter", "network", "Reverse-path filter", "proc/sys/net/ipv4/conf/all/rp_filter", "proc/sys/net/ipv4/conf/default/rp_filter", 1, 6, "Enable net.ipv4.conf.all.rp_filter=1 and default.rp_filter=1."),
		c.cisSysctlMinimumCheck("network.log-martians", "network", "Martian packet logging", "proc/sys/net/ipv4/conf/all/log_martians", "proc/sys/net/ipv4/conf/default/log_martians", 1, 4, "Enable net.ipv4.conf.all.log_martians=1."),
		c.cisSysctlMinimumCheck("network.icmp-hardening", "network", "ICMP broadcast hardening", "proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "proc/sys/net/ipv4/icmp_ignore_bogus_error_responses", 1, 4, "Ignore ICMP broadcast echo and bogus ICMP error responses."),
		c.integerCheck("filesystem.protected-hardlinks", "filesystem", "Protected hardlinks", "proc/sys/fs/protected_hardlinks", 1, 5, true, "Set fs.protected_hardlinks=1."),
		c.integerCheck("filesystem.protected-symlinks", "filesystem", "Protected symlinks", "proc/sys/fs/protected_symlinks", 1, 5, true, "Set fs.protected_symlinks=1."),
		c.integerCheck("kernel.sysrq", "kernel", "Magic SysRq restricted", "proc/sys/kernel/sysrq", 0, 5, true, "Set kernel.sysrq=0."),
		c.minimumCheck("kernel.perf-event", "kernel", "perf_event restricted", "proc/sys/kernel/perf_event_paranoid", 3, 6, true, "Set kernel.perf_event_paranoid=3."),
		c.integerCheck("kernel.tty-ldisc", "kernel", "TTY line-discipline autoload", "proc/sys/dev/tty/ldisc_autoload", 0, 4, true, "Set dev.tty.ldisc_autoload=0."),
		c.swappinessCheck(),
		c.ipv6DisableCheck(),
	}
}

// ---------------------------------------------------------------- userland

// sshdBaselineDirective is one expected directive of the CIS Level-1 SSH
// drop-in. max/min are inclusive bounds; when both are zero the directive must
// match exact (case-insensitive).
type sshdBaselineDirective struct {
	Directive string
	Exact     string
	Max       int
	Min       int
}

var sshdBaselineDirectives = []sshdBaselineDirective{
	{Directive: "maxauthtries", Max: 3},
	{Directive: "allowtcpforwarding", Exact: "no"},
	{Directive: "x11forwarding", Exact: "no"},
	{Directive: "clientalivecountmax", Max: 2},
	{Directive: "loglevel", Exact: "VERBOSE"},
}

// sshdBaselineCheck reads the main sshd_config plus the bounded drop-in set and
// evaluates the effective values. It is a posture fact only: enabling the
// profile happens through gedefense-provision --cis-baseline.
func (c *HardeningCollector) sshdBaselineCheck() HardeningCheck {
	check := baseHardeningCheck("web.sshd-baseline", "network", "SSHD CIS baseline", 7, false)
	files := []string{"etc/ssh/sshd_config"}
	if entries, err := os.ReadDir(c.path("etc/ssh/sshd_config.d")); err == nil {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		if len(names) > 16 {
			names = names[:16]
		}
		for _, name := range names {
			files = append(files, "etc/ssh/sshd_config.d/"+name)
		}
	}
	effective := map[string]string{}
	readable := false
	for _, file := range files {
		raw, err := c.regularText(file, 256<<10)
		if err != nil {
			continue
		}
		readable = true
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			effective[strings.ToLower(fields[0])] = strings.TrimSpace(strings.Join(fields[1:], " "))
		}
	}
	if !readable {
		return unavailableHardening(check)
	}
	satisfied, total := 0, len(sshdBaselineDirectives)
	missing := make([]string, 0, total)
	for _, directive := range sshdBaselineDirectives {
		value, present := effective[directive.Directive]
		if !present {
			missing = append(missing, directive.Directive)
			continue
		}
		ok := false
		switch {
		case directive.Exact != "":
			ok = strings.EqualFold(value, directive.Exact)
		default:
			number, err := strconv.Atoi(value)
			ok = err == nil && number <= directive.Max && (directive.Min == 0 || number >= directive.Min)
		}
		if ok {
			satisfied++
		} else {
			missing = append(missing, directive.Directive+"="+value)
		}
	}
	check.Evidence = fmt.Sprintf("%d/%d CIS directives satisfied", satisfied, total)
	switch {
	case satisfied == total:
		check.State = hardeningStateProtected
	case satisfied == 0:
		check.State = hardeningStateUnprotected
	default:
		check.State = hardeningStatePartial
	}
	if satisfied != total {
		check.Recommendation = "Apply the opt-in CIS baseline: gedefense-provision --cis-baseline (missing: " + strings.Join(missing, ", ") + ")."
	}
	return check
}

// umaskCheck reads the login.defs UMASK and accepts 027 or stricter.
func (c *HardeningCollector) umaskCheck() HardeningCheck {
	check := baseHardeningCheck("web.login-umask", "application-control", "Login UMASK", 5, false)
	raw, err := c.regularText("etc/login.defs", 256<<10)
	if err != nil {
		return unavailableHardening(check)
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.ToUpper(fields[0]) != "UMASK" {
			continue
		}
		mode, err := strconv.ParseUint(fields[1], 8, 32)
		if err != nil {
			return unavailableHardening(check)
		}
		check.Evidence = "UMASK " + fields[1]
		if mode&0o027 == 0o027 || mode <= 0o027 {
			check.State = hardeningStateProtected
			return check
		}
		check.State = hardeningStatePartial
		check.Recommendation = "Set UMASK 027 in /etc/login.defs."
		return check
	}
	check.State = hardeningStateUnprotected
	check.Evidence = "no UMASK directive"
	check.Recommendation = "Set UMASK 027 in /etc/login.defs."
	return check
}

// bannerCheck requires a legal-warning banner in issue/issue.net.
func (c *HardeningCollector) bannerCheck() HardeningCheck {
	check := baseHardeningCheck("web.legal-banner", "application-control", "Legal login banner", 3, false)
	readable, legal := 0, false
	for _, file := range []string{"etc/issue", "etc/issue.net"} {
		raw, err := c.regularText(file, 8<<10)
		if err != nil {
			continue
		}
		readable++
		lower := strings.ToLower(raw)
		if strings.Contains(lower, "authori") || strings.Contains(lower, "unauthor") || strings.Contains(lower, "zugriff") {
			legal = true
		}
	}
	if readable == 0 {
		return unavailableHardening(check)
	}
	if legal {
		check.Evidence = "legal warning present"
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStatePartial
	check.Evidence = "banner exists without a legal warning"
	check.Recommendation = "Install the GEDEFENSE legal banner (gedefense-provision --cis-baseline)."
	return check
}

// auditdBaselineCheck verifies that a managed baseline audit rule file is
// present. It never reloads auditd; the provisioning script only writes rules.
func (c *HardeningCollector) auditdBaselineCheck() HardeningCheck {
	check := baseHardeningCheck("integrity.audit-baseline", "integrity", "Auditd baseline rules", 6, false)
	raw, err := c.regularText("etc/audit/rules.d/gedefense.rules", 256<<10)
	if err != nil {
		// A host without auditd has no rules directory; do not pretend it failed.
		if _, dirErr := os.Stat(c.path("etc/audit/rules.d")); dirErr != nil {
			return unavailableHardening(check)
		}
		check.State = hardeningStateUnprotected
		check.Evidence = "no managed audit rule file"
		check.Recommendation = "Install the baseline audit rules (gedefense-provision --cis-baseline)."
		return check
	}
	rules := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rules++
	}
	check.Evidence = fmt.Sprintf("%d audit rule(s)", rules)
	if rules >= 3 {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStatePartial
	check.Recommendation = "Install the full baseline audit rule set (gedefense-provision --cis-baseline)."
	return check
}

// modprobeBlacklistCheck verifies the managed module blacklist.
func (c *HardeningCollector) modprobeBlacklistCheck() HardeningCheck {
	check := baseHardeningCheck("kernel.module-blacklist", "kernel", "Unused filesystem/module blacklist", 5, false)
	raw, err := c.regularText("etc/modprobe.d/gedefense-blacklist.conf", 64<<10)
	if err != nil {
		if _, dirErr := os.Stat(c.path("etc/modprobe.d")); dirErr != nil {
			return unavailableHardening(check)
		}
		check.State = hardeningStateUnprotected
		check.Evidence = "no managed blacklist"
		check.Recommendation = "Install the module blacklist (gedefense-provision --cis-baseline)."
		return check
	}
	lower := strings.ToLower(raw)
	blocked := 0
	for _, module := range []string{"dccp", "sctp", "rds", "tipc", "cramfs", "usb-storage"} {
		needle := "install " + module + " /bin/true"
		if strings.Contains(lower, needle) || strings.Contains(lower, "blacklist "+module) {
			blocked++
		}
	}
	check.Evidence = fmt.Sprintf("%d/6 modules blocked", blocked)
	if blocked == 6 {
		check.State = hardeningStateProtected
		return check
	}
	check.State = hardeningStatePartial
	check.Recommendation = "Complete the module blacklist (dccp, sctp, rds, tipc, cramfs, usb-storage)."
	return check
}
