package lpeguard

import (
	"sort"
	"strings"
)

// HardeningCheck is one published baseline row. It reports what the host
// actually shows and, when the operator policy names it enforceable, the exact
// apply/rollback plan. `enforceable` never means "already applied".
type HardeningCheck struct {
	Key         string `json:"key"`
	Expected    string `json:"expected"`
	Actual      string `json:"actual"`
	State       string `json:"state"`
	Enforceable bool   `json:"enforceable"`
	// Apply/Rollback are concrete plans for the existing hardening transaction
	// path; they are text, never an executed command.
	Apply    string `json:"apply,omitempty"`
	Rollback string `json:"rollback,omitempty"`
}

// Hardening setting switches.
type HardeningSettings struct {
	EnforceASLR     bool
	BlockLPEModules bool
}

// HostFacts is the read-only host baseline collected per platform.
type HostFacts struct {
	// ASLR is the raw kernel.randomize_va_space value.
	ASLR string
	// Modules maps a module name to whether it is currently loaded.
	Modules map[string]bool
	// Modprobe is the bounded /etc/modprobe.d content (already concatenated).
	Modprobe string
}

// lpeModules are the network families the kernel should not offer on a host that
// does not need them. They are the classic local-privilege-escalation carriers
// in the kernel network stack.
var lpeModules = []string{"sctp", "dccp", "rds"}

// EvaluateHardening renders the baseline rows. The caller never applies them
// implicitly; `enforce_aslr`/`block_lpe_modules` decide whether a concrete
// apply/rollback plan is attached.
func EvaluateHardening(facts HostFacts, settings HardeningSettings) []HardeningCheck {
	checks := make([]HardeningCheck, 0, 1+len(lpeModules))
	checks = append(checks, evaluateASLR(facts.ASLR, settings.EnforceASLR))
	if settings.BlockLPEModules {
		for _, module := range lpeModules {
			checks = append(checks, evaluateModule(module, facts))
		}
	}
	return checks
}

// evaluateASLR reports the kernel address-space randomization state.
func evaluateASLR(actual string, enforceable bool) HardeningCheck {
	actual = strings.TrimSpace(actual)
	check := HardeningCheck{
		Key:      "kernel.randomize_va_space",
		Expected: "2",
		Actual:   actual,
		State:    "fail",
	}
	switch actual {
	case "2":
		check.State = "pass"
	case "":
		check.Actual = "unreadable"
		check.State = "unavailable"
	case "0":
		check.State = "fail"
	default:
		check.State = "fail"
	}
	if enforceable {
		check.Enforceable = true
		check.Apply = "hardening sysctl transaction: control kernel.aslr sets kernel.randomize_va_space from " +
			valueOrUnknown(actual) + " to 2 (SysctlCompareSet, rollback restores the captured value)"
		check.Rollback = "reverse the sysctl transaction; the captured pre-state value is restored"
	} else {
		check.Apply = "not enforceable: enforce_aslr is disabled in the lpe_guard settings"
		check.Rollback = ""
	}
	return check
}

// valueOrUnknown renders an empty observed value explicitly.
func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

// evaluateModule reports whether a network module is blocked.
func evaluateModule(module string, facts HostFacts) HardeningCheck {
	loaded := facts.Modules[module]
	blacklisted := moduleBlockedInModprobe(facts.Modprobe, module)
	check := HardeningCheck{
		Key:         "module." + module,
		Expected:    "blocked",
		Enforceable: true,
		Apply: "write 'blacklist " + module + "' and 'install " + module + " /bin/false' into " +
			"/etc/modprobe.d/gedefense-lpe.conf, then unload the module through the platform package manager",
		Rollback: "remove the " + module + " lines from /etc/modprobe.d/gedefense-lpe.conf and reload the module if the operator needs it",
	}
	switch {
	case loaded:
		check.Actual = "loaded"
		check.State = "fail"
	case blacklisted:
		check.Actual = "blocked"
		check.State = "pass"
	default:
		check.Actual = "not-loaded"
		check.State = "watch"
	}
	return check
}

// moduleBlockedInModprobe scans the concatenated modprobe.d content for a
// blacklist/install-false rule. Comments are ignored.
func moduleBlockedInModprobe(content, module string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "blacklist", "install":
			if strings.EqualFold(fields[1], module) {
				return true
			}
		}
	}
	return false
}

// SortedModuleNames returns the LPE module names in stable order (tests and the
// published plan use it).
func SortedModuleNames() []string {
	out := append([]string(nil), lpeModules...)
	sort.Strings(out)
	return out
}
