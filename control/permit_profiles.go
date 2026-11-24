package main

import (
	"path/filepath"
	"strings"
	"time"
)

const (
	permitExecutableHashCacheSize = 256
	permitExecutableHashCacheTTL  = 5 * time.Minute
	permitMaxExecutableHashBytes  = 512 << 20
)

// permitProfile is one built-in, in-memory TOLERATED profile. Built-ins are not
// persisted and carry no signature; they are TOLERATED by construction and can
// only explain findings inside their explicit scope.
type permitProfile struct {
	PermitID     string
	TrustLevel   string
	Names        []string
	NamePrefixes []string
	Reason       string
	Scope        PermitScope
}

// permitScopeRules is the common dev/build rule scope. It names the
// false-positive classes a development toolchain genuinely produces (temporary
// build directories, baseline parent/uid deviations, behavior warm-up) and
// deliberately excludes every kernel-proven or credential rule.
var permitScopeRules = []string{
	"XDR.TEMP_EXEC",
	"XDR.NAME_PATH_MISMATCH",
	"BASELINE.PARENT_MISMATCH",
	"BASELINE.UID_MISMATCH",
	"XDR.ANOMALY.EXEC_BURST",
	"XDR.ANOMALY.CONNECTION_FANOUT",
	"XDR.ANOMALY.REMOTE_DIVERSITY",
	"XDR.ANOMALY.PORT_DIVERSITY",
}

var permitScopeRulesSecurity = []string{
	"XDR.TEMP_EXEC",
	"XDR.NAME_PATH_MISMATCH",
	"BASELINE.PARENT_MISMATCH",
	"BASELINE.UID_MISMATCH",
	"XDR.ANOMALY.EXEC_BURST",
	"XDR.ANOMALY.CONNECTION_FANOUT",
	"XDR.ANOMALY.REMOTE_DIVERSITY",
	"XDR.ANOMALY.PORT_DIVERSITY",
	"KD.LINUX.BPF_LOAD",
}

// builtinPermitProfiles seeds the broker at construction. Every profile is
// auditable: the PermitDecision carries its stable profile ID and reason.
func builtinPermitProfiles() []permitProfile {
	dev := permitProfile{
		PermitID:   "PERMIT.PROFILE.DEV_TOOLCHAIN",
		TrustLevel: permitTrustTolerated,
		Names:      []string{"cargo", "rustc", "go", "gcc", "cc", "make", "npm", "node", "pytest", "python3", "python"},
		Reason:     "development toolchain profile: build/test/package work in temporary trees and non-baseline parents",
		Scope: PermitScope{
			Rules:        append([]string(nil), permitScopeRules...),
			PathPrefixes: []string{"/usr", "/opt", "/home", "/root", "/tmp", "/var/tmp"},
		},
	}
	container := permitProfile{
		PermitID:   "PERMIT.PROFILE.CONTAINER_RUNTIME",
		TrustLevel: permitTrustTolerated,
		Names:      []string{"runc", "containerd", "containerd-shim", "dockerd", "podman", "podman-runc"},
		Reason:     "container runtime profile: shim/runtime processes appear in temporary and non-baseline lineages",
		Scope: PermitScope{
			Rules:        append([]string(nil), permitScopeRules...),
			PathPrefixes: []string{"/usr", "/opt", "/home", "/root", "/tmp", "/var/tmp"},
		},
	}
	security := permitProfile{
		PermitID:   "PERMIT.PROFILE.SECURITY_OBSERVABILITY",
		TrustLevel: permitTrustTolerated,
		Names:      []string{"bpftrace", "perf", "cilium", "cilium-agent", "falco", "tetragon", "tcpdump", "dumpcap", "gdb"},
		Reason:     "security/observability profile: tracing, capture and debugging tools legitimately load BPF and inspect processes",
		Scope: PermitScope{
			Rules:        append([]string(nil), permitScopeRulesSecurity...),
			PathPrefixes: []string{"/usr", "/opt", "/home", "/root"},
		},
	}
	web := permitProfile{
		PermitID:     "PERMIT.PROFILE.WEB_SERVICE_POOL",
		TrustLevel:   permitTrustTolerated,
		Names:        []string{"nginx", "mariadbd", "mysqld", "postgres", "redis-server"},
		NamePrefixes: []string{"php-fpm"},
		Reason:       "web service pool profile: long-running service workers show baseline and warm-up deviations",
		// The web pool scope deliberately carries no kill-eligible rule: a
		// service pool may explain warm-up/baseline noise, never a process-tree
		// execution finding.
		Scope: PermitScope{
			Rules: []string{
				"XDR.NAME_PATH_MISMATCH",
				"BASELINE.UID_MISMATCH",
				"XDR.ANOMALY.EXEC_BURST",
				"XDR.ANOMALY.CONNECTION_FANOUT",
				"XDR.ANOMALY.REMOTE_DIVERSITY",
				"XDR.ANOMALY.PORT_DIVERSITY",
			},
			PathPrefixes: []string{"/usr", "/opt", "/srv"},
		},
	}
	return []permitProfile{dev, container, security, web}
}

// nonSuppressibleRule reports whether a rule is kernel-proven/integrity evidence
// that no permit may ever explain away.
func nonSuppressibleRule(ruleID string) bool {
	if _, ok := nonSuppressibleRuleIDs[ruleID]; ok {
		return true
	}
	for _, prefix := range nonSuppressibleRulePrefixes {
		if strings.HasPrefix(ruleID, prefix) {
			return true
		}
	}
	return false
}

// permitRulePatternMatches supports exact IDs plus the documented prefix forms
// ("XDR.ANOMALY." and "MALWARE.*").
func permitRulePatternMatches(pattern, ruleID string) bool {
	if pattern == ruleID {
		return true
	}
	if strings.HasSuffix(pattern, ".") && strings.HasPrefix(ruleID, pattern) {
		return true
	}
	if strings.HasSuffix(pattern, "*") && strings.HasPrefix(ruleID, strings.TrimSuffix(pattern, "*")) {
		return true
	}
	return false
}

// permitParentMatches applies the bounded parent lineage. An empty lineage
// means "no parent constraint"; a non-empty one must match the observed parent
// by absolute path or by basename.
func permitParentMatches(parents []string, parentExe string) bool {
	if len(parents) == 0 {
		return true
	}
	cleanParent := cleanPermitExecutablePath(parentExe)
	if cleanParent == "" {
		return false
	}
	parentBase := filepath.Base(cleanParent)
	for _, expected := range parents {
		cleanExpected := cleanPermitExecutablePath(expected)
		if cleanExpected == "" {
			continue
		}
		if filepath.IsAbs(cleanExpected) {
			if cleanExpected == cleanParent {
				return true
			}
			continue
		}
		if strings.EqualFold(cleanExpected, parentBase) {
			return true
		}
	}
	return false
}

// permitProfileNamesMatch matches an executable basename (preferred) or, only
// when no absolute executable path is known, the comm. The comm is spoofable
// via prctl(PR_SET_NAME); accepting it when a real path is present would turn a
// dev-tool profile into a masquerading bypass.
func permitProfileNamesMatch(profile permitProfile, p ProcessSample) bool {
	exe := cleanPermitExecutablePath(p.Exe)
	var candidates []string
	if filepath.IsAbs(exe) {
		candidates = append(candidates, filepath.Base(exe))
	} else if p.Comm != "" {
		candidates = append(candidates, p.Comm)
	}
	if len(candidates) == 0 {
		return false
	}
	for _, candidate := range candidates {
		for _, name := range profile.Names {
			if strings.EqualFold(candidate, name) {
				return true
			}
		}
		for _, prefix := range profile.NamePrefixes {
			if prefix != "" && strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(prefix)) {
				return true
			}
		}
	}
	return false
}

// matchBuiltinProfile applies one TOLERATED profile.
func matchBuiltinProfile(p ProcessSample, ruleIDs, categories []string, profile permitProfile) (*PermitDecision, bool) {
	if !permitProfileNamesMatch(profile, p) {
		return nil, false
	}
	exe := cleanPermitExecutablePath(p.Exe)
	if !permitScopeCovers(profile.Scope, exe, ruleIDs, categories) {
		return nil, false
	}
	trustLevel := profile.TrustLevel
	if trustLevel == "" {
		trustLevel = permitTrustTolerated
	}
	return &PermitDecision{
		PermitID:   profile.PermitID,
		TrustLevel: trustLevel,
		Scope:      stringListSummary(profile.Scope.Rules, 4),
		Reason:     profile.Reason,
	}, true
}

// boundedPermitText trims a value to a printable, bounded field.
func boundedPermitText(value string, max int) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	if max > 0 && len(value) > max {
		value = value[:max] + "…"
	}
	return value
}
