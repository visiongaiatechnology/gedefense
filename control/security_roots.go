// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"sort"
	"strings"
)

// The protection roots of the file-integrity monitor.
//
// The monitor used to watch only the platform's own six files. That is the right scope for
// self-protection and the wrong scope for an attack: a web shell is dropped into a web root, and
// anti-forensics deletes or truncates logs. Neither is one of our files, so neither was a finding.
//
// This list is the environment around the platform. It is a candidate list, not a configuration:
// only paths that exist on this host are taken, the result is bounded, sorted and free of
// duplicates, and the operator sees exactly what was added in the journal. The one-time acceptance
// of the resulting baseline stays a human decision - adding roots automatically must not silently
// bless the files that are already there.
var securityProtectionRootCandidates = []string{
	// Web and application surfaces: where a dropped web shell lands.
	"/var/www",
	"/srv/www",
	"/usr/share/nginx/html",
	"/opt/beyondtrust",
	// Persistence: where an attacker makes themselves at home.
	"/etc/systemd/system",
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/ld.so.preload",
	"/root/.ssh",
	// Anti-forensics: the SSH configuration is monitored. /var/log and
	// /var/log/journal are deliberately not part of the byte-hash baseline: normal
	// log growth would make every subsequent scan look "TAMPERED" and turn a
	// healthy host into a permanent false positive. Log truncation, deletion and
	// anti-forensic commands remain covered by the separate KD.LINUX.LOG_TAMPER
	// detection rules, not by the file-integrity baseline.
	// The directory /etc/ssh is deliberately not listed either: it contains
	// root-only host private keys that the unprivileged control service cannot
	// read, and granting it read access would expose those keys.
	"/etc/ssh/sshd_config",
	"/etc/passwd",
	"/etc/sudoers.d",
}

const securityProtectionRootLimit = 16

// securityProtectionRoots merges the configured roots with the security-relevant paths that exist.
//
// It never removes a configured root, never invents a path, and stays inside a hard limit so a
// single setting cannot turn the scan into a filesystem walk.
func securityProtectionRoots(configured []string, includeSecurityRoots bool, limit int) ([]string, []string) {
	if limit <= 0 {
		limit = securityProtectionRootLimit
	}
	seen := make(map[string]struct{}, len(configured)+len(securityProtectionRootCandidates))
	roots := make([]string, 0, len(configured)+len(securityProtectionRootCandidates))
	for _, path := range configured {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		roots = append(roots, trimmed)
	}
	if !includeSecurityRoots {
		return roots, nil
	}
	added := make([]string, 0, len(securityProtectionRootCandidates))
	for _, candidate := range securityProtectionRootCandidates {
		if len(roots) >= limit {
			break
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		if !pathExists(candidate) {
			// A path that is not on this host would only produce "missing" findings for ever.
			continue
		}
		seen[candidate] = struct{}{}
		roots = append(roots, candidate)
		added = append(added, candidate)
	}
	sort.Strings(added)
	return roots, added
}

func pathExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info != nil
}
