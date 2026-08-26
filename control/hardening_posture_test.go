// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHardeningPostureMeasuresLocalControlsWithoutLeakingBootSecrets(t *testing.T) {
	root := t.TempDir()
	values := map[string]string{
		"proc/sys/kernel/osrelease":                       "6.12.1-hardened1-1-hardened\n",
		"proc/sys/kernel/randomize_va_space":              "2\n",
		"proc/sys/kernel/kptr_restrict":                   "2\n",
		"proc/sys/kernel/dmesg_restrict":                  "1\n",
		"proc/sys/kernel/yama/ptrace_scope":               "2\n",
		"proc/sys/kernel/unprivileged_bpf_disabled":       "1\n",
		"proc/sys/kernel/module_sig_enforce":              "1\n",
		"proc/sys/fs/protected_fifos":                     "2\n",
		"proc/sys/fs/protected_regular":                   "2\n",
		"proc/sys/fs/suid_dumpable":                       "0\n",
		"proc/sys/net/ipv4/tcp_syncookies":                "1\n",
		"proc/sys/net/ipv4/conf/all/accept_redirects":     "0\n",
		"proc/sys/net/ipv4/conf/default/accept_redirects": "0\n",
		"proc/sys/net/ipv4/conf/all/send_redirects":       "0\n",
		"proc/sys/net/ipv4/conf/default/send_redirects":   "0\n",
		"proc/sys/net/ipv6/conf/all/accept_redirects":     "0\n",
		"proc/sys/net/ipv6/conf/default/accept_redirects": "0\n",
		"proc/cmdline":                           "root=/dev/mapper/cryptroot quiet secret=must-not-leak\n",
		"proc/self/mounts":                       "/dev/mapper/cryptroot / btrfs rw 0 0\n",
		"sys/module/apparmor/parameters/enabled": "Y\n",
		"sys/kernel/security/apparmor/profiles":  "gedefense (enforce)\nfirefox (enforce)\n",
		"etc/nftables.conf":                      "table inet filter { chain input { type filter hook input priority 0; policy drop; } }\n",
	}
	for relative, value := range values {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	collector := newHardeningCollectorForTest(root, func() time.Time { return now })
	snapshot := Snapshot{
		FIM:      FIMStatus{Enabled: true, Health: "HEALTHY"},
		Evidence: EvidenceStatus{Enabled: true, Healthy: true},
	}
	boot := BootTrustReport{Items: []BootTrustEvidence{
		{ID: "secure-boot", State: bootStateEnabled, Summary: "enabled"},
		{ID: "kernel-lockdown", State: bootStateEnabled, Summary: "integrity"},
		{ID: "tpm", State: bootStateObserved, Summary: "TPM 2.0"},
	}}
	posture := collector.Collect(snapshot, boot)
	if posture.Score != 100 || posture.Level != "HARDENED" {
		t.Fatalf("unexpected posture: score=%d level=%s", posture.Score, posture.Level)
	}
	if posture.CollectedAt != now || len(posture.Checks) < 20 || len(posture.Domains) != 7 {
		t.Fatalf("incomplete posture: %#v", posture)
	}
	for _, check := range posture.Checks {
		if strings.Contains(check.Evidence, "must-not-leak") {
			t.Fatal("kernel command line secret leaked into posture evidence")
		}
	}
}

func TestHardeningControlSelectionBuildsDeterministicAllowlistedProfile(t *testing.T) {
	profile, err := decodeSysctlProfileRequest(
		[]byte(`{"controls":["network.syn-cookies","kernel.aslr","kernel.kptr"]}`),
		NewSysctlTransactionApplier(nil).profiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "astraeaos-custom-0083" {
		t.Fatalf("unexpected deterministic profile name: %s", profile.Name)
	}
	if len(profile.Values) != 3 || profile.Values["kernel.randomize_va_space"] != "2" ||
		profile.Values["kernel.kptr_restrict"] != "2" || profile.Values["net.ipv4.tcp_syncookies"] != "1" {
		t.Fatalf("unexpected control plan: %#v", profile.Values)
	}
	for _, invalid := range []string{
		`{"controls":[]}`,
		`{"controls":["kernel.aslr","kernel.aslr"]}`,
		`{"controls":["kernel.not-allowlisted"]}`,
		`{"profile":"linux-server-balanced","controls":["kernel.aslr"]}`,
	} {
		if _, err := decodeSysctlProfileRequest([]byte(invalid), NewSysctlTransactionApplier(nil).profiles); err == nil {
			t.Fatalf("invalid hardening selection accepted: %s", invalid)
		}
	}
}

func TestHardeningPostureRefusesSymlinkEvidence(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "value")
	if err := os.WriteFile(target, []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "proc/sys/kernel/randomize_va_space")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	collector := newHardeningCollectorForTest(root, time.Now)
	check := collector.integerCheck(
		"kernel.aslr", "kernel", "ASLR", "proc/sys/kernel/randomize_va_space",
		2, 10, true, "enable",
	)
	if check.State != hardeningStateUnavailable {
		t.Fatalf("symlink evidence was trusted: %#v", check)
	}
}
