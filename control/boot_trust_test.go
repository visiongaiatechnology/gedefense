// STATUS: DIAMANT VGT SUPREME

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBootTrustCollectsGaiaOSEvidenceWithoutLeakingCmdline(t *testing.T) {
	root := t.TempDir()
	writeBootTestFile(t, root, "/etc/os-release", "ID=gaiaos\nNAME=\"GaiaOS\"\nVERSION_ID=\"0.1\"\n")
	writeBootTestFile(t, root, "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", string([]byte{7, 0, 0, 0, 1}))
	writeBootTestFile(t, root, "/sys/kernel/security/lockdown", "none integrity [confidentiality]\n")
	writeBootTestFile(t, root, "/proc/cmdline", "root=UUID=123 rd.luks.key=supersecret init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on module.sig_enforce=1\n")
	writeBootTestFile(t, root, "/proc/sys/kernel/osrelease", "6.12.1-gaia\n")
	writeBootTestFile(t, root, "/sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")
	writeBootTestFile(t, root, "/boot/vmlinuz-linux-hardened", "signed-kernel-image")
	if err := os.MkdirAll(filepath.Join(root, "sys", "class", "tpm", "tpm0"), 0o700); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	collector := newBootTrustCollectorForTest(root, true, func() time.Time { return now })
	report := collector.Collect()
	if !report.GaiaOS || report.DistroID != "gaiaos" || report.ClaimLevel != "evidence-only" {
		t.Fatalf("unexpected report identity: %+v", report)
	}
	if got := bootEvidenceState(report, "secure-boot"); got != bootStateEnabled {
		t.Fatalf("secure boot state=%s", got)
	}
	if got := bootEvidenceState(report, "kernel-lockdown"); got != bootStateEnabled {
		t.Fatalf("lockdown state=%s", got)
	}
	if got := bootEvidenceState(report, "cgroup-v2"); got != bootStateObserved {
		t.Fatalf("cgroup state=%s", got)
	}
	if got := bootEvidenceState(report, "gaia-cells"); got != bootStateNotAvailable {
		t.Fatalf("Gaia Cells must not be inferred from unrelated host state: %s", got)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "supersecret") || strings.Contains(string(encoded), "rd.luks.key") {
		t.Fatal("raw kernel command line leaked into report")
	}
	cmdline := bootEvidence(report, "kernel-cmdline")
	if cmdline.Digest == "" || !strings.Contains(cmdline.Evidence, "module.sig_enforce=1") {
		t.Fatalf("cmdline evidence incomplete: %+v", cmdline)
	}
}

func TestBootTrustCacheReturnsDefensiveCopy(t *testing.T) {
	root := t.TempDir()
	writeBootTestFile(t, root, "/etc/os-release", "ID=gaiaos\n")
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	collector := newBootTrustCollectorForTest(root, true, func() time.Time { return now })
	first := collector.Collect()
	first.Items[0].Summary = "tampered by caller"
	second := collector.Collect()
	if second.Items[0].Summary == "tampered by caller" {
		t.Fatal("cached report alias exposed mutable internal state")
	}
	if !second.GeneratedAt.Equal(now) {
		t.Fatalf("unexpected cached timestamp: %s", second.GeneratedAt)
	}
}

func TestBootTrustRejectsSymlinkEvidence(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("ID=gaiaos\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "etc", "os-release")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	if report.GaiaOS || report.DistroID != "" {
		t.Fatalf("symlink evidence must be rejected: %+v", report)
	}
}

func writeBootTestFile(t *testing.T, root, unixPath, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(unixPath, "/")))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bootEvidence(report BootTrustReport, id string) BootTrustEvidence {
	for _, item := range report.Items {
		if item.ID == id {
			return item
		}
	}
	return BootTrustEvidence{}
}

func bootEvidenceState(report BootTrustReport, id string) string {
	return bootEvidence(report, id).State
}
