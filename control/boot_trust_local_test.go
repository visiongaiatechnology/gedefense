// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the operator-signed local boot baseline used on hosts without UEFI
// Secure Boot or a TPM, and for the explicit NOT_SUPPORTED platform verdict.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const localBootTestCmdline = "quiet init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on module.sig_enforce=1\n"

func newLocalBootTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeBootTestFile(t, root, "/etc/os-release", "ID=ubuntu\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n")
	writeBootTestFile(t, root, "/proc/sys/kernel/osrelease", "7.0.0-38-generic\n")
	writeBootTestFile(t, root, "/proc/cmdline", localBootTestCmdline)
	writeBootTestFile(t, root, "/sys/kernel/security/lockdown", "[none] integrity confidentiality\n")
	writeBootTestFile(t, root, "/sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")
	writeBootTestFile(t, root, "/boot/vmlinuz-linux-hardened", "operator-signed-kernel-image")
	return root
}

// provisionLocalBootBaseline signs the operator document for the current fake
// boot artifacts and writes the pinned key, baseline and detached signature.
func provisionLocalBootBaseline(t *testing.T, root, kernel, cmdline, lockdown string) ed25519.PublicKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kernelDigest := sha256.Sum256([]byte(kernel))
	cmdlineDigest := sha256.Sum256([]byte(cmdline))
	baseline := localSignedBootBaseline{
		Schema: localBootBaselineSchema, CreatedAt: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
		KernelSHA256: hex.EncodeToString(kernelDigest[:]), KernelSource: "/boot/vmlinuz-linux-hardened",
		CmdlineSHA256: hex.EncodeToString(cmdlineDigest[:]), Lockdown: lockdown,
		Operator: "operator@visiongaia", Note: "local fallback for hosts without Secure Boot/TPM",
	}
	raw, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, raw)
	writeBootTestFile(t, root, localBootBaselinePath, string(raw))
	writeBootTestFile(t, root, localBootSignaturePath, hex.EncodeToString(signature)+"\n")
	writeBootTestFile(t, root, localBootPublicKeyPath, hex.EncodeToString(publicKey)+"\n")
	return publicKey
}

func TestBootTrustLocalBaselineVerifiesSignedBootArtifacts(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	root := newLocalBootTestRoot(t)

	unsupported := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	if unsupported.Status != bootTrustStatusNotSupported {
		t.Fatalf("host without firmware root of trust must report NOT_SUPPORTED, got %q", unsupported.Status)
	}
	if unsupported.HardwareRootOfTrust || unsupported.ClaimLevel != bootClaimEvidenceOnly {
		t.Fatalf("unexpected root-of-trust verdict: %+v", unsupported)
	}
	for _, reason := range []string{"no-uefi-secure-boot", "no-tpm", "no-astraeaos"} {
		found := false
		for _, got := range unsupported.NotSupportedReasons {
			if got == reason {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing platform fact %q in %+v", reason, unsupported.NotSupportedReasons)
		}
	}
	if before := bootEvidence(unsupported, "local-boot-baseline"); before.State != bootStateNotAvailable {
		t.Fatalf("a host without a provisioned baseline must report NOT_AVAILABLE, got %+v", before)
	}

	provisionLocalBootBaseline(t, root, "operator-signed-kernel-image", localBootTestCmdline, "none")
	verified := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	if verified.ClaimLevel != bootClaimLocalBaseline || verified.Status != bootTrustStatusVerified {
		t.Fatalf("signed local baseline not verified: claim=%s status=%s", verified.ClaimLevel, verified.Status)
	}
	item := bootEvidence(verified, "local-boot-baseline")
	if item.State != bootStateEnabled || item.Digest == "" {
		t.Fatalf("local baseline evidence incomplete: %+v", item)
	}
}

func TestBootTrustLocalBaselineRejectsTamperedBootArtifacts(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	root := newLocalBootTestRoot(t)
	provisionLocalBootBaseline(t, root, "operator-signed-kernel-image", localBootTestCmdline, "none")
	if err := os.WriteFile(filepath.Join(root, "boot", "vmlinuz-linux-hardened"), []byte("replaced-kernel-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	item := bootEvidence(report, "local-boot-baseline")
	if item.State != bootStateWarning {
		t.Fatalf("tampered kernel image must be a warning, got %+v", item)
	}
	if report.ClaimLevel != bootClaimEvidenceOnly {
		t.Fatalf("tampered boot artifacts must not raise the claim level: %s", report.ClaimLevel)
	}
	if report.Status != bootTrustStatusObserve {
		t.Fatalf("configured-but-mismatching baseline must stay visible as OBSERVE, got %s", report.Status)
	}
}

func TestBootTrustLocalBaselineRejectsInvalidSignature(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	root := newLocalBootTestRoot(t)
	provisionLocalBootBaseline(t, root, "operator-signed-kernel-image", localBootTestCmdline, "none")
	writeBootTestFile(t, root, localBootSignaturePath, hex.EncodeToString(make([]byte, ed25519.SignatureSize)))
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	if item := bootEvidence(report, "local-boot-baseline"); item.State != bootStateWarning {
		t.Fatalf("invalid signature must be a warning, got %+v", item)
	}
	if report.ClaimLevel != bootClaimEvidenceOnly || report.Status != bootTrustStatusObserve {
		t.Fatalf("invalid signature raised trust: claim=%s status=%s", report.ClaimLevel, report.Status)
	}
}

func TestBootTrustLocalBaselineAcceptsOpenSSHPublicKey(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	root := newLocalBootTestRoot(t)
	provisionLocalBootBaseline(t, root, "operator-signed-kernel-image", localBootTestCmdline, "none")
	// Rewrite the pinned key in the OpenSSH form an operator's ssh-keygen produces.
	publicRaw, err := os.ReadFile(filepath.Join(root, "etc", "vgt", "gedefense", "boot-baseline.ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := hex.DecodeString(string(publicRaw[:64]))
	if err != nil {
		t.Fatal(err)
	}
	// Wire format: uint32(len("ssh-ed25519")) type uint32(32) key material.
	blob := []byte{0, 0, 0, 11}
	blob = append(blob, []byte("ssh-ed25519")...)
	blob = append(blob, 0, 0, 0, 32)
	blob = append(blob, keyBytes...)
	sshLine := "ssh-ed25519 " + base64Of(blob) + " operator@visiongaia\n"
	writeBootTestFile(t, root, localBootPublicKeyPath, sshLine)
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	if item := bootEvidence(report, "local-boot-baseline"); item.State != bootStateEnabled {
		t.Fatalf("OpenSSH key form was not accepted: %+v", item)
	}
}

func base64Of(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var builder []byte
	for index := 0; index < len(data); index += 3 {
		var chunk [3]byte
		remaining := len(data) - index
		copy(chunk[:], data[index:])
		builder = append(builder, alphabet[chunk[0]>>2])
		builder = append(builder, alphabet[((chunk[0]&0x03)<<4)|(chunk[1]>>4)])
		if remaining > 1 {
			builder = append(builder, alphabet[((chunk[1]&0x0f)<<2)|(chunk[2]>>6)])
		} else {
			builder = append(builder, '=')
		}
		if remaining > 2 {
			builder = append(builder, alphabet[chunk[2]&0x3f])
		} else {
			builder = append(builder, '=')
		}
	}
	return string(builder)
}
