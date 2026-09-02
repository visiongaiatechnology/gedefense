// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlatformCaps_GenericUbuntu(t *testing.T) {
	tempDir := t.TempDir()
	etcDir := filepath.Join(tempDir, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatalf("failed to create temp etc: %v", err)
	}

	osRelease := `NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04 LTS"
VERSION_ID="24.04"
`
	if err := os.WriteFile(filepath.Join(etcDir, "os-release"), []byte(osRelease), 0644); err != nil {
		t.Fatalf("failed to write os-release: %v", err)
	}

	caps := DetectPlatformCapabilities(tempDir)
	if caps.OSID != "ubuntu" {
		t.Fatalf("expected OSID ubuntu, got %s", caps.OSID)
	}
	if caps.IsAstraeaOS {
		t.Fatal("expected IsAstraeaOS to be false for Ubuntu")
	}
	if caps.EnclaveMode != EnclaveGenericLinux {
		t.Fatalf("expected EnclaveGenericLinux, got %s", caps.EnclaveMode)
	}
	if err := caps.ValidatePlatformInvariants(); err != nil {
		t.Fatalf("invariants failed: %v", err)
	}
}

func TestPlatformCaps_AstraeaOSNative(t *testing.T) {
	tempDir := t.TempDir()
	etcDir := filepath.Join(tempDir, "etc")
	runGaia := filepath.Join(tempDir, "run", "gaia-cells")
	runAstraea := filepath.Join(tempDir, "run", "astraea")
	sysLSM := filepath.Join(tempDir, "sys", "kernel", "security")
	devDir := filepath.Join(tempDir, "dev")

	for _, d := range []string{etcDir, runGaia, runAstraea, sysLSM, devDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
	}

	osRelease := `NAME="AstraeaOS"
ID=astraeaos
VERSION_ID="1.0.0-beta.1"
PRETTY_NAME="AstraeaOS 1.0 Foundation"
`
	_ = os.WriteFile(filepath.Join(etcDir, "os-release"), []byte(osRelease), 0644)
	_ = os.WriteFile(filepath.Join(runGaia, "gaia-cells.sock"), []byte("mock-socket"), 0600)
	_ = os.WriteFile(filepath.Join(runAstraea, "key-broker.sock"), []byte("mock-socket"), 0600)
	_ = os.WriteFile(filepath.Join(sysLSM, "lsm"), []byte("lockdown,capability,landlock,apparmor,bpf"), 0444)
	_ = os.WriteFile(filepath.Join(devDir, "tpmrm0"), []byte("mock-tpm"), 0660)

	caps := DetectPlatformCapabilities(tempDir)
	if caps.OSID != "astraeaos" {
		t.Fatalf("expected OSID astraeaos, got %s", caps.OSID)
	}
	if !caps.IsAstraeaOS {
		t.Fatal("expected IsAstraeaOS to be true")
	}
	if caps.EnclaveMode != EnclaveAstraeaOS {
		t.Fatalf("expected EnclaveAstraeaOS, got %s", caps.EnclaveMode)
	}
	if !caps.HasGaiaCells {
		t.Fatal("expected HasGaiaCells to be true")
	}
	if !caps.HasAstraeaKeyBroker {
		t.Fatal("expected HasAstraeaKeyBroker to be true")
	}
	if !caps.HasBPFLSM {
		t.Fatal("expected HasBPFLSM to be true")
	}
	if !caps.HasTPM2 {
		t.Fatal("expected HasTPM2 to be true")
	}
	if !caps.HardwareEnclaveAvailable {
		t.Fatal("expected HardwareEnclaveAvailable to be true when TPM2 and BPF-LSM are present")
	}
	if err := caps.ValidatePlatformInvariants(); err != nil {
		t.Fatalf("invariants failed: %v", err)
	}

	summary := caps.Summary()
	if summary == "" {
		t.Fatal("expected non-empty summary")
	}
}
