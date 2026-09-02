// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Typed Platform Error Hierarchy (Section 1.5.A Compliance)
type PlatformException struct {
	Message string
	Err     error
}

func (e *PlatformException) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *PlatformException) Unwrap() error { return e.Err }

type PlatformValidationException struct{ PlatformException }

func NewPlatformValidationException(msg string, err error) *PlatformValidationException {
	return &PlatformValidationException{PlatformException{Message: msg, Err: err}}
}

type EnclaveMode string

const (
	EnclaveGenericLinux EnclaveMode = "GENERIC_LINUX"
	EnclaveAstraeaOS    EnclaveMode = "ASTRAEAOS_NATIVE"
)

const (
	defaultGaiaCellsSocket   = "/run/gaia-cells/gaia-cells.sock"
	defaultKeyBrokerSocket   = "/run/astraea/key-broker.sock"
	defaultLSMPath           = "/sys/kernel/security/lsm"
	defaultCgroupControllers = "/sys/fs/cgroup/cgroup.controllers"
	defaultTPMDevice         = "/dev/tpmrm0"
	defaultTPMDeviceAlt      = "/dev/tpm0"
)

// PlatformCapabilities details the runtime security hardware and subsystem availability.
type PlatformCapabilities struct {
	OSID                     string      `json:"os_id"`
	OSName                   string      `json:"os_name"`
	OSVersion                string      `json:"os_version"`
	EnclaveMode              EnclaveMode `json:"enclave_mode"`
	IsAstraeaOS              bool        `json:"is_astraeaos"`
	HasGaiaCells             bool        `json:"has_gaia_cells"`
	GaiaCellsSocket          string      `json:"gaia_cells_socket,omitempty"`
	HasAstraeaKeyBroker      bool        `json:"has_astraea_key_broker"`
	KeyBrokerSocket          string      `json:"key_broker_socket,omitempty"`
	HasBPFLSM                bool        `json:"has_bpf_lsm"`
	HasCgroupV2              bool        `json:"has_cgroup_v2"`
	HasTPM2                  bool        `json:"has_tpm2"`
	HardwareEnclaveAvailable bool        `json:"hardware_enclave_available"`
	DetectedAt               time.Time   `json:"detected_at"`
}

// DetectPlatformCapabilities safely inspects the host environment without panicking or failing on non-Linux hosts.
func DetectPlatformCapabilities(rootFs string) PlatformCapabilities {
	caps := PlatformCapabilities{
		OSID:        "generic",
		OSName:      "Linux Host",
		EnclaveMode: EnclaveGenericLinux,
		DetectedAt:  time.Now().UTC(),
	}

	cleanRoot := filepath.Clean(rootFs)
	if cleanRoot == "." || cleanRoot == "/" {
		cleanRoot = ""
	}

	// 1. Parse /etc/os-release
	osReleasePath := filepath.Join(cleanRoot, "etc", "os-release")
	if data, err := os.ReadFile(osReleasePath); err == nil {
		parseOSRelease(data, &caps)
	} else {
		// Fallback to /usr/lib/os-release
		altPath := filepath.Join(cleanRoot, "usr", "lib", "os-release")
		if dataAlt, errAlt := os.ReadFile(altPath); errAlt == nil {
			parseOSRelease(dataAlt, &caps)
		}
	}

	// 2. Check GaiaCells socket
	gaiaSocket := filepath.Join(cleanRoot, defaultGaiaCellsSocket)
	if fi, err := os.Stat(gaiaSocket); err == nil && (fi.Mode()&os.ModeSocket != 0 || fi.Mode().IsRegular()) {
		caps.HasGaiaCells = true
		caps.GaiaCellsSocket = defaultGaiaCellsSocket
	}

	// 3. Check Astraea Key Broker socket
	keyBrokerSocket := filepath.Join(cleanRoot, defaultKeyBrokerSocket)
	if fi, err := os.Stat(keyBrokerSocket); err == nil && (fi.Mode()&os.ModeSocket != 0 || fi.Mode().IsRegular()) {
		caps.HasAstraeaKeyBroker = true
		caps.KeyBrokerSocket = defaultKeyBrokerSocket
	}

	// 4. Check BPF-LSM in /sys/kernel/security/lsm
	lsmPath := filepath.Join(cleanRoot, defaultLSMPath)
	if data, err := os.ReadFile(lsmPath); err == nil {
		lsmStr := string(data)
		for _, token := range strings.Split(lsmStr, ",") {
			if strings.TrimSpace(token) == "bpf" {
				caps.HasBPFLSM = true
				break
			}
		}
	}

	// 5. Check cgroup v2 presence
	cgroupPath := filepath.Join(cleanRoot, defaultCgroupControllers)
	if _, err := os.Stat(cgroupPath); err == nil {
		caps.HasCgroupV2 = true
	}

	// 6. Check TPM2 device presence
	tpmPath := filepath.Join(cleanRoot, defaultTPMDevice)
	tpmAltPath := filepath.Join(cleanRoot, defaultTPMDeviceAlt)
	if _, err := os.Stat(tpmPath); err == nil {
		caps.HasTPM2 = true
	} else if _, errAlt := os.Stat(tpmAltPath); errAlt == nil {
		caps.HasTPM2 = true
	}

	// 7. Enforce Enclave Mode Decision
	if caps.IsAstraeaOS || (caps.HasGaiaCells && caps.HasAstraeaKeyBroker) {
		caps.EnclaveMode = EnclaveAstraeaOS
		caps.HardwareEnclaveAvailable = caps.HasTPM2 && caps.HasBPFLSM
	} else {
		caps.EnclaveMode = EnclaveGenericLinux
		caps.HardwareEnclaveAvailable = false
	}

	return caps
}

func parseOSRelease(data []byte, caps *PlatformCapabilities) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)

		switch key {
		case "ID":
			caps.OSID = strings.ToLower(val)
			if caps.OSID == "astraeaos" || caps.OSID == "gaiaos" {
				caps.IsAstraeaOS = true
			}
		case "NAME":
			caps.OSName = val
			if strings.Contains(strings.ToLower(val), "astraeaos") {
				caps.IsAstraeaOS = true
			}
		case "VERSION_ID", "VERSION":
			caps.OSVersion = val
		case "ID_LIKE":
			for _, like := range strings.Fields(val) {
				if strings.ToLower(like) == "astraeaos" {
					caps.IsAstraeaOS = true
				}
			}
		}
	}
}

// Summary returns a single formatted line describing the detected platform posture.
func (p PlatformCapabilities) Summary() string {
	return fmt.Sprintf("OS=%s (%s %s) Enclave=%s GaiaCells=%t KeyBroker=%t BPFLSM=%t TPM2=%t",
		p.OSID, p.OSName, p.OSVersion, p.EnclaveMode, p.HasGaiaCells, p.HasAstraeaKeyBroker, p.HasBPFLSM, p.HasTPM2)
}

// ToJSON returns a deterministic JSON representation of the platform capabilities.
func (p PlatformCapabilities) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// ValidatePlatformInvariants asserts non-negotiable security boundaries per deployment profile.
func (p PlatformCapabilities) ValidatePlatformInvariants() error {
	if p.EnclaveMode == EnclaveAstraeaOS {
		if !p.IsAstraeaOS && !p.HasGaiaCells {
			return errors.New("invalid platform state: AstraeaOS enclave active without identity or cell runtime")
		}
	}
	return nil
}
