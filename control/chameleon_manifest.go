// V6.3.0 AP-8: strict manifest discovery, parsing and validation of the opt-in
// Chameleon installation identity (control-plane half). The rules mirror
// `rust/gedefense-core/src/chameleon.rs`: invalid manifests are fatal at
// startup, never silently downgraded to the public identity.
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	// chameleonManifestEnvVar is the fallback discovery path for the installer.
	chameleonManifestEnvVar = "VGT_INSTALL_MANIFEST"
	// chameleonManifestSchema is the first line of every signed install manifest.
	chameleonManifestSchema = "vgt-gedefense-chameleon-v1"
	// chameleonManifestMaxBytes bounds the manifest (strict, small config file).
	chameleonManifestMaxBytes = 16 * 1024
)

// chameleonRequiredKeys / chameleonOptionalKeys mirror the Rust parser.
var (
	chameleonRequiredKeys = []string{
		"install_id",
		"bpf_name_salt",
		"core_socket",
		"scan_socket",
		"bpf_pin_root",
		"state_dir",
		"config_dir",
		"public_port",
		"backend_port",
		"neutral_unit_prefix",
	}
	chameleonOptionalKeys = []string{"admin_audit_path"}
)

// readChameleonManifestFile reads the manifest without following a final symlink
// and enforces the documented file policy: regular file, not group/world
// writable, root-owned or owned by the effective user.
func readChameleonManifestFile(manifestPath string) ([]byte, error) {
	fd, err := syscall.Open(manifestPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("chameleon manifest is unavailable: %w", err)
	}
	file := os.NewFile(uintptr(fd), manifestPath)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("chameleon manifest metadata is unavailable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("chameleon manifest must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("chameleon manifest metadata is unavailable")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("chameleon manifest must not be group/world writable")
	}
	// The installer provisions the manifest as root-owned; the privileged core
	// (root) and the unprivileged control plane (reading a root-owned file through
	// its service group) must both accept it. A file owned by some other account
	// is never accepted.
	if stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("chameleon manifest must belong to root or the effective user")
	}
	if info.Size() > chameleonManifestMaxBytes {
		return nil, fmt.Errorf("chameleon manifest exceeds the %d byte bound", chameleonManifestMaxBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, chameleonManifestMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("chameleon manifest cannot be read: %w", err)
	}
	if len(raw) > chameleonManifestMaxBytes {
		return nil, fmt.Errorf("chameleon manifest exceeds the %d byte bound", chameleonManifestMaxBytes)
	}
	return raw, nil
}

// parseChameleonManifest is the strict, bounded, rejecting parser shared with the
// Rust core's format rules.
func parseChameleonManifest(raw []byte) (ChameleonManifest, error) {
	var manifest ChameleonManifest
	if len(raw) == 0 {
		return manifest, errors.New("chameleon manifest is empty")
	}
	if len(raw) > chameleonManifestMaxBytes {
		return manifest, errors.New("chameleon manifest exceeds the size bound")
	}
	if !utf8.Valid(raw) {
		return manifest, errors.New("chameleon manifest is not UTF-8")
	}
	text := string(raw)
	if strings.HasPrefix(text, "\ufeff") {
		return manifest, errors.New("chameleon manifest must not start with a BOM")
	}
	if strings.Contains(text, "\r") {
		return manifest, errors.New("chameleon manifest must use LF line endings")
	}
	for _, character := range text {
		if (character < 0x20 || character == 0x7f) && character != '\n' {
			return manifest, errors.New("chameleon manifest contains control characters")
		}
	}
	lines := strings.Split(text, "\n")
	if lines[0] != chameleonManifestSchema {
		return manifest, fmt.Errorf("chameleon manifest schema mismatch (expected %s)", chameleonManifestSchema)
	}
	known := make(map[string]bool, len(chameleonRequiredKeys)+len(chameleonOptionalKeys))
	for _, key := range chameleonRequiredKeys {
		known[key] = true
	}
	for _, key := range chameleonOptionalKeys {
		known[key] = true
	}
	values := make(map[string]string, len(chameleonRequiredKeys)+1)
	for lineNumber := 2; lineNumber <= len(lines); lineNumber++ {
		line := lines[lineNumber-1]
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return manifest, fmt.Errorf("chameleon manifest line %d: expected key=value", lineNumber)
		}
		if strings.Contains(value, "=") {
			return manifest, fmt.Errorf("chameleon manifest line %d: unexpected second '='", lineNumber)
		}
		if key == "" || value == "" || !validChameleonKey(key) {
			return manifest, fmt.Errorf("chameleon manifest line %d: invalid key or value", lineNumber)
		}
		if !known[key] {
			return manifest, fmt.Errorf("chameleon manifest contains unknown key %s", key)
		}
		if _, duplicate := values[key]; duplicate {
			return manifest, fmt.Errorf("chameleon manifest contains duplicate key %s", key)
		}
		values[key] = value
	}
	for _, key := range chameleonRequiredKeys {
		if _, ok := values[key]; !ok {
			return manifest, fmt.Errorf("chameleon manifest is missing required key %s", key)
		}
	}
	if err := validateChameleonInstallID(values["install_id"]); err != nil {
		return manifest, err
	}
	if _, err := decodeChameleonSalt(values["bpf_name_salt"]); err != nil {
		return manifest, err
	}
	if err := validateChameleonPath("core_socket", values["core_socket"]); err != nil {
		return manifest, err
	}
	if err := validateChameleonPath("scan_socket", values["scan_socket"]); err != nil {
		return manifest, err
	}
	if err := validateChameleonPath("bpf_pin_root", values["bpf_pin_root"]); err != nil {
		return manifest, err
	}
	if err := validateChameleonPath("state_dir", values["state_dir"]); err != nil {
		return manifest, err
	}
	if err := validateChameleonPath("config_dir", values["config_dir"]); err != nil {
		return manifest, err
	}
	if _, err := validateChameleonPort("public_port", values["public_port"]); err != nil {
		return manifest, err
	}
	if _, err := validateChameleonPort("backend_port", values["backend_port"]); err != nil {
		return manifest, err
	}
	if values["core_socket"] == values["scan_socket"] {
		return manifest, errors.New("chameleon manifest core_socket and scan_socket must differ")
	}
	if values["state_dir"] == values["config_dir"] {
		return manifest, errors.New("chameleon manifest state_dir and config_dir must differ")
	}
	if values["public_port"] == values["backend_port"] {
		return manifest, errors.New("chameleon manifest public_port and backend_port must differ")
	}
	if err := validateChameleonUnitPrefix(values["neutral_unit_prefix"]); err != nil {
		return manifest, err
	}
	if adminAuditPath, ok := values["admin_audit_path"]; ok {
		if err := validateChameleonPath("admin_audit_path", adminAuditPath); err != nil {
			return manifest, err
		}
		manifest.AdminAuditPath = adminAuditPath
	}
	manifest.InstallID = values["install_id"]
	manifest.BPFNameSalt = values["bpf_name_salt"]
	manifest.CoreSocket = values["core_socket"]
	manifest.ScanSocket = values["scan_socket"]
	manifest.BpfPinRoot = values["bpf_pin_root"]
	manifest.StateDir = values["state_dir"]
	manifest.ConfigDir = values["config_dir"]
	manifest.PublicPort = values["public_port"]
	manifest.BackendPort = values["backend_port"]
	manifest.NeutralPrefix = values["neutral_unit_prefix"]
	return manifest, nil
}

func validChameleonKey(key string) bool {
	for _, character := range key {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

// decodeChameleonSalt decodes exactly 32 bytes of lowercase hex.
func decodeChameleonSalt(value string) ([]byte, error) {
	if len(value) != 64 {
		return nil, errors.New("chameleon manifest bpf_name_salt must be exactly 64 hex characters")
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return nil, errors.New("chameleon manifest bpf_name_salt must be lowercase hex")
		}
	}
	salt, err := hex.DecodeString(value)
	if err != nil || len(salt) != 32 {
		return nil, errors.New("chameleon manifest bpf_name_salt is not valid hex")
	}
	return salt, nil
}

func validateChameleonInstallID(value string) error {
	if len(value) < 16 || len(value) > 64 {
		return errors.New("chameleon manifest install_id must be 16..=64 characters")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return errors.New("chameleon manifest install_id must match [a-z0-9-]")
		}
	}
	if strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return errors.New("chameleon manifest install_id must not start or end with '-'")
	}
	return nil
}

func validateChameleonPath(key, value string) error {
	if value == "" || len(value) > 200 {
		return fmt.Errorf("chameleon manifest %s has an invalid length", key)
	}
	for _, character := range value {
		if (character < 0x20 || character == 0x7f) || character == 0 {
			return fmt.Errorf("chameleon manifest %s contains control characters", key)
		}
	}
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("chameleon manifest %s must be an absolute path", key)
	}
	if value == "/" {
		return fmt.Errorf("chameleon manifest %s must not be the filesystem root", key)
	}
	if strings.Contains(value, "//") {
		return fmt.Errorf("chameleon manifest %s must not contain '//'", key)
	}
	if strings.HasSuffix(value, "/") {
		return fmt.Errorf("chameleon manifest %s must not end with '/'", key)
	}
	if path.Clean(value) != value {
		return fmt.Errorf("chameleon manifest %s must not contain '.', '..' or empty components", key)
	}
	return nil
}

func validateChameleonPort(key, value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("chameleon manifest %s must be a decimal port", key)
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("chameleon manifest %s must be a decimal port", key)
		}
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("chameleon manifest %s is out of range", key)
	}
	if port < 1024 || port > 65535 {
		return 0, fmt.Errorf("chameleon manifest %s must be 1024..=65535", key)
	}
	return port, nil
}

func validateChameleonUnitPrefix(value string) error {
	if len(value) < 3 || len(value) > 21 {
		return errors.New("chameleon manifest neutral_unit_prefix must be 3..=21 characters")
	}
	if value[0] < 'a' || value[0] > 'z' {
		return errors.New("chameleon manifest neutral_unit_prefix must start with a letter")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return errors.New("chameleon manifest neutral_unit_prefix must match [a-z0-9-]")
		}
	}
	return nil
}

// chameleonManifestKeys is used by tests and installer-facing diagnostics to
// report the exact accepted key set in a stable order.
func chameleonManifestKeys() []string {
	keys := make([]string, 0, len(chameleonRequiredKeys)+len(chameleonOptionalKeys))
	keys = append(keys, chameleonRequiredKeys...)
	keys = append(keys, chameleonOptionalKeys...)
	sort.Strings(keys)
	return keys
}
