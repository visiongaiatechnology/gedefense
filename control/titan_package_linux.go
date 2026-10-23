// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

// Package-ownership evidence read directly from the local package databases.
//
// The network-facing control plane must not execute local commands, so no
// package manager binary is ever started. Titan reads the on-disk databases
// instead:
//   - Debian/Ubuntu: /var/lib/dpkg/status for the installed-package set and
//     /var/lib/dpkg/info/<package>.list for the absolute file lists.
//   - Arch: /var/lib/pacman/local/<package>/files (%FILES% section), package
//     name from desc (%NAME%).
//   - RPM systems: there is no unshelled reliable reader available, therefore
//     ownership evidence is reported as explicitly unavailable instead of
//     executing rpm.
//
// Every read is bounded, every path is validated, symlinks are never followed,
// and a database that cannot be read yields no ownership evidence: missing
// evidence lowers trust, it never authorizes a change.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	titanDefaultPackageIndexTTL  = 5 * time.Minute
	titanMaxPackageIndexEntries  = 100000
	titanMaxDPKGListFiles        = 50000
	titanMaxDPKGStatusBytes      = 16 << 20
	titanMaxDPKGListBytes        = 8 << 20
	titanMaxDPKGTotalListBytes   = 128 << 20
	titanMaxDPKGInstalledEntries = 200000
	titanMaxPacmanDirs           = 20000
	titanMaxPacmanMetaBytes      = 4 << 20
	titanMaxPacmanTotalMetaBytes = 64 << 20
)

// titanPackageDBConfig is the bounded, test-overridable database configuration.
type titanPackageDBConfig struct {
	dpkgRoot            string
	pacmanRoot          string
	rpmRoot             string
	ttl                 time.Duration
	maxEntries          int
	maxDPKGListFiles    int
	maxStatusBytes      int64
	maxListBytes        int64
	maxTotalListBytes   int64
	maxDPKGInstalled    int
	maxPacmanDirs       int
	maxPacmanMetaBytes  int64
	maxPacmanTotalBytes int64
}

func defaultTitanPackageDBConfig() titanPackageDBConfig {
	return titanPackageDBConfig{
		dpkgRoot: "/var/lib/dpkg", pacmanRoot: "/var/lib/pacman", rpmRoot: "/var/lib/rpm",
		ttl: titanDefaultPackageIndexTTL, maxEntries: titanMaxPackageIndexEntries,
		maxDPKGListFiles: titanMaxDPKGListFiles, maxStatusBytes: titanMaxDPKGStatusBytes,
		maxListBytes: titanMaxDPKGListBytes, maxTotalListBytes: titanMaxDPKGTotalListBytes,
		maxDPKGInstalled: titanMaxDPKGInstalledEntries, maxPacmanDirs: titanMaxPacmanDirs,
		maxPacmanMetaBytes: titanMaxPacmanMetaBytes, maxPacmanTotalBytes: titanMaxPacmanTotalMetaBytes,
	}
}

type titanLocalPackageVerifier struct {
	cfg titanPackageDBConfig
	now func() time.Time

	mu      sync.Mutex
	index   map[string]titanPackageOwner
	manager string
	builtAt time.Time
	lastErr error
}

func newTitanPackageVerifier() titanPackageVerifier {
	return &titanLocalPackageVerifier{
		cfg: defaultTitanPackageDBConfig(),
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Owner resolves package ownership from the cached local database index.
// Missing evidence and unreadable databases both return an error; an unowned
// path inside a readable database returns (zero, false, nil).
func (v *titanLocalPackageVerifier) Owner(ctx context.Context, path string) (titanPackageOwner, bool, error) {
	if v == nil {
		return titanPackageOwner{}, false, errors.New("package ownership evidence unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !titanValidOwnershipPath(path) {
		return titanPackageOwner{}, false, errors.New("package ownership path is invalid")
	}
	index, err := v.cachedIndex(ctx)
	if err != nil {
		return titanPackageOwner{}, false, err
	}
	owner, exists := index[filepath.Clean(path)]
	if !exists {
		return titanPackageOwner{}, false, nil
	}
	return owner, true, nil
}

func (v *titanLocalPackageVerifier) cachedIndex(ctx context.Context) (map[string]titanPackageOwner, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.index != nil && v.now().Sub(v.builtAt) < v.cfg.ttl {
		return v.index, nil
	}
	index, manager, err := buildTitanPackageIndex(ctx, v.cfg)
	if err != nil {
		// A failed rebuild must not serve a stale index as if it were current
		// evidence: the caller sees missing evidence and lowers trust.
		v.index = nil
		v.manager = ""
		v.lastErr = err
		return nil, err
	}
	v.index = index
	v.manager = manager
	v.builtAt = v.now()
	v.lastErr = nil
	return index, nil
}

// buildTitanPackageIndex selects the readable local database and builds the
// bounded path index. It never executes a package manager.
func buildTitanPackageIndex(ctx context.Context, cfg titanPackageDBConfig) (map[string]titanPackageOwner, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	wanted := cfg.dpkgRoot
	if ti, err := os.Lstat(wanted); err != nil || !ti.IsDir() {
		wanted = ""
	}
	if wanted != "" {
		if titanRegularNonSymlinkFile(filepath.Join(cfg.dpkgRoot, "status")) {
			index, err := titanIndexDPKG(ctx, cfg)
			if err != nil {
				return nil, "", err
			}
			return index, "dpkg", nil
		}
	}
	pacmanLocal := filepath.Join(cfg.pacmanRoot, "local")
	if titanNonSymlinkDirectory(pacmanLocal) {
		index, err := titanIndexPacman(ctx, cfg)
		if err != nil {
			return nil, "", err
		}
		return index, "pacman", nil
	}
	if titanRPMDatabasePresent(cfg.rpmRoot) {
		return nil, "", errors.New("package manager ownership evidence unavailable: rpm database cannot be read without command execution")
	}
	return nil, "", errors.New("package manager ownership evidence unavailable: no readable local package database (dpkg status or pacman local)")
}

func titanIndexDPKG(ctx context.Context, cfg titanPackageDBConfig) (map[string]titanPackageOwner, error) {
	statusRaw, err := titanReadBoundedRegularFile(filepath.Join(cfg.dpkgRoot, "status"), cfg.maxStatusBytes)
	if err != nil {
		return nil, errors.New("package manager ownership evidence unavailable: dpkg status cannot be read safely")
	}
	installed, err := titanParseDPKGStatus(statusRaw, cfg.maxDPKGInstalled)
	if err != nil {
		return nil, err
	}
	if len(installed) == 0 {
		return nil, errors.New("package manager ownership evidence unavailable: dpkg status contains no installed packages")
	}
	infoDir := filepath.Join(cfg.dpkgRoot, "info")
	if !titanNonSymlinkDirectory(infoDir) {
		return nil, errors.New("package manager ownership evidence unavailable: dpkg info directory cannot be read safely")
	}
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil, errors.New("package manager ownership evidence unavailable: dpkg info directory cannot be listed")
	}
	index := make(map[string]titanPackageOwner, 4096)
	listFiles := 0
	var totalBytes int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".list") || !entry.Type().IsRegular() {
			continue
		}
		listFiles++
		if listFiles > cfg.maxDPKGListFiles {
			return nil, errors.New("package manager ownership evidence unavailable: dpkg file-list count exceeds the bound")
		}
		packageName := strings.TrimSuffix(name, ".list")
		if !titanDPKGPackageInstalled(packageName, installed) {
			continue
		}
		raw, readErr := titanReadBoundedRegularFile(filepath.Join(infoDir, name), cfg.maxListBytes)
		if readErr != nil {
			// A single unreadable list is skipped; the rest of the database still
			// provides evidence. The path is then "unknown", which lowers trust.
			continue
		}
		totalBytes += int64(len(raw))
		if totalBytes > cfg.maxTotalListBytes {
			return nil, errors.New("package manager ownership evidence unavailable: dpkg file-list bytes exceed the bound")
		}
		// The file list name carries a multiarch suffix (base-files:amd64);
		// report the canonical package name without it.
		displayName := packageName
		if index := strings.IndexByte(displayName, ':'); index > 0 {
			displayName = displayName[:index]
		}
		owner := titanPackageOwner{Manager: "dpkg", Package: titanBoundedPackageName(displayName)}
		if owner.Package == "" {
			continue
		}
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			path, ok := titanNormalizeDPKGListPath(string(line))
			if !ok {
				continue
			}
			if len(index) >= cfg.maxEntries {
				return nil, errors.New("package manager ownership evidence unavailable: dpkg path index exceeds the bound")
			}
			index[path] = owner
		}
	}
	if len(index) == 0 {
		return nil, errors.New("package manager ownership evidence unavailable: dpkg file lists produced no ownership entries")
	}
	return index, nil
}

func titanParseDPKGStatus(raw []byte, maxInstalled int) (map[string]struct{}, error) {
	installed := make(map[string]struct{}, 1024)
	var name, arch, status string
	flush := func() {
		defer func() { name, arch, status = "", "", "" }()
		if name == "" || status == "" {
			return
		}
		if !strings.Contains(status, "installed") {
			return
		}
		if arch != "" {
			installed[name+":"+arch] = struct{}{}
		}
		installed[name] = struct{}{}
	}
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			flush()
			continue
		}
		field, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(field) {
		case "Package":
			name = titanBoundedPackageName(value)
		case "Architecture":
			arch = titanBoundedPackageName(value)
		case "Status":
			status = strings.ToLower(value)
		}
		if name == "" || arch == "" {
			continue
		}
		if len(installed) > maxInstalled {
			return nil, errors.New("package manager ownership evidence unavailable: dpkg installed-package count exceeds the bound")
		}
	}
	flush()
	if len(installed) > maxInstalled {
		return nil, errors.New("package manager ownership evidence unavailable: dpkg installed-package count exceeds the bound")
	}
	return installed, nil
}

func titanDPKGPackageInstalled(listPackage string, installed map[string]struct{}) bool {
	base := listPackage
	if index := strings.IndexByte(listPackage, ':'); index > 0 {
		base = listPackage[:index]
	}
	_, fullExists := installed[listPackage]
	_, baseExists := installed[base]
	return fullExists || baseExists
}

func titanNormalizeDPKGListPath(raw string) (string, bool) {
	value := strings.TrimRight(raw, "\r")
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "#") {
		return "", false
	}
	value = strings.TrimSuffix(value, "/")
	if value == "" || len(value) > titanMaxPathBytes || strings.ContainsRune(value, '\x00') {
		return "", false
	}
	if !filepath.IsAbs(value) {
		return "", false
	}
	clean := filepath.Clean(value)
	if clean != value || clean == string(filepath.Separator) {
		return "", false
	}
	return clean, true
}

func titanIndexPacman(ctx context.Context, cfg titanPackageDBConfig) (map[string]titanPackageOwner, error) {
	entries, err := os.ReadDir(filepath.Join(cfg.pacmanRoot, "local"))
	if err != nil {
		return nil, errors.New("package manager ownership evidence unavailable: pacman local database cannot be listed")
	}
	index := make(map[string]titanPackageOwner, 4096)
	directories := 0
	var totalBytes int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		directories++
		if directories > cfg.maxPacmanDirs {
			return nil, errors.New("package manager ownership evidence unavailable: pacman package directory count exceeds the bound")
		}
		dir := filepath.Join(cfg.pacmanRoot, "local", entry.Name())
		descRaw, readErr := titanReadBoundedRegularFile(filepath.Join(dir, "desc"), cfg.maxPacmanMetaBytes)
		if readErr != nil {
			continue
		}
		totalBytes += int64(len(descRaw))
		filesRaw, readErr := titanReadBoundedRegularFile(filepath.Join(dir, "files"), cfg.maxPacmanMetaBytes)
		if readErr != nil {
			continue
		}
		totalBytes += int64(len(filesRaw))
		if totalBytes > cfg.maxPacmanTotalBytes {
			return nil, errors.New("package manager ownership evidence unavailable: pacman metadata bytes exceed the bound")
		}
		packageName := titanPacmanName(descRaw)
		if packageName == "" {
			continue
		}
		owner := titanPackageOwner{Manager: "pacman", Package: packageName}
		for _, path := range titanPacmanFiles(filesRaw) {
			if len(index) >= cfg.maxEntries {
				return nil, errors.New("package manager ownership evidence unavailable: pacman path index exceeds the bound")
			}
			index[path] = owner
		}
	}
	if len(index) == 0 {
		return nil, errors.New("package manager ownership evidence unavailable: pacman database produced no ownership entries")
	}
	return index, nil
}

func titanPacmanName(descRaw []byte) string {
	section := ""
	for _, line := range bytes.Split(descRaw, []byte{'\n'}) {
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "%") && strings.HasSuffix(trimmed, "%") {
			section = trimmed
			continue
		}
		if section == "%NAME%" {
			return titanBoundedPackageName(trimmed)
		}
	}
	return ""
}

func titanPacmanFiles(filesRaw []byte) []string {
	paths := make([]string, 0, 1024)
	section := ""
	for _, line := range bytes.Split(filesRaw, []byte{'\n'}) {
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "%") && strings.HasSuffix(trimmed, "%") {
			section = trimmed
			continue
		}
		if section != "%FILES%" {
			continue
		}
		if len(trimmed) > titanMaxPathBytes || strings.ContainsRune(trimmed, '\x00') || strings.Contains(trimmed, "..") {
			continue
		}
		relative := strings.TrimPrefix(trimmed, "/")
		relative = strings.TrimSuffix(relative, "/")
		if relative == "" {
			continue
		}
		clean := filepath.Clean("/" + relative)
		if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
			continue
		}
		paths = append(paths, clean)
	}
	return paths
}

// titanReadBoundedRegularFile reads a database file without following links and
// without trusting a file that changes while it is read.
func titanReadBoundedRegularFile(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("package database file is not a regular non-symlink file")
	}
	if before.Size() <= 0 || before.Size() > maxBytes {
		return nil, errors.New("package database file size is outside the bound")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("package database file identity changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(raw)) > maxBytes {
		return nil, errors.New("package database file read rejected")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return nil, errors.New("package database file changed while reading")
	}
	return raw, nil
}

func titanRPMDatabasePresent(root string) bool {
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	for _, name := range []string{"rpmdb.sqlite", "Packages", "rpmdb"} {
		if titanRegularNonSymlinkFile(filepath.Join(root, name)) {
			return true
		}
	}
	return false
}

func titanRegularNonSymlinkFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func titanNonSymlinkDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

// titanBoundedPackageName keeps package names printable and bounded.
func titanBoundedPackageName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 200 {
		value = value[:200]
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	return value
}

// titanValidOwnershipPath keeps the ownership query to a validated absolute path.
func titanValidOwnershipPath(path string) bool {
	if len(path) == 0 || len(path) > titanMaxPathBytes || strings.ContainsRune(path, '\x00') {
		return false
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	if path == string(filepath.Separator) {
		return false
	}
	return !strings.HasPrefix(path, "-")
}
