//go:build linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	packageIntegrityMaxPackages   = 8192
	packageIntegrityMaxEntries    = 500000
	packageIntegrityMaxMtreeBytes = int64(32 << 20)
	packageIntegrityMaxFileBytes  = int64(512 << 20)
	packageIntegrityMaxTotalBytes = int64(16 << 30)
)

func packageIntegritySupported() bool { return true }

func scanPackageIntegrity(dbRoot, fsRoot string) (PackageIntegrityStatus, error) {
	status := PackageIntegrityStatus{Available: true, Findings: []PackageIntegrityFinding{}}
	dbInfo, err := os.Lstat(dbRoot)
	if err != nil || !dbInfo.IsDir() || dbInfo.Mode()&os.ModeSymlink != 0 {
		return status, errors.New("pacman package database is unavailable or unsafe")
	}
	fsRoot, err = filepath.Abs(fsRoot)
	if err != nil {
		return status, err
	}
	packageDirs, err := os.ReadDir(dbRoot)
	if err != nil {
		return status, err
	}
	if len(packageDirs) > packageIntegrityMaxPackages {
		return status, errors.New("package count exceeds scanner boundary")
	}
	var totalBytes int64
	for _, packageDir := range packageDirs {
		if !packageDir.IsDir() || strings.ContainsAny(packageDir.Name(), `/\`) {
			continue
		}
		mtreePath := filepath.Join(dbRoot, packageDir.Name(), "mtree")
		if _, err := os.Lstat(mtreePath); errors.Is(err, os.ErrNotExist) {
			continue
		}
		packageName := installedPackageName(filepath.Join(dbRoot, packageDir.Name(), "desc"), packageDir.Name())
		if err := scanPackageMtree(mtreePath, fsRoot, packageName, &status, &totalBytes); err != nil {
			appendPackageFinding(&status, PackageIntegrityFinding{Package: packageName, Path: "package-manifest", Status: "ERROR"})
			status.Errors++
		}
		status.Packages++
	}
	if status.Packages == 0 {
		return status, errors.New("no pacman package manifests were verified")
	}
	return status, nil
}

func installedPackageName(descPath, fallback string) string {
	info, statErr := os.Lstat(descPath)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 1<<20 {
		return fallback
	}
	raw, err := os.ReadFile(descPath)
	if err != nil {
		return fallback
	}
	lines := strings.Split(string(raw), "\n")
	for index := 0; index+1 < len(lines); index++ {
		if lines[index] == "%NAME%" && lines[index+1] != "" && len(lines[index+1]) <= 255 {
			return lines[index+1]
		}
	}
	return fallback
}

func scanPackageMtree(mtreePath, fsRoot, packageName string, status *PackageIntegrityStatus, totalBytes *int64) error {
	info, err := os.Lstat(mtreePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > packageIntegrityMaxMtreeBytes {
		return errors.New("package manifest is not a bounded regular file")
	}
	file, err := os.Open(mtreePath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()
	limited := &io.LimitedReader{R: reader, N: packageIntegrityMaxMtreeBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		if status.Files >= packageIntegrityMaxEntries {
			return errors.New("package manifest entry boundary exceeded")
		}
		path, expected, ok := packageManifestRecord(scanner.Text())
		if !ok {
			continue
		}
		status.Files++
		target, err := jailedPackagePath(fsRoot, path)
		if err != nil {
			status.Errors++
			appendPackageFinding(status, PackageIntegrityFinding{Package: packageName, Path: path, Status: "ERROR"})
			continue
		}
		actual, size, err := hashInstalledPackageFile(target)
		switch {
		case errors.Is(err, os.ErrNotExist):
			status.Missing++
			appendPackageFinding(status, PackageIntegrityFinding{Package: packageName, Path: path, Status: "MISSING"})
		case err != nil || size > packageIntegrityMaxTotalBytes-*totalBytes:
			status.Errors++
			appendPackageFinding(status, PackageIntegrityFinding{Package: packageName, Path: path, Status: "ERROR"})
		default:
			*totalBytes += size
			if actual == expected {
				status.Verified++
			} else {
				status.Modified++
				appendPackageFinding(status, PackageIntegrityFinding{Package: packageName, Path: path, Status: "MODIFIED"})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if limited.N == 0 {
		return errors.New("decompressed package manifest exceeds boundary")
	}
	return nil
}

func packageManifestRecord(line string) (string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "./") || strings.Contains(fields[0], `\`) {
		return "", "", false
	}
	for _, field := range fields[1:] {
		if digest, ok := strings.CutPrefix(field, "sha256digest="); ok && len(digest) == sha256.Size*2 {
			if _, err := hex.DecodeString(digest); err == nil {
				return strings.TrimPrefix(fields[0], "./"), strings.ToLower(digest), true
			}
		}
	}
	return "", "", false
}

func jailedPackagePath(fsRoot, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.ContainsRune(relative, '\x00') {
		return "", errors.New("invalid package path")
	}
	realRoot, err := filepath.EvalSymlinks(fsRoot)
	if err != nil {
		return "", errors.New("package filesystem root is unavailable")
	}
	target := filepath.Clean(filepath.Join(realRoot, filepath.FromSlash(relative)))
	prefix := realRoot + string(filepath.Separator)
	if realRoot == string(filepath.Separator) {
		prefix = realRoot
	}
	if target == realRoot || !strings.HasPrefix(target, prefix) {
		return "", errors.New("package path escaped jail")
	}
	realParent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil || (realParent != realRoot && !strings.HasPrefix(realParent, prefix)) {
		return "", errors.New("package path parent escaped jail")
	}
	return target, nil
}

func hashInstalledPackageFile(path string) (string, int64, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return "", 0, errors.New("invalid package file descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > packageIntegrityMaxFileBytes {
		return "", 0, errors.New("package object is not a bounded regular file")
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, packageIntegrityMaxFileBytes+1))
	if err != nil || written != info.Size() {
		return "", 0, errors.New("package file changed while hashing")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != written || after.ModTime() != info.ModTime() {
		return "", 0, errors.New("package file identity changed while hashing")
	}
	return hex.EncodeToString(digest.Sum(nil)), written, nil
}

func appendPackageFinding(status *PackageIntegrityStatus, finding PackageIntegrityFinding) {
	if len(status.Findings) < packageIntegrityMaxFindings {
		status.Findings = append(status.Findings, finding)
	}
}
