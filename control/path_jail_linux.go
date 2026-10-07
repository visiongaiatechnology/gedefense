//go:build linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Path components are resolved one descriptor at a time.
//
// A preceding implementation checked the parent directory with Lstat and then
// opened the full path with O_CREATE|O_EXCL. O_EXCL guarantees exactly one thing:
// the *final* component is created fresh, and a symbolic link there is refused.
// It says nothing about the directories above it, which the kernel re-resolves at
// open time. An attacker who replaces a parent directory with a symlink between
// the check and the open therefore redirects the write, and the open still
// succeeds because the final component really is new. For a service that runs as
// root that is an arbitrary-write primitive - the decoy file lands in
// /etc/cron.d, in an authorized_keys file, or behind ld.so.preload.
//
// openBeneath closes that window. It opens the jail root once, then descends one
// component at a time with openat(2) relative to the descriptor it already holds,
// carrying O_NOFOLLOW and O_DIRECTORY on every intermediate step. A substituted
// symlink makes that step fail with ELOOP instead of being followed, and no path
// outside the root can be named because the walk never resolves an absolute path
// again. No kernel newer than what O_NOFOLLOW requires is needed, so this holds on
// every Linux the product targets.

// jailStepFlags is the set of flags forced onto every step of the walk.
const jailStepFlags = syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// noFollowFlag refuses a symbolic link in the final component of an open. It is
// used on the append paths, whose directory is the service's own and whose target
// is therefore only swappable by someone who already holds the service identity -
// but refusing the link costs nothing and removes the case entirely.
const noFollowFlag = syscall.O_NOFOLLOW

// openAbsoluteJailRoot resolves every ancestor without following symbolic links.
func openAbsoluteJailRoot(root string, create bool) (int, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return -1, fmt.Errorf("jail root must be a clean absolute path")
	}
	dirfd, err := syscall.Open("/", syscall.O_DIRECTORY|jailStepFlags|syscall.O_RDONLY, 0)
	if err != nil {
		return -1, fmt.Errorf("open filesystem root: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if component == "" {
			continue
		}
		if create {
			if err := syscall.Mkdirat(dirfd, component, 0o700); err != nil && err != syscall.EEXIST {
				syscall.Close(dirfd)
				return -1, fmt.Errorf("create jail directory: %w", err)
			}
		}
		next, openErr := syscall.Openat(dirfd, component, syscall.O_DIRECTORY|jailStepFlags|syscall.O_RDONLY, 0)
		syscall.Close(dirfd)
		if openErr != nil {
			return -1, fmt.Errorf("resolve jail ancestor: %w", openErr)
		}
		dirfd = next
	}
	return dirfd, nil
}

func ensureCanaryDirectory(root string) error {
	dirfd, err := openAbsoluteJailRoot(root, true)
	if err != nil {
		return err
	}
	return syscall.Close(dirfd)
}

// openBeneath opens or creates name inside root without following a symbolic link
// in any component.
//
// name must be a clean relative path. flags and perm apply to the final component
// only; intermediate components are always opened as directories.
func openBeneath(root, name string, flags int, perm uint32) (*os.File, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("jail root must be absolute")
	}
	clean := filepath.Clean(strings.TrimSpace(name))
	if err := validateJailRelativeName(clean); err != nil {
		return nil, err
	}

	dirfd, err := openAbsoluteJailRoot(root, false)
	if err != nil {
		return nil, fmt.Errorf("open jail root: %w", err)
	}

	components := strings.Split(clean, "/")
	for index, component := range components {
		last := index == len(components)-1
		stepFlags := jailStepFlags
		if last {
			stepFlags |= flags
		} else {
			stepFlags |= syscall.O_DIRECTORY | syscall.O_RDONLY
		}
		next, openErr := syscall.Openat(dirfd, component, stepFlags, perm)
		// The parent descriptor is released on both paths, so a failed walk cannot
		// leak a descriptor for the lifetime of the process.
		syscall.Close(dirfd)
		if openErr != nil {
			return nil, fmt.Errorf("resolve %q inside the jail: %w", component, openErr)
		}
		dirfd = next
		if last {
			return os.NewFile(uintptr(dirfd), filepath.Join(root, clean)), nil
		}
	}
	// A clean relative name always has at least one component, so this is
	// unreachable; it exists so the descriptor cannot escape if that ever changes.
	syscall.Close(dirfd)
	return nil, fmt.Errorf("jail name resolved to no component")
}

// validateJailRelativeName rejects anything that is not a plain relative path.
// The walk cannot escape through ".." in any case, but refusing it here keeps the
// error unambiguous instead of surfacing as a failed component lookup.
func validateJailRelativeName(clean string) error {
	if clean == "" || clean == "." || clean == ".." || strings.ContainsRune(clean, '\x00') {
		return fmt.Errorf("jail name is empty or relative")
	}
	if filepath.IsAbs(clean) {
		return fmt.Errorf("jail name must be relative")
	}
	for _, component := range strings.Split(clean, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("jail name contains a relative component")
		}
	}
	if len(clean) > 2048 {
		return fmt.Errorf("jail name exceeds 2048 bytes")
	}
	return nil
}

// removeBeneath unlinks a file inside root with the same component-wise
// resolution, so a removal cannot be redirected through a symlinked parent either.
func removeBeneath(root, name string) error {
	clean := filepath.Clean(strings.TrimSpace(name))
	if err := validateJailRelativeName(clean); err != nil {
		return err
	}
	parent := filepath.Dir(clean)
	base := filepath.Base(clean)
	if parent == "." {
		parent = ""
	}
	dirfd, err := openAbsoluteJailRoot(root, false)
	if err != nil {
		return fmt.Errorf("open jail root: %w", err)
	}
	for _, component := range strings.Split(strings.Trim(parent, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := syscall.Openat(dirfd, component, syscall.O_DIRECTORY|jailStepFlags|syscall.O_RDONLY, 0)
		syscall.Close(dirfd)
		if openErr != nil {
			return fmt.Errorf("resolve %q inside the jail: %w", component, openErr)
		}
		dirfd = next
	}
	err = syscall.Unlinkat(dirfd, base)
	syscall.Close(dirfd)
	if err != nil {
		return fmt.Errorf("remove %q inside the jail: %w", base, err)
	}
	return nil
}

// renameBeneath atomically replaces one file with another inside root, resolving
// the directory through the same component-wise walk. Rename does not follow a
// symbolic link at the destination, it replaces the link itself, so the decoy
// cannot be redirected by a link placed at the target name either.
func renameBeneath(root, oldName, newName string) error {
	cleanOld := filepath.Clean(strings.TrimSpace(oldName))
	cleanNew := filepath.Clean(strings.TrimSpace(newName))
	if err := validateJailRelativeName(cleanOld); err != nil {
		return err
	}
	if err := validateJailRelativeName(cleanNew); err != nil {
		return err
	}
	if filepath.Dir(cleanOld) != filepath.Dir(cleanNew) {
		return fmt.Errorf("jail rename must stay inside one directory")
	}
	dirfd, err := openJailDir(root, filepath.Dir(cleanOld))
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)
	if err := syscall.Renameat(dirfd, filepath.Base(cleanOld), dirfd, filepath.Base(cleanNew)); err != nil {
		return fmt.Errorf("replace %q inside the jail: %w", cleanNew, err)
	}
	return nil
}

// openJailDir walks to a directory inside root and returns its descriptor. The
// relative path may be "." for the root itself.
func openJailDir(root, relative string) (int, error) {
	dirfd, err := openAbsoluteJailRoot(root, false)
	if err != nil {
		return -1, fmt.Errorf("open jail root: %w", err)
	}
	trimmed := strings.Trim(filepath.Clean(strings.TrimSpace(relative)), "/")
	if trimmed == "" || trimmed == "." {
		return dirfd, nil
	}
	for _, component := range strings.Split(trimmed, "/") {
		if component == "" || component == "." || component == ".." {
			syscall.Close(dirfd)
			return -1, fmt.Errorf("jail directory contains a relative component")
		}
		next, openErr := syscall.Openat(dirfd, component, syscall.O_DIRECTORY|jailStepFlags|syscall.O_RDONLY, 0)
		syscall.Close(dirfd)
		if openErr != nil {
			return -1, fmt.Errorf("resolve %q inside the jail: %w", component, openErr)
		}
		dirfd = next
	}
	return dirfd, nil
}

// jailPathIsSymlinked reports whether a component of an existing path is a
// symbolic link. It is used for diagnostics only; enforcement is openBeneath.
func jailPathIsSymlinked(root, name string) bool {
	clean := filepath.Clean(strings.TrimSpace(name))
	if validateJailRelativeName(clean) != nil {
		return false
	}
	current := root
	for _, component := range strings.Split(clean, "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}
