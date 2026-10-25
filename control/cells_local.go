// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Local cgroup-v2 cell registry.
//
// Gaia Cells normally arrive with the AstraeaOS runtime, which owns the
// versioned control socket, the per-cell cgroups and the network leases. A
// GeDefense host without AstraeaOS still runs the control plane's cell surface:
// the local substrate is the unified cgroup v2 hierarchy, where each cell is one
// directory below /sys/fs/cgroup/vgt-cells with a cgroup.freeze attribute.
//
// This registry is deliberately smaller than the runtime: it lists local cells,
// freezes and unfreezes them through cgroup.freeze, and reports their state.
// Network leases and snapshots stay with the runtime (or with the operator's own
// tooling); the registry says so explicitly instead of faking success.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	defaultLocalCellsRoot = "/sys/fs/cgroup/vgt-cells"
	localCellsLogicalRoot = "/sys/fs/cgroup/vgt-cells"
	localCellsMaxEntries  = 4096
	localCellFreezeMax    = 8
)

type localCellRegistry struct {
	root string
}

func newLocalCellRegistry(root string) localCellRegistry {
	if strings.TrimSpace(root) == "" {
		root = defaultLocalCellsRoot
	}
	return localCellRegistry{root: filepath.Clean(root)}
}

// available reports whether the local substrate exists. It is a platform
// property: false means this host has no local cells, not that a module failed.
func (r localCellRegistry) available() bool {
	info, err := os.Lstat(r.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return true
}

type localCellEntry struct {
	name string
	dir  string
	cell GaiaCell
}

func (r localCellRegistry) entries() ([]localCellEntry, error) {
	dirEntries, err := os.ReadDir(r.root)
	if err != nil {
		return nil, err
	}
	entries := make([]localCellEntry, 0, len(dirEntries))
	now := time.Now().UTC()
	for _, entry := range dirEntries {
		if len(entries) >= localCellsMaxEntries {
			return nil, errors.New("local cell registry exceeds its bounded entry count")
		}
		if !entry.IsDir() || !validLocalCellName(entry.Name()) {
			continue
		}
		dir := filepath.Join(r.root, entry.Name())
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("local cell directory is not a regular directory")
		}
		cell, err := localCellIdentity(entry.Name(), now)
		if err != nil {
			return nil, err
		}
		cell.State = localCellState(dir)
		if err := validateGaiaCell(cell); err != nil {
			return nil, fmt.Errorf("local cell %q violates the cell contract: %w", entry.Name(), err)
		}
		entries = append(entries, localCellEntry{name: entry.Name(), dir: dir, cell: cell})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries, nil
}

func (r localCellRegistry) list() ([]GaiaCell, error) {
	entries, err := r.entries()
	if err != nil {
		return nil, err
	}
	cells := make([]GaiaCell, 0, len(entries))
	for _, entry := range entries {
		cells = append(cells, entry.cell)
	}
	return cells, nil
}

func (r localCellRegistry) owns(uuid string) bool {
	if !validCellUUID(uuid) {
		return false
	}
	entries, err := r.entries()
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.cell.UUID == uuid {
			return true
		}
	}
	return false
}

// action applies the allowlisted operations the local substrate can honestly
// perform. Network isolation and runtime snapshots are refused with the exact
// reason instead of being reported as applied.
func (r localCellRegistry) action(command, uuid string, generation uint64, cgroupID uint64) error {
	entries, err := r.entries()
	if err != nil {
		return err
	}
	var target *localCellEntry
	for index := range entries {
		if entries[index].cell.UUID == uuid {
			target = &entries[index]
			break
		}
	}
	if target == nil {
		return errors.New("local cell is not present in the registry")
	}
	if target.cell.Generation != generation || target.cell.CgroupID != cgroupID {
		return errors.New("local cell identity changed; re-read the registry before acting")
	}
	switch command {
	case "FREEZE":
		return writeLocalCellFreeze(target.dir, "1")
	case "UNFREEZE":
		return writeLocalCellFreeze(target.dir, "0")
	case "SNAPSHOT_EVIDENCE":
		if _, err := readBoundedLocalCellFile(filepath.Join(target.dir, "cgroup.freeze"), localCellFreezeMax); err != nil {
			return errors.New("local cell exposes no readable freeze state for evidence")
		}
		if _, err := readBoundedLocalCellFile(filepath.Join(target.dir, "cgroup.events"), 4096); err != nil {
			return errors.New("local cell exposes no readable cgroup events for evidence")
		}
		return nil
	case "REVOKE_NETWORK", "RESTORE_NETWORK":
		return errors.New("network isolation requires the Gaia Cells runtime; the local cgroup v2 registry cannot revoke network access")
	default:
		return errors.New("local cell action is not allowlisted")
	}
}

// localCellIdentity derives the stable, contract-valid identity for one local
// cell. UUID, generation and cgroup id are deterministic functions of the
// directory name, so two registries on the same host agree and a forged
// identifier cannot address another cell.
func localCellIdentity(name string, now time.Time) (GaiaCell, error) {
	if !validLocalCellName(name) {
		return GaiaCell{}, errors.New("local cell name is invalid")
	}
	identity := sha256.Sum256([]byte("vgt-gedefense-local-cell:" + name))
	policy := sha256.Sum256([]byte("vgt-gedefense-local-cell-policy:" + name))
	cgroup := sha256.Sum256([]byte("vgt-gedefense-local-cell-cgroup:" + name))
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		identity[0:4], identity[4:6], identity[6:8], identity[8:10], identity[10:16])
	// Generation is a deterministic identity token, not a clock reading: it must
	// stay stable across listings so an operator (or the transaction engine) can
	// address the cell it just read, and change only when the directory name does.
	generation := binary.BigEndian.Uint64(identity[16:24])
	if generation == 0 {
		generation = 1
	}
	cgroupID := binary.BigEndian.Uint64(cgroup[:8])
	if cgroupID == 0 {
		cgroupID = 1
	}
	return GaiaCell{
		Version: cellIdentityVersion, UUID: uuid, Label: name,
		Profile: "local", Class: "workspace",
		CgroupPath: filepath.ToSlash(filepath.Join(localCellsLogicalRoot, name)),
		CgroupID:   cgroupID, PolicyDigest: hex.EncodeToString(policy[:]),
		Generation: generation, State: "running", NetworkState: "none",
		ObservedAt: now,
	}, nil
}

func validLocalCellName(name string) bool {
	if len(name) < 1 || len(name) > 32 || name[0] == '.' || name[0] == '-' {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func localCellState(dir string) string {
	raw, err := readBoundedLocalCellFile(filepath.Join(dir, "cgroup.freeze"), localCellFreezeMax)
	if err != nil {
		return "running"
	}
	if strings.TrimSpace(string(raw)) == "1" {
		return "frozen"
	}
	return "running"
}

func writeLocalCellFreeze(dir, value string) error {
	target := filepath.Join(dir, "cgroup.freeze")
	info, err := os.Lstat(target)
	if err != nil {
		return errors.New("local cell exposes no cgroup.freeze attribute")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("local cell freeze attribute is not a regular file")
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(value); err != nil {
		return err
	}
	return file.Close()
}

func readBoundedLocalCellFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > max {
		return nil, errors.New("local cell evidence file is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func boundedCellsReason(reason string) string {
	const max = 200
	reason = strings.TrimSpace(reason)
	if len(reason) > max {
		return reason[:max]
	}
	return reason
}

// localSocketPresent reports whether the external runtime socket exists without
// connecting to it, so a missing installation is reported as a platform fact
// while an installed-but-unauthenticated runtime keeps its authentication error.
func localSocketPresent(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}
