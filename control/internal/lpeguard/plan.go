// Package lpeguard is Module D of GeDefense 6.1.0: the local-privilege-
// escalation kill-chain defence plan.
//
// It renders three plans - the per-cgroup socket-deny flag word, the StyX
// web-ingress-only egress profile and the kernel-hardening baseline - and
// reports capability and refusal honestly. Nothing in this package applies
// itself: the main package hands the plans to the existing CELL_POLICY_SET,
// StyX settings and hardening transaction paths.
package lpeguard

import (
	"errors"
	"sort"
)

// Socket-deny flag bits. Bit 0 stays the pre-existing CELL_LSM_DENY_NON_UNIX_SOCKET
// and is never redefined here; the 6.1.0 increment adds bits 1..6 exactly as the
// Rust contract in the blueprint.
const (
	// BitNonUnixSocket is the bit the Cell LSM policy has always carried.
	BitNonUnixSocket uint8 = 1 << 0
	// BitAFPacket blocks creation of AF_PACKET sockets (raw traffic capture).
	BitAFPacket uint8 = 1 << 1
	// BitAFTIPC blocks AF_TIPC sockets.
	BitAFTIPC uint8 = 1 << 2
	// BitAFVSOCK blocks AF_VSOCK (host<->guest) sockets.
	BitAFVSOCK uint8 = 1 << 3
	// BitSCTP blocks SCTP socket creation.
	BitSCTP uint8 = 1 << 4
	// BitDCCP blocks DCCP socket creation.
	BitDCCP uint8 = 1 << 5
	// BitRDS blocks RDS socket creation.
	BitRDS uint8 = 1 << 6

	// DenyMask is every administrable deny bit of the 6.1.0 flag word.
	DenyMask = BitAFPacket | BitAFTIPC | BitAFVSOCK | BitSCTP | BitDCCP | BitRDS
)

// DenyBitNames maps a flag bit to its published deny name.
var denyBitNames = []struct {
	Bit  uint8
	Name string
}{
	{BitAFPacket, "AF_PACKET"},
	{BitSCTP, "SCTP"},
	{BitDCCP, "DCCP"},
	{BitRDS, "RDS"},
	{BitAFTIPC, "AF_TIPC"},
	{BitAFVSOCK, "AF_VSOCK"},
}

// DenySettings is the administrable subset of the socket policy.
type DenySettings struct {
	AFPacket bool
	AFTIPC   bool
	AFVSOCK  bool
	SCTP     bool
	DCCP     bool
	RDS      bool
}

// Flags renders the deny bits as the single flag word sent to CELL_POLICY_SET.
// The published deny names follow the blueprint order.
func Flags(settings DenySettings) (uint8, []string) {
	flags := uint8(0)
	names := make([]string, 0, len(denyBitNames))
	enabled := map[uint8]bool{
		BitAFPacket: settings.AFPacket,
		BitSCTP:     settings.SCTP,
		BitDCCP:     settings.DCCP,
		BitRDS:      settings.RDS,
		BitAFTIPC:   settings.AFTIPC,
		BitAFVSOCK:  settings.AFVSOCK,
	}
	for _, entry := range denyBitNames {
		if enabled[entry.Bit] {
			flags |= entry.Bit
		}
	}
	for _, entry := range denyBitNames {
		if enabled[entry.Bit] {
			names = append(names, entry.Name)
		}
	}
	return flags, names
}

// ValidateFlags rejects a flag word outside the administrable mask (defence in
// depth: the main package builds it from settings, never from a request).
func ValidateFlags(flags uint8) error {
	if flags&^uint8(DenyMask|BitNonUnixSocket) != 0 {
		return errors.New("socket policy flag word carries an unknown bit")
	}
	return nil
}

// PolicyWorker is one classified web-worker cgroup the policy can target.
type PolicyWorker struct {
	CgroupID uint64
	Comm     string
	UID      uint32
}

// SocketPolicyEntry is one published socket-policy plan row.
type SocketPolicyEntry struct {
	CgroupID uint64   `json:"cgroup_id"`
	Comm     string   `json:"comm"`
	Deny     []string `json:"deny"`
	Applied  bool     `json:"applied"`
	Flags    uint8    `json:"-"`
}

// BuildSocketPolicyPlan renders one row per worker cgroup. A zero cgroup id can
// never be targeted: it would apply the policy host-wide.
func BuildSocketPolicyPlan(workers []PolicyWorker, settings DenySettings) []SocketPolicyEntry {
	flags, names := Flags(settings)
	entries := make([]SocketPolicyEntry, 0, len(workers))
	seen := make(map[uint64]struct{}, len(workers))
	for _, worker := range workers {
		if worker.CgroupID == 0 {
			continue
		}
		if _, dup := seen[worker.CgroupID]; dup {
			continue
		}
		seen[worker.CgroupID] = struct{}{}
		entries = append(entries, SocketPolicyEntry{
			CgroupID: worker.CgroupID, Comm: worker.Comm,
			Deny: append([]string(nil), names...), Flags: flags,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CgroupID < entries[j].CgroupID })
	return entries
}
