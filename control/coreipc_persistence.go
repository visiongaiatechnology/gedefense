// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"strings"
)

// V6.3.0 AP-5: authenticated transport for the persistence/peripheral family
// (`PERSIST_GUARD_*` / `PERSIST_BASELINE`).
//
// The privileged core owns the watched integrity roots, the BTF/tracefs
// resolved offsets, the in-memory SHA-256 baseline and the kernel LSM/TP
// observations. This file is the strict transport: every answer is parsed
// all-or-nothing with bounded counters/payloads and closed class/kind/action
// sets, and a core that predates the family answers "unknown command", which
// maps onto ErrPersistenceUnavailable (a capability fact, not an XDR outage).
//
// Wire vocabulary (additive):
//
//	PERSIST_GUARD_STATUS  -> enabled=..:attached=..:paths=..:execs=..:devices=..:
//	                         secrets=..:pkgdb=..:roots=..:drifted=..:
//	                         baseline_at_ms=..:events=..:drops=..:sessions=..:
//	                         idlehint=..
//	PERSIST_GUARD_EVENTS  -> empty | <dropped>|<record>[,<record>...]
//	PERSIST_GUARD_SET <0|1> -> armed | disarmed
//	PERSIST_BASELINE      -> roots=..:verified=..:drifted=..:at_ms=..
//
// `attached` is a documented bitmask (hook attachment, offsets/package-database
// readiness, session-view availability and a read-failure indicator), not a
// boolean: an operator must be able to tell a fully working sensor from a
// partially attached one.
//
// Event text record (twelve fields):
// `<ts>:<pid>:<tgid>:<uid>:<class>:<kind>:<action>:<detail_code>:<dev>:<ino>:<comm_hex>:<detail_hex>`.
// `comm` is printable ASCII; `detail` is kind-specific (memory scrape:
// `readv`/`writev`; ptrace: decimal mode; every other kind: empty).

const (
	maxPersistenceEventsPerResponse = 16
	maxPersistencePayloadBytes      = 4096
	maxPersistenceRecordBytes       = 320
	maxPersistenceStatusBytes       = 600
)

// Persistence path classes (mirrors `gedefense-common::PERSIST_CLASS_*`).
const (
	PersistenceClassUnspecified      uint8 = 0
	PersistenceClassLDPreload        uint8 = 1
	PersistenceClassLDConf           uint8 = 2
	PersistenceClassLDSO             uint8 = 3
	PersistenceClassTLS              uint8 = 4
	PersistenceClassPAM              uint8 = 5
	PersistenceClassSystemdGenerator uint8 = 6
	PersistenceClassSystemdDropin    uint8 = 7
	PersistenceClassUdev             uint8 = 8
	PersistenceClassAuthorizedKeys   uint8 = 9
	PersistenceClassSSHRC            uint8 = 10
	PersistenceClassShellProfile     uint8 = 11
	PersistenceClassDeviceCamera     uint8 = 20
	PersistenceClassDeviceMic        uint8 = 21
	PersistenceClassDeviceEvdev      uint8 = 22
	PersistenceClassDeviceCapture    uint8 = 23
	PersistenceClassSecretSSH        uint8 = 30
	PersistenceClassSecretGNUPG      uint8 = 31
	PersistenceClassSecretCloud      uint8 = 32
	PersistenceClassSecretBrowser    uint8 = 33
	PersistenceClassSecretKeyring    uint8 = 34
)

// Persistence event kinds (mirrors `gedefense-common::PERSIST_KIND_*`).
const (
	PersistenceKindIntegrityWrite uint8 = 1
	PersistenceKindLibraryMmap    uint8 = 2
	PersistenceKindPeripheralOpen uint8 = 3
	PersistenceKindSecretOpen     uint8 = 4
	PersistenceKindMemoryScrape   uint8 = 5
	PersistenceKindPtraceAccess   uint8 = 6
	PersistenceKindDrift          uint8 = 7
	PersistenceKindBaseline       uint8 = 8
)

// Persistence event actions (mirrors `gedefense-common::PERSIST_ACTION_*`).
const (
	PersistenceActionAudit   uint8 = 1
	PersistenceActionDeny    uint8 = 2
	PersistenceActionObserve uint8 = 3
)

// Detail codes / drift reasons (mirrors `gedefense-common::PERSIST_DETAIL_*`).
const (
	PersistenceDetailAccMask       uint32 = 0x3
	PersistenceDetailAccUnknown    uint32 = 0xffff_ffff
	PersistenceDetailSessionKnown  uint32 = 1 << 0
	PersistenceDetailSessionActive uint32 = 1 << 1
	PersistenceDriftContent        uint32 = 1
	PersistenceDriftMissing        uint32 = 2
	PersistenceDriftAppeared       uint32 = 3
	PersistenceDriftReplaced       uint32 = 4
)

// Status `attached` bitmask (mirrors `gedefense-core`).
const (
	PersistenceHookFileOpen          uint64 = 1 << 0
	PersistenceHookMmap              uint64 = 1 << 1
	PersistenceHookPtrace            uint64 = 1 << 2
	PersistenceHookReadv             uint64 = 1 << 3
	PersistenceHookWritev            uint64 = 1 << 4
	PersistenceStatusIdentityOffsets uint64 = 1 << 5
	PersistenceStatusPkgdbReady      uint64 = 1 << 6
	PersistenceStatusReadvOffsets    uint64 = 1 << 7
	PersistenceStatusWritevOffsets   uint64 = 1 << 8
	PersistenceStatusReadFailures    uint64 = 1 << 9
	PersistenceStatusSessionsKnown   uint64 = 1 << 10
	PersistenceStatusAttachedMaskMax uint64 = (1 << 11) - 1
)

// ErrPersistenceUnavailable marks a core without the PERSIST_* command family.
var ErrPersistenceUnavailable = errors.New("persistence-guard capability unavailable")

// CorePersistenceBaseline is the strict projection of PERSIST_BASELINE:
// `roots=<captured>:verified=<checked>:drifted=<changes found>:at_ms=<unix ms>`.
type CorePersistenceBaseline struct {
	Roots    uint64
	Verified uint64
	Drifted  uint64
	AtMS     uint64
}

// CorePersistenceStatus is the strict projection of PERSIST_GUARD_STATUS: the
// fourteen documented `key=value` fields plus the derived hook projection.
type CorePersistenceStatus struct {
	Enabled      bool
	AttachedMask uint64
	Attached     bool
	HookFileOpen bool
	HookMmap     bool
	HookPtrace   bool
	HookReadv    bool
	HookWritev   bool
	// IdentityOffsetsOK is only true when the file/inode/super offsets and the
	// `file_open` arity were resolved from vmlinux BTF.
	IdentityOffsetsOK bool
	// PkgdbReady is only true when the package database produced a usable
	// inode->package reverse index; `Pkgdb` without it is a database *format*
	// fact, not an ownership claim.
	PkgdbReady       bool
	ReadvOffsetsOK   bool
	WritevOffsetsOK  bool
	ReadFailuresSeen bool
	SessionsKnown    bool
	Paths            uint64
	Execs            uint64
	Devices          uint64
	Secrets          uint64
	Pkgdb            string
	Roots            uint64
	Drifted          uint64
	BaselineAtMS     uint64
	Events           uint64
	Drops            uint64
	SessionsTotal    uint64
	SessionsActive   uint64
	SessionsInactive uint64
	IdleHint         string
}

// CorePersistenceEvent is one decoded persistence/peripheral observation.
type CorePersistenceEvent struct {
	TsNS       uint64
	PID        int
	TGID       int
	UID        uint32
	Class      uint8
	Kind       uint8
	Action     uint8
	DetailCode uint32
	Dev        uint32
	Ino        uint64
	Comm       string
	// Detail is the decoded printable payload (`readv`/`writev` for a memory
	// scrape, the decimal ptrace mode for a ptrace record, "" otherwise).
	Detail string
}

// persistenceCommand runs one command of the PERSIST_* family and maps an
// "unknown command" rejection onto ErrPersistenceUnavailable so an old core is a
// capability fact instead of an outage.
func (c *CoreClient) persistenceCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrPersistenceUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// PersistenceStatus queries the persistence/peripheral guard health.
func (c *CoreClient) PersistenceStatus() (CorePersistenceStatus, error) {
	response, err := c.persistenceCommand("PERSIST_GUARD_STATUS")
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	return parseCorePersistenceStatus(response)
}

// PersistenceEvents drains one bounded batch; the second return value is the
// saturating drop delta reported by the core for this drain.
func (c *CoreClient) PersistenceEvents() ([]CorePersistenceEvent, uint64, error) {
	response, err := c.persistenceCommand("PERSIST_GUARD_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCorePersistenceEvents(response)
}

// PersistenceSet arms (1) or disarms (0) the observe-only guard.
func (c *CoreClient) PersistenceSet(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	response, err := c.persistenceCommand("PERSIST_GUARD_SET", value)
	if err != nil {
		return err
	}
	switch response {
	case "armed", "disarmed":
		return nil
	default:
		return fmt.Errorf("core returned unexpected persistence set state %q", response)
	}
}

// PersistenceBaseline re-verifies and re-captures the userspace integrity roots.
// A malformed answer is rejected instead of being forwarded to the operator.
func (c *CoreClient) PersistenceBaseline() (string, error) {
	response, err := c.persistenceCommand("PERSIST_BASELINE")
	if err != nil {
		return "", err
	}
	if _, parseErr := parsePersistenceBaseline(response); parseErr != nil {
		return "", parseErr
	}
	return response, nil
}

// parseCorePersistenceEvents decodes "empty" or
// "<dropped>|<record>,<record>...". All-or-nothing: one malformed record rejects
// the whole batch so the caller never acts on a partially parsed evidence set.
func parseCorePersistenceEvents(response string) ([]CorePersistenceEvent, uint64, error) {
	if len(response) > maxPersistencePayloadBytes {
		return nil, 0, errors.New("core returned an oversized persistence event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed persistence batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed persistence batch")
	}
	dropped, err := parsePersistenceUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid persistence drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxPersistenceEventsPerResponse {
		return nil, 0, errors.New("core returned too many persistence events")
	}
	events := make([]CorePersistenceEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxPersistenceRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty persistence record")
		}
		event, parseErr := parseCorePersistenceEvent(record)
		if parseErr != nil {
			return nil, 0, parseErr
		}
		events = append(events, event)
	}
	return events, dropped, nil
}
