// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"strings"
)

// V6.3.0 AP-3: authenticated transport for the 8-domain cross-view verifier
// (`CROSS_VIEW_*`).
//
// The privileged core compares independent kernel/userland views of the same
// state (BPF id iterator vs get-fd-by-id, NETLINK_SOCK_DIAG vs /proc/net, /proc
// listing vs stat, /proc/modules vs /sys/module, package DB vs /proc/maps, bpffs
// pins, tap ring, BPF object names). This file only frames and validates the
// VGT3 records; XDR semantics live in xdr_crossview.go.
//
// It is a strict transport: every answer is parsed all-or-nothing with bounded
// counters and payloads and a closed domain/kind/severity vocabulary, and a core
// that predates the family answers "unknown command", which maps onto
// ErrCrossViewUnavailable (a capability fact, not an XDR outage).

// Core-side bounds (mirror `rust/gedefense-core/src/cross_view.rs`).
const (
	maxCrossViewEventsPerResponse = 16
	maxCrossViewPayloadBytes      = 4096
	maxCrossViewRecordBytes       = 220
	maxCrossViewStatusBytes       = 512
	maxCrossViewReportBytes       = 2048
	crossViewStatusFieldCount     = 13
	crossViewReportReasonTokens   = 8
)

// Cross-view domains (`CROSS_VIEW_DOMAIN_*`).
const (
	CrossViewDomainEBPFIDGap     uint8 = 1
	CrossViewDomainSocketView    uint8 = 2
	CrossViewDomainProcessView   uint8 = 3
	CrossViewDomainModuleTrace   uint8 = 4
	CrossViewDomainLibraryView   uint8 = 5
	CrossViewDomainPinView       uint8 = 6
	CrossViewDomainNetlinkFilter uint8 = 7
	CrossViewDomainMapNameView   uint8 = 8
	CrossViewDomainMax           uint8 = CrossViewDomainMapNameView
)

// Cross-view contradiction/observation kinds (`CROSS_VIEW_KIND_*`).
const (
	CrossViewKindHiddenProg      uint8 = 1
	CrossViewKindHiddenMap       uint8 = 2
	CrossViewKindHiddenLink      uint8 = 3
	CrossViewKindLinkTamper      uint8 = 4
	CrossViewKindHiddenSocket    uint8 = 5
	CrossViewKindPortlessRawTap  uint8 = 6
	CrossViewKindHiddenProcess   uint8 = 7
	CrossViewKindLKMHidden       uint8 = 8
	CrossViewKindFtraceHook      uint8 = 9
	CrossViewKindLibraryMismatch uint8 = 10
	CrossViewKindPinMismatch     uint8 = 11
	CrossViewKindRawTapFilter    uint8 = 12
	CrossViewKindMax             uint8 = CrossViewKindRawTapFilter
)

// Cross-view severities (`CROSS_VIEW_SEVERITY_*`).
const (
	CrossViewSeverityInfo     uint8 = 1
	CrossViewSeverityMedium   uint8 = 2
	CrossViewSeverityHigh     uint8 = 3
	CrossViewSeverityCritical uint8 = 4
)

// Cross-view actions (`CROSS_VIEW_ACTION_*`). Both are observe-only.
const (
	CrossViewActionAudit   uint8 = 1
	CrossViewActionObserve uint8 = 2
)

// Detail codes (`CROSS_VIEW_DETAIL_*`; meaning is kind-specific).
const (
	CrossViewDetailIDGap         uint32 = 1
	CrossViewDetailNameHeuristic uint32 = 2
	CrossViewDetailNetlinkOnly   uint32 = 1
	CrossViewDetailProcfsOnly    uint32 = 2
	CrossViewDetailTapCreate     uint32 = 1
	CrossViewDetailTapFilter     uint32 = 2
	CrossViewDetailTapCBPF       uint32 = 3
	CrossViewDetailTapSuspicious uint32 = 4
	CrossViewDetailStatFailed    uint32 = 1
	CrossViewDetailListingMiss   uint32 = 2
	CrossViewDetailProcOnly      uint32 = 1
	CrossViewDetailSysfsOnly     uint32 = 2
	CrossViewDetailLibForeign    uint32 = 1
	CrossViewDetailLibDeleted    uint32 = 2
	CrossViewDetailPinMissing    uint32 = 1
	CrossViewDetailPinReplaced   uint32 = 2
	CrossViewDetailPinUnexpected uint32 = 3
	CrossViewDetailPinDangling   uint32 = 4
	// Module records carry the raw kernel taint word in the wire `dev` field;
	// these are the O (bit 12), E/unsigned (bit 13) and forced-load (bit 1) bits.
	crossViewTaintMask              uint32 = (1 << 1) | (1 << 12) | (1 << 13)
	crossViewModuleDetail                  = uint32(0x3)
	crossViewStatusPackageDBUnknown        = "unknown"
)

// Package-DB capability tokens (`CROSS_VIEW_PKGDB_*`).
const (
	CrossViewPkgDBDebian      = "debian"
	CrossViewPkgDBArch        = "arch"
	CrossViewPkgDBUnsupported = "unsupported"
	CrossViewPkgDBDegraded    = "degraded"
)

// ErrCrossViewUnavailable marks a core without the CROSS_VIEW_* command family.
var ErrCrossViewUnavailable = errors.New("cross-view capability unavailable")

// CoreCrossViewStatus is the strict projection of CROSS_VIEW_STATUS.
type CoreCrossViewStatus struct {
	Enabled        bool
	Scans          uint64
	Contradictions uint64
	Events         uint64
	Drops          uint64
	Domains        uint64
	LastScanAgeMS  uint64
	Tap            bool
	Mods           bool
	Procs          bool
	BPF            bool
	PkgDB          string
	Trace          bool
}

// CoreCrossViewEvent is one bounded cross-view record.
type CoreCrossViewEvent struct {
	TsNS       uint64
	Domain     uint8
	Kind       uint8
	Severity   uint8
	PID        int
	UID        uint32
	Dev        uint32
	Ino        uint64
	DetailCode uint32
	// Detail is the stable kind label (HIDDEN_PROG, PORTLESS_RAW_TAP, ...).
	Detail string
	// Comm is the bounded task name/label carried by the record.
	Comm string
}

// CoreCrossViewReport is the strict projection of CROSS_VIEW_REPORT text.
type CoreCrossViewReport struct {
	BoundsOK       bool
	Domains        uint64
	Contradictions uint64
	Events         uint64
	Scans          uint64
	Drops          uint64
	LastScanAgeMS  uint64
	Tap            bool
	Mods           bool
	Procs          bool
	BPF            bool
	PkgDB          string
	Trace          bool
	Pins           uint64
	Reasons        []string
}

// CrossViewDomainName returns the stable operator label for one domain.
func CrossViewDomainName(domain uint8) string {
	switch domain {
	case CrossViewDomainEBPFIDGap:
		return "ebpf-id-gap"
	case CrossViewDomainSocketView:
		return "socket-view"
	case CrossViewDomainProcessView:
		return "process-view"
	case CrossViewDomainModuleTrace:
		return "module-trace-view"
	case CrossViewDomainLibraryView:
		return "library-view"
	case CrossViewDomainPinView:
		return "pin-view"
	case CrossViewDomainNetlinkFilter:
		return "netlink-filter"
	case CrossViewDomainMapNameView:
		return "map-name-view"
	default:
		return "unknown"
	}
}

// CrossViewKindName returns the stable operator label for one kind.
func CrossViewKindName(kind uint8) string {
	switch kind {
	case CrossViewKindHiddenProg:
		return "HIDDEN_PROG"
	case CrossViewKindHiddenMap:
		return "HIDDEN_MAP"
	case CrossViewKindHiddenLink:
		return "HIDDEN_LINK"
	case CrossViewKindLinkTamper:
		return "LINK_TAMPER"
	case CrossViewKindHiddenSocket:
		return "HIDDEN_SOCKET"
	case CrossViewKindPortlessRawTap:
		return "PORTLESS_RAW_TAP"
	case CrossViewKindHiddenProcess:
		return "HIDDEN_PROCESS"
	case CrossViewKindLKMHidden:
		return "LKM_HIDDEN"
	case CrossViewKindFtraceHook:
		return "FTRACE_HOOK"
	case CrossViewKindLibraryMismatch:
		return "LIBRARY_MISMATCH"
	case CrossViewKindPinMismatch:
		return "PIN_MISMATCH"
	case CrossViewKindRawTapFilter:
		return "RAW_TAP_FILTER"
	default:
		return "unknown"
	}
}

// CrossViewKindDomainValid is the closed domain/kind cross product shared with
// the Rust decoder; a record outside it is rejected, never repaired.
func CrossViewKindDomainValid(domain, kind uint8) bool {
	switch domain {
	case CrossViewDomainEBPFIDGap:
		return kind == CrossViewKindHiddenProg || kind == CrossViewKindHiddenMap ||
			kind == CrossViewKindHiddenLink || kind == CrossViewKindLinkTamper
	case CrossViewDomainSocketView:
		return kind == CrossViewKindHiddenSocket || kind == CrossViewKindPortlessRawTap
	case CrossViewDomainProcessView:
		return kind == CrossViewKindHiddenProcess
	case CrossViewDomainModuleTrace:
		return kind == CrossViewKindLKMHidden || kind == CrossViewKindFtraceHook
	case CrossViewDomainLibraryView:
		return kind == CrossViewKindLibraryMismatch
	case CrossViewDomainPinView:
		return kind == CrossViewKindPinMismatch
	case CrossViewDomainNetlinkFilter:
		return kind == CrossViewKindRawTapFilter
	case CrossViewDomainMapNameView:
		return kind == CrossViewKindHiddenProg || kind == CrossViewKindHiddenMap
	default:
		return false
	}
}

func (c *CoreClient) crossViewCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrCrossViewUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// CrossViewStatus queries the verifier health.
func (c *CoreClient) CrossViewStatus() (CoreCrossViewStatus, error) {
	response, err := c.crossViewCommand("CROSS_VIEW_STATUS")
	if err != nil {
		return CoreCrossViewStatus{}, err
	}
	return parseCoreCrossViewStatus(response)
}

// CrossViewReport forces one bounded scan and returns the report text.
func (c *CoreClient) CrossViewReport() (string, error) {
	response, err := c.crossViewCommand("CROSS_VIEW_REPORT")
	if err != nil {
		return "", err
	}
	if _, err := parseCoreCrossViewReport(response); err != nil {
		return "", err
	}
	return response, nil
}

// CrossViewEvents drains one bounded batch of cross-view records. The second
// return value is the saturating drop delta since the previous drain.
func (c *CoreClient) CrossViewEvents() ([]CoreCrossViewEvent, uint64, error) {
	response, err := c.crossViewCommand("CROSS_VIEW_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreCrossViewEvents(response)
}

// parseCoreCrossViewEvents decodes "empty" or "<dropped>|<record>,<record>…".
func parseCoreCrossViewEvents(response string) ([]CoreCrossViewEvent, uint64, error) {
	if len(response) > maxCrossViewPayloadBytes {
		return nil, 0, errors.New("core returned an oversized cross-view event batch")
	}
	if response == "empty" {
		return nil, 0, nil
	}
	if response == "" || strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return nil, 0, errors.New("core returned a malformed cross-view batch")
	}
	droppedText, recordsText, ok := strings.Cut(response, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed cross-view batch")
	}
	dropped, err := parseCrossViewUint(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid cross-view drop counter")
	}
	if recordsText == "" {
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > maxCrossViewEventsPerResponse {
		return nil, 0, errors.New("core returned too many cross-view events")
	}
	events := make([]CoreCrossViewEvent, 0, len(records))
	for _, record := range records {
		if len(record) == 0 || len(record) > maxCrossViewRecordBytes {
			return nil, 0, errors.New("core returned an oversized or empty cross-view record")
		}
		event, err := parseCoreCrossViewEvent(record)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	return events, dropped, nil
}
