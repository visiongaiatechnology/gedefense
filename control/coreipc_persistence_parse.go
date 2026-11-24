package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func parsePersistenceUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized persistence counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal persistence counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range persistence counter")
	}
	return value, nil
}

// parsePersistenceBaseline validates the bounded PERSIST_BASELINE answer. The
// key order is part of the contract (the core always emits roots, verified,
// drifted, at_ms); a reordered/duplicate/unknown key is rejected.
func parsePersistenceBaseline(response string) (CorePersistenceBaseline, error) {
	if len(response) > maxPersistenceStatusBytes || response == "" ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CorePersistenceBaseline{}, errors.New("core returned a malformed persistence baseline answer")
	}
	keys := []string{"roots", "verified", "drifted", "at_ms"}
	fields := strings.Split(response, ":")
	if len(fields) != len(keys) {
		return CorePersistenceBaseline{}, errors.New("core returned a malformed persistence baseline answer")
	}
	values := make([]uint64, len(keys))
	for index, field := range fields {
		name, valueText, ok := strings.Cut(field, "=")
		if !ok || name != keys[index] || valueText == "" {
			return CorePersistenceBaseline{}, errors.New("core returned an unexpected persistence baseline field")
		}
		value, err := parsePersistenceUint(valueText, 64)
		if err != nil {
			return CorePersistenceBaseline{}, errors.New("core returned an invalid persistence baseline counter")
		}
		values[index] = value
	}
	return CorePersistenceBaseline{
		Roots:    values[0],
		Verified: values[1],
		Drifted:  values[2],
		AtMS:     values[3],
	}, nil
}

// parseCorePersistenceStatus decodes the exactly-fourteen `key=value` status
// fields. Key order is part of the contract; unknown/duplicate/reordered keys
// and out-of-range flag masks are rejected instead of silently ignored.
func parseCorePersistenceStatus(response string) (CorePersistenceStatus, error) {
	if response == "" || len(response) > maxPersistenceStatusBytes ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CorePersistenceStatus{}, errors.New("core returned a malformed persistence status")
	}
	keys := []string{
		"enabled", "attached", "paths", "execs", "devices", "secrets", "pkgdb",
		"roots", "drifted", "baseline_at_ms", "events", "drops", "sessions", "idlehint",
	}
	fields := strings.Split(response, ":")
	if len(fields) != len(keys) {
		return CorePersistenceStatus{}, errors.New("core returned a malformed persistence status")
	}
	for index, field := range fields {
		name, valueText, ok := strings.Cut(field, "=")
		if !ok || name != keys[index] || valueText == "" {
			return CorePersistenceStatus{}, errors.New("core returned an unexpected persistence status field")
		}
	}
	numeric := func(index int, bits int) (uint64, error) {
		_, valueText, _ := strings.Cut(fields[index], "=")
		value, err := parsePersistenceUint(valueText, bits)
		if err != nil {
			return 0, errors.New("core returned invalid persistence status counters")
		}
		return value, nil
	}
	enabled, err := numeric(0, 1)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	attached, err := numeric(1, 64)
	if err != nil || attached > PersistenceStatusAttachedMaskMax {
		return CorePersistenceStatus{}, errors.New("core returned an invalid persistence status attachment mask")
	}
	paths, err := numeric(2, 32)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	execs, err := numeric(3, 32)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	devices, err := numeric(4, 32)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	secrets, err := numeric(5, 32)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	_, pkgdbText, _ := strings.Cut(fields[6], "=")
	switch pkgdbText {
	case "dpkg", "pacman", "both", "unsupported":
	default:
		return CorePersistenceStatus{}, errors.New("core returned an unknown package-database state")
	}
	roots, err := numeric(7, 32)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	drifted, err := numeric(8, 64)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	baselineAtMS, err := numeric(9, 64)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	events, err := numeric(10, 64)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	drops, err := numeric(11, 64)
	if err != nil {
		return CorePersistenceStatus{}, err
	}
	_, sessionsText, _ := strings.Cut(fields[12], "=")
	sessionsTotal, sessionsActive, sessionsInactive, sessionsErr := parsePersistenceSessions(sessionsText)
	if sessionsErr != nil {
		return CorePersistenceStatus{}, sessionsErr
	}
	_, idlehint, _ := strings.Cut(fields[13], "=")
	// The only honest answer today: logind's IdleHint is a D-Bus property, not a
	// file. A real source requires an explicit ABI addition, never a guess.
	if idlehint != "unavailable" {
		return CorePersistenceStatus{}, errors.New("core returned an unsupported idle-hint source")
	}
	return CorePersistenceStatus{
		Enabled:           enabled == 1,
		AttachedMask:      attached,
		Attached:          attached&(PersistenceHookFileOpen|PersistenceHookMmap|PersistenceHookPtrace|PersistenceHookReadv|PersistenceHookWritev) != 0,
		HookFileOpen:      attached&PersistenceHookFileOpen != 0,
		HookMmap:          attached&PersistenceHookMmap != 0,
		HookPtrace:        attached&PersistenceHookPtrace != 0,
		HookReadv:         attached&PersistenceHookReadv != 0,
		HookWritev:        attached&PersistenceHookWritev != 0,
		IdentityOffsetsOK: attached&PersistenceStatusIdentityOffsets != 0,
		PkgdbReady:        attached&PersistenceStatusPkgdbReady != 0,
		ReadvOffsetsOK:    attached&PersistenceStatusReadvOffsets != 0,
		WritevOffsetsOK:   attached&PersistenceStatusWritevOffsets != 0,
		ReadFailuresSeen:  attached&PersistenceStatusReadFailures != 0,
		SessionsKnown:     attached&PersistenceStatusSessionsKnown != 0,
		Paths:             paths,
		Execs:             execs,
		Devices:           devices,
		Secrets:           secrets,
		Pkgdb:             pkgdbText,
		Roots:             roots,
		Drifted:           drifted,
		BaselineAtMS:      baselineAtMS,
		Events:            events,
		Drops:             drops,
		SessionsTotal:     sessionsTotal,
		SessionsActive:    sessionsActive,
		SessionsInactive:  sessionsInactive,
		IdleHint:          idlehint,
	}, nil
}

// parsePersistenceSessions decodes `total/active/inactive` with the invariant
// active+inactive==total (the core derives inactive from the same sample).
func parsePersistenceSessions(text string) (uint64, uint64, uint64, error) {
	parts := strings.Split(text, "/")
	if len(parts) != 3 {
		return 0, 0, 0, errors.New("core returned a malformed persistence session sample")
	}
	values := make([]uint64, 3)
	for index, part := range parts {
		value, err := parsePersistenceUint(part, 32)
		if err != nil {
			return 0, 0, 0, errors.New("core returned an invalid persistence session counter")
		}
		values[index] = value
	}
	if values[1] > values[0] || values[2] > values[0] || values[1]+values[2] != values[0] {
		return 0, 0, 0, errors.New("core returned an inconsistent persistence session sample")
	}
	return values[0], values[1], values[2], nil
}

func parseCorePersistenceEvent(record string) (CorePersistenceEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 12 {
		return CorePersistenceEvent{}, errors.New("core returned a malformed persistence event")
	}
	tsNS, tsErr := parsePersistenceUint(fields[0], 64)
	pid, pidErr := parsePersistenceUint(fields[1], 31)
	tgid, tgidErr := parsePersistenceUint(fields[2], 31)
	uid, uidErr := parsePersistenceUint(fields[3], 32)
	class, classErr := parsePersistenceUint(fields[4], 8)
	kind, kindErr := parsePersistenceUint(fields[5], 8)
	action, actionErr := parsePersistenceUint(fields[6], 8)
	detailCode, detailCodeErr := parsePersistenceUint(fields[7], 32)
	dev, devErr := parsePersistenceUint(fields[8], 32)
	ino, inoErr := parsePersistenceUint(fields[9], 64)
	if tsErr != nil || pidErr != nil || tgidErr != nil || uidErr != nil || classErr != nil ||
		kindErr != nil || actionErr != nil || detailCodeErr != nil || devErr != nil || inoErr != nil {
		return CorePersistenceEvent{}, errors.New("core returned invalid persistence event fields")
	}
	if tsNS == 0 || pid == 0 || tgid == 0 {
		return CorePersistenceEvent{}, errors.New("core returned a persistence event without a producer identity")
	}
	if !persistenceActionKnown(uint8(action)) {
		return CorePersistenceEvent{}, errors.New("core returned an unknown persistence action")
	}
	if !persistenceKindKnown(uint8(kind)) {
		return CorePersistenceEvent{}, errors.New("core returned an unknown persistence event kind")
	}
	if !persistenceClassKindValid(uint8(class), uint8(kind)) {
		return CorePersistenceEvent{}, errors.New("core returned an impossible persistence class/kind pair")
	}
	identityRequired := uint8(kind) != PersistenceKindMemoryScrape &&
		uint8(kind) != PersistenceKindPtraceAccess &&
		uint8(kind) != PersistenceKindBaseline
	if identityRequired {
		if dev == 0 || ino == 0 {
			return CorePersistenceEvent{}, errors.New("core returned a persistence event without the watched identity")
		}
	} else if dev != 0 || ino != 0 {
		return CorePersistenceEvent{}, errors.New("core returned an identity-less persistence event with a file identity")
	}
	if uint8(kind) == PersistenceKindIntegrityWrite {
		if detailCode != uint64(PersistenceDetailAccUnknown) && detailCode > uint64(PersistenceDetailAccMask) {
			return CorePersistenceEvent{}, errors.New("core returned an invalid persistence access-intent code")
		}
	}
	if uint8(kind) == PersistenceKindPeripheralOpen {
		if detailCode&^uint64(PersistenceDetailSessionKnown|PersistenceDetailSessionActive) != 0 {
			return CorePersistenceEvent{}, errors.New("core returned unknown persistence session flags")
		}
	}
	if uint8(kind) == PersistenceKindDrift {
		switch uint32(detailCode) {
		case PersistenceDriftContent, PersistenceDriftMissing, PersistenceDriftAppeared, PersistenceDriftReplaced:
		default:
			return CorePersistenceEvent{}, errors.New("core returned an unknown persistence drift reason")
		}
	}
	comm := ""
	if fields[10] != "" {
		if len(fields[10]) > 32 {
			return CorePersistenceEvent{}, errors.New("core returned a malformed persistence comm")
		}
		decoded, err := decodeStyxHex(fields[10], 16)
		if err != nil || len(decoded) == 0 {
			return CorePersistenceEvent{}, errors.New("core returned a malformed persistence comm")
		}
		for _, character := range decoded {
			if character < 0x20 || character > 0x7e {
				return CorePersistenceEvent{}, errors.New("core returned a persistence comm with rejected characters")
			}
		}
		comm = string(decoded)
	}
	if comm == "" {
		return CorePersistenceEvent{}, errors.New("core returned a persistence event without a task name")
	}
	detail := ""
	if fields[11] != "" {
		if len(fields[11]) > 16 {
			return CorePersistenceEvent{}, errors.New("core returned a malformed persistence detail")
		}
		decoded, err := decodeStyxHex(fields[11], 8)
		if err != nil {
			return CorePersistenceEvent{}, errors.New("core returned a malformed persistence detail")
		}
		for _, character := range decoded {
			if character < 0x20 || character > 0x7e {
				return CorePersistenceEvent{}, errors.New("core returned a persistence detail with rejected characters")
			}
		}
		detail = string(decoded)
	}
	switch uint8(kind) {
	case PersistenceKindMemoryScrape:
		if detail != "" && detail != "readv" && detail != "writev" {
			return CorePersistenceEvent{}, errors.New("core returned an unknown process_vm direction label")
		}
	case PersistenceKindPtraceAccess:
		if detail != "" {
			if len(detail) > 7 {
				return CorePersistenceEvent{}, errors.New("core returned an oversized ptrace mode label")
			}
			for index := 0; index < len(detail); index++ {
				if detail[index] < '0' || detail[index] > '9' {
					return CorePersistenceEvent{}, errors.New("core returned a non-decimal ptrace mode label")
				}
			}
		}
	default:
		if detail != "" {
			return CorePersistenceEvent{}, errors.New("core returned a detail payload the event kind cannot carry")
		}
	}
	return CorePersistenceEvent{
		TsNS:       tsNS,
		PID:        int(pid),
		TGID:       int(tgid),
		UID:        uint32(uid),
		Class:      uint8(class),
		Kind:       uint8(kind),
		Action:     uint8(action),
		DetailCode: uint32(detailCode),
		Dev:        uint32(dev),
		Ino:        ino,
		Comm:       comm,
		Detail:     detail,
	}, nil
}

func persistenceClassKnown(class uint8) bool {
	switch class {
	case PersistenceClassLDPreload, PersistenceClassLDConf, PersistenceClassLDSO,
		PersistenceClassTLS, PersistenceClassPAM, PersistenceClassSystemdGenerator,
		PersistenceClassSystemdDropin, PersistenceClassUdev, PersistenceClassAuthorizedKeys,
		PersistenceClassSSHRC, PersistenceClassShellProfile, PersistenceClassDeviceCamera,
		PersistenceClassDeviceMic, PersistenceClassDeviceEvdev, PersistenceClassDeviceCapture,
		PersistenceClassSecretSSH, PersistenceClassSecretGNUPG, PersistenceClassSecretCloud,
		PersistenceClassSecretBrowser, PersistenceClassSecretKeyring:
		return true
	default:
		return false
	}
}

func persistenceKindKnown(kind uint8) bool {
	return kind >= PersistenceKindIntegrityWrite && kind <= PersistenceKindBaseline
}

func persistenceActionKnown(action uint8) bool {
	switch action {
	case PersistenceActionAudit, PersistenceActionDeny, PersistenceActionObserve:
		return true
	default:
		return false
	}
}

func persistenceClassIsIntegrity(class uint8) bool {
	return class >= PersistenceClassLDPreload && class <= PersistenceClassShellProfile
}

func persistenceClassIsDevice(class uint8) bool {
	return class >= PersistenceClassDeviceCamera && class <= PersistenceClassDeviceCapture
}

func persistenceClassIsSecret(class uint8) bool {
	return class >= PersistenceClassSecretSSH && class <= PersistenceClassSecretKeyring
}

// persistenceClassKindValid is the closed class/kind matrix mirrored by the Rust
// decoder: an event that does not match it cannot have been produced.
func persistenceClassKindValid(class uint8, kind uint8) bool {
	switch kind {
	case PersistenceKindIntegrityWrite:
		return persistenceClassIsIntegrity(class)
	case PersistenceKindLibraryMmap:
		return class == PersistenceClassLDSO
	case PersistenceKindPeripheralOpen:
		return persistenceClassIsDevice(class)
	case PersistenceKindSecretOpen:
		return persistenceClassIsSecret(class)
	case PersistenceKindMemoryScrape, PersistenceKindPtraceAccess, PersistenceKindBaseline:
		return class == PersistenceClassUnspecified
	case PersistenceKindDrift:
		return persistenceClassIsIntegrity(class)
	default:
		return false
	}
}

// PersistenceClassName is the operator-facing stable name of one path class.
func PersistenceClassName(class uint8) string {
	switch class {
	case PersistenceClassUnspecified:
		return "unspecified"
	case PersistenceClassLDPreload:
		return "ld.so.preload"
	case PersistenceClassLDConf:
		return "ld.so.conf"
	case PersistenceClassLDSO:
		return "linker"
	case PersistenceClassTLS:
		return "linker-tls"
	case PersistenceClassPAM:
		return "pam"
	case PersistenceClassSystemdGenerator:
		return "systemd-generator"
	case PersistenceClassSystemdDropin:
		return "systemd-dropin"
	case PersistenceClassUdev:
		return "udev"
	case PersistenceClassAuthorizedKeys:
		return "authorized-keys"
	case PersistenceClassSSHRC:
		return "sshrc"
	case PersistenceClassShellProfile:
		return "shell-profile"
	case PersistenceClassDeviceCamera:
		return "device-camera"
	case PersistenceClassDeviceMic:
		return "device-mic"
	case PersistenceClassDeviceEvdev:
		return "device-evdev"
	case PersistenceClassDeviceCapture:
		return "device-capture-socket"
	case PersistenceClassSecretSSH:
		return "secret-ssh"
	case PersistenceClassSecretGNUPG:
		return "secret-gnupg"
	case PersistenceClassSecretCloud:
		return "secret-cloud"
	case PersistenceClassSecretBrowser:
		return "secret-browser"
	case PersistenceClassSecretKeyring:
		return "secret-keyring"
	default:
		return fmt.Sprintf("class-%d", class)
	}
}

// PersistenceKindName is the operator-facing stable name of one event kind.
func PersistenceKindName(kind uint8) string {
	switch kind {
	case PersistenceKindIntegrityWrite:
		return "integrity-write"
	case PersistenceKindLibraryMmap:
		return "library-mmap"
	case PersistenceKindPeripheralOpen:
		return "peripheral-open"
	case PersistenceKindSecretOpen:
		return "secret-open"
	case PersistenceKindMemoryScrape:
		return "memory-scrape"
	case PersistenceKindPtraceAccess:
		return "ptrace-access"
	case PersistenceKindDrift:
		return "content-drift"
	case PersistenceKindBaseline:
		return "baseline"
	default:
		return fmt.Sprintf("kind-%d", kind)
	}
}

// PersistenceActionName is the operator-facing stable name of one action.
func PersistenceActionName(action uint8) string {
	switch action {
	case PersistenceActionAudit:
		return "audit"
	case PersistenceActionDeny:
		return "deny"
	case PersistenceActionObserve:
		return "observe"
	default:
		return fmt.Sprintf("action-%d", action)
	}
}
