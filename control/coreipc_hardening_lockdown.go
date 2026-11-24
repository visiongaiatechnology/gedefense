// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func validSysctlToken(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func (c *CoreClient) SysctlGet(key string) (string, error) {
	if !validSysctlKey(key) {
		return "", errors.New("invalid sysctl key")
	}
	value, err := c.command("SYSCTL_GET", key)
	if err != nil {
		return "", err
	}
	if !validSysctlToken(value) {
		return "", errors.New("core returned an invalid sysctl value")
	}
	return value, nil
}

func (c *CoreClient) SysctlCompareSet(key, expected, desired string) error {
	if !validSysctlKey(key) || !validSysctlToken(expected) || !validSysctlToken(desired) {
		return errors.New("invalid sysctl compare-set request")
	}
	state, err := c.command("SYSCTL_SET", key, expected, desired)
	if err != nil {
		return err
	}
	if state != desired {
		return fmt.Errorf("core returned unexpected sysctl state %q", state)
	}
	return nil
}

func validHardeningState(value string) bool {
	switch value {
	case "absent", "linux-server-balanced", "astraeaos-workstation-strict", "astraeaos-cis-l1":
		return true
	}
	const prefix = "astraeaos-custom-"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(value, prefix)
	// M5.1 grew the closed control catalogue from 10 to 21 bits, so a custom mask
	// needs up to 6 hex characters now. The value still has to be a non-zero subset
	// of the shipped catalogue ceiling.
	if len(suffix) < 4 || len(suffix) > 8 {
		return false
	}
	decoded, err := strconv.ParseUint(suffix, 16, 32)
	if err != nil || decoded == 0 {
		return false
	}
	return decoded&^uint64(sysctlControlMaskCeiling()) == 0
}

func (c *CoreClient) HardeningProfileState() (string, error) {
	state, err := c.command("HARDENING_GET")
	if err != nil {
		return "", err
	}
	if !validHardeningState(state) {
		return "", errors.New("core returned an invalid persistent hardening state")
	}
	return state, nil
}

func (c *CoreClient) HardeningProfileCompareSet(expected, desired string) error {
	if !validHardeningState(expected) || !validHardeningState(desired) {
		return errors.New("invalid persistent hardening compare-set request")
	}
	state, err := c.command("HARDENING_SET", expected, desired)
	if err != nil {
		return err
	}
	if state != desired {
		return fmt.Errorf("core returned unexpected persistent hardening state %q", state)
	}
	return nil
}

func validSysctlKey(key string) bool {
	if key == "" || len(key) > 96 || strings.HasPrefix(key, ".") || strings.HasSuffix(key, ".") {
		return false
	}
	for _, character := range key {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '.' {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------ lockdown
//
// POINT 5 / P5-T3 (docs/POINT5-LOCKDOWN.md §5, ABI-3): the privileged core owns
// the LOCKDOWN_STATE word, the USB/Thunderbolt policy, the broker SIGSTOP and
// the hardening allowlist. The unprivileged control plane reaches them only
// through the authenticated VGT3 channel; everything below is additive and a
// core that predates the command family answers "ERR unknown command", which
// maps onto ErrLockdownUnavailable so the caller reports a capability fact
// instead of an XDR outage.
//
// Wire vocabulary (closed tokens, no free text, no paths), finalized with the
// P5-T2 core implementation):
//   mode   = "locked" | "unlocked"
//   source = "manual" | "uevent" | "policy" | "timer"  (§3 LOCKDOWN_SOURCE_*)
//   reason = "manual" | "usb-unknown" | "tb-unknown" | "screen-lock" | "tamper"
//            | "xdr-critical" | "boot-trust-drift" | "policy"
//   phase  = "net" | "usb" | "tb" | "hardening" | "brokers" | "cells"
//            | "sessions" | "dm"
//   state  = "off" | "armed" | "active" | "degraded"
//   list   = a bounded csv in a fixed order, or "-" for the empty list
// Every answer is ≤2048 B (already enforced by parseCoreResponse/payload bound).

const (
	lockdownCoreVersion = "lockdown-v1"
	// maxLockdownEventsPerResponse mirrors the core's own batch ceiling (§5).
	maxLockdownEventsPerResponse = 16
	// maxLockdownPayloadBytes bounds the text-wire payload before it is split.
	maxLockdownPayloadBytes = 2048
	// lockdownEpochChars is the documented 8-hex u32 epoch.
	lockdownEpochChars = 8
	// lockdownMaxUnsupportedPhases bounds the unsupported csv of an answer.
	lockdownMaxUnsupportedPhases = maxLockdownEventsPerResponse + 8
)

// CoreLockdownStatus mirrors the LOCKDOWN_STATUS payload (§5):
// state=<off|armed|active|degraded>;epoch=<8hex>;mode=<locked|unlocked>;
// flags=<u8>;phases=<csv-applied>;unsupported=<csv>.
type CoreLockdownStatus struct {
	State       string
	Epoch       string
	Mode        string
	Flags       uint8
	Applied     []string
	Unsupported []string
}

// CoreLockdownTriggerResult mirrors the LOCKDOWN_TRIGGER payload:
// triggered:<epoch8>;phases=<applied-csv>;unsupported=<csv>.
type CoreLockdownTriggerResult struct {
	Epoch       string
	Applied     []string
	Unsupported []string
}

// CoreLockdownHealth mirrors the fixed six-counter LOCKDOWN_HEALTH payload
// "net_drops:witness_passes:uevent_events:usb_blocks:tb_blocks:broker_frozen".
type CoreLockdownHealth struct {
	NetDrops      uint64 `json:"net_drops"`
	WitnessPasses uint64 `json:"witness_passes"`
	UeventEvents  uint64 `json:"uevent_events"`
	USBBlocks     uint64 `json:"usb_blocks"`
	TBBlocks      uint64 `json:"tb_blocks"`
	BrokerFrozen  uint64 `json:"broker_frozen"`
}

// CoreLockdownEvent is one decoded LOCKDOWN_EVENTS record (text wire §5,
// Alles-oder-Nichts). Only closed tokens are carried; there is no path, IP or
// human free text on the wire.
type CoreLockdownEvent struct {
	Seq       uint64
	Timestamp uint64
	Source    uint8
	Reason    uint8
	Phase     uint8
	Outcome   uint8
}

// CoreLockdownPhaseResult is the LOCKDOWN_PHASE answer:
// applied:<phase> | unsupported:<phase>:<reason> | failed:<phase>:<reason>.
type CoreLockdownPhaseResult struct {
	Phase  string
	Status string
	Reason string
}

// lockdownCommand issues one LOCKDOWN_* command and classifies the
// backwards-compatible "unknown command" rejection as ErrLockdownUnavailable.
func (c *CoreClient) lockdownCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrLockdownUnavailable, err)
		}
		return "", err
	}
	if len(response) > maxLockdownPayloadBytes {
		return "", errors.New("core returned an oversized lockdown payload")
	}
	return response, nil
}

func lockdownModeToken(mode string) (string, error) {
	switch mode {
	case lockdownModeLocked, lockdownModeUnlocked:
		return mode, nil
	}
	return "", errors.New("lockdown mode must be locked or unlocked")
}

func lockdownSourceToken(source string) (string, error) {
	if !lockdownSourceValid(source) {
		return "", errors.New("lockdown source token is not in the closed vocabulary")
	}
	return source, nil
}

func lockdownReasonToken(reason string) (string, error) {
	// POINT 4 / P4-T2: the frozen P5 core ABI has no separate witness reason. A
	// proven ledger equivocation is tampering with the evidence chain, so it is
	// reported to the kernel under that reason; the local evidence and the event
	// keep the precise "witness-equivocation" spelling.
	if reason == lockdownReasonWitnessEquivocation {
		return lockdownReasonTamper, nil
	}
	if !lockdownReasonValid(reason) {
		return "", errors.New("lockdown reason token is not in the closed vocabulary")
	}
	return reason, nil
}

// validLockdownEpoch accepts exactly the documented 8 hex characters.
func validLockdownEpoch(value string) bool {
	if len(value) != lockdownEpochChars {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func parseLockdownUint8(field string) (uint8, error) {
	if field == "" || len(field) > 3 {
		return 0, errors.New("core returned an invalid lockdown flags byte")
	}
	value, err := strconv.ParseUint(field, 10, 8)
	if err != nil {
		return 0, errors.New("core returned an invalid lockdown flags byte")
	}
	return uint8(value), nil
}

// parseCoreLockdownTrigger decodes "triggered:<epoch8>;phases=<csv>;unsupported=<csv>".
func parseCoreLockdownTrigger(payload string) (CoreLockdownTriggerResult, error) {
	if len(payload) == 0 || len(payload) > maxLockdownPayloadBytes {
		return CoreLockdownTriggerResult{}, errors.New("core returned an oversized lockdown trigger answer")
	}
	fields := strings.Split(payload, ";")
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "triggered:") ||
		!strings.HasPrefix(fields[1], "phases=") || !strings.HasPrefix(fields[2], "unsupported=") {
		return CoreLockdownTriggerResult{}, errors.New("core returned a malformed lockdown trigger answer")
	}
	epoch := strings.TrimPrefix(fields[0], "triggered:")
	if !validLockdownEpoch(epoch) {
		return CoreLockdownTriggerResult{}, errors.New("core returned an invalid lockdown trigger epoch")
	}
	applied, err := parseLockdownCSV(strings.TrimPrefix(fields[1], "phases="), "phase")
	if err != nil {
		return CoreLockdownTriggerResult{}, err
	}
	unsupported, err := parseLockdownCSV(strings.TrimPrefix(fields[2], "unsupported="), "phase")
	if err != nil {
		return CoreLockdownTriggerResult{}, err
	}
	return CoreLockdownTriggerResult{Epoch: epoch, Applied: applied, Unsupported: unsupported}, nil
}

// parseCoreLockdownHealth decodes the fixed six-counter payload.
func parseCoreLockdownHealth(payload string) (CoreLockdownHealth, error) {
	if len(payload) == 0 || len(payload) > maxLockdownPayloadBytes {
		return CoreLockdownHealth{}, errors.New("core returned an oversized lockdown health payload")
	}
	fields := strings.Split(payload, ":")
	if len(fields) != 6 {
		return CoreLockdownHealth{}, errors.New("core returned malformed lockdown health")
	}
	counters := make([]uint64, len(fields))
	for index, field := range fields {
		value, err := parseStyxUint(field, 64)
		if err != nil {
			return CoreLockdownHealth{}, errors.New("core returned invalid lockdown health counters")
		}
		counters[index] = value
	}
	return CoreLockdownHealth{
		NetDrops: counters[0], WitnessPasses: counters[1], UeventEvents: counters[2],
		USBBlocks: counters[3], TBBlocks: counters[4], BrokerFrozen: counters[5],
	}, nil
}

// parseCoreLockdownPhase decodes the operator single-phase answer.
func parseCoreLockdownPhase(payload string) (CoreLockdownPhaseResult, error) {
	if len(payload) == 0 || len(payload) > maxLockdownPayloadBytes {
		return CoreLockdownPhaseResult{}, errors.New("core returned an oversized lockdown phase answer")
	}
	fields := strings.Split(payload, ":")
	if len(fields) < 2 || len(fields) > 3 {
		return CoreLockdownPhaseResult{}, errors.New("core returned a malformed lockdown phase answer")
	}
	phase := fields[1]
	if !lockdownCorePhaseValid(phase) && phase != lockdownPhaseNameCells {
		return CoreLockdownPhaseResult{}, errors.New("core returned an unknown lockdown phase")
	}
	result := CoreLockdownPhaseResult{Phase: phase, Status: fields[0]}
	switch fields[0] {
	case "applied":
		if len(fields) != 2 {
			return CoreLockdownPhaseResult{}, errors.New("core returned an unexpected lockdown phase reason")
		}
	case "unsupported", "failed":
		if len(fields) != 3 || fields[2] == "" || len(fields[2]) > 96 || !protocolFieldValid(fields[2]) {
			return CoreLockdownPhaseResult{}, errors.New("core returned an invalid lockdown phase reason")
		}
		result.Reason = fields[2]
	default:
		return CoreLockdownPhaseResult{}, errors.New("core returned an unknown lockdown phase status")
	}
	return result, nil
}

// LockdownVersion negotiates the lockdown ABI. A pre-POINT5 core yields
// ErrLockdownUnavailable.
func (c *CoreClient) LockdownVersion() (string, error) {
	version, err := c.lockdownCommand("LOCKDOWN_VERSION")
	if err != nil {
		return "", err
	}
	if version != lockdownCoreVersion {
		return "", fmt.Errorf("core returned unsupported lockdown version %q", version)
	}
	return version, nil
}

// LockdownEpoch returns the 8-hex epoch that changes on every core start and
// every trigger (§5).
func (c *CoreClient) LockdownEpoch() (string, error) {
	epoch, err := c.lockdownCommand("LOCKDOWN_EPOCH")
	if err != nil {
		return "", err
	}
	if !validLockdownEpoch(epoch) {
		return "", errors.New("core returned an invalid lockdown epoch")
	}
	return epoch, nil
}

// LockdownArm applies the arm mode, the closed reason token and the four
// documented LOCKDOWN_TRIGGER flags. It returns the core epoch from the
// idempotent "armed:<epoch8>"/"armed-unchanged:<epoch8>" answer.
func (c *CoreClient) LockdownArm(mode, reason string, flags uint8) (string, error) {
	modeToken, err := lockdownModeToken(mode)
	if err != nil {
		return "", err
	}
	reasonToken, err := lockdownReasonToken(reason)
	if err != nil {
		return "", err
	}
	payload, err := c.lockdownCommand("LOCKDOWN_ARM", modeToken, reasonToken, strconv.FormatUint(uint64(flags), 10))
	if err != nil {
		return "", err
	}
	for _, prefix := range []string{"armed:", "armed-unchanged:"} {
		if strings.HasPrefix(payload, prefix) {
			epoch := strings.TrimPrefix(payload, prefix)
			if !validLockdownEpoch(epoch) {
				return "", errors.New("core returned an invalid lockdown arm epoch")
			}
			return epoch, nil
		}
	}
	return "", errors.New("core returned an unexpected lockdown arm answer")
}

// LockdownSetMode changes only the arm mode (LOCKDOWN_SET_MODE) without a
// trigger. It is the idempotent companion of LOCKDOWN_ARM.
func (c *CoreClient) LockdownSetMode(mode string) error {
	modeToken, err := lockdownModeToken(mode)
	if err != nil {
		return err
	}
	payload, err := c.lockdownCommand("LOCKDOWN_SET_MODE", modeToken)
	if err != nil {
		return err
	}
	if payload != "applied" {
		return fmt.Errorf("core returned unexpected lockdown set-mode answer %q", payload)
	}
	return nil
}

// LockdownEvents drains one bounded lifecycle-event batch plus the saturating
// ring-drop delta since the previous poll.
func (c *CoreClient) LockdownEvents() ([]CoreLockdownEvent, uint64, error) {
	payload, err := c.lockdownCommand("LOCKDOWN_EVENTS")
	if err != nil {
		return nil, 0, err
	}
	return parseCoreLockdownEvents(payload)
}

// LockdownHealth reports the six kernel-side lockdown counters.
func (c *CoreClient) LockdownHealth() (CoreLockdownHealth, error) {
	payload, err := c.lockdownCommand("LOCKDOWN_HEALTH")
	if err != nil {
		return CoreLockdownHealth{}, err
	}
	return parseCoreLockdownHealth(payload)
}

// LockdownPhase applies or releases one single phase for an operator test.
func (c *CoreClient) LockdownPhase(phase string, on bool) (CoreLockdownPhaseResult, error) {
	if !lockdownCorePhaseValid(phase) && phase != lockdownPhaseNameCells {
		return CoreLockdownPhaseResult{}, errors.New("lockdown phase is not in the closed vocabulary")
	}
	state := "off"
	if on {
		state = "on"
	}
	payload, err := c.lockdownCommand("LOCKDOWN_PHASE", phase, state)
	if err != nil {
		return CoreLockdownPhaseResult{}, err
	}
	return parseCoreLockdownPhase(payload)
}
