package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// 6.1.0 Module B: privileged-core client for the worker crash-storm sensor.
//
// The core command family is additive. A core built before 6.1.0 answers
// "unknown command"; that is a capability fact (ErrWorkerGuardUnavailable), not
// a transport failure, exactly like the StyX and TitanExec families.

var (
	// ErrWorkerGuardUnavailable reports a core without the 6.1.0 command family.
	ErrWorkerGuardUnavailable = errors.New("worker guard kernel surface unavailable")
	// ErrWorkerGuardInactive reports maps that exist but a tracepoint that is not
	// attached. Enforcement is never claimed on top of it.
	ErrWorkerGuardInactive = errors.New("worker guard tracepoint is not attached")
)

const workerGuardMaxCommBytes = 15

// WorkerCrashSample is one bounded crash record drained from the kernel ring.
type WorkerCrashSample struct {
	PID      uint32
	UID      uint32
	GID      uint32
	CgroupID uint64
	Signal   uint32
	ExitCode int32
	Comm     string
}

// WorkerGuardCoreStatus is the parsed `WORKER_GUARD_STATUS` answer.
type WorkerGuardCoreStatus struct {
	Enabled   bool
	Attached  bool
	Comms     int
	UIDs      int
	Emitted   uint64
	Dropped   uint64
	RawStatus string
}

// workerGuardSupported is true once the core answered one command of the family.
func (c *CoreClient) workerGuardCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrWorkerGuardUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// WorkerGuardSet arms or disarms the kernel sensor. It returns the fresh status
// line so the caller can report the effective state without a second round trip.
func (c *CoreClient) WorkerGuardSet(enabled bool) (WorkerGuardCoreStatus, error) {
	flag := "0"
	if enabled {
		flag = "1"
	}
	response, err := c.workerGuardCommand("WORKER_GUARD_SET", flag)
	if err != nil {
		return WorkerGuardCoreStatus{}, err
	}
	return parseWorkerGuardCoreStatus(response)
}

// WorkerGuardCommAdd registers one 1..15 byte worker comm name.
func (c *CoreClient) WorkerGuardCommAdd(comm string) error {
	return c.workerGuardRegistry("WORKER_GUARD_COMM_ADD", comm)
}

// WorkerGuardCommDel removes one registered comm; deletion is idempotent.
func (c *CoreClient) WorkerGuardCommDel(comm string) error {
	return c.workerGuardRegistry("WORKER_GUARD_COMM_DEL", comm)
}

// WorkerGuardUIDAdd registers one worker UID.
func (c *CoreClient) WorkerGuardUIDAdd(uid uint32) error {
	return c.workerGuardRegistry("WORKER_GUARD_UID_ADD", strconv.FormatUint(uint64(uid), 10))
}

// WorkerGuardUIDDel removes one registered UID.
func (c *CoreClient) WorkerGuardUIDDel(uid uint32) error {
	return c.workerGuardRegistry("WORKER_GUARD_UID_DEL", strconv.FormatUint(uint64(uid), 10))
}

func (c *CoreClient) workerGuardRegistry(command, value string) error {
	if value == "" || len(value) > workerGuardMaxCommBytes || strings.ContainsRune(value, 0) {
		return errors.New("worker guard registry value must be 1..15 non-NUL bytes")
	}
	response, err := c.workerGuardCommand(command, value)
	if err != nil {
		return err
	}
	// The core answers with the fresh status line on success. Parsing it keeps
	// a malformed answer visible instead of silently accepting it.
	if _, err := parseWorkerGuardCoreStatus(response); err != nil {
		return err
	}
	return nil
}

// WorkerGuardEvents drains at most one bounded batch. "empty" is a successful
// empty batch, not an error.
func (c *CoreClient) WorkerGuardEvents() ([]WorkerCrashSample, error) {
	response, err := c.workerGuardCommand("WORKER_GUARD_EVENTS")
	if err != nil {
		return nil, err
	}
	if response == "empty" {
		return nil, nil
	}
	lines := strings.Split(response, "\n")
	if len(lines) > 16 {
		return nil, errors.New("core returned too many worker crash records")
	}
	samples := make([]WorkerCrashSample, 0, len(lines))
	for _, line := range lines {
		sample, err := parseWorkerCrashSample(line)
		if err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	return samples, nil
}

// WorkerGuardStatus reads the kernel-side sensor state without mutating it.
func (c *CoreClient) WorkerGuardStatus() (WorkerGuardCoreStatus, error) {
	response, err := c.workerGuardCommand("WORKER_GUARD_STATUS")
	if err != nil {
		return WorkerGuardCoreStatus{}, err
	}
	return parseWorkerGuardCoreStatus(response)
}

func parseWorkerCrashSample(line string) (WorkerCrashSample, error) {
	fields := strings.Split(line, ":")
	if len(fields) != 7 {
		return WorkerCrashSample{}, errors.New("core returned a malformed worker crash record")
	}
	parseUint := func(raw string, bits int) (uint64, error) {
		if raw == "" || len(raw) > 20 || strings.Trim(raw, "0123456789") != "" {
			return 0, errors.New("core returned a malformed worker crash integer")
		}
		return strconv.ParseUint(raw, 10, bits)
	}
	pid, err := parseUint(fields[0], 32)
	if err != nil {
		return WorkerCrashSample{}, err
	}
	uid, err := parseUint(fields[1], 32)
	if err != nil {
		return WorkerCrashSample{}, err
	}
	gid, err := parseUint(fields[2], 32)
	if err != nil {
		return WorkerCrashSample{}, err
	}
	cgroup, err := parseUint(fields[3], 64)
	if err != nil {
		return WorkerCrashSample{}, err
	}
	signal, err := parseUint(fields[4], 32)
	if err != nil {
		return WorkerCrashSample{}, err
	}
	exit, err := strconv.ParseInt(fields[5], 10, 32)
	if err != nil {
		return WorkerCrashSample{}, errors.New("core returned a malformed worker exit code")
	}
	commBytes, err := hex.DecodeString(fields[6])
	if err != nil || len(commBytes) == 0 || len(commBytes) > 16 {
		return WorkerCrashSample{}, errors.New("core returned a malformed worker comm")
	}
	for _, value := range commBytes {
		if value < 0x20 || value == 0x7f {
			return WorkerCrashSample{}, errors.New("core returned a non-printable worker comm")
		}
	}
	if pid == 0 || signal > 255 {
		return WorkerCrashSample{}, errors.New("core returned a malformed worker crash record")
	}
	return WorkerCrashSample{
		PID:      uint32(pid),
		UID:      uint32(uid),
		GID:      uint32(gid),
		CgroupID: cgroup,
		Signal:   uint32(signal),
		ExitCode: int32(exit),
		Comm:     string(commBytes),
	}, nil
}

func parseWorkerGuardCoreStatus(response string) (WorkerGuardCoreStatus, error) {
	status := WorkerGuardCoreStatus{RawStatus: response}
	if response == "" || len(response) > 512 {
		return status, errors.New("core returned an empty or oversized worker guard status")
	}
	seen := map[string]bool{}
	for _, field := range strings.Fields(response) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return status, errors.New("core returned a malformed worker guard status")
		}
		if seen[key] {
			return status, errors.New("core returned a duplicate worker guard field")
		}
		seen[key] = true
		switch key {
		case "enabled", "attached":
			if value != "0" && value != "1" {
				return status, errors.New("core returned a malformed worker guard flag")
			}
			if key == "enabled" {
				status.Enabled = value == "1"
			} else {
				status.Attached = value == "1"
			}
		case "comms", "uids":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 || parsed > 1024 {
				return status, errors.New("core returned a malformed worker guard registry count")
			}
			if key == "comms" {
				status.Comms = parsed
			} else {
				status.UIDs = parsed
			}
		case "emitted", "dropped":
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return status, errors.New("core returned a malformed worker guard counter")
			}
			if key == "emitted" {
				status.Emitted = parsed
			} else {
				status.Dropped = parsed
			}
		default:
			return status, errors.New("core returned an unknown worker guard status field")
		}
	}
	for _, required := range []string{"enabled", "attached", "comms", "uids", "emitted", "dropped"} {
		if !seen[required] {
			return status, errors.New("core returned an incomplete worker guard status")
		}
	}
	return status, nil
}
