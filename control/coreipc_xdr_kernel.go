// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	maxExecArgvEventsPerResponse   = 32
	maxExecArgvPayloadBytes        = 56000
	maxKernelProbeEventsPerReply   = 32
	maxKernelProbePayloadBytes     = 12000
	KernelProbeKindPtrace      uint8 = 1
	KernelProbeKindProtocol    uint8 = 2
	KernelProbeKindCredOpenat  uint8 = 3
	KernelProbeKindSymlink     uint8 = 4
	KernelProbeActionDeny      uint8 = 1
	KernelProbeActionAudit     uint8 = 2
)

type CoreExecArgvEvent struct {
	PID      int
	PPID     int
	UID      uint32
	GID      uint32
	Comm     string
	Filename string
	Cmdline  string
}

type CoreKernelProbeEvent struct {
	TsNS       uint64
	PID        int
	UID        uint32
	TargetPID  int
	Kind       uint8
	Action     uint8
	DetailCode uint32
	Comm       string
	Detail     string
}

var (
	ErrExecArgvUnavailable    = errors.New("kernel exec-argv capability unavailable")
	ErrKernelProbeUnavailable = errors.New("kernel probe capability unavailable")
)

func (c *CoreClient) xdrKernelCommand(unavailable error, cmd string) (string, error) {
	response, err := c.command(cmd)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", unavailable, err)
		}
		return "", err
	}
	return response, nil
}

func (c *CoreClient) ExecArgvEvents() ([]CoreExecArgvEvent, error) {
	response, err := c.xdrKernelCommand(ErrExecArgvUnavailable, "EXEC_ARGV_EVENTS")
	if err != nil {
		return nil, err
	}
	return parseCoreExecArgvEvents(response)
}

func (c *CoreClient) KernelProbeEvents() ([]CoreKernelProbeEvent, error) {
	response, err := c.xdrKernelCommand(ErrKernelProbeUnavailable, "KERNEL_PROBE_EVENTS")
	if err != nil {
		return nil, err
	}
	return parseCoreKernelProbeEvents(response)
}

func parseCoreExecArgvEvents(response string) ([]CoreExecArgvEvent, error) {
	if response == "empty" {
		return nil, nil
	}
	if len(response) > maxExecArgvPayloadBytes {
		return nil, errors.New("core returned oversized exec-argv event payload")
	}
	records := strings.Split(response, ",")
	if len(records) > maxExecArgvEventsPerResponse {
		return nil, errors.New("core returned too many exec-argv events")
	}
	events := make([]CoreExecArgvEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 7 {
			return nil, errors.New("core returned malformed exec-argv event")
		}
		pid, pidErr := strconv.ParseInt(fields[0], 10, 32)
		ppid, ppidErr := strconv.ParseInt(fields[1], 10, 32)
		uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
		gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
		comm, commErr := hex.DecodeString(fields[4])
		filename, fnErr := hex.DecodeString(fields[5])
		cmdline, cmdErr := hex.DecodeString(fields[6])
		if pidErr != nil || ppidErr != nil || uidErr != nil || gidErr != nil ||
			commErr != nil || fnErr != nil || cmdErr != nil ||
			pid <= 0 || ppid < 0 || len(comm) > 16 || len(filename) > 472 || len(cmdline) > 472 ||
			strings.ContainsRune(string(comm), '\x00') ||
			strings.ContainsRune(string(filename), '\x00') ||
			strings.ContainsRune(string(cmdline), '\x00') {
			return nil, errors.New("core returned invalid exec-argv event fields")
		}
		events = append(events, CoreExecArgvEvent{
			PID:      int(pid),
			PPID:     int(ppid),
			UID:      uint32(uid),
			GID:      uint32(gid),
			Comm:     string(comm),
			Filename: string(filename),
			Cmdline:  string(cmdline),
		})
	}
	return events, nil
}

func parseCoreKernelProbeEvents(response string) ([]CoreKernelProbeEvent, error) {
	if response == "empty" {
		return nil, nil
	}
	if len(response) > maxKernelProbePayloadBytes {
		return nil, errors.New("core returned oversized kernel-probe event payload")
	}
	records := strings.Split(response, ",")
	if len(records) > maxKernelProbeEventsPerReply {
		return nil, errors.New("core returned too many kernel-probe events")
	}
	events := make([]CoreKernelProbeEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 9 {
			return nil, errors.New("core returned malformed kernel-probe event")
		}
		ts, tsErr := strconv.ParseUint(fields[0], 10, 64)
		pid, pidErr := strconv.ParseInt(fields[1], 10, 32)
		uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
		tpid, tpidErr := strconv.ParseUint(fields[3], 10, 32)
		kind, kindErr := strconv.ParseUint(fields[4], 10, 8)
		action, actionErr := strconv.ParseUint(fields[5], 10, 8)
		code, codeErr := strconv.ParseUint(fields[6], 10, 32)
		comm, commErr := hex.DecodeString(fields[7])
		detail, detErr := hex.DecodeString(fields[8])
		if tsErr != nil || pidErr != nil || uidErr != nil || tpidErr != nil ||
			kindErr != nil || actionErr != nil || codeErr != nil ||
			commErr != nil || detErr != nil ||
			ts == 0 || pid <= 0 ||
			kind == 0 || kind > uint64(KernelProbeKindSymlink) ||
			(action != uint64(KernelProbeActionDeny) && action != uint64(KernelProbeActionAudit)) ||
			len(comm) > 16 || len(detail) > 20 ||
			strings.ContainsRune(string(comm), '\x00') ||
			strings.ContainsRune(string(detail), '\x00') {
			return nil, errors.New("core returned invalid kernel-probe event fields")
		}
		events = append(events, CoreKernelProbeEvent{
			TsNS:       ts,
			PID:        int(pid),
			UID:        uint32(uid),
			TargetPID:  int(tpid),
			Kind:       uint8(kind),
			Action:     uint8(action),
			DetailCode: uint32(code),
			Comm:       string(comm),
			Detail:     string(detail),
		})
	}
	return events, nil
}
