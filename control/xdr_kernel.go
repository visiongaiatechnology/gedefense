// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type xdrKernelCore interface {
	ExecArgvEvents() ([]CoreExecArgvEvent, error)
	KernelProbeEvents() ([]CoreKernelProbeEvent, error)
}

func (e *XDREngine) consumeExecArgvEvents(events []CoreExecArgvEvent, drainErr error, maxCmdBytes int) time.Duration {
	if e == nil {
		return 10 * time.Second
	}
	if drainErr != nil {
		if errors.Is(drainErr, ErrExecArgvUnavailable) {
			return 10 * time.Second
		}
		log.Printf("xdr-kernel exec-argv drain error: %v", drainErr)
		return 2 * time.Second
	}
	for _, ev := range events {
		if ev.PID <= 4 || ev.PID == e.selfPID {
			continue
		}
		cleanExe := filepath.Clean(ev.Filename)
		cmd := strings.TrimSpace(ev.Cmdline)
		process, readErr := readExecProcess(CoreExecEvent{PID: ev.PID, UID: ev.UID, GID: ev.GID, Comm: ev.Comm}, maxCmdBytes)
		if readErr == nil && (cleanExe == "." || !filepath.IsAbs(cleanExe)) && filepath.IsAbs(process.Exe) {
			cleanExe = filepath.Clean(process.Exe)
		}
		if cleanExe == "." || cleanExe == string(filepath.Separator) || !filepath.IsAbs(cleanExe) {
			continue
		}
		if e.allowedProcess(cleanExe) {
			continue
		}
		if cmd == "" {
			cmd = ev.Comm
		}
		if maxCmdBytes > 0 && len(cmd) > maxCmdBytes {
			cmd = cmd[:maxCmdBytes]
		}
		if readErr != nil {
			process = ProcessSample{
				PID:        ev.PID,
				PPID:       ev.PPID,
				StartTicks: 1,
				UID:        ev.UID,
				GID:        ev.GID,
				Comm:       ev.Comm,
				Exe:        cleanExe,
				Cmdline:    cmd,
				CmdSHA256:  commandDigest(cmd),
			}
		} else if cmd != "" && (process.Cmdline == "" || process.Cmdline == process.Comm) {
			process.Cmdline = cmd
			process.CmdSHA256 = commandDigest(cmd)
		}
		key := fmt.Sprintf("argv:%d:%d:%s", process.PID, process.StartTicks, commandDigest(process.Cmdline))
		e.mu.Lock()
		_, alreadySeen := e.seen[key]
		e.seen[key] = struct{}{}
		e.mu.Unlock()
		if alreadySeen {
			continue
		}
		e.submit(evaluationJob{process: process, source: "exec-argv"}, true)
	}
	return 100 * time.Millisecond
}

func (e *XDREngine) consumeKernelProbeEvents(events []CoreKernelProbeEvent, drainErr error, now time.Time) time.Duration {
	if e == nil {
		return 10 * time.Second
	}
	if drainErr != nil {
		if errors.Is(drainErr, ErrKernelProbeUnavailable) {
			return 10 * time.Second
		}
		log.Printf("xdr-kernel probe drain error: %v", drainErr)
		return 2 * time.Second
	}
	for _, ev := range events {
		if ev.PID == e.selfPID || !e.claimKernelProbeRecord(ev, now) {
			continue
		}
		e.recordKernelProbe(ev, now)
	}
	return 100 * time.Millisecond
}

func (e *XDREngine) claimKernelProbeRecord(ev CoreKernelProbeEvent, now time.Time) bool {
	key := fmt.Sprintf("%d|%d|%d|%d", ev.PID, ev.Kind, ev.DetailCode, ev.TsNS)
	e.probeMu.Lock()
	defer e.probeMu.Unlock()
	if e.probeSeen == nil {
		e.probeSeen = make(map[string]time.Time)
	}
	if until, exists := e.probeSeen[key]; exists && now.Before(until) {
		return false
	}
	e.probeSeen[key] = now.Add(5 * time.Minute)
	if len(e.probeSeen) > 4096 {
		for k, until := range e.probeSeen {
			if !until.After(now) {
				delete(e.probeSeen, k)
			}
		}
	}
	return true
}

func (e *XDREngine) recordKernelProbe(ev CoreKernelProbeEvent, now time.Time) {
	var ruleID, eventKind, category, evType, summary, decision, action, outcome string
	var score int
	switch ev.Kind {
	case KernelProbeKindPtrace:
		ruleID = "XDR.PTRACE_ATTEMPT"
		eventKind = "xdr.ptrace_attempt"
		category = "defense-evasion"
		evType = "PTRACE_ATTEMPT"
		decision = "alert"
		action = "none"
		score = 120
		summary = fmt.Sprintf("Kernel tracepoint observed ptrace attempt: pid=%d uid=%d comm=%s req=%d target_pid=%d", ev.PID, ev.UID, ev.Comm, ev.DetailCode, ev.TargetPID)
		outcome = "kernel telemetry recorded ptrace anti-debug/memory inspection attempt"
	case KernelProbeKindProtocol:
		ruleID = "XDR.KERNEL_PROTOCOL_PROBE"
		eventKind = "xdr.kernel_protocol_probe"
		category = "kernel"
		evType = "PROTOCOL_SOCKET_BLOCKED"
		decision = "deny"
		action = "deny-socket"
		score = 150
		protoName := ev.Detail
		if protoName == "" {
			protoName = strconv.FormatUint(uint64(ev.DetailCode), 10)
		}
		summary = fmt.Sprintf("Kernel BPF-LSM denied blacklisted protocol socket (%s): pid=%d uid=%d comm=%s", protoName, ev.PID, ev.UID, ev.Comm)
		outcome = "socket denied by the kernel BPF-LSM before allocation"
	case KernelProbeKindCredOpenat:
		ruleID = "XDR.CREDENTIAL_PROBE"
		eventKind = "xdr.credential_read_blocked"
		category = "credential"
		evType = "CREDENTIAL_PROBE_ATTEMPT"
		decision = "alert"
		action = "none"
		score = 130
		summary = fmt.Sprintf("Kernel pre-DAC probe observed untrusted credential open attempt (%s): pid=%d uid=%d comm=%s", ev.Detail, ev.PID, ev.UID, ev.Comm)
		outcome = "untrusted credential access attempt logged (DAC/LSM enforced)"
	case KernelProbeKindSymlink:
		ruleID = "XDR.SYMLINK_OVER_SENSITIVE"
		eventKind = "xdr.symlink_over_sensitive"
		category = "defense-evasion"
		evType = "SYMLINK_SENSITIVE_TARGET"
		decision = "alert"
		action = "none"
		score = 120
		summary = fmt.Sprintf("Kernel tracepoint observed symlink creation targeting sensitive file (%s): pid=%d uid=%d comm=%s", ev.Detail, ev.PID, ev.UID, ev.Comm)
		outcome = "sensitive symlink creation logged for investigation"
	default:
		return
	}

	if e.state != nil {
		_ = e.state.RecordEvidence(EvidenceRecord{
			Severity: "high", Kind: eventKind, Source: "kernel",
			Message: summary, Target: fmt.Sprintf("pid:%d:kind:%d", ev.PID, ev.Kind), Time: now,
		})
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("probe-%d-%d", ev.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-probe",
		Category:   category,
		EventType:  evType,
		EntityID:   fmt.Sprintf("pid:%d", ev.PID),
		Actor:      fmt.Sprintf("uid:%d", ev.UID),
		Severity:   "high",
		Confidence: 92,
		CausalEdge: EdgePrivilegeEscalated,
		EventUUID:  randomID(),
		Metadata: map[string]string{
			"comm":   ev.Comm,
			"detail": ev.Detail,
			"code":   strconv.FormatUint(uint64(ev.DetailCode), 10),
			"pid":    strconv.Itoa(ev.PID),
			"uid":    strconv.FormatUint(uint64(ev.UID), 10),
		},
	}
	node.Digest = node.ComputeNodeDigest()
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: now, Severity: "high", Score: score,
		PID: ev.PID, UID: ev.UID, Process: ev.Comm,
		RuleIDs: []string{ruleID}, Categories: []string{category, "kernel"},
		Summary: summary, Decision: decision, Action: action, Outcome: outcome,
		ExecutionChainID: node.NodeID, AttackStory: []AttackStoryNode{node}, EvidenceRoot: node.Digest,
	})
	if e.state != nil {
		e.state.AddEvent(Event{
			Time: now, Severity: "high", Kind: eventKind, Source: "kernel",
			Message: summary, Target: fmt.Sprintf("pid:%d", ev.PID),
		})
	}
}
