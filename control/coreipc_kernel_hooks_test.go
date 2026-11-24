// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-4 regression tests: bounded KERNEL_HOOK_* parsers (status, epoch,
// event text wire) and the fuzz target for the event parser. Every accepted
// record must satisfy the closed kind/action contract and the bounded
// comm/detail encoding; every rejected answer must be all-or-nothing.

import (
	"strings"
	"testing"
)

const (
	kernelHookValidCreate = "1700000000000000000:4242:4241:1000:1:1:7:66696f:20800000"
	kernelHookValidModule = "1700000000000000001:500:500:0:4:1:0:696e736d6f64:6576696c5f6c6b6d"
	kernelHookValidLsm    = "1700000000000000002:91:91:0:9:1:0::"
)

func TestCoreKernelHookStatusBoundedAndStrict(t *testing.T) {
	status, err := parseCoreKernelHookStatus(
		"enabled=1:attached=1:io_uring=1:module_trace=1:kprobes=3:lsm_extra=2:events=12:drops=3:loads=4:ring_creates=5")
	if err != nil {
		t.Fatalf("valid kernel-hook status rejected: %v", err)
	}
	if !status.Enabled || !status.Attached || !status.IoUring || !status.ModuleTrace ||
		status.Kprobes != 3 || status.LsmExtra != 2 || status.Events != 12 ||
		status.Drops != 3 || status.Loads != 4 || status.RingCreates != 5 {
		t.Fatalf("kernel-hook status decoded wrong: %+v", status)
	}
	disarmed, err := parseCoreKernelHookStatus(
		"enabled=0:attached=0:io_uring=0:module_trace=0:kprobes=0:lsm_extra=0:events=0:drops=0:loads=0:ring_creates=0")
	if err != nil {
		t.Fatalf("disarmed kernel-hook status rejected: %v", err)
	}
	if disarmed.Enabled || disarmed.Attached || disarmed.Kprobes != 0 || disarmed.LsmExtra != 0 {
		t.Fatalf("disarmed kernel-hook status decoded wrong: %+v", disarmed)
	}
	for _, response := range []string{
		"",
		"enabled=1:attached=1",
		"enabled=1:attached=1:io_uring=1:module_trace=1:kprobes=3:lsm_extra=2:events=12:drops=3:loads=4:ring_creates=5:extra=0",
		"enabled=2:attached=1:io_uring=1:module_trace=1:kprobes=3:lsm_extra=2:events=12:drops=3:loads=4:ring_creates=5",
		"attached=1:enabled=1:io_uring=1:module_trace=1:kprobes=3:lsm_extra=2:events=12:drops=3:loads=4:ring_creates=5",
		"enabled=1:attached=1:io_uring=1:module_trace=1:kprobes=4:lsm_extra=2:events=12:drops=3:loads=4:ring_creates=5",
		"enabled=1:attached=1:io_uring=1:module_trace=1:kprobes=3:lsm_extra=4:events=12:drops=3:loads=4:ring_creates=5",
		"enabled=1:attached=1:io_uring=x:module_trace=1:kprobes=3:lsm_extra=2:events=12:drops=3:loads=4:ring_creates=5",
		" enabled=1:attached=1:io_uring=1:module_trace=1:kprobes=3:lsm_extra=2:events=12:drops=3:loads=4:ring_creates=5",
		"enabled=1:attached=1:io_uring=1:module_trace=1:kprobes=3:lsm_extra=2:events=12:drops=3:loads=4:ring_creates=18446744073709551616",
		strings.Repeat("a", maxKernelHookStatusBytes+1),
	} {
		if _, err := parseCoreKernelHookStatus(response); err == nil {
			t.Fatalf("hostile kernel-hook status accepted: %.60q", response)
		}
	}
}

func TestCoreKernelHookEpochValidation(t *testing.T) {
	epoch, err := parseKernelHookEpoch("0123456789abcdef")
	if err != nil || epoch != "0123456789abcdef" {
		t.Fatalf("valid kernel-hook epoch rejected: %q %v", epoch, err)
	}
	for _, response := range []string{
		"", "0", "0123456789abcde", "0123456789abcdef0", "0123456789ABCDEF",
		"0123456789abcdeg", "0123456789abcde\n", " 0123456789abcdef",
	} {
		if _, err := parseKernelHookEpoch(response); err == nil {
			t.Fatalf("hostile kernel-hook epoch accepted: %q", response)
		}
	}
}

func TestCoreKernelHookEventsBoundedAndStrict(t *testing.T) {
	batch := "2|" + kernelHookValidCreate + "," + kernelHookValidModule + "," + kernelHookValidLsm
	events, dropped, err := parseCoreKernelHookEvents(batch)
	if err != nil {
		t.Fatalf("valid kernel-hook batch rejected: %v", err)
	}
	if dropped != 2 || len(events) != 3 {
		t.Fatalf("batch parsed to %d events dropped=%d", len(events), dropped)
	}
	create := events[0]
	if create.Kind != KernelHookKindIoUringCreate || create.Action != KernelHookActionAudit ||
		create.PID != 4242 || create.TGID != 4241 || create.UID != 1000 ||
		create.DetailCode != 7 || create.Comm != "fio" || create.Detail != "\x20\x80\x00\x00" {
		t.Fatalf("io_uring create record decoded wrong: %+v", create)
	}
	module := events[1]
	if module.Kind != KernelHookKindModuleLoad || module.Comm != "insmod" ||
		module.Detail != "evil_lkm" || module.DetailCode != 0 || module.UID != 0 {
		t.Fatalf("module load record decoded wrong: %+v", module)
	}
	if events[2].Kind != KernelHookKindLsmUringCmd || events[2].Comm != "" || events[2].Detail != "" {
		t.Fatalf("identity-only record decoded wrong: %+v", events[2])
	}
	if events, dropped, err := parseCoreKernelHookEvents("5|"); err != nil || dropped != 5 || events != nil {
		t.Fatalf("drop-only kernel-hook batch is wrong: dropped=%d err=%v", dropped, err)
	}
	if events, _, err := parseCoreKernelHookEvents("empty"); err != nil || events != nil {
		t.Fatalf("empty kernel-hook batch is wrong: %v", err)
	}
	invalid := []string{
		"", " 0|", "x|", "0", "0|" + kernelHookValidCreate + ",",
		"0|1700000000000000000:4242:4241:1000:1:1:7:66696f",                                                                  // missing detail
		"0|1700000000000000000:4242:4241:1000:1:1:7:66696f:20:extra",                                                         // extra field
		"0|0:4242:4241:1000:1:1:7:66696f:20800000",                                                                           // zero ts
		"0|1700000000000000000:0:4241:1000:1:1:7:66696f:20800000",                                                            // zero pid
		"0|1700000000000000000:4242:0:1000:1:1:7:66696f:20800000",                                                            // zero tgid
		"0|1700000000000000000:4242:4241:1000:0:1:7:66696f:20800000",                                                         // kind 0
		"0|1700000000000000000:4242:4241:1000:11:1:7:66696f:20800000",                                                        // kind above bound
		"0|1700000000000000000:4242:4241:1000:1:0:7:66696f:20800000",                                                         // action 0
		"0|1700000000000000000:4242:4241:1000:1:3:7:66696f:20800000",                                                         // action 3
		"0|1700000000000000000:4242:4241:4294967296:1:1:7:66696f:20800000",                                                   // uid above u32
		"0|1700000000000000000:4242:4241:1000:1:1:7:00:20800000",                                                             // NUL comm
		"0|1700000000000000000:4242:4241:1000:1:1:7:66696g:20800000",                                                         // non-hex comm
		"0|1700000000000000000:4242:4241:1000:1:1:7:66696f0:20800000",                                                        // odd comm hex
		"0|1700000000000000000:4242:4241:1000:1:1:7:000102030405060708090a0b0c0d0e0f1011:20800000",                           // comm too long
		"0|1700000000000000000:4242:4241:1000:1:1:7:66696f:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", // detail too long
		"0|1700000000000000000:4242:4241:1000:1:1:7:66696f:208",                                                              // odd detail hex
		"0|" + strings.Repeat("4", maxKernelHookPayloadBytes),                                                                // oversized payload
	}
	for _, response := range invalid {
		if events, dropped, err := parseCoreKernelHookEvents(response); err == nil || events != nil || dropped != 0 {
			t.Fatalf("hostile kernel-hook batch accepted: %.70q", response)
		}
	}
	tooMany := "0|" + strings.TrimSuffix(
		strings.Repeat(kernelHookValidLsm+",", maxKernelHookEventsPerResponse+1), ",")
	if _, _, err := parseCoreKernelHookEvents(tooMany); err == nil {
		t.Fatal("a kernel-hook batch above the core ceiling was accepted")
	}
}

func TestCoreKernelHookKindAndFamilyContract(t *testing.T) {
	contract := map[uint8]string{
		KernelHookKindIoUringCreate:        "io_uring_create",
		KernelHookKindIoUringRegister:      "io_uring_register",
		KernelHookKindIoUringSubmit:        "io_uring_submit_req",
		KernelHookKindModuleLoad:           "module_load",
		KernelHookKindModuleFinit:          "finit_module",
		KernelHookKindModuleDelete:         "delete_module",
		KernelHookKindLsmUringOverrideCred: "lsm_uring_override_creds",
		KernelHookKindLsmUringSQPoll:       "lsm_uring_sqpoll",
		KernelHookKindLsmUringCmd:          "lsm_uring_cmd",
		KernelHookKindLkmTaint:             "lkm_taint",
	}
	if KernelHookKindMax != 10 || len(contract) != 10 {
		t.Fatalf("kind contract is not the documented closed 1..10 set: max=%d len=%d",
			KernelHookKindMax, len(contract))
	}
	for kind := uint8(1); kind <= KernelHookKindMax; kind++ {
		name, ok := contract[kind]
		if !ok {
			t.Fatalf("kind %d is missing from the contract", kind)
		}
		if KernelHookKindName(kind) != name {
			t.Fatalf("kind %d rendered as %q, want %q", kind, KernelHookKindName(kind), name)
		}
		module := KernelHookKindIsModule(kind)
		ioUring := KernelHookKindIsIoUring(kind)
		if module == ioUring {
			t.Fatalf("kind %d must belong to exactly one hook family (module=%t io_uring=%t)",
				kind, module, ioUring)
		}
	}
	if KernelHookKindIsModule(1) || KernelHookKindIsIoUring(4) {
		t.Fatal("kind family classification is inverted")
	}
	if KernelHookActionAudit != 1 || KernelHookActionDeny != 2 {
		t.Fatalf("action contract drifted: audit=%d deny=%d",
			KernelHookActionAudit, KernelHookActionDeny)
	}
	if KernelHookActionName(KernelHookActionAudit) != "audit" ||
		KernelHookActionName(KernelHookActionDeny) != "deny" {
		t.Fatal("action names drifted")
	}
	if KernelHookDetailBytes != 20 || KernelHookCommBytes != 16 {
		t.Fatalf("wire bounds drifted: detail=%d comm=%d", KernelHookDetailBytes, KernelHookCommBytes)
	}
	if maxKernelHookEventsPerResponse != 16 || maxKernelHookPayloadBytes != 4096 {
		t.Fatalf("response bounds drifted: events=%d bytes=%d",
			maxKernelHookEventsPerResponse, maxKernelHookPayloadBytes)
	}
}

// FuzzCoreKernelHookParser feeds arbitrary bytes into the KERNEL_HOOK event
// parser. A panic or an accepted record that violates the closed wire contract
// would mean the XDR engine can be tricked into acting on attacker-shaped data.
func FuzzCoreKernelHookParser(f *testing.F) {
	f.Add("empty")
	f.Add("0|" + kernelHookValidCreate)
	f.Add("2|" + kernelHookValidCreate + "," + kernelHookValidModule)
	f.Add("0|" + kernelHookValidLsm)
	f.Add("1|")
	f.Add("x|")
	f.Add("0|")
	f.Add(strings.Repeat("A", 4096))
	f.Fuzz(func(t *testing.T, payload string) {
		events, dropped, err := parseCoreKernelHookEvents(payload)
		if err != nil {
			if events != nil || dropped != 0 {
				t.Fatalf("rejected batch returned partial state: events=%d dropped=%d", len(events), dropped)
			}
			return
		}
		if len(events) > maxKernelHookEventsPerResponse {
			t.Fatalf("accepted more than the batch ceiling: %d", len(events))
		}
		for _, event := range events {
			if event.PID == 0 || event.TGID == 0 || event.TsNS == 0 {
				t.Fatal("accepted an event without identity or timestamp")
			}
			if event.Kind == 0 || event.Kind > KernelHookKindMax {
				t.Fatalf("accepted unknown kind: %d", event.Kind)
			}
			if event.Action != KernelHookActionAudit && event.Action != KernelHookActionDeny {
				t.Fatalf("accepted unknown action: %d", event.Action)
			}
			if len(event.Comm) > KernelHookCommBytes {
				t.Fatalf("accepted an oversized comm: %d bytes", len(event.Comm))
			}
			if len(event.Detail) > KernelHookDetailBytes {
				t.Fatalf("accepted an oversized detail: %d bytes", len(event.Detail))
			}
			for index := 0; index < len(event.Comm); index++ {
				if event.Comm[index] < 0x20 || event.Comm[index] > 0x7e {
					t.Fatal("accepted a comm with rejected characters")
				}
			}
		}
	})
}
