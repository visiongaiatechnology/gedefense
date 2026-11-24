#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 8 (original lines 2126-2484).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
pass 'Point 4 witness epoch/checkpoint, hardened client, receipts, bounded outbox, export/import, equivocation, v17 default-off and privacy/no-server boundaries present'

# V6.3.0 (AP-0/AP-1/AP-2): sensor self-protection, executable-inode trust gate
# and the attach-time eBPF guard. Every anchor pins a definition, a decision or a
# default - never a bare comment. The observe-only contract and the unchanged
# kill gate are pinned as explicit negatives, and the musl release gate is
# pinned in the Makefile and in CI.
python3 - "$ROOT" <<'PYV63'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
missing = []

def read(relative):
    return (root / relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

def forbid(component, text, pattern, label):
    if re.search(pattern, text) is not None:
        missing.append(f'{component}: forbidden {label}')

# AP-0: eBPF pin manifest, synthetic canary self-test and the bounded queue.
self_defense = read('rust/gedefense-core/src/self_defense.rs')
for anchor in [
    'const TAMPER_QUEUE_CAPACITY', 'const PIN_VERIFY_INTERVAL_MS',
    'const CANARY_TEST_INTERVAL_MS', 'fn install_pins(',
    'fn verify_pins(', 'fn pin_one(', 'fn inspect_pin(',
    'KIND_PIN_MISSING', 'KIND_PIN_REPLACED', 'KIND_CANARY_DEAD',
    'DECOY_CANARY_TYPE', 'const CRITICAL_MAPS',
]:
    need('self-defence', self_defense, anchor)
selfguard_go = read('control/xdr_selfguard.go')
for anchor in [
    'selfGuardRuleID = "XDR.SELF_TAMPER"',
    'selfGuardSBCFamily = "SBC-EVID-08"',
    'func (e *XDREngine) pollSelfGuard',
    'func (e *XDREngine) watchSelfGuardRingDrops',
    'func (e *XDREngine) recordSelfTamperFact',
]:
    need('xdr-selfguard', selfguard_go, anchor)
need_match('xdr-selfguard', selfguard_go, 'self-tamper incidents are evidence-first and alert-only',
           r'Decision:\s*"degrade"[\s\S]{0,200}?Action:\s*"none"')
forbid('xdr-selfguard', selfguard_go, r'\bKillEligible\s*:\s*true', 'kill-eligible self-tamper rule')
forbid('xdr-selfguard', selfguard_go, r'Decision:\s*"kill"', 'self-tamper kill decision')
selfguard_ipc = read('control/coreipc_selfguard.go')
for anchor in ['ErrSelfGuardUnavailable', 'func (c *CoreClient) SelfTamperEvents()',
               'func parseCoreSelfTamperEvents']:
    need('selfguard-ipc', selfguard_ipc, anchor)
need('selfguard-fuzz', read('control/coreipc_selfguard_test.go'), 'func FuzzCoreSelfGuardParser')
makefile = read('Makefile')
for anchor in ['rust-core-musl', 'rust-check', 'readelf -d',
               'statically linked', 'FuzzCoreSelfGuardParser',
               'FuzzCoreExecInodeParser', 'FuzzCoreBpfGuardParser']:
    need('makefile-v63', makefile, anchor)
ci = read('.github/workflows/ci.yml')
for anchor in ['x86_64-unknown-linux-musl', 'readelf -d', 'statically linked']:
    need('ci-musl', ci, anchor)

# AP-1: executable-inode trust gate (primary) with audited comm fallback.
common_exec = read('rust/gedefense-common/src/exec_inode.rs')
for anchor in ['EXEC_INODE_STATE_MAGIC', 'EXEC_INODE_ALLOW_CRED_READ',
               'EXEC_INODE_ALLOW_RANSOM_FULL', 'EXEC_INODE_ALLOW_RANSOM_POOL_META',
               'EXEC_INODE_EVENT_WIRE_BYTES', 'decode_exec_inode_event',
               'EXEC_INODE_OFFSETS_TABLE_LEN']:
    need('exec-inode-ab', common_exec, anchor)
ebpf_exec = read('rust/gedefense-ebpf/src/exec_inode.rs')
for anchor in ['static TRUSTED_EXEC_INODES', 'static MALWARE_TTL_INODES',
               'static EXEC_INODE_EVENTS', 'fn current_exec_trust',
               'fn ttl_inode_denied', 'fn emit_exec_inode_fallback_once']:
    need('exec-inode-ebpf', ebpf_exec, anchor)
ebpf_cred = read('rust/gedefense-ebpf/src/credential_guard.rs')
for anchor in ['current_exec_trust()', 'CRED_GUARD_ACTION_DENY_INODE',
               'emit_exec_inode_fallback_once', 'EXEC_INODE_CRED_FLAG']:
    need('exec-inode-credguard', ebpf_cred, anchor)
need_match('exec-inode-credguard', ebpf_cred,
           'the inode gate is the primary credential decision',
           r'let Some\(\(exe_identity, trust_flags\)\) = current_exec_trust\(\) else \{')
ebpf_ransom = read('rust/gedefense-ebpf/src/ransom.rs')
for anchor in ['current_exec_trust()', 'exec_inode_trust_tier',
               'EXEC_INODE_RANSOM_FULL_FLAG', 'EXEC_INODE_RANSOM_POOL_META_FLAG']:
    need('exec-inode-ransom', ebpf_ransom, anchor)
btf = ''.join(p.read_text(encoding='utf-8') for p in sorted(list((root/'rust'/'gedefense-core'/'src').glob('btf_offsets*.rs')) + list((root/'rust'/'gedefense-core'/'src'/'btf_offsets').rglob('*.rs'))))
for anchor in ['pub struct ExecInodeOffsets', 'pub fn resolve_exec_inode',
               'task_struct.mm', 'mm_struct.exe_file']:
    need('exec-inode-btf', btf, anchor)
need('exec-inode-btf-validate', read('rust/gedefense-core/src/btf_validate.rs'),
     'fn validate_exec_inode_offsets')
core_exec = read('rust/gedefense-core/src/exec_inode.rs')
for anchor in ['RESOLVE_NO_SYMLINKS', 'libc::SYS_openat2',
               'fn resolve_executable_identity', 'fn parse_ttl_token',
               'MALWARE_TTL_INODES', 'AUTH_EXEC_PATHS', 'POOL_SERVICE_PATHS']:
    need('exec-inode-core', core_exec, anchor)
exec_ipc = read('control/coreipc_execinode.go')
for anchor in ['ErrExecInodeUnavailable', 'func parseCoreExecInodeStatus',
               'func parseCoreExecInodeEvents', 'func (c *CoreClient) ExecInodeEvents()',
               'func (c *CoreClient) ExecInodeAllowDelete',
               'func (c *CoreClient) MalwareInodeLock']:
    need('exec-inode-ipc', exec_ipc, anchor)
need('exec-inode-fuzz', read('control/coreipc_execinode_test.go'), 'func FuzzCoreExecInodeParser')
xdr_exec = read('control/xdr_execinode.go')
for anchor in ['func (e *XDREngine) pollExecInode', '"XDR.NAME_PATH_MISMATCH"']:
    need('xdr-exec-inode', xdr_exec, anchor)
forbid('xdr-exec-inode', xdr_exec, r'\bKillEligible\s*:\s*true', 'kill-eligible inode mismatch rule')
need('exec-inode-credguard-label', read('control/coreipc_credguard.go'), 'CredGuardActionDenyInode')

# AP-2: attach-time eBPF guard / helper-risk bitmap.
common_bpf = read('rust/gedefense-common/src/bpf_guard.rs')
for anchor in ['BPF_GUARD_EVENT_WIRE_BYTES', 'HELPER_BIT_PROBE_WRITE_USER',
               'HELPER_BIT_OVERRIDE_RETURN', 'HELPER_BIT_SEND_SIGNAL',
               'decode_bpf_guard_event', 'BPF_GUARD_MAX_HELPER_ID']:
    need('bpf-guard-abi', common_bpf, anchor)
ebpf_bpf = read('rust/gedefense-ebpf/src/bpf_guard.rs')
for anchor in ['#[lsm(hook = "bpf_prog")]', '#[tracepoint]', '#[kprobe]',
               'gedefense_bpf_prog_guard', 'gedefense_bpf_syscall',
               'gedefense_check_helper_call', 'static BPF_GUARD_HELPER_BITMAP',
               'static BPF_GUARD_EVENTS']:
    need('bpf-guard-ebpf', ebpf_bpf, anchor)
core_bpf = read('rust/gedefense-core/src/bpf_guard.rs')
for anchor in ['check_helper_call', '/proc/kallsyms', 'BPF_GUARD_EVENTS',
               'BPF_GUARD_HELPER_BITMAP']:
    need('bpf-guard-core', core_bpf, anchor)
bpf_ipc = read('control/coreipc_bpf_guard.go')
for anchor in ['ErrBpfGuardUnavailable', 'func (c *CoreClient) BpfGuardEvents()',
               'func parseCoreBpfGuardEvents']:
    need('bpf-guard-ipc', bpf_ipc, anchor)
need('bpf-guard-fuzz', read('control/coreipc_bpfguard_test.go'), 'func FuzzCoreBpfGuardParser')
xdr_bpf = read('control/xdr_bpfguard.go')
for anchor in ['func (e *XDREngine) pollBpfGuard', 'func (e *XDREngine) bpfGuardEventTolerated',
               '"XDR.BPF_ANOMALY"', '"XDR.BPF_ROOTKIT_HELPER"']:
    need('xdr-bpf-guard', xdr_bpf, anchor)
forbid('xdr-bpf-guard', xdr_bpf, r'\bKillEligible\s*:\s*true', 'kill-eligible BPF guard rule')
need_match('xdr-bpf-guard', xdr_bpf, 'BPF guard incidents never derive an active response',
           r'Decision:\s*"alert"[\s\S]{0,160}?Action:\s*"none"')
need('bpf-guard-tolerated', xdr_bpf, 'bpftrace')

# Unchanged kill gate and sandbox invariants (regression pins).
need('kill-gate', read('control/xdr_rules.go'),
     'responseScore >= 120 && len(killCategories) >= 2')
core_unit = read('packaging/systemd/gedefense-core.service')
forbid('systemd-core-unit', core_unit, r'(?m)^\s*PrivateTmp\s*=\s*true',
       'private tmp hiding host drop paths')
forbid('systemd-core-unit', core_unit, r'(?m)^\s*CapabilityBoundingSet=.*CAP_DAC_OVERRIDE',
       'broad DAC override')
forbid('systemd-core-unit', core_unit, r'(?m)^\s*ProtectSystem\s*=\s*(?:no|false|off)',
       'weakened ProtectSystem')

if missing:
    raise SystemExit('V6.3.0 AP-0/AP-1/AP-2 anchors missing:\n' + '\n'.join(missing))
PYV63
pass 'V6.3.0 AP-0 self-protection, AP-1 executable-inode trust and AP-2 attach-time eBPF guard anchors present'

# V6.3.0 round 2 (AP-3 cross-view, AP-4 io_uring/LKM hooks, AP-5 persistence &
# peripheral integrity, AP-9 S09 TUF feed anti-poisoning). Every anchor pins a
# definition, a decision or a default; observe-only, the unchanged kill gate and
# the boot/package TOLERATED paths are pinned as explicit negatives.
python3 - "$ROOT" <<'PYV63R2'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
missing = []

def read(relative):
    return (root / relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

def forbid(component, text, pattern, label):
    if re.search(pattern, text) is not None:
        missing.append(f'{component}: forbidden {label}')

# AP-3: 8-domain cross-view verifier.
cross_common = read('rust/gedefense-common/src/cross_view.rs')
for anchor in ['CROSS_VIEW_EVENT_WIRE_BYTES', 'CROSS_VIEW_MAX_BPF_PROBES',
               'CROSS_VIEW_SCAN_BUDGET_MS', 'CROSS_VIEW_DOMAIN_EBPF_ID_GAP',
               'CROSS_VIEW_DOMAIN_SOCKET_VIEW',
               'decode_cross_view_event']:
    need('cross-view-abi', cross_common, anchor)
cross_ebpf = read('rust/gedefense-ebpf/src/iter.rs')
for anchor in ['#[lsm(hook = "socket_create")]',
               '#[lsm(hook = "socket_setsockopt")]', '#[kprobe]',
               'gedefense_crossview_socket_create',
               'gedefense_crossview_socket_setsockopt',
               'gedefense_crossview_sk_attach_filter',
               'static CROSS_VIEW_STATE', 'static CROSS_VIEW_EVENTS']:
    need('cross-view-ebpf', cross_ebpf, anchor)
cross_core = read('rust/gedefense-core/src/cross_view.rs')
for anchor in ['BPF_CMD_PROG_GET_NEXT_ID', 'BPF_CMD_PROG_GET_FD_BY_ID',
               'BPF_CMD_MAP_GET_FD_BY_ID', 'BPF_CMD_LINK_GET_FD_BY_ID',
               'NETLINK_SOCK_DIAG', 'PACKET_SHOW_FILTER',
               'fn report(', 'fn take_events(']:
    need('cross-view-core', cross_core, anchor)
cross_ipc = read('control/coreipc_crossview.go')
for anchor in ['ErrCrossViewUnavailable', 'func parseCoreCrossViewEvents',
               'func (c *CoreClient) CrossViewReport()',
               'func (c *CoreClient) CrossViewEvents()']:
    need('cross-view-ipc', cross_ipc, anchor)
need('cross-view-fuzz', read('control/coreipc_crossview_test.go'),
     'func FuzzCoreCrossViewParser')
cross_xdr = read('control/xdr_crossview.go')
for anchor in ['func (e *XDREngine) pollCrossView',
               '"XDR.HIDDEN_BPF_PROG"', '"XDR.HIDDEN_SOCKET"',
               '"XDR.PORTLESS_RAW_TAP"', '"XDR.HIDDEN_PROCESS"',
               '"XDR.LKM_HIDDEN"', '"XDR.FTRACE_HOOK_ANOMALY"',
               'crossViewToleratedRawTaps']:
    need('xdr-cross-view', cross_xdr, anchor)
forbid('xdr-cross-view', cross_xdr, r'\bKillEligible\s*:\s*true',
       'kill-eligible cross-view rule')
forbid('xdr-cross-view', cross_xdr, r'Decision:\s*"kill"', 'cross-view kill decision')

# AP-4: io_uring tracepoints/LSM hooks and pre-stealth LKM capture.
kh_common = read('rust/gedefense-common/src/kernel_hooks.rs')
for anchor in ['KERNEL_HOOK_EVENT_WIRE_BYTES', 'KERNEL_HOOK_KIND_IO_URING_CREATE',
               'KERNEL_HOOK_KIND_MODULE_LOAD', 'decode_kernel_hook_event',
               'KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD']:
    need('kernel-hooks-abi', kh_common, anchor)
kh_ebpf = read('rust/gedefense-ebpf/src/kernel_hooks.rs')
for anchor in ['gedefense_io_uring_create', 'gedefense_io_uring_register',
               'gedefense_io_uring_submit_req', 'gedefense_module_load',
               'gedefense_init_module', 'gedefense_finit_module',
               'gedefense_delete_module', 'gedefense_lsm_uring_override_creds',
               'gedefense_lsm_uring_sqpoll', 'gedefense_lsm_uring_cmd',
               'static KERNEL_HOOK_STATE', 'static KERNEL_HOOK_EVENTS',
               'static KERNEL_HOOK_OFFSETS']:
    need('kernel-hooks-ebpf', kh_ebpf, anchor)
kh_core = read('rust/gedefense-core/src/kernel_hooks.rs')
for anchor in ['/proc/kallsyms', 'KERNEL_HOOK_OFFSETS', 'fn epoch(',
               'fn take_events(']:
    need('kernel-hooks-core', kh_core, anchor)
kh_ipc = read('control/coreipc_kernel_hooks.go')
for anchor in ['ErrKernelHooksUnavailable', 'func parseCoreKernelHookEvents',
               'func (c *CoreClient) KernelHookEvents()']:
    need('kernel-hooks-ipc', kh_ipc, anchor)
need('kernel-hooks-fuzz', read('control/coreipc_kernel_hooks_test.go'),
     'func FuzzCoreKernelHookParser')
kh_xdr = read('control/xdr_kernel_hooks.go')
for anchor in ['func (e *XDREngine) pollKernelHooks', '"XDR.LKM_LOAD"',
               '"XDR.IO_URING_ANOMALY"', 'kernelHookModuleTolerated',
               'kernelHookIoUringTolerated']:
    need('xdr-kernel-hooks', kh_xdr, anchor)
forbid('xdr-kernel-hooks', kh_xdr, r'\bKillEligible\s*:\s*true',
       'kill-eligible kernel-hook rule')
hardening = read('control/hardening_sysctl.go')
for anchor in ['kernel.io_uring_disabled', 'vm.memfd_noexec',
               'sysctlControlReservedMaskBits', '1 << 22', '1 << 23',
               '2 disables io_uring entirely']:
    need('hardening-ap4', hardening, anchor)
core_main = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
for anchor in ['0x00df_ffff', '(1 << 22, &[("kernel.io_uring_disabled", "1")])',
               '(1 << 23, &[("vm.memfd_noexec", "2")])',
               '["KERNEL_HOOK_EVENTS"]', '["CROSS_VIEW_REPORT"]',
               '["PERSIST_GUARD_EVENTS"]', '["PERSIST_BASELINE"]',
               '"kernel.io_uring_disabled" =>', '"vm.memfd_noexec" =>']:
    need('core-v63-seams', core_main, anchor)
forbid('core-v63-seams', core_main, r'HARDENING_CUSTOM_MASK: u32 = 0x001f_ffff',
       'stale 21-bit hardening mask (AP-4 opt-in bits missing)')

# AP-5: persistence/peripheral integrity guard.
pers_common = read('rust/gedefense-common/src/persistence.rs')
for anchor in ['PERSIST_EVENT_WIRE_BYTES', 'PERSIST_CLASS_LD_PRELOAD',
               'PERSIST_CLASS_PAM', 'PERSIST_CLASS_DEVICE_CAMERA',
               'PERSIST_CLASS_SECRET_SSH', 'decode_persistence_event',
               'encode_persistence_event']:
    need('persistence-abi', pers_common, anchor)
pers_ebpf = read('rust/gedefense-ebpf/src/persistence.rs')
for anchor in ['gedefense_persistence_file_open', 'gedefense_persistence_mmap',
               'gedefense_persistence_ptrace', 'gedefense_process_vm_readv',
               'gedefense_process_vm_writev', 'static PERSIST_GUARD_STATE',
               'static PERSIST_GUARD_PATHS', 'static PERSIST_GUARD_EXECS',
               'static PERSIST_GUARD_EVENTS']:
    need('persistence-ebpf', pers_ebpf, anchor)
pers_core = read('rust/gedefense-core/src/persistence.rs')
for anchor in ['RESOLVE_NO_SYMLINKS', 'libc::SYS_openat2',
               '/var/lib/dpkg/info', '/var/lib/pacman/local',
               'PERSIST_IDLEHINT_UNAVAILABLE', 'PERSIST_GUARD_EXECS',
               'fn baseline(', 'fn take_events(']:
    need('persistence-core', pers_core, anchor)
pers_ipc = read('control/coreipc_persistence.go')
for anchor in ['ErrPersistenceUnavailable',
               'func parseCorePersistenceEvents',
               'func (c *CoreClient) PersistenceBaseline()']:
    need('persistence-ipc', pers_ipc, anchor)
need('persistence-fuzz', read('control/coreipc_persistence_test.go'),
     'func FuzzCorePersistenceParser')
pers_xdr = read('control/xdr_persistence.go')
for anchor in ['func (e *XDREngine) pollPersistence',
               'XDR.LD_PRELOAD_INTEGRITY', 'XDR.LINKER_HOOK',
               'XDR.PERSISTENCE_ENTRY_DRIFT', 'XDR.PERIPHERAL_BG_ACCESS',
               'XDR.EVDEV_KEYLOG_PROBE', 'XDR.MEMORY_SCRAPE_PROBE',
               'XDR.SECRET_STORE_ACCESS', 'persistenceQualityTemporal',
               'persistenceIntegrityTolerated']:
    need('xdr-persistence', pers_xdr, anchor)
forbid('xdr-persistence', pers_xdr, r'\bKillEligible\s*:\s*true',
       'kill-eligible persistence rule')
forbid('xdr-persistence', pers_xdr, r'Decision:\s*"kill"', 'persistence kill decision')

# AP-9 / S09: TUF-grade threshold feed anti-poisoning + semantic guard + HWR.
tuf_manifest = read('control/tuf_manifest.go')
for anchor in ['vgt-gedefense-tuf-manifest-v1', 'vgt-gedefense-tuf-role-v1',
               'tufSignatureThreshold = 2', 'TUFReasonSignatureThreshold',
               'TUFReasonExpired', 'TUFReasonEpochRollback',
               'TUFReasonContentBinding', 'TUFReasonDiffBudget',
               'TUFReasonImmutableZone', 'TUFReasonGlobalAllow',
               'TUFReasonRegexComplexity', 'TUFReasonSystemPathInject']:
    need('tuf-manifest', tuf_manifest, anchor)
tuf_verify = read('control/tuf_manifest_verify.go')
for anchor in ['func verifyTUFManifestEnvelope',
               'func parseTUFManifestEnvelope', 'ed25519.Verify']:
    need('tuf-verify', tuf_verify, anchor)
tuf_guard = read('control/tuf_guard.go')
for anchor in ['func', 'immutable', '0.0.0.0/0']:
    need('tuf-guard', tuf_guard, anchor)
tuf_epoch = read('control/tuf_epoch.go')
for anchor in ['vgt-gedefense-tuf-high-water-v1', 'tuf-high-water.json',
               'tuf-high-water.key', 'hmac', '0600']:
    need('tuf-epoch', tuf_epoch, anchor)
tuf_shadow = read('control/tuf_shadow.go')
for anchor in ['r5_isolation=shadow', 'r5_helper_isolation=helper-pending']:
    need('tuf-shadow', tuf_shadow, anchor)
feeds = read('control/feeds.go')
for anchor in ['TUF TUFSecurityStatus', 'tufFeedProtectionSnapshot',
               'SetTUFEventSink', 'feed.poisoning_blocked']:
    need('feeds-tuf-gate', feeds, anchor)
need_match('feeds-tuf-gate', feeds, 'TUF gate runs before Last-Known-Good promotion',
           r'tufGate := m\.tufPrepareSyncGateLocked\(now\)[\s\S]{0,400}?tufGuardBlocked')
tuf_tests = (read('control/tuf_manifest_test.go') + read('control/tuf_guard_test.go')
             + read('control/tuf_epoch_test.go') + read('control/tuf_integration_test.go'))
for anchor in ['TestTufManifestRejectsInsufficientThreshold',
               'TestTufManifestRejectsExpiredAndAbsurdSnapshot',
               'TestTufManifestEpochStrictlyMonotonic',
               'TestTufGuardDiffBudget', 'TestTufGuardImmutableZoneDeletion',
               'TestTufGuardGlobalAllow', 'TestTufGuardRegexComplexity',
               'TestTufGuardSystemPathInject',
               'TestTufFeedBoundaryRejectsPoisonedValidlySignedUpdate',
               'TestTufHighWaterStoreCorruptionsFailClosed']:
    need('tuf-tests', tuf_tests, anchor)
forbid('tuf-verify', tuf_verify, r'tufSignatureThreshold\s*=\s*1', 'single-signature TUF threshold')

if missing:
    raise SystemExit('V6.3.0 round-2 anchors missing:\n' + '\n'.join(missing))
PYV63R2
pass 'V6.3.0 AP-3 cross-view, AP-4 io_uring/LKM hooks, AP-5 persistence/peripheral integrity and AP-9 S09 TUF anti-poisoning anchors present'

# V6.3.0 round 3 (AP-6 StyX phase 2 / DNS tunnelling / GIEF v1.0 + SBC fusion and
# AP-7 PermitV1 / review queue / QUARANTINE_PRUNE / explainability). Anchors pin
# definitions, decisions and defaults; observe-only, metadata-only and the
# unchanged kill gate are pinned as explicit negatives.
