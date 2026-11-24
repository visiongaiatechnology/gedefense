#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 4 (original lines 902-1130).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
python3 - "$ROOT" <<'PYP1'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
missing=[]

def read(relative):
    return (root/relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

common_lib=read('rust/gedefense-common/src/lib.rs')
common_titan=read('rust/gedefense-common/src/titan_exec.rs')
ebpf=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-ebpf'/'src').rglob('*.rs')) if p.is_file())
core=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
core_titan=read('rust/gedefense-core/src/titan_exec.rs')
btf=''.join(p.read_text(encoding='utf-8') for p in sorted(list((root/'rust'/'gedefense-core'/'src').glob('btf_offsets*.rs')) + list((root/'rust'/'gedefense-core'/'src'/'btf_offsets').rglob('*.rs'))))
ipc=read('control/coreipc.go')
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
settings=read('control/titan_exec_settings.go')
syncer=read('control/titan_exec_syncer.go')
syncer_status=read('control/titan_exec_syncer_status.go')
events=read('control/titan_exec_events.go')
runtime=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('runtime_settings*.go')) if not p.name.endswith('_test.go'))
schema=read('control/fabric_schema.go')
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
state=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('state*.go')) if not p.name.endswith('_test.go'))

# ABI-1: one shared, exactly 88-byte TitanExecEvent contract with a rejecting decoder.
need('rust-common', common_lib, 'mod titan_exec;')
need('rust-common', common_lib, 'pub use titan_exec::*;')
need('rust-common', common_titan, 'pub const TITAN_EXEC_EVENT_WIRE_BYTES: usize = 88;')
need('rust-common', common_titan, '#[repr(C)]')
need('rust-common', common_titan, 'pub struct TitanExecEvent {')
need('rust-common', common_titan, 'pub fn decode_titan_exec_event(bytes: &[u8]) -> Option<TitanExecEvent> {')
need('rust-common', common_titan, 'if bytes.len() != TITAN_EXEC_EVENT_WIRE_BYTES {')
need('rust-common', common_titan, 'reason > TITAN_EXEC_REASON_MAX')
need('rust-common', common_titan, 'pub fn encode_titan_exec_event(event: &TitanExecEvent) -> [u8; TITAN_EXEC_EVENT_WIRE_BYTES] {')
need('rust-common', common_titan, 'TITAN_EXEC_MODE_STRICT: u8 = 3;')

# ABI-2: both LSM hooks, the five maps/ring and the direct-reservation event write.
need('rust-ebpf', ebpf, '#[lsm(hook = "bprm_check_security")]')
need('rust-ebpf', ebpf, '#[lsm(hook = "mmap_file")]')
need('rust-ebpf', ebpf, 'pub fn gedefense_titan_exec_bprm(ctx: LsmContext) -> i32 {')
need('rust-ebpf', ebpf, 'pub fn gedefense_titan_exec_mmap(ctx: LsmContext) -> i32 {')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_STATE: Array<u64> = Array::with_max_entries(1, 0);')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_OFFSETS: Array<u32> = Array::with_max_entries(TITAN_EXEC_OFFSETS_ENTRIES, 0);')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_MODE: HashMap<u64, u8> =')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_POLICY: HashMap<[u8; 16], [u8; 16]> =')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(TITAN_EXEC_EVENT_RING_BYTES, 0);')
need('rust-ebpf', ebpf, 'TITAN_EXEC_EVENTS.reserve::<TitanExecEvent>(0)')
need('rust-ebpf', ebpf, 'entry.submit(0);')
need('rust-ebpf', ebpf, 'core::ptr::addr_of_mut!((*event).f_flags).write(0);')
need('rust-ebpf', ebpf, 'bpf_probe_read_kernel(address).ok()')
need('rust-ebpf', ebpf, 'increment_counter(&TITAN_EXEC_EVENTS_EMITTED);')
need('rust-ebpf', ebpf, 'increment_counter(&TITAN_EXEC_RING_DROPS);')
# The kernel-side gate must never grow a userland command/shell execution sink.
for forbidden in ('std::process::Command', 'Command::new', 'libc::exec', 'libc::system', '/bin/sh', '/bin/bash'):
    if forbidden in ebpf:
        missing.append(f'rust-ebpf: forbidden execution primitive {forbidden}')

# Rust core: active-LSM probe, validated BTF/arity, both attaches, honest status,
# reject-not-repair IPC arms and the fail-closed enforcement-unavailable path.
need('rust-core', core, 'let bpf_lsm_active = match titan_exec::bpf_lsm_active_from_sys_fs() {')
need('rust-core', core_titan, 'pub fn bpf_lsm_active_from_list(list: &str) -> bool {')
need('rust-core', core_titan, 'pub fn bpf_lsm_active_from_sys_fs() -> Result<bool, String> {')
need('rust-core', core_titan, 'pub const ENFORCEMENT_UNAVAILABLE: &str = "enforcement-unavailable";')
need('rust-core', core, 'fn attach_titan_exec_lsm(ebpf: &mut Ebpf, btf: &Btf) -> Result<(), BoxError> {')
need('rust-core', core, '("gedefense_titan_exec_bprm", "bprm_check_security"),')
need('rust-core', core, '("gedefense_titan_exec_mmap", "mmap_file"),')
need('rust-core', core, '["TITAN_EXEC_VERSION"] => core.titan_exec.version(),')
need('rust-core', core, '["TITAN_EXEC_SET_GLOBAL", mode, flags] => core.titan_exec.set_global(mode, flags),')
need('rust-core', core, '["TITAN_EXEC_ALLOW_ADD", path] => core.titan_exec.allow_add(path),')
need('rust-core', core, '["TITAN_EXEC_EVENTS"] => core.titan_exec.take_events(),')
need('rust-core', core, 'let Some(event) = decode_titan_exec_event(&item) else {')
need('rust-core', core, 'self.rejected_events = self.rejected_events.saturating_add(1);')
need('rust-core', core, 'fn enforcement_available(&self) -> bool {')
need('rust-core', core, 'if mode != TITAN_EXEC_MODE_OFF && !self.enforcement_available() {')
need('rust-core', core, 'return Err(titan_exec::ENFORCEMENT_UNAVAILABLE.into());')
need('rust-core', core, 'ebpf.take_map("TITAN_EXEC_STATE").ok_or("TITAN_EXEC_STATE missing")?')
# P1-T3 moved the hard attach shape out of `btf_offsets::matches_ebpf_slots` into
# the core predicate `titan_exec_offsets_match_ebpf_slots` (main.rs). Read both
# core files so the gate survives such a move, and pin the 1/4 arity condition
# itself: the looser 3..=5 BTF plausibility range is deliberately NOT the attach
# shape (only bprm=1/mmap=4 may ever be attached).
core_btf = core + '\n' + btf
need_match('rust-core', core_btf, 'the eBPF slot/arity predicate exists in a core file',
           r'fn\s+\w*(?:match|matches)_ebpf_slots\w*\s*\([^)]*\)\s*->\s*bool\s*\{')
need_match('rust-core', core_btf, 'the hard attach shape pins bprm arity 1 and mmap arity 4',
           r'bprm_nargs\s*==\s*1[\s\S]{0,200}?mmap_nargs\s*==\s*4')
need('rust-core', core, 'titan_exec_offsets_match_ebpf_slots(&offsets)')
need('rust-core', btf, 'u16::from_le_bytes')
need('rust-core', btf, 'u32::from_le_bytes')
need('rust-core', btf, 'pub const MAX_VMLINUX_BTF_BYTES: usize = 64 * 1024 * 1024;')
need_match('rust-core', core, 'Titan hooks attach only on active BPF LSM, valid offsets and supported hook arity',
           r'if titan_exec\.offsets_valid && titan_slots_supported && bpf_lsm_active \{.*?attach_titan_exec_lsm\(&mut ebpf, btf\)')
# P3 fix in the core: `attached` is only true after an active-LSM attach, and
# `+bpf-lsm-cell`/`cell_lsm=attached` are gated on that boolean.
need('rust-core', core, 'if cell_lsm_attached {')
need_match('rust-core', core, 'the bpf-lsm-cell PING token is gated on the real attach',
           r'if cell_lsm_attached \{\s*mode\.push_str\("\+bpf-lsm-cell"\);')
need('rust-core', core, '"BPF LSM is not active (or its BTF is missing); Gaia Cell host socket reinforcement optional-unavailable, bpf-lsm-cell not claimed"')
need('rust-core', core, 'fn require_cell_lsm(&self) -> Result<(), BoxError> {')

# Go control plane: settings namespace (v14, default off), read-only status/event
# API, strict parsers, capability sentinel and the fail-closed enforcement gate.
need('go-ipc', ipc, 'var ErrTitanExecUnavailable = errors.New("titan-exec capability unavailable")')
need('go-ipc', ipc, 'func (c *CoreClient) TitanExecEvents() (string, error) {')
need('go-ipc', ipc, 'func (c *CoreClient) TitanExecStatus() (TitanExecCoreStatus, error) {')
need('go-ipc', ipc, 'func parseTitanExecCoreStatus(payload string) (TitanExecCoreStatus, error) {')
need('go-events', events, 'func parseCoreTitanExecEvents(payload string) (events []CoreTitanExecEvent, dropped uint64, err error) {')
need('go-settings', settings, 'func defaultTitanExecFabricSettings() TitanExecFabricSettings {')
need_match('go-settings', settings, 'titan_exec defaults are disabled and off',
           r'func defaultTitanExecFabricSettings\(\) TitanExecFabricSettings \{.*?Enabled:\s+false,.*?Mode:\s+TitanExecModeOff,')
# POINT 2 (P2-T3) raised the settings schema to v15 (parser_cells namespace);
# the P1 anchor must follow the current schema version instead of pinning 14,
# otherwise a legitimate v15 upgrade fails the P1 gate. The titan_exec migration
# note below still proves the P1 namespace migration exists in v15.
need_match('go-settings', runtime, 'settings schema version is at least v15 (P2 parser_cells migration)',
           r'const fabricSettingsVersion = (?:1[5-9]|[2-9][0-9])')
need('go-settings', runtime, 'titan_exec namespace added with enabled=false and mode=off')
need('go-schema', schema, '{module: "titan_exec", group: "Kernel Exec Gate", key: "enabled"')
need('go-syncer', syncer, 'type titanExecPolicySyncer struct {')
need('go-syncer', syncer, 'func NewTitanExecPolicySyncer(')
need('go-syncer', syncer_status, 'func titanExecEnforcementUnavailable(plan titanExecPolicyPlan, status TitanExecCoreStatus) (reason, state string, unavailable bool) {')
need('go-syncer', syncer_status, 'if plan.Mode == 0 {')
need('go-syncer', syncer_status, 'BPF-LSM is not active in the running kernel; add bpf to the lsm= kernel command line and reboot before enforcing')
need('go-syncer', syncer_status, 'func (s *titanExecPolicySyncer) finishEnforcementUnavailable(')
need('go-syncer', syncer_status, 'TitanExecSyncStateInactive')
need('go-xdr', xdr, 'func (e *XDREngine) TitanExecPolicyStatus() TitanExecSyncStatus {')
need('go-xdr', xdr, 'e.titanExec = NewTitanExecPolicySyncer(titanExecCore, state, runtime, titanExecPlanDeps{})')
need('go-xdr', xdr, 'func (e *XDREngine) titanExecSensorState() string {')
need('go-xdr', xdr, 'case errors.Is(drainErr, ErrTitanExecUnavailable):')
need_match('go-state', state, 'status snapshot carries the bounded titan_exec field',
           r'TitanExec\s+\*TitanExecStatus')
need('go-api', server, 'mux.HandleFunc("GET /api/v1/titan/exec/status", s.auth(s.titanExecStatus))')
need('go-api', server, 'mux.HandleFunc("GET /api/v1/titan/exec/events", s.auth(s.titanExecEvents))')
# P3 activation fix in the control plane: a configured Cell LSM is reported as
# `cell-lsm-unavailable`, never as a working `bpf-lsm-cell`.
need('go-xdr', xdr, 'mode = "cell-lsm-unavailable+" + mode')
need('go-xdr', xdr, 'mode = "bpf-lsm-cell+" + mode')

if missing:
    raise SystemExit('Point 1 Titan exec-gate anchors missing:\n'+'\n'.join(missing))
PYP1
pass 'Point 1 Titan exec-gate ABI, LSM attach gate, fail-closed status and P3 claim fix present'

# POINT 1 T7-FAIL fix (2026-11-15): modern kernels store inode ctime as split
# `i_ctime_sec`/`i_ctime_nsec`; the core publishes the real nsec width via
# OFFSETS[28] and keeps the legacy timespec64 pair as fallback, while the hook
# reads 4/8 bytes accordingly and saturates the sum (never a fake match).
python3 - "$ROOT" <<'PYP1CTIME'
from pathlib import Path
import sys
root=Path(sys.argv[1])
missing=[]

def read(relative):
    return (root/relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

ebpf=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-ebpf'/'src').rglob('*.rs')) if p.is_file())
core=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
btf=''.join(p.read_text(encoding='utf-8') for p in sorted(list((root/'rust'/'gedefense-core'/'src').glob('btf_offsets*.rs')) + list((root/'rust'/'gedefense-core'/'src'/'btf_offsets').rglob('*.rs'))))

need('rust-core', btf, 'pub const OFF_INODE_I_CTIME_NSEC_WIDTH: usize = 28;')
need('rust-core', btf, 'self.field_ref(inode, &["i_ctime_sec"])')
need('rust-core', btf, 'self.field_ref(inode, &["i_ctime", "tv_sec"])')
need('rust-core', core, 'table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH] = offsets.inode_i_ctime_nsec_width;')
need('rust-ebpf', ebpf, 'const TITAN_OFF_INODE_CTIME_NSEC_WIDTH: u32 = 28;')
need('rust-ebpf', ebpf, 'let nsec: u64 = if offsets.ctime_nsec_width == TITAN_CTIME_NSEC_WIDTH_32 {')
need('rust-ebpf', ebpf, 'seconds_ns.saturating_add(nsec)')

if missing:
    raise SystemExit('Point 1 T7 ctime anchors missing:\n'+'\n'.join(missing))
PYP1CTIME
pass 'Point 1 T7 fix (a): split-inode ctime layout, real nsec width and saturating compare present'

# POINT 1 T7-Befund fix (b) + precision (c) (2026-11-15): the kernel task name is
# process-controlled (PR_SET_NAME), so the parser accepts every raw byte sequence
# and only enforces the NUL-padding shape; hostile names must never suppress a
# batch and are sanitised only for output. The inert-policy ban applies to an
# ENABLED namespace whose mode is off; a disabled draft stays allowed.
python3 - "$ROOT" <<'PYP1COMM'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
missing=[]

def read(relative):
    return (root/relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

events=read('control/titan_exec_events.go')
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
settings=read('control/titan_exec_settings.go')

need('go-events', events, 'func decodeTitanExecComm(field string) (string, error) {')
need('go-events', events, 'sanitizeTitanExecComm(decoded[:end])')
need('go-xdr', xdr, 'func sanitizeTitanExecComm(raw []byte) string {')
need_match('go-settings', settings, 'enabled mode=off policies with rules are rejected (drafts stay allowed)',
           r'if in\.Enabled && mode == 0 &&[\s\S]{0,220}?len\(in\.ExecRoots\) > 0')

if missing:
    raise SystemExit('Point 1 T7 comm/inert-policy anchors missing:\n'+'\n'.join(missing))
PYP1COMM
pass 'Point 1 T7 fix (b/c): raw-comm contract and enabled-only inert-policy ban present'

# POINT 2 (docs/POINT2-PARSER-CELLS.md): ephemeral "parser-ephemeral" Gaia cells.
# Additive gate only - every pre-existing Point 1/Point 3 anchor above stays
# unchanged. It pins the privilege split (only the Rust helper spawns/executes),
# the VGTGC2 auth protocol, fail-closed/default-off behaviour and the packaging
# boundary (unit sandbox, tmpfiles, provisioning, installer/release/deployment).
