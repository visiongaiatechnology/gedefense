#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 3 (original lines 675-901).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
ebpf=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-ebpf'/'src').rglob('*.rs')) if p.is_file())
core=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
ipc=(root/'control'/'coreipc.go').read_text(encoding='utf-8')
packages=(root/'control'/'package_integrity_linux.go').read_text(encoding='utf-8')
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
required={
    'eBPF exec sensor': ['#[tracepoint]', 'gedefense_exec', 'EXEC_EVENTS.output::<ExecEvent>'],
    'eBPF egress enforcement': [
        '#[cgroup_skb(egress)]', 'gedefense_egress',
        'EGRESS_EVENTS.output::<EgressDropEvent>', 'BLOCKLIST_V4', 'BLOCKLIST_V6',
    ],
    'eBPF GaiaCells LSM enforcement': [
        '#[lsm(hook = "socket_create")]', 'gedefense_cell_socket_create',
        'CELL_LSM_POLICIES', 'CELL_LSM_EVENTS.output::<CellLsmDenyEvent>', 'Ok(-EPERM)',
    ],
    'privileged event broker': ['TracePoint', 'sched_process_exec', 'RingBuf<MapData>', '["EXEC_EVENTS"]'],
    'privileged egress broker': [
        'CgroupSkbAttachType::Egress', 'CgroupAttachMode', 'AllowMultiple',
        '["EGRESS_EVENTS"]', 'take_egress_events',
    ],
    'privileged GaiaCells LSM broker': [
        'Btf::from_sys_fs()', 'attach_cell_socket_lsm',
        'program.load("socket_create", btf)?',
        '["CELL_POLICY_EPOCH"]', '["CELL_POLICY_SET", cgroup_id, flags]',
        '["CELL_POLICY_DEL", cgroup_id]', '["CELL_LSM_EVENTS"]',
        'flag("require-bpf-lsm")',
    ],
    'authenticated event client': ['func (c *CoreClient) ExecEvents()', 'parseCoreExecEvents'],
    'authenticated egress client': [
        'func (c *CoreClient) EgressEvents()', 'parseCoreEgressDropEvents',
    ],
    'authenticated GaiaCells LSM client': [
        'func (c *CoreClient) CellPolicyEpoch()',
        'func (c *CoreClient) CellPolicySet(',
        'func (c *CoreClient) CellPolicyDelete(',
        'func (c *CoreClient) CellLSMEvents()',
        'parseCoreCellLSMDenyEvents',
    ],
    'XDR event pipeline': ['ebpf-exec+procfs-fallback', 'readExecProcess', 'xdr.exec_sensor_fallback'],
    'XDR egress pipeline': [
        'cgroup-egress+procfs-bounded-fallback', 'xdr.egress_blocked',
        'xdr.egress_sensor_fallback',
    ],
    'XDR GaiaCells LSM pipeline': [
        'syncCellLSMPolicies', 'recordCellLSMDeny',
        'xdr.cell_lsm_policy_unavailable', 'xdr.cell_lsm_event_unavailable',
        'CELL.LSM_SOCKET_DENY',
    ],
    'package integrity scanner': [
        'gzip.NewReader', 'sha256.New', 'syscall.O_NOFOLLOW',
        'packageIntegrityMaxTotalBytes', 'package path parent escaped jail',
    ],
    'package integrity API': [
        'GET /api/v1/package-integrity', 'POST /api/v1/package-integrity/scan',
        'packageIntegrityPostureCheck',
    ],
}
texts={
    'eBPF exec sensor': ebpf,
    'eBPF egress enforcement': ebpf,
    'eBPF GaiaCells LSM enforcement': ebpf,
    'privileged event broker': core,
    'privileged egress broker': core,
    'privileged GaiaCells LSM broker': core,
    'authenticated event client': ipc,
    'authenticated egress client': ipc,
    'authenticated GaiaCells LSM client': ipc,
    'XDR event pipeline': xdr,
    'XDR egress pipeline': xdr,
    'XDR GaiaCells LSM pipeline': xdr,
    'package integrity scanner': packages,
    'package integrity API': server,
}
missing=[]
for component, anchors in required.items():
    missing.extend(f'{component}: {anchor}' for anchor in anchors if anchor not in texts[component])
if missing:
    raise SystemExit('local EDR/package-integrity anchors missing:\n'+'\n'.join(missing))
PY
pass 'kernel exec EDR, GaiaCells BPF-LSM and signed-package integrity controls present'

# POINT 3 (P3-T6, docs/POINT3-EGRESS-BEACON.md): mandatory anchors for the
# per-cgroup egress enforcement and the beacon/exfiltration detector. Every
# anchor pins a definition, a decision or a default - never a bare comment or a
# test fixture - so removing a control cannot be compensated elsewhere.
python3 - "$ROOT" <<'PYSTYX'
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
common_flow=read('rust/gedefense-common/src/styx_flow.rs')
ebpf=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-ebpf'/'src').rglob('*.rs')) if p.is_file())
core=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
core_flow=read('rust/gedefense-core/src/styx_flow.rs')
ipc=read('control/coreipc.go')
beacon=read('control/styx_beacon.go')
# The Go StyX policy/sync anchors live across the VGT line-limit split
# (styx_settings.go, styx_policy_plan.go, styx_syncer.go,
# styx_syncer_status.go, styx_policy.go). Concatenate every production
# control/styx_*.go file so the anchors stay pinned to the whole subsystem and a
# future split into even more files cannot silently satisfy the gate with an
# empty file set.
styx_sources=sorted((root/'control').glob('styx_*.go'))
styx_sources=[path for path in styx_sources if not path.name.endswith('_test.go')]
if 'styx_policy.go' not in {path.name for path in styx_sources}:
    missing.append('go-policy: control/styx_policy.go missing from the StyX source set')
policy='\n'.join(path.read_text(encoding='utf-8') for path in styx_sources)
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
runtime=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('runtime_settings*.go')) if not p.name.endswith('_test.go'))
schema=read('control/fabric_schema.go')
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))

# ABI-1: one shared, exactly 104-byte FlowEvent contract with a rejecting decoder.
need('rust-common', common_lib, 'mod styx_flow;')
need('rust-common', common_lib, 'pub use styx_flow::*;')
need('rust-common', common_flow, 'pub const STYX_FLOW_EVENT_WIRE_BYTES: usize = 104;')
need('rust-common', common_flow, '#[repr(C)]')
need('rust-common', common_flow, 'pub struct FlowEvent {')
need('rust-common', common_flow, 'pub fn decode_styx_flow_event(bytes: &[u8]) -> Option<FlowEvent> {')
need('rust-common', common_flow, 'if bytes.len() != STYX_FLOW_EVENT_WIRE_BYTES {')
need('rust-common', common_flow, 'verdict > STYX_VERDICT_DEFAULT_DENY')
need('rust-common', common_flow, 'pub const STYX_MODE_OFF: u8 = 0;')
need('rust-common', common_flow, 'pub const STYX_FLAG_LOG_FLOWS: u8 = 1 << 6;')

# ABI-2: the egress hook keeps the legacy verdict/event path and adds the StyX maps.
need('rust-ebpf', ebpf, '#[cgroup_skb(egress)]')
need('rust-ebpf', ebpf, 'pub fn gedefense_egress(ctx: SkBuffContext) -> i32 {')
need('rust-ebpf', ebpf, 'EGRESS_EVENTS.output::<EgressDropEvent>(&event, 0);')
need('rust-ebpf', ebpf, 'static CELL_EGRESS_MODE: HashMap<u64, u8> =')
need('rust-ebpf', ebpf, 'static STYX_GLOBAL: Array<u64> = Array::with_max_entries(1, 0);')
need('rust-ebpf', ebpf, 'static STYX_RESOLVED: LruHashMap<u64, [u8; 16]> =')
need('rust-ebpf', ebpf, 'static FLOW_AGG_V4: LruPerCpuHashMap<[u8; 16], [u8; 40]> =')
need('rust-ebpf', ebpf, 'static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(')
need('rust-ebpf', ebpf, 'FLOW_EVENTS.reserve::<FlowEvent>(0)')
need('rust-ebpf', ebpf, 'entry.submit(0);')
need('rust-ebpf', ebpf, 'let global = match STYX_GLOBAL.get(STYX_GLOBAL_INDEX) {')
need('rust-ebpf', ebpf, 'increment_counter(&FLOW_RING_DROPS);')
need('rust-ebpf', ebpf, 'STYX_VERDICT_METADATA_VETO')
need('rust-ebpf', ebpf, 'STYX_VERDICT_DNS_PIN')
need_match('rust-ebpf', ebpf,
           'default-off shortcut returns the byte-identical 5.2.0 verdict path',
           r'if global_mode == STYX_MODE_OFF && \(global_flags & STYX_FLAG_LOG_FLOWS\) == 0 \{.*?return legacy_inspect_egress\(ctx\);')

# Rust core: validate before one map write, seed the mandatory veto, drain honestly.
need('rust-core', core, 'mod styx_flow;')
need('rust-core', core, 'ebpf.take_map("STYX_GLOBAL").ok_or("STYX_GLOBAL missing")?')
need('rust-core', core, 'ebpf.take_map("FLOW_EVENTS").ok_or("FLOW_EVENTS missing")?')
need('rust-core', core, 'seed_styx_mandatory_veto(&mut styx_block_v4, &mut styx_block_v6)?;')
need('rust-core', core, 'encode_styx_global(styx_epoch as u32, STYX_MODE_OFF, 0)')
need('rust-core', core, 'CgroupAttachMode::AllowOverride')
need('rust-core', core, '["STYX_VERSION"] => core.styx_version(),')
need('rust-core', core, '["STYX_GLOBAL", args @ ..] => core.styx_set_global(args),')
need('rust-core', core, '["STYX_MODE_SET", args @ ..] => core.styx_mode_set(args),')
need('rust-core', core, '["STYX_FLOW_EVENTS"] => core.styx_take_flow_events(),')
need('rust-core', core, '["STYX_FLOW_HEALTH"] => core.styx_flow_health(),')
need('rust-core', core, 'let Some(event) = decode_styx_flow_event(&item) else {')
need('rust-core', core, 'self.styx_flow_rejected = self.styx_flow_rejected.saturating_add(1);')
need('rust-core', core_flow, 'pub const STYX_GLOBAL_FLAG_LOG_FLOWS: u8 = 1 << 0;')
need('rust-core', core_flow, 'Ok(if flags & STYX_GLOBAL_FLAG_LOG_FLOWS != 0 { STYX_FLAG_LOG_FLOWS } else { 0 })')
need('rust-core', core_flow, 'pub fn encode_styx_global(epoch: u32, mode: u8, flags: u8) -> u64 {')
need('rust-core', core_flow, 'pub fn encode_styx_flow_event_text(event: &FlowEvent) -> Option<String> {')

# Go: capability-gated commands, all-or-nothing parser, beacon detector, syncer.
need('go-ipc', ipc, 'func parseCoreStyxFlowEvents(response string) ([]CoreStyxFlowEvent, uint64, error) {')
need('go-ipc', ipc, '"STYX_VERSION"')
need('go-ipc', ipc, '"STYX_GLOBAL"')
need('go-ipc', ipc, '"STYX_MODE_SET"')
need('go-ipc', ipc, '"STYX_FLOW_EVENTS"')
need('go-ipc', ipc, 'ErrStyxUnavailable')
need_match('go-ipc', ipc, 'batch and payload limits pinned on the control-plane side',
           r'maxStyxFlowEventsPerResponse = 64.*?maxStyxFlowPayloadBytes = 16 << 10')
need('go-beacon', beacon, 'type StyxBeaconEngine struct {')
need('go-beacon', beacon, 'CausalEdge: EdgeEgressAttempted')
need_match('go-beacon', beacon, 'signal 3 can never fire without a DNS capability (no fake)',
           r'if b\.cfg\.DNSObservationAvailable && !aggregate\.lastDNSSeen')
need_match('go-beacon', beacon, 'a degraded sensor suppresses incidents instead of claiming absence',
           r'if b\.degraded \{\s*b\.suppressed\+\+\s*return false')
need_match('go-beacon', beacon, 'a repeated overflow poll series degrades the sensor',
           r'b\.overflowPolls\+\+.*?if b\.overflowPolls >= 3 \{\s*b\.degraded = true')
need('go-policy', policy, 'type styxPolicySyncer struct {')
need('go-policy', policy, 'func (s *styxPolicySyncer) SyncIfDue(ctx context.Context) StyxSyncStatus {')
need('go-policy', policy, 's.core.StyxGlobal(0, 0)')
need('go-policy', policy, 's.core.StyxModeSet(cell.CgroupID, cell.Mode, cell.Flags)')
need_match('go-policy', policy, 'default namespace is disabled and off (no behaviour change)',
           r'func defaultStyxFabricSettings\(\) StyxFabricSettings \{.*?Enabled:\s+false,.*?Mode:\s+StyxModeOff,')
need('go-policy', policy, 'IPv6 cell rules cannot carry port/protocol restrictions in phase 1')
need('go-policy', policy, 'a port rule requires a host CIDR (/32 or /128)')
need('go-policy', policy, 'port range must be a single port or 0-65535')
need('go-xdr', xdr, 'e.styxBeacon = NewStyxBeaconEngine(StyxBeaconConfig{')
need('go-xdr', xdr, 'e.styxPolicy = NewStyxPolicySyncer(core, state, runtime)')
need('go-xdr', xdr, 'events, dropped, flowErr := e.core.StyxFlowEvents()')
need('go-xdr', xdr, 'e.recordStyxFlowBatch(events, dropped, now)')
need('go-xdr', xdr, 'noteVerificationFailure("styx_flow_sensor"')
need('go-settings', runtime, 'Styx *StyxFabricSettings `json:"styx,omitempty"`')
need('go-settings', runtime, 'styX namespace added with enabled=false and mode=off')
need('go-schema', schema, '{module: "styx", group: "Kernel Egress Enforcement", key: "enabled"')
need('go-api', server, 'mux.HandleFunc("GET /api/v1/styx/status", s.auth(s.styxKernelStatus))')
need('go-api', server, 'mux.HandleFunc("GET /api/v1/styx/beacons", s.auth(s.styxBeacons))')

if missing:
    raise SystemExit('Point 3 egress/beacon anchors missing:\n'+'\n'.join(missing))
PYSTYX
pass 'Point 3 per-cgroup egress, flow telemetry, beacon detector, policy syncer and default-off guards present'

# POINT 1 (P1-T6, docs/POINT1-TITAN-EXEC-GATE.md): mandatory anchors for the
# Titan eBPF-LSM exec/library gate. Every anchor pins a definition, a decision, a
# fail-safe default or an honest-status boundary - never a bare comment or a test
# fixture - so removing a control cannot be compensated elsewhere. The ELF gate
# below additionally proves the shipped object carries both LSM hooks and maps.
