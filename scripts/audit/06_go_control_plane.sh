#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 6 (original lines 1433-1751).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
python3 - "$ROOT" <<'PYP5'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
missing = []

def read(relative):
    path = root / relative
    if not path.is_file():
        missing.append(f'missing file: {relative}')
        return ''
    return path.read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

def forbid(component, text, pattern, label):
    if re.search(pattern, text, re.S) is not None:
        missing.append(f'{component}: forbidden {label}')

# --- ABI-1: shared constants, epoch/flag word and the 64-byte event (§3) -----
common_lib = read('rust/gedefense-common/src/lib.rs')
common = read('rust/gedefense-common/src/lockdown.rs')
if 'mod lockdown;' not in common_lib or 'pub use lockdown::*;' not in common_lib:
    missing.append('rust-common-lib: lockdown module is not exported')
for anchor in (
    'pub const LOCKDOWN_STATE_MAGIC: u8 = 0x4C;', 'pub const LOCKDOWN_STATE_ABI: u8 = 1;',
    'pub const LOCKDOWN_FLAG_DROP_ALL: u8 = 1 << 0;', 'pub const LOCKDOWN_FLAG_ALLOW_LOOPBACK: u8 = 1 << 1;',
    'pub const LOCKDOWN_FLAG_HARDENING_APPLIED: u8 = 1 << 3;',
    'pub const LOCKDOWN_FLAG_USB_LOCKED: u8 = 1 << 4;', 'pub const LOCKDOWN_FLAG_TB_LOCKED: u8 = 1 << 5;',
    'pub const fn encode_lockdown_word(epoch: u32, mode: u8, flags: u8) -> u64 {',
    'pub const fn decode_lockdown_word(word: u64) -> Option<LockdownWord> {',
    'pub const LOCKDOWN_EVENT_WIRE_BYTES: usize = 64;',
    'pub const LOCKDOWN_REASON_POLICY: u8 = 8;', 'pub const LOCKDOWN_SOURCE_TIMER: u8 = 4;',
    'pub const LOCKDOWN_PHASE_DM: u8 = 8;', 'pub const LOCKDOWN_OUTCOME_PARTIAL: u8 = 5;',
    'pub reserved: [u8; 24],',
    'assert!(core::mem::size_of::<LockdownEvent>() == LOCKDOWN_EVENT_WIRE_BYTES);',
    'assert!(core::mem::offset_of!(LockdownEvent, reserved) == 40);',
):
    need('rust-common-lockdown', common, anchor)

# --- ABI-2: eBPF fastpath in XDP, TC-ingress and cgroup egress (§4) ----------
# Default word 0 = OFF; a foreign magic/ABI/mode or a zero word returns None so
# the pre-existing verdict path stays byte-identical (fail-safe, no claim).
ebpf = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-ebpf'/'src').rglob('*.rs')) if p.is_file())
for anchor in (
    'static LOCKDOWN_STATE: Array<u64> = Array::with_max_entries(1, 0);',
    'static LOCKDOWN_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);',
    'static LOCKDOWN_WITNESS_PASSES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);',
    'if magic != LOCKDOWN_STATE_MAGIC || abi != LOCKDOWN_STATE_ABI || mode != LOCKDOWN_MODE_ARMED {',
    'fn lockdown_drop_active() -> bool {',
    'fn lockdown_egress_verdict(ctx: &SkBuffContext) -> Option<i32> {',
    'fn lockdown_loopback_packet(ctx: &SkBuffContext) -> Option<bool> {',
    'increment_counter(&LOCKDOWN_DROPS);', 'increment_counter(&LOCKDOWN_WITNESS_PASSES);',
    'src[0] == 127 && dst[0] == 127',
):
    need('rust-ebpf', ebpf, anchor)
need_match('rust-ebpf', ebpf, 'XDP drops before the pre-existing inspect pipeline',
           r'pub fn gedefense_xdp\(ctx: XdpContext\) -> u32 \{.*?if lockdown_drop_active\(\) \{.*?return xdp_action::XDP_DROP;.*?match inspect\(&ctx\)')
need_match('rust-ebpf', ebpf, 'TC-ingress shots before the pre-existing policy pipeline',
           r'pub fn gedefense_tc_ingress\(ctx: TcContext\) -> i32 \{.*?if lockdown_drop_active\(\) \{.*?return TC_ACT_SHOT;.*?match inspect_tc_ingress\(&ctx\)')
need_match('rust-ebpf', ebpf, 'cgroup egress consults the lockdown verdict before the Point 3 policy',
           r'pub fn gedefense_egress\(ctx: SkBuffContext\) -> i32 \{.*?if let Some\(verdict\) = lockdown_egress_verdict\(&ctx\) \{.*?match inspect_egress\(&ctx\)')

# --- ABI-3: core LOCKDOWN_* command family, state file and re-arm (§5) -------
core = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
lockdown = read('rust/gedefense-core/src/lockdown.rs')
usb = ''.join(p.read_text(encoding='utf-8') for p in sorted(list((root/'rust'/'gedefense-core'/'src').glob('lockdown_usb*.rs')) + list((root/'rust'/'gedefense-core'/'src'/'lockdown_usb').rglob('*.rs'))))
uevent = read('rust/gedefense-core/src/lockdown_uevent.rs')
hardening = read('rust/gedefense-core/src/lockdown_hardening.rs')
brokers = read('rust/gedefense-core/src/lockdown_brokers.rs')
for command in (
    '["LOCKDOWN_VERSION"] => Ok(core.version().to_owned()),',
    '["LOCKDOWN_EPOCH"] => Ok(format!("{:08x}", core.epoch())),',
    '["LOCKDOWN_STATUS"] => Ok(lockdown_status(core)),',
    '["LOCKDOWN_ARM", mode, reason, flags] => {',
    '["LOCKDOWN_TRIGGER", source, reason, flags] => {',
    '["LOCKDOWN_CLEAR", expected_epoch, reason] => {',
    '["LOCKDOWN_SET_MODE", mode] => {',
    '["LOCKDOWN_EVENTS"] => lockdown_events(core),',
    '["LOCKDOWN_HEALTH"] => lockdown_health(core),',
    '["LOCKDOWN_PHASE", phase, state] => {',
):
    need('rust-core', core, command)
need('rust-core', core, '[command, ..] if command.starts_with("LOCKDOWN_") => {')
need('rust-core', core, 'ebpf.take_map("LOCKDOWN_STATE").ok_or("LOCKDOWN_STATE missing")?')
need('rust-core', core, 'ebpf.take_map("LOCKDOWN_DROPS").ok_or("LOCKDOWN_DROPS missing")?')
need('rust-core', core, 'ebpf.take_map("LOCKDOWN_WITNESS_PASSES").ok_or("LOCKDOWN_WITNESS_PASSES missing")?')
need('rust-core', core, 'let lockdown_state_path = arg("lockdown-state", lockdown::DEFAULT_STATE_FILE);')
for anchor in (
    'pub(crate) const VERSION: &str = "lockdown-v1";',
    'pub(crate) const DEFAULT_STATE_FILE: &str = "/var/lib/vgt/gedefense/LOCKDOWN.state";',
    'pub(crate) const DELEGATED: u8 = 0x80;',
    'pub(crate) const REASON_SESSIONS: &str = "no-dbus-session-lock";',
    'pub(crate) const REASON_DM: &str = "no-device-mapper";',
    'pub(crate) fn startup_rearm(&mut self) -> Result<String, String> {',
    'self.epoch = new_epoch(self.epoch)?;',
    'fn new_epoch(previous: u32) -> Result<u32, String> {',
    'pub(crate) fn state_text(&self) -> &\'static str {',
    'LOCKDOWN_PHASE_CELLS => (DELEGATED, "delegated-to-control"),',
):
    need('rust-core-lockdown', lockdown, anchor)
need('rust-core', core, 'fn write_lockdown_state_atomic(path: &Path, content: &str) -> Result<(), String> {')
need('rust-core', core, '.mode(0o640)')
need('rust-core', core, 'fn load_lockdown_state(path: &Path) -> LockdownStateLoad {')
need('rust-core', core, 'if core.phase_outcome(LOCKDOWN_PHASE_CELLS) == lockdown::DELEGATED {')
need('rust-core', core, '[LOCKDOWN_PHASE_SESSIONS, LOCKDOWN_PHASE_DM]')
need('rust-core', core, 'const LOCKDOWN_KERNEL_LOCKDOWN_REASON: &str = "boot-parameter-immutable";')

# --- USB/Thunderbolt policy + lossy uevent handling + rescan (§6.2) ---------
for anchor in (
    'self.sys_root.join("bus/usb/drivers_autoprobe")',
    'self.sys_root.join("bus/thunderbolt/devices")',
    'const CLASS_HID: u8 = 0x03;', 'const CLASS_HUB: u8 = 0x09;',
    'fn is_power_only(',
    'let Some(count) = num_interfaces else { return false };',
    'count as usize != ifaces.len()',
    'fn parent_device_devpath(',
    'DevicePolicy::PowerOnly', 'DevicePolicy::Console',
    'pub(crate) fn apply_usb(paths: &UsbPaths) -> PolicyReport {',
    'pub(crate) fn release_usb(paths: &UsbPaths) -> PolicyReport {',
    'pub(crate) fn apply_tb_device(paths: &UsbPaths, devpath: &str) -> Result<(), &\'static str> {',
):
    need('rust-core-usb', usb, anchor)
for anchor in (
    'pub(crate) const UEVENT_GROUP: u32 = 1;',
    'Some(libc::ENOBUFS) => Poll::Rescan,',
    'fn rescan(shared: &LockdownShared, usb_paths: &lockdown_usb::UsbPaths) {',
    'Poll::Rescan => rescan(shared, usb_paths),',
    'if shared.auto_network_drop().is_err() {',
):
    need('rust-core-uevent', uevent, anchor)

# --- Hardening: observation always, opt-in writes, modules_disabled never auto
for anchor in (
    'pub(crate) fn hardening_phase(&mut self, explicit: bool) -> (u8, &\'static str) {',
    'modules-disabled-auto-forbidden',
    'pub(crate) fn modules_disabled_auto_state() -> &\'static str {',
    'paths.kexec()', 'paths.sysrq()', 'paths.modules()',
    'Write::Blocked',
):
    need('rust-core-hardening', hardening, anchor)

# --- Broker freeze: reversible SIGSTOP/SIGCONT, honest frozen-not-locked -----
for anchor in (
    'pub(crate) const BROKER_STATUS: &str = "frozen-not-locked";',
    'pub(crate) const BROKER_NAMES: &[&str] =',
    'pub(crate) const BROKER_TTL: Duration = Duration::from_secs(300);',
    'libc::SIGSTOP', 'libc::SIGCONT', 'pidfd_signal',
):
    need('rust-core-brokers', brokers, anchor)
need('rust-core', core, 'fn lockdown_modules_never_use_shell_or_kill_primitives() {')

# --- Go control plane: default-off settings, latch, triggers, API (§7) --------
settings = read('control/lockdown_settings.go')
runtime_settings = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('runtime_settings*.go')) if not p.name.endswith('_test.go'))
engine = read('control/lockdown.go')
engine_ops = read('control/lockdown_engine.go')
phases = read('control/lockdown_phases.go')
triggers = read('control/lockdown_triggers.go')
api = read('control/lockdown_api.go')
status = read('control/lockdown_status.go')
coreipc = read('control/coreipc.go')
server = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
main = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('main*.go')) if not p.name.endswith('_test.go'))
state = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('state*.go')) if not p.name.endswith('_test.go'))
schema = read('control/fabric_schema.go')
fabric_settings = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('fabric_settings*.go')) if not p.name.endswith('_test.go'))
need_match('go-settings', settings, 'lockdown defaults are disabled and disarmed (inert upgrade)',
           r'func defaultLockdownFabricSettings\(\) LockdownFabricSettings \{.*?Enabled:\s+false,.*?AutoArm:\s+false,')
need_match('go-settings', settings, 'the panic loopback drop is opt-in and hardening is off by default',
           r'DropLoopback:\s+false,.*?HardeningApply:\s+false,')
for anchor in (
    'func validateLockdownFabricSettings(', 'func cloneLockdownFabricSettings(',
    'func effectiveLockdownSettings(',
    'lockdownConfirmationTrigger = "TRIGGER LOCKDOWN"',
    'lockdownConfirmationClear   = "CLEAR:LOCKDOWN"',
    'lockdownMaxRequireSources   = 4', 'lockdownMaxTargetsCap',
):
    need('go-settings', settings, anchor)
need_match('go-runtime', runtime_settings, 'settings schema version is at least v16 (lockdown namespace)',
           r'const fabricSettingsVersion = (?:1[6-9]|[2-9][0-9])')
need('go-runtime', runtime_settings, 'Lockdown *LockdownFabricSettings `json:"lockdown,omitempty"`')
need('go-runtime', runtime_settings, 'if settings.Lockdown == nil {')
need('go-runtime', runtime_settings, 'settings.Migrations = append(settings.Migrations, lockdownMigrationNote)')
need('go-runtime', runtime_settings, 'if err := validateLockdownFabricSettings(&lockdown); err != nil {')
for anchor in (
    'type LockdownEngine struct {', 'func NewLockdownEngine(',
    'lockdownEngineStatePath = "/var/lib/vgt/gedefense/lockdown-engine.state"',
    'lockdownEnginePurpose = "lockdown-engine"',
    'e.storage.Decrypt(e.path, lockdownEnginePurpose, raw, nil)',
    'e.storage.Encrypt(e.path, lockdownEnginePurpose, e.doc.Revision, plaintext)',
    'e.addEvent("critical", "lockdown.state.corrupt",',
    'errLockdownCapabilityMiss',
):
    need('go-engine', engine, anchor)
for anchor in (
    'func (e *LockdownEngine) Arm(', 'func (e *LockdownEngine) Trigger(',
    'func (e *LockdownEngine) Clear(',
    'lockdown.trigger.intent', 'lockdown.trigger.outcome',
    'lockdown.clear.intent', 'lockdown.clear.outcome',
    '"lockdown.phase."+phase.Phase',
    'lockdown.state.persist_failed',
    'engine.Reverse(id, "REVERSE "+id)',
    'lockdown.cells.resume_failed', 'lockdown.cells.resumed',
    'func lockdownCoreFlags(settings LockdownFabricSettings) uint8 {',
):
    need('go-engine', engine_ops, anchor)
for anchor in (
    'lockdownPhaseUnsupported', 'lockdownPhaseNameSessions', 'lockdownPhaseNameDM',
    'lockdownPhaseNameKernelLockdown', 'uid-0 process excluded by settings',
    'func (e *LockdownEngine) runCorePhases(',
):
    need('go-phases', phases, anchor)
for anchor in (
    'func lockdownIncidentCandidate(', 'func lockdownCanaryUnauthorizedProbe(',
    'func lockdownFingerprint(', 'func (e *LockdownEngine) applyTriggerGuards(',
    'errLockdownCooldown', 'errLockdownSourcesPending',
    'func (e *LockdownEngine) reconcileBootTrust(',
    'func (e *LockdownEngine) pollDuress(',
):
    need('go-triggers', triggers, anchor)
need('go-api', api, 'POST /api/v1/lockdown/trigger  {confirmation: "TRIGGER LOCKDOWN", reason, source?}')
need('go-api', api, 'strings.TrimSpace(in.Confirmation) != lockdownConfirmationTrigger')
need('go-api', api, 'strings.TrimSpace(in.Confirmation) != lockdownConfirmationClear')
need('go-api', api, 'view := s.lockdown.StatusView()')
for route in (
    'mux.HandleFunc("GET /api/v1/lockdown/status", s.auth(s.lockdownStatus))',
    'mux.HandleFunc("POST /api/v1/lockdown/arm", s.auth(s.lockdownArm))',
    'mux.HandleFunc("POST /api/v1/lockdown/trigger", s.auth(s.lockdownTrigger))',
    'mux.HandleFunc("POST /api/v1/lockdown/clear", s.auth(s.lockdownClear))',
):
    need('go-server', server, route)
need('go-server', server, '"/api/v1/lockdown/trigger",')
need('go-server', server, '"/api/v1/lockdown/clear":')
need('go-server', server, 's.lockdownLimiter = NewRateLimiter(1, 1)')
need('go-server', server, 'snapshot.Lockdown = &lockdownView')
need('go-state', state, 'Lockdown       *LockdownStatusView `json:"lockdown,omitempty"`')
need('go-xdr', xdr, 'func (e *XDREngine) AttachLockdown(engine *LockdownEngine) {')
need('go-xdr', xdr, 'e.lockdown.ObserveIncident(incident)')
need('go-main', main, 'lockdownEngine, lockdownErr := NewLockdownEngine(LockdownEngineConfig{')
need('go-main', main, 'lockdownEngine.AttachBootTrust(srv.bootTrustVerdict)')
need('go-main', main, 'go lockdownEngine.Run(xdrCtx)')
need('go-schema', schema, '{module: "lockdown", group: "Emergency Lockdown", key: "enabled"')
need('go-fabric-settings', fabric_settings, 'case "lockdown":')
for anchor in (
    'var ErrLockdownUnavailable = errors.New("lockdown capability unavailable")',
    'func (c *CoreClient) LockdownStatus() (CoreLockdownStatus, error) {',
    'func (c *CoreClient) LockdownTrigger(source, reason string, flags uint8) (CoreLockdownTriggerResult, error) {',
    'func (c *CoreClient) LockdownClear(expectedEpoch, reason string) (string, error) {',
    'func parseCoreLockdownStatus(payload string) (CoreLockdownStatus, error) {',
    'lockdownPhaseNameCells',
):
    need('go-coreipc', coreipc, anchor)
need('go-triggers', triggers, 'func parseCoreLockdownEvents(payload string) ([]CoreLockdownEvent, uint64, error) {')

# --- packaging boundary: exact grants, unchanged cap/af/syscall contract -----
# /sys/devices is required in addition to the bus paths because
# /sys/bus/usb/devices and /sys/bus/thunderbolt/devices are sysfs symlinks: a
# per-device "authorized" write resolves into /sys/devices/** and would be
# EROFS with a bus-only grant (fail-safe but ineffective).
unit = read('packaging/systemd/gedefense-core.service')
for directive in (
    'ReadWritePaths=-/sys/bus/usb -/sys/bus/thunderbolt/devices -/sys/devices',
    'ReadWritePaths=-/proc/sys/kernel/kexec_load_disabled -/proc/sys/kernel/sysrq -/proc/sys/kernel/modules_disabled',
    'ReadWritePaths=/var/lib/vgt/gedefense',
    'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_KILL',
    'AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_KILL',
    'RestrictAddressFamilies=AF_UNIX AF_NETLINK',
    'SystemCallFilter=@system-service bpf perf_event_open pidfd_open pidfd_send_signal fanotify_init fanotify_mark',
):
    need('systemd-core-unit', unit, directive)
# No further /sys node may be granted: the complete writable sysfs set is the
# pre-existing bpffs mount (plus /sys/fs/bpf/gedefense pin dir under
# ProtectKernelTunables=true on systemd 255+) and the three reviewed lockdown nodes.
sys_grants = set()
for line in unit.splitlines():
    if not line.startswith('ReadWritePaths='):
        continue
    for token in line.split('=', 1)[1].split():
        token = token.lstrip('-')
        if token == '/sys' or token.startswith('/sys/'):
            sys_grants.add(token)
if sys_grants != {'/sys/bus/usb', '/sys/bus/thunderbolt/devices', '/sys/devices', '/sys/fs/bpf', '/sys/fs/bpf/gedefense'}:
    missing.append('systemd-core-unit: unexpected writable sysfs set: ' + ', '.join(sorted(sys_grants)))
if len(re.findall(r'(?m)^CapabilityBoundingSet=', unit)) != 1:
    missing.append('systemd-core-unit: CapabilityBoundingSet must stay one reviewed line')
if re.search(r'(?m)^CapabilityBoundingSet=.*(?:CAP_SYS_PTRACE|CAP_SYS_MODULE|CAP_DAC_READ_SEARCH|CAP_SYS_RAWIO)', unit):
    missing.append('systemd-core-unit: lockdown must not widen the capability set (ptrace/module/DAC/rawio)')
if re.search(r'(?m)^RestrictAddressFamilies=.*(?:AF_INET|AF_PACKET|AF_BLUETOOTH)', unit):
    missing.append('systemd-core-unit: lockdown must not widen the address families')
if re.search(r'ReadWritePaths=(?:[^\n]*\s)?/sys(?:\s|$)', unit):
    missing.append('systemd-core-unit: /sys must not be granted writable as a whole (lockdown grants exact bus paths only)')
tmpfiles = read('packaging/tmpfiles/vgt-gedefense.conf')
need('tmpfiles', tmpfiles, 'd /var/lib/vgt/gedefense 1770 root gedefense -')
need('pkgbuild', read('packaging/arch/PKGBUILD'), '"${_source_root}/packaging/systemd/gedefense-core.service"')
need('validate-systemd', read('scripts/validate-systemd.sh'), 'POINT 5')
need('install-smoke', read('packaging/tests/install-smoke.sh'), 'POINT 5')

if missing:
    raise SystemExit('Point 5 lockdown anchors missing:\n' + '\n'.join(missing))
PYP5
pass 'Point 5 lockdown ABI, fail-safe eBPF fastpath, core state/re-arm, Go latch/API and packaging grants present'

# POINT 4 (P4-T3, docs/POINT4-WITNESS.md §3-§8, §11): mandatory anchors for the
# Out-of-Band Witness. Additive gate only - every pre-existing Point 1/2/3/5
# anchor above stays unchanged. Each anchor pins a definition, a decision, a
# hard bound or an honest capability boundary (never a bare comment or a test
# fixture), so removing a control cannot be compensated elsewhere. The witness is
# unprivileged Go control: it ships no daemon, no unit and no new
# capability/address-family/syscall contract, and the external witness server is
# deliberately not part of the repository (Phase 2, no fake server).
