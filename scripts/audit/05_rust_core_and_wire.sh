#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 5 (original lines 1131-1432).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
python3 - "$ROOT" <<'PYP2'
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

# --- L1: privileged Rust helper crate (only spawner and only execve sink) ---
workspace = read('rust/Cargo.toml')
helper_cargo = read('rust/gedefense-cell-helper/Cargo.toml')
need('rust-workspace', workspace, '"gedefense-cell-helper",')
need('helper-cargo', helper_cargo, 'name = "gedefense-cell-helper"')
for forbidden_dependency in ('serde', 'toml'):
    if forbidden_dependency in helper_cargo:
        missing.append(f'helper-cargo: forbidden dependency {forbidden_dependency} (offline text contract)')

helper_sources = {}
for source_path in sorted((root / 'rust' / 'gedefense-cell-helper' / 'src').glob('*.rs')):
    helper_sources[source_path.name] = source_path.read_text(encoding='utf-8')
for required in ('main.rs', 'protocol.rs', 'config.rs', 'lifecycle.rs', 'export.rs', 'types.rs', 'sandbox.rs', 'seccomp.rs'):
    if required not in helper_sources:
        missing.append(f'helper-crate: missing source {required}')
sandbox = helper_sources.get('sandbox.rs', '')
seccomp = helper_sources.get('seccomp.rs', '')
protocol = helper_sources.get('protocol.rs', '')
config = helper_sources.get('config.rs', '')
export = helper_sources.get('export.rs', '')
lifecycle = helper_sources.get('lifecycle.rs', '')
types = helper_sources.get('types.rs', '')
main = helper_sources.get('main.rs', '')

# Sandbox contract (spec §4): namespaces, tmpfs/read-only mounts, credential and
# capability drop, no_new_privs and a single pinned execve as the last child step.
for anchor in (
    'libc::CLONE_NEWNS', 'libc::CLONE_NEWPID', 'libc::CLONE_NEWIPC', 'libc::CLONE_NEWUTS', 'libc::CLONE_NEWNET',
    'libc::MS_REC | libc::MS_PRIVATE', 'c"tmpfs"', 'hidepid=2',
    'libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC', 'libc::MS_RDONLY', 'libc::chroot',
    'libc::setgroups(0, std::ptr::null())', 'libc::setresgid', 'libc::setresuid',
    'libc::PR_CAPBSET_DROP', 'PR_CAP_AMBIENT', 'libc::PR_SET_NO_NEW_PRIVS',
    'libc::PR_SET_PDEATHSIG', 'libc::umask(0o077)',
    'libc::execve(plan.binary.as_ptr()', 'display_unavailable',
    'GEDEFENSE_INPUT_FD', 'GEDEFENSE_EXPORT_FD',
):
    need('helper-sandbox', sandbox, anchor)
need_match('helper-sandbox', sandbox, 'X11 display variables are always refused', r'XAUTHORITY')
for reserved in ('HOME', 'USER', 'LOGNAME', 'PATH', 'TMPDIR', 'XDG_RUNTIME_DIR', 'WAYLAND_DISPLAY', 'PIPEWIRE_REMOTE'):
    need('helper-sandbox', sandbox, f'"{reserved}"')

# Seccomp contract (§4.4): arch check, no_new_privs before install, exact deny
# list with EPERM (not ENOSYS) and AF_UNIX-only sockets.
for anchor in (
    'pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;', 'SECCOMP_SET_MODE_FILTER',
    'libc::PR_SET_NO_NEW_PRIVS', 'libc::SYS_seccomp', 'libc::AF_UNIX', 'RET_ERRNO | libc::EPERM as u32',
):
    need('helper-seccomp', seccomp, anchor)
for denied in (
    'ptrace', 'process_vm_readv', 'process_vm_writev', 'bpf', 'perf_event_open', 'userfaultfd',
    'io_uring_setup', 'io_uring_enter', 'io_uring_register', 'mount', 'umount2', 'pivot_root',
    'chroot', 'unshare', 'setns', 'clone', 'clone3', 'fork', 'vfork', 'keyctl', 'add_key',
    'request_key', 'kexec_load', 'init_module', 'finit_module', 'delete_module',
    'open_by_handle_at', 'name_to_handle_at',
):
    need('helper-seccomp', seccomp, f'libc::SYS_{denied}')

# VGTGC2 wire contract (§3): HMAC-SHA256, SO_PEERCRED, bounded timestamp/replay,
# size limits and exactly one SCM_RIGHTS FD.
for anchor in (
    'VGTGC2', 'VGTGC2R', 'fn verify_mac', 'fn parse_request', 'libc::SO_PEERCRED',
    'libc::SCM_RIGHTS', 'REPLAY_CACHE_CAPACITY', 'MAX_REQUEST_BYTES', 'MAX_REQUESTS_PER_CONNECTION',
):
    need('helper-protocol', protocol, anchor)
need_match('helper-protocol', protocol, 'timestamp window is bounded to +-30s', r'abs_diff\(ts\) > TIME_WINDOW_SECS')
need('helper-protocol', protocol, 'pub fn parse_response')
need('helper-protocol', protocol, 'fn encode_line')

# Profile/input/export validation (§4): root-owned 0640 config, O_NOFOLLOW,
# 32-byte key, sha256-pinned binaries, bounded staging, sealed memfd broker.
for anchor in (
    'pub const KEY_FILE_LEN: u64 = 32;', 'pub const MAX_PROFILE_FILE_BYTES: u64 = 256 * 1024;',
    'md.mode() & 0o777 != 0o640', 'libc::O_NOFOLLOW', 'pub fn validate_staging_dirs',
    'pub fn validate_input', 'pub fn validate_export_dir',
):
    need('helper-config', config, anchor)
need_match('helper-config', config, 'parser binaries are sha256-pinned', r'sha256')
need('helper-export', export, 'create_new(true)')
for anchor in ('libc::F_SEAL_WRITE', 'libc::F_SEAL_GROW', 'libc::F_SEAL_SHRINK', 'libc::SYS_memfd_create', 'copy_bounded'):
    need('helper-export', export, anchor)
for anchor in (
    'pub const CGROUP_PREFIX: &str = "parser-";', 'memory.max', 'pids.max', 'cpu.max',
    'cgroup.freeze', 'cgroup.kill', 'sweep_orphans', 'pub const LEDGER_MAX_BYTES',
):
    need('helper-lifecycle', lifecycle, anchor)
for code in (
    'bad-request', 'bad-mac', 'stale', 'replay', 'unknown-command', 'capability-missing',
    'profile-unknown', 'profile-invalid', 'input-invalid', 'input-missing', 'sandbox-unavailable',
    'cell-limit', 'unknown-cell', 'stale-generation', 'export-missing', 'export-overflow',
    'burn-failed', 'internal',
):
    need('helper-types', types, f'"{code}"')
# T5-Fix (P2-T1): capability self-check + non-root cgroup probe. The helper must
# never probe the kernel root cgroup for cgroup.kill (CFTYPE_NOT_ON_ROOT); it
# probes a throwaway child under the CLI cgroup-root and fails closed with clear
# diagnostic codes when the capability or cgroup support is missing.
need('helper-types', types, 'REQUIRED_CAPABILITIES')
need('helper-types', types, '("CAP_CHOWN", 0)')
need('helper-types', types, 'pub fn missing_capabilities')
need('helper-main', main, 'static CGROUP_PROBE_OK')
need('helper-main', main, 'fn probe_cgroup_root')
need('helper-main', main, '"cgroup-root-missing"')
need('helper-main', main, '"cgroup-unavailable"')
need('helper-main', main, 'caps={}/{}')
need('helper-main', main, 'probe_cgroup_root(&cli.cgroup_root)')
need('helper-main', main, 'capability-check-failed missing=')
if 'Path::new("/sys/fs/cgroup/cgroup.kill")' in main:
    missing.append('helper-main: cgroup.kill must be probed in a child of the CLI cgroup-root, not the kernel root cgroup')
need('helper-main', main, 'VGTGC2 listener')

# execve may only exist in sandbox.rs; no helper module other than sandbox.rs may
# contain a shell/command sink (the pre-existing daemon gate above is untouched).
for name, source in helper_sources.items():
    if name == 'sandbox.rs':
        continue
    if 'libc::execve' in source:
        missing.append(f'helper-crate: libc::execve outside sandbox.rs: {name}')
for name, source in helper_sources.items():
    body = re.sub(r'#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]', '', source)
    for pattern in (r'std::process::Command', r'\bCommand::new\b', r'libc::system\b', r'["\'`]/bin/(?:ba)?sh\b'):
        if re.search(pattern, body):
            missing.append(f'helper-crate: forbidden execution primitive in {name}: {pattern}')

# --- Go control plane: VGTGC2 client, manager, settings, API, host layers ----
client = read('control/parser_cells_client.go')
manager = read('control/parser_cells_manager.go')
manager_ops = read('control/parser_cells_manager_ops.go')
settings = read('control/parser_cells_settings.go')
kernel = read('control/parser_cells_kernel.go')
api = read('control/parser_cells_api.go')
runtime_settings = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('runtime_settings*.go')) if not p.name.endswith('_test.go'))
server = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
guard = read('control/cell_guard.go')
bootstrap = read('control/config.go')
for anchor in (
    'parserCellFrameTag          = "VGTGC2"', 'parserCellResponseTag       = "VGTGC2R"',
    'parserCellTimestampSkewSecs = 30', 'syscall.SO_PEERCRED', 'syscall.Recvmsg',
    'syscall.ParseUnixRights', 'syscall.CmsgSpace', 'ErrParserCellsRuntimeUnavailable',
    'ErrParserCellsPeer', '"capability-missing"', '"sandbox-unavailable"', '"export-overflow"',
):
    need('go-client', client, anchor)
need_match('go-client', client, 'exactly one export FD is accepted for CELL_EXPORT_READ only',
           r'len\(fds\) == 1 && command != parserCellCommandExportRead')
need('go-client', client, 'parserCellCloseFDs')
for anchor in (
    'type ParserCellManager struct {', 'parserCellKindBurnIntent  = "cells.parser.burn.intent"',
    'state.RecordEvidence', 'Helper: "disabled"', 'capability-missing', 'parserCellStateBurned',
):
    need('go-manager', manager, anchor)
need('go-manager', manager_ops, 'm.evidence(EvidenceRecord{Severity: "high", Kind: kind')
need('go-settings', settings, 'parserCellsClassEphemeral = "parser-ephemeral"')
need_match('go-settings', settings, 'parser_cells defaults to disabled', r'Enabled:\s+false,')
# POINT 5 (P5-T3) raised the schema to v16 (lockdown namespace). This P2 anchor
# must follow the current schema version instead of pinning 15, exactly like the
# P1 anchor above; the parser_cells migration proof below is unchanged.
need_match('go-runtime', runtime_settings, 'settings schema version is at least v16 (POINT 5 lockdown migration)',
           r'const fabricSettingsVersion = (?:1[6-9]|[2-9][0-9])')
need('go-runtime', runtime_settings, 'parser_cells namespace added with enabled=false')
for anchor in (
    'CELL_POLICY_SET(cgroup, DENY_NON_UNIX_SOCKET)', 'StyxModeSet', 'TitanExecScopeSet',
    'parserCellLayerUnavailable + ":bpf-lsm-inactive"', 'parserCellLayerUnavailable + ":styx-disabled"',
):
    need('go-kernel', kernel, anchor)
need('go-api', api, 'request.Confirm != "BURN "+uuid')
need('go-api', api, 'parserCellListLimit')
need('go-api', api, 'Content-Disposition')
need('go-api', api, 'X-Content-Type-Options')
need('go-api', api, '"nosniff"')
for route in (
    'mux.HandleFunc("GET /api/v1/parser-cells/status", s.auth(s.parserCellsStatus))',
    'mux.HandleFunc("GET /api/v1/parser-cells", s.auth(s.parserCellsList))',
    'mux.HandleFunc("POST /api/v1/parser-cells/inputs", s.auth(s.parserCellsInput))',
    'mux.HandleFunc("POST /api/v1/parser-cells/open", s.auth(s.parserCellsOpen))',
    'mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/burn", s.auth(s.parserCellsBurn))',
    'mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/freeze", s.auth(s.parserCellsFreeze))',
    'mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/unfreeze", s.auth(s.parserCellsUnfreeze))',
    'mux.HandleFunc("GET /api/v1/parser-cells/{uuid}/export", s.auth(s.parserCellsExport))',
):
    need('go-server', server, route)
need('go-guard', guard, 'manager.BurnForIncident(cgroupID, score, incidentID,')
need('go-guard', guard, 'parser-ephemeral cell burned instead of frozen')
need('go-bootstrap', bootstrap, '"/run/vgt-gedefense/cell-helper.sock"')
need('go-bootstrap', bootstrap, '"/etc/vgt/gedefense/secrets/cell-helper.key"')
need('go-bootstrap', bootstrap, 'PeerUID:              0')
# T5-Fixes (P2-T3): control-owned import sink, adopt-reassert, route-scoped body
# limit and the Wayland capability boundary.
need('go-bootstrap', bootstrap, 'ImportsDir:')
need('go-bootstrap', bootstrap, '"/var/lib/vgt/gedefense/parser-imports"')
need('go-manager-ops', manager_ops, 'm.cfg.ImportsDir')
need('go-manager-ops', manager_ops, 'durable copy is written to the control-owned parser-imports root')
need('go-manager-ops', manager_ops, 'No stored claim without the mandatory evidence record')
need('go-kernel', kernel, 'func (k *parserCellKernel) Reassert(settings RuntimeSettings, active []uint64)')
need('go-supervision', read('control/parser_cells_supervision.go'), 'm.kernel.Reassert(m.runtimeSettings(), activeCgroups)')
need('go-api', api, 'parserCellInputBodyLimit int64 = 12 << 20')
need('go-api', api, '12 MiB base64 request bound')
need('go-client', client, 'Wayland')
need('go-client-codec', read('control/parser_cells_client_codec.go'), 'parseParserCellCapabilitiesPayload')

# --- packaging/deployment boundary ------------------------------------------
unit = read('packaging/systemd/gedefense-cell-helper.service')
for directive in (
    'ConditionPathExists=@RELEASE@/libexec/gedefense-cell-helper',
    'User=root', 'NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
    'PrivateTmp=yes', 'RestrictAddressFamilies=AF_UNIX', 'RestrictNamespaces=mnt pid ipc uts net',
    'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_RESOURCE CAP_CHOWN',
    'ReadWritePaths=/var/lib/vgt/gedefense/parser-inputs /var/lib/vgt/gedefense/parser-exports',
    'ReadWritePaths=/var/lib/vgt/gedefense/parser-burn-ledger.jsonl',
    'IPAddressDeny=any', 'UMask=0077', 'Restart=on-failure', 'StartLimitIntervalSec=120',
    'SystemCallFilter=@system-service @mount seccomp',
):
    need('systemd-helper-unit', unit, directive)
if 'ProtectControlGroups=yes' in unit:
    missing.append('systemd-helper-unit: ProtectControlGroups=yes would block the dedicated cgroup subtree')
# T5 fix: the control-plane-owned parser-imports directory must never be in the
# helper unit's writable set - the helper only writes inputs/exports/ledger.
if 'parser-imports' in unit:
    missing.append('systemd-helper-unit: parser-imports must not be a helper ReadWritePath (control-owned import copy)')
tmpfiles = read('packaging/tmpfiles/vgt-gedefense.conf')
for line in (
    'd /var/lib/vgt/gedefense/parser-inputs 0730 gedefense gedefense -',
    'd /var/lib/vgt/gedefense/parser-exports 0750 root gedefense -',
    'd /var/lib/vgt/gedefense/parser-imports 0750 gedefense gedefense -',
    'f /var/lib/vgt/gedefense/parser-burn-ledger.jsonl 0640 root gedefense -',
    'C /etc/vgt/gedefense/parser-profiles.conf 0640 root root - /usr/share/gedefense/parser-profiles.conf',
):
    need('tmpfiles', tmpfiles, line)
provision = read('packaging/scripts/gedefense-provision')
need('provision', provision, 'ensure_raw_key "${SECRETS_DIR}/cell-helper.key" 0640 root "${CONTROL_GROUP}"')
need('provision', provision, '"/var/lib/vgt/gedefense/parser-inputs:0730:${CONTROL_USER}:${CONTROL_GROUP}"')
need('provision', provision, '"/var/lib/vgt/gedefense/parser-imports:0750:${CONTROL_USER}:${CONTROL_GROUP}"')
need('provision', provision, 'ensure_parser_profile')
templates = read('packaging/templates/parser-profiles.conf')
if re.search(r'(?m)^\[profile ', templates):
    missing.append('parser-profiles template: packaged default must not invent an active parser profile')
pkgbuild = read('packaging/arch/PKGBUILD')
need('pkgbuild', pkgbuild, 'packaging/systemd/gedefense-cell-helper.service')
need('pkgbuild', pkgbuild, 'dist/gedefense-cell-helper')
need('makefile', read('Makefile'), 'rust-helper')
need('release-build', read('scripts/package-artifacts.sh'), 'gedefense-cell-helper')
installer = read('scripts/oneclick-installer-header.sh')
for anchor in (
    'readonly HELPER_SHA256="__HELPER_SHA256__"',
    '--artifact-file "gedefense-cell-helper=$PAYLOAD/bin/gedefense-cell-helper"',
    'libexec/gedefense-cell-helper',
    'cell-helper.key',
    'parser-profiles.conf',
    'gedefense-cell-helper.service',
):
    need('installer-prebuilt', installer, anchor)
source_bootstrap = read('scripts/oneclick-source-bootstrap-header.sh')
for anchor in (
    'packaging/systemd/gedefense-cell-helper.service',
    'packaging/templates/parser-profiles.conf',
    '__HELPER_SHA256__/source-built',
):
    need('installer-source', source_bootstrap, anchor)
need('install-smoke', read('packaging/tests/install-smoke.sh'), 'gedefense-cell-helper.service')
need('validate-systemd', read('scripts/validate-systemd.sh'), 'gedefense-cell-helper.service')
installed_gate = read('scripts/validate-installed-linux-host.sh')
need('installed-host-gate', installed_gate, 'release-manifest.signed.json')
need('installed-host-gate', installed_gate, 'deployment drift detected')
need('installed-host-gate', installed_gate, 'parser_cells enabled but runtime unavailable')
need('installed-host-gate', installed_gate, 'PARSER_CELLS_LSM_WARNING')
need('astraeaos-provision', read('integration/astraeaos/gedefense-astraeaos-provision'), 'CELL_HELPER_KEY')
need('astraeaos-contract', read('integration/astraeaos/contract.json'), 'ephemeral_parser_cells')

if missing:
    raise SystemExit('Point 2 parser-cell anchors missing:\n' + '\n'.join(missing))
PYP2
pass 'Point 2 parser-cell helper boundary, VGTGC2 control integration, default-off and packaging gates present'

# POINT 5 (docs/POINT5-LOCKDOWN.md §3-§9, §12): Emergency Lockdown /
# anti-physical-extraction. Additive gate only - every pre-existing Point 1/2/3
# anchor above stays unchanged. It pins the shared ABI, the OFF/fail-safe eBPF
# fastpath in all three hooks, the core LOCKDOWN_* dispatch/state/re-arm, the
# honest phase and unsupported vocabulary, the default-off authenticated Go
# latch/API, and the exact unit grant set (no capability/address-family/syscall
# widening). Source-only anchors are paired with the shipped-object readelf
# check below.
