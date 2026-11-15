#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
#
# F-05 / CHAIN-005 install smoke test.
#
# Two phases:
#   1) static package-contract validation (units, tmpfiles, sysusers, PKGBUILD,
#      port/backend topology, ownership/mode assertions, install hook);
#   2) an executable first-boot provisioning test in a staged fake root using the
#      real shipped access binary, followed by idempotency and negative checks.
#
# The script is honest about its environment limits: it prints NOT_TESTED lines
# for a real pacman install, systemd boot and nspawn/VM start, because this
# environment cannot install Arch packages or boot the image.
#
# Usage: install-smoke.sh [--source-root <repo>] [--work <dir>]
set -Eeuo pipefail
umask 0077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SOURCE_ROOT=$(realpath "${SCRIPT_DIR}/../..")
WORK=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-root) SOURCE_ROOT=$(realpath "$2"); shift 2 ;;
    --work) WORK=$2; shift 2 ;;
    *) printf 'usage: %s [--source-root <repo>] [--work <dir>]\n' "$0" >&2; exit 2 ;;
  esac
done

passes=0
failures=0

pass() {
  passes=$((passes + 1))
  printf 'SMOKE PASS: %s\n' "$1"
}

fail() {
  failures=$((failures + 1))
  printf 'SMOKE FAIL: %s\n' "$1" >&2
}

not_tested() {
  printf 'SMOKE NOT_TESTED: %s\n' "$1"
}

require_file() {
  local path=$1
  [[ -f $path ]] || fail "missing file: ${path#"${SOURCE_ROOT}/"}"
}

assert_contains() {
  local path=$1 needle=$2 label=$3
  grep -Fq -- "$needle" "$path" || fail "$label"
}

assert_unit_syntax() {
  local unit=$1
  command -v systemd-analyze >/dev/null 2>&1 || {
    not_tested "systemd-analyze unavailable; unit syntax for $(basename "$unit") not verified"
    return
  }
  local output status
  set +e
  output=$(systemd-analyze verify --man=no "$unit" 2>&1)
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    pass "systemd-analyze verify $(basename "$unit")"
  else
    printf '%s\n' "$output" >&2
    fail "systemd-analyze verify $(basename "$unit")"
  fi
}

readonly REQUIRED_FILES=(
  packaging/systemd/gedefense-access.service.in
  packaging/systemd/gedefense-bpffs.service
  packaging/systemd/gedefense-core.service
  packaging/systemd/gedefense-control.service
  packaging/systemd/gedefense-cell-helper.service
  packaging/systemd/gedefense-provision.service
  packaging/scripts/gedefense-provision
  packaging/templates/parser-profiles.conf
  packaging/tmpfiles/vgt-gedefense.conf
  packaging/sysusers/vgt-gedefense.conf
  packaging/pacman/gedefense-provision.hook
  packaging/arch/PKGBUILD
)
for required in "${REQUIRED_FILES[@]}"; do
  require_file "${SOURCE_ROOT}/${required}"
done

# --- Phase 1: static package contract ---------------------------------------
access_unit="${SOURCE_ROOT}/packaging/systemd/gedefense-access.service.in"
assert_contains "$access_unit" 'User=gedefense-access' "access unit must run as the separated gateway account"
assert_contains "$access_unit" '--backend=http://127.0.0.1:9844' "access unit backend must target the internal control port 9844"
assert_contains "$access_unit" '--listen=0.0.0.0:@PUBLIC_PORT@' "access unit must listen on the public port template"
assert_contains "$access_unit" '/var/lib/vgt/gedefense-access/dashboard.token' "access unit must consume the gateway-owned token"
assert_contains "$access_unit" '/etc/vgt/gedefense/tls/access.crt' "access unit must consume the canonical TLS certificate"
assert_contains "$access_unit" 'ReadWritePaths=/var/lib/vgt/gedefense-access' "access unit sandbox must permit its own runtime directory"
# Argon2id migration: a legacy PBKDF2 record is replaced atomically after a successful
# login (temp file + rename in /etc/vgt/gedefense-access). That write path needs the
# gateway's own credential directory in ReadWritePaths - and nowhere near ReadOnlyPaths.
assert_contains "$access_unit" 'ReadOnlyPaths=@RELEASE@' "access unit must keep the release tree read-only"
access_ro_paths=$(grep -E '^[[:space:]]*ReadOnlyPaths=' "$access_unit" || true)
access_rw_paths=$(grep -E '^[[:space:]]*ReadWritePaths=' "$access_unit" || true)
if grep -Eq '(^|[[:space:]])/etc/vgt/gedefense-access([[:space:]]|$)' <<<"$access_rw_paths"; then
  pass "access unit keeps the gateway credential directory in ReadWritePaths (atomic Argon2id migration)"
else
  fail "access unit must list /etc/vgt/gedefense-access in ReadWritePaths so the Argon2id migration can write the password record"
fi
if grep -Eq '(^|[[:space:]])/etc/vgt/gedefense-access([[:space:]]|$)' <<<"$access_ro_paths"; then
  fail "access unit must not pin /etc/vgt/gedefense-access read-only (blocks the Argon2id migration)"
else
  pass "access unit does not pin the gateway credential directory read-only"
fi

provision_unit="${SOURCE_ROOT}/packaging/systemd/gedefense-provision.service"
assert_contains "$provision_unit" 'Before=gedefense-bpffs.service gedefense-core.service gedefense-control.service gedefense-access.service gedefense-cell-helper.service' "provision unit must run before every GeDefense service"
assert_contains "$provision_unit" 'ConditionPathExists=/opt/vgt/gedefense/current/bin/gedefense-access' "provision unit must be conditioned on the installed release"
assert_contains "$provision_unit" '/usr/libexec/gedefense/gedefense-provision' "provision unit must execute the packaged provisioning contract"

# POINT 2 (docs/POINT2-PARSER-CELLS.md §4.9/§7): privileged parser-cell helper
# unit contract. @RELEASE@ must stay a placeholder (rendered by packaging); the
# sandbox directives and CLI paths are the reviewed privilege boundary.
helper_unit="${SOURCE_ROOT}/packaging/systemd/gedefense-cell-helper.service"
for needle in \
  'ConditionPathExists=@RELEASE@/libexec/gedefense-cell-helper' \
  'ExecStart=@RELEASE@/libexec/gedefense-cell-helper' \
  '--socket=/run/vgt-gedefense/cell-helper.sock' \
  '--key-file=/etc/vgt/gedefense/secrets/cell-helper.key' \
  '--profiles=/etc/vgt/gedefense/parser-profiles.conf' \
  '--staging-inputs=/var/lib/vgt/gedefense/parser-inputs' \
  '--staging-exports=/var/lib/vgt/gedefense/parser-exports' \
  '--ledger=/var/lib/vgt/gedefense/parser-burn-ledger.jsonl' \
  '--cgroup-root=/sys/fs/cgroup/vgt-cells' \
  '--max-cells=16' \
  'User=root' \
  'Restart=on-failure' \
  'StartLimitIntervalSec=120' \
  'NoNewPrivileges=yes' \
  'ProtectSystem=strict' \
  'ProtectHome=yes' \
  'PrivateTmp=yes' \
  'RestrictAddressFamilies=AF_UNIX' \
  'RestrictNamespaces=mnt pid ipc uts net' \
  'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_RESOURCE CAP_CHOWN' \
  'ReadWritePaths=/sys/fs/cgroup/vgt-cells' \
  'ReadWritePaths=/var/lib/vgt/gedefense/parser-inputs /var/lib/vgt/gedefense/parser-exports' \
  'ReadWritePaths=/var/lib/vgt/gedefense/parser-burn-ledger.jsonl' \
  'IPAddressDeny=any' \
  'UMask=0077' \
  'SystemCallFilter=@system-service @mount seccomp'; do
  assert_contains "$helper_unit" "$needle" "parser-cell helper unit missing: $needle"
done
if grep -qE '^[[:space:]]*RestrictNamespaces=~' "$helper_unit"; then
  fail "parser-cell helper unit uses a '~' RestrictNamespaces deny list that would deny the required namespace types"
else
  pass "parser-cell helper unit allows exactly the required namespace types"
fi
if grep -Eq '^[[:space:]]*CapabilityBoundingSet=.*CAP_SYS_PTRACE|^[[:space:]]*CapabilityBoundingSet=.*CAP_DAC_READ_SEARCH' "$helper_unit"; then
  fail "parser-cell helper unit grants capabilities outside the reviewed sandbox contract"
else
  pass "parser-cell helper unit grants no capabilities outside the reviewed sandbox contract"
fi

core_unit="${SOURCE_ROOT}/packaging/systemd/gedefense-core.service"
assert_contains "$core_unit" 'ReadWritePaths=/run/vgt-gedefense /run/gedefense-scan' "core unit must be allowed to bind the restricted user scan socket"
assert_contains "$core_unit" '--scan-socket=/run/gedefense-scan/scan.sock' "core unit must use the packaged scan socket path"
# POINT 5 (docs/POINT5-LOCKDOWN.md §8): the Emergency Lockdown phases need the
# USB/Thunderbolt sysfs policy and the opt-in hardening sysctl nodes; the kernel
# latch lives below /var/lib/vgt/gedefense (1770 root:gedefense in tmpfiles).
# The grants are exact and additive - the reviewed capability, address-family
# and syscall contract must stay unchanged. /sys/devices is required in addition
# to the bus paths: /sys/bus/usb/devices and /sys/bus/thunderbolt/devices are
# sysfs symlinks, so per-device "authorized" writes resolve into /sys/devices/**
# and would be EROFS with a bus-only grant (fail-safe but ineffective).
for needle in \
  'ReadWritePaths=-/sys/bus/usb -/sys/bus/thunderbolt/devices -/sys/devices' \
  'ReadWritePaths=-/proc/sys/kernel/kexec_load_disabled -/proc/sys/kernel/sysrq -/proc/sys/kernel/modules_disabled' \
  'ReadWritePaths=/var/lib/vgt/gedefense' \
  'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_KILL' \
  'AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_KILL' \
  'RestrictAddressFamilies=AF_UNIX AF_NETLINK' \
  'SystemCallFilter=@system-service bpf perf_event_open pidfd_open pidfd_send_signal fanotify_init fanotify_mark'; do
  assert_contains "$core_unit" "$needle" "core unit missing POINT 5 lockdown contract: $needle"
done
# The complete writable sysfs set must stay exactly reviewed: the pre-existing
# bpffs mount plus the three lockdown nodes.
expected_sys_grants='/sys/bus/thunderbolt/devices /sys/bus/usb /sys/devices /sys/fs/bpf'
actual_sys_grants=$(grep -E '^[[:space:]]*ReadWritePaths=' "$core_unit" |
  sed 's/^[^=]*=//' | tr ' ' '\n' | sed 's/^-//' |
  grep -E '^/sys(/|$)' | sort -u | tr '\n' ' ' | sed 's/ $//')
if [[ $actual_sys_grants == "$expected_sys_grants" ]]; then
  pass "core unit writes exactly the reviewed sysfs set ($actual_sys_grants)"
else
  fail "core unit writable sysfs set is '$actual_sys_grants', expected '$expected_sys_grants'"
fi
if grep -Eq '^[[:space:]]*CapabilityBoundingSet=.*(CAP_SYS_PTRACE|CAP_SYS_MODULE|CAP_DAC_READ_SEARCH|CAP_SYS_RAWIO)' "$core_unit"; then
  fail "core unit grants a capability outside the reviewed lockdown contract"
else
  pass "core unit keeps the reviewed capability set for the lockdown grants"
fi
if grep -Eq '^[[:space:]]*RestrictAddressFamilies=.*(AF_INET|AF_PACKET|AF_BLUETOOTH)' "$core_unit"; then
  fail "core unit widens RestrictAddressFamilies for the lockdown"
else
  pass "core unit does not widen the address-family contract for the lockdown"
fi
if grep -Eq 'ReadWritePaths=([^[:space:]]*[[:space:]])*/sys([[:space:]]|$)' "$core_unit"; then
  fail "core unit makes /sys writable as a whole instead of the exact bus nodes"
else
  pass "core unit grants only the exact USB/Thunderbolt sysfs nodes"
fi
assert_contains "${SOURCE_ROOT}/packaging/tmpfiles/vgt-gedefense.conf" 'd /var/lib/vgt/gedefense 1770 root gedefense -' "tmpfiles must keep the lockdown state directory writable by the core only"

tmpfiles="${SOURCE_ROOT}/packaging/tmpfiles/vgt-gedefense.conf"
for line in \
  'd /run/gedefense-scan 0750 root gedefense -' \
  'd /etc/vgt/gedefense 0750 root gedefense -' \
  'd /etc/vgt/gedefense/secrets 0750 root gedefense -' \
  'd /etc/vgt/gedefense/tls 0750 root gedefense -' \
  'd /etc/vgt/gedefense-access 0750 gedefense-access gedefense-access -' \
  'd /var/lib/vgt/gedefense-access 0750 gedefense gedefense-access -' \
  'd /var/lib/vgt/gedefense-access/state 0700 gedefense-access gedefense-access -' \
  'd /var/lib/vgt/gedefense/parser-inputs 0730 gedefense gedefense -' \
  'd /var/lib/vgt/gedefense/parser-exports 0750 root gedefense -' \
  'd /var/lib/vgt/gedefense/parser-imports 0750 gedefense gedefense -' \
  'f /var/lib/vgt/gedefense/parser-burn-ledger.jsonl 0640 root gedefense -' \
  'C /etc/vgt/gedefense/parser-profiles.conf 0640 root root - /usr/share/gedefense/parser-profiles.conf'; do
  assert_contains "$tmpfiles" "$line" "tmpfiles contract missing: $line"
done
# POINT 4 (docs/POINT4-WITNESS.md §4/§7): the Out-of-Band Witness state
# (outbox.enc/ack.enc below /var/lib/vgt/gedefense/witness) is created at
# runtime by the unprivileged control plane (directory 0700, files 0600), never
# by the provisioner. Phase 1 ships no dedicated witness unit and no
# witness-specific sandbox grant: the reviewed 1770 root:gedefense state root is
# what lets the control user create the witness subdirectory itself, and the
# pre-existing control-plane contract stays unchanged.
assert_contains "$tmpfiles" 'd /var/lib/vgt/gedefense 1770 root gedefense -' "tmpfiles must keep the witness state root writable by the control plane (1770 root:gedefense)"
control_unit="${SOURCE_ROOT}/packaging/systemd/gedefense-control.service"
if [[ -n $(find "${SOURCE_ROOT}/packaging/systemd" -maxdepth 1 -name '*witness*' -print -quit) ]]; then
  fail "Phase 1 must not ship a dedicated witness systemd unit (unprivileged Go control only)"
else
  pass "no dedicated witness systemd unit is shipped (witness runs inside gedefense-control)"
fi
if grep -Eq 'ReadWritePaths=[^[:space:]]*witness' "$core_unit" "$control_unit"; then
  fail "no witness-specific ReadWritePaths exception may exist; the state stays inside /var/lib/vgt/gedefense"
else
  pass "witness state uses only the reviewed /var/lib/vgt/gedefense grant"
fi
if grep -q 'witness' "${SOURCE_ROOT}/packaging/scripts/gedefense-provision"; then
  fail "the provisioner must not pre-create witness state (the control plane creates <state>/witness/ 0700 at first use)"
else
  pass "provisioner does not pre-create witness state (runtime-owned 0700)"
fi
if grep -Eq '^d /var/lib/vgt/gedefense/parser-inputs 0[0-7]*[0-7] root ' "$tmpfiles"; then
  fail "parser-inputs must be control-owned (helper staging contract: Owner=Control-UID), not root-owned"
else
  pass "parser-inputs tmpfiles entry keeps the control-owned helper staging contract"
fi
# FIND-007: tmpfiles is the single source of truth for the secrets directory.
# It must stay 0750 root:gedefense (group-traversable for the control plane);
# the provisioning script and this smoke test have to agree with it.
provision_script="${SOURCE_ROOT}/packaging/scripts/gedefense-provision"
if grep -Fq '"/etc/vgt/gedefense/secrets:0750:root:${CONTROL_GROUP}"' "$provision_script"; then
  pass "provisioning script declares the secrets directory as 0750 root:gedefense"
else
  fail "provisioning script must declare /etc/vgt/gedefense/secrets as 0750 root:gedefense (FIND-007)"
fi
if grep -Eq '/etc/vgt/gedefense/secrets:0[0-7]00' "$provision_script"; then
  fail "provisioning script still tightens the secrets directory below 0750 (control plane cannot traverse)"
else
  pass "provisioning script does not tighten the secrets directory below 0750"
fi
# POINT 2: the provisioner must create the helper key, both staging roots, the
# burn ledger and the header-only profile default; these are the helper's
# fail-closed startup preconditions.
for needle in \
  'cell-helper.key' \
  '"/var/lib/vgt/gedefense/parser-inputs:0730:${CONTROL_USER}:${CONTROL_GROUP}"' \
  '"/var/lib/vgt/gedefense/parser-exports:0750:root:${CONTROL_GROUP}"' \
  '"/var/lib/vgt/gedefense/parser-imports:0750:${CONTROL_USER}:${CONTROL_GROUP}"' \
  'ensure_empty_regular_file "${PARSER_LEDGER}" 0640 root "${CONTROL_GROUP}"' \
  'ensure_parser_profile'; do
  assert_contains "$provision_script" "$needle" "provisioning script missing POINT 2 helper provisioning: $needle"
done
parser_template="${SOURCE_ROOT}/packaging/templates/parser-profiles.conf"
if grep -Eq '^\[profile ' "$parser_template"; then
  fail "packaged parser profile default must not invent an active parser profile"
else
  pass "packaged parser profile default is header-only (no invented parser profile)"
fi
assert_contains "$parser_template" 'intentionally contains NO parser profile' "parser profile default must document the empty default"
if grep -Eq '(^|[[:space:]])(0777|0666)([[:space:]]|$)' "$tmpfiles" "${SOURCE_ROOT}/packaging/systemd"/*.service "${SOURCE_ROOT}/packaging/systemd"/*.in; then
  fail "world-writable mode declared in packaging"
else
  pass "no world-writable modes in packaging units/tmpfiles"
fi

sysusers="${SOURCE_ROOT}/packaging/sysusers/vgt-gedefense.conf"
assert_contains "$sysusers" 'g gedefense-access - -' "sysusers must create the separated gateway group"
assert_contains "$sysusers" 'u gedefense-access - ' "sysusers must create the gateway account"
if grep -Eq '^m gedefense-access|gedefense-access[[:space:]]+gedefense' "$sysusers"; then
  fail "gateway account must not join the control plane group"
else
  pass "gateway account is not a member of the control-plane group"
fi

pkgbuild="${SOURCE_ROOT}/packaging/arch/PKGBUILD"
for needle in \
  'usr/libexec/gedefense/gedefense-provision' \
  'gedefense-provision.service' \
  'gedefense-provision.hook' \
  'tmpfiles/vgt-gedefense.conf' \
  'sysusers/vgt-gedefense.conf' \
  'install-smoke.sh' \
  'dist/gedefense-cell-helper' \
  'packaging/systemd/gedefense-cell-helper.service' \
  'packaging/templates/parser-profiles.conf' \
  '-o root -g gedefense "${srcdir}/gedefense.packaged.toml"' \
  's#^listen = "127.0.0.1:9843"#listen = "127.0.0.1:9844"#'; do
  assert_contains "$pkgbuild" "$needle" "PKGBUILD missing provisioning/topology element: $needle"
done

hook="${SOURCE_ROOT}/packaging/pacman/gedefense-provision.hook"
assert_contains "$hook" 'systemctl enable gedefense-provision.service' "pacman hook must enable the provisioning unit"
assert_contains "$hook" 'gedefense-cell-helper.service' "pacman hook must enable the parser-cell helper unit"
assert_contains "$hook" 'When=PostTransaction' "pacman hook must run after the package transaction"

astraeaos_profile="${SOURCE_ROOT}/integration/astraeaos/astraeaos-profile.toml"
assert_contains "$astraeaos_profile" 'listen = "127.0.0.1:9844"' "AstraeaOS profile must keep the internal backend port 9844"

# Unit syntax is verified in Phase 2 against a staged root where every
# ExecStart path resolves to an existing file (systemd-analyze treats missing
# binaries as errors, which would only measure this offline source tree).

# --- Phase 2: executable provisioning in a staged root ----------------------
if [[ -z $WORK ]]; then
  WORK=$(mktemp -d)
else
  mkdir -p "$WORK"
fi
stage="${WORK}/root"
mkdir -p "${stage}/opt/vgt/gedefense/current/bin" \
  "${stage}/opt/vgt/gedefense/current/libexec" \
  "${stage}/opt/vgt/gedefense/current/lib/gedefense" \
  "${stage}/etc/vgt/gedefense" "${stage}/usr/lib/systemd/system" \
  "${stage}/usr/share/gedefense" "${stage}/usr/libexec/gedefense"

access_bin="${SOURCE_ROOT}/dist/gedefense-access"
control_bin="${SOURCE_ROOT}/dist/gedefense-control"
core_bin="${SOURCE_ROOT}/rust/target/release/gedefense-core"
helper_bin="${SOURCE_ROOT}/rust/target/release/gedefense-cell-helper"
helper_staged=0
if [[ ! -x $access_bin ]]; then
  fail "dist/gedefense-access missing; run 'make full' before the install smoke test"
  printf 'SMOKE RESULT: %d passed, %d failed\n' "$passes" "$failures"
  exit 1
fi
cp "$access_bin" "${stage}/opt/vgt/gedefense/current/bin/gedefense-access"
if [[ -x $control_bin ]]; then
  cp "$control_bin" "${stage}/opt/vgt/gedefense/current/bin/gedefense-control"
else
  cp "$access_bin" "${stage}/opt/vgt/gedefense/current/bin/gedefense-control"
  fail "dist/gedefense-control missing; placeholder used only for hashing"
fi
if [[ -x $core_bin ]]; then
  cp "$core_bin" "${stage}/opt/vgt/gedefense/current/libexec/gedefense-core"
else
  cp "$access_bin" "${stage}/opt/vgt/gedefense/current/libexec/gedefense-core"
  not_tested "Rust core release binary missing; xdr-baseline hashing used the access binary as placeholder"
fi
chmod 0755 "${stage}"/opt/vgt/gedefense/current/bin/* "${stage}"/opt/vgt/gedefense/current/libexec/gedefense-core
# POINT 2: stage the built parser-cell helper. Without the release build it is
# NOT_TESTED (never silently counted as a pass); the unit syntax check below
# still needs a resolvable ExecStart path, so the access binary placeholders it.
if [[ -x $helper_bin ]]; then
  cp "$helper_bin" "${stage}/opt/vgt/gedefense/current/libexec/gedefense-cell-helper"
  chmod 0755 "${stage}/opt/vgt/gedefense/current/libexec/gedefense-cell-helper"
  helper_staged=1
else
  cp "$access_bin" "${stage}/opt/vgt/gedefense/current/libexec/gedefense-cell-helper"
  chmod 0755 "${stage}/opt/vgt/gedefense/current/libexec/gedefense-cell-helper"
  not_tested "gedefense-cell-helper release binary missing; unit/--check smoke used a placeholder (run make rust-helper)"
fi
install -Dm644 "${SOURCE_ROOT}/packaging/templates/parser-profiles.conf" \
  "${stage}/usr/share/gedefense/parser-profiles.conf"

# Stage resolved units for offline syntax validation. All dependencies are
# placed in the same directory so cross-unit references resolve.
install -Dm755 "${SOURCE_ROOT}/packaging/scripts/gedefense-provision" \
  "${stage}/usr/libexec/gedefense/gedefense-provision"
sed \
  -e "s#/opt/vgt/gedefense/current#${stage}/opt/vgt/gedefense/current#g" \
  "${SOURCE_ROOT}/packaging/systemd/gedefense-core.service" \
  > "${stage}/usr/lib/systemd/system/gedefense-core.service"
sed \
  -e "s#/opt/vgt/gedefense/current#${stage}/opt/vgt/gedefense/current#g" \
  "${SOURCE_ROOT}/packaging/systemd/gedefense-control.service" \
  > "${stage}/usr/lib/systemd/system/gedefense-control.service"
sed \
  -e "s#/usr/libexec/gedefense/gedefense-provision#${stage}/usr/libexec/gedefense/gedefense-provision#g" \
  -e "s#/opt/vgt/gedefense/current#${stage}/opt/vgt/gedefense/current#g" \
  "${SOURCE_ROOT}/packaging/systemd/gedefense-provision.service" \
  > "${stage}/usr/lib/systemd/system/gedefense-provision.service"
install -Dm644 "${SOURCE_ROOT}/packaging/systemd/gedefense-bpffs.service" \
  "${stage}/usr/lib/systemd/system/gedefense-bpffs.service"
sed \
  -e "s#@RELEASE@#${stage}/opt/vgt/gedefense/current#g" \
  -e 's#@PUBLIC_PORT@#9843#g' \
  -e 's#@PUBLIC_HOST@#127.0.0.1:9843#g' \
  "${access_unit}" > "${stage}/usr/lib/systemd/system/gedefense-access.service"
sed \
  -e "s#@RELEASE@#${stage}/opt/vgt/gedefense/current#g" \
  "${SOURCE_ROOT}/packaging/systemd/gedefense-cell-helper.service" \
  > "${stage}/usr/lib/systemd/system/gedefense-cell-helper.service"
if grep -q '@RELEASE@' "${stage}/usr/lib/systemd/system/gedefense-cell-helper.service"; then
  fail "staged parser-cell helper unit still contains the @RELEASE@ placeholder"
else
  pass "parser-cell helper unit renders the @RELEASE@ placeholder"
fi
for unit in gedefense-bpffs.service gedefense-core.service gedefense-control.service \
  gedefense-provision.service gedefense-access.service gedefense-cell-helper.service; do
  assert_unit_syntax "${stage}/usr/lib/systemd/system/${unit}"
done

# Staged configuration mirrors PKGBUILD package() exactly (CRLF-safe).
sed -e 's/\r$//' -e 's#^listen = "127.0.0.1:9843"#listen = "127.0.0.1:9844"#' \
  "${SOURCE_ROOT}/gedefense.toml" > "${stage}/etc/vgt/gedefense/gedefense.toml"
chmod 0640 "${stage}/etc/vgt/gedefense/gedefense.toml"
cp "${SOURCE_ROOT}/malware-hashes.sha256" "${stage}/etc/vgt/gedefense/malware-hashes.sha256"
chmod 0600 "${stage}/etc/vgt/gedefense/malware-hashes.sha256"

provision="${SOURCE_ROOT}/packaging/scripts/gedefense-provision"
current_user=$(id -un)
current_group=$(id -gn)
run_provision() {
  env \
    GEDEFENSE_PROVISION_ROOT="$stage" \
    GEDEFENSE_ACCESS_BIN="${stage}/opt/vgt/gedefense/current/bin/gedefense-access" \
    GEDEFENSE_CONTROL_USER="$current_user" \
    GEDEFENSE_CONTROL_GROUP="$current_group" \
    GEDEFENSE_ACCESS_USER="$current_user" \
    GEDEFENSE_ACCESS_GROUP="$current_group" \
    GEDEFENSE_SKIP_OWNER=1 \
    GEDEFENSE_PUBLIC_HOST="127.0.0.1:9843" \
    bash "$provision" "$@"
}

if run_provision >"${WORK}/provision-first.log" 2>&1; then
  pass "first-boot provisioning executed in staged root"
else
  cat "${WORK}/provision-first.log" >&2
  fail "first-boot provisioning failed"
fi

check_file() {
  local path=$1 mode=$2 label=$3
  if [[ ! -f $path ]]; then
    fail "$label missing: ${path#"${stage}/"}"
    return
  fi
  local actual
  actual=$(stat -c '%a' -- "$path")
  if [[ $actual != "${mode#0}" ]]; then
    fail "$label mode $actual, expected $mode"
  else
    pass "$label exists with mode $mode"
  fi
}

for entry in \
  "etc/vgt/gedefense:750" \
  "etc/vgt/gedefense/secrets:750" \
  "etc/vgt/gedefense/tls:750" \
  "etc/vgt/gedefense-access:750" \
  "var/lib/vgt/gedefense:1770" \
  "var/lib/vgt/gedefense-access:750" \
  "var/lib/vgt/gedefense-access/state:700" \
  "var/lib/vgt/gedefense/parser-inputs:730" \
  "var/lib/vgt/gedefense/parser-exports:750" \
  "var/lib/vgt/gedefense/parser-imports:750" \
  "run/gedefense-scan:750"; do
  IFS=: read -r relative mode <<<"$entry"
  actual=$(stat -c '%a' -- "${stage}/${relative}")
  if [[ $actual == "$mode" ]]; then
    pass "directory ${relative} mode ${mode}"
  else
    fail "directory ${relative} mode ${actual}, expected ${mode}"
  fi
done

# FIND-007: the control plane (gedefense) must be able to traverse the secrets
# directory to reach its 0640 root:gedefense keys. Assert the DAC contract
# (group execute, no world access) and, when the smoke test runs as root, prove
# traversal with the actual control-plane identity.
secrets_dir="${stage}/etc/vgt/gedefense/secrets"
secrets_mode=$(stat -c '%a' -- "$secrets_dir")
if [[ $secrets_mode == 750 ]]; then
  pass "secrets directory is group-traversable (mode 0750, not 0700)"
else
  fail "secrets directory mode $secrets_mode, expected 0750 so the control-plane group can traverse it"
fi
if (( (8#$secrets_mode & 8#007) == 0 )); then
  pass "secrets directory has no world permissions"
else
  fail "secrets directory mode $secrets_mode grants world permissions"
fi
if [[ $(id -u) -eq 0 ]] && command -v setpriv >/dev/null 2>&1 && id -u "$current_user" >/dev/null 2>&1; then
  if setpriv --reuid="$(id -u "$current_user")" --regid="$(id -g "$current_user")" --clear-groups \
      test -x "$secrets_dir" && \
    setpriv --reuid="$(id -u "$current_user")" --regid="$(id -g "$current_user")" --clear-groups \
      test -r "${secrets_dir}/core-ipc.key"; then
    pass "control-plane identity can traverse the secrets directory and read its key"
  else
    fail "control-plane identity cannot traverse the secrets directory or read its key"
  fi
else
  not_tested "real cross-account traversal of /etc/vgt/gedefense/secrets as the gedefense user (requires root)"
fi
for secret in "$secrets_dir"/*; do
  [[ -f $secret && ! -L $secret ]] || continue
  secret_mode=$(stat -c '%a' -- "$secret")
  if (( (8#$secret_mode & 8#007) == 0 )); then
    pass "secret $(basename -- "$secret") is not world-accessible (mode $secret_mode)"
  else
    fail "secret $(basename -- "$secret") is world-accessible (mode $secret_mode)"
  fi
done

check_file "${stage}/etc/vgt/gedefense/secrets/core-ipc.key" 0640 "core IPC key"
check_file "${stage}/etc/vgt/gedefense/secrets/storage-master.key" 0640 "storage master key"
check_file "${stage}/var/lib/vgt/gedefense/xdr-log.key" 0600 "evidence log key"
check_file "${stage}/var/lib/vgt/gedefense-access/dashboard.token" 0600 "gateway source token"
check_file "${stage}/var/lib/vgt/gedefense-access/state/access-session.key" 0600 "gateway session key"
check_file "${stage}/etc/vgt/gedefense-access/access-password" 0600 "operator password record"
check_file "${stage}/etc/vgt/gedefense-access/access.crt" 0644 "gateway certificate"
check_file "${stage}/etc/vgt/gedefense/tls/access.key" 0600 "gateway TLS key"
check_file "${stage}/etc/vgt/gedefense/xdr-baseline.json" 0640 "xdr baseline"
check_file "${stage}/etc/vgt/gedefense/gedefense.toml" 0640 "control configuration"
# POINT 2: helper key, burn ledger and header-only profile default are the
# fail-closed startup preconditions of the privileged parser-cell helper.
check_file "${stage}/etc/vgt/gedefense/secrets/cell-helper.key" 0640 "parser-cell helper VGTGC2 key"
check_file "${stage}/var/lib/vgt/gedefense/parser-burn-ledger.jsonl" 0640 "parser burn ledger"
check_file "${stage}/etc/vgt/gedefense/parser-profiles.conf" 0640 "parser profile default"

for key in \
  "etc/vgt/gedefense/secrets/core-ipc.key" \
  "etc/vgt/gedefense/secrets/storage-master.key" \
  "etc/vgt/gedefense/secrets/cell-helper.key" \
  "var/lib/vgt/gedefense/xdr-log.key" \
  "var/lib/vgt/gedefense-access/state/access-session.key"; do
  if [[ $(stat -c %s -- "${stage}/${key}") -eq 32 ]]; then
    pass "${key} contains exactly 32 bytes"
  else
    fail "${key} does not contain exactly 32 bytes"
  fi
done

# POINT 2: the provisioned profile default must stay header-only (no invented
# parser) until an operator/package adds a hash-verified profile.
if grep -Eq '^\[profile ' "${stage}/etc/vgt/gedefense/parser-profiles.conf"; then
  fail "provisioned parser profile default invents an active parser profile"
else
  pass "provisioned parser profile default has no active parser profile"
fi
if grep -q 'intentionally contains NO parser profile' "${stage}/etc/vgt/gedefense/parser-profiles.conf"; then
  pass "provisioned parser profile default carries the reviewed header documentation"
else
  fail "provisioned parser profile default header documentation is missing"
fi

# POINT 2: fail-safe smoke of the helper binary itself. The full --check needs
# root (it validates the key, profiles, staging dirs and cgroup prerequisites);
# as non-root the only correct behaviour is a clean refusal, and that is reported
# as NOT_TESTED for the root-gated validation - never counted as a PASS.
staged_helper="${stage}/opt/vgt/gedefense/current/libexec/gedefense-cell-helper"
if (( helper_staged == 1 )); then
  set +e
  helper_check_output=$("$staged_helper" --check --key-file="${stage}/etc/vgt/gedefense/secrets/cell-helper.key" --profiles="${stage}/etc/vgt/gedefense/parser-profiles.conf" --staging-inputs="${stage}/var/lib/vgt/gedefense/parser-inputs" --staging-exports="${stage}/var/lib/vgt/gedefense/parser-exports" --ledger="${stage}/var/lib/vgt/gedefense/parser-burn-ledger.jsonl" --cgroup-root="${stage}/sys/fs/cgroup/vgt-cells" 2>&1)
  helper_check_status=$?
  set -e
  if [[ $(id -u) -eq 0 ]]; then
    not_tested "gedefense-cell-helper --check as root against the staged root (cgroup/namespace prerequisites of this environment not asserted)"
  elif [[ $helper_check_status -eq 1 && $helper_check_output == *'check-failed'* ]]; then
    not_tested "gedefense-cell-helper --check root-gated: non-root fail-safe verified (exit 1, sandbox-unavailable), not a PASS"
  else
    fail "gedefense-cell-helper --check did not fail closed as non-root (exit=${helper_check_status})"
  fi
else
  not_tested "gedefense-cell-helper --check not executed: release binary missing (make rust-helper)"
fi

if grep -Eq '^v2\$argon2id\$' "${stage}/etc/vgt/gedefense-access/access-password"; then
  pass "operator password record uses Argon2id"
else
  fail "operator password record is not an Argon2id record"
fi
if [[ -s ${stage}/var/lib/vgt/gedefense/initial-access-password ]]; then
  pass "initial operator password stored root-only for first login"
else
  fail "initial operator password file missing"
fi
if openssl x509 -in "${stage}/etc/vgt/gedefense-access/access.crt" -noout -checkip 127.0.0.1 >/dev/null 2>&1; then
  pass "gateway certificate binds 127.0.0.1"
else
  fail "gateway certificate does not bind 127.0.0.1"
fi
if python3 - "${stage}/etc/vgt/gedefense/xdr-baseline.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["version"] == 1
assert len(doc["profiles"]) == 3
assert all(len(entry["sha256"]) == 64 for entry in doc["profiles"])
PY
then
  pass "xdr baseline contains three sha256-bound profiles"
else
  fail "xdr baseline is malformed"
fi
if grep -Eq '^listen[[:space:]]*=[[:space:]]*"127\.0\.0\.1:9844"' "${stage}/etc/vgt/gedefense/gedefense.toml"; then
  pass "control configuration listens on internal backend port 9844"
else
  fail "control configuration does not listen on 127.0.0.1:9844"
fi

# Idempotency and change-only-when-needed behaviour.
file_digest() {
  find "${stage}" -type f -print0 | sort -z | xargs -0 sha256sum
}
before=$(file_digest | sha256sum | cut -d' ' -f1)
if run_provision >"${WORK}/provision-second.log" 2>&1; then
  after=$(file_digest | sha256sum | cut -d' ' -f1)
  if [[ $before == "$after" ]]; then
    pass "re-running provisioning is idempotent (byte-identical state)"
  else
    fail "re-running provisioning changed already provisioned files"
  fi
else
  cat "${WORK}/provision-second.log" >&2
  fail "second provisioning run failed"
fi
if run_provision --check >"${WORK}/provision-check.log" 2>&1; then
  pass "provisioning --check validates the staged installation"
else
  cat "${WORK}/provision-check.log" >&2
  fail "provisioning --check rejected a valid staged installation"
fi

# Negative check: a world-readable token must be rejected by --check.
chmod 0644 "${stage}/var/lib/vgt/gedefense-access/dashboard.token"
if run_provision --check >"${WORK}/provision-negative.log" 2>&1; then
  fail "provisioning --check accepted a world-readable backend token"
else
  pass "provisioning --check rejects a world-readable backend token"
fi
chmod 0600 "${stage}/var/lib/vgt/gedefense-access/dashboard.token"

# Negative check: a non-traversable secrets directory (0700) must be rejected by
# --check, because the control plane could no longer reach its 0640 keys.
chmod 0700 "$secrets_dir"
if run_provision --check >"${WORK}/provision-secrets-negative.log" 2>&1; then
  fail "provisioning --check accepted a 0700 secrets directory (control plane cannot traverse it)"
else
  pass "provisioning --check rejects a 0700 secrets directory"
fi
chmod 0750 "$secrets_dir"

# PKGBUILD must normalize CRLF and must not ship the two-profile example as a
# live baseline (the provisioned baseline has three hash-bound profiles).
assert_contains "$pkgbuild" "s/\\r\$//" "PKGBUILD must strip CR characters from the packaged configuration"
assert_contains "$pkgbuild" 'usr/share/gedefense/xdr-baseline.example.json' "PKGBUILD must not install the example baseline as live trust state"

not_tested "real 'pacman -U' installation with dependency resolution"
not_tested "systemd boot of the four units and TLS livez HTTP 200 on a real host"
not_tested "nspawn/VM install test using only the two packages"
not_tested "AstraeaOS login-gate ready transition during boot"

printf 'SMOKE RESULT: %d passed, %d failed\n' "$passes" "$failures"
if (( failures > 0 )); then
  exit 1
fi
