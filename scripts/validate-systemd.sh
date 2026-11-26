#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-systemd.XXXXXXXX")
cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

UNIT_DIR=${TEST_ROOT}/usr/lib/systemd/system
RELEASE=${TEST_ROOT}/opt/vgt/gedefense/current
mkdir -p \
  "$UNIT_DIR/gedefense-access.service.d" \
  "$UNIT_DIR/gedefense-core.service.d" \
  "$UNIT_DIR/gedefense-control.service.d" \
  "$RELEASE/libexec" "$RELEASE/bin" \
  "${TEST_ROOT}/bin" "${TEST_ROOT}/usr/bin" "${TEST_ROOT}/usr/lib/astraeaos"

install -m 0644 "$ROOT/packaging/systemd/gedefense-bpffs.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/packaging/systemd/gedefense-core.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/packaging/systemd/gedefense-capture-helper.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/packaging/systemd/gedefense-control.service" "$UNIT_DIR/"
# POINT 2: the privileged parser-cell helper unit is rendered from its @RELEASE@
# placeholder exactly like the installer/PKGBUILD do - an unrendered unit would
# point at a literal "@RELEASE@" path and must never pass this gate.
sed \
  -e 's#@RELEASE@#/opt/vgt/gedefense/current#g' \
  "$ROOT/packaging/systemd/gedefense-cell-helper.service" \
  >"$UNIT_DIR/gedefense-cell-helper.service"
chmod 0644 "$UNIT_DIR/gedefense-cell-helper.service"
if grep -q '@RELEASE@' "$UNIT_DIR/gedefense-cell-helper.service"; then
  printf 'gedefense-cell-helper.service contains an unrendered @RELEASE@ placeholder.\n' >&2
  exit 1
fi
install -m 0644 "$ROOT/integration/astraeaos/gedefense-astraeaos-provision.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/integration/astraeaos/gedefense-core-astraeaos.conf" \
  "$UNIT_DIR/gedefense-core.service.d/10-astraeaos-provision.conf"
install -m 0644 "$ROOT/integration/astraeaos/gedefense-control-astraeaos.conf" \
  "$UNIT_DIR/gedefense-control.service.d/10-astraeaos-provision.conf"
sed \
  -e 's#@RELEASE@#/opt/vgt/gedefense/current#g' \
  -e 's#@PUBLIC_PORT@#9843#g' \
  -e 's#@PUBLIC_HOST@#127.0.0.1:9843#g' \
  "$ROOT/packaging/systemd/gedefense-access.service.in" \
  >"$UNIT_DIR/gedefense-access.service"
chmod 0644 "$UNIT_DIR/gedefense-access.service"
install -m 0644 "$ROOT/integration/astraeaos/gedefense-access-astraeaos.conf" \
  "$UNIT_DIR/gedefense-access.service.d/10-astraeaos-loopback.conf"
install -m 0755 "$ROOT/integration/astraeaos/gedefense-access-ready" \
  "${TEST_ROOT}/usr/lib/astraeaos/gedefense-access-ready"
install -m 0755 "$ROOT/integration/astraeaos/gedefense-core-launch" \
  "${TEST_ROOT}/usr/lib/astraeaos/gedefense-core-launch"

for path in \
  "$RELEASE/libexec/gedefense-core" \
  "$RELEASE/libexec/gedefense-cell-helper" \
  "$RELEASE/bin/gedefense-control" \
  "$RELEASE/bin/gedefense-access" \
  "${TEST_ROOT}/usr/lib/astraeaos/gedefense-astraeaos-provision"; do
  printf '#!/bin/sh\nexit 0\n' >"$path"
  chmod 0755 "$path"
done
# The helper unit's ReadWritePaths/ReadOnlyPaths must resolve inside the verified
# root; fake the provisioned helper staging material so the sandbox paths exist.
mkdir -p "${TEST_ROOT}/var/lib/vgt/gedefense/parser-inputs" \
  "${TEST_ROOT}/var/lib/vgt/gedefense/parser-exports" \
  "${TEST_ROOT}/var/lib/vgt/gedefense/quarantine" \
  "${TEST_ROOT}/var/lib/vgt/gedefense/canaries" \
  "${TEST_ROOT}/etc/vgt/gedefense/secrets" \
  "${TEST_ROOT}/etc/sysctl.d" \
  "${TEST_ROOT}/run/vgt-gedefense" \
  "${TEST_ROOT}/run/vgt-gedefense-capture" \
  "${TEST_ROOT}/run/gedefense-scan" \
  "${TEST_ROOT}/sys/fs/bpf" \
  "${TEST_ROOT}/sys/fs/cgroup/vgt-cells" \
  "${TEST_ROOT}/sys/bus/usb" \
  "${TEST_ROOT}/sys/bus/thunderbolt/devices"
: >"${TEST_ROOT}/var/lib/vgt/gedefense/parser-burn-ledger.jsonl"
: >"${TEST_ROOT}/etc/vgt/gedefense/secrets/cell-helper.key"
: >"${TEST_ROOT}/etc/vgt/gedefense/parser-profiles.conf"
install -m 0755 /usr/bin/mount "${TEST_ROOT}/bin/mount"
install -m 0755 /usr/bin/bash "${TEST_ROOT}/usr/bin/bash"
# gedefense-control.service uses a privileged `/bin/sh -c` ExecStartPre (one-time
# cgroup-subtree bootstrap). The isolated --root has no /bin/sh, so stage bash as
# /bin/sh purely for systemd-analyze path resolution. NOT_TESTED: the production
# ExecStartPre itself is never executed by this gate.
install -m 0755 /usr/bin/bash "${TEST_ROOT}/bin/sh"
printf 'NOT_TESTED: /bin/sh in the verify root is a harness shim for systemd-analyze; the control unit ExecStartPre is not executed here.\n'
# The access unit runs privileged pre-steps with /usr/bin/install; systemd-analyze verify rejects a unit
# whose Exec lines are missing from the fake root, so the helper has to be present there too.
install -m 0755 /usr/bin/install "${TEST_ROOT}/usr/bin/install"

systemd-analyze verify --recursive-errors=no --root="$TEST_ROOT" \
  gedefense-bpffs.service \
  gedefense-core.service \
  gedefense-capture-helper.service \
  gedefense-control.service \
  gedefense-access.service \
  gedefense-cell-helper.service \
  gedefense-astraeaos-provision.service

access_unit=$(
  <"$UNIT_DIR/gedefense-access.service"
)
credential_key=$(sed -n 's/^LoadCredential=tls-key:\(.*\)$/\1/p' <<<"$access_unit")
if [[ -z $credential_key ]]; then
  printf 'gedefense-access does not load its TLS key as a systemd credential.\n' >&2
  exit 1
fi
# The key arrives as a credential from the TLS directory while the certificate is pinned by path. If the
# two halves are sourced from different directories they drift apart on the next renewal and the gateway
# dies with "tls: private key does not match public key" - a listener that silently stops answering.
if ! grep -qF -- "$(dirname "$credential_key")/access.crt" <<<"$access_unit"; then
  printf 'gedefense-access sources its certificate outside %s.\n' "$(dirname "$credential_key")" >&2
  exit 1
fi

gaia_access_dropin=$(
  <"$UNIT_DIR/gedefense-access.service.d/10-astraeaos-loopback.conf"
)
grep -Fxq 'ExecStart=' <<<"$gaia_access_dropin"
grep -Fq -- '--listen=127.0.0.1:9843' <<<"$gaia_access_dropin"
grep -Fq 'Requires=gedefense-astraeaos-provision.service' <<<"$gaia_access_dropin"
grep -Fq 'TimeoutStartSec=20s' <<<"$gaia_access_dropin"
if grep -Fq -- '--listen=0.0.0.0:9843' <<<"$gaia_access_dropin"; then
  printf 'GeDefense AstraeaOS access service exposes a wildcard listener.\n' >&2
  exit 1
fi

gaia_control_dropin=$(
  <"$UNIT_DIR/gedefense-control.service.d/10-astraeaos-provision.conf"
)
grep -Fq 'Requires=gedefense-astraeaos-provision.service' <<<"$gaia_control_dropin"
grep -Fq 'After=gedefense-astraeaos-provision.service' <<<"$gaia_control_dropin"

bpffs_unit=$(
  <"$UNIT_DIR/gedefense-bpffs.service"
)
if grep -Fq 'ConditionPathIsMountPoint=' <<<"$bpffs_unit"; then
  printf 'gedefense-bpffs must not skip when bpffs is already mounted.\n' >&2
  exit 1
fi
grep -Fq 'RemainAfterExit=yes' <<<"$bpffs_unit"
grep -Fq 'findmnt' <<<"$bpffs_unit"

# POINT 5 (docs/POINT5-LOCKDOWN.md §8): the core unit gets deterministic,
# single-node writable paths for the Emergency Lockdown. ProtectKernelTunables
# keeps /sys and /proc/sys read-only, so the USB/Thunderbolt policy and the
# opt-in hardening sysctls need those exceptions. The security contract is that
# nothing else changes: no capability, address-family or syscall widening, and
# /sys must never become writable as a whole. The /sys/devices grant is
# deliberate: /sys/bus/usb/devices and /sys/bus/thunderbolt/devices are sysfs
# symlinks, so every per-device "authorized" write resolves to /sys/devices/**
# and would be EROFS with a bus-path-only grant (fail-safe but ineffective).
core_unit=$(
  <"$UNIT_DIR/gedefense-core.service"
)
for directive in \
  'ReadWritePaths=-/sys/bus/usb -/sys/bus/thunderbolt/devices -/sys/devices' \
  'ReadWritePaths=-/proc/sys/kernel/kexec_load_disabled -/proc/sys/kernel/sysrq -/proc/sys/kernel/modules_disabled' \
  'ReadWritePaths=/var/lib/vgt/gedefense' \
  'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_KILL' \
  'AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_KILL' \
  'RestrictAddressFamilies=AF_UNIX AF_NETLINK' \
  'SystemCallFilter=@system-service bpf perf_event_open pidfd_open pidfd_send_signal fanotify_init fanotify_mark' \
  'ProtectKernelTunables=true' \
  'PrivateDevices=true'; do
  grep -Fq -- "$directive" <<<"$core_unit" || {
    printf 'gedefense-core.service is missing required POINT 5 directive: %s\n' "$directive" >&2
    exit 1
  }
done
# The complete writable sysfs set must stay exactly reviewed: the pre-existing
# bpffs mount plus the three lockdown nodes. Any further /sys ReadWritePaths
# token (e.g. /sys/kernel) would silently widen the lockdown sandbox.
read -r -a sys_grants <<<"$(
  grep -E '^[[:space:]]*ReadWritePaths=' <<<"$core_unit" |
    sed 's/^[^=]*=//' | tr ' ' '\n' | sed 's/^-//' |
    grep -E '^/sys(/|$)' | sort -u | tr '\n' ' '
)"
if [[ ${sys_grants[*]-} != '/sys/bus/thunderbolt/devices /sys/bus/usb /sys/devices /sys/fs/bpf /sys/fs/bpf/gedefense' ]]; then
  printf 'gedefense-core.service has an unexpected writable sysfs set: %s\n' "${sys_grants[*]-}" >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*CapabilityBoundingSet=.*(CAP_SYS_PTRACE|CAP_SYS_MODULE|CAP_DAC_READ_SEARCH|CAP_SYS_RAWIO)' <<<"$core_unit"; then
  printf 'gedefense-core.service grants a capability outside the reviewed lockdown contract.\n' >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*RestrictAddressFamilies=.*(AF_INET|AF_PACKET|AF_BLUETOOTH)' <<<"$core_unit"; then
  printf 'gedefense-core.service widens RestrictAddressFamilies for the lockdown.\n' >&2
  exit 1
fi
if grep -Eq 'ReadWritePaths=([^[:space:]]*[[:space:]])*/sys([[:space:]]|$)' <<<"$core_unit"; then
  printf 'gedefense-core.service makes /sys writable as a whole instead of the exact bus/device nodes.\n' >&2
  exit 1
fi

# POINT 2: the privileged parser-cell helper is the only process allowed to
# spawn/freeze/burn cells. Pin the reviewed privilege boundary: root service,
# exact capability set, the sandbox directives from spec §4.9, the dedicated
# writable paths and a fail-closed restart policy.
helper_unit=$(
  <"$UNIT_DIR/gedefense-cell-helper.service"
)
for directive in \
  'User=root' \
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
  'Restart=on-failure' \
  'StartLimitIntervalSec=120' \
  'SystemCallFilter=@system-service @mount seccomp'; do
  grep -Fq -- "$directive" <<<"$helper_unit" || {
    printf 'gedefense-cell-helper.service is missing required directive: %s\n' "$directive" >&2
    exit 1
  }
done
if grep -Fq 'ProtectControlGroups=yes' <<<"$helper_unit"; then
  printf 'gedefense-cell-helper must not enable ProtectControlGroups=yes (it owns the dedicated cgroup subtree).\n' >&2
  exit 1
fi
if grep -Eq 'CapabilityBoundingSet=.*CAP_SYS_PTRACE' <<<"$helper_unit"; then
  printf 'gedefense-cell-helper grants CAP_SYS_PTRACE outside the reviewed contract.\n' >&2
  exit 1
fi
grep -Fq -- '--socket=/run/vgt-gedefense/cell-helper.sock' <<<"$helper_unit"
grep -Fq -- '--key-file=/etc/vgt/gedefense/secrets/cell-helper.key' <<<"$helper_unit"
grep -Fq -- '--profiles=/etc/vgt/gedefense/parser-profiles.conf' <<<"$helper_unit"
grep -Fq -- '--max-cells=16' <<<"$helper_unit"

# POINT 4 (docs/POINT4-WITNESS.md §4/§7/§8): the Out-of-Band Witness state
# (encrypted outbox.enc + authenticated ack.enc below <state>/witness/) is
# written at runtime by the unprivileged control plane. The witness client itself
# adds no capability and no address-family/syscall widening: it only uses the
# pre-existing outbound AF_INET/AF_INET6 families.
# FIND-008 (VGT-AUDIT-20261118-GD61-R2): the control plane holds zero Linux
# capabilities and no AF_PACKET family. Passive AF_PACKET capture (Module C)
# and CN_PROC netlink fallback (Module B) are isolated into the dedicated
# gedefense-capture-helper.service unit (IPAddressDeny=any, no AF_INET/AF_INET6,
# zero access to /etc/vgt/gedefense, /var/lib/vgt/gedefense or /run/vgt-gedefense).
control_unit=$(
  <"$UNIT_DIR/gedefense-control.service"
)
for directive in \
  'User=gedefense' \
  'ReadWritePaths=/var/lib/vgt/gedefense' \
  'NoNewPrivileges=true'; do
  grep -Fq -- "$directive" <<<"$control_unit" || {
    printf 'gedefense-control.service is missing required POINT 4 directive: %s\n' "$directive" >&2
    exit 1
  }
done
control_capabilities=$(grep -E '^[[:space:]]*(CapabilityBoundingSet|AmbientCapabilities)=' <<<"$control_unit" | sed 's/^[[:space:]]*//' || true)
if [[ "$control_capabilities" != 'CapabilityBoundingSet=' ]]; then
  printf 'gedefense-control.service must hold ZERO capabilities (CapabilityBoundingSet= only, FIND-008).\n' >&2
  exit 1
fi
control_families=$(grep -E '^[[:space:]]*RestrictAddressFamilies=' <<<"$control_unit" | sed 's/^[[:space:]]*//' || true)
if [[ "$control_families" != 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' ]]; then
  printf 'gedefense-control.service must not allow AF_PACKET (FIND-008).\n' >&2
  exit 1
fi

capture_unit=$(
  <"$UNIT_DIR/gedefense-capture-helper.service"
)
for directive in \
  'User=gedefense' \
  'Group=gedefense' \
  'RuntimeDirectory=vgt-gedefense-capture' \
  'RuntimeDirectoryMode=0700' \
  'NoNewPrivileges=true' \
  'ProtectSystem=strict' \
  'ProtectHome=true' \
  'PrivateDevices=true' \
  'IPAddressDeny=any' \
  'ReadOnlyPaths=/opt/vgt/gedefense/current' \
  'ReadWritePaths=/run/vgt-gedefense-capture' \
  '--capture-helper' \
  '--capture-helper-socket=/run/vgt-gedefense-capture/capture.sock'; do
  grep -Fq -- "$directive" <<<"$capture_unit" || {
    printf 'gedefense-capture-helper.service is missing required FIND-008 directive: %s\n' "$directive" >&2
    exit 1
  }
done
capture_capabilities=$(grep -E '^[[:space:]]*(CapabilityBoundingSet|AmbientCapabilities)=' <<<"$capture_unit" | sed 's/^[[:space:]]*//' || true)
expected_capture_capabilities=$'CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\nAmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN'
if [[ "$capture_capabilities" != "$expected_capture_capabilities" ]]; then
  printf 'gedefense-capture-helper.service must hold exactly CAP_NET_RAW CAP_NET_ADMIN (FIND-008).\n' >&2
  exit 1
fi
capture_families=$(grep -E '^[[:space:]]*RestrictAddressFamilies=' <<<"$capture_unit" | sed 's/^[[:space:]]*//' || true)
if [[ "$capture_families" != 'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET' ]]; then
  printf 'gedefense-capture-helper.service must allow exactly AF_UNIX AF_NETLINK AF_PACKET (FIND-008).\n' >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*(ReadWritePaths|ReadOnlyPaths)=.*(/etc/vgt/gedefense|/var/lib/vgt/gedefense|/run/vgt-gedefense([[:space:]]|$))' <<<"$capture_unit"; then
  printf 'gedefense-capture-helper.service must not access /etc/vgt/gedefense, /var/lib/vgt/gedefense, or /run/vgt-gedefense (FIND-008).\n' >&2
  exit 1
fi
if grep -Eq 'ReadWritePaths=[^[:space:]]*witness' <<<"$control_unit"; then
  printf 'gedefense-control.service has a witness-specific ReadWritePaths exception; the state stays inside /var/lib/vgt/gedefense.\n' >&2
  exit 1
fi
if grep -Eq 'ReadWritePaths=[^[:space:]]*witness' <<<"$core_unit"; then
  printf 'gedefense-core.service must not gain a witness state grant (the state belongs to the control plane).\n' >&2
  exit 1
fi
if compgen -G "$ROOT/packaging/systemd/*witness*" >/dev/null; then
  printf 'no dedicated witness systemd unit may ship in Phase 1 (unprivileged Go control only).\n' >&2
  exit 1
fi
grep -Fq 'd /var/lib/vgt/gedefense 1770 root gedefense -' "$ROOT/packaging/tmpfiles/vgt-gedefense.conf" || {
  printf 'tmpfiles must keep /var/lib/vgt/gedefense 1770 root:gedefense so the control plane can create <state>/witness/ itself.\n' >&2
  exit 1
}

printf 'GeDefense systemd units validated in isolated root.\n'
