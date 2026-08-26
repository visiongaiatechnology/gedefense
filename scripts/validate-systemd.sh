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
  "${TEST_ROOT}/bin" "${TEST_ROOT}/usr/lib/astraeaos"

install -m 0644 "$ROOT/packaging/systemd/gedefense-bpffs.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/packaging/systemd/gedefense-core.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/packaging/systemd/gedefense-control.service" "$UNIT_DIR/"
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

for path in \
  "$RELEASE/libexec/gedefense-core" \
  "$RELEASE/bin/gedefense-control" \
  "$RELEASE/bin/gedefense-access" \
  "${TEST_ROOT}/usr/lib/astraeaos/gedefense-astraeaos-provision"; do
  printf '#!/bin/sh\nexit 0\n' >"$path"
  chmod 0755 "$path"
done
install -m 0755 /usr/bin/mount "${TEST_ROOT}/bin/mount"

systemd-analyze verify --recursive-errors=no --root="$TEST_ROOT" \
  gedefense-bpffs.service \
  gedefense-core.service \
  gedefense-control.service \
  gedefense-access.service \
  gedefense-astraeaos-provision.service

gaia_access_dropin=$(
  <"$UNIT_DIR/gedefense-access.service.d/10-astraeaos-loopback.conf"
)
grep -Fxq 'ExecStart=' <<<"$gaia_access_dropin"
grep -Fq -- '--listen=127.0.0.1:9843' <<<"$gaia_access_dropin"
grep -Fq 'Requires=gedefense-astraeaos-provision.service' <<<"$gaia_access_dropin"
grep -Fq 'TimeoutStartSec=90s' <<<"$gaia_access_dropin"
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

printf 'GeDefense systemd units validated in isolated root.\n'
