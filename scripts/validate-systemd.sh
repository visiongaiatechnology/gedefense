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
  "$UNIT_DIR/gedefense-core.service.d" \
  "$RELEASE/libexec" "$RELEASE/bin" \
  "${TEST_ROOT}/bin" "${TEST_ROOT}/usr/lib/gaiaos"

install -m 0644 "$ROOT/packaging/systemd/gedefense-bpffs.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/packaging/systemd/gedefense-core.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/packaging/systemd/gedefense-control.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/integration/gaiaos/gedefense-gaiaos-provision.service" "$UNIT_DIR/"
install -m 0644 "$ROOT/integration/gaiaos/gedefense-core-gaiaos.conf" \
  "$UNIT_DIR/gedefense-core.service.d/10-gaiaos-provision.conf"
sed \
  -e 's#@RELEASE@#/opt/vgt/gedefense/current#g' \
  -e 's#@PUBLIC_PORT@#9843#g' \
  -e 's#@PUBLIC_HOST@#127.0.0.1:9843#g' \
  "$ROOT/packaging/systemd/gedefense-access.service.in" \
  >"$UNIT_DIR/gedefense-access.service"
chmod 0644 "$UNIT_DIR/gedefense-access.service"

for path in \
  "$RELEASE/libexec/gedefense-core" \
  "$RELEASE/bin/gedefense-control" \
  "$RELEASE/bin/gedefense-access" \
  "${TEST_ROOT}/usr/lib/gaiaos/gedefense-gaiaos-provision"; do
  printf '#!/bin/sh\nexit 0\n' >"$path"
  chmod 0755 "$path"
done
install -m 0755 /usr/bin/mount "${TEST_ROOT}/bin/mount"

systemd-analyze verify --recursive-errors=no --root="$TEST_ROOT" \
  gedefense-bpffs.service \
  gedefense-core.service \
  gedefense-control.service \
  gedefense-access.service \
  gedefense-gaiaos-provision.service

printf 'GeDefense systemd units validated in isolated root.\n'
