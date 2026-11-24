#!/usr/bin/env bash
# V6.3.0 AP-8 — non-invasive packaging smoke test for the Chameleon installer
# helper. Runs entirely inside a temporary staging root; it never touches the
# host's systemd, /etc, /var/lib or /run.
#
# Usage: bash packaging/tests/install-chameleon-smoke.sh
set -Eeuo pipefail
umask 022

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
HELPER="$REPO/scripts/apply-chameleon-profile.sh"
CORE_UNIT="$REPO/packaging/systemd/gedefense-core.service"
CONTROL_UNIT="$REPO/packaging/systemd/gedefense-control.service"
ACCESS_UNIT="$REPO/packaging/systemd/gedefense-access.service.in"

failures=0
check() {
  local label="$1"
  shift
  if "$@"; then
    printf '  ok    %s\n' "$label"
  else
    printf '  FAIL  %s\n' "$label" >&2
    failures=$((failures + 1))
  fi
}
fail() { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT

mkdir -p "$TMP/etc/systemd/system"
install -m 0644 "$CORE_UNIT" "$TMP/etc/systemd/system/gedefense-core.service"
install -m 0644 "$CONTROL_UNIT" "$TMP/etc/systemd/system/gedefense-control.service"
# The access unit is a template in the release payload; render the placeholders
# like the oneclick installer does so the helper sees a realistic ExecStart.
sed -e 's#@RELEASE@#/opt/vgt/gedefense/current#g' \
  -e 's#@PUBLIC_PORT@#9843#g' \
  -e 's#@PUBLIC_HOST@#vgt.example:9843#g' \
  "$ACCESS_UNIT" >"$TMP/etc/systemd/system/gedefense-access.service"

INSTALL_ID="gd-smoke-4f8c2e91a7b3d6c0"
COMMON_ARGS=(
  --root "$TMP"
  --install-id "$INSTALL_ID"
  --salt "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  --state-dir /var/lib/gdn/state
  --config-dir /etc/gdn
  --core-socket /run/gdn-4f8c/core.sock
  --scan-socket /run/gedefense-scan/4f8c2e91.sock
  --bpf-pin-root /sys/fs/bpf/gdn-4f8c
  --backend-port 31441
  --public-port 31440
  --unit-prefix gdn
)

echo "[1] dry-run writes nothing"
if bash "$HELPER" "${COMMON_ARGS[@]}" --dry-run >/dev/null 2>&1; then
  check "dry-run exits 0" test ! -e "$TMP/etc/gdn"
else
  fail "dry-run exited non-zero"
fi

echo "[2] initial application"
if bash "$HELPER" "${COMMON_ARGS[@]}" >/dev/null 2>&1; then
  check "helper exits 0" true
else
  fail "helper exited non-zero"
fi
MANIFEST="$TMP/etc/gdn/${INSTALL_ID}.conf"
check "manifest exists" test -f "$MANIFEST"
check "manifest is not a symlink" test ! -L "$MANIFEST"
check "manifest schema line" grep -qx 'vgt-gedefense-chameleon-v1' "$MANIFEST"
check "manifest install id" grep -qx "install_id=${INSTALL_ID}" "$MANIFEST"
check "manifest salt" grep -qx 'bpf_name_salt=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' "$MANIFEST"
check "manifest core socket" grep -qx 'core_socket=/run/gdn-4f8c/core.sock' "$MANIFEST"
check "manifest scan socket" grep -qx 'scan_socket=/run/gedefense-scan/4f8c2e91.sock' "$MANIFEST"
check "manifest pin root" grep -qx 'bpf_pin_root=/sys/fs/bpf/gdn-4f8c' "$MANIFEST"
check "manifest state dir" grep -qx 'state_dir=/var/lib/gdn/state' "$MANIFEST"
check "manifest config dir" grep -qx 'config_dir=/etc/gdn' "$MANIFEST"
check "manifest ports" grep -qx 'backend_port=31441' "$MANIFEST"
check "manifest public port" grep -qx 'public_port=31440' "$MANIFEST"
check "manifest unit prefix" grep -qx 'neutral_unit_prefix=gdn' "$MANIFEST"

CORE_DROPIN="$TMP/etc/systemd/system/gedefense-core.service.d/10-chameleon.conf"
CONTROL_DROPIN="$TMP/etc/systemd/system/gedefense-control.service.d/10-chameleon.conf"
ACCESS_DROPIN="$TMP/etc/systemd/system/gedefense-access.service.d/10-chameleon.conf"
check "core drop-in exists" test -f "$CORE_DROPIN"
check "control drop-in exists" test -f "$CONTROL_DROPIN"
check "access drop-in exists" test -f "$ACCESS_DROPIN"
check "core drop-in passes the manifest" grep -q -- "--chameleon-manifest=/etc/gdn/${INSTALL_ID}.conf" "$CORE_DROPIN"
check "core drop-in uses the neutral core socket" grep -q -- '--socket=/run/gdn-4f8c/core.sock' "$CORE_DROPIN"
check "core drop-in uses the neutral scan socket" grep -q -- '--scan-socket=/run/gedefense-scan/4f8c2e91.sock' "$CORE_DROPIN"
check "core drop-in uses the neutral pin root" grep -q -- '--bpf-pin-root=/sys/fs/bpf/gdn-4f8c' "$CORE_DROPIN"
check "core drop-in removed the public socket flag" bash -c "! grep -q -- '--socket=/run/vgt-gedefense/core.sock' '$CORE_DROPIN'"
check "core drop-in resets RuntimeDirectory" grep -qx 'RuntimeDirectory=' "$CORE_DROPIN"
check "core drop-in grants the neutral state root" grep -q -- "ReadWritePaths=/var/lib/gdn/state" "$CORE_DROPIN"
check "control drop-in passes the manifest" grep -q -- "--chameleon-manifest=/etc/gdn/${INSTALL_ID}.conf" "$CONTROL_DROPIN"
check "access drop-in uses the neutral backend port" grep -q -- '--backend=http://127.0.0.1:31441' "$ACCESS_DROPIN"
check "access drop-in uses the neutral public port" grep -q -- '--listen=0.0.0.0:31440' "$ACCESS_DROPIN"
check "tmpfiles drop-in exists" test -f "$TMP/etc/tmpfiles.d/10-chameleon-neutral.conf"
check "tmpfiles provisions the runtime dir" grep -qx 'd /run/gdn-run 0750 root gedefense -' "$TMP/etc/tmpfiles.d/10-chameleon-neutral.conf"
check "tmpfiles provisions the state dir" grep -qx 'd /var/lib/gdn/state 0770 root gedefense -' "$TMP/etc/tmpfiles.d/10-chameleon-neutral.conf"
check "state dir created in staging root" test -d "$TMP/var/lib/gdn/state"

if [[ $EUID -eq 0 ]]; then
  check "manifest is root:gedefense 0640" test "$(stat -c '%U:%G:%a' "$MANIFEST")" = "root:gedefense:640"
else
  check "manifest is not group/world readable" test "$(stat -c '%a' "$MANIFEST")" = "600"
fi

echo "[3] idempotent second application"
before=$(cd "$TMP" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
if bash "$HELPER" "${COMMON_ARGS[@]}" >/dev/null 2>&1; then
  after=$(cd "$TMP" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
  if [[ $before == "$after" ]]; then
    check "second run leaves every file byte-identical" true
  else
    fail "second run changed files"
  fi
else
  fail "second (idempotent) run exited non-zero"
fi

echo "[4] invalid inputs are rejected without writing"
for mutation in \
  "--salt=zz" \
  "--backend-port=80" \
  "--public-port=31441" \
  "--unit-prefix=Gdn" \
  "--state-dir=relative/state" \
  "--scan-socket=/tmp/foreign-scan.sock" \
  "--core-socket=/tmp/foreign-core.sock" \
  "--install-id=short"; do
  if bash "$HELPER" "${COMMON_ARGS[@]}" "$mutation" >/dev/null 2>&1; then
    fail "invalid input accepted: $mutation"
  else
    printf '  ok    rejected: %s\n' "$mutation"
  fi
done

echo "[5] the manifest parses with the packaged contract"
python3 - "$MANIFEST" "$REPO" <<'PY'
import sys
from pathlib import Path

manifest = Path(sys.argv[1]).read_text(encoding="utf-8")
lines = manifest.split("\n")
assert lines[0] == "vgt-gedefense-chameleon-v1", lines[0]
keys = {}
for line in lines[1:]:
    if not line:
        continue
    key, value = line.split("=", 1)
    assert key not in keys, f"duplicate {key}"
    keys[key] = value
required = {
    "install_id", "bpf_name_salt", "core_socket", "scan_socket", "bpf_pin_root",
    "state_dir", "config_dir", "public_port", "backend_port", "neutral_unit_prefix",
}
assert required <= set(keys), required - set(keys)
assert len(keys["bpf_name_salt"]) == 64
assert int(keys["public_port"]) >= 1024 and int(keys["backend_port"]) >= 1024
print("  ok    manifest contract")
PY

echo
if [[ $failures -ne 0 ]]; then
  echo "CHAMELEON PACKAGING SMOKE FAILED: $failures failure(s)" >&2
  exit 1
fi
echo "CHAMELEON PACKAGING SMOKE PASS"
