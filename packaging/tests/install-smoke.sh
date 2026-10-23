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
  grep -Fq -- "$needle" -- "$path" || fail "$label"
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
  packaging/systemd/gedefense-provision.service
  packaging/scripts/gedefense-provision
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

provision_unit="${SOURCE_ROOT}/packaging/systemd/gedefense-provision.service"
assert_contains "$provision_unit" 'Before=gedefense-bpffs.service gedefense-core.service gedefense-control.service gedefense-access.service' "provision unit must run before every GeDefense service"
assert_contains "$provision_unit" 'ConditionPathExists=/opt/vgt/gedefense/current/bin/gedefense-access' "provision unit must be conditioned on the installed release"
assert_contains "$provision_unit" '/usr/libexec/gedefense/gedefense-provision' "provision unit must execute the packaged provisioning contract"

core_unit="${SOURCE_ROOT}/packaging/systemd/gedefense-core.service"
assert_contains "$core_unit" 'ReadWritePaths=/run/vgt-gedefense /run/gedefense-scan' "core unit must be allowed to bind the restricted user scan socket"
assert_contains "$core_unit" '--scan-socket=/run/gedefense-scan/scan.sock' "core unit must use the packaged scan socket path"

tmpfiles="${SOURCE_ROOT}/packaging/tmpfiles/vgt-gedefense.conf"
for line in \
  'd /run/gedefense-scan 0750 root gedefense -' \
  'd /etc/vgt/gedefense 0750 root gedefense -' \
  'd /etc/vgt/gedefense/secrets 0700 root gedefense -' \
  'd /etc/vgt/gedefense/tls 0750 root gedefense -' \
  'd /etc/vgt/gedefense-access 0750 gedefense-access gedefense-access -' \
  'd /var/lib/vgt/gedefense-access 0750 gedefense gedefense-access -' \
  'd /var/lib/vgt/gedefense-access/state 0700 gedefense-access gedefense-access -'; do
  assert_contains "$tmpfiles" "$line" "tmpfiles contract missing: $line"
done
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
  '-o root -g gedefense "${srcdir}/gedefense.packaged.toml"' \
  's#^listen = "127.0.0.1:9843"#listen = "127.0.0.1:9844"#'; do
  assert_contains "$pkgbuild" "$needle" "PKGBUILD missing provisioning/topology element: $needle"
done

hook="${SOURCE_ROOT}/packaging/pacman/gedefense-provision.hook"
assert_contains "$hook" 'systemctl enable gedefense-provision.service' "pacman hook must enable the provisioning unit"
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
  "${stage}/etc/vgt/gedefense" "${stage}/usr/lib/systemd/system"

access_bin="${SOURCE_ROOT}/dist/gedefense-access"
control_bin="${SOURCE_ROOT}/dist/gedefense-control"
core_bin="${SOURCE_ROOT}/rust/target/release/gedefense-core"
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
for unit in gedefense-bpffs.service gedefense-core.service gedefense-control.service \
  gedefense-provision.service gedefense-access.service; do
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
  "etc/vgt/gedefense/secrets:700" \
  "etc/vgt/gedefense/tls:750" \
  "etc/vgt/gedefense-access:750" \
  "var/lib/vgt/gedefense:1770" \
  "var/lib/vgt/gedefense-access:750" \
  "var/lib/vgt/gedefense-access/state:700" \
  "run/gedefense-scan:750"; do
  IFS=: read -r relative mode <<<"$entry"
  actual=$(stat -c '%a' -- "${stage}/${relative}")
  if [[ $actual == "$mode" ]]; then
    pass "directory ${relative} mode ${mode}"
  else
    fail "directory ${relative} mode ${actual}, expected ${mode}"
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

for key in \
  "etc/vgt/gedefense/secrets/core-ipc.key" \
  "etc/vgt/gedefense/secrets/storage-master.key" \
  "var/lib/vgt/gedefense/xdr-log.key" \
  "var/lib/vgt/gedefense-access/state/access-session.key"; do
  if [[ $(stat -c %s -- "${stage}/${key}") -eq 32 ]]; then
    pass "${key} contains exactly 32 bytes"
  else
    fail "${key} does not contain exactly 32 bytes"
  fi
done

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
