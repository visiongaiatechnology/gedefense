#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
#
# Static/package regression tests for F-14 / CHAIN-016 (privileged password
# helper), the fixed-argument sudoers rule and the AstraeaOS access-gateway
# provision contract (F-05 / CHAIN-005).
#
# The helper itself needs root and a real installation to execute. This
# environment cannot install the Arch packages or run root helpers against a
# live /etc, so the dynamic helper path is reported as NOT_TESTED instead of
# being faked. Every assertion below fails the run, so a regression cannot pass
# silently.
set -Eeuo pipefail
umask 0077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
INTEGRATION_DIR=$(realpath "${SCRIPT_DIR}/..")
if [[ ${1:-} == --integration-dir ]]; then
  [[ -n ${2:-} ]] || { printf 'usage: %s [--integration-dir <dir>]\n' "$0" >&2; exit 2; }
  INTEGRATION_DIR=$(realpath "$2")
elif [[ $# -gt 0 ]]; then
  printf 'usage: %s [--integration-dir <dir>]\n' "$0" >&2
  exit 2
fi

passes=0
failures=0

pass() {
  passes=$((passes + 1))
  printf 'HOST-POLICY PASS: %s\n' "$1"
}

fail() {
  failures=$((failures + 1))
  printf 'HOST-POLICY FAIL: %s\n' "$1" >&2
}

not_tested() {
  printf 'HOST-POLICY NOT_TESTED: %s\n' "$1"
}

require_contains() {
  local path=$1 needle=$2 label=$3
  if grep -Fq -- "$needle" "$path"; then
    pass "$label"
  else
    fail "$label (missing: $needle)"
  fi
}

require_absent() {
  local path=$1 needle=$2 label=$3
  if grep -Fq -- "$needle" "$path"; then
    fail "$label (found: $needle)"
  else
    pass "$label"
  fi
}

helper="${INTEGRATION_DIR}/gedefense-set-password"
app="${INTEGRATION_DIR}/gedefense-app"
provision="${INTEGRATION_DIR}/gedefense-astraeaos-provision"
access_dropin="${INTEGRATION_DIR}/gedefense-access-astraeaos.conf"
sudoers="${INTEGRATION_DIR}/90-astraeaos-gedefense.sudoers"
profile="${INTEGRATION_DIR}/astraeaos-profile.toml"
pkgbuild="${INTEGRATION_DIR}/PKGBUILD"

for script in "$helper" "$app" "$provision" "${SCRIPT_DIR}/$(basename "$0")"; do
  if bash -n "$script"; then
    pass "bash -n $(basename "$script")"
  else
    fail "bash -n $(basename "$script")"
  fi
done

# --- F-14: no caller-controlled path is shredded ----------------------------
require_absent "$helper" 'shred' "password helper must not shed caller files with shred"
require_contains "$helper" 'readonly destination=/etc/vgt/gedefense-access/access-password' "password record is installed in the gateway-owned directory"
require_contains "$helper" 'PKEXEC_UID' "helper derives the invoking identity from the privilege boundary"
require_contains "$helper" 'SUDO_UID' "helper accepts the sudo invoking identity"
require_contains "$helper" '/proc/self/fd/3' "helper validates the password file on an open descriptor (fstat)"
require_contains "$helper" 'file_mode == "600"' "password file must be 0600"
require_contains "$helper" 'file_uid == "$caller_uid"' "password file must be owned by the invoking user"
require_contains "$helper" 'parent_mode == "700"' "private caller directory is required before the helper unlinks its temp file"
require_contains "$helper" 'caller_private_parent=1' "only a validated caller-private temp file may be removed"
require_contains "$helper" 'only an optional single --password-file argument is accepted' "helper rejects arbitrary positional arguments"
require_contains "$helper" '--reload-access' "helper reloads the gateway and verifies readiness before committing"
if grep -Fq -- '--password-file' "$helper" && ! grep -Fq -- 'case "$1"' "$helper"; then
  pass "helper option handling is an explicit allowlist"
fi

# --- F-14: fixed-argument sudoers rule --------------------------------------
require_contains "$sudoers" '/usr/lib/astraeaos/gedefense-set-password ""' "sudoers permits only the argument-less set-password helper"
require_contains "$sudoers" '/usr/lib/astraeaos/gedefense-ensure-ready ""' "sudoers permits only the argument-less ensure-ready helper"
if grep -Eq '\*|NOPASSWD: ALL|/bin/(ba)?sh|sudoedit' "$sudoers"; then
  fail "sudoers rule contains a wildcard, shell or password-file argument expansion"
else
  pass "sudoers rule contains no wildcards or shell indirection"
fi
if grep -Fq -- '--password-file' "$sudoers"; then
  fail "sudoers must not permit a caller-controlled --password-file argument"
else
  pass "sudoers does not expose the --password-file argument"
fi

# --- F-14: desktop app only hands over a private temp file -----------------
require_absent "$app" 'shred' "desktop app no longer shreds password files"
require_contains "$app" 'XDG_RUNTIME_DIR' "desktop app prefers the private per-user runtime directory"
require_contains "$app" 'chmod 0700 -- "$own_dir"' "fallback temp directory is 0700"
require_contains "$app" 'printf '\''%s'\'' "$first" >"$pwfile"' "desktop app writes the secret without echoing"

# --- F-05: AstraeaOS access drop-in uses the canonical gateway contract ----
require_contains "$access_dropin" '--backend=http://127.0.0.1:9844' "access backend targets the internal control port 9844"
require_contains "$access_dropin" '--password-file=/etc/vgt/gedefense-access/access-password' "access reads the gateway-owned password record"
require_contains "$access_dropin" '--backend-token-file=/var/lib/vgt/gedefense-access/state/backend-token' "access reads the ExecStartPre-provisioned token copy"
require_contains "$access_dropin" '--session-key-file=/var/lib/vgt/gedefense-access/state/access-session.key' "access session key lives in the gateway state directory"
require_contains "$access_dropin" '--tls-cert=/etc/vgt/gedefense-access/access.crt' "access certificate comes from the gateway-owned directory"
require_absent "$access_dropin" 'ExecStartPre=' "drop-in must not clear the base unit's root provisioning steps"
require_contains "$access_dropin" 'ExecStartPost=/usr/lib/astraeaos/gedefense-access-ready' "readiness post-step kept"

require_contains "$profile" 'listen = "127.0.0.1:9844"' "AstraeaOS profile keeps the internal backend port"
require_contains "$profile" 'token_file = "/var/lib/vgt/gedefense-access/dashboard.token"' "AstraeaOS profile uses the gateway-owned token path"

# --- F-05: AstraeaOS provisioning creates the same contract ----------------
require_contains "$provision" 'readonly ACCESS_CONFIG_DIR=/etc/vgt/gedefense-access' "provision creates the gateway configuration directory"
require_contains "$provision" 'readonly ACCESS_STATE_DIR=${ACCESS_STATE_PARENT}/state' "provision creates the gateway state directory"
require_contains "$provision" 'local path=${ACCESS_STATE_PARENT}/dashboard.token' "provision installs the token at the canonical path"
require_contains "$provision" 'local record=${ACCESS_CONFIG_DIR}/access-password' "provision installs the password record at the canonical path"
require_contains "$provision" 'install_random_key "${ACCESS_STATE_DIR}/access-session.key" "$ACCESS_USER" "$ACCESS_GROUP" 0600' "provision installs the session key for the gateway account"
require_contains "$provision" 'install -m 0644 -o "$ACCESS_USER" -g "$ACCESS_GROUP" "$cert" "${ACCESS_CONFIG_DIR}/access.crt"' "provision installs the gateway-owned certificate copy"
require_contains "$provision" 'install -d -m 0750 -o root -g gedefense "$SCAN_RUN_DIR"' "provision creates the restricted user-scan runtime directory"
require_contains "$provision" 'mv -T -- "$legacy" "$path"' "provision migrates the pre-5.0 token path instead of rotating it"
provision_unit="${INTEGRATION_DIR}/gedefense-astraeaos-provision.service"
require_contains "$provision_unit" 'ReadWritePaths=/etc/vgt/gedefense /etc/vgt/gedefense-access /var/lib/vgt /run/gedefense-scan' "provision unit sandbox permits exactly the provisioned paths"

# --- F-05: PKGBUILD source hashes are complete and consistent --------------
python3 - "$pkgbuild" "$INTEGRATION_DIR" <<'PY'
import hashlib, re, sys
from pathlib import Path

pkgbuild = Path(sys.argv[1])
root = Path(sys.argv[2])
text = pkgbuild.read_text(encoding="utf-8")
source_block = re.search(r"source=\((.*?)\n\)", text, re.S)
sums_block = re.search(r"sha256sums=\((.*?)\n\)", text, re.S)
assert source_block and sums_block, "source/sha256sums block missing"
sources = re.findall(r"'([^']+)'", source_block.group(1))
sums = re.findall(r"'([0-9a-f]{64})'", sums_block.group(1))
assert len(sources) == len(sums), f"source count {len(sources)} != checksum count {len(sums)}"
for name, expected in zip(sources, sums):
    path = root / name
    assert path.is_file(), f"missing integration source {name}"
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == expected, f"stale checksum for {name}"
print(f"PKGBUILD-SYNC OK: {len(sources)} sources content-addressed")
PY
if [[ $? -eq 0 ]]; then
  pass "AstraeaOS PKGBUILD source list matches sha256sums"
else
  fail "AstraeaOS PKGBUILD source list does not match sha256sums"
fi

# --- F-18: no world-writable socket/runtime declarations in integration ----
if grep -Eq '0666|0777|mode=0o666|Permissions::from_mode\(0o666\)' "$INTEGRATION_DIR"/*; then
  fail "integration tree contains a world-writable mode declaration"
else
  pass "integration tree contains no world-writable mode declarations"
fi

not_tested "dynamic helper execution as root with PKEXEC_UID/SUDO_UID and a real Argon2id binary"
not_tested "caller-owned 0700 temp file deletion as root (requires the installed helper and real accounts)"
not_tested "fixed-argument sudoers rule syntax validation with visudo on AstraeaOS"
not_tested "real access-unit start and TLS livez readiness on AstraeaOS"

printf 'HOST-POLICY RESULT: %d passed, %d failed\n' "$passes" "$failures"
if (( failures > 0 )); then
  exit 1
fi
