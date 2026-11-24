#!/usr/bin/env bash
# =============================================================================
# V6.3.0 AP-8 — GeDefense Chameleon Identity Mode installer helper
#
# Writes the opt-in install manifest (root-owned, bounded, strict key=value) and
# the neutral systemd drop-ins/tmpfiles that an installation needs to present an
# installation-specific identity: neutral eBPF program/map names (derived by the
# core from the manifest salt), neutral core/scan socket paths, a neutral loopback
# backend port, a neutral bpffs pin root and neutral daemon state roots.
#
# This is deliberately NOT a runtime toggle: it is run by the installer before
# the services start and is idempotent. It never writes outside the directories
# it is given (plus the systemd/tmpfiles drop-in directories of the target root),
# never touches keys, TLS material or units, and refuses every invalid input.
#
# Usage (minimal; installer integration):
#   apply-chameleon-profile.sh \
#     --install-id=gdn-4f8c2e91a7b3d6c0 \
#     --state-dir=/var/lib/gdn/state \
#     --config-dir=/etc/gdn \
#     --core-socket=/run/gdn-4f8c/core.sock \
#     --scan-socket=/run/gedefense-scan/4f8c2e91.sock \
#     --bpf-pin-root=/sys/fs/bpf/gdn-4f8c \
#     --backend-port=31441 --public-port=31440 \
#     --unit-prefix=gdn
#
# --salt may be omitted; 32 random bytes are then read from /dev/urandom (the
# salt is the HMAC key for the neutral kernel identifiers and must be treated as
# an installation secret, not published).
#
# Options:
#   --install-id ID            16..64 chars [a-z0-9-]
#   --salt 64-hex              exactly 32 random bytes, lowercase hex
#   --state-dir PATH           daemon state root (under /var/lib/)
#   --config-dir PATH          install identity root (under /etc/)
#   --core-socket PATH         neutral core IPC socket (under /run/)
#   --scan-socket PATH         user malware scan socket; parent must be
#                              /run/gedefense-scan for the V6.3.0 core jail
#   --bpf-pin-root PATH        neutral bpffs pin root (under /sys/fs/bpf/)
#   --backend-port PORT        1024..65535, loopback dashboard backend
#   --public-port PORT        1024..65535, distinct from --backend-port
#   --unit-prefix PREFIX      3..21 chars [a-z][a-z0-9-]; runtime dir name
#   --admin-audit-path PATH    optional explicit admin mapping audit file
#   --root DIR                 operate below DIR (for staging/tests); default /
#   --allow-foreign-scan-dir   permit a scan socket outside /run/gedefense-scan
#                              (requires a matching core-side jail change)
#   --dry-run                  validate and print, write nothing
#   -h | --help                this help
#
# Exit codes: 0 success/idempotent, 1 validation or write failure.
# =============================================================================
set -Eeuo pipefail
umask 0027

SCRIPT_NAME="${0##*/}"
MANIFEST_SCHEMA="vgt-gedefense-chameleon-v1"
DEFAULT_CORE_SERVICE="gedefense-core.service"
DEFAULT_CONTROL_SERVICE="gedefense-control.service"
DEFAULT_ACCESS_SERVICE="gedefense-access.service"
SCAN_PARENT="/run/gedefense-scan"

ROOT="/"
DRY_RUN=0
ALLOW_FOREIGN_SCAN_DIR=0
INSTALL_ID=""
SALT=""
STATE_DIR=""
CONFIG_DIR=""
CORE_SOCKET=""
SCAN_SOCKET=""
BPF_PIN_ROOT=""
BACKEND_PORT=""
PUBLIC_PORT=""
UNIT_PREFIX=""
ADMIN_AUDIT_PATH=""
MANIFEST_GROUP="gedefense"

log() { printf '[chameleon] %s\n' "$*" >&2; }
fail() { printf '[chameleon] FEHLER: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-id) INSTALL_ID="${2:?--install-id requires a value}"; shift 2 ;;
    --install-id=*) INSTALL_ID="${1#*=}"; shift ;;
    --salt) SALT="${2:?--salt requires a value}"; shift 2 ;;
    --salt=*) SALT="${1#*=}"; shift ;;
    --state-dir) STATE_DIR="${2:?--state-dir requires a value}"; shift 2 ;;
    --state-dir=*) STATE_DIR="${1#*=}"; shift ;;
    --config-dir) CONFIG_DIR="${2:?--config-dir requires a value}"; shift 2 ;;
    --config-dir=*) CONFIG_DIR="${1#*=}"; shift ;;
    --core-socket) CORE_SOCKET="${2:?--core-socket requires a value}"; shift 2 ;;
    --core-socket=*) CORE_SOCKET="${1#*=}"; shift ;;
    --scan-socket) SCAN_SOCKET="${2:?--scan-socket requires a value}"; shift 2 ;;
    --scan-socket=*) SCAN_SOCKET="${1#*=}"; shift ;;
    --bpf-pin-root) BPF_PIN_ROOT="${2:?--bpf-pin-root requires a value}"; shift 2 ;;
    --bpf-pin-root=*) BPF_PIN_ROOT="${1#*=}"; shift ;;
    --backend-port) BACKEND_PORT="${2:?--backend-port requires a value}"; shift 2 ;;
    --backend-port=*) BACKEND_PORT="${1#*=}"; shift ;;
    --public-port) PUBLIC_PORT="${2:?--public-port requires a value}"; shift 2 ;;
    --public-port=*) PUBLIC_PORT="${1#*=}"; shift ;;
    --unit-prefix) UNIT_PREFIX="${2:?--unit-prefix requires a value}"; shift 2 ;;
    --unit-prefix=*) UNIT_PREFIX="${1#*=}"; shift ;;
    --admin-audit-path) ADMIN_AUDIT_PATH="${2:?--admin-audit-path requires a value}"; shift 2 ;;
    --admin-audit-path=*) ADMIN_AUDIT_PATH="${1#*=}"; shift ;;
    --manifest-group) MANIFEST_GROUP="${2:?--manifest-group requires a value}"; shift 2 ;;
    --manifest-group=*) MANIFEST_GROUP="${1#*=}"; shift ;;
    --root) ROOT="${2:?--root requires a value}"; shift 2 ;;
    --root=*) ROOT="${1#*=}"; shift ;;
    --allow-foreign-scan-dir) ALLOW_FOREIGN_SCAN_DIR=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unbekanntes Argument: $1 (--help für Hilfe)" ;;
  esac
done

# --------------------------------------------------------------- validation

valid_install_id() {
  local value="$1"
  [[ ${#value} -ge 16 && ${#value} -le 64 ]] || return 1
  [[ $value =~ ^[a-z0-9][a-z0-9-]*[a-z0-9]$ ]] || return 1
  return 0
}

valid_salt() { [[ $1 =~ ^[0-9a-f]{64}$ ]]; }

valid_port() {
  [[ $1 =~ ^[0-9]+$ ]] || return 1
  local port=$((10#$1))
  [[ $port -ge 1024 && $port -le 65535 ]]
}

valid_unit_prefix() { [[ $1 =~ ^[a-z][a-z0-9-]{2,20}$ ]]; }

# Absolute, normalized, no '..'/'.'/'//', no control characters, not "/".
valid_abs_path() {
  local value="$1"
  [[ -n $value && ${#value} -le 200 ]] || return 1
  [[ $value == /* ]] || return 1
  [[ $value != "/" ]] || return 1
  [[ $value != *"//"* ]] || return 1
  [[ $value != */ ]] || return 1
  [[ $value != *"/./"* && $value != */.. && $value != *"/../"* && $value != *"/../"* ]] || return 1
  [[ $value != *..* ]] || return 1
  # Control characters are rejected explicitly because they would corrupt the
  # key=value manifest and the generated unit drop-in.
  local LC_ALL=C
  [[ $value != *[[:cntrl:]]* ]] || return 1
  return 0
}

path_under() { [[ $1 == "$2"/* ]]; }

target_path() {
  # Maps a logical target path to the staging root (--root). ROOT is normalized
  # below to "" (real root) or "/abs/path" (no trailing slash).
  if [[ $ROOT == "/" ]]; then
    printf '%s' "$1"
  else
    printf '%s%s' "$ROOT" "$1"
  fi
}

normalize_root() {
  [[ -n $ROOT ]] || fail "--root must not be empty"
  [[ $ROOT == /* ]] || fail "--root must be absolute"
  while [[ $ROOT == */ && $ROOT != "/" ]]; do ROOT="${ROOT%/}"; done
  [[ $ROOT == "/" || -d $ROOT ]] || fail "--root $ROOT is not a directory"
}

# ------------------------------------------------------------------- checks

normalize_root

[[ -n $INSTALL_ID ]] || fail "--install-id is required"
valid_install_id "$INSTALL_ID" || fail "--install-id must be 16..64 chars [a-z0-9-] (no leading/trailing '-')"
[[ -n $STATE_DIR ]] || fail "--state-dir is required"
valid_abs_path "$STATE_DIR" || fail "--state-dir must be an absolute normalized path"
path_under "$STATE_DIR" "/var/lib" || fail "--state-dir must live below /var/lib"
[[ -n $CONFIG_DIR ]] || fail "--config-dir is required"
valid_abs_path "$CONFIG_DIR" || fail "--config-dir must be an absolute normalized path"
path_under "$CONFIG_DIR" "/etc" || fail "--config-dir must live below /etc"
[[ -n $CORE_SOCKET ]] || fail "--core-socket is required"
valid_abs_path "$CORE_SOCKET" || fail "--core-socket must be an absolute normalized path"
path_under "$CORE_SOCKET" "/run" || fail "--core-socket must live below /run"
[[ -n $SCAN_SOCKET ]] || fail "--scan-socket is required"
valid_abs_path "$SCAN_SOCKET" || fail "--scan-socket must be an absolute normalized path"
path_under "$SCAN_SOCKET" "/run" || fail "--scan-socket must live below /run"
if [[ $(dirname "$SCAN_SOCKET") != "$SCAN_PARENT" && $ALLOW_FOREIGN_SCAN_DIR -ne 1 ]]; then
  fail "--scan-socket parent must be $SCAN_PARENT (the V6.3.0 core runtime jail); pass --allow-foreign-scan-dir only together with a matching core-side change"
fi
[[ -n $BPF_PIN_ROOT ]] || fail "--bpf-pin-root is required"
valid_abs_path "$BPF_PIN_ROOT" || fail "--bpf-pin-root must be an absolute normalized path"
path_under "$BPF_PIN_ROOT" "/sys/fs/bpf" || fail "--bpf-pin-root must live below /sys/fs/bpf"
[[ $BPF_PIN_ROOT != "/sys/fs/bpf" ]] || fail "--bpf-pin-root must be a subdirectory of the bpffs mount"
[[ -n $BACKEND_PORT ]] || fail "--backend-port is required"
valid_port "$BACKEND_PORT" || fail "--backend-port must be 1024..65535"
[[ -n $PUBLIC_PORT ]] || fail "--public-port is required"
valid_port "$PUBLIC_PORT" || fail "--public-port must be 1024..65535"
[[ $BACKEND_PORT != "$PUBLIC_PORT" ]] || fail "--backend-port and --public-port must differ"
[[ -n $UNIT_PREFIX ]] || fail "--unit-prefix is required"
valid_unit_prefix "$UNIT_PREFIX" || fail "--unit-prefix must match ^[a-z][a-z0-9-]{2,20}$"
[[ $CORE_SOCKET != "$SCAN_SOCKET" ]] || fail "--core-socket and --scan-socket must differ"
[[ $STATE_DIR != "$CONFIG_DIR" ]] || fail "--state-dir and --config-dir must differ"
[[ $MANIFEST_GROUP =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail "--manifest-group is not a valid group name"
if [[ -n $ADMIN_AUDIT_PATH ]]; then
  valid_abs_path "$ADMIN_AUDIT_PATH" || fail "--admin-audit-path must be an absolute normalized path"
fi

if [[ -z $SALT ]]; then
  [[ -r /dev/urandom ]] || fail "/dev/urandom is required to generate the install salt"
  SALT=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
fi
valid_salt "$SALT" || fail "--salt must be exactly 64 lowercase hex characters (32 random bytes)"

if [[ $DRY_RUN -ne 1 && $ROOT == "/" && $EUID -ne 0 ]]; then
  fail "must run as root (or use --root for staging/tests and --dry-run)"
fi
# The manifest is read by the unprivileged control plane. The literal spec value
# root:root 0640 would make that read impossible, so the default group is the
# platform service group; no other account may read the installation salt.
MANIFEST_PATH="${CONFIG_DIR}/${INSTALL_ID}.conf"
RUNTIME_DIR="/run/${UNIT_PREFIX}-run"

# ------------------------------------------------------------- file writers

write_file() {
  # write_file <logical-path> <mode> <content> [group]
  local logical="$1" mode="$2" content="$3" group="${4:-root}"
  local target
  target="$(target_path "$logical")"
  local parent
  parent="$(dirname "$target")"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "dry-run: would write $logical ($mode)"
    return 0
  fi
  mkdir -p -- "$parent"
  if [[ -f $target && ! -L $target ]] && [[ "$(cat -- "$target")" == "$content" ]]; then
    log "unchanged: $logical"
    return 0
  fi
  local temp="${target}.tmp.$$"
  ( umask 0077; printf '%s' "$content" >"$temp" )
  if [[ $EUID -eq 0 ]]; then
    chown "root:${group}" "$temp" 2>/dev/null || chown root:root "$temp"
    chmod "0${mode}" "$temp"
  else
    # Staging/test mode (non-root): the target account owns the file; strip every
    # group/world bit so a staging tree can never leak the installation salt.
    local mode_num=$((8#$mode))
    chmod "$(printf '%o' "$((mode_num & 0700))")" "$temp" 2>/dev/null || chmod 600 "$temp"
  fi
  mv -f -- "$temp" "$target"
  log "wrote: $logical ($mode root:${group})"
}

write_manifest() {
  local logical="$1" content="$2"
  write_file "$logical" 640 "$content" "$MANIFEST_GROUP"
}

ensure_dir() {
  # ensure_dir <logical-path> <mode> [group]
  local logical="$1" mode="$2" group="${3:-root}"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "dry-run: would create directory $logical ($mode)"
    return 0
  fi
  local target
  target="$(target_path "$logical")"
  if [[ -d $target ]]; then
    return 0
  fi
  mkdir -p -- "$target"
  if [[ $EUID -eq 0 ]]; then
    chown "root:${group}" "$target"
    chmod "0${mode}" "$target"
  fi
  log "created directory: $logical ($mode)"
}

# ------------------------------------------------------ unit discovery/render

unit_candidates() {
  local service="$1"
  printf '%s\n' \
    "$(target_path "/etc/systemd/system/$service")" \
    "$(target_path "/usr/lib/systemd/system/$service")" \
    "$(cd -- "$(dirname -- "$0")" && pwd)/../packaging/systemd/$service"
}

discover_unit() {
  local service="$1" candidate
  while IFS= read -r candidate; do
    if [[ -f $candidate && ! -L $candidate ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done < <(unit_candidates "$service")
  return 1
}

exec_start_of() {
  local unit="$1" line
  line=$(grep -m1 '^ExecStart=' -- "$unit" || true)
  [[ -n $line ]] || return 1
  printf '%s' "${line#ExecStart=}"
}

# Builds a neutral ExecStart line by dropping the identity-bearing flags from the
# packaged ExecStart and appending the manifest-owned values last. The core's
# `arg()` helper takes the FIRST occurrence of a flag, so the old values must be
# removed rather than appended after.
render_core_exec_start() {
  local unit="$1" original word
  original=$(exec_start_of "$unit") || return 1
  local -a words filtered
  read -r -a words <<<"$original"
  [[ ${#words[@]} -ge 1 ]] || return 1
  filtered=()
  for word in "${words[@]:1}"; do
    case "$word" in
      --socket=*|--scan-socket=*|--bpf-pin-root=*|--chameleon-manifest=*) continue ;;
    esac
    filtered+=("$word")
  done
  local rendered="ExecStart=${words[0]}"
  for word in "${filtered[@]}"; do rendered+=" ${word}"; done
  rendered+=" --chameleon-manifest=${MANIFEST_PATH} --bpf-pin-root=${BPF_PIN_ROOT}"
  rendered+=" --socket=${CORE_SOCKET} --scan-socket=${SCAN_SOCKET}"
  printf '%s' "$rendered"
}

render_scoped_exec_start() {
  # render_scoped_exec_start <unit> <extra-flag>
  local unit="$1" extra="$2" original word
  original=$(exec_start_of "$unit") || return 1
  local -a words filtered
  read -r -a words <<<"$original"
  [[ ${#words[@]} -ge 1 ]] || return 1
  filtered=()
  for word in "${words[@]:1}"; do
    case "$word" in
      --chameleon-manifest=*) continue ;;
    esac
    filtered+=("$word")
  done
  local rendered="ExecStart=${words[0]}"
  for word in "${filtered[@]}"; do rendered+=" ${word}"; done
  rendered+=" ${extra}"
  printf '%s' "$rendered"
}

render_access_exec_start() {
  local unit="$1" original word
  original=$(exec_start_of "$unit") || return 1
  local -a words rewritten
  read -r -a words <<<"$original"
  [[ ${#words[@]} -ge 1 ]] || return 1
  rewritten=("${words[0]}")
  for word in "${words[@]:1}"; do
    case "$word" in
      --listen=*)
        local host="${word#--listen=}"
        host="${host%:*}"
        rewritten+=("--listen=${host}:${PUBLIC_PORT}")
        ;;
      --backend=*) rewritten+=("--backend=http://127.0.0.1:${BACKEND_PORT}") ;;
      *) rewritten+=("$word") ;;
    esac
  done
  local rendered="ExecStart=${rewritten[0]}"
  for word in "${rewritten[@]:1}"; do rendered+=" ${word}"; done
  printf '%s' "$rendered"
}

# ------------------------------------------------------------------- payload

manifest_content() {
  printf '%s\n' "$MANIFEST_SCHEMA"
  printf 'install_id=%s\n' "$INSTALL_ID"
  printf 'bpf_name_salt=%s\n' "$SALT"
  printf 'core_socket=%s\n' "$CORE_SOCKET"
  printf 'scan_socket=%s\n' "$SCAN_SOCKET"
  printf 'bpf_pin_root=%s\n' "$BPF_PIN_ROOT"
  printf 'state_dir=%s\n' "$STATE_DIR"
  printf 'config_dir=%s\n' "$CONFIG_DIR"
  printf 'public_port=%s\n' "$PUBLIC_PORT"
  printf 'backend_port=%s\n' "$BACKEND_PORT"
  printf 'neutral_unit_prefix=%s\n' "$UNIT_PREFIX"
  if [[ -n $ADMIN_AUDIT_PATH ]]; then
    printf 'admin_audit_path=%s\n' "$ADMIN_AUDIT_PATH"
  fi
}

write_dropins() {
  local core_unit control_unit access_unit core_exec control_exec access_exec
  core_unit=$(discover_unit "$DEFAULT_CORE_SERVICE") ||
    fail "cannot find ${DEFAULT_CORE_SERVICE} to derive the neutral ExecStart"
  control_unit=$(discover_unit "$DEFAULT_CONTROL_SERVICE") ||
    fail "cannot find ${DEFAULT_CONTROL_SERVICE} to derive the neutral ExecStart"
  core_exec=$(render_core_exec_start "$core_unit") ||
    fail "cannot derive a neutral ExecStart from $core_unit"
  control_exec=$(render_scoped_exec_start "$control_unit" "--chameleon-manifest=${MANIFEST_PATH}") ||
    fail "cannot derive a neutral ExecStart from $control_unit"

  local core_dropin
  core_dropin="# V6.3.0 AP-8 Chameleon install profile (generated by ${SCRIPT_NAME})
# Do not edit by hand: re-run the installer helper to regenerate.
[Service]
# Neutral runtime directory for the installation-specific core socket.
RuntimeDirectory=
RuntimeDirectory=${UNIT_PREFIX}-run
RuntimeDirectoryMode=0750
ExecStart=
${core_exec}
# Exact write grants for the opt-in profile: the core writes the admin mapping
# audit under the neutral state root and binds its socket in the neutral runtime
# directory. No other sandbox directive is relaxed.
ReadWritePaths=${STATE_DIR} ${RUNTIME_DIR} ${SCAN_PARENT}
"
  write_file "/etc/systemd/system/${DEFAULT_CORE_SERVICE}.d/10-chameleon.conf" 644 "$core_dropin" root

  local control_dropin
  control_dropin="# V6.3.0 AP-8 Chameleon install profile (generated by ${SCRIPT_NAME})
# The unprivileged control plane reads the same root-owned manifest and applies
# the installation-specific core socket/ports/state roots at startup.
[Service]
ExecStart=
${control_exec}
ReadWritePaths=${STATE_DIR}
ReadOnlyPaths=${CONFIG_DIR}
"
  write_file "/etc/systemd/system/${DEFAULT_CONTROL_SERVICE}.d/10-chameleon.conf" 644 "$control_dropin" root

  if access_unit=$(discover_unit "$DEFAULT_ACCESS_SERVICE"); then
    access_exec=$(render_access_exec_start "$access_unit") ||
      fail "cannot derive a neutral ExecStart from $access_unit"
    local access_dropin
    access_dropin="# V6.3.0 AP-8 Chameleon install profile (generated by ${SCRIPT_NAME})
# The HTTPS gateway keeps its own account, sandbox and TLS handling; only the
# loopback backend port and the public listen port become installation-specific.
[Service]
ExecStart=
${access_exec}
"
    write_file "/etc/systemd/system/${DEFAULT_ACCESS_SERVICE}.d/10-chameleon.conf" 644 "$access_dropin" root
  else
    log "warning: ${DEFAULT_ACCESS_SERVICE} not found; gateway ports keep the packaged defaults"
  fi

  local tmpfiles
  tmpfiles="# V6.3.0 AP-8 Chameleon install profile (generated by ${SCRIPT_NAME})
# Neutral runtime/state/config roots. Ownership follows the platform service
# group; no login account is a member of it.
d ${RUNTIME_DIR} 0750 root gedefense -
d ${STATE_DIR} 0770 root gedefense -
d ${CONFIG_DIR} 0750 root gedefense -
d ${SCAN_PARENT} 0750 root gedefense -
"
  write_file "/etc/tmpfiles.d/10-chameleon-neutral.conf" 644 "$tmpfiles" root
}

# --------------------------------------------------------------------- main

log "install-id=${INSTALL_ID} unit-prefix=${UNIT_PREFIX} root=${ROOT} dry-run=${DRY_RUN}"
ensure_dir "$STATE_DIR" 770 gedefense
ensure_dir "$CONFIG_DIR" 750 gedefense
ensure_dir "$RUNTIME_DIR" 750 gedefense
ensure_dir "$SCAN_PARENT" 750 gedefense
if [[ -n $ADMIN_AUDIT_PATH ]]; then
  ensure_dir "$(dirname "$ADMIN_AUDIT_PATH")" 750 gedefense
fi
write_manifest "$MANIFEST_PATH" "$(manifest_content)
"
write_dropins

if [[ $DRY_RUN -ne 1 ]]; then
  if command -v systemd-tmpfiles >/dev/null 2>&1 && [[ $ROOT == "/" ]]; then
    systemd-tmpfiles --create "/etc/tmpfiles.d/10-chameleon-neutral.conf" ||
      fail "systemd-tmpfiles could not apply the neutral runtime/state roots"
  fi
  if command -v systemctl >/dev/null 2>&1 && [[ $ROOT == "/" ]]; then
    systemctl daemon-reload || fail "systemctl daemon-reload failed"
  fi
  # The manifest must be readable by the unprivileged control plane but not by
  # any other local account. Verify what was actually written.
  target_manifest="$(target_path "$MANIFEST_PATH")"
  [[ -f $target_manifest && ! -L $target_manifest ]] ||
    fail "manifest was not written as a regular file: $target_manifest"
  if [[ $EUID -eq 0 ]]; then
    [[ $(stat -c '%U:%G:%a' "$target_manifest") == "root:${MANIFEST_GROUP}:640" ]] ||
      fail "manifest ownership/mode is not root:${MANIFEST_GROUP}:640"
  fi
fi

cat >&2 <<SUMMARY

Chameleon install profile applied successfully.
  manifest:            ${MANIFEST_PATH} (0640 root:${MANIFEST_GROUP})
  neutral core socket: ${CORE_SOCKET}
  neutral scan socket: ${SCAN_SOCKET}
  neutral bpffs root:  ${BPF_PIN_ROOT}
  loopback backend:    127.0.0.1:${BACKEND_PORT} (public ${PUBLIC_PORT})
  daemon state root:   ${STATE_DIR}
  install identity:    ${CONFIG_DIR}
  admin mapping audit: ${ADMIN_AUDIT_PATH:-${STATE_DIR}/chameleon-map.audit}

Informational service alias: ${UNIT_PREFIX}-core (${UNIT_PREFIX}-control)
  Full neutral systemd unit *renaming* is not performed by this helper: copying
  units under neutral names in addition to the packaged ones can double-start a
  service. It remains an installer-level unit-generation task (see
  docs/V6.3.0-CHAMELEON.md, "Residual limits").
SUMMARY
