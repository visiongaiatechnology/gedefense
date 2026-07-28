#!/usr/bin/env bash
# VGT GeDefense 1.0.0-beta.5 Full-Stack One-Click Installer
set -Eeuo pipefail
umask 0077

readonly SETUP_VERSION="3.5.1"
readonly PRODUCT_VERSION="1.0.0-beta.5"
readonly PAYLOAD_SHA256="__PAYLOAD_SHA256__"
readonly CONTROL_SHA256="__CONTROL_SHA256__"
readonly ACCESS_SHA256="__ACCESS_SHA256__"
readonly RUST_STABLE_TOOLCHAIN="1.97.1"
readonly RUST_NIGHTLY_TOOLCHAIN="nightly-2026-07-16"
readonly BPF_LINKER_VERSION="0.10.3"
readonly BASE="/opt/vgt/gedefense"
readonly RELEASES="${BASE}/releases"
readonly RELEASE="${RELEASES}/${PRODUCT_VERSION}"
readonly CURRENT="${BASE}/current"
readonly PREVIOUS="${BASE}/previous"
readonly STATE="/var/lib/vgt/gedefense"
readonly QUARANTINE_DIR="${STATE}/quarantine"
readonly QUARANTINE_OBJECT_DIR="${QUARANTINE_DIR}/objects"
readonly CONFIG_DIR="/etc/vgt/gedefense"
readonly CONFIG_FILE="${CONFIG_DIR}/gedefense.toml"
readonly BASELINE_FILE="${CONFIG_DIR}/xdr-baseline.json"
readonly PASSWORD_FILE="${CONFIG_DIR}/access-password"
readonly TLS_DIR="${CONFIG_DIR}/tls"
readonly SECRETS_DIR="${CONFIG_DIR}/secrets"
readonly CERT_FILE="${TLS_DIR}/access.crt"
readonly TLS_KEY_FILE="${TLS_DIR}/access.key"
readonly TOKEN_FILE="${STATE}/dashboard.token"
readonly CORE_KEY_FILE="${SECRETS_DIR}/core-ipc.key"
readonly STORAGE_KEY_FILE="${SECRETS_DIR}/storage-master.key"
readonly XDR_KEY_FILE="${STATE}/xdr-log.key"
readonly RUNTIME_KEY_FILE="${STATE}/runtime-settings.key"
readonly SESSION_KEY_FILE="${STATE}/access-session.key"
readonly POLICY_STATE_FILE="${STATE}/policy.json"
readonly POLICY_PRIVATE_KEY_FILE="${STATE}/policy.ed25519"
readonly POLICY_PUBLIC_KEY_FILE="${STATE}/policy.ed25519.pub"
readonly INCIDENT_LOG_FILE="${STATE}/incidents.jsonl"
readonly INCIDENT_HEAD_FILE="${STATE}/incidents.jsonl.head"
readonly BEHAVIOR_FILE="${STATE}/behavior-profiles.json"
readonly RUNTIME_SETTINGS_FILE="${STATE}/runtime-settings.json"
readonly PUBLIC_PORT_DEFAULT="9843"
readonly BACKEND_PORT="9844"
readonly LOG_FILE="/var/log/vgt-gedefense-install.log"
readonly SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"

WORK=""
PAYLOAD=""
BUILD_ROOT=""
ACTIVATING=0
BACKUP_DIR=""
OLD_CURRENT=""
OLD_OBSERVE_ACTIVE=0
OLD_ACCESS_ACTIVE=0
OLD_CORE_ACTIVE=0
OLD_CONTROL_ACTIVE=0
OLD_BPFFS_ACTIVE=0
OLD_PREVIOUS=""
ARCHIVED_RELEASE=""
NEW_RELEASE_STAGED=0
OLD_STATE_LATCH=0
OLD_CONFIG_LATCH=0
PUBLIC_HOST=""
PUBLIC_PORT="${PUBLIC_PORT_DEFAULT}"
INTERFACE=""
MANAGEMENT_ALLOWLIST=""

log(){ printf '[%s] %s\n' "$(date -Is 2>/dev/null || date)" "$*" | tee -a "$LOG_FILE"; }
have(){ command -v "$1" >/dev/null 2>&1; }
cleanup(){ [[ -n ${WORK:-} && -d ${WORK:-} ]] && rm -rf -- "$WORK" || true; }

backup_path(){
  local source=$1 name=$2
  if [[ -e $source || -L $source ]]; then
    cp -a -- "$source" "$BACKUP_DIR/$name"
  else
    : > "$BACKUP_DIR/${name}.absent"
  fi
}

restore_backup_path(){
  local target=$1 name=$2 parent
  rm -rf -- "$target"
  if [[ -e "$BACKUP_DIR/$name" || -L "$BACKUP_DIR/$name" ]]; then
    parent=$(dirname "$target")
    if [[ ! -d $parent ]]; then
      case "$target" in
        "$STATE"/*) install -d -m 0700 -o gedefense -g gedefense "$parent" ;;
        *) install -d -m 0750 -o root -g gedefense "$parent" ;;
      esac
    fi
    cp -a -- "$BACKUP_DIR/$name" "$target"
  fi
}

rollback(){
  local rc=${1:-$?}
  trap - ERR
  if (( ACTIVATING == 1 )); then
    set +e
    log "Aktivierung fehlgeschlagen. Automatischer Rollback beginnt."
    systemctl stop gedefense-access.service gedefense-control.service gedefense-core.service 2>/dev/null || true

    for unit in gedefense-bpffs.service gedefense-core.service gedefense-control.service gedefense-access.service; do
      rm -rf -- "/etc/systemd/system/${unit}.d"
      if [[ -f "$BACKUP_DIR/$unit" ]]; then
        cp -f -- "$BACKUP_DIR/$unit" "/etc/systemd/system/$unit"
      else
        rm -f -- "/etc/systemd/system/$unit"
      fi
      if [[ -d "$BACKUP_DIR/${unit}.d" ]]; then
        cp -a -- "$BACKUP_DIR/${unit}.d" "/etc/systemd/system/${unit}.d"
      fi
    done

    rm -f -- "$CURRENT" "$PREVIOUS"
    if (( NEW_RELEASE_STAGED == 1 )); then
      rm -rf -- "$RELEASE"
    fi
    if [[ -n $OLD_CURRENT ]]; then ln -s -- "$OLD_CURRENT" "$CURRENT"; fi
    if [[ -n $OLD_PREVIOUS ]]; then ln -s -- "$OLD_PREVIOUS" "$PREVIOUS"; fi

    restore_backup_path "$CONFIG_FILE" config.toml
    restore_backup_path "$BASELINE_FILE" xdr-baseline.json
    restore_backup_path "$CERT_FILE" access.crt
    restore_backup_path "$TLS_KEY_FILE" access.key
    restore_backup_path "$CORE_KEY_FILE" core-ipc.key
    restore_backup_path "$STORAGE_KEY_FILE" storage-master.key
    restore_backup_path "$PASSWORD_FILE" access-password
    restore_backup_path "$TOKEN_FILE" dashboard.token
    restore_backup_path "$XDR_KEY_FILE" xdr-log.key
    restore_backup_path "$RUNTIME_KEY_FILE" runtime-settings.key
    restore_backup_path "$SESSION_KEY_FILE" access-session.key
    restore_backup_path "$POLICY_STATE_FILE" policy.json
    restore_backup_path "$POLICY_PRIVATE_KEY_FILE" policy.ed25519
    restore_backup_path "$POLICY_PUBLIC_KEY_FILE" policy.ed25519.pub
    restore_backup_path "$INCIDENT_LOG_FILE" incidents.jsonl
    restore_backup_path "$INCIDENT_HEAD_FILE" incidents.jsonl.head
    restore_backup_path "$BEHAVIOR_FILE" behavior-profiles.json
    restore_backup_path "$RUNTIME_SETTINGS_FILE" runtime-settings.json

    if (( OLD_STATE_LATCH == 1 )) && [[ -f "$BACKUP_DIR/EMERGENCY_STOP.state" ]]; then
      install -o gedefense -g gedefense -m 0600 "$BACKUP_DIR/EMERGENCY_STOP.state" "$STATE/EMERGENCY_STOP"
    fi
    if (( OLD_CONFIG_LATCH == 1 )) && [[ -f "$BACKUP_DIR/EMERGENCY_STOP.config" ]]; then
      install -o root -g gedefense -m 0640 "$BACKUP_DIR/EMERGENCY_STOP.config" "$CONFIG_DIR/EMERGENCY_STOP"
    fi

    systemctl daemon-reload || true
    (( OLD_BPFFS_ACTIVE == 1 )) && systemctl start gedefense-bpffs.service 2>/dev/null || true
    (( OLD_CORE_ACTIVE == 1 )) && systemctl start gedefense-core.service 2>/dev/null || true
    (( OLD_CONTROL_ACTIVE == 1 )) && systemctl start gedefense-control.service 2>/dev/null || true
    (( OLD_OBSERVE_ACTIVE == 1 )) && systemctl start gedefense-observe.service 2>/dev/null || true
    (( OLD_ACCESS_ACTIVE == 1 )) && systemctl start gedefense-access.service 2>/dev/null || true
    log "Rollback abgeschlossen. Details: $LOG_FILE"
    set -e
  fi
  cleanup
  exit "$rc"
}
fail(){ log "FEHLER: $*"; rollback 1; }
trap 'rollback $?' ERR
trap cleanup EXIT

[[ ${EUID} -eq 0 ]] || fail "Bitte als root ausführen."
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 0600 "$LOG_FILE"

platform_check(){
  [[ $(uname -s) == Linux ]] || fail "Nur Linux wird unterstützt."
  [[ $(uname -m) == x86_64 || $(uname -m) == amd64 ]] || fail "Diese Beta unterstützt x86_64."
  have systemctl || fail "systemctl fehlt."
  [[ -d /run/systemd/system ]] || fail "systemd ist nicht das aktive Init-System."
  [[ -r /proc/net/route ]] || fail "/proc ist nicht vollständig verfügbar."
}

install_build_dependencies(){
  log "Prüfe Build- und BPF-Werkzeuge."
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >>"$LOG_FILE" 2>&1
    apt-get install -y ca-certificates curl build-essential pkg-config clang llvm libelf-dev zlib1g-dev libargon2-1 git python3 iproute2 coreutils tar gzip openssl >>"$LOG_FILE" 2>&1
  elif have dnf; then
    dnf install -y ca-certificates curl gcc gcc-c++ make pkgconf-pkg-config clang llvm elfutils-libelf-devel zlib-devel libargon2 git python3 iproute coreutils tar gzip openssl >>"$LOG_FILE" 2>&1
  elif have yum; then
    yum install -y ca-certificates curl gcc gcc-c++ make pkgconfig clang llvm elfutils-libelf-devel zlib-devel libargon2 git python3 iproute coreutils tar gzip openssl >>"$LOG_FILE" 2>&1
  else
    fail "Kein unterstützter Paketmanager gefunden."
  fi
  for cmd in curl python3 tar sha256sum ip clang systemctl systemd-analyze; do have "$cmd" || fail "Werkzeug fehlt: $cmd"; done
}

extract_payload(){
  WORK=$(mktemp -d /var/tmp/vgt-gedefense-beta1.XXXXXX)
  local line archive actual
  line=$(awk '/^__VGT_PAYLOAD_BELOW__$/{print NR+1; exit}' "$SELF")
  [[ $line =~ ^[0-9]+$ ]] || fail "Payload-Marker fehlt."
  archive="$WORK/payload.tar.gz"
  tail -n +"$line" "$SELF" > "$archive"
  actual=$(sha256sum "$archive" | awk '{print $1}')
  [[ $actual == "$PAYLOAD_SHA256" ]] || fail "Payload-Prüfsumme stimmt nicht."
  mkdir "$WORK/payload"
  python3 - "$archive" "$WORK/payload" <<'PY'
import pathlib, sys, tarfile
archive, dst = sys.argv[1:]
root = pathlib.Path(dst).resolve()
with tarfile.open(archive, 'r:gz') as tf:
    for member in tf.getmembers():
        p = pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or member.issym() or member.islnk() or member.isdev():
            raise SystemExit('unsafe payload member')
        target = (root / pathlib.Path(*p.parts)).resolve()
        if target != root and root not in target.parents:
            raise SystemExit('payload path escape')
    tf.extractall(root)
PY
  PAYLOAD="$WORK/payload"
  [[ $(sha256sum "$PAYLOAD/bin/gedefense-control" | awk '{print $1}') == "$CONTROL_SHA256" ]] || fail "Control-Binary ist beschädigt."
  [[ $(sha256sum "$PAYLOAD/bin/gedefense-access" | awk '{print $1}') == "$ACCESS_SHA256" ]] || fail "Gateway-Binary ist beschädigt."
  ldd "$PAYLOAD/bin/gedefense-access" 2>/dev/null | grep -q 'libargon2.so.1' || fail "Gateway benötigt libargon2.so.1."
  ! ldd "$PAYLOAD/bin/gedefense-access" 2>/dev/null | grep -q 'not found' || fail "Gateway-Runtimebibliothek fehlt."
  chmod 0755 "$PAYLOAD/bin/gedefense-control" "$PAYLOAD/bin/gedefense-access"
  [[ $("$PAYLOAD/bin/gedefense-control" --version) == "$PRODUCT_VERSION" ]] || fail "Control-Version ist falsch."
  [[ $("$PAYLOAD/bin/gedefense-access" --version) == "${PRODUCT_VERSION}-access" ]] || fail "Gateway-Version ist falsch."
}

detect_interface(){
  local iface
  iface=$(ip -4 route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
  [[ -n $iface ]] || iface=$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | grep -v '^lo$' | head -n1 || true)
  [[ -n $iface && -d /sys/class/net/$iface ]] || fail "Aktives Netzwerkinterface konnte nicht erkannt werden."
  INTERFACE=$iface
}

existing_exec(){ systemctl show gedefense-access.service -p ExecStart --value 2>/dev/null || true; }

collect_access_settings(){
  local exec_line existing default_host answer existing_allow
  exec_line=$(existing_exec)
  existing=$(printf '%s\n' "$exec_line" | sed -n 's/.*--public-host=\([^ ;}]*\).*/\1/p' | head -n1)
  if [[ $existing =~ ^(.+):([0-9]+)$ ]]; then
    default_host=${BASH_REMATCH[1]}
    PUBLIC_PORT=${BASH_REMATCH[2]}
  else
    default_host=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')
  fi
  PUBLIC_PORT=${PUBLIC_PORT:-$PUBLIC_PORT_DEFAULT}
  if [[ -t 0 ]]; then
    if [[ -n $default_host ]]; then
      read -r -p "Öffentliche IP oder Domain (Enter = vorhandenen/erkannten Wert übernehmen): " answer
    else
      read -r -p "Öffentliche IP oder Domain: " answer
    fi
    PUBLIC_HOST=${answer:-$default_host}
    read -r -p "HTTPS-Port [$PUBLIC_PORT]: " answer
    PUBLIC_PORT=${answer:-$PUBLIC_PORT}
  else
    PUBLIC_HOST=$default_host
  fi
  [[ -n $PUBLIC_HOST ]] || fail "Öffentlicher Host fehlt."
  [[ $PUBLIC_PORT =~ ^[0-9]+$ ]] && (( PUBLIC_PORT >= 1024 && PUBLIC_PORT <= 65535 )) || fail "Ungültiger Port."
  python3 - "$PUBLIC_HOST" <<'PY' || fail "Ungültige öffentliche IP/Domain."
import ipaddress, re, sys
value=sys.argv[1].strip().strip('[]')
try:
    ip=ipaddress.ip_address(value)
    assert ip.version == 4 and not ip.is_unspecified and not ip.is_multicast
except ValueError:
    assert len(value) <= 253 and re.fullmatch(r'(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value)
PY
  existing_allow=""
  [[ -r $CONFIG_FILE ]] && existing_allow=$(awk -F= '/^[[:space:]]*allowlist[[:space:]]*=/{gsub(/["[:space:]]/,"",$2);print $2;exit}' "$CONFIG_FILE" || true)
  if [[ -z $existing_allow && -n ${SSH_CLIENT:-} ]]; then existing_allow="${SSH_CLIENT%% *}/32"; fi
  if [[ -t 0 ]]; then
    if [[ -n $existing_allow ]]; then
      read -r -p "Management-IP/CIDR (Enter = vorhandenen/SSH-Wert übernehmen): " answer
    else
      read -r -p "Management-IP/CIDR (leer = später im Dashboard setzen): " answer
    fi
    MANAGEMENT_ALLOWLIST=${answer:-$existing_allow}
  else
    MANAGEMENT_ALLOWLIST=$existing_allow
  fi
  if [[ -n $MANAGEMENT_ALLOWLIST ]]; then
    MANAGEMENT_ALLOWLIST=$(python3 - "$MANAGEMENT_ALLOWLIST" <<'PY'
import ipaddress, sys
out=[]
for raw in sys.argv[1].split(','):
    raw=raw.strip()
    if not raw: continue
    if '/' not in raw:
        ip=ipaddress.ip_address(raw); raw=f'{ip}/{32 if ip.version==4 else 128}'
    net=ipaddress.ip_network(raw, strict=False)
    if net.is_unspecified: raise SystemExit('unspecified management network')
    value=str(net)
    if value not in out: out.append(value)
print(','.join(out))
PY
    ) || fail "Management-Allowlist ist ungültig."
  fi
}

valid_password_record(){
  [[ -f $PASSWORD_FILE && ! -L $PASSWORD_FILE ]] || return 1
  grep -Eq '^(v1\$pbkdf2-sha256\$[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+|v2\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+)$' "$PASSWORD_FILE"
}

create_password_record(){
  local first second tmp
  [[ -t 0 ]] || fail "Bei einer Neuinstallation wird ein interaktives Passwort benötigt."
  while true; do
    read -r -s -p "GeDefense Dashboard-Passwort (mindestens 14 Zeichen): " first; printf '\n'
    read -r -s -p "Passwort wiederholen: " second; printf '\n'
    [[ $first == "$second" ]] || { log "Passwörter stimmen nicht überein."; continue; }
    (( ${#first} >= 14 && ${#first} <= 128 )) || { log "Passwort muss 14 bis 128 Zeichen lang sein."; continue; }
    tmp="${PASSWORD_FILE}.tmp.$$"
    printf '%s\n' "$first" | "$PAYLOAD/bin/gedefense-access" --hash-password-stdin > "$tmp"
    chown gedefense:gedefense "$tmp"; chmod 0600 "$tmp"
    mv -fT -- "$tmp" "$PASSWORD_FILE"
    unset first second
    log "Dashboard-Passwort mit Argon2id (64 MiB, t=3, p=1) gespeichert."
    break
  done
}
ensure_user_and_dirs(){
  getent group gedefense >/dev/null 2>&1 || groupadd --system gedefense
  id gedefense >/dev/null 2>&1 || useradd --system --gid gedefense --home-dir "$STATE" --shell /usr/sbin/nologin gedefense
  install -d -o root -g root -m 0755 /opt /opt/vgt "$BASE" "$RELEASES"
  # The root core deliberately runs without CAP_DAC_OVERRIDE and with
  # Group=gedefense. 0710 lets that group traverse only to the root-owned
  # 0700 quarantine vault while preserving private directory listings.
  install -d -o gedefense -g gedefense -m 0710 "$STATE"
  install -d -o root -g gedefense -m 0700 "$QUARANTINE_DIR" "$QUARANTINE_OBJECT_DIR"
  install -d -o root -g gedefense -m 0750 "$CONFIG_DIR" "$TLS_DIR" "$SECRETS_DIR"
  [[ $(stat -c '%U:%G:%a' "$STATE") == 'gedefense:gedefense:710' ]] ||
    fail "Runtime-State-Rechte konnten nicht sicher gesetzt werden."
  [[ $(stat -c '%U:%G:%a' "$QUARANTINE_DIR") == 'root:gedefense:700' ]] ||
    fail "Quarantäne-Vault-Rechte konnten nicht sicher gesetzt werden."
  [[ $(stat -c '%U:%G:%a' "$QUARANTINE_OBJECT_DIR") == 'root:gedefense:700' ]] ||
    fail "Quarantäne-Objektrechte konnten nicht sicher gesetzt werden."
}

ensure_raw_key(){
  local path=$1 bytes=$2
  if [[ ! -f $path || -L $path || $(stat -c %s "$path" 2>/dev/null || echo 0) -ne $bytes ]]; then
    [[ -e $path ]] && mv -f -- "$path" "${path}.invalid.$(date +%s)" || true
    head -c "$bytes" /dev/urandom > "$path"
  fi
  chown gedefense:gedefense "$path"; chmod 0600 "$path"
}

# Shared only by the root Rust broker and the unprivileged gedefense control
# plane. It lives outside the private 0700 runtime-state directory so both
# sandboxed services can traverse the parent path without DAC-bypass powers.
# Exact root:gedefense 0640 avoids broad CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH.
ensure_core_ipc_key(){
  local path=$CORE_KEY_FILE
  if [[ ! -f $path || -L $path || $(stat -c %s "$path" 2>/dev/null || echo 0) -ne 32 ]]; then
    [[ -e $path ]] && mv -f -- "$path" "${path}.invalid.$(date +%s)" || true
    head -c 32 /dev/urandom > "$path"
  fi
  chown root:gedefense "$path"
  chmod 0640 "$path"
  [[ $(stat -c '%U:%G:%a:%s' "$path") == 'root:gedefense:640:32' ]] || fail "Core-IPC-Schlüsselrechte konnten nicht sicher gesetzt werden."
  log "Core-IPC-Schlüsselprofil: $(stat -c '%U:%G mode=%a bytes=%s' "$path")"
}

ensure_storage_key(){
  local path=$STORAGE_KEY_FILE
  if [[ ! -f $path || -L $path || $(stat -c %s "$path" 2>/dev/null || echo 0) -ne 32 ]]; then
    [[ -e $path ]] && mv -f -- "$path" "${path}.invalid.$(date +%s)" || true
    head -c 32 /dev/urandom > "$path"
  fi
  chown root:gedefense "$path"
  chmod 0640 "$path"
  [[ $(stat -c '%U:%G:%a:%s' "$path") == 'root:gedefense:640:32' ]] || fail "Storage-Master-Key konnte nicht sicher gesetzt werden."
  log "AES-256-GCM Storage-Key: root:gedefense mode=640 bytes=32"
}

ensure_token(){
  if [[ ! -f $TOKEN_FILE || -L $TOKEN_FILE ]] || ! python3 - "$TOKEN_FILE" <<'PY' >/dev/null 2>&1
import base64, pathlib, sys
raw=pathlib.Path(sys.argv[1]).read_text().strip(); pad='='*((4-len(raw)%4)%4)
assert len(base64.urlsafe_b64decode(raw+pad))==32
PY
  then
    python3 - "$TOKEN_FILE" <<'PY'
import base64, pathlib, secrets, sys
pathlib.Path(sys.argv[1]).write_text(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')+'\n')
PY
  fi
  chown gedefense:gedefense "$TOKEN_FILE"; chmod 0600 "$TOKEN_FILE"
}

prepare_secrets(){
  ensure_token
  ensure_core_ipc_key
  ensure_storage_key
  ensure_raw_key "$XDR_KEY_FILE" 32
  ensure_raw_key "$RUNTIME_KEY_FILE" 32
  ensure_raw_key "$SESSION_KEY_FILE" 32
  if valid_password_record; then
    log "Bestehendes Dashboard-Passwort wird übernommen."
  else
    create_password_record
  fi
  chown gedefense:gedefense "$PASSWORD_FILE"; chmod 0600 "$PASSWORD_FILE"
}

install_rust_toolchains(){
  export RUSTUP_HOME=${RUSTUP_HOME:-/root/.rustup}
  export CARGO_HOME=${CARGO_HOME:-/root/.cargo}
  if ! have rustup; then
    log "Installiere minimale Rust-Toolchain."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >>"$LOG_FILE" 2>&1
  fi
  export PATH="$CARGO_HOME/bin:$PATH"
  rustup toolchain install "$RUST_STABLE_TOOLCHAIN" --profile minimal >>"$LOG_FILE" 2>&1
  rustup toolchain install "$RUST_NIGHTLY_TOOLCHAIN" --profile minimal --component rust-src >>"$LOG_FILE" 2>&1
  if ! have bpf-linker || [[ $(bpf-linker --version 2>/dev/null | awk '{print $2}') != "$BPF_LINKER_VERSION" ]]; then
    log "Installiere bpf-linker ${BPF_LINKER_VERSION}."
    cargo +"$RUST_STABLE_TOOLCHAIN" install bpf-linker --version "$BPF_LINKER_VERSION" --locked --force >>"$LOG_FILE" 2>&1
  fi
  rustc +"$RUST_STABLE_TOOLCHAIN" --version | tee -a "$LOG_FILE"
  rustc +"$RUST_NIGHTLY_TOOLCHAIN" --version | tee -a "$LOG_FILE"
  bpf-linker --version | tee -a "$LOG_FILE"
}

build_rust_stack(){
  BUILD_ROOT="$WORK/build"
  mkdir -p "$BUILD_ROOT"
  cp -a -- "$PAYLOAD/rust" "$BUILD_ROOT/rust"
  export RUSTUP_HOME=${RUSTUP_HOME:-/root/.rustup}
  export CARGO_HOME=${CARGO_HOME:-/root/.cargo}
  export PATH="$CARGO_HOME/bin:$PATH"
  log "Kompiliere Rust eBPF/XDP für den Zielkernel. Das kann einige Minuten dauern."
  [[ -f "$BUILD_ROOT/rust/Cargo.lock" ]] || fail "Gepinntes Rust Cargo.lock fehlt."
  cargo +"$RUST_NIGHTLY_TOOLCHAIN" build --locked --manifest-path "$BUILD_ROOT/rust/Cargo.toml" -p gedefense-ebpf --release --target bpfel-unknown-none -Z build-std=core >>"$LOG_FILE" 2>&1
  log "Kompiliere privilegierten Rust Response Broker."
  cargo +"$RUST_STABLE_TOOLCHAIN" test --locked --manifest-path "$BUILD_ROOT/rust/Cargo.toml" -p gedefense-common -p gedefense-core >>"$LOG_FILE" 2>&1
  cargo +"$RUST_STABLE_TOOLCHAIN" build --locked --manifest-path "$BUILD_ROOT/rust/Cargo.toml" -p gedefense-core --release >>"$LOG_FILE" 2>&1
  [[ -s "$BUILD_ROOT/rust/target/bpfel-unknown-none/release/gedefense-ebpf" ]] || fail "eBPF-Artefakt fehlt."
  [[ -x "$BUILD_ROOT/rust/target/release/gedefense-core" ]] || chmod 0755 "$BUILD_ROOT/rust/target/release/gedefense-core"
  [[ $("$BUILD_ROOT/rust/target/release/gedefense-core" --version) == "$PRODUCT_VERSION" ]] || fail "Rust-Core-Version ist falsch."
}

write_config_and_baseline(){
  python3 - "$PAYLOAD/templates/gedefense.toml" "$CONFIG_FILE" "$INTERFACE" "$MANAGEMENT_ALLOWLIST" "$(hostname -s)" <<'PY'
import pathlib, re, sys
template,out,iface,allowlist,hostname=sys.argv[1:]
text=pathlib.Path(template).read_text()
name='VGT-Beta-'+re.sub(r'[^A-Za-z0-9_.-]','-',hostname)[:48]
text=text.replace('name = "VGT-Beta-Node"', f'name = "{name}"')
text=text.replace('interface = "auto"', f'interface = "{iface}"')
text=text.replace('listen = "127.0.0.1:9843"', 'listen = "127.0.0.1:9844"')
text=text.replace('allowlist = ""', f'allowlist = "{allowlist}"')
pathlib.Path(out).write_text(text)
PY
  chown root:gedefense "$CONFIG_FILE"; chmod 0640 "$CONFIG_FILE"
  local control_hash core_hash access_hash
  control_hash=$(sha256sum "$RELEASE/bin/gedefense-control" | awk '{print $1}')
  core_hash=$(sha256sum "$RELEASE/libexec/gedefense-core" | awk '{print $1}')
  access_hash=$(sha256sum "$RELEASE/bin/gedefense-access" | awk '{print $1}')
  python3 - "$BASELINE_FILE" "$control_hash" "$core_hash" "$access_hash" <<'PY'
import json, pathlib, sys
out, control, core, access=sys.argv[1:]
doc={"version":1,"profiles":[
 {"executable":"/opt/vgt/gedefense/current/bin/gedefense-control","sha256":control,"allowed_parents":["/usr/lib/systemd/systemd"],"allow_external_network":True,"allowed_remote_ports":[53,443]},
 {"executable":"/opt/vgt/gedefense/current/libexec/gedefense-core","sha256":core,"allowed_uids":[0],"allowed_parents":["/usr/lib/systemd/systemd"],"allow_external_network":False},
 {"executable":"/opt/vgt/gedefense/current/bin/gedefense-access","sha256":access,"allowed_parents":["/usr/lib/systemd/systemd"],"allow_external_network":True}
]}
pathlib.Path(out).write_text(json.dumps(doc,indent=2)+'\n')
PY
  chown root:gedefense "$BASELINE_FILE"; chmod 0640 "$BASELINE_FILE"
}

stage_release(){
  local staging="${RELEASE}.staging.$$" stamp
  rm -rf -- "$staging"
  install -d -o root -g root -m 0755 "$staging/bin" "$staging/libexec" "$staging/lib/gedefense" "$staging/share"
  install -o root -g root -m 0755 "$PAYLOAD/bin/gedefense-control" "$staging/bin/gedefense-control"
  install -o root -g root -m 0755 "$PAYLOAD/bin/gedefense-access" "$staging/bin/gedefense-access"
  install -o root -g root -m 0755 "$BUILD_ROOT/rust/target/release/gedefense-core" "$staging/libexec/gedefense-core"
  install -o root -g root -m 0644 "$BUILD_ROOT/rust/target/bpfel-unknown-none/release/gedefense-ebpf" "$staging/lib/gedefense/gedefense-ebpf"
  install -o root -g root -m 0644 "$BUILD_ROOT/rust/Cargo.lock" "$staging/share/Cargo.lock"
  install -o root -g root -m 0644 "$PAYLOAD/share/README.md" "$staging/share/README.md"
  printf '%s\n' "$PRODUCT_VERSION" > "$staging/share/VERSION"
  (cd "$staging" && find . -type f -print0 | sort -z | xargs -0 sha256sum > share/SHA256SUMS)
  chmod 0644 "$staging/share/VERSION" "$staging/share/SHA256SUMS"
  find "$staging" -type d -exec chmod 0755 {} +

  if [[ -e $RELEASE || -L $RELEASE ]]; then
    stamp=$(date +%s)
    ARCHIVED_RELEASE="${RELEASE}.preupgrade.${stamp}"
    mv -- "$RELEASE" "$ARCHIVED_RELEASE"
    [[ $OLD_CURRENT == "$RELEASE" ]] && OLD_CURRENT=$ARCHIVED_RELEASE
    [[ $OLD_PREVIOUS == "$RELEASE" ]] && OLD_PREVIOUS=$ARCHIVED_RELEASE
    log "Vorhandenes gleichnamiges Release archiviert: $ARCHIVED_RELEASE"
  fi
  mv -- "$staging" "$RELEASE"
  NEW_RELEASE_STAGED=1
}

generate_tls(){
  if [[ -f $CERT_FILE && -f $TLS_KEY_FILE && ! -L $CERT_FILE && ! -L $TLS_KEY_FILE ]]; then
    log "Bestehendes TLS-Zertifikat wird übernommen."
  else
    rm -f -- "$CERT_FILE" "$TLS_KEY_FILE"
    "$RELEASE/bin/gedefense-access" --generate-self-signed --public-host="${PUBLIC_HOST}:${PUBLIC_PORT}" --tls-cert="$CERT_FILE" --tls-key="$TLS_KEY_FILE"
  fi
  chown root:gedefense "$CERT_FILE"; chmod 0644 "$CERT_FILE"
  chown gedefense:gedefense "$TLS_KEY_FILE"; chmod 0600 "$TLS_KEY_FILE"
}

backup_activation_state(){
  BACKUP_DIR="$WORK/activation-backup"
  mkdir -p "$BACKUP_DIR"
  for unit in gedefense-bpffs.service gedefense-core.service gedefense-control.service gedefense-access.service; do
    [[ -f /etc/systemd/system/$unit ]] && cp -a -- "/etc/systemd/system/$unit" "$BACKUP_DIR/$unit" || true
    [[ -d /etc/systemd/system/${unit}.d ]] && cp -a -- "/etc/systemd/system/${unit}.d" "$BACKUP_DIR/${unit}.d" || true
  done
  [[ -L $CURRENT ]] && OLD_CURRENT=$(readlink -f -- "$CURRENT" 2>/dev/null || readlink "$CURRENT") || true
  [[ -L $PREVIOUS ]] && OLD_PREVIOUS=$(readlink -f -- "$PREVIOUS" 2>/dev/null || readlink "$PREVIOUS") || true
  systemctl is-active --quiet gedefense-observe.service && OLD_OBSERVE_ACTIVE=1 || true
  systemctl is-active --quiet gedefense-access.service && OLD_ACCESS_ACTIVE=1 || true
  systemctl is-active --quiet gedefense-core.service && OLD_CORE_ACTIVE=1 || true
  systemctl is-active --quiet gedefense-control.service && OLD_CONTROL_ACTIVE=1 || true
  systemctl is-active --quiet gedefense-bpffs.service && OLD_BPFFS_ACTIVE=1 || true
  backup_path "$CONFIG_FILE" config.toml
  backup_path "$BASELINE_FILE" xdr-baseline.json
  backup_path "$CERT_FILE" access.crt
  backup_path "$TLS_KEY_FILE" access.key
  backup_path "$CORE_KEY_FILE" core-ipc.key
  backup_path "$STORAGE_KEY_FILE" storage-master.key
  backup_path "$PASSWORD_FILE" access-password
  backup_path "$TOKEN_FILE" dashboard.token
  backup_path "$XDR_KEY_FILE" xdr-log.key
  backup_path "$RUNTIME_KEY_FILE" runtime-settings.key
  backup_path "$SESSION_KEY_FILE" access-session.key
  backup_path "$POLICY_STATE_FILE" policy.json
  backup_path "$POLICY_PRIVATE_KEY_FILE" policy.ed25519
  backup_path "$POLICY_PUBLIC_KEY_FILE" policy.ed25519.pub
  backup_path "$INCIDENT_LOG_FILE" incidents.jsonl
  backup_path "$INCIDENT_HEAD_FILE" incidents.jsonl.head
  backup_path "$BEHAVIOR_FILE" behavior-profiles.json
  backup_path "$RUNTIME_SETTINGS_FILE" runtime-settings.json
  ACTIVATING=1
}

install_units(){
  # Remove stale RC/hotfix drop-ins that could override the full-stack binaries.
  rm -rf -- /etc/systemd/system/gedefense-bpffs.service.d /etc/systemd/system/gedefense-core.service.d /etc/systemd/system/gedefense-control.service.d /etc/systemd/system/gedefense-access.service.d
  install -o root -g root -m 0644 "$PAYLOAD/systemd/gedefense-bpffs.service" /etc/systemd/system/gedefense-bpffs.service
  sed "s#--interface=auto#--interface=${INTERFACE}#" "$PAYLOAD/systemd/gedefense-core.service" > /etc/systemd/system/gedefense-core.service
  install -o root -g root -m 0644 "$PAYLOAD/systemd/gedefense-control.service" /etc/systemd/system/gedefense-control.service
  sed -e "s#@RELEASE@#/opt/vgt/gedefense/current#g" -e "s#@PUBLIC_PORT@#${PUBLIC_PORT}#g" -e "s#@PUBLIC_HOST@#${PUBLIC_HOST}:${PUBLIC_PORT}#g" "$PAYLOAD/systemd/gedefense-access.service.in" > /etc/systemd/system/gedefense-access.service
  chmod 0644 /etc/systemd/system/gedefense-core.service /etc/systemd/system/gedefense-access.service
}

verify_units(){
  log "Validiere systemd-Sandbox und Service-Syntax."
  systemd-analyze verify \
    /etc/systemd/system/gedefense-bpffs.service \
    /etc/systemd/system/gedefense-core.service \
    /etc/systemd/system/gedefense-control.service \
    /etc/systemd/system/gedefense-access.service >>"$LOG_FILE" 2>&1
}

activate_release(){
  archive_old_latch
  systemctl stop gedefense-access.service gedefense-observe.service gedefense-control.service gedefense-core.service 2>/dev/null || true
  rm -f -- "$PREVIOUS"
  if [[ -n $OLD_CURRENT ]]; then ln -s -- "$OLD_CURRENT" "$PREVIOUS"; fi
  rm -f -- "$CURRENT"; ln -s -- "$RELEASE" "$CURRENT"
  install_units
  systemctl daemon-reload
  verify_units
  systemctl reset-failed gedefense-bpffs.service gedefense-core.service gedefense-control.service gedefense-access.service || true
  systemctl enable gedefense-bpffs.service gedefense-core.service gedefense-control.service gedefense-access.service >/dev/null
  systemctl start gedefense-bpffs.service
  systemctl start gedefense-core.service
  for _ in $(seq 1 40); do [[ -S /run/vgt-gedefense/core.sock ]] && break; sleep .5; done
  [[ -S /run/vgt-gedefense/core.sock ]] || { journalctl -u gedefense-core.service -n 100 --no-pager | tee -a "$LOG_FILE"; fail "Rust-Core-Socket wurde nicht erstellt."; }
  if ! systemctl start gedefense-control.service; then
    systemctl --no-pager --full status gedefense-control.service 2>&1 | tee -a "$LOG_FILE" || true
    journalctl -u gedefense-control.service -n 160 --no-pager 2>&1 | tee -a "$LOG_FILE" || true
    fail "Control Plane konnte nicht gestartet werden; Diagnose wurde in $LOG_FILE geschrieben."
  fi
  for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:${BACKEND_PORT}/livez >/dev/null 2>&1 && break; sleep .5; done
  if ! curl -fsS http://127.0.0.1:${BACKEND_PORT}/livez | tee -a "$LOG_FILE"; then
    systemctl --no-pager --full status gedefense-control.service 2>&1 | tee -a "$LOG_FILE" || true
    journalctl -u gedefense-control.service -n 160 --no-pager 2>&1 | tee -a "$LOG_FILE" || true
    fail "Control-Liveness blieb nach dem Start unerreichbar."
  fi
  local token status
  token=$(tr -d '\r\n' < "$TOKEN_FILE")
  status=$(curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:${BACKEND_PORT}/api/v1/status)
  printf '%s\n' "$status" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["core_connected"] is True, d; assert d["core_mode"] in ("native","generic"), d; print("authenticated core/xdp status:",d["core_mode"])' | tee -a "$LOG_FILE"
  "$CURRENT/bin/gedefense-access" --listen="127.0.0.1:0" --backend="http://127.0.0.1:${BACKEND_PORT}" --public-host="${PUBLIC_HOST}:${PUBLIC_PORT}" --password-file="$PASSWORD_FILE" --session-key-file="$SESSION_KEY_FILE" --backend-token-file="$TOKEN_FILE" --tls-cert="$CERT_FILE" --tls-key="$TLS_KEY_FILE" --self-test-backend | tee -a "$LOG_FILE"
  systemctl start gedefense-access.service
  for _ in $(seq 1 40); do curl -kfsS --resolve "${PUBLIC_HOST}:${PUBLIC_PORT}:127.0.0.1" "https://${PUBLIC_HOST}:${PUBLIC_PORT}/gateway/livez" >/dev/null 2>&1 && break; sleep .5; done
  curl -kfsS --resolve "${PUBLIC_HOST}:${PUBLIC_PORT}:127.0.0.1" "https://${PUBLIC_HOST}:${PUBLIC_PORT}/gateway/livez" | tee -a "$LOG_FILE"
  systemctl is-active --quiet gedefense-core.service
  systemctl is-active --quiet gedefense-control.service
  systemctl is-active --quiet gedefense-access.service
  systemctl disable gedefense-observe.service >/dev/null 2>&1 || true
  ACTIVATING=0
}

open_firewall(){
  if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "${PUBLIC_PORT}/tcp" comment 'VGT GeDefense' >/dev/null || true
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${PUBLIC_PORT}/tcp" >/dev/null || true
    firewall-cmd --reload >/dev/null || true
  elif have iptables; then
    iptables -C INPUT -p tcp --dport "$PUBLIC_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$PUBLIC_PORT" -j ACCEPT
  fi
}

install_manager(){
  cat > /usr/local/sbin/vgt-gedefense <<'MANAGER'
#!/usr/bin/env bash
set -Eeuo pipefail
case ${1:-status} in
  status) systemctl --no-pager --full status gedefense-core.service gedefense-control.service gedefense-access.service ;;
  restart) systemctl restart gedefense-core.service gedefense-control.service gedefense-access.service ;;
  logs) journalctl -u gedefense-core.service -u gedefense-control.service -u gedefense-access.service -n "${2:-200}" --no-pager ;;
  stop) systemctl stop gedefense-access.service gedefense-control.service gedefense-core.service ;;
  start) systemctl start gedefense-core.service gedefense-control.service gedefense-access.service ;;
  *) echo "Usage: vgt-gedefense {status|restart|logs [N]|start|stop}" >&2; exit 2 ;;
esac
MANAGER
  chmod 0755 /usr/local/sbin/vgt-gedefense
}

archive_old_latch(){
  local stamp latch backup archive
  stamp=$(date +%s)
  for latch in "$STATE/EMERGENCY_STOP" "$CONFIG_DIR/EMERGENCY_STOP"; do
    [[ -e $latch ]] || continue
    [[ -f $latch && ! -L $latch ]] || fail "Unsichere Emergency-Stop-Datei: $latch"
    if [[ $latch == "$STATE/EMERGENCY_STOP" ]]; then
      backup="$BACKUP_DIR/EMERGENCY_STOP.state"
      OLD_STATE_LATCH=1
    else
      backup="$BACKUP_DIR/EMERGENCY_STOP.config"
      OLD_CONFIG_LATCH=1
    fi
    archive="${latch}.pre-full-stack-beta.${stamp}"
    cp -a -- "$latch" "$backup"
    cp -a -- "$latch" "$archive"
    rm -f -- "$latch"
    log "Alte Control-only-Sperre revisionssicher archiviert: $archive"
  done
}

main(){
  log "VGT GeDefense ${PRODUCT_VERSION} Full-Stack Installation startet."
  platform_check
  install_build_dependencies
  extract_payload
  detect_interface
  collect_access_settings
  ensure_user_and_dirs
  install_rust_toolchains
  build_rust_stack
  backup_activation_state
  prepare_secrets
  stage_release
  write_config_and_baseline
  generate_tls
  activate_release
  open_firewall
  install_manager
  log "Installation und Zielhost-Validierung erfolgreich. Persistente Betriebsdaten nutzen AES-256-GCM mit AAD-Bindung; neue Passwörter Argon2id."
  printf '\n============================================================\n'
  printf 'VGT GeDefense %s läuft vollständig.\n' "$PRODUCT_VERSION"
  printf 'Rust Core / XDP: ONLINE auf %s\n' "$INTERFACE"
  printf 'Dashboard wurde auf dem konfigurierten HTTPS-Port %s bereitgestellt.\n' "$PUBLIC_PORT"
  printf 'Startmodus: OBSERVE (sichere Beta-Freigabe)\n'
  if [[ -z $MANAGEMENT_ALLOWLIST ]]; then
    printf 'Hinweis: Management-Allowlist im Dashboard setzen, bevor Enforce freigegeben wird.\n'
  fi
  printf 'Status: vgt-gedefense status\n'
  printf 'Log: %s\n' "$LOG_FILE"
  printf '============================================================\n'
}

main "$@"
exit 0
__VGT_PAYLOAD_BELOW__
