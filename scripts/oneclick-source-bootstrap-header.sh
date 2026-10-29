#!/usr/bin/env bash
# VGT GeDefense 5.1.0-beta.3 source-self-contained one-click bootstrap installer
set -Eeuo pipefail
umask 0077

readonly PRODUCT_VERSION="5.1.0-beta.3"
readonly PAYLOAD_SHA256="__SOURCE_PAYLOAD_SHA256__"
readonly GO_VERSION="1.27.3"
readonly GO_LINUX_AMD64_SHA256="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"
readonly GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
readonly SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
# Rendered by scripts/render-installer-header.py. Unfilled placeholders fail
# closed: the installer refuses to run without a signed release index.
readonly RELEASE_PUBKEY_HEX="__RELEASE_PUBKEY_HEX__"
readonly RELEASE_INDEX_B64="__RELEASE_INDEX_B64__"
readonly RELEASE_VERIFIER_B64="__RELEASE_VERIFIER_B64__"
readonly RELEASE_TRUST_MODE="__RELEASE_TRUST_MODE__"
readonly STATE_DIR="/var/lib/vgt/gedefense"
readonly CURRENT_LINK="/opt/vgt/gedefense/current"
readonly FLOOR_FILE="${STATE_DIR}/release-floor.json"

WORK=""
TRUST_WORK=""
SOURCE_ROOT=""
MODE="install"
GO_BIN=""
ALLOW_DOWNGRADE=0
INSTALLED_VERSION=""
NEXT_FLOOR=""

log(){ printf '[GeDefense bootstrap] %s\n' "$*"; }
fail(){ printf '[GeDefense bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }
cleanup(){ [[ -n ${WORK:-} && -d ${WORK:-} ]] && rm -rf -- "$WORK" || true; [[ -n ${TRUST_WORK:-} && -d ${TRUST_WORK:-} ]] && rm -rf -- "$TRUST_WORK" || true; }
trap cleanup EXIT

usage(){
  cat <<'USAGE'
VGT GeDefense 5.1.0-beta.3 One-Click Installer

Usage:
  ./GeDefense-5.1.0-beta.3-OneClick.run              Install or upgrade GeDefense
  ./GeDefense-5.1.0-beta.3-OneClick.run --self-test  Verify this installer and inspect host readiness without modifying the host
  ./GeDefense-5.1.0-beta.3-OneClick.run --verify     Alias for --self-test
  ./GeDefense-5.1.0-beta.3-OneClick.run --allow-downgrade  Explicit recovery downgrade (still blocked below the release floor)
  ./GeDefense-5.1.0-beta.3-OneClick.run --help       Show this help

The installer verifies the embedded signed release index with the pinned
Ed25519 release public key and enforces semantic version monotonicity before any
privileged action. Unknown or unsigned installers are refused (fail closed).

The real installation is transactional. The embedded full-stack installer backs
up the current release, configuration, secrets and unit state and rolls back if
activation or post-start validation fails.
USAGE
}

parse_args(){
  local argument index=0
  for argument in "$@"; do
    case $argument in
      --self-test|--verify) MODE="self-test" ;;
      --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; fail "Unknown argument: $argument" ;;
    esac
    index=$((index + 1))
  done
  (( index <= 2 )) || fail "Too many arguments."
}

safe_extract(){
  local archive=$1 dst=$2
  python3 - "$archive" "$dst" <<'PY'
import pathlib, sys, tarfile
archive, dst = sys.argv[1:]
root = pathlib.Path(dst).resolve()
with tarfile.open(archive, 'r:gz') as tf:
    members = tf.getmembers()
    if not members:
        raise SystemExit('empty payload')
    for member in members:
        p = pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or member.issym() or member.islnk() or member.isdev():
            raise SystemExit(f'unsafe payload member: {member.name}')
        target = (root / pathlib.Path(*p.parts)).resolve()
        if target != root and root not in target.parents:
            raise SystemExit(f'payload path escape: {member.name}')
    tf.extractall(root)
PY
}

release_placeholder_ok(){
  local value=$1 name=$2
  [[ -n $value && $value != __*__ && $value != "__${name}__" ]] || fail "Installer wurde ohne signierten Release-Kontext gebaut ($name fehlt)."
}

resolve_installed_version(){
  INSTALLED_VERSION=""
  if [[ -r "$CURRENT_LINK/share/VERSION" && ! -L "$CURRENT_LINK/share/VERSION" ]]; then
    INSTALLED_VERSION=$(tr -d '\r\n' < "$CURRENT_LINK/share/VERSION")
  fi
}

release_trust_check(){
  release_placeholder_ok "$RELEASE_PUBKEY_HEX" RELEASE_PUBKEY_HEX
  release_placeholder_ok "$RELEASE_INDEX_B64" RELEASE_INDEX_B64
  release_placeholder_ok "$RELEASE_VERIFIER_B64" RELEASE_VERIFIER_B64
  release_placeholder_ok "$RELEASE_TRUST_MODE" RELEASE_TRUST_MODE
  [[ $RELEASE_PUBKEY_HEX =~ ^[0-9a-f]{64}$ ]] || fail "Release-Public-Key ist ungÃ¼ltig."
  have python3 || fail "python3 ist fÃ¼r die SignaturprÃ¼fung erforderlich (python3 zuerst installieren)."
  have sha256sum || fail "sha256sum ist fÃ¼r die SignaturprÃ¼fung erforderlich."
  TRUST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-release-trust.XXXXXX")
  printf '%s' "$RELEASE_INDEX_B64" | base64 -d > "$TRUST_WORK/release-index.signed.json"
  printf '%s' "$RELEASE_VERIFIER_B64" | base64 -d > "$TRUST_WORK/release-verifier.py"
  chmod 0600 "$TRUST_WORK/release-index.signed.json" "$TRUST_WORK/release-verifier.py"
  python3 "$TRUST_WORK/release-verifier.py" verify-index \
    --index "$TRUST_WORK/release-index.signed.json" \
    --pubkey "$RELEASE_PUBKEY_HEX" \
    --expected-version "$PRODUCT_VERSION" >/dev/null \
    || fail "Signierte Release-Index-PrÃ¼fung fehlgeschlagen (Manipulation oder falscher SchlÃ¼ssel?)."
  log "Signierter Release-Index: Ed25519-Signatur gÃ¼ltig, Version ${PRODUCT_VERSION}, Trust-Modus ${RELEASE_TRUST_MODE}."
  resolve_installed_version
  local guard_args=(version-guard --candidate "$PRODUCT_VERSION" --floor-file "$FLOOR_FILE")
  [[ -n $INSTALLED_VERSION ]] && guard_args+=(--installed "$INSTALLED_VERSION")
  (( ALLOW_DOWNGRADE == 1 )) && guard_args+=(--allow-downgrade)
  local decision
  if ! decision=$(python3 "$TRUST_WORK/release-verifier.py" "${guard_args[@]}"); then
    fail "Anti-Rollback-PrÃ¼fung abgelehnt: ${decision:-keine Entscheidung}"
  fi
  NEXT_FLOOR=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["next_floor"])' <<< "$decision")
  log "Anti-Rollback: ${decision}"
}

persist_release_floor(){
  [[ -n ${NEXT_FLOOR:-} ]] || fail "Release-Floor ist nicht bestimmt; SignaturprÃ¼fung wurde Ã¼bersprungen."
  if [[ ${EUID} -ne 0 ]]; then
    log "Release-Floor wird nur bei der Installation persistiert ($FLOOR_FILE)."
    return 0
  fi
  install -d -o root -g root -m 0755 "$STATE_DIR"
  python3 - "$FLOOR_FILE" "$NEXT_FLOOR" <<'PY'
import json, os, pathlib, sys, time
path, highest = sys.argv[1:]
document = {
    "schema": "vgt.gedefense.release-floor.v1",
    "highest_version": highest,
    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
target = pathlib.Path(path)
temporary = target.with_name(target.name + f".tmp.{os.getpid()}")
temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
os.replace(temporary, target)
PY
  chown root:root "$FLOOR_FILE" 2>/dev/null || true
  chmod 0600 "$FLOOR_FILE"
  log "Release-Floor persistiert: $NEXT_FLOOR"
}
extract_and_verify_payload(){
  have python3 || fail "python3 is required to verify the installer payload."
  have sha256sum || fail "sha256sum is required to verify the installer payload."
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-oneclick.XXXXXX")
  local marker archive actual
  marker=$(awk '/^__VGT_SOURCE_PAYLOAD_BELOW__$/{print NR+1; exit}' "$SELF")
  [[ $marker =~ ^[0-9]+$ ]] || fail "Embedded payload marker is missing."
  archive="$WORK/source.tar.gz"
  tail -n +"$marker" "$SELF" > "$archive"
  actual=$(sha256sum "$archive" | awk '{print $1}')
  [[ $actual == "$PAYLOAD_SHA256" ]] || fail "Embedded payload checksum mismatch."
  python3 "$TRUST_WORK/release-verifier.py" verify-index \
    --index "$TRUST_WORK/release-index.signed.json" \
    --pubkey "$RELEASE_PUBKEY_HEX" \
    --expected-version "$PRODUCT_VERSION" \
    --artifact-file "payload.tar.gz=$archive" >/dev/null \
    || fail "Payload ist nicht durch den signierten Release-Index gedeckt."
  mkdir -p "$WORK/source"
  safe_extract "$archive" "$WORK/source"
  SOURCE_ROOT="$WORK/source"
  local manifest_name
  if [[ -f "$SOURCE_ROOT/PAYLOAD-MANIFEST.sha256" ]]; then
    manifest_name=PAYLOAD-MANIFEST.sha256
  elif [[ -f "$SOURCE_ROOT/SOURCE-MANIFEST.sha256" ]]; then
    manifest_name=SOURCE-MANIFEST.sha256
  else
    fail "Payload manifest is missing."
  fi
  (
    cd "$SOURCE_ROOT"
    sha256sum -c "$manifest_name" >/dev/null
  ) || fail "Payload file manifest verification failed."
  [[ -f "$SOURCE_ROOT/VERSION" ]] || fail "VERSION is missing."
  [[ $(tr -d '\r\n' < "$SOURCE_ROOT/VERSION") == "$PRODUCT_VERSION" ]] || fail "Payload VERSION mismatch."
  for required in \
    control/go.mod gateway/go.mod rust/Cargo.lock \
    scripts/oneclick-installer-header.sh \
    packaging/systemd/gedefense-core.service \
    integration/linux/gedefense-app gedefense.toml; do
    [[ -f "$SOURCE_ROOT/$required" ]] || fail "Required payload file is missing: $required"
  done
}

host_readiness_report(){
  local pass=0 pending=0 fail_count=0
  report(){ printf '  %-8s %s\n' "$1" "$2"; }
  if [[ $(uname -s 2>/dev/null || true) == Linux ]]; then report PASS "Linux host"; ((pass+=1)); else report FAIL "Linux host required"; ((fail_count+=1)); fi
  if [[ $(uname -m 2>/dev/null || true) == x86_64 || $(uname -m 2>/dev/null || true) == amd64 ]]; then report PASS "x86_64 architecture"; ((pass+=1)); else report FAIL "x86_64 required by this RC"; ((fail_count+=1)); fi
  if [[ -d /run/systemd/system ]]; then report PASS "systemd is active"; ((pass+=1)); else report PENDING "systemd is not the active init system in this environment"; ((pending+=1)); fi
  if mountpoint -q /sys/fs/bpf 2>/dev/null; then report PASS "bpffs is mounted"; ((pass+=1)); else report PENDING "bpffs is not mounted (installer can provision it on a real host)"; ((pending+=1)); fi
  if have bpftool; then report PASS "bpftool available"; ((pass+=1)); else report PENDING "bpftool not installed in this environment"; ((pending+=1)); fi
  if have cargo && have rustup; then report PASS "Rust bootstrap available"; ((pass+=1)); else report PENDING "Rust toolchain will be installed during real installation"; ((pending+=1)); fi
  if have go && [[ $(go env GOVERSION 2>/dev/null || true) == "go${GO_VERSION}" ]]; then report PASS "Go ${GO_VERSION} already available"; ((pass+=1)); else report PENDING "Go ${GO_VERSION} will be downloaded and checksum-verified during installation"; ((pending+=1)); fi
  if have curl; then report PASS "curl available"; ((pass+=1)); else report PENDING "curl must be installed by the package manager"; ((pending+=1)); fi
  printf 'SELF_TEST_SUMMARY pass=%d pending=%d fail=%d\n' "$pass" "$pending" "$fail_count"
  (( fail_count == 0 ))
}

self_test(){
  log "Verifying embedded GeDefense ${PRODUCT_VERSION} source payload."
  release_trust_check
  extract_and_verify_payload
  log "Payload checksum and per-file manifest: PASS"
  bash -n "$SOURCE_ROOT/scripts/oneclick-installer-header.sh"
  bash -n "$SOURCE_ROOT/integration/linux/gedefense-app"
  bash -n "$SOURCE_ROOT/integration/linux/gedefense-ensure-ready"
  log "Installer/integration shell syntax: PASS"
  python3 "$SOURCE_ROOT/scripts/validate-linux-integration.py" >/dev/null
  log "Linux integration static contract: PASS"
  log "Host readiness (non-destructive):"
  host_readiness_report
  log "Self-test complete. No system files, services, firewall rules or package state were modified."
}

install_bootstrap_dependencies(){
  log "Installing minimal bootstrap dependencies."
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl build-essential libargon2-1 python3 tar gzip coreutils
  elif have dnf; then
    dnf install -y ca-certificates curl gcc gcc-c++ make libargon2 python3 tar gzip coreutils
  elif have yum; then
    yum install -y ca-certificates curl gcc gcc-c++ make libargon2 python3 tar gzip coreutils
  elif have pacman; then
    pacman -Sy --needed --noconfirm ca-certificates curl base-devel argon2 python tar gzip coreutils
  elif have zypper; then
    zypper --non-interactive install ca-certificates curl gcc gcc-c++ make libargon2-1 python3 tar gzip coreutils
  else
    fail "No supported package manager found (APT/DNF/YUM/pacman/Zypper)."
  fi
  for cmd in curl gcc python3 tar gzip sha256sum; do have "$cmd" || fail "Bootstrap tool missing after dependency install: $cmd"; done
}

prepare_exact_go(){
  if have go && [[ $(go env GOVERSION 2>/dev/null || true) == "go${GO_VERSION}" ]]; then
    GO_BIN=$(command -v go)
    return 0
  fi
  local archive="$WORK/go${GO_VERSION}.linux-amd64.tar.gz" actual
  log "Downloading pinned Go ${GO_VERSION} toolchain."
  curl --proto '=https' --tlsv1.2 --fail --location --retry 3 --connect-timeout 15 \
    "$GO_URL" -o "$archive"
  actual=$(sha256sum "$archive" | awk '{print $1}')
  [[ $actual == "$GO_LINUX_AMD64_SHA256" ]] || fail "Go ${GO_VERSION} checksum mismatch."
  rm -rf "$WORK/go"
  tar -xzf "$archive" -C "$WORK"
  [[ $("$WORK/go/bin/go" env GOVERSION) == "go${GO_VERSION}" ]] || fail "Downloaded Go toolchain version mismatch."
  GO_BIN="$WORK/go/bin/go"
}

build_go_release(){
  local go_bin=$1 build="$WORK/go-build"
  mkdir -p "$build"
  log "Running Go unit/vet gates with pinned Go ${GO_VERSION}."
  (cd "$SOURCE_ROOT/control" && umask 0022 && GOTOOLCHAIN=local "$go_bin" test ./... && GOTOOLCHAIN=local "$go_bin" vet ./...)
  (cd "$SOURCE_ROOT/gateway" && umask 0022 && CGO_ENABLED=1 GOTOOLCHAIN=local "$go_bin" test ./... && CGO_ENABLED=1 GOTOOLCHAIN=local "$go_bin" vet ./...)
  log "Building release Go binaries."
  (cd "$SOURCE_ROOT/control" && CGO_ENABLED=0 GOTOOLCHAIN=local "$go_bin" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$build/gedefense-control" .)
  (cd "$SOURCE_ROOT/gateway" && CGO_ENABLED=1 GOTOOLCHAIN=local "$go_bin" build -trimpath -buildvcs=false -ldflags='-s -w -buildid= -extldflags=-Wl,--build-id=none' -o "$build/gedefense-access" .)
  [[ $("$build/gedefense-control" --version) == "$PRODUCT_VERSION" ]] || fail "Built control version mismatch."
  [[ $("$build/gedefense-access" --version) == "${PRODUCT_VERSION}-access" ]] || fail "Built access version mismatch."
  ldd "$build/gedefense-access" | grep -q 'libargon2.so.1' || fail "Built gateway is not linked against libargon2.so.1."
  ! ldd "$build/gedefense-access" | grep -q 'not found' || fail "Built gateway has unresolved runtime libraries."
}

make_inner_payload(){
  local payload="$WORK/fullstack-payload" go_build="$WORK/go-build"
  mkdir -p "$payload/bin" "$payload/rust" "$payload/share" "$payload/systemd" "$payload/tmpfiles" "$payload/templates" "$payload/integration/linux" "$payload/integration/nginx"
  install -m 0755 "$go_build/gedefense-control" "$payload/bin/gedefense-control"
  install -m 0755 "$go_build/gedefense-access" "$payload/bin/gedefense-access"
  cp -a "$SOURCE_ROOT/rust/." "$payload/rust/"
  rm -rf "$payload/rust/target"
  for f in README.md VALIDATION.md SECURITY.md THIRD-PARTY-LICENSES.md CRYPTOGRAPHY.md TOOLCHAINS.lock; do install -m 0644 "$SOURCE_ROOT/$f" "$payload/share/$f"; done
  install -m 0644 "$SOURCE_ROOT"/packaging/systemd/* "$payload/systemd/"
  install -m 0644 "$SOURCE_ROOT/packaging/tmpfiles/vgt-gedefense-l7.conf" "$payload/tmpfiles/vgt-gedefense-l7.conf"
  install -m 0644 "$SOURCE_ROOT/gedefense.toml" "$payload/templates/gedefense.toml"
  install -m 0644 "$SOURCE_ROOT/malware-hashes.sha256" "$payload/templates/malware-hashes.sha256"
  if [[ -f "$SOURCE_ROOT/geoip.csv" ]]; then
    install -m 0644 "$SOURCE_ROOT/geoip.csv" "$payload/templates/geoip.csv"
  fi
  if [[ -f "$SOURCE_ROOT/geoip.csv.sha256" ]]; then
    install -m 0644 "$SOURCE_ROOT/geoip.csv.sha256" "$payload/templates/geoip.csv.sha256"
  fi
  install -m 0755 "$SOURCE_ROOT/integration/linux/gedefense-app" "$payload/integration/linux/gedefense-app"
  install -m 0755 "$SOURCE_ROOT/integration/linux/gedefense-ensure-ready" "$payload/integration/linux/gedefense-ensure-ready"
  install -m 0644 "$SOURCE_ROOT/integration/linux/gedefense.desktop" "$payload/integration/linux/gedefense.desktop"
  install -m 0644 "$SOURCE_ROOT/integration/linux/org.vgt.gedefense.policy" "$payload/integration/linux/org.vgt.gedefense.policy"
  install -m 0644 "$SOURCE_ROOT/integration/nginx/gedefense-l7.conf.example" "$payload/integration/nginx/gedefense-l7.conf.example"
  install -m 0644 "$SOURCE_ROOT/integration/nginx/README.md" "$payload/integration/nginx/README.md"
  printf '%s\n' "$payload"
}

build_inner_installer(){
  local payload=$1 tar_raw="$WORK/fullstack.tar" tar_gz="$WORK/fullstack.tar.gz" header="$WORK/fullstack-header.sh" output="$WORK/gedefense-fullstack.run"
  tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner -cf "$tar_raw" -C "$payload" .
  gzip -n -9 -c "$tar_raw" > "$tar_gz"
  local payload_sha control_sha access_sha
  payload_sha=$(sha256sum "$tar_gz" | awk '{print $1}')
  control_sha=$(sha256sum "$payload/bin/gedefense-control" | awk '{print $1}')
  access_sha=$(sha256sum "$payload/bin/gedefense-access" | awk '{print $1}')
  sed \
    -e "s/__PAYLOAD_SHA256__/$payload_sha/g" \
    -e "s/__CONTROL_SHA256__/$control_sha/g" \
    -e "s/__ACCESS_SHA256__/$access_sha/g" \
    "$SOURCE_ROOT/scripts/oneclick-installer-header.sh" > "$header"
  # The release index and verifier are base64 blobs. Passing them as sed
  # replacement arguments can exceed ARG_MAX on a real installation, so the
  # header is rendered by a bounded Python substitution instead.
  VGT_RELEASE_PUBKEY_HEX="$RELEASE_PUBKEY_HEX" \
  VGT_RELEASE_INDEX_B64="$RELEASE_INDEX_B64" \
  VGT_RELEASE_VERIFIER_B64="$RELEASE_VERIFIER_B64" \
  VGT_RELEASE_TRUST_MODE="$RELEASE_TRUST_MODE" \
  python3 - "$header" <<'PY'
import os
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    text = handle.read()
for key in ("RELEASE_PUBKEY_HEX", "RELEASE_INDEX_B64", "RELEASE_VERIFIER_B64", "RELEASE_TRUST_MODE"):
    text = text.replace("__" + key + "__", os.environ.get("VGT_" + key, ""))
with open(path, "w", encoding="utf-8", newline="\n") as handle:
    handle.write(text)
PY
  grep -q '^__VGT_PAYLOAD_BELOW__$' "$header" || fail "Inner installer payload marker missing."
  ! grep -q '__RELEASE_\|__PAYLOAD_SHA256__\|__CONTROL_SHA256__\|__ACCESS_SHA256__' "$header" || fail "Inner installer contains unresolved release placeholders."
  head -n "$(awk '/^__VGT_PAYLOAD_BELOW__$/{print NR; exit}' "$header")" "$header" | bash -n
  cat "$header" "$tar_gz" > "$output"
  chmod 0700 "$output"
  printf '%s\n' "$output"
}

install_mode(){
  [[ ${EUID} -eq 0 ]] || fail "Run the installer as root: sudo $SELF"
  [[ $(uname -s) == Linux ]] || fail "Linux is required."
  [[ $(uname -m) == x86_64 || $(uname -m) == amd64 ]] || fail "This RC supports x86_64 only."
  [[ -d /run/systemd/system ]] || fail "systemd must be the active init system."
  release_trust_check
  extract_and_verify_payload
  install_bootstrap_dependencies
  local payload inner
  prepare_exact_go
  [[ -x $GO_BIN ]] || fail "Pinned Go toolchain path is not executable."
  build_go_release "$GO_BIN"
  payload=$(make_inner_payload)
  inner=$(build_inner_installer "$payload")
  log "Bootstrap gates passed. Handing off to the transactional full-stack installer."
  VGT_RELEASE_TRUST_MODE=source-signed bash "$inner"
  persist_release_floor
}

main(){
  parse_args "$@"
  if [[ $MODE == self-test ]]; then self_test; else install_mode; fi
}

main "$@"
exit 0
__VGT_SOURCE_PAYLOAD_BELOW__
