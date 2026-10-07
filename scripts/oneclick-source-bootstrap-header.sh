#!/usr/bin/env bash
# VGT GeDefense 4.2.0 source-self-contained one-click bootstrap installer
set -Eeuo pipefail
umask 0077

readonly PRODUCT_VERSION="4.2.0"
readonly PAYLOAD_SHA256="__SOURCE_PAYLOAD_SHA256__"
readonly GO_VERSION="1.26.8"
readonly GO_LINUX_AMD64_SHA256="d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b"
readonly GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
readonly SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"

WORK=""
SOURCE_ROOT=""
MODE="install"
GO_BIN=""

log(){ printf '[GeDefense bootstrap] %s\n' "$*"; }
fail(){ printf '[GeDefense bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }
cleanup(){ [[ -n ${WORK:-} && -d ${WORK:-} ]] && rm -rf -- "$WORK" || true; }
trap cleanup EXIT

usage(){
  cat <<'USAGE'
VGT GeDefense 4.2.0 One-Click Installer

Usage:
  ./GeDefense-4.2.0-OneClick.run              Install or upgrade GeDefense
  ./GeDefense-4.2.0-OneClick.run --self-test  Verify this installer and inspect host readiness without modifying the host
  ./GeDefense-4.2.0-OneClick.run --verify     Alias for --self-test
  ./GeDefense-4.2.0-OneClick.run --help       Show this help

The real installation is transactional. The embedded full-stack installer backs
up the current release, configuration, secrets and unit state and rolls back if
activation or post-start validation fails.
USAGE
}

parse_args(){
  case ${1:-} in
    "") MODE="install" ;;
    --self-test|--verify) MODE="self-test" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "Unknown argument: $1" ;;
  esac
  [[ $# -le 1 ]] || fail "Only one mode argument is supported."
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
  mkdir -p "$WORK/source"
  safe_extract "$archive" "$WORK/source"
  SOURCE_ROOT="$WORK/source"
  [[ -f "$SOURCE_ROOT/PAYLOAD-MANIFEST.sha256" ]] || fail "Payload manifest is missing."
  (
    cd "$SOURCE_ROOT"
    sha256sum -c PAYLOAD-MANIFEST.sha256 >/dev/null
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
  for f in README.md VALIDATION.md SECURITY-AUDIT-BETA5.md CRYPTOGRAPHY.md TOOLCHAINS.lock; do install -m 0644 "$SOURCE_ROOT/$f" "$payload/share/$f"; done
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
  grep -q '^__VGT_PAYLOAD_BELOW__$' "$header" || fail "Inner installer payload marker missing."
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
  extract_and_verify_payload
  install_bootstrap_dependencies
  local payload inner
  prepare_exact_go
  [[ -x $GO_BIN ]] || fail "Pinned Go toolchain path is not executable."
  build_go_release "$GO_BIN"
  payload=$(make_inner_payload)
  inner=$(build_inner_installer "$payload")
  log "Bootstrap gates passed. Handing off to the transactional full-stack installer."
  bash "$inner"
}

main(){
  parse_args "$@"
  if [[ $MODE == self-test ]]; then self_test; else install_mode; fi
}

main "$@"
exit 0
__VGT_SOURCE_PAYLOAD_BELOW__
