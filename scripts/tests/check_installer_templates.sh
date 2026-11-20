#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Static syntax gate and trust regression for the installer header templates.
#
# The templates contain placeholders that are substituted by
# scripts/render-installer-header.py. This gate renders deterministic dummy
# values into a temporary copy and runs `bash -n` on the header section only
# (the appended payload is not part of the bash source).
#
# FIND-001 additionally binds the desktop One-Click installer into this gate:
# * scripts/desktop-oneclick-header.sh is rendered and syntax-checked here too,
# * a throwaway Ed25519 release key signs a fixture payload, the rendered
#   installer is assembled and executed with --self-test,
# * negative tests prove that a tampered payload, a foreign signing key and an
#   unrendered (unsigned) header all abort BEFORE extraction: the self-test
#   target directory stays empty in every failure case.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/vgt-header-syntax.XXXXXX")
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT

version=$(tr -d '\r\n' < "$ROOT/VERSION")
dummy_pub=$(python3 -c 'print("ab" * 32)')
dummy_b64=$(printf 'signed-release-index-placeholder' | base64 -w0)

render_template(){
  local template=$1 marker=$2 output=$3
  python3 - "$template" "$output" "$marker" "$dummy_pub" "$dummy_b64" "$version" <<'PY'
import sys
from pathlib import Path
template, output, marker, pub, b64, version = sys.argv[1:]
substitutions = {
    "__VERSION__": version,
    "__RELEASE_PUBKEY_HEX__": pub,
    "__RELEASE_INDEX_B64__": b64,
    "__RELEASE_VERIFIER_B64__": b64,
    "__RELEASE_TRUST_MODE__": "prebuilt",
    "__SOURCE_PAYLOAD_SHA256__": "0" * 64,
    "__PAYLOAD_SHA256__": "0" * 64,
    "__CONTROL_SHA256__": "0" * 64,
    "__ACCESS_SHA256__": "0" * 64,
}
text = Path(template).read_text(encoding="utf-8")
for placeholder, value in substitutions.items():
    text = text.replace(placeholder, value)
header = text.split("\n" + marker + "\n")[0]
# Check the exact placeholder tokens only. The source-bootstrap header contains a
# self-test grep for the literal prefix "__RELEASE_" inside the rendered header
# itself, so a bare substring test produced a false positive (CI supply-chain-gate).
remaining = [token for token in substitutions if token in header]
if remaining:
    raise SystemExit(f"unrendered placeholders remain in {template}: {remaining}")
Path(output).write_text(header, encoding="utf-8", newline="\n")
PY
  bash -n "$output"
  echo "PASS: bash -n $template"
}

render_template "$ROOT/scripts/oneclick-installer-header.sh" "__VGT_PAYLOAD_BELOW__" "$work/installer-header.sh"
render_template "$ROOT/scripts/oneclick-source-bootstrap-header.sh" "__VGT_SOURCE_PAYLOAD_BELOW__" "$work/source-bootstrap-header.sh"
render_template "$ROOT/scripts/desktop-oneclick-header.sh" "__VGT_PAYLOAD_BELOW__" "$work/desktop-oneclick-header.sh"

# --- FIND-001: desktop installer verifies Ed25519+checksum before extraction ---
functional_desktop_trust_test(){
  local case_dir="$work/desktop-trust"
  local payload="$case_dir/payload.tar.gz"
  local index_a="$case_dir/release-index-a.signed.json"
  local index_b="$case_dir/release-index-b.signed.json"
  local pub_a="$case_dir/pubkey-a.hex"
  local pub_b="$case_dir/pubkey-b.hex"
  local sha_file="$case_dir/payload.sha256"
  mkdir -p "$case_dir"

  # Throwaway Ed25519 key pair, signed release index (offline, no network) and a
  # fixture payload that satisfies the desktop --self-test assertions.
  python3 - "$ROOT" "$case_dir" "$version" <<'PY'
import pathlib, sys, tarfile
root, case, version = sys.argv[1:]
sys.path.insert(0, root + "/scripts")
import vgt_release_security as security
case = pathlib.Path(case)
payload_root = case / "payload-root"
(payload_root / "desktop" / "tray").mkdir(parents=True)
(payload_root / "desktop" / "tray" / "CMakeLists.txt").write_text(
    "cmake_minimum_required(VERSION 3.16)\nproject(gedefense-tray LANGUAGES CXX)\n",
    encoding="utf-8",
)
(payload_root / "THIRD-PARTY-LICENSES.md").write_text("third-party notices fixture\n", encoding="utf-8")
payload = case / "payload.tar.gz"
with tarfile.open(payload, "w:gz") as handle:
    for path in sorted(payload_root.rglob("*")):
        handle.add(path, arcname=str(path.relative_to(payload_root)))
digest = security.sha256_file(payload)
size = payload.stat().st_size
for suffix, key in (("a", security.generate_key()), ("b", security.generate_key())):
    index = security.build_release_index(
        version=version,
        channel=security.channel_for_version(version),
        commit="0" * 40,
        tree_clean=True,
        epoch=1785110400,
        key=key,
        artifacts=[{"name": "payload.tar.gz", "sha256": digest, "size": size, "role": "installer-payload"}],
    )
    (case / f"release-index-{suffix}.signed.json").write_bytes(security.sign_release_index(index, key))
    (case / f"pubkey-{suffix}.hex").write_text(key.public.hex() + "\n", encoding="utf-8")
(case / "payload.sha256").write_text(digest + "\n", encoding="utf-8")
PY

  local payload_sha pubkey_a pubkey_b
  payload_sha=$(tr -d '\r\n' < "$sha_file")
  pubkey_a=$(tr -d '\r\n' < "$pub_a")
  pubkey_b=$(tr -d '\r\n' < "$pub_b")

  assemble_installer(){
    local name=$1 pubkey=$2 index=$3 sha=$4
    local header="$case_dir/header-${name}.sh"
    local output="$case_dir/GeDefense-Desktop-${name}.run"
    python3 "$ROOT/scripts/render-installer-header.py" \
      --template "$ROOT/scripts/desktop-oneclick-header.sh" \
      --output "$header" \
      --public-key-hex "$pubkey" \
      --index "$index" \
      --verifier "$ROOT/scripts/vgt_release_security.py" \
      --trust-mode prebuilt \
      --product-version "$version" \
      --payload-sha256 "$sha"
    cat "$header" "$payload" > "$output"
    chmod 0755 "$output"
    printf '%s\n' "$output"
  }

  local good_installer foreign_installer unrendered_installer unrendered_header
  good_installer=$(assemble_installer good "$pubkey_a" "$index_a" "$payload_sha")
  foreign_installer=$(assemble_installer foreign "$pubkey_a" "$index_b" "$payload_sha")
  unrendered_header="$case_dir/header-unrendered.sh"
  python3 - "$ROOT/scripts/desktop-oneclick-header.sh" "$unrendered_header" "$version" "$payload_sha" <<'PY'
import pathlib, sys
template, output, version, digest = sys.argv[1:]
text = pathlib.Path(template).read_text(encoding="utf-8")
text = text.replace("__VERSION__", version).replace("__PAYLOAD_SHA256__", digest)
pathlib.Path(output).write_text(text, encoding="utf-8", newline="\n")
PY
  unrendered_installer="$case_dir/GeDefense-Desktop-unrendered.run"
  cat "$unrendered_header" "$payload" > "$unrendered_installer"
  chmod 0755 "$unrendered_installer"

  run_self_test(){
    local installer=$1 target=$2 output=$3
    mkdir -p "$target"
    set +e
    GEDEFENSE_DESKTOP_SELFTEST_DIR="$target" "$installer" --self-test >"$output" 2>&1
    local status=$?
    set -e
    printf '%s\n' "$status"
  }

  local target status
  # Positive: valid signature + hash -> self-test passes and extracts.
  target="$case_dir/target-good"
  status=$(run_self_test "$good_installer" "$target" "$case_dir/good.log")
  if [[ $status -ne 0 ]]; then
    cat "$case_dir/good.log" >&2
    echo "FAIL: signed desktop installer failed --self-test (FIND-001 regression)" >&2
    return 1
  fi
  grep -Fq 'SELF-TEST PASS' "$case_dir/good.log" || { echo "FAIL: self-test success marker missing" >&2; return 1; }
  [[ -f "$target/desktop/tray/CMakeLists.txt" ]] || { echo "FAIL: verified payload was not extracted" >&2; return 1; }
  echo "PASS: desktop installer verifies signature+checksum and extracts the signed payload"

  # Negative 1: tampered payload -> checksum mismatch, target stays empty.
  local tampered="$case_dir/GeDefense-Desktop-tampered.run"
  cp "$good_installer" "$tampered"
  printf 'tampered' >> "$tampered"
  target="$case_dir/target-tampered"
  status=$(run_self_test "$tampered" "$target" "$case_dir/tampered.log")
  if [[ $status -eq 0 ]]; then
    echo "FAIL: tampered desktop payload passed --self-test" >&2
    return 1
  fi
  grep -Fq 'checksum mismatch' "$case_dir/tampered.log" || {
    cat "$case_dir/tampered.log" >&2
    echo "FAIL: tampered payload did not fail the checksum gate" >&2
    return 1
  }
  if find "$target" -mindepth 1 -print -quit | grep -q .; then
    echo "FAIL: files were extracted from a tampered payload (verify-before-extract broken)" >&2
    return 1
  fi
  echo "PASS: tampered desktop payload aborts before extraction (target directory stays empty)"

  # Negative 2: payload signed by a foreign Ed25519 key -> signature gate fails.
  target="$case_dir/target-foreign"
  status=$(run_self_test "$foreign_installer" "$target" "$case_dir/foreign.log")
  if [[ $status -eq 0 ]]; then
    echo "FAIL: desktop installer accepted an index signed by a foreign release key" >&2
    return 1
  fi
  grep -Eq 'Ed25519-Signatur|signer fingerprint' "$case_dir/foreign.log" || {
    cat "$case_dir/foreign.log" >&2
    echo "FAIL: foreign signing key was not rejected by the Ed25519 gate" >&2
    return 1
  }
  if find "$target" -mindepth 1 -print -quit | grep -q .; then
    echo "FAIL: files were extracted before the Ed25519 signature check" >&2
    return 1
  fi
  echo "PASS: foreign Ed25519 signing key aborts before extraction (target directory stays empty)"

  # Negative 3: unrendered header (no release trust context) fails closed.
  target="$case_dir/target-unrendered"
  status=$(run_self_test "$unrendered_installer" "$target" "$case_dir/unrendered.log")
  if [[ $status -eq 0 ]]; then
    echo "FAIL: unrendered desktop installer ran without a signed release context" >&2
    return 1
  fi
  grep -Fq 'ohne signierten Release-Kontext' "$case_dir/unrendered.log" || {
    cat "$case_dir/unrendered.log" >&2
    echo "FAIL: unrendered installer did not fail closed with an explicit trust error" >&2
    return 1
  }
  if find "$target" -mindepth 1 -print -quit | grep -q .; then
    echo "FAIL: unrendered installer extracted payload files" >&2
    return 1
  fi
  echo "PASS: unrendered (unsigned) desktop installer fails closed before extraction"
}

functional_desktop_trust_test
echo "ALL INSTALLER HEADER TEMPLATES PARSE AND THE DESKTOP TRUST GATE PASSES"

# --- FIND-002/FIND-003: regression gate for the server One-Click installer -----
# These are ordering/invariant checks on the rendered template source; the
# privileged runtime paths themselves are exercised only on a real target host.
server_installer_hardening_gate(){
  local template="$ROOT/scripts/oneclick-installer-header.sh"
  local failures=0
  check(){
    local needle=$1 label=$2
    grep -Fq -- "$needle" "$template" || { echo "FAIL: $label (missing: $needle)" >&2; failures=$((failures + 1)); }
  }
  forbid(){
    local needle=$1 label=$2
    if grep -Fq -- "$needle" "$template"; then echo "FAIL: $label (found: $needle)" >&2; failures=$((failures + 1)); fi
  }
  # release_trust_check must be the first step of main() (FIND-002).
  local main_body first_trust first_deps
  main_body=$(awk '/^main\(\)\{/{flag=1} flag{print} flag && /^\}$/{exit}' "$template")
  first_trust=$(printf '%s\n' "$main_body" | grep -n 'release_trust_check' | head -n1 | cut -d: -f1)
  first_deps=$(printf '%s\n' "$main_body" | grep -n 'install_build_dependencies' | head -n1 | cut -d: -f1)
  if [[ -n $first_trust && -n $first_deps && $first_trust -lt $first_deps ]]; then
    echo "PASS: server installer verifies the signed release index before any package manager call"
  else
    echo "FAIL: release_trust_check is not the first step of the server installer main()" >&2
    failures=$((failures + 1))
  fi
  # No network-installed executable toolchains (curl | sh, rustup install, cargo install).
  forbid 'sh.rustup.rs' "server installer still downloads rustup via curl | sh"
  forbid 'rustup toolchain install' "server installer still installs unpinned Rust toolchains from the network"
  forbid 'cargo +"$RUST_STABLE_TOOLCHAIN" install' "server installer still installs bpf-linker from the network"
  # systemd-sysusers before any gedefense-access ownership use (FIND-002).
  local sysusers_line access_line
  sysusers_line=$(grep -n 'systemd-sysusers' "$template" | head -n1 | cut -d: -f1)
  access_line=$(grep -n 'install -d -o gedefense-access' "$template" | head -n1 | cut -d: -f1)
  if [[ -n $sysusers_line && -n $access_line && $sysusers_line -lt $access_line ]]; then
    echo "PASS: service accounts are provisioned (systemd-sysusers) before gedefense-access ownership is used"
  else
    echo "FAIL: gedefense-access ownership is used before the account provisioning" >&2
    failures=$((failures + 1))
  fi
  # persist_release_floor must not reset the state directory (FIND-003).
  forbid 'install -d -o root -g root -m 0755 "$STATE"' "persist_release_floor resets \$STATE to root:root 0755"
  check "'gedefense:gedefense:710'" "persist_release_floor no longer asserts the 0710 gedefense:gedefense state contract"
  forbid '.tmp.$$' "predictable secret/password temp file name remains"
  check 'tempfile.mkstemp' "release floor is not written through an O_EXCL temp file"
  check 'chown root:root "$TLS_KEY_FILE"; chmod 0600 "$TLS_KEY_FILE"' "TLS private key is not root-only 0600"
  check 'readonly CERT_FILE="${TLS_DIR}/access.crt"' "installer does not write canonical TLS certificate to \${TLS_DIR}/access.crt"
  forbid 'readonly CERT_FILE="${ACCESS_DIR}/access.crt"' "installer still sets CERT_FILE to \${ACCESS_DIR}/access.crt instead of \${TLS_DIR}/access.crt"
  check 'g gedefense-desktop - -' "systemd-sysusers block is missing gedefense-desktop"
  check 'groupadd --system gedefense-desktop' "groupadd fallback is missing gedefense-desktop"
  check 'install -d -o root -g gedefense -m 0750 /run/gedefense-scan' "installer does not pre-create /run/gedefense-scan (0750 root:gedefense)"
  check 'install -d -o gedefense -g gedefense-desktop -m 2750 /run/gedefense' "installer does not pre-create /run/gedefense (2750 gedefense:gedefense-desktop)"
  check 'install -d -o gedefense -g gedefense -m 0775 /sys/fs/cgroup/vgt-cells' "installer does not pre-create /sys/fs/cgroup/vgt-cells before gedefense-cell-helper starts"
  if (( failures > 0 )); then
    echo "FAIL: server installer hardening gate ($failures finding(s))" >&2
    return 1
  fi
  echo "PASS: server installer hardening gate (signature first, no curl|sh, sysusers first, 0710 state, atomic secrets, root-only TLS key)"
}

server_installer_hardening_gate
echo "ALL INSTALLER TEMPLATE AND HARDENING GATES PASS"

