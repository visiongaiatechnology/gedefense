#!/usr/bin/env bash
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:-"$ROOT/dist/release"}
VERSION=$(tr -d '\r\n' < "$ROOT/VERSION")
SOURCE_NAME="VGT_GeDefense_Beta_1.0.0-beta.5_Source.zip"
RUN_NAME="VGT_GeDefense_Beta_1.0.0-beta.5_OneClick.run"
EPOCH=${SOURCE_DATE_EPOCH:-1785110400}

for cmd in go node python3 tar gzip sha256sum sed awk ldd grep; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing build tool: $cmd" >&2; exit 1; }
done
[[ $VERSION == "1.0.0-beta.5" ]] || { echo "unexpected VERSION: $VERSION" >&2; exit 1; }
mkdir -p "$OUT" "$ROOT/dist"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-gedefense-package.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

cd "$ROOT"
# XDP source must not derive packet pointers from attacker-provided IP length
# fields. The fixed source-address headers are sufficient for LPM filtering.
if grep -nE 'ptr_at\([^\n]*(total_len|payload_len|ihl)' rust/gedefense-ebpf/src/main.rs; then
  echo "unsafe packet-length-derived ptr_at reintroduced" >&2
  exit 1
fi
make test test-race go gateway
./scripts/security-audit.sh
if [[ ${EUID} -eq 0 ]]; then
  bash "$ROOT/scripts/validate-quarantine-dac.sh"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo -n bash "$ROOT/scripts/validate-quarantine-dac.sh"
else
  echo "release packaging requires root or passwordless sudo for capability-stripped DAC validation" >&2
  exit 1
fi

CONTROL_SHA=$(sha256sum "$ROOT/dist/gedefense-control" | awk '{print $1}')
ACCESS_SHA=$(sha256sum "$ROOT/dist/gedefense-access" | awk '{print $1}')
[[ $("$ROOT/dist/gedefense-control" --version) == "$VERSION" ]]
[[ $("$ROOT/dist/gedefense-access" --version) == "${VERSION}-access" ]]
ldd "$ROOT/dist/gedefense-access" | grep -q 'libargon2.so.1'
if ldd "$ROOT/dist/gedefense-access" | grep -q 'not found'; then
  echo "gateway has unresolved shared-library dependencies" >&2
  exit 1
fi

# Source archive: no binaries, build products, keys, tokens, logs or local VCS state.
SOURCE_STAGE="$WORK/VGT_GeDefense_Beta_1.0.0-beta.5"
mkdir -p "$SOURCE_STAGE"
python3 - "$ROOT" "$SOURCE_STAGE" <<'PY'
from pathlib import Path
import os, shutil, sys
src, dst = map(Path, sys.argv[1:])
excluded_dirs={
    '.git','.go-cache','.tmp-go-cache','.agents','.codex','dist','target',
    '__pycache__','RUN Build','GitHub Upload','release-beta','release-beta-final',
    'release-complete','release-final',
}
excluded_names={'SOURCE-MANIFEST.sha256'}
for path in sorted(src.rglob('*')):
    rel=path.relative_to(src)
    if (
        any(part in excluded_dirs for part in rel.parts)
        or path.name in excluded_names
        or path.suffix.lower() in {'.run', '.zip', '.sha256'}
    ):
        continue
    target=dst/rel
    if path.is_dir():
        target.mkdir(parents=True,exist_ok=True)
    elif path.is_file() and not path.is_symlink():
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(path,target)
PY
(
  cd "$SOURCE_STAGE"
  find . -type f ! -name SOURCE-MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > SOURCE-MANIFEST.sha256
)
python3 - "$SOURCE_STAGE" "$OUT/$SOURCE_NAME" "$EPOCH" <<'PY'
from pathlib import Path
import datetime, os, stat, sys, zipfile
root=Path(sys.argv[1]); output=Path(sys.argv[2]); epoch=int(sys.argv[3])
dt=datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc)
zip_dt=(max(dt.year,1980),dt.month,dt.day,dt.hour,dt.minute,dt.second)
base=root.name
with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        rel=Path(base)/path.relative_to(root)
        info=zipfile.ZipInfo(rel.as_posix(),zip_dt)
        mode=path.stat().st_mode
        info.external_attr=((0o755 if mode & stat.S_IXUSR else 0o644) & 0xFFFF) << 16
        info.compress_type=zipfile.ZIP_DEFLATED
        z.writestr(info,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
PY

# Self-extracting installer payload. Go binaries are prebuilt; Rust/eBPF source is
# intentionally compiled and verified on the destination kernel/NIC.
PAYLOAD="$WORK/payload"
mkdir -p "$PAYLOAD/bin" "$PAYLOAD/rust" "$PAYLOAD/share" "$PAYLOAD/systemd" "$PAYLOAD/templates"
install -m 0755 "$ROOT/dist/gedefense-control" "$PAYLOAD/bin/gedefense-control"
install -m 0755 "$ROOT/dist/gedefense-access" "$PAYLOAD/bin/gedefense-access"
cp -a "$ROOT/rust/." "$PAYLOAD/rust/"
rm -rf "$PAYLOAD/rust/target"
install -m 0644 "$ROOT/README.md" "$PAYLOAD/share/README.md"
install -m 0644 "$ROOT/VALIDATION.md" "$PAYLOAD/share/VALIDATION.md"
install -m 0644 "$ROOT/SECURITY-AUDIT-BETA5.md" "$PAYLOAD/share/SECURITY-AUDIT-BETA5.md"
install -m 0644 "$ROOT/CRYPTOGRAPHY.md" "$PAYLOAD/share/CRYPTOGRAPHY.md"
install -m 0644 "$ROOT/TOOLCHAINS.lock" "$PAYLOAD/share/TOOLCHAINS.lock"
install -m 0644 "$ROOT"/packaging/systemd/* "$PAYLOAD/systemd/"
install -m 0644 "$ROOT/gedefense.toml" "$PAYLOAD/templates/gedefense.toml"

find "$PAYLOAD" -exec touch -h -d "@$EPOCH" {} +
TAR_RAW="$WORK/payload.tar"
TAR_GZ="$WORK/payload.tar.gz"
tar --sort=name --format=gnu --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
    -cf "$TAR_RAW" -C "$PAYLOAD" .
gzip -n -9 -c "$TAR_RAW" > "$TAR_GZ"
PAYLOAD_SHA=$(sha256sum "$TAR_GZ" | awk '{print $1}')
HEADER="$WORK/installer-header.sh"
sed \
  -e "s/__PAYLOAD_SHA256__/$PAYLOAD_SHA/g" \
  -e "s/__CONTROL_SHA256__/$CONTROL_SHA/g" \
  -e "s/__ACCESS_SHA256__/$ACCESS_SHA/g" \
  "$ROOT/scripts/oneclick-installer-header.sh" > "$HEADER"
grep -q '^__VGT_PAYLOAD_BELOW__$' "$HEADER"
head -n "$(awk '/^__VGT_PAYLOAD_BELOW__$/{print NR; exit}' "$HEADER")" "$HEADER" | bash -n
cat "$HEADER" "$TAR_GZ" > "$OUT/$RUN_NAME"
chmod 0755 "$OUT/$RUN_NAME"

(
  cd "$OUT"
  sha256sum "$SOURCE_NAME" > "$SOURCE_NAME.sha256"
  sha256sum "$RUN_NAME" > "$RUN_NAME.sha256"
)

# Verify the embedded stream and the declared component digests.
VERIFY="$WORK/verify"
mkdir "$VERIFY"
LINE=$(awk '/^__VGT_PAYLOAD_BELOW__$/{print NR+1; exit}' "$OUT/$RUN_NAME")
tail -n +"$LINE" "$OUT/$RUN_NAME" > "$WORK/embedded.tar.gz"
[[ $(sha256sum "$WORK/embedded.tar.gz" | awk '{print $1}') == "$PAYLOAD_SHA" ]]
tar -xzf "$WORK/embedded.tar.gz" -C "$VERIFY"
[[ $(sha256sum "$VERIFY/bin/gedefense-control" | awk '{print $1}') == "$CONTROL_SHA" ]]
[[ $(sha256sum "$VERIFY/bin/gedefense-access" | awk '{print $1}') == "$ACCESS_SHA" ]]
[[ $("$VERIFY/bin/gedefense-control" --version) == "$VERSION" ]]
[[ $("$VERIFY/bin/gedefense-access" --version) == "${VERSION}-access" ]]
ldd "$VERIFY/bin/gedefense-access" | grep -q 'libargon2.so.1'
! ldd "$VERIFY/bin/gedefense-access" | grep -q 'not found'
python3 - "$OUT/$SOURCE_NAME" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    bad=z.testzip()
    if bad: raise SystemExit(f'bad zip member: {bad}')
    names=z.namelist()
    assert any(n.endswith('/SOURCE-MANIFEST.sha256') for n in names)
    assert any(n.endswith('/rust/Cargo.lock') for n in names)
    assert not any('/dist/' in n or '/target/' in n for n in names)
PY
printf 'Created:\n  %s\n  %s\n' "$OUT/$SOURCE_NAME" "$OUT/$RUN_NAME"
