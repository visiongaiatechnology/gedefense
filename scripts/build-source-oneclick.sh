#!/usr/bin/env bash
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:-"$ROOT/dist/oneclick"}
VERSION=$(tr -d '\r\n' < "$ROOT/VERSION")
EPOCH=${SOURCE_DATE_EPOCH:-1785110400}
[[ $VERSION == 4.2.1 ]] || { echo "unexpected VERSION: $VERSION" >&2; exit 1; }
mkdir -p "$OUT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-oneclick-build.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

for cmd in python3 tar gzip sha256sum bash; do command -v "$cmd" >/dev/null 2>&1 || { echo "missing packaging tool: $cmd" >&2; exit 1; }; done

STAGE="$WORK/source"
mkdir -p "$STAGE"
python3 - "$ROOT" "$STAGE" <<'PY'
from pathlib import Path
import shutil, sys
src, dst = map(Path, sys.argv[1:])
excluded_dirs = {'.git','.go-cache','.tmp-go-cache','dist','target','__pycache__','release-beta','release-final','RUN Build','GitHub Upload','qa'}
excluded_names = {
    'SOURCE-MANIFEST.sha256','PAYLOAD-MANIFEST.sha256','control','gateway',
    'wsl-verify.sh','wsl-qa.sh','wsl-vuln.sh','wsl-probe.sh','wsl-race.sh','wsl-gate.sh','wsl-login-qa.sh',
    'wsl-panel-qa.sh','wsl-rust-syntax.sh',
    'extract.sh','qa-server.py','GEDEFENSE_4.2_TESTBEFUNDE.md','GEDEFENSE_4.2_CHANGELOG_KONSOLIDIERT.md',
    'GEDEFENSE_4.2_FIX_VERIFICATION.md','OPENAI_REWORK_PROGRESS.md','GeDefense_4.2_SECURITY_FABRIC_CONTROL_PLANE_PLAN.md'
}
excluded_suffixes = {'.zip','.run','.pyc'}
for path in sorted(src.rglob('*')):
    rel = path.relative_to(src)
    if any(part in excluded_dirs for part in rel.parts):
        continue
    if path.name in excluded_names or path.name.startswith('wsl-') or path.suffix.lower() in excluded_suffixes:
        continue
    target = dst / rel
    if path.is_dir():
        target.mkdir(parents=True, exist_ok=True)
    elif path.is_file() and not path.is_symlink():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
PY
(
  cd "$STAGE"
  find . -type f ! -name PAYLOAD-MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > PAYLOAD-MANIFEST.sha256
)
find "$STAGE" -exec touch -h -d "@$EPOCH" {} +

TAR_RAW="$WORK/source.tar"
TAR_GZ="$WORK/source.tar.gz"
tar --sort=name --format=gnu --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner -cf "$TAR_RAW" -C "$STAGE" .
gzip -n -9 -c "$TAR_RAW" > "$TAR_GZ"
PAYLOAD_SHA=$(sha256sum "$TAR_GZ" | awk '{print $1}')
HEADER="$WORK/header.sh"
sed -e "s/__SOURCE_PAYLOAD_SHA256__/$PAYLOAD_SHA/g" "$ROOT/scripts/oneclick-source-bootstrap-header.sh" > "$HEADER"
grep -q '^__VGT_SOURCE_PAYLOAD_BELOW__$' "$HEADER"
head -n "$(awk '/^__VGT_SOURCE_PAYLOAD_BELOW__$/{print NR; exit}' "$HEADER")" "$HEADER" | bash -n

OUTPUT="$OUT/GeDefense-${VERSION}-OneClick.run"
cat "$HEADER" "$TAR_GZ" > "$OUTPUT"
chmod 0755 "$OUTPUT"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"

# Independent embedded-payload verification.
VERIFY="$WORK/verify"
mkdir -p "$VERIFY"
LINE=$(awk '/^__VGT_SOURCE_PAYLOAD_BELOW__$/{print NR+1; exit}' "$OUTPUT")
tail -n +"$LINE" "$OUTPUT" > "$WORK/embedded.tar.gz"
[[ $(sha256sum "$WORK/embedded.tar.gz" | awk '{print $1}') == "$PAYLOAD_SHA" ]]
python3 - "$WORK/embedded.tar.gz" "$VERIFY" <<'PY'
import pathlib, sys, tarfile
archive, dst = sys.argv[1:]
root = pathlib.Path(dst).resolve()
with tarfile.open(archive, 'r:gz') as tf:
    for member in tf.getmembers():
        p=pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or member.issym() or member.islnk() or member.isdev():
            raise SystemExit(f'unsafe member: {member.name}')
    tf.extractall(root)
PY
(cd "$VERIFY" && sha256sum -c PAYLOAD-MANIFEST.sha256 >/dev/null)
[[ $(tr -d '\r\n' < "$VERIFY/VERSION") == "$VERSION" ]]

printf 'Created %s\n' "$OUTPUT"
printf 'SHA256 %s\n' "$(sha256sum "$OUTPUT" | awk '{print $1}')"
