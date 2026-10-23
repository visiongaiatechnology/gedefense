#!/usr/bin/env bash
# Build the self-contained desktop tray One-Click installer.
# Payload: desktop/tray source + public license notices. The payload checksum is
# embedded in the header; --self-test validates it before an operator installs.
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:-"$ROOT/dist/oneclick"}
VERSION=$(tr -d '\r\n' < "$ROOT/VERSION")
EPOCH=${SOURCE_DATE_EPOCH:-1785110400}
export SOURCE_DATE_EPOCH="$EPOCH"

for cmd in python3 tar gzip sha256sum bash; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "missing packaging tool: $cmd" >&2; exit 1; }
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-desktop-oneclick.XXXXXX")
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT

PAYLOAD_ROOT="$WORK/payload"
mkdir -p "$PAYLOAD_ROOT/desktop"
cp -a "$ROOT/desktop/tray" "$PAYLOAD_ROOT/desktop/tray"
rm -rf "$PAYLOAD_ROOT/desktop/tray/build" "$PAYLOAD_ROOT/desktop/tray/target"
cp "$ROOT/README.md" "$PAYLOAD_ROOT/README.md"
cp "$ROOT/LICENSE" "$PAYLOAD_ROOT/LICENSE"
cp "$ROOT/THIRD-PARTY-LICENSES.md" "$PAYLOAD_ROOT/THIRD-PARTY-LICENSES.md"

PAYLOAD="$WORK/payload.tar.gz"
tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
    -czf "$PAYLOAD" -C "$PAYLOAD_ROOT" .
PAYLOAD_SHA=$(sha256sum "$PAYLOAD" | awk '{print $1}')
HEADER="$WORK/header.sh"
python3 - "$ROOT/scripts/desktop-oneclick-header.sh" "$HEADER" "$VERSION" "$PAYLOAD_SHA" <<'PY'
import pathlib
import sys
template, output, version, digest = sys.argv[1:]
text = pathlib.Path(template).read_text(encoding="utf-8")
text = text.replace("__VERSION__", version).replace("__PAYLOAD_SHA256__", digest)
pathlib.Path(output).write_text(text, encoding="utf-8", newline="\n")
PY
grep -q '^__PAYLOAD_BELOW__$' "$HEADER"
bash -n "$HEADER"

mkdir -p "$OUT"
OUTPUT="$OUT/GeDefense-${VERSION}-Desktop-OneClick.run"
cat "$HEADER" "$PAYLOAD" > "$OUTPUT"
chmod 0755 "$OUTPUT"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"
printf 'Created %s\nSHA256 %s\n' "$OUTPUT" "$(sha256sum "$OUTPUT" | awk '{print $1}')"
