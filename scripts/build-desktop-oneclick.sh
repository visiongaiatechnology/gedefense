#!/usr/bin/env bash
# Build the self-contained desktop tray One-Click installer.
# Payload: desktop/tray source + public license notices.
#
# FIND-001 security contract: the payload is hashed and signed into the release
# index with the offline Ed25519 release key. The rendered header embeds the
# signed release index, the trusted release public key and the stdlib-only
# verifier, so the installer verifies SHA-256 and the Ed25519 signature BEFORE it
# extracts a single archive member (fail closed, offline --self-test included).
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:-"$ROOT/dist/oneclick"}
VERSION=$(tr -d '\r\n' < "$ROOT/VERSION")
EPOCH=${SOURCE_DATE_EPOCH:-1785110400}
export SOURCE_DATE_EPOCH="$EPOCH"

: "${RELEASE_SIGNING_PRIVATE_KEY:?RELEASE_SIGNING_PRIVATE_KEY must point to the offline Ed25519 release key}"
: "${RELEASE_SIGNING_PUBLIC_KEY:?RELEASE_SIGNING_PUBLIC_KEY must point to the raw 32-byte public key}"
PUBLIC_HEX=$(python3 - "$RELEASE_SIGNING_PUBLIC_KEY" <<'PY'
import pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
if len(raw) != 32:
    raise SystemExit("release public key must be 32 raw bytes")
print(raw.hex())
PY
)

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

echo "== sign desktop payload into the Ed25519 release index =="
ASSETS="$WORK/assets"
mkdir -p "$ASSETS"
cp "$PAYLOAD" "$ASSETS/payload.tar.gz"
python3 "$ROOT/scripts/release-tool.py" sign-index --repo "$ROOT" --artifacts-dir "$ASSETS" \
    --out "$ASSETS/release-index.signed.json" --epoch "$EPOCH" \
    --role payload.tar.gz=installer-payload > "$WORK/index.json"
python3 "$ROOT/scripts/release-tool.py" verify-index --index "$ASSETS/release-index.signed.json" \
    --pubkey "$RELEASE_SIGNING_PUBLIC_KEY" --expected-version "$VERSION" \
    --artifact-file "payload.tar.gz=$ASSETS/payload.tar.gz" >/dev/null

echo "== render + verify installer =="
HEADER="$WORK/header.sh"
python3 "$ROOT/scripts/render-installer-header.py" \
    --template "$ROOT/scripts/desktop-oneclick-header.sh" \
    --output "$HEADER" \
    --public-key-hex "$PUBLIC_HEX" \
    --index "$ASSETS/release-index.signed.json" \
    --verifier "$ROOT/scripts/vgt_release_security.py" \
    --trust-mode prebuilt \
    --product-version "$VERSION" \
    --payload-sha256 "$PAYLOAD_SHA"
grep -q '^__VGT_PAYLOAD_BELOW__$' "$HEADER"
! grep -q '__RELEASE_\|__PAYLOAD_SHA256__\|__VERSION__' "$HEADER" \
    || { echo "rendered header still contains unresolved placeholders" >&2; exit 1; }
head -n "$(awk '/^__VGT_PAYLOAD_BELOW__$/{print NR; exit}' "$HEADER")" "$HEADER" | bash -n

mkdir -p "$OUT"
OUTPUT="$OUT/GeDefense-${VERSION}-Desktop-OneClick.run"
cat "$HEADER" "$PAYLOAD" > "$OUTPUT"
chmod 0755 "$OUTPUT"

# Fail closed before publishing: the installer must pass its own signature gate
# and an independent static verification of the embedded index/payload.
"$OUTPUT" --self-test >/dev/null
python3 "$ROOT/scripts/tests/verify_rendered_installer.py" \
    --installer "$OUTPUT" --public-key-hex "$PUBLIC_HEX" --expected-version "$VERSION" \
    --expected-payload-sha "$PAYLOAD_SHA" >/dev/null
cp "$ASSETS/release-index.signed.json" "$OUT/release-index.signed.json"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"
printf 'Created %s\nSHA256 %s\n' "$OUTPUT" "$(sha256sum "$OUTPUT" | awk '{print $1}')"
