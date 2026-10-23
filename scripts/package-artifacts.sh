#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Build the signed GeDefense release artifacts (F-01/F-12/G-SC-01/G-STATE-01).
#
# Pipeline:
#   1. content gate on the committed HEAD tree (tracked allowlist + markers),
#   2. deterministic source ZIP (tracked HEAD tree only, manifest from shipped bytes),
#   3. pinned-toolchain Go build + required prebuilt Rust/eBPF artifacts,
#   4. SPDX SBOM + build provenance,
#   5. canonical Ed25519-signed release manifest (Go-compatible schema, the same
#      format control/release_manifest.go produces/verifies),
#   6. signed release index binding payload, source archive, SBOM, provenance and
#      manifest to the pinned release key,
#   7. rendered self-extracting installer whose header verifies the signed index
#      and signed manifest before any privileged action, plus anti-rollback,
#   8. full offline re-verification (fail closed) and SHA256SUMS.
#
# Requirements: RELEASE_SIGNING_PRIVATE_KEY + RELEASE_SIGNING_PUBLIC_KEY
# (offline 0600 raw Ed25519 key files). The private key is never read from or
# written to the repository.
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:-"$ROOT/dist/release"}
VERSION=$(tr -d '\r\n' < "$ROOT/VERSION")
EPOCH=${SOURCE_DATE_EPOCH:-1785110400}
ALLOW_DIRTY=${ALLOW_DIRTY:-0}
export SOURCE_DATE_EPOCH="$EPOCH"
export PYTHONDONTWRITEBYTECODE=1

: "${RELEASE_SIGNING_PRIVATE_KEY:?RELEASE_SIGNING_PRIVATE_KEY must point to the offline Ed25519 release key}"
: "${RELEASE_SIGNING_PUBLIC_KEY:?RELEASE_SIGNING_PUBLIC_KEY must point to the raw 32-byte public key}"

for cmd in go node python3 tar gzip sha256sum sed awk ldd grep git; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing build tool: $cmd" >&2; exit 1; }
done
"$ROOT/scripts/verify-release-toolchains.sh"
[[ $OUT != "$ROOT" && $OUT != "$ROOT"/* ]] || { echo "release output must live outside the repository: $OUT" >&2; exit 1; }
mkdir -p "$OUT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-gedefense-package.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

release_tool(){ python3 "$ROOT/scripts/release-tool.py" "$@"; }
PUBLIC_HEX=$(python3 - "$RELEASE_SIGNING_PUBLIC_KEY" <<'PY'
import pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
if len(raw) != 32:
    raise SystemExit("release public key must be 32 raw bytes")
print(raw.hex())
PY
)

echo "== content gate (tracked allowlist + FORBIDDEN_MARKERS) =="
release_tool gate-tree --repo "$ROOT" > "$WORK/gate.json"

echo "== pinned-toolchain Go build =="
cd "$ROOT"
if [[ $(git status --porcelain --untracked-files=no | wc -l) -ne 0 && $ALLOW_DIRTY -ne 1 ]]; then
  echo "working tree has uncommitted tracked changes; release build requires a clean committed tree (set ALLOW_DIRTY=1 only for local dry-runs)" >&2
  exit 1
fi
make go gateway
"$ROOT/scripts/security-audit.sh"
for binary in gedefense-control gedefense-access; do
  [[ -x "$ROOT/dist/$binary" ]] || { echo "missing built binary: dist/$binary" >&2; exit 1; }
done
[[ $("$ROOT/dist/gedefense-control" --version) == "$VERSION" ]]
[[ $("$ROOT/dist/gedefense-access" --version) == "${VERSION}-access" ]]
for artifact in gedefense-core gedefense-ebpf; do
  [[ -f "$ROOT/dist/$artifact" ]] || { echo "missing release artifact dist/$artifact - run 'make rust' with the pinned Rust toolchains first (fail closed)" >&2; exit 1; }
done
ldd "$ROOT/dist/gedefense-access" | grep -q 'libargon2.so.1'
! ldd "$ROOT/dist/gedefense-access" | grep -q 'not found'

echo "== deterministic source archive =="
python3 "$ROOT/scripts/pack_release_zip.py" --out-dir "$OUT" --epoch "$EPOCH" --verify-twice
SOURCE_NAME="VGT_GeDefense_Beta_v5_${VERSION}_Source.zip"
python3 - "$OUT/$SOURCE_NAME" "$OUT/SOURCE-MANIFEST.sha256" <<'PY'
import sys, zipfile
from pathlib import Path
archive, output = sys.argv[1:]
with zipfile.ZipFile(archive) as handle:
    names = [name for name in handle.namelist() if name.endswith('/SOURCE-MANIFEST.sha256')]
    if len(names) != 1:
        raise SystemExit("source archive must contain exactly one SOURCE-MANIFEST.sha256")
    Path(output).write_bytes(handle.read(names[0]))
PY

echo "== stage release binaries =="
RELEASE_STAGE="$WORK/release-stage"
mkdir -p "$RELEASE_STAGE"
install -m 0755 "$ROOT/dist/gedefense-control" "$RELEASE_STAGE/gedefense-control"
install -m 0755 "$ROOT/dist/gedefense-access" "$RELEASE_STAGE/gedefense-access"
install -m 0755 "$ROOT/dist/gedefense-core" "$RELEASE_STAGE/gedefense-core"
install -m 0644 "$ROOT/dist/gedefense-ebpf" "$RELEASE_STAGE/gedefense-ebpf"

echo "== SBOM + provenance =="
release_tool sbom --repo "$ROOT" --out "$RELEASE_STAGE/sbom.spdx.json" --epoch "$EPOCH" \
  --artifact "gedefense-control=$RELEASE_STAGE/gedefense-control" \
  --artifact "gedefense-access=$RELEASE_STAGE/gedefense-access" \
  --artifact "gedefense-core=$RELEASE_STAGE/gedefense-core" \
  --artifact "gedefense-ebpf=$RELEASE_STAGE/gedefense-ebpf" > "$WORK/sbom.json"
release_tool provenance --repo "$ROOT" --out "$RELEASE_STAGE/build-provenance.json" --epoch "$EPOCH" \
  --sbom "$RELEASE_STAGE/sbom.spdx.json" --source-manifest "$OUT/SOURCE-MANIFEST.sha256" \
  --artifact "gedefense-control=$RELEASE_STAGE/gedefense-control" \
  --artifact "gedefense-access=$RELEASE_STAGE/gedefense-access" \
  --artifact "gedefense-core=$RELEASE_STAGE/gedefense-core" \
  --artifact "gedefense-ebpf=$RELEASE_STAGE/gedefense-ebpf" > "$WORK/provenance.json"

echo "== sign canonical release manifest (Go-compatible schema) =="
release_tool sign-go-manifest --repo "$ROOT" --artifact-dir "$RELEASE_STAGE" \
  --out "$RELEASE_STAGE/release-manifest.signed.json" --epoch "$EPOCH" > "$WORK/manifest.json"
TOOLCHAINS_JSON=$(release_tool toolchains --repo "$ROOT")
release_tool verify-manifest --manifest "$RELEASE_STAGE/release-manifest.signed.json" \
  --pubkey "$RELEASE_SIGNING_PUBLIC_KEY" --expected-version "$VERSION" \
  --toolchains-json "$TOOLCHAINS_JSON" >/dev/null

echo "== build installer payload =="
PAYLOAD="$WORK/payload"
mkdir -p "$PAYLOAD/bin" "$PAYLOAD/rust" "$PAYLOAD/share" "$PAYLOAD/systemd" "$PAYLOAD/tmpfiles" "$PAYLOAD/templates" "$PAYLOAD/integration/linux" "$PAYLOAD/integration/nginx"
install -m 0755 "$ROOT/dist/gedefense-control" "$PAYLOAD/bin/gedefense-control"
install -m 0755 "$ROOT/dist/gedefense-access" "$PAYLOAD/bin/gedefense-access"
cp -a "$ROOT/rust/." "$PAYLOAD/rust/"
rm -rf "$PAYLOAD/rust/target"
for f in README.md VALIDATION.md SECURITY.md THIRD-PARTY-LICENSES.md CRYPTOGRAPHY.md TOOLCHAINS.lock; do install -m 0644 "$ROOT/$f" "$PAYLOAD/share/$f"; done
install -m 0644 "$RELEASE_STAGE/release-manifest.signed.json" "$PAYLOAD/share/release-manifest.signed.json"
install -m 0644 "$RELEASE_STAGE/sbom.spdx.json" "$PAYLOAD/share/sbom.spdx.json"
install -m 0644 "$RELEASE_STAGE/build-provenance.json" "$PAYLOAD/share/build-provenance.json"
install -m 0644 "$ROOT"/packaging/systemd/* "$PAYLOAD/systemd/"
install -m 0644 "$ROOT/packaging/tmpfiles/vgt-gedefense-l7.conf" "$PAYLOAD/tmpfiles/vgt-gedefense-l7.conf"
install -m 0644 "$ROOT/gedefense.toml" "$PAYLOAD/templates/gedefense.toml"
install -m 0644 "$ROOT/malware-hashes.sha256" "$PAYLOAD/templates/malware-hashes.sha256"
if [[ -f "$ROOT/geoip.csv" ]]; then install -m 0644 "$ROOT/geoip.csv" "$PAYLOAD/templates/geoip.csv"; fi
if [[ -f "$ROOT/geoip.csv.sha256" ]]; then install -m 0644 "$ROOT/geoip.csv.sha256" "$PAYLOAD/templates/geoip.csv.sha256"; fi
install -m 0755 "$ROOT/integration/linux/gedefense-app" "$PAYLOAD/integration/linux/gedefense-app"
install -m 0755 "$ROOT/integration/linux/gedefense-ensure-ready" "$PAYLOAD/integration/linux/gedefense-ensure-ready"
install -m 0644 "$ROOT/integration/linux/gedefense.desktop" "$PAYLOAD/integration/linux/gedefense.desktop"
install -m 0644 "$ROOT/integration/linux/org.vgt.gedefense.policy" "$PAYLOAD/integration/linux/org.vgt.gedefense.policy"
install -m 0644 "$ROOT/integration/nginx/gedefense-l7.conf.example" "$PAYLOAD/integration/nginx/gedefense-l7.conf.example"
install -m 0644 "$ROOT/integration/nginx/README.md" "$PAYLOAD/integration/nginx/README.md"
PAYLOAD_TAR="$WORK/payload.tar.gz"
release_tool tar-gz --dir "$PAYLOAD" --out "$PAYLOAD_TAR" --epoch "$EPOCH" > "$WORK/payload.json"
PAYLOAD_SHA=$(python3 -c "import json;print(json.load(open('$WORK/payload.json'))['sha256'])")
CONTROL_SHA=$(sha256sum "$PAYLOAD/bin/gedefense-control" | awk '{print $1}')
ACCESS_SHA=$(sha256sum "$PAYLOAD/bin/gedefense-access" | awk '{print $1}')

echo "== assemble signed release index =="
ASSETS="$WORK/assets"
mkdir -p "$ASSETS"
cp "$RELEASE_STAGE/gedefense-control" "$ASSETS/gedefense-control"
cp "$RELEASE_STAGE/gedefense-access" "$ASSETS/gedefense-access"
cp "$RELEASE_STAGE/gedefense-core" "$ASSETS/gedefense-core"
cp "$RELEASE_STAGE/gedefense-ebpf" "$ASSETS/gedefense-ebpf"
cp "$RELEASE_STAGE/sbom.spdx.json" "$ASSETS/sbom.spdx.json"
cp "$RELEASE_STAGE/build-provenance.json" "$ASSETS/build-provenance.json"
cp "$RELEASE_STAGE/release-manifest.signed.json" "$ASSETS/release-manifest.signed.json"
cp "$PAYLOAD_TAR" "$ASSETS/payload.tar.gz"
cp "$OUT/$SOURCE_NAME" "$ASSETS/$SOURCE_NAME"
cp "$OUT/$SOURCE_NAME.sha256" "$ASSETS/$SOURCE_NAME.sha256"
release_tool sign-index --repo "$ROOT" --artifacts-dir "$ASSETS" \
  --out "$ASSETS/release-index.signed.json" --epoch "$EPOCH" \
  --role "payload.tar.gz=installer-payload" \
  --role "$SOURCE_NAME=source-archive" \
  --role "sbom.spdx.json=sbom" --role "build-provenance.json=provenance" \
  --role "release-manifest.signed.json=release-manifest" > "$WORK/index.json"
release_tool verify-index --index "$ASSETS/release-index.signed.json" \
  --pubkey "$RELEASE_SIGNING_PUBLIC_KEY" --expected-version "$VERSION" \
  --artifact-file "payload.tar.gz=$ASSETS/payload.tar.gz" \
  --artifact-file "gedefense-control=$ASSETS/gedefense-control" \
  --artifact-file "gedefense-access=$ASSETS/gedefense-access" >/dev/null

echo "== render signed installer =="
HEADER="$WORK/installer-header.sh"
python3 "$ROOT/scripts/render-installer-header.py" \
  --template "$ROOT/scripts/oneclick-installer-header.sh" \
  --output "$HEADER" \
  --public-key-hex "$PUBLIC_HEX" \
  --index "$ASSETS/release-index.signed.json" \
  --verifier "$ROOT/scripts/vgt_release_security.py" \
  --trust-mode prebuilt \
  --payload-sha256 "$PAYLOAD_SHA" \
  --control-sha256 "$CONTROL_SHA" \
  --access-sha256 "$ACCESS_SHA"
grep -q '^__VGT_PAYLOAD_BELOW__$' "$HEADER"
head -n "$(awk '/^__VGT_PAYLOAD_BELOW__$/{print NR; exit}' "$HEADER")" "$HEADER" | bash -n
RUN_NAME="VGT_GeDefense_Beta_v5_${VERSION}_OneClick.run"
cat "$HEADER" "$PAYLOAD_TAR" > "$OUT/$RUN_NAME"
chmod 0755 "$OUT/$RUN_NAME"
python3 "$ROOT/scripts/tests/verify_rendered_installer.py" \
  --installer "$OUT/$RUN_NAME" --public-key-hex "$PUBLIC_HEX" \
  --expected-version "$VERSION" --expected-payload-sha "$PAYLOAD_SHA" >/dev/null

echo "== publish signed artifacts to $OUT =="
for asset in gedefense-control gedefense-access gedefense-core gedefense-ebpf \
             sbom.spdx.json build-provenance.json release-manifest.signed.json \
             payload.tar.gz release-index.signed.json; do
  cp "$ASSETS/$asset" "$OUT/$asset"
done
sha256sum "$OUT/$RUN_NAME" > "$OUT/$RUN_NAME.sha256"
( cd "$OUT" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS' -printf '%f\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS )

echo "== final offline verification (fail closed) =="
release_tool verify-release --dir "$OUT" --pubkey "$RELEASE_SIGNING_PUBLIC_KEY" \
  --expected-version "$VERSION" --require-manifest --check-manifests-artifacts >/dev/null
release_tool verify-archive --archive "$OUT/$SOURCE_NAME" >/dev/null
release_tool verify-archive --archive "$OUT/payload.tar.gz" >/dev/null
python3 "$ROOT/scripts/tests/verify_rendered_installer.py" \
  --installer "$OUT/$RUN_NAME" --public-key-hex "$PUBLIC_HEX" \
  --expected-version "$VERSION" --expected-payload-sha "$PAYLOAD_SHA" >/dev/null
( cd "$OUT" && sha256sum -c SHA256SUMS >/dev/null )

cat > "$OUT/RELEASE-MANIFEST.txt" <<EOF
product: VGT GeDefense
version: $VERSION
channel: $(python3 -c "import sys;sys.path.insert(0,'$ROOT/scripts');import vgt_release_security as s;print(s.channel_for_version('$VERSION'))")
commit: $(git -C "$ROOT" rev-parse HEAD)
tree_clean: $([[ $ALLOW_DIRTY -eq 1 ]] && echo false || echo true)
release_key_sha256: $(python3 -c "import sys;sys.path.insert(0,'$ROOT/scripts');import vgt_release_security as s;print(s.sha256_bytes(bytes.fromhex('$PUBLIC_HEX')))")
source_archive: $SOURCE_NAME
installer: $RUN_NAME
signed_manifest: release-manifest.signed.json
signed_index: release-index.signed.json
sbom: sbom.spdx.json
provenance: build-provenance.json
external_blockers:
  - public CA code-signing identity
  - RFC3161 timestamp
  - CRL/OCSP revocation
  - externally anchored anti-rollback channel
EOF

printf 'Created and verified release assets in %s\n' "$OUT"
printf 'Installer SHA256: %s\n' "$(sha256sum "$OUT/$RUN_NAME" | awk '{print $1}')"
