#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Build the self-contained source One-Click installer (F-01/F-02/F-12).
#
# Guarantees:
# * payload contains only the committed HEAD tree (git archive), minus internal
#   operational/audit documents, and passes the shared FORBIDDEN_MARKERS gate,
# * deterministic tar.gz (fixed epoch/order/owner) and deterministic payload,
# * SBOM + build provenance are generated and signed into a release index with
#   the local Ed25519 release key; the installer header embeds the signed index,
#   the trusted public key and a stdlib-only verifier and refuses to run without
#   a valid signature,
# * no writes inside the repository and no network access.
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:-"$ROOT/dist/oneclick"}
VERSION=$(tr -d '\r\n' < "$ROOT/VERSION")
EPOCH=${SOURCE_DATE_EPOCH:-1785110400}
ALLOW_DIRTY=0
if [[ ${2:-} == "--allow-dirty" ]]; then ALLOW_DIRTY=1; fi
export SOURCE_DATE_EPOCH="$EPOCH"

for cmd in python3 git tar gzip sha256sum bash; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing packaging tool: $cmd" >&2; exit 1; }
done
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-oneclick-build.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

echo "== content gate =="
python3 "$ROOT/scripts/release-tool.py" gate-tree --repo "$ROOT" > "$WORK/gate.json"

echo "== deterministic source payload (committed HEAD tree) =="
STAGE_ARGS=(stage-source --repo "$ROOT" --stage "$WORK/source" --tar-out "$WORK/payload.tar.gz" --epoch "$EPOCH")
if [[ $ALLOW_DIRTY -eq 1 ]]; then STAGE_ARGS+=(--allow-dirty); fi
python3 "$ROOT/scripts/release-tool.py" "${STAGE_ARGS[@]}" > "$WORK/stage.json"
PAYLOAD_SHA=$(python3 -c "import json;print(json.load(open('$WORK/stage.json'))['payload_sha256'])")
COMMIT=$(python3 -c "import json;print(json.load(open('$WORK/stage.json'))['commit'])")
TREE_CLEAN=$(python3 -c "import json;print(str(json.load(open('$WORK/stage.json'))['tree_clean']).lower())")
printf '%s\n' "$PAYLOAD_SHA" > "$WORK/payload.sha256"

echo "== SBOM + build provenance =="
ASSETS="$WORK/assets"
mkdir -p "$ASSETS"
cp "$WORK/payload.tar.gz" "$ASSETS/payload.tar.gz"
python3 "$ROOT/scripts/release-tool.py" sbom --repo "$ROOT" --out "$ASSETS/sbom.spdx.json" --epoch "$EPOCH" \
  --artifact "payload.tar.gz=$ASSETS/payload.tar.gz" > "$WORK/sbom.json"
python3 "$ROOT/scripts/release-tool.py" provenance --repo "$ROOT" --out "$ASSETS/build-provenance.json" --epoch "$EPOCH" \
  --sbom "$ASSETS/sbom.spdx.json" --source-manifest "$WORK/source/SOURCE-MANIFEST.sha256" \
  --artifact "payload.tar.gz=$ASSETS/payload.tar.gz" > "$WORK/provenance.json"

echo "== sign release index =="
python3 "$ROOT/scripts/release-tool.py" sign-index --repo "$ROOT" --artifacts-dir "$ASSETS" \
  --out "$ASSETS/release-index.signed.json" --epoch "$EPOCH" \
  --role payload.tar.gz=installer-payload --role sbom.spdx.json=sbom --role build-provenance.json=provenance > "$WORK/index.json"
python3 "$ROOT/scripts/release-tool.py" verify-index --index "$ASSETS/release-index.signed.json" \
  --pubkey "$RELEASE_SIGNING_PUBLIC_KEY" --expected-version "$VERSION" \
  --artifact-file "payload.tar.gz=$ASSETS/payload.tar.gz" >/dev/null

echo "== render + verify installer =="
mkdir -p "$OUT"
HEADER="$WORK/header.sh"
python3 "$ROOT/scripts/render-installer-header.py" \
  --template "$ROOT/scripts/oneclick-source-bootstrap-header.sh" \
  --output "$HEADER" \
  --public-key-hex "$PUBLIC_HEX" \
  --index "$ASSETS/release-index.signed.json" \
  --verifier "$ROOT/scripts/vgt_release_security.py" \
  --trust-mode source-signed \
  --source-payload-sha256 "$PAYLOAD_SHA"
grep -q '^__VGT_SOURCE_PAYLOAD_BELOW__$' "$HEADER"
head -n "$(awk '/^__VGT_SOURCE_PAYLOAD_BELOW__$/{print NR; exit}' "$HEADER")" "$HEADER" | bash -n
OUTPUT="$OUT/GeDefense-${VERSION}-OneClick.run"
cat "$HEADER" "$WORK/payload.tar.gz" > "$OUTPUT"
chmod 0755 "$OUTPUT"
python3 "$ROOT/scripts/tests/verify_rendered_installer.py" \
  --installer "$OUTPUT" --public-key-hex "$PUBLIC_HEX" --expected-version "$VERSION" \
  --expected-payload-sha "$PAYLOAD_SHA" >/dev/null
(cd "$OUT" && sha256sum "$(basename "$OUTPUT")" > "$(basename "$OUTPUT").sha256")

echo "== publish signed metadata sidecars to $OUT =="
for name in release-index.signed.json sbom.spdx.json build-provenance.json; do
  cp "$ASSETS/$name" "$OUT/$name"
done
printf '%s  %s\n' "$PAYLOAD_SHA" 'payload.tar.gz' > "$OUT/payload.tar.gz.sha256"
python3 - "$OUT" "$VERSION" "$COMMIT" "$TREE_CLEAN" "$EPOCH" <<'PY'
import json, pathlib, sys
out, version, commit, clean, epoch = sys.argv[1:]
document = {
    "schema": "vgt.gedefense.source-release-notes.v1",
    "product": "VGT GeDefense",
    "version": version,
    "channel": "beta" if "-" in version else "stable",
    "commit": commit,
    "tree_clean": clean == "true",
    "source_date_epoch": int(epoch),
    "signed_assets": ["release-index.signed.json", "sbom.spdx.json", "build-provenance.json", "payload.tar.gz.sha256"],
    "anti_rollback": "installer enforces semantic version monotonicity and a local release floor",
    "external_blockers": [
        "public CA code-signing identity",
        "RFC3161 timestamp",
        "CRL/OCSP revocation",
        "externally anchored anti-rollback channel",
    ],
}
pathlib.Path(out, "source-release.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf 'Created %s\n' "$OUTPUT"
printf 'SHA256 %s\n' "$(sha256sum "$OUTPUT" | awk '{print $1}')"
printf 'Payload SHA256 %s\n' "$PAYLOAD_SHA"
printf 'Commit %s (tree_clean=%s)\n' "$COMMIT" "$TREE_CLEAN"
