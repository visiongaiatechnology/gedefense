#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Cross-implementation verification of the signed release manifest (G-STATE-01).
#
# Proves interoperability between the Python release tooling and the existing Go
# implementation in control/release_manifest.go (which the Lead/task-11 wiring
# may use):
#   * Python-signed manifest  -> verified by the Go control binary,
#   * Go-signed manifest      -> verified by the Python verifier,
#   * Python-signed index     -> signature verified independently by OpenSSL.
#
# Usage: go_manifest_crosscheck.sh --control-binary /path/to/linux/gedefense-control
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
PYTHON=${PYTHON:-python3}
CONTROL_BINARY=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --control-binary) CONTROL_BINARY=${2:?}; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ -n $CONTROL_BINARY && -x $CONTROL_BINARY ]] || { echo "--control-binary must point to an executable Linux gedefense-control build" >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl missing" >&2; exit 2; }

VERSION=$(tr -d '\r\n' < "$ROOT/VERSION")
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1785110400}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-manifest-crosscheck.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

"$PYTHON" "$ROOT/scripts/release-tool.py" keygen --out "$WORK/keys" >/dev/null
PUBKEY="$WORK/keys/release-public.key"
PRIVKEY="$WORK/keys/release-private.key"
ARTIFACTS="$WORK/artifacts"
mkdir -p "$ARTIFACTS"
for name in gedefense-control gedefense-core gedefense-ebpf; do printf 'fixture %s\n' "$name" > "$ARTIFACTS/$name"; done
printf '{"spdxVersion":"SPDX-2.3"}\n' > "$ARTIFACTS/sbom.spdx.json"
printf '{"schema":"vgt.gedefense.build-provenance.v1"}\n' > "$ARTIFACTS/build-provenance.json"

echo "== Python-signed manifest verified by the Go control binary =="
"$PYTHON" "$ROOT/scripts/release-tool.py" sign-go-manifest --repo "$ROOT" --artifact-dir "$ARTIFACTS" \
  --out "$WORK/python-manifest.json" --private-key "$PRIVKEY" >/dev/null
"$CONTROL_BINARY" --verify-release-manifest "$WORK/python-manifest.json" \
  --release-public-key "$PUBKEY" --release-artifact-dir "$ARTIFACTS" \
  || { echo "FAIL: Go verifier rejected the Python-signed manifest" >&2; exit 1; }
echo "PASS: Go verifier accepted the Python-signed manifest"

echo "== Go-signed manifest verified by the Python verifier =="
"$CONTROL_BINARY" --sign-release-dir "$ARTIFACTS" --release-private-key "$PRIVKEY" \
  --release-public-key "$PUBKEY" --release-manifest-output "$WORK/go-manifest.json" >/dev/null
TOOLCHAINS=$("$PYTHON" "$ROOT/scripts/release-tool.py" toolchains --repo "$ROOT")
"$PYTHON" "$ROOT/scripts/release-tool.py" verify-manifest --manifest "$WORK/go-manifest.json" \
  --pubkey "$PUBKEY" --expected-version "$VERSION" --toolchains-json "$TOOLCHAINS" >/dev/null \
  || { echo "FAIL: Python verifier rejected the Go-signed manifest" >&2; exit 1; }
echo "PASS: Python verifier accepted the Go-signed manifest"

echo "== Python-signed index verified independently by OpenSSL Ed25519 =="
mkdir -p "$WORK/index-assets"
printf 'signed-payload\n' > "$WORK/index-assets/payload.tar.gz"
"$PYTHON" "$ROOT/scripts/release-tool.py" sign-index --repo "$ROOT" --artifacts-dir "$WORK/index-assets" \
  --out "$WORK/index-assets/release-index.signed.json" --private-key "$PRIVKEY" >/dev/null
"$PYTHON" - "$WORK/index-assets/release-index.signed.json" "$PUBKEY" "$WORK" "$ROOT" <<'PY'
import base64, hashlib, json, pathlib, sys
index_path, pubkey_path, work, root = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(root) / "scripts"))
import importlib
security = importlib.import_module("vgt_release_security")
document = json.loads(pathlib.Path(index_path).read_text(encoding="utf-8"))
payload = security.canonical_json_bytes(document["index"])
message = security.RELEASE_INDEX_DOMAIN + payload
signature = security.base64url_decode(document["signature"])
public = pathlib.Path(pubkey_path).read_bytes()
# Write raw public key as DER SubjectPublicKeyInfo (1.3.101.112 = Ed25519).
der = bytes.fromhex("302a300506032b6570032100") + public
pathlib.Path(work, "message.bin").write_bytes(message)
pathlib.Path(work, "signature.bin").write_bytes(signature)
pathlib.Path(work, "public.der").write_bytes(der)
PY
openssl pkeyutl -verify -pubin -keyform DER -inkey "$WORK/public.der" \
  -rawin -in "$WORK/message.bin" -sigfile "$WORK/signature.bin" >/dev/null \
  || { echo "FAIL: OpenSSL rejected the Python Ed25519 signature" >&2; exit 1; }
echo "PASS: OpenSSL independently verified the release-index Ed25519 signature"

echo "GO-MANIFEST-CROSSCHECK PASSED"
