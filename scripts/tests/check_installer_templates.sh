#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Static syntax gate for the two installer header templates.
#
# The templates contain placeholders that are substituted by
# scripts/render-installer-header.py. This gate renders deterministic dummy
# values into a temporary copy and runs `bash -n` on the header section only
# (the appended payload is not part of the bash source).
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/vgt-header-syntax.XXXXXX")
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT

dummy_pub=$(python3 -c 'print("ab" * 32)')
dummy_b64=$(printf 'signed-release-index-placeholder' | base64 -w0)

render_template(){
  local template=$1 marker=$2 output=$3
  python3 - "$template" "$output" "$marker" "$dummy_pub" "$dummy_b64" <<'PY'
import sys
from pathlib import Path
template, output, marker, pub, b64 = sys.argv[1:]
substitutions = {
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
echo "ALL INSTALLER HEADER TEMPLATES PARSE"
