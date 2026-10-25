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
import re, sys
from pathlib import Path
template, output, marker, pub, b64 = sys.argv[1:]
text = Path(template).read_text(encoding="utf-8")
text = text.replace("__RELEASE_PUBKEY_HEX__", pub)
text = text.replace("__RELEASE_INDEX_B64__", b64)
text = text.replace("__RELEASE_VERIFIER_B64__", b64)
text = text.replace("__RELEASE_TRUST_MODE__", "prebuilt")
text = text.replace("__SOURCE_PAYLOAD_SHA256__", "0" * 64)
text = text.replace("__PAYLOAD_SHA256__", "0" * 64)
text = text.replace("__CONTROL_SHA256__", "0" * 64)
text = text.replace("__ACCESS_SHA256__", "0" * 64)
header = text.split("\n" + marker + "\n")[0]
if "__RELEASE_" in header or "__PAYLOAD_SHA256__" in header:
    raise SystemExit(f"unrendered placeholders remain in {template}")
Path(output).write_text(header, encoding="utf-8", newline="\n")
PY
  bash -n "$output"
  echo "PASS: bash -n $template"
}

render_template "$ROOT/scripts/oneclick-installer-header.sh" "__VGT_PAYLOAD_BELOW__" "$work/installer-header.sh"
render_template "$ROOT/scripts/oneclick-source-bootstrap-header.sh" "__VGT_SOURCE_PAYLOAD_BELOW__" "$work/source-bootstrap-header.sh"
echo "ALL INSTALLER HEADER TEMPLATES PARSE"
