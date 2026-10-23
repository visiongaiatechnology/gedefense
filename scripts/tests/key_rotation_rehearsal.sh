#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Rehearsal for release-key rotation + revocation (G-SC-12 / F-16).
#
# Uses throwaway Ed25519 keys in a temporary directory (never the real release
# key) to prove that:
#   1. an index signed with the current key verifies,
#   2. after revocation of that key the verifier refuses the same index,
#   3. an index signed with the rotated key verifies against the new key and is
#      rejected by the old key.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
PYTHON=${PYTHON:-python3}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-key-rotation-rehearsal.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

release_tool(){ "$PYTHON" "$ROOT/scripts/release-tool.py" "$@"; }

echo "== generate throwaway release keys =="
release_tool keygen --out "$WORK/current" > "$WORK/current-key.json"
release_tool keygen --out "$WORK/rotated" > "$WORK/rotated-key.json"
CURRENT_FINGERPRINT=$("$PYTHON" -c "import json;print(json.load(open('$WORK/current-key.json'))['fingerprint_sha256'])")
ROTATED_FINGERPRINT=$("$PYTHON" -c "import json;print(json.load(open('$WORK/rotated-key.json'))['fingerprint_sha256'])")

mkdir -p "$WORK/assets"
printf 'payload\n' > "$WORK/assets/payload.tar.gz"

echo "== sign index with current key =="
release_tool sign-index --repo "$ROOT" --artifacts-dir "$WORK/assets" \
  --out "$WORK/assets/release-index.old.signed.json" --private-key "$WORK/current/release-private.key" >/dev/null
release_tool verify-index --index "$WORK/assets/release-index.old.signed.json" \
  --pubkey "$WORK/current/release-public.key" --expected-version "$(tr -d '\r\n' < "$ROOT/VERSION")" >/dev/null
echo "PASS: index signed by current key verifies"

echo "== publish revocation of the current key =="
"$PYTHON" - "$WORK/revocations.json" "$CURRENT_FINGERPRINT" <<'PY'
import json, sys
path, fingerprint = sys.argv[1:]
document = {
    "schema": "vgt.gedefense.release-key-revocations.v1",
    "issued_at": "2026-07-25T00:00:00Z",
    "revoked": [
        {"fingerprint": fingerprint, "reason": "rehearsal rotation of the release key", "replacement_key_fingerprint": ""},
    ],
}
open(path, "w", encoding="utf-8").write(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
if release_tool verify-index --index "$WORK/assets/release-index.old.signed.json" \
  --pubkey "$WORK/current/release-public.key" --expected-version "$(tr -d '\r\n' < "$ROOT/VERSION")" \
  --revocation-list "$WORK/revocations.json" >/dev/null 2>&1; then
  echo "FAIL: revoked key was still accepted" >&2
  exit 1
fi
echo "PASS: revoked key is refused (fail closed)"

echo "== rotate to new key =="
release_tool sign-index --repo "$ROOT" --artifacts-dir "$WORK/assets" \
  --out "$WORK/assets/release-index.new.signed.json" --private-key "$WORK/rotated/release-private.key" >/dev/null
release_tool verify-index --index "$WORK/assets/release-index.new.signed.json" \
  --pubkey "$WORK/rotated/release-public.key" --expected-version "$(tr -d '\r\n' < "$ROOT/VERSION")" \
  --revocation-list "$WORK/revocations.json" >/dev/null
if release_tool verify-index --index "$WORK/assets/release-index.new.signed.json" \
  --pubkey "$WORK/current/release-public.key" --expected-version "$(tr -d '\r\n' < "$ROOT/VERSION")" >/dev/null 2>&1; then
  echo "FAIL: rotated index verified against the retired/revoked key" >&2
  exit 1
fi
echo "PASS: rotated key verifies; retired key rejected"

"$PYTHON" - "$WORK/report.json" "$CURRENT_FINGERPRINT" "$ROTATED_FINGERPRINT" <<'PY'
import json, sys
path, current, rotated = sys.argv[1:]
report = {
    "schema": "vgt.gedefense.key-rotation-rehearsal.v1",
    "status": "PASS",
    "revoked_key_fingerprint": current,
    "rotation_key_fingerprint": rotated,
    "verified": [
        "current key verifies its index",
        "revoked key is refused",
        "rotated key verifies its index",
        "retired key cannot verify the rotated index",
    ],
    "note": "Throwaway keys only; the real release key ceremony and public revocation publication remain an external operational task.",
}
open(path, "w", encoding="utf-8").write(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY
cat "$WORK/report.json"
echo "KEY-ROTATION-REHEARSAL PASSED"
