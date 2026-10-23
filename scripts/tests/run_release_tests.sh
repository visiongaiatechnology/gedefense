#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Local equivalent of the CI supply-chain gate. Runs the release-security unit
# tests plus offline positive/negative CLI rehearsals (keygen, sign/verify,
# tamper rejection, downgrade rejection, content gate).
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
PYTHON=${PYTHON:-python3}

work=$(mktemp -d "${TMPDIR:-/tmp}/vgt-release-tests.XXXXXX")
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT

echo "== unit tests =="
"$PYTHON" -m unittest discover -s "$ROOT/scripts/tests" -p 'test_*.py' -v

echo "== keygen + sign + verify (offline rehearsal) =="
"$PYTHON" "$ROOT/scripts/release-tool.py" keygen --out "$work/keys" >/dev/null
"$PYTHON" "$ROOT/scripts/release-tool.py" gate-tree --repo "$ROOT" >/dev/null

mkdir -p "$work/artifacts"
for name in gedefense-control gedefense-core gedefense-ebpf; do
  printf 'release fixture %s\n' "$name" > "$work/artifacts/$name"
done
printf '{"spdxVersion":"SPDX-2.3"}\n' > "$work/artifacts/sbom.spdx.json"
printf '{"schema":"vgt.gedefense.build-provenance.v1"}\n' > "$work/artifacts/build-provenance.json"
printf 'signed payload fixture\n' > "$work/artifacts/payload.tar.gz"

SOURCE_DATE_EPOCH=1785110400 "$PYTHON" "$ROOT/scripts/release-tool.py" sign-go-manifest \
  --repo "$ROOT" --artifact-dir "$work/artifacts" --out "$work/artifacts/release-manifest.signed.json" \
  --private-key "$work/keys/release-private.key" >/dev/null
TOOLCHAINS=$("$PYTHON" "$ROOT/scripts/release-tool.py" toolchains --repo "$ROOT")
SOURCE_DATE_EPOCH=1785110400 "$PYTHON" "$ROOT/scripts/release-tool.py" verify-manifest \
  --manifest "$work/artifacts/release-manifest.signed.json" --pubkey "$work/keys/release-public.key" \
  --expected-version "$(tr -d '\r\n' < "$ROOT/VERSION")" --toolchains-json "$TOOLCHAINS" >/dev/null

SOURCE_DATE_EPOCH=1785110400 "$PYTHON" "$ROOT/scripts/release-tool.py" sign-index \
  --repo "$ROOT" --artifacts-dir "$work/artifacts" --out "$work/artifacts/release-index.signed.json" \
  --private-key "$work/keys/release-private.key" >/dev/null
"$PYTHON" "$ROOT/scripts/release-tool.py" verify-release \
  --dir "$work/artifacts" --pubkey "$work/keys/release-public.key" \
  --expected-version "$(tr -d '\r\n' < "$ROOT/VERSION")" --require-manifest >/dev/null
echo "PASS: signed manifest + signed index verify"

echo "== negative: tampered payload must be rejected =="
printf 'tampered\n' >> "$work/artifacts/payload.tar.gz"
if "$PYTHON" "$ROOT/scripts/release-tool.py" verify-release --dir "$work/artifacts" --pubkey "$work/keys/release-public.key" >/dev/null 2>&1; then
  echo "FAIL: tampered release directory was accepted" >&2
  exit 1
fi
printf 'signed payload fixture\n' > "$work/artifacts/payload.tar.gz"
echo "PASS: tampering rejected (fail closed)"

echo "== negative: unsigned / foreign index must be rejected =="
"$PYTHON" "$ROOT/scripts/release-tool.py" keygen --out "$work/other-keys" >/dev/null
if "$PYTHON" "$ROOT/scripts/release-tool.py" verify-release --dir "$work/artifacts" --pubkey "$work/other-keys/release-public.key" >/dev/null 2>&1; then
  echo "FAIL: release verified with a foreign public key" >&2
  exit 1
fi
echo "PASS: foreign key rejected"

echo "== anti-rollback / version monotonicity =="
"$PYTHON" "$ROOT/scripts/release-tool.py" version-guard --candidate 5.0.0 --installed 5.0.0-beta.1 >/dev/null
if "$PYTHON" "$ROOT/scripts/release-tool.py" version-guard --candidate 5.0.0-beta.1 --installed 5.0.0 >/dev/null 2>&1; then
  echo "FAIL: downgrade was accepted" >&2
  exit 1
fi
if "$PYTHON" "$ROOT/scripts/release-tool.py" version-guard --candidate 5.0.0-beta.1 --installed 5.0.0 --allow-downgrade >/dev/null 2>&1; then
  : # explicit recovery is allowed
else
  echo "FAIL: explicit recovery downgrade was rejected" >&2
  exit 1
fi
if "$PYTHON" "$ROOT/scripts/release-tool.py" version-guard --candidate 5.0.0-beta.1 --floor 5.0.0 --allow-downgrade >/dev/null 2>&1; then
  echo "FAIL: candidate below the release floor was accepted" >&2
  exit 1
fi
echo "PASS: upgrades accepted, downgrades/floor violations rejected"

echo "== content gate: FORBIDDEN_MARKERS detects a synthetic leak =="
mkdir -p "$work/gate"
printf 'clean\n' > "$work/gate/clean.txt"
"$PYTHON" - "$work/gate" "$ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[2] + "/scripts")
import vgt_release_security as security
from pathlib import Path
root = Path(sys.argv[1])
(root / "leak.txt").write_bytes(b"prefix" + security.FORBIDDEN_MARKERS[0] + b"suffix")
try:
    security.scan_tree_markers(root)
except security.GateError:
    print("PASS: synthetic forbidden marker rejected")
    raise SystemExit(0)
raise SystemExit("FAIL: marker gate accepted a leak")
PY

echo "== deterministic packaging: two builds byte-identical =="
"$PYTHON" "$ROOT/scripts/release-tool.py" pack-source --repo "$ROOT" --out-dir "$work/pack" --epoch 1785110400 --verify-twice --allow-dirty >"$work/pack.json"
"$PYTHON" "$ROOT/scripts/release-tool.py" verify-archive --archive "$work/pack/VGT_GeDefense_Beta_v5_$(tr -d '\r\n' < "$ROOT/VERSION")_Source.zip" >/dev/null
archive=$(find "$work/pack" -name '*_Source.zip' -print -quit)
"$PYTHON" - "$archive" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    names = archive.namelist()
    assert names == sorted(names), "archive member order is not deterministic"
    assert not any("/control/webtools/" in name for name in names), "gitignored webtools data leaked"
    assert not any(name.endswith("/wsl-verify.sh") for name in names), "gitignored tooling leaked"
    assert any(name.endswith("/SOURCE-MANIFEST.sha256") for name in names), "source manifest missing"
print("PASS: archive contains tracked files only and is deterministic")
PY

echo "== no release key inside the repository =="
if find "$ROOT" -path "$ROOT/.git" -prune -o \( -name 'release-private.key' -o -name '*.pem' -o -name '*.key' \) -print -quit | grep -q .; then
  echo "FAIL: release key material found inside the repository" >&2
  find "$ROOT" -path "$ROOT/.git" -prune -o \( -name 'release-private.key' -o -name '*.pem' -o -name '*.key' \) -print >&2
  exit 1
fi
echo "PASS: no release key material in the repository"

echo "ALL LOCAL RELEASE-SECURITY CHECKS PASSED"
