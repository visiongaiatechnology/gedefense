#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Local equivalent of the CI supply-chain gate. Runs the release-security unit
# tests, offline positive/negative CLI rehearsals (keygen, sign/verify, tamper
# rejection, downgrade rejection, content gate) and the shell regression tests
# from scripts/tests.
#
# SKIP contract: this script is also executed inside published source packages.
# Those intentionally contain no .git directory and no prebuilt cross-check
# binary, so every check that needs git HEAD metadata, a Go control binary or
# git+ssh-keygen is reported as an explicit "SKIP:" line with its concrete
# reason - never as PASS. Executed checks must all pass; the script exits 0
# with documented SKIPs, or non-zero on the first real failure. Run it inside a
# real git checkout (optionally with GEDEFENSE_CONTROL_BINARY pointing at a
# built gedefense-control) for the complete gate.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
PYTHON=${PYTHON:-python3}

work=$(mktemp -d "${TMPDIR:-/tmp}/vgt-release-tests.XXXXXX")
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT

skips=0
skip(){ printf 'SKIP: %s\n' "$*"; skips=$((skips + 1)); }

# A published source package has no .git; the release rehearsals below are
# git-bound (HEAD tree and commit metadata) and are skipped in that case.
have_git=0
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
  have_git=1
fi

echo "== unit tests =="
"$PYTHON" -m unittest discover -s "$ROOT/scripts/tests" -p 'test_*.py' -v

if (( have_git == 1 )); then
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
else
  echo "== keygen + sign + verify (offline rehearsal) =="
  skip "signed manifest/index rehearsal needs git HEAD metadata; no git repository at $ROOT"
  echo "== negative: tampered payload / foreign key must be rejected =="
  skip "tamper/foreign-key negatives replay the signed rehearsal artifacts (needs git HEAD metadata)"
fi

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

if (( have_git == 1 )); then
  echo "== deterministic packaging: two builds byte-identical =="
  "$PYTHON" "$ROOT/scripts/release-tool.py" pack-source --repo "$ROOT" --out-dir "$work/pack" --epoch 1785110400 --verify-twice --allow-dirty >"$work/pack.json"
  "$PYTHON" "$ROOT/scripts/release-tool.py" verify-archive --archive "$work/pack/VGT_GeDefense_V6_$(tr -d '\r\n' < "$ROOT/VERSION")_Source.zip" >/dev/null
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
else
  echo "== deterministic packaging: two builds byte-identical =="
  skip "deterministic source packaging needs the git-tracked HEAD tree (pack-source --verify-twice); no git repository at $ROOT"
fi

echo "== no release key inside the repository =="
if find "$ROOT" -path "$ROOT/.git" -prune -o \( -name 'release-private.key' -o -name '*.pem' -o -name '*.key' \) -print -quit | grep -q .; then
  echo "FAIL: release key material found inside the repository" >&2
  find "$ROOT" -path "$ROOT/.git" -prune -o \( -name 'release-private.key' -o -name '*.pem' -o -name '*.key' \) -print >&2
  exit 1
fi
echo "PASS: no release key material in the repository"

echo "== static FIND-003 gate: source bootstrap header =="
bootstrap_header="$ROOT/scripts/oneclick-source-bootstrap-header.sh"
[[ -f $bootstrap_header ]] || { echo "FAIL: missing $bootstrap_header" >&2; exit 1; }
bootstrap_failures=0
bootstrap_forbid(){
  local needle=$1 label=$2
  if grep -Fq -- "$needle" "$bootstrap_header"; then
    echo "FAIL: $label (found: $needle)" >&2
    bootstrap_failures=$((bootstrap_failures + 1))
  fi
}
bootstrap_require(){
  local needle=$1 label=$2
  grep -Fq -- "$needle" "$bootstrap_header" || {
    echo "FAIL: $label (missing: $needle)" >&2
    bootstrap_failures=$((bootstrap_failures + 1))
  }
}
# The source bootstrap hands off to the transactional full-stack installer and
# must not reset the runtime-state contract afterwards (FIND-003 class).
bootstrap_forbid 'install -d -o root -g root -m 0755 "$STATE_DIR"' "bootstrap resets \$STATE_DIR to root:root 0755"
bootstrap_require "'gedefense:gedefense:710'" "bootstrap no longer asserts the 0710 gedefense:gedefense state contract"
bootstrap_forbid '.tmp.$$' "predictable shell temp file name remains in the bootstrap"
bootstrap_forbid 'with_name(target.name + f".tmp.{os.getpid()}")' "predictable PID-based release-floor temp path remains in the bootstrap"
bootstrap_require 'tempfile.mkstemp' "release floor is not written through an O_EXCL temp file"
bootstrap_require "'root:root:600'" "release floor owner/mode is not verified after persistence"
bootstrap_forbid 'chown root:root "$FLOOR_FILE" 2>/dev/null || true' "release floor chown errors are swallowed (fail open)"
if (( bootstrap_failures > 0 )); then
  echo "FAIL: source bootstrap FIND-003 gate ($bootstrap_failures finding(s))" >&2
  exit 1
fi
echo "PASS: source bootstrap FIND-003 gate (0710 state preserved, atomic 0600 release floor, fail closed)"

echo "== shell regression tests (offline) =="
run_shell_test(){
  local name=$1 log rc
  shift
  log="$work/$name.log"
  set +e
  "$@" >"$log" 2>&1
  rc=$?
  set -e
  cat "$log"
  if (( rc != 0 )); then
    echo "FAIL: $name exited with status $rc" >&2
    exit 1
  fi
  # A test may declare its own defined SKIP (e.g. key rotation without .git).
  # That is never counted as PASS.
  if grep -Eq '(^|[^A-Za-z])SKIPPED([^A-Za-z]|$)' "$log"; then
    skip "$name reported a defined SKIP (nothing was verified; see output above)"
  else
    echo "PASS: $name (exit 0)"
  fi
}

echo "-- syntax: shell regression scripts"
for shell_test in \
  test_verify_release_toolchains.sh test_sca_gate_status.sh check_installer_templates.sh \
  key_rotation_rehearsal.sh go_manifest_crosscheck.sh tag_signing_rehearsal.sh; do
  bash -n "$ROOT/scripts/tests/$shell_test"
done
echo "PASS: bash -n for all shell regression scripts"

run_shell_test test_verify_release_toolchains.sh bash "$ROOT/scripts/tests/test_verify_release_toolchains.sh"
run_shell_test test_sca_gate_status.sh bash "$ROOT/scripts/tests/test_sca_gate_status.sh"
run_shell_test check_installer_templates.sh bash "$ROOT/scripts/tests/check_installer_templates.sh"
run_shell_test key_rotation_rehearsal.sh bash "$ROOT/scripts/tests/key_rotation_rehearsal.sh"

# go_manifest_crosscheck.sh needs an executable control binary (CI builds it
# with `make go`) and git metadata for its signed-index phase. Both are absent
# in a published source package; an operator can opt in via the environment.
control_binary=${GEDEFENSE_CONTROL_BINARY:-}
if [[ -z $control_binary ]]; then
  for candidate in "$ROOT/dist/gedefense-control" "$ROOT/control/gedefense-control"; do
    if [[ -x $candidate ]]; then
      control_binary=$candidate
      break
    fi
  done
fi
if [[ -n $control_binary && -x $control_binary && $have_git == 1 ]] && command -v openssl >/dev/null 2>&1; then
  run_shell_test go_manifest_crosscheck.sh bash "$ROOT/scripts/tests/go_manifest_crosscheck.sh" --control-binary "$control_binary"
else
  echo "== go_manifest_crosscheck.sh =="
  if [[ -n $control_binary && -x $control_binary ]]; then
    skip "Go/Python/OpenSSL manifest interoperability needs git HEAD metadata (no git repository at $ROOT)"
  elif command -v openssl >/dev/null 2>&1; then
    skip "Go/Python/OpenSSL manifest interoperability needs an executable gedefense-control build (set GEDEFENSE_CONTROL_BINARY)"
  else
    skip "Go/Python/OpenSSL manifest interoperability needs openssl and an executable gedefense-control build"
  fi
fi

# tag_signing_rehearsal.sh clones the repository and therefore needs a real
# git checkout plus ssh-keygen; a published source package cannot run it.
if (( have_git == 1 )) && command -v ssh-keygen >/dev/null 2>&1; then
  run_shell_test tag_signing_rehearsal.sh bash "$ROOT/scripts/tests/tag_signing_rehearsal.sh"
else
  echo "== tag_signing_rehearsal.sh =="
  skip "signed-tag rehearsal needs a real git checkout (it clones $ROOT) and ssh-keygen"
fi

echo
if (( skips > 0 )); then
  printf 'DOCUMENTED SKIPS: %d (see SKIP lines above; no check was silently counted as PASS)\n' "$skips"
  echo "ALL EXECUTED LOCAL RELEASE-SECURITY CHECKS PASSED"
else
  echo "ALL LOCAL RELEASE-SECURITY CHECKS PASSED"
fi
