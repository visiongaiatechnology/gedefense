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
#
# Git metadata contract (VGT-060): signing a release index binds the git commit.
# A published source package has no .git, which used to abort this rehearsal with
# a raw "git rev-parse HEAD failed". The deterministic contract is now:
#   - git checkout:                          use the real HEAD commit,
#   - RELEASE_COMMIT=<40-64 hex> exported:   use that commit (offline metadata
#                                            shim; the working tree is never
#                                            modified and no network is used),
#   - neither:                               defined SKIP with exit code 0 and an
#                                            explicit "nothing verified" notice.
#
# Exit codes:
#   0  rehearsal passed, or defined SKIP (no git repository and no RELEASE_COMMIT)
#   1  rehearsal failed (key-rotation contract violated)
#   2  usage/configuration error (invalid RELEASE_COMMIT, missing tooling)
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
PYTHON=${PYTHON:-python3}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-key-rotation-rehearsal.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

command -v "$PYTHON" >/dev/null 2>&1 || { echo "missing python interpreter: $PYTHON" >&2; exit 2; }

# Resolve the commit the signed index will be bound to. This never silently
# invents a commit: either git reports the repository HEAD or the operator
# supplies one explicitly through RELEASE_COMMIT.
RELEASE_COMMIT=${RELEASE_COMMIT:-}
COMMIT_SOURCE=""
if [[ -n $RELEASE_COMMIT ]]; then
  if [[ ! $RELEASE_COMMIT =~ ^[0-9a-f]{40,64}$ ]]; then
    echo "FAIL: RELEASE_COMMIT is not a 40-64 character lowercase hex commit hash: $RELEASE_COMMIT" >&2
    exit 2
  fi
  COMMIT_SOURCE="RELEASE_COMMIT environment override"
elif command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
  RELEASE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
  COMMIT_SOURCE="git HEAD of the working repository"
else
  cat >&2 <<'SKIP'
SKIP: no git repository at the repository root and RELEASE_COMMIT is not set.
SKIP:       A published source package has no .git, so the release index commit
SKIP:       cannot be resolved from this tree. Set RELEASE_COMMIT=<40-64 hex>
SKIP:       to run the full key-rotation rehearsal against that commit.
SKIP:       This is a defined skip, not a success: nothing was verified.
SKIP
  echo "KEY-ROTATION-REHEARSAL SKIPPED (defined skip contract, exit code 0)"
  exit 0
fi
export RELEASE_COMMIT

if [[ $COMMIT_SOURCE != "git HEAD of the working repository" ]]; then
  # Offline git metadata shim: release-tool.py sign-index reads exactly two git
  # facts (HEAD commit, worktree cleanliness). For a source package without .git
  # (or an explicit RELEASE_COMMIT override) the shim reports only the supplied
  # commit hash. It never changes the working tree and never touches the network.
  mkdir -p "$WORK/git-shim"
  cat > "$WORK/git-shim/git" <<'SHIM'
#!/usr/bin/env bash
set -Eeuo pipefail
arguments=("$@")
while [[ ${#arguments[@]} -gt 0 && ${arguments[0]} == "-C" ]]; do
  arguments=("${arguments[@]:2}")
done
case "${arguments[*]}" in
  "rev-parse HEAD") printf '%s\n' "${RELEASE_COMMIT:?RELEASE_COMMIT must be exported}"; exit 0 ;;
  "status --porcelain") exit 0 ;;
  *) echo "rehearsal git metadata shim: unsupported invocation: ${arguments[*]}" >&2; exit 2 ;;
esac
SHIM
  chmod 0755 "$WORK/git-shim/git"
  export PATH="$WORK/git-shim:$PATH"
  echo "NOTE: no usable git repository; binding the rehearsal index to RELEASE_COMMIT=$RELEASE_COMMIT (offline metadata shim, commit source: $COMMIT_SOURCE)"
fi

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

"$PYTHON" - "$WORK/report.json" "$CURRENT_FINGERPRINT" "$ROTATED_FINGERPRINT" "$RELEASE_COMMIT" "$COMMIT_SOURCE" <<'PY'
import json, sys
path, current, rotated, release_commit, commit_source = sys.argv[1:]
report = {
    "schema": "vgt.gedefense.key-rotation-rehearsal.v1",
    "status": "PASS",
    "revoked_key_fingerprint": current,
    "rotation_key_fingerprint": rotated,
    "release_commit": release_commit,
    "commit_source": commit_source,
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
echo "KEY-ROTATION-REHEARSAL PASSED (commit $RELEASE_COMMIT via $COMMIT_SOURCE)"
