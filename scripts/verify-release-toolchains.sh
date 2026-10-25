#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Toolchain gate (F-25 / G-SC-12 / HB-6).
#
# - exact Node.js pin and Go >= pinned release version,
# - Go security floor: a release must be built with a toolchain that contains
#   the known crypto/x509 and net/http fixes (GO-2026-6809 fixed in go1.26.10;
#   GO-2026-6600..6617 fixed in go1.26.9). ``--require-security-floor`` makes a
#   stale pin a hard release blocker instead of silently shipping vulnerable
#   standard-library code (govulncheck evidence; see SECURITY.md).
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
LOCK="$ROOT/TOOLCHAINS.lock"
REQUIRE_FLOOR=0
for argument in "$@"; do
  case $argument in
    --require-security-floor) REQUIRE_FLOOR=1 ;;
    *) echo "unknown argument: $argument" >&2; exit 2 ;;
  esac
done

[[ -f "$LOCK" ]] || { echo "missing toolchain lock: $LOCK" >&2; exit 1; }

lock_value() {
  local key=$1
  awk -F' = ' -v key="$key" '$1 == key { print $2; found=1; exit } END { if (!found) exit 1 }' "$LOCK"
}

version_ge() { [[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1) == "$2" ]]; }

EXPECTED_GO=$(lock_value 'Go release validation')
EXPECTED_NODE=$(lock_value 'Node.js syntax validation')
GO_SECURITY_FLOOR=${GEDEFENSE_GO_SECURITY_FLOOR:-1.27.3}
[[ $EXPECTED_GO =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid pinned Go version: $EXPECTED_GO" >&2; exit 1; }
[[ $EXPECTED_NODE =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid pinned Node.js version: $EXPECTED_NODE" >&2; exit 1; }

command -v go >/dev/null 2>&1 || { echo "missing Go toolchain" >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "missing Node.js toolchain" >&2; exit 1; }

ACTUAL_GO_VERSION=$(go env GOVERSION | sed 's/^go//')
ACTUAL_NODE=$(node --version)
if ! version_ge "$ACTUAL_GO_VERSION" "$EXPECTED_GO"; then
  echo "Go release toolchain too old: pinned go$EXPECTED_GO, got go$ACTUAL_GO_VERSION" >&2
  exit 1
fi
[[ $ACTUAL_NODE == "v$EXPECTED_NODE" ]] || {
  echo "Node.js release toolchain mismatch: expected v$EXPECTED_NODE, got $ACTUAL_NODE" >&2
  exit 1
}

if ! version_ge "$EXPECTED_GO" "$GO_SECURITY_FLOOR"; then
  message="TOOLCHAINS.lock pins Go $EXPECTED_GO but the patched security floor is $GO_SECURITY_FLOOR (GO-2026-6809 crypto/x509; net/http and TLS fixes in 1.26.9)."
  echo "WARNING: $message" >&2
  if (( REQUIRE_FLOOR == 1 )); then
    echo "BLOCKED: release build refuses a vulnerable Go release toolchain. Bump TOOLCHAINS.lock and control/go.mod toolchain, then re-run govulncheck." >&2
    exit 1
  fi
fi

printf 'Release toolchains verified: Go %s (pinned %s, security floor %s), Node.js %s\n' "$ACTUAL_GO_VERSION" "$EXPECTED_GO" "$GO_SECURITY_FLOOR" "$EXPECTED_NODE"
