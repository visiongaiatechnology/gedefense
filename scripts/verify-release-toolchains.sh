#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
LOCK="$ROOT/TOOLCHAINS.lock"

[[ -f "$LOCK" ]] || { echo "missing toolchain lock: $LOCK" >&2; exit 1; }

lock_value() {
  local key=$1
  awk -F' = ' -v key="$key" '$1 == key { print $2; found=1; exit } END { if (!found) exit 1 }' "$LOCK"
}

EXPECTED_GO=$(lock_value 'Go release validation')
EXPECTED_NODE=$(lock_value 'Node.js syntax validation')
[[ $EXPECTED_GO =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid pinned Go version: $EXPECTED_GO" >&2; exit 1; }
[[ $EXPECTED_NODE =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid pinned Node.js version: $EXPECTED_NODE" >&2; exit 1; }

command -v go >/dev/null 2>&1 || { echo "missing Go toolchain" >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "missing Node.js toolchain" >&2; exit 1; }

ACTUAL_GO=$(go env GOVERSION)
ACTUAL_NODE=$(node --version)
[[ $ACTUAL_GO == "go$EXPECTED_GO" ]] || {
  echo "Go release toolchain mismatch: expected go$EXPECTED_GO, got $ACTUAL_GO" >&2
  exit 1
}
[[ $ACTUAL_NODE == "v$EXPECTED_NODE" ]] || {
  echo "Node.js release toolchain mismatch: expected v$EXPECTED_NODE, got $ACTUAL_NODE" >&2
  exit 1
}

printf 'Release toolchains verified: Go %s, Node.js %s\n' "$EXPECTED_GO" "$EXPECTED_NODE"
