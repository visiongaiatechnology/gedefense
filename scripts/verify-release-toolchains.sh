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
SELF_TEST=0
TEST_VERSION_GE=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --require-security-floor) REQUIRE_FLOOR=1 ;;
    --self-test) SELF_TEST=1 ;;
    --test-version-ge)
      [[ $# -ge 3 ]] || { echo "--test-version-ge requires LEFT RIGHT" >&2; exit 2; }
      TEST_VERSION_GE=("$2" "$3"); shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

[[ -f "$LOCK" ]] || { echo "missing toolchain lock: $LOCK" >&2; exit 1; }

lock_value() {
  local key=$1
  awk -F' = ' -v key="$key" '$1 == key { print $2; found=1; exit } END { if (!found) exit 1 }' "$LOCK"
}

# version_ge compares dotted numeric versions: returns 0 when $1 >= $2,
# 1 when $1 < $2 and 2 when either operand is not a structurally comparable
# version (unparseable segment or a different segment count). The previous
# implementation used ``sort -V | tail -n1 == "$2"`` which implements
# $1 <= $2, so a stale go1.27.1 passed a go1.27.3 security floor. A non-zero
# status is always fail-closed for the callers below.
version_ge() {
  local left=$1 right=$2
  local -a left_parts right_parts
  IFS=. read -r -a left_parts <<< "$left"
  IFS=. read -r -a right_parts <<< "$right"
  (( ${#left_parts[@]} > 0 && ${#left_parts[@]} == ${#right_parts[@]} )) || return 2
  local index
  for (( index = 0; index < ${#left_parts[@]}; index++ )); do
    [[ ${left_parts[index]} =~ ^[0-9]+$ ]] || return 2
    [[ ${right_parts[index]} =~ ^[0-9]+$ ]] || return 2
    if (( 10#${left_parts[index]} > 10#${right_parts[index]} )); then return 0; fi
    if (( 10#${left_parts[index]} < 10#${right_parts[index]} )); then return 1; fi
  done
  return 0
}

# self_test pins the comparison semantics with explicit positive/negative cases
# so a future rewrite cannot silently invert the gate again. It is independent
# of the host toolchains and runs before the lock/toolchain checks.
self_test() {
  local failures=0
  self_test_case() {
    local expected=$1 left=$2 right=$3 actual
    if version_ge "$left" "$right"; then actual=pass; else actual=fail; fi
    if [[ $actual == "$expected" ]]; then
      printf 'SELFTEST PASS: version_ge %s %s -> %s\n' "$left" "$right" "$actual"
    else
      printf 'SELFTEST FAIL: version_ge %s %s -> %s (expected %s)\n' "$left" "$right" "$actual" "$expected" >&2
      failures=$((failures + 1))
    fi
  }
  self_test_case fail 1.27.1 1.27.3  # audit case FIND-004: go1.27.1 < go1.27.3
  self_test_case pass 1.27.3 1.27.3
  self_test_case pass 1.27.4 1.27.3
  self_test_case pass 1.28.0 1.27.3
  self_test_case pass 2.0.0 1.27.3
  self_test_case fail 1.26.99 1.27.3
  self_test_case fail 1.27 1.27.3
  self_test_case fail 1.27.3.0 1.27.3
  if (( failures > 0 )); then
    printf 'SELFTEST FAILED (%d case(s)): version_ge gate would accept a stale toolchain\n' "$failures" >&2
    return 1
  fi
  printf 'SELFTEST OK: version_ge is >= and fails closed on incomparable versions\n'
  return 0
}

if (( SELF_TEST == 1 )); then
  self_test
  exit $?
fi
if (( ${#TEST_VERSION_GE[@]} == 2 )); then
  if version_ge "${TEST_VERSION_GE[0]}" "${TEST_VERSION_GE[1]}"; then exit 0; else exit $?; fi
fi

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
