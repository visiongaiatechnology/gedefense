#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Offline regression test for scripts/verify-release-toolchains.sh (FIND-004).
#
# The release gate used to treat version_ge as "$1 <= $2", so a stale
# go1.27.1 passed a go1.27.3 security floor. This test pins the corrected,
# fail-closed comparison semantics without depending on the host toolchains.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
SCRIPT="$ROOT/scripts/verify-release-toolchains.sh"
BASH_PATH=$(command -v bash)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-toolchain-gate-test.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

fail(){ echo "FAIL: $*" >&2; exit 1; }

run_self_test(){
  local exit_code
  set +e
  "$BASH_PATH" "$SCRIPT" --self-test >"$WORK/self-test.log" 2>&1
  exit_code=$?
  set -e
  printf '%s' "$exit_code"
}

check_version_ge(){
  local label=$1 left=$2 right=$3 expected_rc=$4 actual_rc
  set +e
  "$BASH_PATH" "$SCRIPT" --test-version-ge "$left" "$right" >/dev/null 2>&1
  actual_rc=$?
  set -e
  [[ $actual_rc == "$expected_rc" ]] || fail "$label: version_ge $left $right exit $actual_rc, expected $expected_rc"
  echo "PASS: version_ge $left $right -> exit $expected_rc ($label)"
}

echo "== self-test mode =="
self_test_rc=$(run_self_test)
[[ $self_test_rc == "0" ]] || { cat "$WORK/self-test.log" >&2; fail "self-test exit $self_test_rc, expected 0"; }
grep -q 'SELFTEST OK' "$WORK/self-test.log" || fail "self-test did not report OK"
grep -q 'version_ge 1.27.1 1.27.3' "$WORK/self-test.log" || fail "self-test is missing the audit case 1.27.1 vs 1.27.3"
echo "PASS: --self-test verifies the comparison table (exit 0)"

echo "== comparison semantics (FIND-004 audit cases) =="
check_version_ge "stale patch release must FAIL" 1.27.1 1.27.3 1
check_version_ge "stale minor release must FAIL" 1.26.99 1.27.3 1
check_version_ge "incomparable segment count fails closed" 1.27 1.27.3 2
check_version_ge "equal versions satisfy the floor" 1.27.3 1.27.3 0
check_version_ge "newer patch release satisfies the floor" 1.27.4 1.27.3 0
check_version_ge "newer minor release satisfies the floor" 1.28.0 1.27.3 0
check_version_ge "newer major release satisfies the floor" 2.0.0 1.27.3 0

echo "== argument validation =="
set +e
"$BASH_PATH" "$SCRIPT" --unknown-argument >/dev/null 2>&1
unknown_rc=$?
set -e
[[ $unknown_rc == "2" ]] || fail "unknown argument exit $unknown_rc, expected 2"
echo "PASS: unknown arguments are rejected with exit 2"

echo "VERSION-GE-GATE-TEST PASSED"
