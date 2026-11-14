#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Offline regression test for scripts/sca-gate.sh status derivation (FIND-005).
#
# The gate must never report "PASS" while mandatory scanners are BLOCKED:
#   - mandatory scanner(s) unavailable, non-strict -> JSON status BLOCKED, exit 0
#   - mandatory scanner(s) unavailable, --strict  -> JSON status FAIL, exit 1
#   - all mandatory scanners ran clean             -> JSON status PASS, exit 0/0
#   - a mandatory scanner reported findings        -> JSON status FAIL, exit 1
#
# All scanners are uncontrolled fake executables; no network and no real
# advisory database is used.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
PYTHON=$(command -v python3)
BASH_PATH=$(command -v bash)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-sca-gate-test.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

fail(){ echo "FAIL: $*" >&2; exit 1; }
expect_exit(){
  local label=$1 actual=$2 expected=$3
  [[ $actual == "$expected" ]] || fail "$label: exit code $actual, expected $expected"
}
expect_status(){
  local label=$1 report=$2 expected=$3
  local actual
  actual=$("$PYTHON" - "$report" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    document = json.load(handle)
print(document.get("status", ""))
PY
)
  [[ $actual == "$expected" ]] || fail "$label: JSON status $actual, expected $expected"
}

# Minimal, fully controlled PATH: required OS utilities plus fake scanners. The
# system toolchain (and any installed real scanner) is not visible to the gate.
MINBIN="$WORK/minbin"
mkdir -p "$MINBIN"
for utility in mktemp rm cat dirname; do
  ln -s "$(command -v "$utility")" "$MINBIN/$utility"
done
ln -s "$PYTHON" "$MINBIN/python3"

run_gate(){
  local expectations=$1 report=$2
  shift 2
  local exit_code
  set +e
  PATH="$MINBIN" "$BASH_PATH" "$ROOT/scripts/sca-gate.sh" "$@" --report "$report" >"$WORK/gate.log" 2>&1
  exit_code=$?
  set -e
  printf '%s' "$exit_code"
}

echo "== case 1: no mandatory scanner available (offline) =="
exit_code=$(run_gate "" "$WORK/report-blocked.json")
expect_exit "non-strict blocked" "$exit_code" 0
expect_status "non-strict blocked" "$WORK/report-blocked.json" BLOCKED
grep -q '"mandatory_blockers": 2' "$WORK/report-blocked.json" || fail "non-strict report does not record 2 mandatory blockers"
if grep -q '"status": "PASS"' "$WORK/report-blocked.json"; then
  fail "non-strict report claims PASS while mandatory scanners are BLOCKED"
fi
echo "PASS: non-strict gate reports BLOCKED (exit 0), never PASS"

exit_code=$(run_gate "" "$WORK/report-strict-blocked.json" --strict)
expect_exit "strict blocked" "$exit_code" 1
expect_status "strict blocked" "$WORK/report-strict-blocked.json" FAIL
grep -q '"strict": true' "$WORK/report-strict-blocked.json" || fail "strict flag missing from JSON report"
echo "PASS: --strict gate reports FAIL (exit 1)"

echo "== case 2: fake mandatory scanners installed and clean =="
FAKEBIN="$WORK/fakebin"
mkdir -p "$FAKEBIN"
for scanner in govulncheck cargo-audit; do
  printf '#!/bin/sh\nexit 0\n' > "$FAKEBIN/$scanner"
  chmod 0755 "$FAKEBIN/$scanner"
done
# sca-gate.sh invokes `cargo audit`; the fake cargo keeps the run offline.
printf '#!/bin/sh\nexit 0\n' > "$FAKEBIN/cargo"
chmod 0755 "$FAKEBIN/cargo"
ln -s "$FAKEBIN/govulncheck" "$MINBIN/govulncheck"
ln -s "$FAKEBIN/cargo-audit" "$MINBIN/cargo-audit"
ln -s "$FAKEBIN/cargo" "$MINBIN/cargo"
exit_code=$(run_gate "" "$WORK/report-clean.json")
expect_exit "non-strict clean" "$exit_code" 0
expect_status "non-strict clean" "$WORK/report-clean.json" PASS
exit_code=$(run_gate "" "$WORK/report-strict-clean.json" --strict)
expect_exit "strict clean" "$exit_code" 0
expect_status "strict clean" "$WORK/report-strict-clean.json" PASS
grep -q '"failed_checks": 0' "$WORK/report-strict-clean.json" || fail "clean strict report records failed checks"
echo "PASS: clean mandatory scanners report PASS in both modes"

echo "== case 3: fake mandatory scanner reports findings =="
printf '#!/bin/sh\nexit 1\n' > "$FAKEBIN/govulncheck"
chmod 0755 "$FAKEBIN/govulncheck"
exit_code=$(run_gate "" "$WORK/report-findings.json")
expect_exit "non-strict findings" "$exit_code" 1
expect_status "non-strict findings" "$WORK/report-findings.json" FAIL
exit_code=$(run_gate "" "$WORK/report-strict-findings.json" --strict)
expect_exit "strict findings" "$exit_code" 1
expect_status "strict findings" "$WORK/report-strict-findings.json" FAIL
echo "PASS: scanner findings fail the gate in both modes"

echo "SCA-GATE-STATUS-TEST PASSED"
