#!/usr/bin/env bash
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
fail(){ printf 'SECURITY AUDIT FAIL: %s\n' "$*" >&2; exit 1; }
pass(){ printf '  PASS  %s\n' "$*"; }

for cmd in python3 grep find; do command -v "$cmd" >/dev/null 2>&1 || fail "missing tool: $cmd"; done
cd "$ROOT"

echo 'VGT GeDefense V6 static security regression audit'

# V6.3.0 refactoring wave 5: the former monolithic audit body now lives in
# ordered stages under scripts/audit/. Sourcing keeps one shell, so ROOT,
# pass/fail and environment state behave exactly as before.
for stage in "$ROOT"/scripts/audit/*.sh; do
  # shellcheck source=/dev/null
  . "$stage"
done

printf 'SECURITY AUDIT PASS\n'
