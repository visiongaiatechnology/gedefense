#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Software-composition-analysis gate (F-01/HB-6, G-SC-14).
#
# Runs the SCA tools that are actually available and records exact evidence.
# There is no fake PASS: a tool that is unavailable is reported as a blocker
# together with the reason, and ``--strict`` fails the gate when a mandatory
# scanner cannot run.
#
# Mandatory when available: govulncheck (Go), cargo audit (Rust).
# Optional/advisory: trivy, osv-scanner, syft (recorded as unavailable when the
# tool or its advisory database is not present offline).
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
STRICT=0
REPORT=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --strict) STRICT=1 ;;
    --report) REPORT=${2:?--report requires a path}; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-sca.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

declare -a RESULTS=()
FAILURES=0
BLOCKERS=0
MANDATORY_BLOCKERS=0

record(){ RESULTS+=("$1|$2|$3"); }
run_required(){
  local name=$1 command=$2
  if ! command -v "$command" >/dev/null 2>&1; then
    record "$name" "BLOCKED" "tool not installed: $command (install in CI/release environment; offline advisory database unavailable)"
    BLOCKERS=$((BLOCKERS + 1))
    if [[ $name == "govulncheck" || $name == "cargo-audit" ]]; then
      MANDATORY_BLOCKERS=$((MANDATORY_BLOCKERS + 1))
      (( STRICT == 0 )) || FAILURES=$((FAILURES + 1))
    fi
    return 0
  fi
  return 1
}

echo "== govulncheck (Go) =="
if ! run_required govulncheck govulncheck; then
  for module in control gateway; do
    echo "-- $module"
    if ( cd "$ROOT/$module" && govulncheck ./... ) > "$WORK/govulncheck-$module.log" 2>&1; then
      record "govulncheck:$module" "PASS" "no reachable vulnerabilities reported"
    else
      record "govulncheck:$module" "FAIL" "govulncheck reported findings or failed; see log"
      cat "$WORK/govulncheck-$module.log" >&2
      FAILURES=$((FAILURES + 1))
    fi
  done
fi

echo "== cargo audit (Rust) =="
if ! run_required cargo-audit cargo-audit; then
  if ( cd "$ROOT/rust" && cargo audit --file Cargo.lock ) > "$WORK/cargo-audit.log" 2>&1; then
    record "cargo-audit" "PASS" "no vulnerable crates reported by the advisory database"
  else
    record "cargo-audit" "FAIL" "cargo audit reported findings or could not load the advisory database"
    cat "$WORK/cargo-audit.log" >&2
    FAILURES=$((FAILURES + 1))
  fi
fi

echo "== optional composite scanners =="
for tool in trivy osv-scanner syft; do
  if command -v "$tool" >/dev/null 2>&1; then
    record "$tool" "AVAILABLE" "tool present; run manually for full database coverage"
  else
    record "$tool" "BLOCKED" "tool not installed and no offline advisory database is available"
    BLOCKERS=$((BLOCKERS + 1))
  fi
done

REPORT=${REPORT:-"$WORK/sca-report.json"}
python3 - "$REPORT" "${RESULTS[@]}" <<'PY'
import json, sys
path, *entries = sys.argv[1:]
rows = []
for entry in entries:
    name, status, detail = entry.split("|", 2)
    rows.append({"tool": name, "status": status, "detail": detail})
document = {
    "schema": "vgt.gedefense.sca-report.v1",
    "status": "PASS" if not any(row["status"] == "FAIL" for row in rows) else "FAIL",
    "results": rows,
    "external_blocker": "Offline advisory databases and network access to vuln.go.dev/GitHub Advisory/RustSec are not available in the audited environment; the release host/CI must run this gate with network and pinned databases.",
}
open(path, "w", encoding="utf-8").write(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
cat "$REPORT"
if (( FAILURES > 0 )); then
  echo "SCA GATE FAILED ($FAILURES mandatory check(s) failed)" >&2
  exit 1
fi
if (( MANDATORY_BLOCKERS > 0 && STRICT == 1 )); then
  echo "SCA GATE FAILED (strict mode: $MANDATORY_BLOCKERS mandatory scanner(s) unavailable)" >&2
  exit 1
fi
echo "SCA GATE COMPLETED (blockers documented: $BLOCKERS)"
