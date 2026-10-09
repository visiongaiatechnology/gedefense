#!/usr/bin/env bash
# GeDefense 4.1 Kinetic Defense release-candidate gate.
#
# Local mode proves source-level gates available on the current machine and
# reports unavailable target-only gates as PENDING. --target-host is strict and
# additionally requires the installed privileged Linux/XDP qualification.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"
MODE=local
INTERFACE=""
if [[ ${1:-} == "--target-host" ]]; then
  MODE=target
  INTERFACE=${2:-}
elif [[ ${1:-} != "" && ${1:-} != "--local" ]]; then
  printf 'usage: %s [--local | --target-host <interface>]\n' "$0" >&2
  exit 64
fi

pass_count=0
pending_count=0
fail_count=0
pending=()

pass(){ printf '[PASS] %s\n' "$1"; pass_count=$((pass_count+1)); }
pend(){ printf '[PENDING] %s\n' "$1"; pending_count=$((pending_count+1)); pending+=("$1"); }
fail(){ printf '[FAIL] %s\n' "$1" >&2; fail_count=$((fail_count+1)); }
run_gate(){
  local label=$1; shift
  if "$@"; then pass "$label"; else fail "$label"; fi
}

run_gate 'control unit/integration tests' bash -lc 'cd control && go test ./...'
run_gate 'control go vet' bash -lc 'cd control && go vet ./...'
run_gate 'control race detector' bash -lc 'cd control && go test -race ./...'
run_gate 'B13/B14 security matrix' bash -lc "cd control && go test -run 'TestKineticFalsePositiveAndAttackCorpus|TestB13|TestB14|TestTLS' ./..."
run_gate 'frontend JavaScript syntax' bash -lc 'for f in control/web/*.js; do node --check "$f" >/dev/null || exit 1; done'
run_gate 'shell syntax' bash -lc 'bash -n scripts/*.sh integration/linux/gedefense-app integration/linux/gedefense-ensure-ready'
run_gate 'Linux integration contracts' python3 scripts/validate-linux-integration.py
run_gate 'GitHub release contracts' python3 scripts/validate-github-release.py
run_gate 'i18n contracts' node scripts/validate-i18n.mjs
run_gate 'static security audit' bash scripts/security-audit.sh

# Gateway intentionally declares Go 1.26. Avoid Go's automatic toolchain
# download here: an offline validation environment must report PENDING rather
# than trying the network and then pretending the failure says something about
# the source tree.
gateway_go_required=$(awk '$1 == "go" {print $2; exit}' gateway/go.mod)
current_go=$(go env GOVERSION | sed 's/^go//')
if python3 - "$current_go" "$gateway_go_required" <<'PYGO'
import sys
def mm(value):
    parts=value.split('.')
    return tuple(int(x) for x in (parts+["0","0"])[:2])
raise SystemExit(0 if mm(sys.argv[1]) >= mm(sys.argv[2]) else 1)
PYGO
then
  if (cd gateway && GOTOOLCHAIN=local go test ./... && GOTOOLCHAIN=local go vet ./...); then
    pass "gateway Go ${gateway_go_required} module tests/vet"
  else
    fail "gateway Go ${gateway_go_required} module tests/vet"
  fi
else
  if [[ $MODE == target ]]; then
    fail "gateway Go ${gateway_go_required} toolchain available (current ${current_go})"
  else
    pend "gateway Go ${gateway_go_required} module tests/vet (current ${current_go})"
  fi
fi

if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
  if cargo +1.97.1 test --locked --manifest-path rust/Cargo.toml -p gedefense-common -p gedefense-core; then
    pass 'Rust common/core tests'
  else
    if [[ $MODE == target ]]; then fail 'Rust common/core tests'; else pend 'Rust common/core tests'; fi
  fi
  if cargo +nightly-2026-07-16 build --locked --release --manifest-path rust/Cargo.toml -p gedefense-ebpf --target bpfel-unknown-none -Z build-std=core; then
    pass 'release eBPF build'
  else
    if [[ $MODE == target ]]; then fail 'release eBPF build'; else pend 'release eBPF build'; fi
  fi
else
  if [[ $MODE == target ]]; then
    fail 'Rust/eBPF release toolchains available'
  else
    pend 'Rust common/core tests (cargo/rustc unavailable)'
    pend 'release eBPF build (cargo/rustc unavailable)'
  fi
fi

if [[ $MODE == target ]]; then
  [[ $(id -u) -eq 0 ]] || fail '--target-host requires root for kernel/XDP qualification'
  if [[ -z $INTERFACE ]]; then
    fail 'target interface was not provided'
  elif sudo -n true >/dev/null 2>&1 || [[ $(id -u) -eq 0 ]]; then
    if bash scripts/validate-installed-linux-host.sh "$INTERFACE"; then
      pass 'installed target kernel/XDP/core/policy qualification'
    else
      fail 'installed target kernel/XDP/core/policy qualification'
    fi
  else
    fail 'non-interactive root qualification unavailable'
  fi
  # These gates need elapsed real deployment time and an external authorized
  # traffic source. They are intentionally never synthesized by this script.
  pend '24h Observe/Canary deployment soak with resource trend capture'
  pend 'authorized external live packet-drop proof for /32, /24 and IPv6 /64 containment'
  pend 'TC fallback attach/verifier parity on a host where XDP attach is intentionally unavailable'
else
  pend 'target-kernel verifier/XDP attach and installed-host qualification'
  pend 'authorized external live packet-drop proof'
  pend '24h Observe/Canary deployment soak'
fi

printf '\nGeDefense Kinetic RC gate summary: PASS=%d PENDING=%d FAIL=%d MODE=%s\n' "$pass_count" "$pending_count" "$fail_count" "$MODE"
if (( fail_count > 0 )); then
  exit 1
fi
if [[ $MODE == target && $pending_count -gt 0 ]]; then
  printf 'Production certification BLOCKED: mandatory target-host gates remain pending.\n' >&2
  exit 2
fi
if (( pending_count > 0 )); then
  printf 'Release-candidate source gates passed, but production certification remains BLOCKED by the PENDING gates above.\n'
else
  printf 'All invoked gates passed.\n'
fi
