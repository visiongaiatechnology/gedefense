#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -Eeuo pipefail

readonly cert=/etc/vgt/gedefense/tls/access.crt
readonly tls_key=/etc/vgt/gedefense/tls/access.key
readonly gateway_cert=/etc/vgt/gedefense-access/access.crt
readonly token=/var/lib/vgt/gedefense/dashboard.token
readonly core_socket=/run/vgt-gedefense/core.sock
readonly release=/opt/vgt/gedefense/current
readonly cell_helper="${release}/libexec/gedefense-cell-helper"
readonly cell_helper_unit=gedefense-cell-helper.service
readonly cell_helper_key=/etc/vgt/gedefense/secrets/cell-helper.key
readonly cell_helper_socket=/run/vgt-gedefense/cell-helper.sock
readonly parser_profile=/etc/vgt/gedefense/parser-profiles.conf
readonly parser_inputs=/var/lib/vgt/gedefense/parser-inputs
readonly parser_exports=/var/lib/vgt/gedefense/parser-exports
readonly parser_ledger=/var/lib/vgt/gedefense/parser-burn-ledger.jsonl
readonly release_manifest="${release}/share/release-manifest.signed.json"
readonly interface=${1:-$(ip -4 route show default | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')}
readonly -a units=(gedefense-bpffs.service gedefense-core.service gedefense-control.service gedefense-access.service)

fail(){ printf 'installed-host security gate failed: %s\n' "$1" >&2; exit 1; }
warn(){ printf 'installed-host security gate WARNING: %s\n' "$1" >&2; }
not_tested(){ printf 'installed-host security gate NOT_TESTED: %s\n' "$1" >&2; }
[[ $(id -u) -eq 0 ]] || fail 'root privileges are required'
[[ $(uname -s) == Linux ]] || fail 'Linux is required'
[[ -d /run/systemd/system ]] || fail 'systemd is not active'
[[ -n $interface && -d /sys/class/net/$interface ]] || fail 'target interface is invalid'

for unit in "${units[@]}"; do
  systemd-analyze verify "/etc/systemd/system/$unit" >/dev/null || fail "invalid unit: $unit"
  systemctl is-enabled --quiet "$unit" || fail "unit is not enabled: $unit"
  systemctl is-active --quiet "$unit" || fail "unit is not active: $unit"
done

# POINT 2: the privileged parser-cell helper is optional infrastructure, but if
# it is installed it must be a valid, hash-consistent root unit. A missing helper
# never fails the core gate (parser cells then stay runtime-unavailable); an
# inconsistent unit/key/profile does, because that is a broken trust boundary.
if [[ -e $cell_helper || -L $cell_helper ]]; then
  [[ -f $cell_helper && ! -L $cell_helper && -x $cell_helper ]] || fail 'parser-cell helper binary must be a regular executable file'
  systemd-analyze verify "/etc/systemd/system/$cell_helper_unit" >/dev/null || fail "invalid unit: $cell_helper_unit"
  systemctl is-enabled --quiet "$cell_helper_unit" || fail "unit is not enabled: $cell_helper_unit"
  [[ -f $cell_helper_key && ! -L $cell_helper_key ]] || fail 'parser-cell helper VGTGC2 key is unavailable'
  [[ $(stat -c '%U:%G:%a:%s' "$cell_helper_key") == 'root:gedefense:640:32' ]] || fail 'parser-cell helper key must be root:gedefense 0640 and exactly 32 bytes'
  [[ -f $parser_profile && ! -L $parser_profile ]] || fail 'parser profile file is unavailable'
  [[ $(stat -c '%U:%G:%a' "$parser_profile") == 'root:root:640' ]] || fail 'parser profile file must be root:root 0640'
  [[ -d $parser_inputs && ! -L $parser_inputs && $(stat -c '%U:%G:%a' "$parser_inputs") == 'gedefense:gedefense:730' ]] ||
    fail 'parser input staging directory must be a gedefense:gedefense 0730 directory'
  [[ -d $parser_exports && ! -L $parser_exports && $(stat -c '%U:%G:%a' "$parser_exports") == 'root:gedefense:750' ]] ||
    fail 'parser export staging directory must be a root:gedefense 0750 directory'
  [[ -f $parser_ledger && ! -L $parser_ledger && $(stat -c '%U:%G:%a' "$parser_ledger") == 'root:gedefense:640' ]] ||
    fail 'parser burn ledger must be a root:gedefense 0640 regular file'
  if systemctl is-active --quiet "$cell_helper_unit"; then
    [[ -S $cell_helper_socket && ! -L $cell_helper_socket ]] || fail 'active parser-cell helper has no VGTGC2 socket'
    [[ $(stat -c '%a' "$cell_helper_socket") == '660' ]] || fail 'VGTGC2 socket must be mode 0660'
    [[ $(stat -c '%U:%G' "$cell_helper_socket") == 'root:gedefense' ]] || fail 'VGTGC2 socket must be root:gedefense'
  else
    not_tested "parser-cell helper unit is installed but not active on this host"
  fi
else
  not_tested "parser-cell helper is not installed on this host (parser_cells stays runtime-unavailable)"
fi

[[ -S $core_socket && ! -L $core_socket ]] || fail 'authenticated core socket is unavailable'
[[ -f $cert && ! -L $cert ]] || fail 'TLS certificate is unavailable'
[[ -f $tls_key && ! -L $tls_key ]] || fail 'TLS private key is unavailable'
[[ -f $gateway_cert && ! -L $gateway_cert ]] || fail 'gateway certificate copy is unavailable'
[[ -f $token && ! -L $token ]] || fail 'dashboard token is unavailable'
# The gateway reads its key as a systemd credential from the TLS directory and its certificate from the
# gateway directory. Those two halves are written by different steps, so a drifted pair only shows up as a
# dead listener ("ERR_CONNECTION_REFUSED") long after the fact. Assert the pairing while both are intact.
command -v openssl >/dev/null 2>&1 || fail 'openssl is required for the TLS pairing check'
[[ $(openssl x509 -in "$gateway_cert" -noout -pubkey | openssl sha256) == \
   "$(openssl pkey -in "$tls_key" -pubout | openssl sha256)" ]] ||
  fail 'gateway certificate and private key do not match'
curl --fail --silent --show-error --max-time 3 http://127.0.0.1:9844/bootz >/dev/null || fail 'control boot gate failed'
curl --fail --silent --show-error --max-time 3 --cacert "$cert" https://127.0.0.1:9843/gateway/livez >/dev/null || fail 'TLS gateway gate failed'

status_file=$(mktemp)
lsm_file=$(mktemp)
trap 'rm -f "$status_file" "$lsm_file"' EXIT
curl --fail --silent --show-error --max-time 3 \
  -H "Authorization: Bearer $(tr -d '\r\n' < "$token")" \
  http://127.0.0.1:9844/api/v1/status > "$status_file"
# /sys/kernel/security/lsm is the kernel's authoritative LSM list; an absent or
# bpf-less list is a host fact, not an installer claim.
cat /sys/kernel/security/lsm > "$lsm_file" 2>/dev/null || : > "$lsm_file"
python3 - "$interface" "$status_file" "$(tr -d '\r\n' < "$lsm_file")" <<'PY'
import json, sys
interface, status_path, lsm_list = sys.argv[1], sys.argv[2], sys.argv[3]
with open(status_path, 'r', encoding='utf-8') as handle:
    doc = json.load(handle)
assert doc.get('core_connected') is True, doc
core_parts = str(doc.get('core_mode') or '').split('+')
assert core_parts[0] in {'native', 'generic'} and all(p == 'bpf-lsm-cell' or p.startswith(('titan-exec:', 'lockdown:')) for p in core_parts[1:]), doc
policy = doc.get('policy') or {}
assert policy.get('verified') is True, policy
coverage = doc.get('coverage') or {}
sensors = coverage.get('sensors') or {}
ingress = sensors.get('xdp_ingress') or {}
assert ingress.get('required') is True, ingress
assert str(ingress.get('status', '')).lower() == 'online', ingress
kinetic = doc.get('kinetic') or {}
layer = (kinetic.get('layers') or {}).get('ingress_network') or {}
assert layer.get('detection_healthy') is True, layer
release = doc.get('release') or {}
assert release.get('emergency_stop') is not True, release

# POINT 2: an enabled parser_cells namespace must never be accepted while the
# helper is unreachable or its sandbox/layers are misreported. Default off stays
# the honest state and is reported as such.
parser_cells = doc.get('parser_cells')
bpf_lsm_active = 'bpf' in {part.strip() for part in lsm_list.split(',')}
if isinstance(parser_cells, dict):
    enabled = parser_cells.get('enabled') is True
    available = parser_cells.get('available') is True
    if enabled and not available:
        raise SystemExit(f"parser_cells enabled but runtime unavailable: {parser_cells.get('last_error') or parser_cells.get('degraded_reason')}")
    if enabled and parser_cells.get('require_host_layers') and not bpf_lsm_active:
        print('PARSER_CELLS_LSM_WARNING require_host_layers=true but /sys/kernel/security/lsm has no bpf entry', file=sys.stderr)
    if enabled:
        print(f"parser_cells: enabled=true helper={parser_cells.get('helper')} sandbox={parser_cells.get('sandbox')} bpf_lsm={parser_cells.get('bpf_lsm')}", file=sys.stderr)
    else:
        print('parser_cells: enabled=false (default off, helper not contacted)', file=sys.stderr)
print(f"core/policy/kinetic gate: PASS ({doc['core_mode']}, interface={interface}, ingress=online)")
PY

# POINT 2 deployment drift gate: installed core/control/eBPF/helper binaries must
# match the signed release manifest that was deployed into the release tree.
# The manifest is signed by the release key; the installer already verified that
# signature before installing, so this gate proves the deployed bytes still match
# the manifest (mixed upgrades, manual copies). No manifest (e.g. distribution
# package without a release manifest) is NOT_TESTED, never a silent PASS.
if [[ -f $release_manifest && ! -L $release_manifest ]]; then
  python3 - "$release_manifest" "$release" <<'PY'
import hashlib, json, sys
from pathlib import Path
manifest_path, release_root = Path(sys.argv[1]), Path(sys.argv[2])
try:
    envelope = json.loads(manifest_path.read_text(encoding='utf-8'))['envelope']
except (KeyError, ValueError) as error:
    raise SystemExit(f'release manifest is malformed: {error}')
artifacts = envelope.get('artifacts')
if not isinstance(artifacts, dict) or not artifacts:
    raise SystemExit('release manifest carries no artifacts')
installed = {
    'gedefense-control': release_root / 'bin' / 'gedefense-control',
    'gedefense-access': release_root / 'bin' / 'gedefense-access',
    'gedefense-core': release_root / 'libexec' / 'gedefense-core',
    'gedefense-cell-helper': release_root / 'libexec' / 'gedefense-cell-helper',
    'gedefense-ebpf': release_root / 'lib' / 'gedefense' / 'gedefense-ebpf',
}
problems = []
for name, path in installed.items():
    expected = artifacts.get(name)
    if expected is None:
        continue
    if not path.is_file() or path.is_symlink():
        problems.append(f'{name}: deployed file missing at {path}')
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected.get('sha256') or path.stat().st_size != expected.get('size'):
        problems.append(f'{name}: deployed bytes differ from the signed release manifest')
if problems:
    raise SystemExit('deployment drift detected:\n' + '\n'.join(problems))
print(f"release manifest drift gate: PASS ({len(artifacts)} signed artifacts, deployed core/control/eBPF/helper checked)")
PY
else
  not_tested "signed release manifest is not deployed under ${release_manifest}; mixed core/control/eBPF/helper drift cannot be verified"
fi

# POINT 2: a bpf-less LSM list makes the P1 Titan-Exec and P2 Cell-LSM host layers
# unavailable. The gate must warn when the running system claims/enables them so
# an operator does not mistake L1 sandboxing for kernel-side LSM enforcement.
lsm_list=$(tr -d '\r\n' < "$lsm_file")
if [[ $lsm_list != *bpf* ]]; then
  if python3 - "$status_file" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as handle:
    doc = json.load(handle)
parser_cells = doc.get('parser_cells') or {}
titan_exec = doc.get('titan_exec') or {}
cell_lsm = doc.get('cell_lsm') or {}
active = parser_cells.get('enabled') is True or titan_exec.get('enabled') is True or cell_lsm.get('enabled') is True
raise SystemExit(0 if active else 1)
PY
  then
    warn "/sys/kernel/security/lsm='${lsm_list:-unavailable}' has no bpf entry but P1/P2 BPF-LSM features are enabled: Titan-Exec/Cell-LSM/parser_cells host layers stay unavailable (L1 sandbox only)"
  else
    not_tested "BPF-LSM host layer: /sys/kernel/security/lsm='${lsm_list:-unavailable}' has no bpf entry (P1/P2 LSM features stay unavailable, no claim)"
  fi
else
  printf 'kernel LSM list: bpf active\n'
fi

ip -details link show dev "$interface" | grep -E 'xdp|prog/xdp' >/dev/null || fail 'no XDP program is attached to the target interface'
mountpoint -q /sys/fs/bpf || fail 'bpffs is not mounted'
command -v bpftool >/dev/null 2>&1 || fail 'bpftool is required for verifier evidence'
bpftool prog show | grep gedefense >/dev/null || fail 'loaded GeDefense eBPF programs are not visible'

python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
policy = Path('/usr/share/polkit-1/actions/org.vgt.gedefense.policy')
desktop = Path('/usr/share/applications/gedefense.desktop')
assert policy.is_file() and not policy.is_symlink()
assert desktop.is_file() and not desktop.is_symlink()
ET.parse(policy)
text = desktop.read_text(encoding='utf-8')
assert 'Exec=gedefense-app' in text and 'Terminal=false' in text
PY

printf 'GeDefense installed-host kernel, XDP, systemd, Polkit, desktop and P2 deployment gates: PASS\n'
