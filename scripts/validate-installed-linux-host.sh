#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -Eeuo pipefail

readonly cert=/etc/vgt/gedefense/tls/access.crt
readonly token=/var/lib/vgt/gedefense/dashboard.token
readonly core_socket=/run/vgt-gedefense/core.sock
readonly interface=${1:-$(ip -4 route show default | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')}
readonly -a units=(gedefense-bpffs.service gedefense-core.service gedefense-control.service gedefense-access.service)

fail(){ printf 'installed-host security gate failed: %s\n' "$1" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail 'root privileges are required'
[[ $(uname -s) == Linux ]] || fail 'Linux is required'
[[ -d /run/systemd/system ]] || fail 'systemd is not active'
[[ -n $interface && -d /sys/class/net/$interface ]] || fail 'target interface is invalid'

for unit in "${units[@]}"; do
  systemd-analyze verify "/etc/systemd/system/$unit" >/dev/null || fail "invalid unit: $unit"
  systemctl is-enabled --quiet "$unit" || fail "unit is not enabled: $unit"
  systemctl is-active --quiet "$unit" || fail "unit is not active: $unit"
done

[[ -S $core_socket && ! -L $core_socket ]] || fail 'authenticated core socket is unavailable'
[[ -f $cert && ! -L $cert ]] || fail 'TLS certificate is unavailable'
[[ -f $token && ! -L $token ]] || fail 'dashboard token is unavailable'
curl --fail --silent --show-error --max-time 3 http://127.0.0.1:9844/bootz >/dev/null || fail 'control boot gate failed'
curl --fail --silent --show-error --max-time 3 --cacert "$cert" https://127.0.0.1:9843/gateway/livez >/dev/null || fail 'TLS gateway gate failed'

curl --fail --silent --show-error --max-time 3 \
  -H "Authorization: Bearer $(tr -d '\r\n' < "$token")" \
  http://127.0.0.1:9844/api/v1/status | python3 - "$interface" <<'PY'
import json, sys
interface = sys.argv[1]
doc = json.load(sys.stdin)
assert doc.get('core_connected') is True, doc
assert doc.get('core_mode') in {'native', 'generic', 'native+bpf-lsm-cell', 'generic+bpf-lsm-cell'}, doc
print(f"core gate: PASS ({doc['core_mode']}, interface={interface})")
PY

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

printf 'GeDefense installed-host kernel, XDP, systemd, Polkit and desktop gates: PASS\n'
