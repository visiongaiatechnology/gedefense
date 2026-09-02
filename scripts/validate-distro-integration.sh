#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -Eeuo pipefail

readonly root=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}
readonly expected=${EXPECTED_DISTRO:-}

fail(){ printf 'distribution integration validation failed: %s\n' "$1" >&2; exit 1; }
[[ -r /etc/os-release ]] || fail '/etc/os-release is unavailable'
# shellcheck disable=SC1091
source /etc/os-release
actual=${ID:-unknown}

case "$expected" in
  ubuntu) [[ $actual == ubuntu || $actual == debian ]] || fail "expected Debian family, got $actual"; command -v apt-get >/dev/null ;;
  fedora) [[ $actual == fedora || $actual == rhel || $actual == centos || $actual == rocky || $actual == almalinux ]] || fail "expected RPM family, got $actual"; command -v dnf >/dev/null ;;
  arch) [[ $actual == arch ]] || fail "expected Arch, got $actual"; command -v pacman >/dev/null ;;
  opensuse) [[ $actual == opensuse-tumbleweed || $actual == opensuse-leap || $actual == sles ]] || fail "expected SUSE family, got $actual"; command -v zypper >/dev/null ;;
  *) fail "unsupported EXPECTED_DISTRO: $expected" ;;
esac

for command_name in bash python3 curl openssl pkexec; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is missing: $command_name"
done

bash -n \
  "$root/scripts/oneclick-installer-header.sh" \
  "$root/integration/linux/gedefense-app" \
  "$root/integration/linux/gedefense-ensure-ready"
python3 "$root/scripts/validate-linux-integration.py"

desktop-file-validate "$root/integration/linux/gedefense.desktop"
python3 - "$root/integration/linux/org.vgt.gedefense.policy" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
path = Path(sys.argv[1])
root = ET.parse(path).getroot()
actions = {node.attrib.get('id') for node in root.findall('action')}
assert actions == {'org.vgt.gedefense.ensure-ready'}, actions
PY

printf 'GeDefense distribution contract: PASS (%s)\n' "$actual"
