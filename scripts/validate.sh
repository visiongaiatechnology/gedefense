#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"
make test
make test-race
bash -n scripts/oneclick-installer-header.sh
bash -n integration/linux/gedefense-app integration/linux/gedefense-ensure-ready
python3 scripts/validate-linux-integration.py
python3 scripts/validate-github-release.py
printf 'GeDefense source validation passed.\n'
