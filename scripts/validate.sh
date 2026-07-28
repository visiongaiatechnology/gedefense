#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"
make test
make test-race
bash -n scripts/oneclick-installer-header.sh
printf 'GeDefense source validation passed.\n'
