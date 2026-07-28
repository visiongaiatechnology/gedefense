#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
GAIAOS_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
GEDEFENSE_ROOT="${GAIAOS_ROOT}/gedefense"

die() {
  printf 'GeDefense local package build failed: %s\n' "$1" >&2
  exit 1
}

[[ -d "${GEDEFENSE_ROOT}" ]] ||
  die "GaiaOS/gedefense is missing; synchronize the complete source mirror first"
[[ ! -L "${GEDEFENSE_ROOT}" ]] ||
  die "GaiaOS/gedefense must not be a symlink"
[[ -f "${GEDEFENSE_ROOT}/scripts/sync-gaiaos-gedefense.py" ]] ||
  die "mirror verifier is missing"
[[ -f "${GEDEFENSE_ROOT}/packaging/arch/PKGBUILD" ]] ||
  die "local GeDefense Arch package is missing"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v makepkg >/dev/null 2>&1 || die "makepkg is required"

python3 "${GEDEFENSE_ROOT}/scripts/sync-gaiaos-gedefense.py" \
  verify "${GAIAOS_ROOT}"

(
  cd -- "${GEDEFENSE_ROOT}/packaging/arch"
  makepkg --cleanbuild --clean --force
)

(
  cd -- "${SCRIPT_DIR}"
  makepkg --cleanbuild --clean --force
)

printf 'GeDefense packages built exclusively from GaiaOS/gedefense.\n'
