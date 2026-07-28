#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
WORK=$(mktemp -d "${TMPDIR:-/var/tmp}/gedefense-arch-package.XXXXXXXX")
cleanup() {
  rm -rf -- "$WORK"
}
trap cleanup EXIT

BUILD_HOME=${WORK}/home
SOURCE_MIRROR=${WORK}/source
GEDEFENSE_JOB=${WORK}/gedefense
INTEGRATION_JOB=${WORK}/integration
mkdir -p "$BUILD_HOME" "$SOURCE_MIRROR" "$GEDEFENSE_JOB" "$INTEGRATION_JOB"
cp -a /root/.rustup "$BUILD_HOME/.rustup"
cp -a /root/.cargo "$BUILD_HOME/.cargo"
tar \
  --exclude='./.git' \
  --exclude='./dist' \
  --exclude='./rust/target' \
  --exclude='./RUN Build' \
  --exclude='./release-beta' \
  --exclude='./release-beta-final' \
  -cf - -C "$ROOT" . |
  tar -xf - -C "$SOURCE_MIRROR"
install -m 0644 "$SOURCE_MIRROR/packaging/arch/PKGBUILD" "$GEDEFENSE_JOB/PKGBUILD"
cp -a "$SOURCE_MIRROR/integration/gaiaos/." "$INTEGRATION_JOB/"
chown -R nobody:nobody "$WORK"

run_builder() {
  sudo -u nobody env \
    HOME="$BUILD_HOME" \
    RUSTUP_HOME="$BUILD_HOME/.rustup" \
    CARGO_HOME="$BUILD_HOME/.cargo" \
    PATH="$BUILD_HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/bin" \
    GEDEFENSE_SOURCE_ROOT="$SOURCE_MIRROR" \
    "$@"
}

(
  cd "$GEDEFENSE_JOB"
  run_builder makepkg --force --noconfirm --nodeps
)
(
  cd "$INTEGRATION_JOB"
  run_builder makepkg --force --noconfirm --nodeps
)

compgen -G "$GEDEFENSE_JOB/gedefense-*.pkg.tar.*" >/dev/null ||
  {
    printf 'GeDefense Arch package was not produced.\n' >&2
    exit 1
  }
compgen -G "$INTEGRATION_JOB/gaiaos-gedefense-integration-*.pkg.tar.*" >/dev/null ||
  {
    printf 'GaiaOS integration package was not produced.\n' >&2
    exit 1
  }

printf 'GeDefense and GaiaOS integration Arch packages validated.\n'
