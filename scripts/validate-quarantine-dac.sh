#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -Eeuo pipefail
umask 0077

[[ ${EUID} -eq 0 ]] || {
  printf 'Quarantine DAC validation requires root.\n' >&2
  exit 1
}
command -v setpriv >/dev/null 2>&1 || {
  printf 'Quarantine DAC validation requires setpriv.\n' >&2
  exit 1
}

readonly TEST_GID=42424
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-dac.XXXXXXXX")
cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

chown 65534:"$TEST_GID" "$TEST_ROOT"
chmod 0710 "$TEST_ROOT"
install -d -o root -g "$TEST_GID" -m 0700 \
  "$TEST_ROOT/quarantine" \
  "$TEST_ROOT/quarantine/objects"

readonly -a UNPRIVILEGED_ROOT=(
  setpriv
  --reuid=0
  --regid="$TEST_GID"
  --clear-groups
  --bounding-set=-all
  --inh-caps=-all
  --ambient-caps=-all
  --securebits=+noroot,+noroot_locked
)

"${UNPRIVILEGED_ROOT[@]}" sh -c \
  'test -d "$1" && touch "$1/probe" && rm -f -- "$1/probe"' \
  sh "$TEST_ROOT/quarantine/objects"

if "${UNPRIVILEGED_ROOT[@]}" sh -c 'ls "$1" >/dev/null 2>&1' sh "$TEST_ROOT"; then
  printf 'Parent directory listing unexpectedly permitted.\n' >&2
  exit 1
fi

printf 'Quarantine DAC traversal validated without capabilities.\n'
