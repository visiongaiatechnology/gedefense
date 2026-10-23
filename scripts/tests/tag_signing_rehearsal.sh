#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
# Rehearsal for SSH-Ed25519-signed release tags (G-SC-01 / G-SC-12).
#
# Runs entirely in a throwaway clone of the local repository (no network, no
# push, no modification of the working repository's refs). Proves that a tag
# signed with a local Ed25519 SSH key can be verified with an explicit
# allowed-signers configuration, which is the documented release-tag procedure.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vgt-tag-sign-rehearsal.XXXXXX")
cleanup(){ rm -rf -- "$WORK"; }
trap cleanup EXIT

command -v git >/dev/null || { echo "git missing" >&2; exit 1; }
command -v ssh-keygen >/dev/null || { echo "ssh-keygen missing" >&2; exit 1; }

echo "== throwaway local clone + Ed25519 SSH signing key =="
git clone --quiet --no-hardlinks "$ROOT" "$WORK/repo"
ssh-keygen -q -t ed25519 -N "" -C "vgt-release-tag-rehearsal" -f "$WORK/tag-signing-key"
TAG="v$(tr -d '\r\n' < "$WORK/repo/VERSION")-rehearsal-$$"
SIGNER_ID="release-tag-rehearsal@example.invalid"
printf '%s %s\n' "$SIGNER_ID" "$(cat "$WORK/tag-signing-key.pub")" > "$WORK/allowed_signers"
git -C "$WORK/repo" config user.name "Release Tag Rehearsal"
git -C "$WORK/repo" config user.email "release-tag-rehearsal@example.invalid"
git -C "$WORK/repo" config gpg.format ssh
git -C "$WORK/repo" config user.signingkey "$WORK/tag-signing-key"
git -C "$WORK/repo" config gpg.ssh.allowedSignersFile "$WORK/allowed_signers"

echo "== create and verify SSH-Ed25519 signed tag =="
git -C "$WORK/repo" tag -s "$TAG" -m "VGT release tag rehearsal"
git -C "$WORK/repo" verify-tag "$TAG" >/dev/null
echo "PASS: git verify-tag accepted the Ed25519 SSH signature"

echo "== negative: unsigned/foreign tag must not verify =="
git -C "$WORK/repo" tag -a "${TAG}-unsigned" -m "unsigned rehearsal tag"
if git -C "$WORK/repo" verify-tag "${TAG}-unsigned" >/dev/null 2>&1; then
  echo "FAIL: unsigned tag was accepted" >&2
  exit 1
fi
echo "PASS: unsigned tag rejected"

echo "TAG-SIGNING-REHEARSAL PASSED (tag $TAG in throwaway clone; working repository untouched)"
