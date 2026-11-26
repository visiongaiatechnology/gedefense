#!/usr/bin/env bash
# VGT GeDefense desktop tray One-Click installer header.
#
# Trust contract (FIND-001):
# * scripts/build-desktop-oneclick.sh renders this template with
#   scripts/render-installer-header.py. The rendered header embeds the Ed25519
#   release public key, the signed release index (covering the payload) and the
#   stdlib-only verifier; unfilled placeholders always fail closed.
# * The appended payload is first buffered into a private 0600 file. SHA-256 and
#   the signed release-index binding are verified BEFORE a single archive member
#   is extracted. Any failure leaves the extraction directory empty.
# * Extraction validates every tar member (path escapes, symlinks, hardlinks,
#   devices) and uses tar protections (--no-same-owner/--no-same-permissions/
#   --no-overwrite-dir).
set -Eeuo pipefail
umask 0077

readonly PRODUCT_VERSION="__VERSION__"
readonly PAYLOAD_SHA256="__PAYLOAD_SHA256__"
readonly LOG_FILE="/var/log/vgt-gedefense-desktop-install.log"
readonly MARKER="__VGT_PAYLOAD_BELOW__"
readonly SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
# Rendered by scripts/render-installer-header.py; unfilled placeholders fail closed.
readonly RELEASE_PUBKEY_HEX="__RELEASE_PUBKEY_HEX__"
readonly RELEASE_INDEX_B64="__RELEASE_INDEX_B64__"
readonly RELEASE_VERIFIER_B64="__RELEASE_VERIFIER_B64__"
readonly RELEASE_TRUST_MODE="__RELEASE_TRUST_MODE__"
# Test seam used only by scripts/tests/check_installer_templates.sh to prove that
# no file is extracted on a verification failure. Ignored by the install path.
readonly SELFTEST_DIR_OVERRIDE="${GEDEFENSE_DESKTOP_SELFTEST_DIR:-}"

TRUST_WORK=""
VERIFY_WORK=""
PAYLOAD_ARCHIVE=""
INSTALL_TMP=""
INSTALL_BUILD=""
LOG_READY=0

usage() {
    printf 'VGT GeDefense %s desktop tray installer\n\n' "$PRODUCT_VERSION"
    printf 'Options:\n  --self-test   verify the embedded source payload signature and checksum without installing\n  --help        show this help\n\n'
    printf 'The installer builds the locally vendored Qt6 tray client and installs\n'
    printf 'it to /usr/local; it does not install the server or connect to the network\n'
    printf 'except for distribution package installation.\n'
}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() {
    printf '%s\n' "$*"
    if (( LOG_READY )); then
        printf '%s\n' "$*" >>"$LOG_FILE" 2>/dev/null || true
    fi
}
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
    local path
    for path in "$VERIFY_WORK" "$TRUST_WORK" "$INSTALL_TMP" "$INSTALL_BUILD"; do
        if [[ -n $path && -d $path ]]; then
            rm -rf -- "$path"
        fi
    done
}
on_err() {
    local line=$1 rc=$?
    printf 'ERROR: desktop installer failed at line %s (exit %s).\n' "$line" "$rc" >&2
    if (( LOG_READY )) && [[ -s "$LOG_FILE" ]]; then
        printf '--- Last 20 lines of %s ---\n' "$LOG_FILE" >&2
        tail -n 20 -- "$LOG_FILE" >&2 || true
    fi
}
trap cleanup EXIT
trap 'on_err "$LINENO"' ERR

release_placeholder_ok() {
    local value=$1 name=$2
    [[ -n $value && $value != __*__ ]] \
        || fail "Installer wurde ohne signierten Release-Kontext gebaut ($name fehlt)."
}

release_trust_check() {
    release_placeholder_ok "$PRODUCT_VERSION" PRODUCT_VERSION
    release_placeholder_ok "$PAYLOAD_SHA256" PAYLOAD_SHA256
    release_placeholder_ok "$RELEASE_PUBKEY_HEX" RELEASE_PUBKEY_HEX
    release_placeholder_ok "$RELEASE_INDEX_B64" RELEASE_INDEX_B64
    release_placeholder_ok "$RELEASE_VERIFIER_B64" RELEASE_VERIFIER_B64
    release_placeholder_ok "$RELEASE_TRUST_MODE" RELEASE_TRUST_MODE
    [[ $PAYLOAD_SHA256 =~ ^[0-9a-f]{64}$ ]] || fail "Eingebettete Payload-Prüfsumme ist ungültig."
    [[ $RELEASE_PUBKEY_HEX =~ ^[0-9a-f]{64}$ ]] || fail "Release-Public-Key ist ungültig."
    case "$RELEASE_TRUST_MODE" in
        prebuilt | source-signed) ;;
        *) fail "Unbekannter Release-Trust-Modus; nur prebuilt/source-signed sind zulässig." ;;
    esac
    local tool
    for tool in python3 sha256sum base64 awk tar; do
        have "$tool" || fail "$tool ist für die Signaturprüfung erforderlich."
    done
    TRUST_WORK=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-desktop-trust.XXXXXX")
    chmod 0700 "$TRUST_WORK"
    printf '%s' "$RELEASE_INDEX_B64" | base64 -d > "$TRUST_WORK/release-index.signed.json" \
        || fail "Eingebetteter Release-Index ist nicht dekodierbar."
    printf '%s' "$RELEASE_VERIFIER_B64" | base64 -d > "$TRUST_WORK/release-verifier.py" \
        || fail "Eingebetteter Release-Verifier ist nicht dekodierbar."
    chmod 0600 "$TRUST_WORK/release-index.signed.json" "$TRUST_WORK/release-verifier.py"
    python3 "$TRUST_WORK/release-verifier.py" verify-index \
        --index "$TRUST_WORK/release-index.signed.json" \
        --pubkey "$RELEASE_PUBKEY_HEX" \
        --expected-version "$PRODUCT_VERSION" >/dev/null \
        || fail "Ed25519-Signatur des Release-Index ist ungültig (falscher Schlüssel oder Manipulation)."
    log "Release-Index: Ed25519-Signatur gültig (Version ${PRODUCT_VERSION}, Trust-Modus ${RELEASE_TRUST_MODE})."
}

verify_archive_binding() {
    local archive=$1
    python3 "$TRUST_WORK/release-verifier.py" verify-index \
        --index "$TRUST_WORK/release-index.signed.json" \
        --pubkey "$RELEASE_PUBKEY_HEX" \
        --expected-version "$PRODUCT_VERSION" \
        --artifact-file "payload.tar.gz=$archive" >/dev/null \
        || fail "Eingebetteter Payload ist nicht durch den signierten Release-Index gedeckt."
}

buffer_and_verify_payload() {
    local marker line actual
    marker=$(awk -v marker="$MARKER" '$0 == marker {print NR; exit}' "$SELF")
    [[ $marker =~ ^[0-9]+$ ]] || fail "Embedded payload marker is missing."
    line=$((marker + 1))
    VERIFY_WORK=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-desktop-verify.XXXXXX")
    chmod 0700 "$VERIFY_WORK"
    PAYLOAD_ARCHIVE="$VERIFY_WORK/payload.tar.gz"
    (umask 0077; tail -n +"$line" "$SELF" >"$PAYLOAD_ARCHIVE") \
        || fail "Eingebetteter Payload konnte nicht gepuffert werden."
    chmod 0600 "$PAYLOAD_ARCHIVE"
    actual=$(sha256sum "$PAYLOAD_ARCHIVE" | awk '{print $1}')
    [[ $actual == "$PAYLOAD_SHA256" ]] \
        || fail "Embedded payload checksum mismatch (expected $PAYLOAD_SHA256, got $actual)."
    if [[ $RELEASE_TRUST_MODE == "prebuilt" ]]; then
        verify_archive_binding "$PAYLOAD_ARCHIVE"
        log "Payload: SHA-256 und Ed25519-Signatur des Release-Index vor der Extraktion verifiziert."
    else
        log "Quell-basierter Trust-Modus: Payload-SHA-256 geprüft; die Signaturbindung erfolgte über den signierten Quell-Payload des Bootstraps."
    fi
}

extract_verified_payload() {
    local out=$1
    [[ -n $PAYLOAD_ARCHIVE && -f $PAYLOAD_ARCHIVE && ! -L $PAYLOAD_ARCHIVE ]] \
        || fail "Payload wurde nicht gepuffert und verifiziert."
    mkdir -p -- "$out"
    chmod 0700 "$out"
    # Validate every member before extraction: absolute names, path traversal,
    # symlinks, hardlinks and device nodes are rejected.
    python3 - "$PAYLOAD_ARCHIVE" "$out" <<'PY' || fail "Payload enthält unsichere Pfade oder Link-Einträge."
import pathlib, sys, tarfile
archive, dst = sys.argv[1:]
root = pathlib.Path(dst).resolve()
with tarfile.open(archive, 'r:gz') as tf:
    members = tf.getmembers()
    if not members:
        raise SystemExit('empty payload')
    for member in members:
        p = pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or member.issym() or member.islnk() or member.isdev():
            raise SystemExit('unsafe payload member: %s' % member.name)
        target = (root / pathlib.Path(*p.parts)).resolve()
        if target != root and root not in target.parents:
            raise SystemExit('payload path escape: %s' % member.name)
PY
    tar --no-same-owner --no-same-permissions --no-overwrite-dir -xzf "$PAYLOAD_ARCHIVE" -C "$out" \
        || fail "Payload-Extraktion fehlgeschlagen."
    # Defence in depth after extraction: no symlinks/devices and every path must
    # still resolve below the extraction root.
    python3 - "$out" <<'PY' || fail "Entpackter Payload verletzt die Pfadgrenzen."
import pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
for entry in root.rglob('*'):
    if entry.is_symlink():
        raise SystemExit('extracted symlink refused: %s' % entry)
    if not (entry.is_dir() or entry.is_file()):
        raise SystemExit('extracted non-regular entry refused: %s' % entry)
    target = entry.resolve()
    if target != root and root not in target.parents:
        raise SystemExit('extracted path escape: %s' % entry)
PY
}

verify_and_extract() {
    local out=$1
    release_trust_check
    buffer_and_verify_payload
    extract_verified_payload "$out"
}

self_test() {
    local tmp
    if [[ -n $SELFTEST_DIR_OVERRIDE ]]; then
        # Test seam: caller-provided, existing empty directory. It is neither
        # created nor deleted here, so a verification failure provably leaves it
        # empty; the install path never consults this variable.
        tmp=$SELFTEST_DIR_OVERRIDE
        [[ $tmp == /* ]] || fail "self-test override directory must be absolute."
        [[ -d $tmp && ! -L $tmp ]] || fail "self-test override directory is missing or a symlink."
        [[ -z $(ls -A -- "$tmp" 2>/dev/null || true) ]] || fail "self-test override directory is not empty."
        verify_and_extract "$tmp"
    else
        tmp=$(mktemp -d "${TMPDIR:-/tmp}/gedefense-desktop-selftest.XXXXXX")
        INSTALL_TMP=$tmp
        verify_and_extract "$tmp"
    fi
    [[ -f $tmp/desktop/tray/CMakeLists.txt ]] || fail "desktop/tray/CMakeLists.txt missing"
    [[ -f $tmp/THIRD-PARTY-LICENSES.md ]] || fail "third-party notices missing"
    grep -q 'gedefense-tray' "$tmp/desktop/tray/CMakeLists.txt" || fail "tray target missing"
    if [[ -z $SELFTEST_DIR_OVERRIDE ]]; then
        rm -rf -- "$tmp"
        INSTALL_TMP=""
    fi
    printf 'SELF-TEST PASS: Ed25519 release signature and payload checksum valid, desktop source and notices present\n'
}

install_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >>"$LOG_FILE" 2>&1
        apt-get install -y build-essential cmake ninja-build qt6-base-dev qt6-base-dev-tools \
            qt6-svg-dev qt6-tools-dev qt6-tools-dev-tools qt6-l10n-tools >>"$LOG_FILE" 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y gcc gcc-c++ make cmake ninja-build qt6-qtbase-devel qt6-qtsvg-devel \
            qt6-qttools-devel qt6-linguist >>"$LOG_FILE" 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm --needed base-devel cmake ninja qt6-base qt6-svg qt6-tools >>"$LOG_FILE" 2>&1
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install gcc gcc-c++ make cmake ninja qt6-base-devel qt6-svg-devel \
            qt6-tools-devel qt6-linguist-devel >>"$LOG_FILE" 2>&1
    else
        fail "unsupported distribution: install Qt6 development packages, cmake and ninja manually"
    fi
}

install_desktop() {
    [[ ${EUID:-0} -eq 0 ]] || fail "desktop installation requires root"
    install -d -m 0755 "$(dirname "$LOG_FILE")"
    : >"$LOG_FILE"
    chmod 0600 "$LOG_FILE"
    LOG_READY=1
    log "VGT GeDefense ${PRODUCT_VERSION} desktop tray installer"
    INSTALL_TMP=$(mktemp -d /tmp/gedefense-desktop-install.XXXXXX)
    INSTALL_BUILD=$(mktemp -d /tmp/gedefense-desktop-build.XXXXXX)
    # Cryptographic verification strictly precedes package installation and build.
    verify_and_extract "$INSTALL_TMP"
    install_packages
    cmake -S "$INSTALL_TMP/desktop/tray" -B "$INSTALL_BUILD" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo >>"$LOG_FILE" 2>&1
    cmake --build "$INSTALL_BUILD" >>"$LOG_FILE" 2>&1
    cmake --install "$INSTALL_BUILD" --prefix /usr/local >>"$LOG_FILE" 2>&1
    command -v gedefense-tray >/dev/null 2>&1 || fail "gedefense-tray was not installed"
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/local/share/applications >>"$LOG_FILE" 2>&1 || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q /usr/local/share/icons/hicolor >>"$LOG_FILE" 2>&1 || true
    fi
    log "Desktop tray installed: $(command -v gedefense-tray)"
    log "Autostart entry: /usr/local/share/applications/gedefense-tray-autostart.desktop"
    log "Installer log: $LOG_FILE"
}

case ${1:-} in
    --self-test) self_test ;;
    --help | -h) usage ;;
    '') install_desktop ;;
    *) usage >&2; exit 2 ;;
esac
exit 0

__VGT_PAYLOAD_BELOW__
