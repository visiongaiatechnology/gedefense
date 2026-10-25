#!/usr/bin/env bash
# VGT GeDefense desktop tray One-Click installer header.
# The build script replaces __VERSION__ and __PAYLOAD_SHA256__, then appends the
# deterministic source payload after the marker line below.
set -Eeuo pipefail

readonly PRODUCT_VERSION="__VERSION__"
readonly PAYLOAD_SHA256="__PAYLOAD_SHA256__"
readonly LOG_FILE="/var/log/vgt-gedefense-desktop-install.log"
readonly MARKER="__PAYLOAD_BELOW__"

usage() {
    printf 'VGT GeDefense %s desktop tray installer\n\n' "$PRODUCT_VERSION"
    printf 'Options:\n  --self-test   verify the embedded source payload without installing\n  --help        show this help\n\n'
    printf 'The installer builds the locally vendored Qt6 tray client and installs\n'
    printf 'it to /usr/local; it does not install the server or connect to the network\n'
    printf 'except for distribution package installation.\n'
}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '%s\n' "$*" | tee -a "$LOG_FILE"; }

extract_payload() {
    local out=$1
    local line
    line=$(awk -v marker="$MARKER" '$0 == marker { print NR + 1; exit }' "$0")
    [[ -n $line ]] || fail "embedded payload marker missing"
    mkdir -p "$out"
    tail -n +"$line" "$0" | tar -xzf - -C "$out"
    local actual
    actual=$(tail -n +"$line" "$0" | sha256sum | awk '{print $1}')
    [[ $actual == "$PAYLOAD_SHA256" ]] || fail "embedded payload checksum mismatch"
}

self_test() {
    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf -- "$tmp"' RETURN
    extract_payload "$tmp"
    [[ -f $tmp/desktop/tray/CMakeLists.txt ]] || fail "desktop/tray/CMakeLists.txt missing"
    [[ -f $tmp/THIRD-PARTY-LICENSES.md ]] || fail "third-party notices missing"
    grep -q 'gedefense-tray' "$tmp/desktop/tray/CMakeLists.txt" || fail "tray target missing"
    printf 'SELF-TEST PASS: payload checksum valid, desktop source and notices present\n'
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
    : > "$LOG_FILE"
    log "VGT GeDefense ${PRODUCT_VERSION} desktop tray installer"
    local tmp build
    tmp=$(mktemp -d /tmp/gedefense-desktop-install.XXXXXX)
    build=$(mktemp -d /tmp/gedefense-desktop-build.XXXXXX)
    trap 'rm -rf -- "$tmp" "$build"' EXIT
    extract_payload "$tmp"
    install_packages
    cmake -S "$tmp/desktop/tray" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo >>"$LOG_FILE" 2>&1
    cmake --build "$build" >>"$LOG_FILE" 2>&1
    cmake --install "$build" --prefix /usr/local >>"$LOG_FILE" 2>&1
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
    --help|-h) usage ;;
    '') install_desktop ;;
    *) usage >&2; exit 2 ;;
esac
exit 0

__PAYLOAD_BELOW__
