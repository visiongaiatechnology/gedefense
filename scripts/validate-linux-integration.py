#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from __future__ import annotations

import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def fail(message: str) -> None:
    raise SystemExit(f"universal Linux integration validation failed: {message}")


root = Path(__file__).resolve().parent.parent
integration = root / "integration" / "linux"
required = {
    "gedefense-app",
    "gedefense-ensure-ready",
    "gedefense.desktop",
    "org.vgt.gedefense.policy",
    "README.md",
}
missing = sorted(name for name in required if not (integration / name).is_file())
if missing:
    fail(f"missing files: {', '.join(missing)}")

version = (root / "VERSION").read_text(encoding="utf-8").strip()
if version != "3.0.0-beta.1":
    fail(f"unexpected version: {version}")

contract = json.loads((root / "integration" / "astraeaos" / "contract.json").read_text(encoding="utf-8"))
if contract.get("gedefense_version") != version:
    fail("AstraeaOS contract version drift")
if contract.get("universal_linux_integration") != "implemented-v2-systemd-polkit-desktop":
    fail("universal integration capability is not declared")
if set(contract.get("supported_package_managers", [])) != {"apt", "dnf", "yum", "pacman", "zypper"}:
    fail("package-manager coverage drift")

ET.parse(integration / "org.vgt.gedefense.policy")
desktop = (integration / "gedefense.desktop").read_text(encoding="utf-8")
for anchor in ("[Desktop Entry]", "Exec=gedefense-app", "Terminal=false", "Categories=System;Security;"):
    if anchor not in desktop:
        fail(f"desktop contract missing: {anchor}")

launcher = (integration / "gedefense-app").read_text(encoding="utf-8")
for anchor in ("--ignore-certificate-errors-spki-list", "--cacert", "pkexec", "https://127.0.0.1:9843/"):
    if anchor not in launcher:
        fail(f"launcher security contract missing: {anchor}")

installer = (root / "scripts" / "oneclick-installer-header.sh").read_text(encoding="utf-8")
for anchor in ("have apt-get", "have dnf", "have yum", "have pacman", "have zypper", "install_linux_integration"):
    if anchor not in installer:
        fail(f"installer integration missing: {anchor}")

print(f"GeDefense {version} universal Linux integration: PASS")
