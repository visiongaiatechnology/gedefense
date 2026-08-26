#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Final


SCHEMA: Final[str] = "vgt-gedefense-astraeaos-integration-v1"
MAX_CONTRACT_BYTES: Final[int] = 64 * 1024
SYNC_FILES: Final[tuple[str, ...]] = (
    "PKGBUILD",
    "README.md",
    "build-local-packages.sh",
    "contract.json",
    "firefox-policies.json",
    "astraeaos-profile.toml",
    "gedefense-app",
    "gedefense-access-astraeaos.conf",
    "gedefense-access-ready",
    "gedefense-control-astraeaos.conf",
    "gedefense-core-astraeaos.conf",
    "gedefense-core-launch",
    "gedefense-ensure-ready",
    "gedefense-astraeaos-provision",
    "gedefense-astraeaos-provision.service",
    "gedefense-set-password",
    "gedefense.desktop",
    "astraeaos-boot-attestation",
    "astraeaos-boot-attestation.service",
    "astraeaos-runtime.conf",
    "astraeaos-security-login-gate",
    "astraeaos-security-login-gate.service",
    "astraeaos-security-boot-failure",
    "astraeaos-security-boot-failure.service",
    "org.astraeaos.gedefense.policy",
    "50-astraeaos-gedefense.rules",
    "sddm-gedefense-login-gate.conf",
    "verify_sync.py",
)


def fail(message: str) -> None:
    raise SystemExit(f"GeDefense/AstraeaOS synchronization failed: {message}")


def bounded_regular(path: Path) -> bytes:
    try:
        stat = path.lstat()
    except OSError as exc:
        fail(f"{path}: {exc}")
    if path.is_symlink() or not path.is_file():
        fail(f"{path} is not a regular non-symlink file")
    if stat.st_size < 1 or stat.st_size > MAX_CONTRACT_BYTES:
        fail(f"{path} exceeds the integration-file boundary")
    return path.read_bytes()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_contract(data: bytes, path: Path) -> dict[str, object]:
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{path} is malformed: {exc}")
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        fail(f"{path} has an unsupported schema")
    if document.get("security_authority") != "gedefense":
        fail(f"{path} enables a conflicting security authority")
    version = document.get("gedefense_version")
    if not isinstance(version, str) or not version:
        fail(f"{path} has no GeDefense version")
    return document


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        fail("usage: verify_sync.py /path/to/AstraeaOS")
    gaia_root = Path(argv[1]).resolve(strict=True)
    # Packaging path used by astraeaos-gedefense-integration / ISO packages.
    target = gaia_root / "integration" / "gedefense"
    # Optional GeDefense-side mirror of the same integration files.
    mirror = gaia_root / "gedefense" / "integration" / "astraeaos"
    source = mirror if mirror.is_dir() else Path(__file__).resolve().parent

    for name in SYNC_FILES:
        source_data = bounded_regular(source / name)
        target_data = bounded_regular(target / name)
        if not hmac.compare_digest(digest(source_data), digest(target_data)):
            fail(f"{name} differs between {source} and {target}")
    source_contract = load_contract(
        bounded_regular(source / "contract.json"), source / "contract.json"
    )
    target_contract = load_contract(
        bounded_regular(target / "contract.json"), target / "contract.json"
    )
    if source_contract != target_contract:
        fail("contract semantics differ")
    capabilities = source_contract.get("capabilities")
    if not isinstance(capabilities, dict):
        fail("contract capabilities are missing or malformed")
    if capabilities.get("gaia_cells_bpf_lsm") != "implemented-mandatory-astraeaos":
        fail("mandatory GaiaCells BPF-LSM capability is missing")
    print(
        "GeDefense/AstraeaOS integration synchronized:",
        source_contract["gedefense_version"],
        digest(bounded_regular(source / "contract.json")),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
