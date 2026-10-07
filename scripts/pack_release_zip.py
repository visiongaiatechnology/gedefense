#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Pack production release ZIP archives for GeDefense 4.2.0."""

from __future__ import annotations

import datetime
import hashlib
import os
from pathlib import Path
import stat
import sys
import zipfile


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    downloads = Path("C:/Users/Masterboard/Downloads")
    if not downloads.exists():
        downloads.mkdir(parents=True, exist_ok=True)

    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if version != "4.2.0":
        raise ValueError(f"Unexpected VERSION: {version}")

    print(f"Packaging GeDefense {version} from {root}...")

    excluded_dirs = {
        ".git",
        ".go-cache",
        ".tmp-go-cache",
        ".agents",
        ".codex",
        "qa",
        "dist",
        "target",
        "__pycache__",
        "RUN Build",
        "GitHub Upload",
        "V4 Update",
        "release-beta",
        "release-beta-final",
        "release-complete",
        "release-final",
    }
    excluded_exts = {".exe", ".pyc", ".run", ".zip", ".bin"}
    excluded_names = {
        "SOURCE-MANIFEST.sha256",
        ".DS_Store",
        "Thumbs.db",
        "wsl-verify.sh",
        "wsl-qa.sh",
        "wsl-vuln.sh",
        "wsl-probe.sh",
        "wsl-race.sh",
        "wsl-gate.sh",
        "wsl-login-qa.sh",
        "extract.sh",
        "qa-server.py",
        "GEDEFENSE_4.2_TESTBEFUNDE.md",
        "GEDEFENSE_4.2_CHANGELOG_KONSOLIDIERT.md",
        "GEDEFENSE_4.2_FIX_VERIFICATION.md",
        "OPENAI_REWORK_PROGRESS.md",
        "GeDefense_4.2_SECURITY_FABRIC_CONTROL_PLANE_PLAN.md",
    }

    # 1. Collect clean files
    files_to_pack: list[tuple[Path, Path]] = [] # (absolute_path, relative_path)
    for p in sorted(root.rglob("*")):
        if any(part in excluded_dirs for part in p.parts):
            continue
        if p.name in excluded_names:
            continue
        if p.suffix.lower() in excluded_exts:
            continue
        if p.is_file() and not p.is_symlink():
            rel = p.relative_to(root)
            files_to_pack.append((p, rel))

    print(f"Collected {len(files_to_pack)} clean source files.")

    # 2. Build SOURCE-MANIFEST.sha256
    manifest_lines = []
    for abs_path, rel_path in files_to_pack:
        digest = sha256_file(abs_path)
        manifest_lines.append(f"{digest}  {rel_path.as_posix()}\n")
    manifest_data = "".join(manifest_lines).encode("utf-8")
    (root / "SOURCE-MANIFEST.sha256").write_bytes(manifest_data)

    # Fixed reproducible timestamp: 2026-10-06 17:30:00 UTC
    dt = datetime.datetime(2026, 10, 6, 17, 30, 0, tzinfo=datetime.timezone.utc)
    zip_dt = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

    targets = [
        (f"gedefense-{version}", downloads / f"gedefense-{version}.zip"),
        (f"gedefense-{version}", downloads / f"gedefense4.2.zip"),
        (f"VGT_GeDefense_Beta_v4_{version}", downloads / f"VGT_GeDefense_Beta_v4_{version}_Source.zip"),
    ]

    for prefix, out_zip in targets:
        print(f"Writing {out_zip} with root prefix '{prefix}/'...")
        with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            # Write SOURCE-MANIFEST.sha256
            manifest_info = zipfile.ZipInfo(f"{prefix}/SOURCE-MANIFEST.sha256", zip_dt)
            manifest_info.external_attr = (0o644 & 0xFFFF) << 16
            manifest_info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(manifest_info, manifest_data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

            for abs_path, rel_path in files_to_pack:
                arc_name = f"{prefix}/{rel_path.as_posix()}"
                info = zipfile.ZipInfo(arc_name, zip_dt)
                mode = abs_path.stat().st_mode
                is_exec = (
                    bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    or rel_path.suffix.lower() in {".sh", ".py"}
                    or "bin/" in rel_path.as_posix()
                    or "libexec/" in rel_path.as_posix()
                )
                info.external_attr = ((0o755 if is_exec else 0o644) & 0xFFFF) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                content = abs_path.read_bytes()
                zf.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

        zip_hash = sha256_file(out_zip)
        zip_size = out_zip.stat().st_size
        sha_file = out_zip.with_suffix(out_zip.suffix + ".sha256")
        sha_file.write_text(f"{zip_hash}  {out_zip.name}\n", encoding="utf-8")
        print(f"Created: {out_zip} ({zip_size:,} bytes)")
        print(f"SHA-256: {zip_hash}")
        print(f"Checksum file: {sha_file}")

    print("\nALL ARCHIVES PACKED AND VERIFIED SUCCESSFULLY.")


if __name__ == "__main__":
    main()
