#!/usr/bin/env python3
"""Regenerate ASTRAEAOS-MIRROR-MANIFEST.sha256 for the in-tree gedefense mirror."""

from __future__ import annotations

from pathlib import Path


if __name__ == "__main__":
    # Import via importlib because the file name contains hyphens.
    import importlib.util

    script_dir = Path(__file__).resolve().parent
    sync_path = script_dir / "sync-astraeaos-gedefense.py"
    spec = importlib.util.spec_from_file_location("sync_astraeaos_gedefense", sync_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {sync_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    source_root = script_dir.parent
    files = mod.collect_source_files(source_root)
    content = mod.manifest_content(files)
    dest = source_root / mod.MANIFEST_NAME
    mod.write_atomic(dest, content, 0o644)
    print(f"Wrote {dest} ({len(files)} entries, {len(content)} bytes)")
    raise SystemExit(0)
