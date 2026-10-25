#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Pack the deterministic GeDefense source release ZIP (F-02/F-12).

Replaces the previous ad-hoc packer which:

* copied the whole working tree (including gitignored ``control/webtools``
  operational data and an 18 MB dev binary),
* wrote ``SOURCE-MANIFEST.sha256`` back into the repository,
* hardcoded a Windows download path that became ``<repo>/C:/...`` on Linux,
* produced a different archive per run.

This packer packages only the committed HEAD tree (``git archive``), enforces
the shared tracked-file allowlist and ``FORBIDDEN_MARKERS`` gate from
``scripts/vgt_release_security.py``, writes a deterministic stored-metadata ZIP
and only writes outside the repository.

Usage:
    python3 scripts/pack_release_zip.py [--out-dir DIR] [--epoch EPOCH]
                                        [--allow-dirty] [--verify-twice]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The release tool deliberately lives in a hyphenated filename. Load it as a
# module explicitly; a plain ``import release_tool`` cannot resolve it and made
# the release-artifacts CI job fail after the security audit.
import importlib.util  # noqa: E402

_release_tool_spec = importlib.util.spec_from_file_location(
    "release_tool", Path(__file__).with_name("release-tool.py")
)
if _release_tool_spec is None or _release_tool_spec.loader is None:
    raise SystemExit("release-tool.py could not be loaded for source packaging")
release_tool = importlib.util.module_from_spec(_release_tool_spec)
sys.modules["release_tool"] = release_tool
_release_tool_spec.loader.exec_module(release_tool)

import vgt_release_security as security  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pack the deterministic GeDefense source release ZIP")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--epoch", type=int, default=None)
    parser.add_argument("--allow-dirty", action="store_true", help="explicit local dry-run on an uncommitted tree")
    parser.add_argument("--verify-twice", action="store_true", default=True)
    parser.add_argument("--no-verify-twice", dest="verify_twice", action="store_false")
    arguments = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    out_dir = Path(arguments.out_dir).resolve() if arguments.out_dir else root / "dist" / "release"
    try:
        if out_dir == root or root in out_dir.parents:
            raise security.GateError("source archive output must not be written inside the repository")
        namespace = argparse.Namespace(
            repo=str(root),
            out_dir=str(out_dir),
            work_dir="",
            version="",
            epoch=arguments.epoch,
            verify_twice=arguments.verify_twice,
            allow_dirty=arguments.allow_dirty,
        )
        exit_code = release_tool.cmd_pack_source(namespace)
        return exit_code
    except security.GateError as error:
        print(f"CONTENT-GATE-FAILED: {error}", file=sys.stderr)
        return 2
    except security.ReleaseError as error:
        print(f"RELEASE-ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
