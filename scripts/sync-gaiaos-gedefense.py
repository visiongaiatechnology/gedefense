#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Synchronize the complete public GeDefense source tree into GaiaOS."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath


MANIFEST_NAME = "GAIAOS-MIRROR-MANIFEST.sha256"
MARKER_NAME = ".gedefense-managed-mirror"
MARKER_VALUE = "vgt-gedefense-managed-mirror-v1\n"

SOURCE_DIRECTORIES = (
    ".github",
    "control",
    "gateway",
    "integration",
    "packaging",
    "rust",
    "scripts",
)

SOURCE_FILES = (
    ".gitignore",
    "ARCHITECTURE.md",
    "BETA-TEST-PLAN.md",
    "BUILD-RUNBOOK.md",
    "CHANGELOG.md",
    "CI-POLICY.md",
    "CRYPTOGRAPHY.md",
    "DEPENDENCIES.md",
    "GEDEFENSE-GAIAOS-INTEGRATION.md",
    "GITHUB-UPLOAD-ANLEITUNG.md",
    "LICENSE",
    "MIGRATION-NOTES.md",
    "Makefile",
    "OPERATIONS.md",
    "PRODUCTION-BETA-GATE.md",
    "README.md",
    "RELEASE-NOTES.md",
    "ROADMAP.md",
    "SECURITY-AUDIT-BETA5.md",
    "SECURITY-RELEASE-CHECKLIST.md",
    "SECURITY.md",
    "TECHNISCHES-DATENBLATT.md",
    "THREAT-MODEL.md",
    "TOOLCHAINS.lock",
    "VALIDATION.md",
    "VERSION",
    "XDR-DESIGN.md",
    "gedefense.toml",
    "xdr-baseline.example.json",
)

EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".agents",
    ".codex",
    "__pycache__",
    "dist",
    "target",
}

EXCLUDED_FILE_SUFFIXES = (
    ".exe",
    ".pyc",
    ".run",
    ".sha256",
    ".zip",
)


class MirrorError(RuntimeError):
    """A mirror invariant was violated."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_excluded(relative_path: Path) -> bool:
    return (
        any(part in EXCLUDED_DIRECTORY_NAMES for part in relative_path.parts)
        or relative_path.name in {MANIFEST_NAME, MARKER_NAME, "SOURCE-MANIFEST.sha256"}
        or relative_path.name.endswith(EXCLUDED_FILE_SUFFIXES)
    )


def collect_source_files(source_root: Path) -> dict[PurePosixPath, Path]:
    selected: dict[PurePosixPath, Path] = {}

    for name in SOURCE_FILES:
        candidate = source_root / name
        if not candidate.is_file() or candidate.is_symlink():
            raise MirrorError(f"Required regular source file is missing: {name}")
        selected[PurePosixPath(name)] = candidate

    for directory_name in SOURCE_DIRECTORIES:
        directory = source_root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            raise MirrorError(f"Required source directory is missing: {directory_name}")
        for candidate in sorted(directory.rglob("*")):
            relative = candidate.relative_to(source_root)
            if is_excluded(relative):
                continue
            if candidate.is_symlink():
                raise MirrorError(f"Source symlink is forbidden: {relative}")
            if candidate.is_file():
                selected[PurePosixPath(relative.as_posix())] = candidate

    return dict(sorted(selected.items(), key=lambda item: item[0].as_posix()))


def validate_gaia_root(raw_path: str) -> tuple[Path, Path]:
    gaia_root = Path(raw_path).expanduser()
    if not gaia_root.exists() or not gaia_root.is_dir():
        raise MirrorError(f"GaiaOS root does not exist: {gaia_root}")
    if gaia_root.is_symlink():
        raise MirrorError("GaiaOS root must not be a symlink.")

    resolved_root = gaia_root.resolve(strict=True)
    target = resolved_root / "gedefense"
    if target.exists() and target.is_symlink():
        raise MirrorError("GaiaOS GeDefense target must not be a symlink.")
    if target.parent != resolved_root or target.name != "gedefense":
        raise MirrorError("Refusing target outside the GaiaOS/gedefense boundary.")
    return resolved_root, target


def validate_relative_manifest_path(raw_path: str) -> PurePosixPath:
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise MirrorError(f"Unsafe manifest path: {raw_path}")
    if not relative.parts:
        raise MirrorError("Empty manifest path.")
    return relative


def read_manifest(target: Path) -> dict[PurePosixPath, str]:
    manifest_path = target / MANIFEST_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise MirrorError(f"Mirror manifest is missing: {manifest_path}")

    entries: dict[PurePosixPath, str] = {}
    for line_number, raw_line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        digest, separator, raw_path = raw_line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise MirrorError(f"Invalid manifest line {line_number}.")
        relative = validate_relative_manifest_path(raw_path)
        if relative in entries:
            raise MirrorError(f"Duplicate manifest path: {relative}")
        entries[relative] = digest
    if not entries:
        raise MirrorError("Mirror manifest must not be empty.")
    return entries


def write_atomic(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def manifest_content(files: dict[PurePosixPath, Path]) -> bytes:
    lines = [
        f"{sha256_file(source_path)}  {relative.as_posix()}\n"
        for relative, source_path in files.items()
    ]
    return "".join(lines).encode("utf-8")


def require_managed_existing_target(target: Path) -> dict[PurePosixPath, str]:
    if not target.exists():
        return {}
    marker = target / MARKER_NAME
    if not marker.is_file() or marker.is_symlink():
        raise MirrorError(
            f"Refusing to modify unmanaged existing directory: {target}"
        )
    if marker.read_text(encoding="utf-8") != MARKER_VALUE:
        raise MirrorError("Managed mirror marker is invalid.")
    return read_manifest(target)


def sync(source_root: Path, target: Path) -> None:
    source_files = collect_source_files(source_root)
    previous_entries = require_managed_existing_target(target)
    target.mkdir(mode=0o755, parents=False, exist_ok=True)

    for relative, source_path in source_files.items():
        destination = target.joinpath(*relative.parts)
        if destination.exists() and destination.is_symlink():
            raise MirrorError(f"Target symlink is forbidden: {relative}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.sync-{os.getpid()}")
        try:
            shutil.copyfile(source_path, temporary, follow_symlinks=False)
            shutil.copymode(source_path, temporary, follow_symlinks=False)
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()

    current_paths = set(source_files)
    for obsolete in sorted(set(previous_entries) - current_paths, reverse=True):
        obsolete_path = target.joinpath(*obsolete.parts)
        if obsolete_path.is_symlink():
            raise MirrorError(f"Refusing to remove obsolete symlink: {obsolete}")
        if obsolete_path.is_file():
            obsolete_path.unlink()

    write_atomic(target / MARKER_NAME, MARKER_VALUE.encode("utf-8"), 0o644)
    write_atomic(target / MANIFEST_NAME, manifest_content(source_files), 0o644)


def verify(source_root: Path, target: Path) -> None:
    source_files = collect_source_files(source_root)
    manifest = read_manifest(target)
    expected = {
        relative: sha256_file(source_path)
        for relative, source_path in source_files.items()
    }
    if manifest != expected:
        raise MirrorError("Mirror manifest does not match the current source tree.")

    for relative, expected_digest in expected.items():
        mirrored = target.joinpath(*relative.parts)
        if not mirrored.is_file() or mirrored.is_symlink():
            raise MirrorError(f"Mirrored regular file is missing: {relative}")
        if sha256_file(mirrored) != expected_digest:
            raise MirrorError(f"Hash mismatch: {relative}")

    allowed_paths = set(expected)
    actual_paths: set[PurePosixPath] = set()
    for candidate in target.rglob("*"):
        if candidate.is_symlink():
            raise MirrorError(
                f"Target symlink is forbidden: {candidate.relative_to(target)}"
            )
        if candidate.is_file() and candidate.name not in {MANIFEST_NAME, MARKER_NAME}:
            actual_paths.add(
                PurePosixPath(candidate.relative_to(target).as_posix())
            )
    unexpected = sorted(actual_paths - allowed_paths)
    if unexpected:
        raise MirrorError(f"Unmanaged mirror files detected: {unexpected[0]}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synchronize or verify GaiaOS/gedefense against this source tree."
    )
    parser.add_argument("command", choices=("sync", "verify"))
    parser.add_argument("gaiaos_root", help="Absolute or relative GaiaOS repository root.")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()

    try:
        source_root = Path(__file__).resolve(strict=True).parent.parent
        _, target = validate_gaia_root(arguments.gaiaos_root)
        if arguments.command == "sync":
            sync(source_root, target)
        verify(source_root, target)
        source_count = len(collect_source_files(source_root))
    except (MirrorError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"PASS: GaiaOS/gedefense is byte-identical for {source_count} source files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
