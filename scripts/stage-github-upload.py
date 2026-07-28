#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Build a reviewable GitHub repository tree and separate release assets."""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import sys
from pathlib import Path, PurePosixPath


UPLOAD_DIRECTORY = "GitHub Upload"
REPOSITORY_DIRECTORY = "Repository"
RELEASE_DIRECTORY = "Release Assets"
SOURCE_MANIFEST = "SOURCE-MANIFEST.sha256"
UPLOAD_MANIFEST = "UPLOAD-MANIFEST.sha256"
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024

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
    "gedefense.toml",
    "GEDEFENSE-GAIAOS-INTEGRATION.md",
    "GITHUB-UPLOAD-ANLEITUNG.md",
    "LICENSE",
    "Makefile",
    "MIGRATION-NOTES.md",
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
    "xdr-baseline.example.json",
)

EXCLUDED_DIRECTORIES = {
    ".git",
    ".agents",
    ".codex",
    ".go-cache",
    ".tmp-go-cache",
    "__pycache__",
    "dist",
    "target",
    UPLOAD_DIRECTORY,
    "RUN Build",
    "release-beta",
    "release-beta-final",
    "release-complete",
    "release-final",
}

EXCLUDED_SUFFIXES = (
    ".exe",
    ".pyc",
    ".run",
    ".sha256",
    ".zip",
)

RELEASE_ASSETS = (
    "VGT_GeDefense_Beta_1.0.0-beta.5_OneClick_CompleteBeta.run",
    "VGT_GeDefense_Beta_1.0.0-beta.5_OneClick_CompleteBeta.run.sha256",
    "VGT_GeDefense_Beta_1.0.0-beta.5_CompleteBeta_Source.zip",
    "VGT_GeDefense_Beta_1.0.0-beta.5_CompleteBeta_Source.zip.sha256",
    "VGT_GeDefense_1.0.0-beta.5_Technisches_Datenblatt.pdf",
    "VGT_GeDefense_1.0.0-beta.5_Technisches_Datenblatt.pdf.sha256",
)

FORBIDDEN_BYTE_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN RSA " + b"PRIVATE KEY-----",
    b"-----BEGIN EC " + b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----",
    b"212.132." + b"67.175",
    b"87.122." + b"22.193",
)


class StageError(RuntimeError):
    """The GitHub staging boundary was violated."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def excluded(relative: Path) -> bool:
    return (
        any(part in EXCLUDED_DIRECTORIES for part in relative.parts)
        or relative.name == SOURCE_MANIFEST
        or relative.name.endswith(EXCLUDED_SUFFIXES)
    )


def collect_sources(root: Path) -> dict[PurePosixPath, Path]:
    selected: dict[PurePosixPath, Path] = {}
    for name in SOURCE_FILES:
        candidate = root / name
        if not candidate.is_file() or candidate.is_symlink():
            raise StageError(f"required source file missing or unsafe: {name}")
        selected[PurePosixPath(name)] = candidate

    for directory_name in SOURCE_DIRECTORIES:
        directory = root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            raise StageError(f"required source directory missing or unsafe: {directory_name}")
        for candidate in sorted(directory.rglob("*")):
            relative = candidate.relative_to(root)
            if excluded(relative):
                continue
            if candidate.is_symlink():
                raise StageError(f"source symlink rejected: {relative}")
            if candidate.is_file():
                if candidate.stat().st_size > MAX_SOURCE_FILE_BYTES:
                    raise StageError(f"source file exceeds staging boundary: {relative}")
                selected[PurePosixPath(relative.as_posix())] = candidate
    return dict(sorted(selected.items(), key=lambda item: item[0].as_posix()))


def copy_sources(selected: dict[PurePosixPath, Path], repository: Path) -> None:
    for relative, source in selected.items():
        destination = repository.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)


def write_manifest(directory: Path, manifest_name: str) -> None:
    entries: list[str] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.name == manifest_name:
            continue
        relative = path.relative_to(directory).as_posix()
        entries.append(f"{sha256_file(path)}  {relative}\n")
    (directory / manifest_name).write_text("".join(entries), encoding="utf-8", newline="\n")


def verify_manifest(directory: Path, manifest_name: str) -> None:
    manifest = directory / manifest_name
    lines = manifest.read_text(encoding="utf-8").splitlines()
    actual_files = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file() and not path.is_symlink() and path.name != manifest_name
    }
    recorded_files: set[str] = set()
    for line in lines:
        digest, separator, relative = line.partition("  ")
        if separator != "  " or len(digest) != 64 or relative in recorded_files:
            raise StageError(f"malformed manifest record: {line[:80]}")
        path = directory.joinpath(*PurePosixPath(relative).parts)
        if not path.is_file() or path.is_symlink() or sha256_file(path) != digest:
            raise StageError(f"manifest verification failed: {relative}")
        recorded_files.add(relative)
    if recorded_files != actual_files:
        raise StageError("manifest file set does not match staged files")


def copy_release_assets(root: Path, destination: Path) -> None:
    release_root = root / "RUN Build"
    for name in RELEASE_ASSETS:
        source = release_root / name
        if not source.is_file() or source.is_symlink():
            raise StageError(f"required release asset missing or unsafe: {name}")
        shutil.copy2(source, destination / name, follow_symlinks=False)


def scan_forbidden_markers(directory: Path) -> None:
    for path in directory.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as handle:
            overlap = b""
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                data = overlap + block
                for marker in FORBIDDEN_BYTE_MARKERS:
                    if marker in data:
                        raise StageError(f"forbidden sensitive marker found: {path.name}")
                overlap = data[-64:]


def main() -> int:
    root = Path(__file__).resolve(strict=True).parent.parent
    upload = root / UPLOAD_DIRECTORY
    if upload.exists() or upload.is_symlink():
        if upload.is_symlink() or not upload.is_dir():
            raise StageError(f"existing staging target is unsafe: {upload}")
        resolved_upload = upload.resolve(strict=True)
        if resolved_upload.parent != root or resolved_upload.name != UPLOAD_DIRECTORY:
            raise StageError(f"existing staging target escaped the workspace boundary: {upload}")
        verify_manifest(upload, UPLOAD_MANIFEST)
        shutil.rmtree(upload)

    temporary = root / f".github-upload-{os.getpid()}-{secrets.token_hex(8)}"
    temporary.mkdir()
    try:
        repository = temporary / REPOSITORY_DIRECTORY
        release = temporary / RELEASE_DIRECTORY
        repository.mkdir()
        release.mkdir()

        selected = collect_sources(root)
        copy_sources(selected, repository)
        if not (repository / "rust" / "Cargo.lock").is_file():
            raise StageError("pinned rust/Cargo.lock was not staged")
        write_manifest(repository, SOURCE_MANIFEST)
        verify_manifest(repository, SOURCE_MANIFEST)

        copy_release_assets(root, release)
        shutil.copy2(
            root / "GITHUB-UPLOAD-ANLEITUNG.md",
            temporary / "README ZUERST.md",
            follow_symlinks=False,
        )
        scan_forbidden_markers(temporary)
        write_manifest(temporary, UPLOAD_MANIFEST)
        verify_manifest(temporary, UPLOAD_MANIFEST)
        os.replace(temporary, upload)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    repository_files = sum(1 for path in (upload / REPOSITORY_DIRECTORY).rglob("*") if path.is_file())
    release_files = sum(1 for path in (upload / RELEASE_DIRECTORY).rglob("*") if path.is_file())
    print(
        f"PASS: staged {repository_files} repository files and "
        f"{release_files} release assets under {upload}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, StageError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
