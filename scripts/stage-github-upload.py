#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Build a reviewable GitHub repository tree and optional release assets."""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vgt_release_security as security  # noqa: E402


UPLOAD_DIRECTORY = "GitHub Upload"
REPOSITORY_DIRECTORY = "Repository"
RELEASE_DIRECTORY = "Release Assets"
SOURCE_MANIFEST = "SOURCE-MANIFEST.sha256"
UPLOAD_MANIFEST = "UPLOAD-MANIFEST.sha256"
MAX_SOURCE_FILE_BYTES = 100 * 1024 * 1024

SOURCE_DIRECTORIES = (
    ".github",
    "control",
    "docs",
    "gateway",
    "integration",
    "packaging",
    "rust",
    "scripts",
    "testdata",
)

SOURCE_FILES = (
    ".gitattributes",
    ".gitignore",
    "ARCHITECTURE.md",
    "BETA-TEST-PLAN.md",
    "BUILD-RUNBOOK.md",
    "CHANGELOG.md",
    "CI-POLICY.md",
    "CRYPTOGRAPHY.md",
    "DEPENDENCIES.md",
    "gedefense.toml",
    "GEDEFENSE-ASTRAEAOS-INTEGRATION.md",
    "geoip.csv",
    "geoip.csv.sha256",
    "LICENSE",
    "malware-hashes.sha256",
    "Makefile",
    "MIGRATION-NOTES.md",

    "ONECLICK-INSTALL.md",
    "OPERATIONS.md",
    "PRODUCTION-BETA-GATE.md",
    "README.de.md",
    "README.md",
    "README.ru.md",
    "README.zh.md",
    "RELEASE-NOTES.md",
    "ROADMAP.md",
    "SECURITY.md",
    "SECURITY-RELEASE-CHECKLIST.md",
    "THIRD-PARTY-LICENSES.md",
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
    "qa",
    "dist",
    "target",
    UPLOAD_DIRECTORY,
    "RUN Build",
    "release-beta",
    "release-beta-final",
    "release-complete",
    "release-final",
}

EXCLUDED_FILES = {
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
    "emergency_stop.sh",
    "control",
    "gateway",
}

EXCLUDED_SUFFIXES = (
    ".exe",
    ".pyc",
    ".run",
    ".sha256",
    ".zip",
)

def release_asset_names(version: str) -> tuple[str, ...]:
    """Derive release asset names from VERSION (no channel/version drift)."""
    base = f"VGT_GeDefense_Beta_v5_{version}"
    return (
        f"{base}_OneClick.run",
        f"{base}_OneClick.run.sha256",
        f"{base}_Source.zip",
        f"{base}_Source.zip.sha256",
        "release-index.signed.json",
        "release-manifest.signed.json",
        "sbom.spdx.json",
        "build-provenance.json",
        "SHA256SUMS",
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
        or relative.name in EXCLUDED_FILES
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
        relative_path = path.relative_to(directory)
        if (
            not path.is_file()
            or path.is_symlink()
            or path.name == manifest_name
            or ".git" in relative_path.parts
        ):
            continue
        relative = relative_path.as_posix()
        entries.append(f"{sha256_file(path)}  {relative}\n")
    (directory / manifest_name).write_text("".join(entries), encoding="utf-8", newline="\n")


def verify_manifest(directory: Path, manifest_name: str) -> None:
    manifest = directory / manifest_name
    lines = manifest.read_text(encoding="utf-8").splitlines()
    actual_files = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.name != manifest_name
        and ".git" not in path.relative_to(directory).parts
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


def copy_release_assets(root: Path, destination: Path, version: str) -> None:
    release_root = root / "RUN Build"
    public_key = os.environ.get("RELEASE_SIGNING_PUBLIC_KEY", "")
    if not public_key:
        raise StageError("RELEASE_SIGNING_PUBLIC_KEY is required to stage signed release assets (fail closed)")
    required = release_asset_names(version)
    for name in required:
        source = release_root / name
        if not source.is_file() or source.is_symlink():
            raise StageError(f"required release asset missing or unsafe: {name}")
        shutil.copy2(source, destination / name, follow_symlinks=False)
    # Verify the signed index against every staged asset before uploading.
    try:
        index_bytes = (release_root / "release-index.signed.json").read_bytes()
        index = security.verify_release_index(index_bytes, security._load_public_key_argument(public_key))
        for entry in index["artifacts"]:
            candidate = release_root / str(entry["name"])
            if not candidate.is_file():
                raise StageError(f"signed release index references a missing asset: {entry['name']}")
            actual = security.sha256_file(candidate)
            if actual != entry["sha256"]:
                raise StageError(f"signed release index hash mismatch: {entry['name']}")
        manifest = release_root / "release-manifest.signed.json"
        if manifest.is_file():
            security.verify_go_manifest(manifest.read_bytes(), security._load_public_key_argument(public_key), expected_version=version)
        else:
            raise StageError("signed release manifest is missing from the release assets")
    except security.ReleaseError as error:
        raise StageError(f"signed release asset verification failed: {error}") from error


def scan_forbidden_markers(directory: Path) -> None:
    """Delegate to the single shared FORBIDDEN_MARKERS gate (no private copy)."""
    try:
        security.scan_tree_markers(directory)
    except security.GateError as error:
        raise StageError(str(error)) from error


def main(include_release_assets: bool = False) -> int:
    root = Path(__file__).resolve(strict=True).parent.parent
    upload = root / UPLOAD_DIRECTORY
    if upload.exists() or upload.is_symlink():
        if upload.is_symlink() or not upload.is_dir():
            raise StageError(f"existing staging target is unsafe: {upload}")
        resolved_upload = upload.resolve(strict=True)
        if resolved_upload.parent != root or resolved_upload.name != UPLOAD_DIRECTORY:
            raise StageError(f"existing staging target escaped the workspace boundary: {upload}")

    temporary = root / f".github-upload-{os.getpid()}-{secrets.token_hex(8)}"
    temporary.mkdir()
    try:
        repository = temporary / REPOSITORY_DIRECTORY
        release = temporary / RELEASE_DIRECTORY
        repository.mkdir()
        release.mkdir()

        version = (root / "VERSION").read_text(encoding="utf-8").strip()
        security.parse_version(version)
        tracked = set(security.git_tracked_files(root))
        selected = collect_sources(root)
        untracked = sorted(str(relative) for relative in selected if str(relative) not in tracked)
        if untracked:
            raise StageError(f"staging source is not committed to HEAD: {untracked[:5]}")
        copy_sources(selected, repository)
        if not (repository / "rust" / "Cargo.lock").is_file():
            raise StageError("pinned rust/Cargo.lock was not staged")
        write_manifest(repository, SOURCE_MANIFEST)
        verify_manifest(repository, SOURCE_MANIFEST)

        if include_release_assets:
            copy_release_assets(root, release, version)
        else:
            (release / "README.md").write_text(
                "# Release assets pending Linux CI\n\n"
                "The source repository is ready for GitHub. Create and attach the signed "
                "Beta v4 artifacts only after all GitHub CI and concrete Linux host gates pass.\n",
                encoding="utf-8",
                newline="\n",
            )
        shutil.copy2(
            root / "GITHUB-UPLOAD-ANLEITUNG.md",
            temporary / "README ZUERST.md",
            follow_symlinks=False,
        )
        scan_forbidden_markers(temporary)
        write_manifest(temporary, UPLOAD_MANIFEST)
        verify_manifest(temporary, UPLOAD_MANIFEST)
        def _remove_readonly(func, path, excinfo):
            import stat
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass

        repository_dst = upload / REPOSITORY_DIRECTORY
        release_dst = upload / RELEASE_DIRECTORY
        upload.mkdir(parents=True, exist_ok=True)
        repository_dst.mkdir(parents=True, exist_ok=True)
        if release_dst.exists():
            shutil.rmtree(release_dst, onerror=_remove_readonly)
        shutil.copytree(temporary / RELEASE_DIRECTORY, release_dst)

        for child in list(repository_dst.iterdir()):
            if child.name == ".git":
                continue
            if child.is_dir():
                shutil.rmtree(child, onerror=_remove_readonly)
            else:
                child.unlink()

        for child in (temporary / REPOSITORY_DIRECTORY).iterdir():
            if child.name == ".git":
                continue
            dst = repository_dst / child.name
            if child.is_dir():
                shutil.copytree(child, dst)
            else:
                shutil.copy2(child, dst)

        for child in temporary.iterdir():
            if child.name in (REPOSITORY_DIRECTORY, RELEASE_DIRECTORY):
                continue
            shutil.copy2(child, upload / child.name)

        shutil.rmtree(temporary, onerror=_remove_readonly)
    except Exception:
        def _cleanup_readonly(func, path, excinfo):
            import stat
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass
        shutil.rmtree(temporary, onerror=_cleanup_readonly)
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
        arguments = set(sys.argv[1:])
        if arguments - {"--with-release-assets"}:
            raise StageError("usage: stage-github-upload.py [--with-release-assets]")
        raise SystemExit(main(include_release_assets="--with-release-assets" in arguments))
    except (OSError, StageError) as error:
        import traceback
        traceback.print_exc()
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
