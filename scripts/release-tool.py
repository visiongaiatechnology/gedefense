#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""GeDefense release CLI: signing, verification, deterministic packing, SBOM.

Thin command-line wrapper around ``scripts/vgt_release_security.py`` used by
every packer (pack_release_zip.py, build-source-oneclick.sh,
package-artifacts.sh, stage-github-upload.py) and by CI/local release gates.

All commands are offline and fail closed. The release private key is never
accepted from the repository: pass a path outside the working tree (0600 file)
via --private-key or the RELEASE_SIGNING_PRIVATE_KEY environment variable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vgt_release_security as security  # noqa: E402


def _repo_root(value: str | None) -> Path:
    if value:
        return Path(value).resolve()
    return Path(__file__).resolve().parent.parent


def _version(root: Path, override: str | None) -> str:
    if override:
        return override
    text = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not text:
        raise security.ReleaseError("VERSION is empty")
    security.parse_version(text)
    return text


def _epoch(override: int | None) -> int:
    if override is not None:
        if override <= 0:
            raise security.ReleaseError("SOURCE_DATE_EPOCH must be positive")
        return override
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not raw:
        return security.DEFAULT_EPOCH
    try:
        value = int(raw)
    except ValueError as error:
        raise security.ReleaseError(f"SOURCE_DATE_EPOCH is not an integer: {raw!r}") from error
    if value <= 0:
        raise security.ReleaseError("SOURCE_DATE_EPOCH must be positive")
    return value


def _private_key(path: str | None) -> security.ReleaseKey:
    candidate = path or os.environ.get("RELEASE_SIGNING_PRIVATE_KEY", "")
    if not candidate:
        raise security.ReleaseError("no release private key provided (--private-key or RELEASE_SIGNING_PRIVATE_KEY)")
    key = security.load_release_private_key(candidate)
    public_env = os.environ.get("RELEASE_SIGNING_PUBLIC_KEY", "")
    if public_env:
        recorded = security.load_release_public_key(public_env)
        if recorded != key.public:
            raise security.ReleaseError("RELEASE_SIGNING_PUBLIC_KEY does not match the private key")
    return key


def _artifact_entries(root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(root.iterdir()):
        if path.is_dir() or path.is_symlink():
            if path.is_symlink():
                raise security.ReleaseError(f"release artifact directory contains a symlink: {path.name}")
            continue
        lower = path.name.lower()
        if lower.endswith((".sig", ".sha256", ".sig.b64")) or path.name in {"SHA256SUMS", "release-manifest.signed.json"}:
            continue
        entries.append({"name": path.name, "sha256": security.sha256_file(path), "size": path.stat().st_size, "role": _infer_role(path.name)})
    if not entries:
        raise security.ReleaseError(f"release artifact directory is empty: {root}")
    return entries


def _infer_role(name: str) -> str:
    if name.endswith(".run"):
        return "installer"
    if name.endswith(".zip"):
        return "source-archive"
    if name.endswith("sbom.spdx.json"):
        return "sbom"
    if name.endswith("build-provenance.json"):
        return "provenance"
    if name.endswith("release-manifest.signed.json"):
        return "release-manifest"
    if name.startswith("gedefense-"):
        return "binary"
    return "other"


def _parse_roles(values: list[str]) -> dict[str, str]:
    roles: dict[str, str] = {}
    for item in values:
        name, separator, role = item.partition("=")
        if separator != "=" or not name or not role:
            raise security.ReleaseError(f"invalid --role value: {item!r}")
        roles[name] = role
    return roles


def _parse_hashes(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        name, separator, path = item.partition("=")
        if separator != "=" or not name or not path:
            raise security.ReleaseError(f"invalid --artifact value: {item!r}")
        result[name] = security.sha256_file(path)
    return result


def _write_json(path: Path, document: object) -> None:
    security.write_atomic(path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"), 0o644)


def cmd_keygen(args: argparse.Namespace) -> int:
    key = security.generate_key()
    private_path, public_path = security.write_release_keypair(args.out, key, force=args.force)
    print(json.dumps({
        "private_key": str(private_path),
        "public_key": str(public_path),
        "public_key_hex": key.public_hex,
        "signer": key.signer_id,
        "fingerprint_sha256": key.fingerprint,
        "note": "Keep the private key offline (0600, outside the repository). Publish the public key/fingerprint out-of-band.",
    }, indent=2, sort_keys=True))
    return 0


def cmd_gate_tree(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo)
    files = security.collect_tracked_sources(root)
    scanned = 0
    for relative in files:
        path = root / relative
        reason = security.forbidden_path_reason(relative)
        if reason:
            raise security.GateError(f"{reason}: {relative}")
        security.scan_file_markers(path)
        scanned += 1
    findings = security.audit_tracked_markers(root)
    result = {
        "status": "PASS",
        "tracked_files": len(security.git_tracked_files(root)),
        "packaged_files": len(files),
        "excluded_internal_files": len(security.git_tracked_files(root)) - len(files),
        "scanned": scanned,
        "gate": "tracked-allowlist+FORBIDDEN_MARKERS",
        "repository_marker_findings": findings,
        "repository_marker_note": (
            "Repository-hygiene report only: internal-only documents are excluded from published "
            "artifacts, but leaked operational values remain in git history and require owner "
            "redaction/rotation (external remediation)."
        ),
    }
    if findings:
        print(json.dumps({"warning": f"{len(findings)} forbidden marker(s) remain in tracked internal documents (excluded from releases)", "findings": findings}, sort_keys=True), file=sys.stderr)
    print(json.dumps(result, sort_keys=True))
    return 0


def cmd_pack_source(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo)
    version = _version(root, args.version)
    epoch = _epoch(args.epoch)
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    channel = security.channel_for_version(version)
    with_digest = args.verify_twice
    work = Path(args.work_dir) if args.work_dir else out_dir / ".source-stage"
    if work.exists():
        raise security.ReleaseError(f"staging directory already exists: {work}")
    try:
        stage_info = security.stage_tracked_tree(root, work, allow_dirty=args.allow_dirty)
        name = f"VGT_GeDefense_{channel.capitalize()}_v5_{version}_Source.zip"
        archive = out_dir / name
        prefix = f"VGT_GeDefense_{channel.capitalize()}_v5_{version}/"
        first_hash = security.deterministic_zip(work, archive, prefix=prefix, epoch=epoch)
        sidecar = out_dir / (name + ".sha256")
        sidecar.write_text(f"{first_hash}  {name}\n", encoding="utf-8", newline="\n")
        manifest_copy = out_dir / "SOURCE-MANIFEST.sha256"
        manifest_copy.write_text(str(stage_info["manifest"]), encoding="utf-8", newline="\n")
        if with_digest:
            second_work = out_dir / ".source-stage-verify"
            if second_work.exists():
                raise security.ReleaseError(f"verification staging directory already exists: {second_work}")
            try:
                security.stage_tracked_tree(root, second_work, allow_dirty=args.allow_dirty)
                second_archive = out_dir / (name + ".verify")
                second_hash = security.deterministic_zip(second_work, second_archive, prefix=prefix, epoch=epoch)
                if second_hash != first_hash:
                    raise security.GateError("source archive is not reproducible: two builds produced different digests")
                second_archive.unlink()
            finally:
                _remove_tree(second_work)
        result = {
            "status": "PASS",
            "version": version,
            "channel": channel,
            "epoch": epoch,
            "files": stage_info["files"],
            "commit": stage_info["commit"],
            "tree_clean": stage_info["tree_clean"],
            "manifest_sha256": hashlib.sha256(str(stage_info["manifest"]).encode("utf-8")).hexdigest(),
            "archive": str(archive),
            "sha256": first_hash,
            "size": archive.stat().st_size,
            "reproducibility_verified": bool(with_digest),
        }
        print(json.dumps(result, sort_keys=True))
    finally:
        _remove_tree(work)
    return 0


def cmd_stage_source(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo)
    epoch = _epoch(args.epoch)
    stage = Path(args.stage).resolve()
    if stage.exists():
        raise security.ReleaseError(f"staging directory already exists: {stage}")
    info = security.stage_tracked_tree(root, stage, allow_dirty=args.allow_dirty)
    tar_path = Path(args.tar_out).resolve()
    tar_sha = security.deterministic_tar_gz(stage, tar_path, epoch=epoch)
    manifest_sha = hashlib.sha256(str(info["manifest"]).encode("utf-8")).hexdigest()
    print(json.dumps({
        "status": "PASS",
        "stage": str(stage),
        "files": info["files"],
        "commit": info["commit"],
        "tree_clean": info["tree_clean"],
        "manifest_sha256": manifest_sha,
        "payload": str(tar_path),
        "payload_sha256": tar_sha,
        "payload_size": tar_path.stat().st_size,
        "epoch": epoch,
    }, sort_keys=True))
    return 0


def cmd_tar_gz(args: argparse.Namespace) -> int:
    digest = security.deterministic_tar_gz(Path(args.dir).resolve(), Path(args.out).resolve(), epoch=_epoch(args.epoch))
    print(json.dumps({"status": "PASS", "sha256": digest, "out": str(Path(args.out).resolve())}, sort_keys=True))
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo)
    version = _version(root, args.version)
    epoch = _epoch(args.epoch)
    git = security.git_metadata(root)
    artifacts = _parse_hashes(args.artifact)
    document = security.build_spdx(root, version=version, epoch=epoch, commit=str(git["commit"]), artifact_hashes=artifacts)
    out = Path(args.out).resolve()
    _write_json(out, document)
    print(json.dumps({"status": "PASS", "sbom": str(out), "sha256": security.sha256_file(out), "packages": len(document["packages"])}, sort_keys=True))
    return 0


def cmd_provenance(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo)
    version = _version(root, args.version)
    epoch = _epoch(args.epoch)
    artifacts = _parse_hashes(args.artifact)
    sbom_path = Path(args.sbom).resolve()
    if not sbom_path.is_file():
        raise security.ReleaseError(f"SBOM is missing: {sbom_path}")
    manifest_path = Path(args.source_manifest).resolve()
    if not manifest_path.is_file():
        raise security.ReleaseError(f"SOURCE-MANIFEST.sha256 is missing: {manifest_path}")
    document = security.build_provenance(
        root,
        version=version,
        epoch=epoch,
        artifact_hashes=artifacts,
        sbom_sha256=security.sha256_file(sbom_path),
        source_manifest_sha256=security.sha256_file(manifest_path),
    )
    out = Path(args.out).resolve()
    _write_json(out, document)
    print(json.dumps({"status": "PASS", "provenance": str(out), "sha256": security.sha256_file(out)}, sort_keys=True))
    return 0


def cmd_sign_go_manifest(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo)
    version = _version(root, args.version)
    epoch = _epoch(args.epoch)
    key = _private_key(args.private_key)
    toolchains = security.release_toolchains(root)
    channel = args.channel or security.channel_for_version(version)
    artifact_dir = Path(args.artifact_dir).resolve()
    envelope = security.build_go_envelope(version=version, channel=channel, epoch=epoch, toolchains=toolchains, artifact_dir=artifact_dir)
    document = security.sign_go_manifest(envelope, key)
    out = Path(args.out).resolve()
    security.write_atomic(out, document, 0o644)
    # Self-verify before announcing success.
    security.verify_go_manifest(document, key.public, expected_version=version, expected_toolchains=toolchains)
    print(json.dumps({"status": "PASS", "manifest": str(out), "signer": key.signer_id, "fingerprint_sha256": key.fingerprint, "artifacts": len(envelope["artifacts"])}, sort_keys=True))
    return 0


def cmd_sign_index(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo)
    version = _version(root, args.version)
    epoch = _epoch(args.epoch)
    key = _private_key(args.private_key)
    git = security.git_metadata(root)
    artifact_dir = Path(args.artifacts_dir).resolve()
    roles = _parse_roles(args.role)
    entries = _artifact_entries(artifact_dir)
    for entry in entries:
        if entry["name"] in roles:
            entry["role"] = roles[entry["name"]]
    index = security.build_release_index(
        version=version,
        channel=security.channel_for_version(version),
        commit=str(git["commit"]),
        tree_clean=bool(git["tree_clean"]),
        epoch=epoch,
        key=key,
        artifacts=entries,
    )
    document = security.sign_release_index(index, key)
    out = Path(args.out).resolve()
    security.write_atomic(out, document, 0o644)
    security.verify_release_index(document, key.public, expected_version=version)
    print(json.dumps({"status": "PASS", "index": str(out), "signer": key.signer_id, "fingerprint_sha256": key.fingerprint, "artifacts": len(entries)}, sort_keys=True))
    return 0


def cmd_verify_index(args: argparse.Namespace) -> int:
    public = security._load_public_key_argument(args.pubkey)
    artifacts: dict[str, Path] = {}
    for item in args.artifact_file:
        name, separator, path = item.partition("=")
        if separator != "=":
            raise security.ReleaseError(f"invalid --artifact-file: {item!r}")
        artifacts[name] = Path(path)
    revoked = security.load_revocation_document(args.revocation_list) if args.revocation_list else set()
    index = security.verify_release_index(
        security.read_limited(args.index),
        public,
        expected_version=args.expected_version or None,
        artifact_files=artifacts or None,
        revoked_fingerprints=revoked,
    )
    print(json.dumps({"status": "PASS", "version": index["version"], "channel": index["channel"], "commit": index["commit"], "artifacts": len(index["artifacts"]), "signer": "ed25519:" + public[:8].hex()}, sort_keys=True))
    return 0


def cmd_verify_manifest(args: argparse.Namespace) -> int:
    public = security._load_public_key_argument(args.pubkey)
    toolchains = None
    if args.toolchains_json:
        loaded = json.loads(args.toolchains_json)
        toolchains = {str(key): str(value) for key, value in loaded.items()}
    verified = security.verify_go_manifest(
        security.read_limited(args.manifest),
        public,
        expected_version=args.expected_version,
        expected_toolchains=toolchains,
        artifact_dir=args.artifact_dir or None,
    )
    print(json.dumps({"status": "PASS", "version": verified.envelope["version"], "signer": verified.signer, "artifacts": len(verified.envelope["artifacts"])}, sort_keys=True))
    return 0


def cmd_verify_release(args: argparse.Namespace) -> int:
    public = security._load_public_key_argument(args.pubkey)
    directory = Path(args.dir).resolve()
    index_document = security.read_limited(directory / "release-index.signed.json")
    revoked = security.load_revocation_document(args.revocation_list) if args.revocation_list else set()
    index = security.verify_release_index(index_document, public, expected_version=args.expected_version or None, artifact_root=directory, revoked_fingerprints=revoked)
    manifest_path = directory / "release-manifest.signed.json"
    if manifest_path.is_file():
        security.verify_go_manifest(
            security.read_limited(manifest_path),
            public,
            expected_version=args.expected_version or str(index["version"]),
            artifact_dir=directory if args.check_manifests_artifacts else None,
        )
    elif args.require_manifest:
        raise security.ReleaseError("required signed release manifest is missing")
    print(json.dumps({"status": "PASS", "version": index["version"], "artifacts": len(index["artifacts"]), "manifest": manifest_path.is_file()}, sort_keys=True))
    return 0


def cmd_toolchains(args: argparse.Namespace) -> int:
    root = _repo_root(args.repo)
    print(json.dumps(security.release_toolchains(root), sort_keys=True))
    return 0


def cmd_version_guard(args: argparse.Namespace) -> int:
    decision = security.version_decision(
        args.candidate,
        installed=args.installed or None,
        floor=args.floor or None,
        allow_downgrade=args.allow_downgrade,
    )
    print(json.dumps({
        "allowed": decision.allowed,
        "action": decision.action,
        "reason": decision.reason,
        "candidate": decision.candidate,
        "installed": decision.installed,
        "floor": decision.floor,
        "next_floor": decision.next_floor,
    }, sort_keys=True))
    return 0 if decision.allowed else 3


def cmd_verify_archive(args: argparse.Namespace) -> int:
    archive = Path(args.archive).resolve()
    if not archive.is_file():
        raise security.ReleaseError(f"archive is missing: {archive}")
    import tempfile

    with tempfile.TemporaryDirectory(prefix="vgt-archive-gate-") as temporary:
        if archive.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive) as handle:
                if handle.testzip() is not None:
                    raise security.GateError("zip archive is corrupt")
                handle.extractall(temporary)
        else:
            import tarfile

            with tarfile.open(archive, "r:gz") as handle:
                for member in handle.getmembers():
                    pure = security.PurePosixPath(member.name)
                    if pure.is_absolute() or ".." in pure.parts or member.issym() or member.islnk() or member.isdev():
                        raise security.GateError(f"unsafe archive member: {member.name}")
                handle.extractall(temporary)
        scanned = security.scan_tree_markers(temporary)
        manifest_count = len(list(Path(temporary).rglob("SOURCE-MANIFEST.sha256"))) + len(list(Path(temporary).rglob("PAYLOAD-MANIFEST.sha256")))
    print(json.dumps({"status": "PASS", "archive": str(archive), "scanned_files": scanned, "manifests": manifest_count}, sort_keys=True))
    return 0


def _remove_tree(path: Path) -> None:
    import shutil

    if path.exists():
        shutil.rmtree(path, ignore_errors=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release-tool.py", description="GeDefense offline release tooling")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate a local Ed25519 release key pair")
    keygen.add_argument("--out", required=True)
    keygen.add_argument("--force", action="store_true")
    keygen.set_defaults(func=cmd_keygen)

    gate = sub.add_parser("gate-tree", help="enforce tracked-files allowlist and FORBIDDEN_MARKERS")
    gate.add_argument("--repo", default="")
    gate.set_defaults(func=cmd_gate_tree)

    pack = sub.add_parser("pack-source", help="build the deterministic source archive")
    pack.add_argument("--repo", default="")
    pack.add_argument("--out-dir", required=True)
    pack.add_argument("--work-dir", default="")
    pack.add_argument("--version", default="")
    pack.add_argument("--epoch", type=int, default=None)
    pack.add_argument("--verify-twice", action="store_true")
    pack.add_argument("--allow-dirty", action="store_true", help="explicit local dry-run on an uncommitted tree")
    pack.set_defaults(func=cmd_pack_source)

    stage = sub.add_parser("stage-source", help="stage tracked sources and build a deterministic tar.gz")
    stage.add_argument("--repo", default="")
    stage.add_argument("--stage", required=True)
    stage.add_argument("--tar-out", required=True)
    stage.add_argument("--epoch", type=int, default=None)
    stage.add_argument("--allow-dirty", action="store_true", help="explicit local dry-run on an uncommitted tree")
    stage.set_defaults(func=cmd_stage_source)

    tar_gz = sub.add_parser("tar-gz", help="create a deterministic tar.gz from a directory")
    tar_gz.add_argument("--dir", required=True)
    tar_gz.add_argument("--out", required=True)
    tar_gz.add_argument("--epoch", type=int, default=None)
    tar_gz.set_defaults(func=cmd_tar_gz)

    sbom = sub.add_parser("sbom", help="generate an SPDX 2.3 SBOM")
    sbom.add_argument("--repo", default="")
    sbom.add_argument("--out", required=True)
    sbom.add_argument("--version", default="")
    sbom.add_argument("--epoch", type=int, default=None)
    sbom.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH")
    sbom.set_defaults(func=cmd_sbom)

    provenance = sub.add_parser("provenance", help="generate build provenance")
    provenance.add_argument("--repo", default="")
    provenance.add_argument("--out", required=True)
    provenance.add_argument("--version", default="")
    provenance.add_argument("--epoch", type=int, default=None)
    provenance.add_argument("--sbom", required=True)
    provenance.add_argument("--source-manifest", required=True)
    provenance.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH")
    provenance.set_defaults(func=cmd_provenance)

    sign_manifest = sub.add_parser("sign-go-manifest", help="sign the canonical Go-format release manifest")
    sign_manifest.add_argument("--repo", default="")
    sign_manifest.add_argument("--artifact-dir", required=True)
    sign_manifest.add_argument("--out", required=True)
    sign_manifest.add_argument("--private-key", default="")
    sign_manifest.add_argument("--version", default="")
    sign_manifest.add_argument("--channel", default="")
    sign_manifest.add_argument("--epoch", type=int, default=None)
    sign_manifest.set_defaults(func=cmd_sign_go_manifest)

    sign_index = sub.add_parser("sign-index", help="sign the release index")
    sign_index.add_argument("--repo", default="")
    sign_index.add_argument("--artifacts-dir", required=True)
    sign_index.add_argument("--out", required=True)
    sign_index.add_argument("--private-key", default="")
    sign_index.add_argument("--version", default="")
    sign_index.add_argument("--epoch", type=int, default=None)
    sign_index.add_argument("--role", action="append", default=[], metavar="NAME=ROLE")
    sign_index.set_defaults(func=cmd_sign_index)

    verify_index = sub.add_parser("verify-index", help="verify a signed release index")
    verify_index.add_argument("--index", required=True)
    verify_index.add_argument("--pubkey", required=True)
    verify_index.add_argument("--expected-version", default="")
    verify_index.add_argument("--artifact-file", action="append", default=[], metavar="NAME=PATH")
    verify_index.add_argument("--revocation-list", default="", help="JSON release-key revocation list; revoked keys are refused")
    verify_index.set_defaults(func=cmd_verify_index)

    verify_manifest = sub.add_parser("verify-manifest", help="verify a Go-format signed release manifest")
    verify_manifest.add_argument("--manifest", required=True)
    verify_manifest.add_argument("--pubkey", required=True)
    verify_manifest.add_argument("--expected-version", required=True)
    verify_manifest.add_argument("--toolchains-json", default="")
    verify_manifest.add_argument("--artifact-dir", default="")
    verify_manifest.set_defaults(func=cmd_verify_manifest)

    verify_release = sub.add_parser("verify-release", help="verify all signed release artifacts in a directory")
    verify_release.add_argument("--dir", required=True)
    verify_release.add_argument("--pubkey", required=True)
    verify_release.add_argument("--expected-version", default="")
    verify_release.add_argument("--require-manifest", action="store_true")
    verify_release.add_argument("--check-manifests-artifacts", action="store_true")
    verify_release.add_argument("--revocation-list", default="", help="JSON release-key revocation list; revoked keys are refused")
    verify_release.set_defaults(func=cmd_verify_release)

    verify_archive = sub.add_parser("verify-archive", help="scan an archive for forbidden markers/symlinks")
    verify_archive.add_argument("--archive", required=True)
    verify_archive.set_defaults(func=cmd_verify_archive)

    toolchains = sub.add_parser("toolchains", help="print pinned release toolchains as JSON")
    toolchains.add_argument("--repo", default="")
    toolchains.set_defaults(func=cmd_toolchains)

    guard = sub.add_parser("version-guard", help="semantic version monotonicity / anti-rollback decision")
    guard.add_argument("--candidate", required=True)
    guard.add_argument("--installed", default="")
    guard.add_argument("--floor", default="")
    guard.add_argument("--allow-downgrade", action="store_true")
    guard.set_defaults(func=cmd_version_guard)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except security.GateError as error:
        print(f"CONTENT-GATE-FAILED: {error}", file=sys.stderr)
        return 2
    except security.ReleaseError as error:
        print(f"RELEASE-ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
