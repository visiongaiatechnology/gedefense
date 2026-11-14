#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Unit and negative tests for scripts/vgt_release_security.py.

Run with:  python3 -m unittest discover -s scripts/tests -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vgt_release_security as security  # noqa: E402

RFC8032_VECTORS = [
    {
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
]


class TempRepo:
    """Disposable git repository fixture."""

    def __init__(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="vgt-release-test-"))
        self.root = self.directory / "repo"
        self.root.mkdir()
        self._git("init", "-q")
        self._git("config", "user.email", "release-test@example.invalid")
        self._git("config", "user.name", "Release Test")

    def _git(self, *arguments: str) -> None:
        result = subprocess.run(["git", "-C", str(self.root), *arguments], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise AssertionError(result.stderr.decode("utf-8", "replace"))

    def write(self, relative: str, content: str | bytes, *, mode: int = 0o644) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            content = content.encode("utf-8")
        path.write_bytes(content)
        os.chmod(path, mode)
        return path

    def commit(self) -> None:
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "fixture")

    def cleanup(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)

    def __enter__(self) -> "TempRepo":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.cleanup()


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self) -> None:
        for vector in RFC8032_VECTORS:
            seed = bytes.fromhex(vector["seed"])
            message = bytes.fromhex(vector["message"])
            public = security.ed25519_public_from_seed(seed)
            self.assertEqual(public.hex(), vector["public"])
            signature = security.ed25519_sign(seed, message)
            self.assertEqual(signature.hex(), vector["signature"])
            self.assertTrue(security.ed25519_verify(public, message, signature))

    def test_verify_rejects_tampering(self) -> None:
        key = security.generate_key()
        message = b"release message"
        signature = security.ed25519_sign(key.seed, message)
        self.assertFalse(security.ed25519_verify(key.public, message + b"x", signature))
        broken = bytearray(signature)
        broken[5] ^= 0xFF
        self.assertFalse(security.ed25519_verify(key.public, message, bytes(broken)))
        self.assertFalse(security.ed25519_verify(b"\x00" * 31, message, signature))
        self.assertFalse(security.ed25519_verify(key.public, message, b"\x00" * 64))

    def test_keypair_roundtrip_and_permissions(self) -> None:
        key = security.generate_key()
        with tempfile.TemporaryDirectory() as temporary:
            private_path, public_path = security.write_release_keypair(temporary, key)
            self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(public_path.stat().st_mode), 0o644)
            loaded = security.load_release_private_key(private_path)
            self.assertEqual(loaded.public, key.public)
            with self.assertRaises(security.ReleaseError):
                security.write_release_keypair(temporary, security.generate_key())
            os.chmod(private_path, 0o644)
            with self.assertRaises(security.ReleaseError):
                security.load_release_private_key(private_path)


class GoManifestTests(unittest.TestCase):
    TOOLCHAINS = {
        "go": "go1.27.3",
        "node": "v22.16.0",
        "rust": "1.97.1",
        "rust-ebpf": "nightly-2026-07-16",
        "bpf-linker": "0.10.3",
    }
    EPOCH = 1785110400

    def _artifact_dir(self, root: Path) -> Path:
        directory = root / "artifacts"
        directory.mkdir()
        for name in ("gedefense-control", "gedefense-core", "gedefense-ebpf", "sbom.spdx.json", "build-provenance.json", "gedefense-access"):
            (directory / name).write_bytes(f"fixture:{name}".encode("utf-8"))
        return directory

    def _signed_manifest(self, root: Path, key: security.ReleaseKey, version: str = "5.0.0-beta.1") -> tuple[bytes, Path]:
        directory = self._artifact_dir(root)
        envelope = security.build_go_envelope(
            version=version,
            channel="beta",
            epoch=self.EPOCH,
            toolchains=self.TOOLCHAINS,
            artifact_dir=directory,
        )
        return security.sign_go_manifest(envelope, key), directory

    def test_canonical_encoding_matches_go_field_order(self) -> None:
        envelope = {
            "schema": security.GO_MANIFEST_SCHEMA,
            "product": security.PRODUCT,
            "version": "5.0.0-beta.1",
            "channel": "beta",
            "created_at": "2026-07-25T00:00:00Z",
            "toolchains": dict(self.TOOLCHAINS),
            "artifacts": {"b": {"sha256": "b" * 64, "size": 2}, "a": {"sha256": "a" * 64, "size": 1}},
        }
        canonical = security.canonical_go_envelope(envelope).decode("utf-8")
        self.assertIn('"schema":"vgt.gedefense.release.v1"', canonical)
        self.assertIn('"artifacts":{"a":{"sha256":"' + "a" * 64 + '","size":1},"b"', canonical)
        self.assertIn('"toolchains":{"bpf-linker":"0.10.3","go":"go1.27.3"', canonical)
        self.assertLess(canonical.index('"bpf-linker"'), canonical.index('"go"'))

    def test_sign_verify_roundtrip_and_artifact_binding(self) -> None:
        key = security.generate_key()
        with tempfile.TemporaryDirectory() as temporary:
            document, directory = self._signed_manifest(Path(temporary), key)
            verified = security.verify_go_manifest(
                document,
                key.public,
                expected_version="5.0.0-beta.1",
                expected_toolchains=self.TOOLCHAINS,
                artifact_dir=directory,
            )
            self.assertEqual(verified.envelope["version"], "5.0.0-beta.1")
            # tampered artifact
            (directory / "gedefense-control").write_bytes(b"tampered")
            with self.assertRaises(security.ReleaseError):
                security.verify_go_manifest(document, key.public, expected_version="5.0.0-beta.1", artifact_dir=directory)

    def test_tamper_and_negative_cases(self) -> None:
        key = security.generate_key()
        with tempfile.TemporaryDirectory() as temporary:
            document, directory = self._signed_manifest(Path(temporary), key)
            payload = json.loads(document)
            # tampered signature
            signature = bytearray(security.base64url_decode(payload["signature"]))
            signature[0] ^= 1
            payload["signature"] = security.base64url_encode(bytes(signature))
            with self.assertRaises(security.ReleaseError):
                security.verify_go_manifest(json.dumps(payload).encode(), key.public, expected_version="5.0.0-beta.1")
            # unknown field
            payload = json.loads(document)
            payload["envelope"]["extra"] = "rejected"
            with self.assertRaises(security.ReleaseError):
                security.verify_go_manifest(json.dumps(payload).encode(), key.public, expected_version="5.0.0-beta.1")
            # version mismatch
            with self.assertRaises(security.ReleaseError):
                security.verify_go_manifest(document, key.public, expected_version="5.0.1")
            # toolchain mismatch
            with self.assertRaises(security.ReleaseError):
                security.verify_go_manifest(document, key.public, expected_version="5.0.0-beta.1", expected_toolchains={"go": "go0.0.0"})
            # wrong key
            with self.assertRaises(security.ReleaseError):
                security.verify_go_manifest(document, security.generate_key().public, expected_version="5.0.0-beta.1")
            # duplicate JSON keys
            with self.assertRaises(security.ReleaseError):
                security.verify_go_manifest(b'{"envelope":{},"envelope":{},"signer":"","signature":""}', key.public, expected_version="5.0.0-beta.1")

    def test_required_artifact_missing_is_rejected(self) -> None:
        key = security.generate_key()
        with tempfile.TemporaryDirectory() as temporary:
            document, directory = self._signed_manifest(Path(temporary), key)
            (directory / "gedefense-ebpf").unlink()
            with self.assertRaises(security.ReleaseError):
                security.verify_go_manifest(document, key.public, expected_version="5.0.0-beta.1", artifact_dir=directory)


class ReleaseIndexTests(unittest.TestCase):
    def _index(self, key: security.ReleaseKey, artifacts: list[dict[str, object]]) -> dict[str, object]:
        return security.build_release_index(
            version="5.0.0-beta.1",
            channel="beta",
            commit="b5b103f04c7f21c2468f9cce876c4dec1e6dd523",
            tree_clean=True,
            epoch=1785110400,
            key=key,
            artifacts=artifacts,
        )

    def test_sign_verify_and_tamper(self) -> None:
        key = security.generate_key()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload.tar.gz"
            payload.write_bytes(b"payload-bytes")
            source = root / "source.zip"
            source.write_bytes(b"source-bytes")
            artifacts = [
                {"name": "payload.tar.gz", "sha256": security.sha256_file(payload), "size": payload.stat().st_size, "role": "installer-payload"},
                {"name": "source.zip", "sha256": security.sha256_file(source), "size": source.stat().st_size, "role": "source-archive"},
            ]
            document = security.sign_release_index(self._index(key, artifacts), key)
            index = security.verify_release_index(
                document,
                key.public,
                expected_version="5.0.0-beta.1",
                artifact_files={"payload.tar.gz": payload, "source.zip": source},
            )
            self.assertEqual(index["version"], "5.0.0-beta.1")
            mismatch = json.loads(document)
            mismatch["index"]["artifacts"][0]["sha256"] = "0" * 64
            with self.assertRaises(security.ReleaseError):
                security.verify_release_index(json.dumps(mismatch).encode(), key.public, expected_version="5.0.0-beta.1")
            payload.write_bytes(b"tampered-payload")
            with self.assertRaises(security.ReleaseError):
                security.verify_release_index(document, key.public, expected_version="5.0.0-beta.1", artifact_files={"payload.tar.gz": payload})
            with self.assertRaises(security.ReleaseError):
                security.verify_release_index(document, security.generate_key().public, expected_version="5.0.0-beta.1")
            with self.assertRaises(security.ReleaseError):
                security.verify_release_index(document, key.public, expected_version="5.0.1")


class GateTests(unittest.TestCase):
    def test_forbidden_paths(self) -> None:
        for relative in (
            "control/webtools/allowlist.json",
            "wsl-verify.sh",
            "config/dashboard.token",
            "config/release.key",
            "dist/gedefense-control",
            "rust/target/release/core",
            "ARCHIVE.zip",
            ".git/config",
        ):
            self.assertIsNotNone(security.forbidden_path_reason(relative), relative)
        for relative in ("control/main.go", "scripts/release-tool.py", "geoip.csv", "docs/release/SIGNED-RELEASE.md"):
            self.assertIsNone(security.forbidden_path_reason(relative), relative)

    def test_marker_detection(self) -> None:
        marker = security.FORBIDDEN_MARKERS[0]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "leak.bin"
            path.write_bytes(b"prefix" + marker + b"suffix")
            with self.assertRaises(security.GateError):
                security.scan_file_markers(path)
            clean = Path(temporary) / "clean.bin"
            clean.write_bytes(b"nothing sensitive here")
            security.scan_file_markers(clean)
        self.assertIsNotNone(security.has_forbidden_marker(security.FORBIDDEN_MARKERS[1]))

    def test_tracked_allowlist_and_staging(self) -> None:
        with TempRepo() as repo:
            repo.write("README.md", "release fixture\n")
            repo.write("control/main.go", "package main\n")
            repo.write("geoip.csv", "network,country\n")
            repo.write(".gitignore", "control/webtools/\n*.zip\nwsl-*.sh\n")
            repo.write("control/webtools/allowlist.json", '{"ip":"hidden"}\n')
            repo.write("wsl-verify.sh", "#!/bin/sh\n")
            repo.write("dev.zip", "zip\n")
            repo.commit()
            tracked = security.collect_tracked_sources(repo.root)
            self.assertIn("README.md", tracked)
            self.assertNotIn("control/webtools/allowlist.json", tracked)
            self.assertNotIn("wsl-verify.sh", tracked)
            self.assertNotIn("dev.zip", tracked)
            with tempfile.TemporaryDirectory() as temporary:
                stage = Path(temporary) / "stage"
                info = security.stage_tracked_tree(repo.root, stage)
                self.assertFalse((stage / "control/webtools").exists())
                self.assertFalse((stage / "wsl-verify.sh").exists())
                manifest = (stage / "SOURCE-MANIFEST.sha256").read_text(encoding="utf-8")
                count = security.verify_manifest_lines(manifest, stage)
                self.assertEqual(count, info["files"] - 0)
                # tampering is detected
                (stage / "README.md").write_text("tampered\n", encoding="utf-8")
                with self.assertRaises(security.GateError):
                    security.verify_manifest_lines(manifest, stage)

    def test_tracked_sensitive_marker_is_rejected(self) -> None:
        with TempRepo() as repo:
            repo.write("README.md", "ok\n")
            repo.write("leaked.txt", b"x" + security.FORBIDDEN_MARKERS[0] + b"y")
            repo.commit()
            # The allowlist gate is path-based; marker content is enforced when
            # files are staged/packed (fail closed).
            security.collect_tracked_sources(repo.root)
            with self.assertRaises(security.GateError):
                with tempfile.TemporaryDirectory() as temporary:
                    security.stage_tracked_tree(repo.root, Path(temporary) / "stage")

    def test_internal_operational_docs_are_excluded(self) -> None:
        with TempRepo() as repo:
            repo.write("README.md", "public\n")
            repo.write("Next.md", "internal handoff\n")
            repo.write("VGT-AUDIT-20261016-GEDEFENSE.md", "audit evidence\n")
            repo.write("wsl-verify.sh", "#!/bin/sh\n")
            repo.write("docs/release/SIGNED-RELEASE.md", "public docs\n")
            repo.commit()
            files = security.collect_tracked_sources(repo.root)
            self.assertIn("README.md", files)
            self.assertIn("docs/release/SIGNED-RELEASE.md", files)
            for excluded in ("Next.md", "VGT-AUDIT-20261016-GEDEFENSE.md", "wsl-verify.sh"):
                self.assertNotIn(excluded, files)
                self.assertTrue(security.is_internal_only_path(excluded))
            with tempfile.TemporaryDirectory() as temporary:
                stage = Path(temporary) / "stage"
                security.stage_tracked_tree(repo.root, stage)
                self.assertFalse((stage / "Next.md").exists())
                self.assertTrue((stage / "README.md").exists())

    def test_repository_marker_audit_reports_internal_leak(self) -> None:
        with TempRepo() as repo:
            repo.write("README.md", "public\n")
            repo.write("Next.md", b"internal " + security.FORBIDDEN_MARKERS[-1])
            repo.commit()
            findings = security.audit_tracked_markers(repo.root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["file"], "Next.md")
            self.assertEqual(findings[0]["kind"], "operational-value")
            # The release allowlist excludes the internal document, so staging
            # succeeds without publishing the leaked value.
            with tempfile.TemporaryDirectory() as temporary:
                security.stage_tracked_tree(repo.root, Path(temporary) / "stage")

    def test_symlink_tracked_source_rejected(self) -> None:
        with TempRepo() as repo:
            repo.write("README.md", "ok\n")
            os.symlink("README.md", repo.root / "link.md")
            repo.commit()
            with self.assertRaises(security.GateError):
                security.collect_tracked_sources(repo.root)

    def test_scan_tree_rejects_markers_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "good.txt").write_text("clean\n", encoding="utf-8")
            self.assertEqual(security.scan_tree_markers(root), 1)
            (root / "leak.txt").write_bytes(b"x" + security.FORBIDDEN_MARKERS[0] + b"y")
            with self.assertRaises(security.GateError):
                security.scan_tree_markers(root)
            (root / "leak.txt").unlink()
            os.symlink("good.txt", root / "link")
            with self.assertRaises(security.GateError):
                security.scan_tree_markers(root)


class PackagingTests(unittest.TestCase):
    def _fixture(self, base: Path) -> Path:
        root = base / "tree"
        root.mkdir()
        (root / "VERSION").write_text("5.0.0-beta.1\n", encoding="utf-8")
        (root / "bin").mkdir()
        (root / "bin" / "tool").write_text("#!/bin/sh\necho tool\n", encoding="utf-8")
        os.chmod(root / "bin" / "tool", 0o755)
        return root

    def test_deterministic_zip_twice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._fixture(base)
            first = security.deterministic_zip(root, base / "a.zip", prefix="Release/", epoch=1785110400)
            second = security.deterministic_zip(root, base / "b.zip", prefix="Release/", epoch=1785110400)
            self.assertEqual(first, second)
            with security.zipfile.ZipFile(base / "a.zip") as archive:
                names = archive.namelist()
                self.assertEqual(names, sorted(names))
                self.assertEqual(archive.getinfo("Release/bin/tool").date_time, (2026, 7, 27, 0, 0, 0))

    def test_deterministic_tar_gz_twice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self._fixture(base)
            first = security.deterministic_tar_gz(root, base / "a.tar.gz", epoch=1785110400)
            second = security.deterministic_tar_gz(root, base / "b.tar.gz", epoch=1785110400)
            self.assertEqual(first, second)

    def test_manifest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._fixture(Path(temporary))
            manifest = security.build_manifest(root)
            self.assertEqual(security.verify_manifest_lines(manifest, root), 2)
            (root / "VERSION").write_text("6.0.0\n", encoding="utf-8")
            with self.assertRaises(security.GateError):
                security.verify_manifest_lines(manifest, root)


class SbomProvenanceTests(unittest.TestCase):
    def test_sbom_and_provenance_are_deterministic(self) -> None:
        with TempRepo() as repo:
            repo.write("VERSION", "5.0.0-beta.1\n")
            repo.write("TOOLCHAINS.lock", "Go release validation = 1.27.3\nNode.js syntax validation = 22.16.0\nRust stable = 1.97.1\nRust eBPF nightly = nightly-2026-07-16\nbpf-linker = 0.10.3\n")
            repo.write("control/go.mod", "module example\n\ngo 1.23\n")
            repo.write("gateway/go.mod", "module example/gateway\n\ngo 1.26\n")
            repo.write("rust/Cargo.lock", '[[package]]\nname = "aya"\nversion = "0.14.0"\n\n[[package]]\nname = "libc"\nversion = "0.2.180"\n')
            repo.write("Makefile", "all:\n\t@true\n")
            repo.write("docs/release/README.md", "fixture\n")
            repo.commit()
            toolchains = security.release_toolchains(repo.root)
            self.assertEqual(toolchains["go"], "go1.27.3")
            first = security.build_spdx(repo.root, version="5.0.0-beta.1", epoch=1785110400, commit="a" * 40, artifact_hashes={"gedefense-control": "b" * 64})
            second = security.build_spdx(repo.root, version="5.0.0-beta.1", epoch=1785110400, commit="a" * 40, artifact_hashes={"gedefense-control": "b" * 64})
            self.assertEqual(first, second)
            names = [package["name"] for package in first["packages"]]
            self.assertIn("aya", names)
            self.assertIn("go", names)
            provenance = security.build_provenance(
                repo.root,
                version="5.0.0-beta.1",
                epoch=1785110400,
                artifact_hashes={"gedefense-control": "b" * 64},
                sbom_sha256="c" * 64,
                source_manifest_sha256="d" * 64,
            )
            self.assertEqual(provenance["commit"], subprocess.run(["git", "-C", str(repo.root), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip())
            self.assertTrue(provenance["tree_clean"])  # committed tree is clean

    def test_provenance_records_dirty_tree(self) -> None:
        with TempRepo() as repo:
            repo.write("VERSION", "5.0.0-beta.1\n")
            repo.write("TOOLCHAINS.lock", "Go release validation = 1.27.3\nNode.js syntax validation = 22.16.0\nRust stable = 1.97.1\nRust eBPF nightly = nightly-2026-07-16\nbpf-linker = 0.10.3\n")
            repo.write("control/go.mod", "module example\n\ngo 1.23\n")
            repo.write("gateway/go.mod", "module example/gateway\n\ngo 1.26\n")
            repo.write("rust/Cargo.lock", "")
            repo.commit()
            repo.write("UNTRACKED.txt", "dirty\n")
            provenance = security.build_provenance(repo.root, version="5.0.0-beta.1", epoch=1785110400, artifact_hashes={"a": "b" * 64}, sbom_sha256="c" * 64, source_manifest_sha256="d" * 64)
            self.assertTrue(provenance["tree_clean"] is False)


class VersionTests(unittest.TestCase):
    def test_ordering(self) -> None:
        self.assertLess(security.compare_versions("5.0.0-beta.1", "5.0.0-beta.2"), 0)
        self.assertLess(security.compare_versions("5.0.0-beta.9", "5.0.0"), 0)
        self.assertGreater(security.compare_versions("5.0.1", "5.0.0"), 0)
        self.assertEqual(security.compare_versions("5.0.0-beta.1", "5.0.0-beta.1"), 0)
        self.assertLess(security.compare_versions("5.0.0-alpha.1", "5.0.0-beta.1"), 0)

    def test_decisions(self) -> None:
        fresh = security.version_decision("5.0.0-beta.1")
        self.assertTrue(fresh.allowed)
        self.assertEqual(fresh.action, "install")
        upgrade = security.version_decision("5.0.0", installed="5.0.0-beta.1")
        self.assertTrue(upgrade.allowed)
        downgrade = security.version_decision("5.0.0-beta.1", installed="5.0.0")
        self.assertFalse(downgrade.allowed)
        recovery = security.version_decision("5.0.0-beta.1", installed="5.0.0", allow_downgrade=True)
        self.assertTrue(recovery.allowed)
        self.assertEqual(recovery.action, "downgrade")
        floor_denied = security.version_decision("5.0.0-beta.1", installed="5.0.0-beta.1", floor="5.0.0", allow_downgrade=True)
        self.assertFalse(floor_denied.allowed)
        reinstall = security.version_decision("5.0.0-beta.1", installed="5.0.0-beta.1")
        self.assertTrue(reinstall.allowed)
        self.assertEqual(reinstall.action, "reinstall")
        self.assertEqual(security.max_floor("5.0.0-beta.1", "5.0.0", "4.9.0"), "5.0.0")
        self.assertRaises(security.ReleaseError, security.parse_version, "5.0")

    def test_channel(self) -> None:
        self.assertEqual(security.channel_for_version("5.0.0-beta.1"), "beta")
        self.assertEqual(security.channel_for_version("5.0.0"), "stable")


if __name__ == "__main__":
    unittest.main()
