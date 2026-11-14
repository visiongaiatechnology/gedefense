#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Offline tests for the canonical signed GeoIP update contract (FIND-006).

The producer (scripts/update-geoip-db.py) and the consumer (control/geoip.go)
must agree byte-for-byte on:

  geoip.csv.sha256  canonical compact JSON, sorted keys, ASCII, no newline
                    {"file":...,"schema":...,"sha256":...,"size":...}
  geoip.csv.sig     Base64 Ed25519 over the exact sidecar bytes

These tests are offline and use only throwaway keys/temp directories. They
consume the same shared vector as control/geoip_test.go, so both sides of the
contract are pinned to one fixture.

Run with:  python3 -B -m unittest discover -s scripts/tests -p 'test_*.py' -v
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))

import vgt_release_security as security  # noqa: E402

_SPEC = importlib.util.spec_from_file_location("update_geoip_db", SCRIPTS / "update-geoip-db.py")
assert _SPEC is not None and _SPEC.loader is not None
geodb = importlib.util.module_from_spec(_SPEC)
# dataclasses with postponed annotations resolve their class module through
# sys.modules, so the dynamically loaded producer module must be registered.
sys.modules["update_geoip_db"] = geodb
_SPEC.loader.exec_module(geodb)

VECTOR_PATH = Path(__file__).resolve().parent / "geoip_integrity_vector.json"

FIXTURE_V4 = geodb.MergedRange(
    int(ipaddress.IPv4Address("8.8.8.0")),
    int(ipaddress.IPv4Address("8.8.8.255")),
    False,
    "US",
    "United States",
    37.751,
    -97.822,
    "AS15169",
    "Google LLC",
)
FIXTURE_V4_B = geodb.MergedRange(
    int(ipaddress.IPv4Address("9.9.9.0")),
    int(ipaddress.IPv4Address("9.9.9.255")),
    False,
    "DE",
    "Germany",
    50.110,
    8.682,
    "AS19281",
    "Quad9",
)


def load_vector() -> dict[str, object]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


class GeoIPContractTests(unittest.TestCase):
    def staging_directory(self, target: Path) -> list[Path]:
        return sorted(path for path in target.parent.glob(".vgt-geoip-staging-*") if path.is_dir())

    def stage(self, target: Path) -> geodb.StagedGeoIPDataset:
        return geodb.stage_geoip_dataset([FIXTURE_V4], [], target)

    def keypair(self, directory: Path) -> tuple[security.ReleaseKey, Path, Path]:
        key = security.generate_key()
        private_path, public_path = security.write_release_keypair(str(directory), key)
        return key, private_path, public_path

    def signature_file(self, directory: Path, key: security.ReleaseKey, sidecar_bytes: bytes) -> Path:
        """Write a Base64 signature input; never inside the installed dataset dir."""
        inputs = Path(directory) / "signature-inputs"
        inputs.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix="geoip-", suffix=".sig", dir=str(inputs))
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(base64.b64encode(security.ed25519_sign(key.seed, sidecar_bytes)) + b"\n")
        return Path(name)

    def test_canonical_sidecar_matches_shared_go_vector(self) -> None:
        vector = load_vector()
        sidecar = geodb.canonical_integrity_sidecar(
            str(vector["csv_name"]), str(vector["csv_sha256"]), int(vector["csv_size"])
        )
        self.assertEqual(sidecar.decode("ascii"), vector["sidecar_canonical"])
        # The deterministic throwaway test key (derived from a fixed label, no
        # secret material in the repository) reproduces exactly the committed
        # vector signature and public key, which control/geoip_test.go verifies.
        seed = hashlib.sha256(b"vgt-geoip-integrity-interop-test-vector-v1").digest()
        public = security.ed25519_public_from_seed(seed)
        self.assertEqual(base64.b64encode(public).decode("ascii"), vector["public_key_base64"])
        signature = security.ed25519_sign(seed, sidecar)
        self.assertEqual(base64.b64encode(signature).decode("ascii"), vector["signature_base64"])
        self.assertTrue(security.ed25519_verify(public, sidecar, signature))
        # The sidecar binds the CSV digest and exact byte size, not just a name.
        document = json.loads(sidecar)
        self.assertEqual(document["schema"], geodb.GEOIP_INTEGRITY_SCHEMA)
        self.assertEqual(document["sha256"], hashlib.sha256(str(vector["csv"]).encode("utf-8")).hexdigest())
        self.assertEqual(document["size"], len(str(vector["csv"]).encode("utf-8")))
        self.assertNotIn(b"\n", sidecar)

    def test_staging_is_private_unpredictable_and_target_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "geoip.csv"
            first = self.stage(target)
            second = self.stage(target)
            try:
                self.assertFalse(target.exists(), "staging must not install the dataset")
                self.assertFalse((Path(temporary) / "geoip.csv.sha256").exists())
                self.assertNotEqual(first.directory, second.directory)
                for staged in (first, second):
                    self.assertEqual(stat.S_IMODE(staged.directory.stat().st_mode), 0o700)
                    self.assertTrue(staged.directory.name.startswith(".vgt-geoip-staging-"))
                    self.assertEqual(hashlib.sha256(staged.csv_path.read_bytes()).hexdigest(), staged.sha256)
                    self.assertEqual(staged.sidecar_path.read_bytes(), geodb.canonical_integrity_sidecar("geoip.csv", staged.sha256, staged.size))
                    self.assertEqual(stat.S_IMODE(staged.csv_path.stat().st_mode), 0o600)
            finally:
                first.cleanup()
                second.cleanup()
            self.assertEqual(self.staging_directory(target), [])

    def test_install_with_expected_digest_and_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "state" / "geoip.csv"
            staged = self.stage(target)
            expected_csv = staged.csv_path.read_bytes()
            expected_sidecar = staged.sidecar_path.read_bytes()
            key, private_path, public_path = self.keypair(base / "keys")
            signature_path = self.signature_file(base, key, expected_sidecar)
            geodb.authenticate_staged_dataset(
                staged,
                expected_sha256=staged.sha256,
                signature_path=signature_path,
                verify_key_path=public_path,
            )
            geodb.commit_staged_dataset(staged)
            self.assertTrue(target.is_file())
            self.assertEqual(target.read_bytes(), expected_csv)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), staged.sha256)
            sidecar_target = target.with_name("geoip.csv.sha256")
            self.assertEqual(sidecar_target.read_bytes(), expected_sidecar)
            signature_target = target.with_name("geoip.csv.sig")
            self.assertTrue(signature_target.is_file())
            expected_signature = security.ed25519_sign(key.seed, sidecar_target.read_bytes())
            self.assertEqual(
                signature_target.read_text(encoding="ascii").strip(),
                base64.b64encode(expected_signature).decode("ascii"),
            )
            self.assertTrue(security.ed25519_verify(key.public, sidecar_target.read_bytes(), expected_signature))
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(sidecar_target.stat().st_mode), 0o640)
            if os.geteuid() != 0:
                self.assertEqual(self.staging_directory(target), [])

    def test_signing_key_writes_canonical_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "geoip.csv"
            key, private_path, _public_path = self.keypair(base / "keys")
            staged = self.stage(target)
            geodb.authenticate_staged_dataset(staged, signing_key_path=private_path)
            geodb.commit_staged_dataset(staged)
            sidecar_target = target.with_name("geoip.csv.sha256")
            expected_signature = security.ed25519_sign(key.seed, sidecar_target.read_bytes())
            signature_target = target.with_name("geoip.csv.sig")
            self.assertEqual(
                signature_target.read_text(encoding="ascii").strip(),
                base64.b64encode(expected_signature).decode("ascii"),
            )

    def test_tampered_staged_dataset_is_not_installed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "geoip.csv"
            staged = self.stage(target)
            key, private_path, public_path = self.keypair(base / "keys")
            signature_path = self.signature_file(base, key, staged.sidecar_path.read_bytes())
            with open(staged.csv_path, "ab") as handle:
                handle.write(b"1.1.1.1/32,US,United States,0.000,0.000,,\n")
            with self.assertRaises(RuntimeError):
                geodb.authenticate_staged_dataset(
                    staged,
                    expected_sha256=staged.sha256,
                    signature_path=signature_path,
                    verify_key_path=public_path,
                )
            staged.cleanup()
            self.assertFalse(target.exists(), "tampered staging must not replace the dataset")
            self.assertEqual(self.staging_directory(target), [])

    def test_failed_update_leaves_installed_dataset_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "geoip.csv"
            key, private_path, public_path = self.keypair(base / "keys")
            # Install a verified baseline dataset.
            baseline = self.stage(target)
            baseline_signature = self.signature_file(base, key, baseline.sidecar_path.read_bytes())
            geodb.authenticate_staged_dataset(
                baseline,
                expected_sha256=baseline.sha256,
                signature_path=baseline_signature,
                verify_key_path=public_path,
            )
            geodb.commit_staged_dataset(baseline)
            baseline_bytes = target.read_bytes()
            baseline_sidecar = target.with_name("geoip.csv.sha256").read_bytes()
            baseline_signature_bytes = target.with_name("geoip.csv.sig").read_bytes()

            # A wrong pinned digest must abort before any replacement.
            new_dataset = geodb.stage_geoip_dataset([FIXTURE_V4_B], [], target)
            new_signature = self.signature_file(base, key, new_dataset.sidecar_path.read_bytes())
            with self.assertRaises(RuntimeError):
                geodb.authenticate_staged_dataset(
                    new_dataset,
                    expected_sha256="0" * 64,
                    signature_path=new_signature,
                    verify_key_path=public_path,
                )
            new_dataset.cleanup()
            self.assertEqual(target.read_bytes(), baseline_bytes)
            self.assertEqual(target.with_name("geoip.csv.sha256").read_bytes(), baseline_sidecar)
            self.assertEqual(target.with_name("geoip.csv.sig").read_bytes(), baseline_signature_bytes)

    def test_replayed_sidecar_signature_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "geoip.csv"
            key, private_path, public_path = self.keypair(base / "keys")
            baseline = self.stage(target)
            old_sidecar = baseline.sidecar_path.read_bytes()
            old_signature = self.signature_file(base, key, old_sidecar)
            geodb.authenticate_staged_dataset(baseline, signature_path=old_signature, verify_key_path=public_path)
            geodb.commit_staged_dataset(baseline)
            baseline_bytes = target.read_bytes()

            # Replay the authentic (sidecar, signature) pair for a different
            # dataset: dataset B has its own sidecar, so the old signature must
            # not authenticate it even with a matching pinned key.
            replay = geodb.stage_geoip_dataset([FIXTURE_V4_B], [], target)
            with self.assertRaises(RuntimeError):
                geodb.authenticate_staged_dataset(replay, signature_path=old_signature, verify_key_path=public_path)
            replay.cleanup()
            self.assertEqual(target.read_bytes(), baseline_bytes)

    def test_raw_and_malformed_signatures_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "geoip.csv"
            key, private_path, public_path = self.keypair(base / "keys")
            staged = self.stage(target)
            raw_signature_path = base / "raw.sig"
            raw_signature_path.write_bytes(security.ed25519_sign(key.seed, staged.sidecar_path.read_bytes()))
            with self.assertRaises(RuntimeError):
                geodb.authenticate_staged_dataset(staged, signature_path=raw_signature_path, verify_key_path=public_path)
            malformed_path = base / "malformed.sig"
            malformed_path.write_text("not base64 at all!!\n", encoding="ascii")
            with self.assertRaises(RuntimeError):
                geodb.authenticate_staged_dataset(staged, signature_path=malformed_path, verify_key_path=public_path)
            zero_path = base / "zero.sig"
            zero_path.write_text(base64.b64encode(bytes(64)).decode("ascii") + "\n", encoding="ascii")
            with self.assertRaises(RuntimeError):
                geodb.authenticate_staged_dataset(staged, signature_path=zero_path, verify_key_path=public_path)
            staged.cleanup()

    def test_signature_requires_matching_verify_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "geoip.csv"
            staged = self.stage(target)
            key, _private_path, _public_path = self.keypair(base / "keys")
            signature_path = self.signature_file(base, key, staged.sidecar_path.read_bytes())
            with self.assertRaises(RuntimeError):
                geodb.authenticate_staged_dataset(staged, signature_path=signature_path)
            with self.assertRaises(RuntimeError):
                geodb.authenticate_staged_dataset(staged, verify_key_path=base / "keys" / "release-public.key")
            staged.cleanup()

    def test_cache_directory_is_private_and_has_no_tmp_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_dir = geodb.resolve_cache_dir(str(Path(temporary) / "cache"))
            self.assertEqual(stat.S_IMODE(cache_dir.stat().st_mode), 0o700)
        # A broken default cache must fail closed, not fall back to a
        # predictable /tmp/geoip-cache path.
        original = geodb.DEFAULT_CACHE_DIR
        try:
            geodb.DEFAULT_CACHE_DIR = "/proc/vgt-gedefense-unwritable-cache"
            with self.assertRaises(RuntimeError) as raised:
                geodb.resolve_cache_dir("")
            self.assertIn("cache", str(raised.exception).lower())
        finally:
            geodb.DEFAULT_CACHE_DIR = original

    def test_download_cache_rejects_symlinks_and_non_https(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_dir = geodb.ensure_private_directory(Path(temporary) / "cache")
            real = cache_dir / "dataset.csv"
            real.write_text("fixture\n", encoding="utf-8")
            link = cache_dir / "link.csv"
            link.symlink_to(real)
            url = "https://example.invalid/link.csv"
            with self.assertRaises(RuntimeError):
                geodb.download_cached(url, cache_dir, "symlinked cache entry")
            with self.assertRaises(RuntimeError):
                geodb.download_cached("http://example.invalid/dbip.csv", cache_dir, "plain http")
            # A regular cached file is reused without network access.
            cached = cache_dir / "dbip-city-ipv4.csv.gz"
            cached.write_bytes(b"cached fixture")
            self.assertEqual(
                geodb.download_cached("https://example.invalid/dbip-city-ipv4.csv.gz", cache_dir, "cached fixture"),
                cached,
            )


if __name__ == "__main__":
    unittest.main()
