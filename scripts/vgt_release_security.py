#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Shared GeDefense release-security primitives.

This module is the single source of truth for:

* Ed25519 release signing/verification (RFC 8032, pure Python stdlib so the
  installer can verify without a Go toolchain),
* canonical JSON encoding compatible with the existing Go release manifest
  implementation in ``control/release_manifest.go`` (schema
  ``vgt.gedefense.release.v1``),
* the signed release *index* (schema ``vgt.gedefense.release-index.v1``) that
  binds the published ``.run`` payloads, source archives, SBOM and provenance to
  one release key,
* the shared ``FORBIDDEN_MARKERS`` content gate and tracked-files allowlist used
  by every packer (pack_release_zip.py, build-source-oneclick.sh,
  stage-github-upload.py, package-artifacts.sh),
* deterministic source packaging (stored timestamps, ordinal order, manifest
  from tracked files only),
* SBOM (SPDX 2.3 JSON) and build-provenance generation,
* semantic version monotonicity / anti-rollback decisions.

No network access, no external Python dependencies. The module is imported by
release tooling on Linux and embedded (base64) into generated installers so the
installer can verify the signed release index before any privileged action.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence

PRODUCT = "VGT GeDefense"
GO_MANIFEST_SCHEMA = "vgt.gedefense.release.v1"
INDEX_SCHEMA = "vgt.gedefense.release-index.v1"
SIGNED_INDEX_SCHEMA = "vgt.gedefense.signed-index.v1"
PROVENANCE_SCHEMA = "vgt.gedefense.build-provenance.v1"
RELEASE_MANIFEST_DOMAIN = b"VGT-GEDEFENSE-RELEASE-MANIFEST-V1\n"
RELEASE_INDEX_DOMAIN = b"VGT-GEDEFENSE-RELEASE-INDEX-V1\n"

DEFAULT_EPOCH = 1785110400  # 2026-07-25T00:00:00Z, matches existing packers
MAX_ARTIFACT_BYTES = 1 << 30
MAX_MANIFEST_BYTES = 8 << 20
MAX_SCAN_BYTES = 1 << 30
ED25519_SIGNATURE_SIZE = 64
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_PRIVATE_KEY_SIZE = 64

# Sensitive operational values that were previously shipped by accident. They
# are assembled at runtime so this scanner's own source does not expose them as
# a single literal. Every packer runs this scan over every produced artifact.
FORBIDDEN_MARKERS: tuple[bytes, ...] = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN RSA " + b"PRIVATE KEY-----",
    b"-----BEGIN EC " + b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----",
    b"212.132." + b"67.175",
    b"87.122." + b"22.193",
    b"87.122." + b"22.213",
)

# Paths/classes that must never enter a published archive even if tracked.
FORBIDDEN_PATH_PARTS = frozenset(
    {
        ".git",
        "webtools",
        "__pycache__",
        "target",
        "node_modules",
        "dist",
        "GitHub Upload",
        "release-beta",
        "release-beta-final",
        "release-complete",
        "release-final",
    }
)
# Internal operational/audit working documents that are tracked at HEAD but must
# never be published (handoff logs, audit evidence, local helper scripts). Some
# of them contain real operational values; excluding them from packaged
# artifacts is mandatory until the owner redacts/rotates the leaked values.
INTERNAL_ONLY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^Next\.md$"),
    re.compile(r"^OPENAI_REWORK_PROGRESS\.md$"),
    re.compile(r"^VGT-AUDIT-.*\.md$"),
    re.compile(r"^VGT-SECURITY-ATTACK-.*\.md$"),
    re.compile(r"^audit_matrix\.json$"),
    re.compile(r"^GEDEFENSE_.*\.md$"),
    re.compile(r"^GeDefense_4\.2_.*\.md$"),
    re.compile(r"^ERWEITERUNGSPLAN_.*\.md$"),
    re.compile(r"^wsl-.*\.sh$"),
    re.compile(r"^bump-version-.*\.py$"),
    re.compile(r"^add-stale\.py$"),
    re.compile(r"^extract\.sh$"),
    re.compile(r"^qa-server\.py$"),
    re.compile(r"^.*\.patch$"),
)

FORBIDDEN_NAME_PATTERNS = (
    re.compile(r"^wsl-.*\.sh$"),
    re.compile(r"^extract\.sh$"),
    re.compile(r"^qa-server\.py$"),
    re.compile(r"^.*\.key$"),
    re.compile(r"^.*\.pem$"),
    re.compile(r"^\.env(\..*)?$"),
    re.compile(r"^dashboard\.token$"),
    re.compile(r"^.*\.jsonl$"),
    re.compile(r"^.*\.run$"),
    re.compile(r"^.*\.zip$"),
    re.compile(r"^.*\.pkg\.tar\..*$"),
    re.compile(r"^.*\.pyc$"),
    re.compile(r"^.*\.exe$"),
)


class ReleaseError(RuntimeError):
    """A release-security contract was violated."""


class GateError(ReleaseError):
    """A packer/content gate rejected the input."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: os.PathLike[str] | str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_limited(path: os.PathLike[str] | str, limit: int = MAX_MANIFEST_BYTES) -> bytes:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ReleaseError(f"not a regular non-symlink file: {path}")
    if info.st_size <= 0 or info.st_size > limit:
        raise ReleaseError(f"file size is outside the accepted boundary: {path}")
    with open(path, "rb") as handle:
        return handle.read()


def write_atomic(path: os.PathLike[str] | str, data: bytes, mode: int = 0o644) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + f".tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, mode)
    finally:
        if temporary.exists():
            temporary.unlink()


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(text: str) -> bytes:
    padding = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + padding)


def load_json_bytes(data: bytes, what: str) -> object:
    duplicates: list[str] = []

    def hook(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=hook, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"{what} is not valid UTF-8 JSON: {error}") from error
    if duplicates:
        raise ReleaseError(f"{what} contains duplicate JSON keys: {sorted(set(duplicates))}")
    return document


def _reject_constant(name: str) -> None:
    raise ReleaseError(f"{what if False else 'JSON'} contains the non-finite constant {name}")


_SAFE_STRING = re.compile(r"^[A-Za-z0-9._:/@+ -]*$")


def _canonical_string(value: str, what: str) -> str:
    if not isinstance(value, str):
        raise ReleaseError(f"{what} must be a string")
    if not _SAFE_STRING.fullmatch(value):
        raise ReleaseError(f"{what} contains characters outside the canonical release charset: {value!r}")
    return json.dumps(value, ensure_ascii=True)


def canonical_json_bytes(document: object) -> bytes:
    """Canonical JSON used for the release index (sorted keys, ASCII, compact)."""
    chunks: list[str] = []

    def encode(value: object) -> None:
        if isinstance(value, bool):
            chunks.append("true" if value else "false")
        elif isinstance(value, int):
            if value < 0 or value > 1 << 63:
                raise ReleaseError("integer outside canonical range")
            chunks.append(str(value))
        elif isinstance(value, str):
            chunks.append(_canonical_string(value, "canonical string"))
        elif value is None:
            chunks.append("null")
        elif isinstance(value, list):
            chunks.append("[")
            for index, item in enumerate(value):
                if index:
                    chunks.append(",")
                encode(item)
            chunks.append("]")
        elif isinstance(value, dict):
            chunks.append("{")
            for index, key in enumerate(sorted(value.keys())):
                if not isinstance(key, str):
                    raise ReleaseError("canonical object key must be a string")
                if index:
                    chunks.append(",")
                chunks.append(_canonical_string(key, "canonical key"))
                chunks.append(":")
                encode(value[key])
            chunks.append("}")
        else:
            raise ReleaseError(f"unsupported canonical JSON type: {type(value).__name__}")

    encode(document)
    return "".join(chunks).encode("utf-8")


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032 reference construction, pure Python)
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * pow(2, (_P - 1) // 4, _P)) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * _inv(5)) % _P
_BX = _xrecover(_BY)
_B = (_BX % _P, _BY % _P, 1, (_BX * _BY) % _P)


def _edwards_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d2 = 2 * z1 * z2 % _P
    e = b - a
    f = d2 - c
    g = d2 + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


def _point_compress(point: tuple[int, int, int, int]) -> bytes:
    z_inv = _inv(point[2])
    x = point[0] * z_inv % _P
    y = point[1] * z_inv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(raw: bytes) -> tuple[int, int, int, int]:
    if len(raw) != 32:
        raise ReleaseError("invalid Ed25519 point length")
    value = int.from_bytes(raw, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _P:
        raise ReleaseError("non-canonical Ed25519 point")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _P - x
    point = (x, y, 1, x * y % _P)
    if not _point_equal(_scalar_mult(_Q, point), (0, 1, 1, 0)):
        raise ReleaseError("Ed25519 point is not in the prime-order subgroup")
    return point


def _point_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    if (p[1] * q[2] - q[1] * p[2]) % _P != 0:
        return False
    return True


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _hash_int(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % _Q


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ReleaseError("Ed25519 seed must be 32 bytes")
    digest = _sha512(seed)
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def ed25519_public_from_seed(seed: bytes) -> bytes:
    scalar, _ = _expand_seed(seed)
    return _point_compress(_scalar_mult(scalar, _B))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _expand_seed(seed)
    public = _point_compress(_scalar_mult(scalar, _B))
    nonce = _hash_int(prefix + message)
    encoded_r = _point_compress(_scalar_mult(nonce, _B))
    challenge = _hash_int(encoded_r + public + message)
    s = (nonce + challenge * scalar) % _Q
    return encoded_r + int.to_bytes(s, 32, "little")


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        a = _point_decompress(public)
        r = _point_decompress(signature[:32])
    except ReleaseError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    challenge = _hash_int(signature[:32] + public + message)
    return _point_equal(_scalar_mult(s, _B), _edwards_add(r, _scalar_mult(challenge, a)))


# ---------------------------------------------------------------------------
# Release key handling
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReleaseKey:
    seed: bytes
    public: bytes

    @property
    def private_raw(self) -> bytes:
        return self.seed + self.public

    @property
    def public_hex(self) -> str:
        return self.public.hex()

    @property
    def signer_id(self) -> str:
        return "ed25519:" + self.public[:8].hex()

    @property
    def fingerprint(self) -> str:
        return sha256_bytes(self.public)


def generate_key() -> ReleaseKey:
    seed = os.urandom(32)
    return ReleaseKey(seed=seed, public=ed25519_public_from_seed(seed))


def key_from_private_raw(raw: bytes) -> ReleaseKey:
    if len(raw) != ED25519_PRIVATE_KEY_SIZE:
        raise ReleaseError("release private key must be 64 raw bytes (seed||public)")
    seed, public = raw[:32], raw[32:]
    expected = ed25519_public_from_seed(seed)
    if expected != public:
        raise ReleaseError("release private key seed does not match the embedded public key")
    return ReleaseKey(seed=seed, public=public)


def load_release_private_key(path: os.PathLike[str] | str) -> ReleaseKey:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ReleaseError("release private key must be a regular non-symlink file")
    if info.st_mode & 0o077:
        raise ReleaseError("release private key must be mode 0600 (no group/other access)")
    return key_from_private_raw(read_limited(path, limit=1024))


def load_release_public_key(path: os.PathLike[str] | str) -> bytes:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ReleaseError("release public key must be a regular non-symlink file")
    if info.st_mode & 0o022:
        raise ReleaseError("release public key must not be group/world writable")
    raw = read_limited(path, limit=1024)
    if len(raw) != ED25519_PUBLIC_KEY_SIZE:
        raise ReleaseError("release public key must be 32 raw bytes")
    return raw


def write_release_keypair(directory: os.PathLike[str] | str, key: ReleaseKey, force: bool = False) -> tuple[Path, Path]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    private_path = root / "release-private.key"
    public_path = root / "release-public.key"
    if not force and (private_path.exists() or public_path.exists()):
        raise ReleaseError("release key files already exist; refusing to overwrite without --force")
    write_atomic(private_path, key.private_raw, 0o600)
    write_atomic(public_path, key.public, 0o644)
    return private_path, public_path


# ---------------------------------------------------------------------------
# Go-compatible signed release manifest (control/release_manifest.go)
# ---------------------------------------------------------------------------


def _go_json_string(value: str, what: str) -> str:
    if not isinstance(value, str):
        raise ReleaseError(f"{what} must be a string")
    if not _SAFE_STRING.fullmatch(value):
        raise ReleaseError(f"{what} contains characters the Go-canonical encoder does not support: {value!r}")
    return json.dumps(value, ensure_ascii=False)


_GO_TOOLCHAIN_KEYS = ("bpf-linker", "go", "node", "rust", "rust-ebpf")


def canonical_go_envelope(envelope: Mapping[str, object]) -> bytes:
    """Reproduce Go ``json.Marshal(ReleaseManifestEnvelope)`` byte-for-byte."""
    if set(envelope.keys()) != {"schema", "product", "version", "channel", "created_at", "toolchains", "artifacts"}:
        raise ReleaseError("release manifest envelope has unexpected fields")
    if envelope["schema"] != GO_MANIFEST_SCHEMA:
        raise ReleaseError("unsupported release manifest schema")
    if envelope["product"] != PRODUCT:
        raise ReleaseError("release manifest product mismatch")
    toolchains = envelope["toolchains"]
    if not isinstance(toolchains, dict):
        raise ReleaseError("release manifest toolchains must be an object")
    artifacts = envelope["artifacts"]
    if not isinstance(artifacts, dict):
        raise ReleaseError("release manifest artifacts must be an object")
    chunks: list[str] = ["{"]
    chunks.append('"schema":' + _go_json_string(str(envelope["schema"]), "schema") + ",")
    chunks.append('"product":' + _go_json_string(str(envelope["product"]), "product") + ",")
    chunks.append('"version":' + _go_json_string(str(envelope["version"]), "version") + ",")
    chunks.append('"channel":' + _go_json_string(str(envelope["channel"]), "channel") + ",")
    created_at = envelope["created_at"]
    if not isinstance(created_at, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created_at):
        raise ReleaseError("release manifest created_at must be RFC3339 UTC without fractional seconds")
    chunks.append('"created_at":' + _go_json_string(created_at, "created_at") + ",")
    chunks.append('"toolchains":{')
    for index, key in enumerate(sorted(toolchains)):
        if key not in _GO_TOOLCHAIN_KEYS:
            raise ReleaseError(f"unexpected toolchain key in release manifest: {key}")
        if index:
            chunks.append(",")
        chunks.append(_go_json_string(key, "toolchain key") + ":" + _go_json_string(str(toolchains[key]), "toolchain value"))
    chunks.append("},")
    chunks.append('"artifacts":{')
    for index, name in enumerate(sorted(artifacts)):
        entry = artifacts[name]
        if not isinstance(entry, dict) or set(entry.keys()) != {"sha256", "size"}:
            raise ReleaseError(f"invalid artifact entry for {name}")
        digest = entry["sha256"]
        size = entry["size"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReleaseError(f"invalid artifact digest for {name}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > MAX_ARTIFACT_BYTES:
            raise ReleaseError(f"invalid artifact size for {name}")
        if index:
            chunks.append(",")
        chunks.append(
            _go_json_string(name, "artifact name")
            + ':{'
            + '"sha256":' + _go_json_string(digest, "artifact digest") + ","
            + '"size":' + str(size)
            + "}"
        )
    chunks.append("}}")
    return "".join(chunks).encode("utf-8")


def _artifact_entry(path: os.PathLike[str] | str) -> dict[str, object]:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ReleaseError(f"release artifact must be a regular non-symlink file: {path}")
    return {"sha256": sha256_file(path), "size": info.st_size}


def build_go_envelope(
    *,
    version: str,
    channel: str,
    epoch: int,
    toolchains: Mapping[str, str],
    artifact_dir: os.PathLike[str] | str,
) -> dict[str, object]:
    directory = Path(artifact_dir)
    artifacts: dict[str, dict[str, object]] = {}
    for entry in sorted(directory.iterdir()):
        name = entry.name
        if name in {"release-manifest.signed.json", "SHA256SUMS"} or entry.is_dir():
            continue
        lowered = name.lower()
        if lowered.endswith(".key") or "private" in lowered or "ed25519" in lowered:
            raise ReleaseError(f"secret-like file is forbidden in release artifacts: {name}")
        if Path(name).name != name:
            raise ReleaseError(f"invalid artifact name: {name}")
        artifacts[name] = _artifact_entry(entry)
    return {
        "schema": GO_MANIFEST_SCHEMA,
        "product": PRODUCT,
        "version": version,
        "channel": channel,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
        "toolchains": {key: str(toolchains[key]) for key in sorted(toolchains)},
        "artifacts": artifacts,
    }


def sign_go_manifest(envelope: Mapping[str, object], key: ReleaseKey) -> bytes:
    payload = canonical_go_envelope(envelope)
    signature = ed25519_sign(key.seed, RELEASE_MANIFEST_DOMAIN + payload)
    document = {
        "envelope": envelope,
        "signer": key.signer_id,
        "signature": base64url_encode(signature),
    }
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


@dataclass(frozen=True)
class VerifiedGoManifest:
    envelope: dict[str, object]
    signer: str


def verify_go_manifest(
    document_bytes: bytes,
    public_key: bytes,
    *,
    expected_version: str | None = None,
    expected_toolchains: Mapping[str, str] | None = None,
    artifact_dir: os.PathLike[str] | str | None = None,
    required_artifacts: Iterable[str] = ("gedefense-control", "gedefense-core", "gedefense-ebpf", "sbom.spdx.json", "build-provenance.json"),
) -> VerifiedGoManifest:
    document = load_json_bytes(document_bytes, "release manifest")
    if not isinstance(document, dict) or set(document.keys()) != {"envelope", "signer", "signature"}:
        raise ReleaseError("release manifest top-level fields are invalid")
    envelope = document["envelope"]
    signer = document["signer"]
    signature_text = document["signature"]
    if not isinstance(envelope, dict) or not isinstance(signer, str) or not isinstance(signature_text, str):
        raise ReleaseError("release manifest field types are invalid")
    expected_signer = "ed25519:" + public_key[:8].hex()
    if signer != expected_signer:
        raise ReleaseError("release manifest signer fingerprint mismatch")
    try:
        signature = base64url_decode(signature_text)
    except (ValueError, base64.binascii.Error) as error:  # type: ignore[attr-defined]
        raise ReleaseError(f"release manifest signature is not valid base64url: {error}") from error
    payload = canonical_go_envelope(envelope)
    if not ed25519_verify(public_key, RELEASE_MANIFEST_DOMAIN + payload, signature):
        raise ReleaseError("release manifest Ed25519 signature verification failed")
    if envelope["version"] != expected_version:
        raise ReleaseError(f"release manifest version mismatch: {envelope['version']} != {expected_version}")
    if expected_toolchains is not None:
        mapped = {key: str(expected_toolchains[key]) for key in sorted(expected_toolchains)}
        if envelope["toolchains"] != mapped:
            raise ReleaseError("release manifest toolchain set does not match the pinned release toolchains")
    recorded = envelope["artifacts"]
    if not isinstance(recorded, dict):
        raise ReleaseError("release manifest artifacts are invalid")
    for required in required_artifacts:
        if required not in recorded:
            raise ReleaseError(f"required release artifact missing from manifest: {required}")
    if artifact_dir is not None:
        directory = Path(artifact_dir)
        for name in sorted(recorded):
            expected = recorded[name]
            try:
                actual = _artifact_entry(directory / name)
            except FileNotFoundError as error:
                raise ReleaseError(f"release artifact is missing: {name}") from error
            if actual != expected:
                raise ReleaseError(f"release artifact integrity mismatch: {name}")
    return VerifiedGoManifest(envelope=envelope, signer=signer)


# ---------------------------------------------------------------------------
# Release index (binds run payloads / source archives / SBOM / provenance)
# ---------------------------------------------------------------------------


def _validate_index(index: object) -> dict[str, object]:
    if not isinstance(index, dict):
        raise ReleaseError("release index must be an object")
    required = {
        "schema",
        "product",
        "version",
        "channel",
        "commit",
        "tree_clean",
        "created_at",
        "source_date_epoch",
        "key_fingerprint",
        "artifacts",
    }
    if set(index.keys()) != required:
        raise ReleaseError("release index fields are invalid")
    if index["schema"] != INDEX_SCHEMA or index["product"] != PRODUCT:
        raise ReleaseError("release index schema/product mismatch")
    for field in ("version", "channel", "commit", "created_at", "key_fingerprint"):
        if not isinstance(index[field], str) or not index[field]:
            raise ReleaseError(f"release index field {field} is invalid")
    if not re.fullmatch(r"[0-9a-f]{40,64}", index["commit"]):
        raise ReleaseError("release index commit is invalid")
    if not isinstance(index["tree_clean"], bool):
        raise ReleaseError("release index tree_clean must be a boolean")
    epoch = index["source_date_epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0:
        raise ReleaseError("release index source_date_epoch is invalid")
    if not isinstance(index["key_fingerprint"], str) or not re.fullmatch(r"[0-9a-f]{64}", index["key_fingerprint"]):
        raise ReleaseError("release index key_fingerprint is invalid")
    artifacts = index["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ReleaseError("release index artifacts list is invalid")
    seen: set[str] = set()
    for entry in artifacts:
        if not isinstance(entry, dict) or set(entry.keys()) != {"name", "sha256", "size", "role"}:
            raise ReleaseError("release index artifact entry is invalid")
        name = entry["name"]
        if not isinstance(name, str) or not name or PurePosixPath(name).name != name or name in {".", ".."}:
            raise ReleaseError("release index artifact name is invalid")
        if name in seen:
            raise ReleaseError(f"duplicate release index artifact: {name}")
        seen.add(name)
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ReleaseError(f"release index artifact digest is invalid: {name}")
        if not isinstance(entry["size"], int) or isinstance(entry["size"], bool) or entry["size"] < 0:
            raise ReleaseError(f"release index artifact size is invalid: {name}")
        if not isinstance(entry["role"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", entry["role"]):
            raise ReleaseError(f"release index artifact role is invalid: {name}")
    return index


def build_release_index(
    *,
    version: str,
    channel: str,
    commit: str,
    tree_clean: bool,
    epoch: int,
    key: ReleaseKey,
    artifacts: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    index = {
        "schema": INDEX_SCHEMA,
        "product": PRODUCT,
        "version": version,
        "channel": channel,
        "commit": commit,
        "tree_clean": tree_clean,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
        "source_date_epoch": epoch,
        "key_fingerprint": key.fingerprint,
        "artifacts": sorted(
            ({"name": str(entry["name"]), "sha256": str(entry["sha256"]), "size": int(entry["size"]), "role": str(entry["role"])} for entry in artifacts),
            key=lambda entry: entry["name"],
        ),
    }
    return _validate_index(index)


def sign_release_index(index: Mapping[str, object], key: ReleaseKey) -> bytes:
    validated = _validate_index(index)
    if validated["key_fingerprint"] != key.fingerprint:
        raise ReleaseError("release index key fingerprint does not match the signing key")
    payload = canonical_json_bytes(validated)
    signature = ed25519_sign(key.seed, RELEASE_INDEX_DOMAIN + payload)
    document = {
        "schema": SIGNED_INDEX_SCHEMA,
        "index": validated,
        "signer": key.signer_id,
        "signature": base64url_encode(signature),
    }
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def load_revocation_document(path: os.PathLike[str] | str) -> set[str]:
    """Load the release-key revocation list (key fingerprints that are revoked)."""
    document = load_json_bytes(read_limited(path, limit=1024 * 1024), "release key revocation list")
    if not isinstance(document, dict) or document.get("schema") != "vgt.gedefense.release-key-revocations.v1":
        raise ReleaseError("release key revocation document schema is invalid")
    revoked = document.get("revoked")
    if not isinstance(revoked, list):
        raise ReleaseError("release key revocation list is invalid")
    fingerprints: set[str] = set()
    for entry in revoked:
        if not isinstance(entry, dict) or not isinstance(entry.get("fingerprint"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["fingerprint"]):
            raise ReleaseError("release key revocation entry is invalid")
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise ReleaseError("release key revocation entry is missing a reason")
        fingerprints.add(entry["fingerprint"])
    return fingerprints


def verify_release_index(
    document_bytes: bytes,
    public_key: bytes,
    *,
    expected_version: str | None = None,
    artifact_root: os.PathLike[str] | str | None = None,
    artifact_files: Mapping[str, os.PathLike[str] | str] | None = None,
    revoked_fingerprints: Iterable[str] = (),
) -> dict[str, object]:
    document = load_json_bytes(document_bytes, "signed release index")
    if not isinstance(document, dict) or set(document.keys()) != {"schema", "index", "signer", "signature"}:
        raise ReleaseError("signed release index top-level fields are invalid")
    if document["schema"] != SIGNED_INDEX_SCHEMA:
        raise ReleaseError("signed release index schema mismatch")
    index = _validate_index(document["index"])
    signer = document["signer"]
    if not isinstance(signer, str) or signer != "ed25519:" + public_key[:8].hex():
        raise ReleaseError("signed release index signer fingerprint mismatch")
    if index["key_fingerprint"] != sha256_bytes(public_key):
        raise ReleaseError("signed release index key fingerprint does not match the trusted public key")
    revoked = set(revoked_fingerprints)
    if index["key_fingerprint"] in revoked:
        raise ReleaseError("signed release index was signed with a revoked release key")
    try:
        signature = base64url_decode(str(document["signature"]))
    except (ValueError, base64.binascii.Error) as error:  # type: ignore[attr-defined]
        raise ReleaseError(f"signed release index signature is not valid base64url: {error}") from error
    payload = canonical_json_bytes(index)
    if not ed25519_verify(public_key, RELEASE_INDEX_DOMAIN + payload, signature):
        raise ReleaseError("signed release index Ed25519 signature verification failed")
    if expected_version is not None and index["version"] != expected_version:
        raise ReleaseError(f"release index version mismatch: {index['version']} != {expected_version}")
    if artifact_root is not None:
        root = Path(artifact_root)
        for entry in index["artifacts"]:
            path = root / str(entry["name"])
            actual = _artifact_entry(path)
            if actual != {"sha256": entry["sha256"], "size": entry["size"]}:
                raise ReleaseError(f"release index artifact integrity mismatch: {entry['name']}")
    if artifact_files:
        by_name = {str(entry["name"]): entry for entry in index["artifacts"]}
        for name, path in artifact_files.items():
            if name not in by_name:
                raise ReleaseError(f"required artifact is not covered by the release index: {name}")
            actual = _artifact_entry(path)
            if actual != {"sha256": by_name[name]["sha256"], "size": by_name[name]["size"]}:
                raise ReleaseError(f"release index artifact integrity mismatch: {name}")
    return index


# ---------------------------------------------------------------------------
# Content gate: tracked-files allowlist + FORBIDDEN_MARKERS
# ---------------------------------------------------------------------------


def forbidden_path_reason(relative: str) -> str | None:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        return "path escapes the repository"
    for part in pure.parts:
        if part in FORBIDDEN_PATH_PARTS:
            return f"forbidden path component: {part}"
    name = pure.name
    for pattern in FORBIDDEN_NAME_PATTERNS:
        if pattern.fullmatch(name):
            return f"forbidden file name: {name}"
    return None


def has_forbidden_marker(data: bytes) -> bytes | None:
    for marker in FORBIDDEN_MARKERS:
        if marker in data:
            return marker
    return None


def scan_bytes_markers(data: bytes, label: str) -> None:
    marker = has_forbidden_marker(data)
    if marker is not None:
        raise GateError(f"forbidden sensitive marker detected in {label}")


def scan_file_markers(path: os.PathLike[str] | str) -> None:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise GateError(f"refusing to scan a non-regular file: {path}")
    if info.st_size > MAX_SCAN_BYTES:
        raise GateError(f"file exceeds the marker-scan boundary: {path}")
    with open(path, "rb") as handle:
        overlap = b""
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            scan_bytes_markers(overlap + block, str(path))
            overlap = (overlap + block)[-64:]


def scan_tree_markers(root: os.PathLike[str] | str) -> int:
    count = 0
    for entry in sorted(Path(root).rglob("*")):
        if entry.is_symlink():
            raise GateError(f"symlink is forbidden in staged release content: {entry}")
        if not entry.is_file():
            continue
        relative = entry.relative_to(root).as_posix()
        reason = forbidden_path_reason(relative)
        if reason:
            raise GateError(f"{reason}: {entry}")
        scan_file_markers(entry)
        count += 1
    return count


def git_tracked_files(root: os.PathLike[str] | str) -> list[str]:
    """Return the tracked file set of the committed HEAD tree.

    Releases are packaged from the committed tree, not from uncommitted working
    tree edits, so a dirty development workspace cannot silently change a
    release artifact.
    """
    repository = Path(root).resolve()
    result = subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-r", "--name-only", "-z", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise GateError(f"git ls-tree HEAD failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    names = [entry for entry in result.stdout.decode("utf-8", "surrogateescape").split("\0") if entry]
    if not names:
        raise GateError("git HEAD tree contains no tracked files")
    return names


def _extract_git_head(repo: os.PathLike[str] | str, destination: os.PathLike[str] | str) -> None:
    """Extract the committed HEAD tree into ``destination`` via git archive."""
    import io

    repository = Path(repo).resolve()
    target = Path(destination).resolve()
    target.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "-C", str(repository), "archive", "--format=tar", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise GateError(f"git archive HEAD failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or member.issym() or member.islnk() or member.isdev():
                raise GateError(f"git archive contains an unsafe member: {member.name}")
            archive.extract(member, target)


def is_git_ignored(root: os.PathLike[str] | str, relative: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(root), "check-ignore", "-q", "--", relative],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def is_internal_only_path(relative: str) -> bool:
    name = PurePosixPath(relative).name
    return any(pattern.fullmatch(name) for pattern in INTERNAL_ONLY_PATTERNS)


def collect_tracked_sources(root: os.PathLike[str] | str, *, include_internal: bool = False) -> list[str]:
    """Return tracked files eligible for a source release.

    Only files tracked by git are eligible (gitignored operational data and dev
    binaries are therefore excluded by construction), each file is checked
    against the forbidden-path policy, and internal operational/audit documents
    are excluded from published artifacts. Content marker scanning happens when
    the staged tree is written/scanned.
    """
    repository = Path(root).resolve()
    modes = _git_head_modes(repository)
    eligible: list[str] = []
    for relative in git_tracked_files(repository):
        if not include_internal and is_internal_only_path(relative):
            continue
        reason = forbidden_path_reason(relative)
        if reason:
            raise GateError(f"tracked file violates the release allowlist ({reason}): {relative}")
        mode = modes.get(relative, "100644")
        if mode == "120000":
            raise GateError(f"tracked symlink is forbidden in release content: {relative}")
        if mode not in {"100644", "100755"}:
            raise GateError(f"tracked entry is not a regular file (mode {mode}): {relative}")
        eligible.append(relative)
    return sorted(eligible)


def _git_head_modes(repo: Path) -> dict[str, str]:
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "-z", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise GateError(f"git ls-tree HEAD failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    modes: dict[str, str] = {}
    for entry in result.stdout.decode("utf-8", "surrogateescape").split("\0"):
        if not entry:
            continue
        header, _, name = entry.partition("\t")
        fields = header.split()
        if len(fields) >= 3:
            modes[name] = fields[0]
    return modes


def repository_is_clean(root: os.PathLike[str] | str) -> bool:
    repository = Path(root).resolve()
    result = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=no"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise GateError(f"git status failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return not result.stdout.strip()


def git_commit(root: os.PathLike[str] | str) -> str:
    repository = Path(root).resolve()
    result = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise GateError("git HEAD could not be resolved")
    commit = result.stdout.decode("utf-8", "replace").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise GateError("git HEAD is not a commit hash")
    return commit


def audit_tracked_markers(root: os.PathLike[str] | str) -> list[dict[str, str]]:
    """Report forbidden markers that still exist in tracked files.

    This is a repository-hygiene report, not a packaging decision: internal-only
    documents are already excluded from published artifacts, but leaked values
    remain in git history until the owner redacts and rotates them.
    """
    repository = Path(root).resolve()
    findings: list[dict[str, str]] = []
    for relative in git_tracked_files(repository):
        try:
            data = subprocess.run(
                ["git", "-C", str(repository), "show", f"HEAD:{relative}"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if data.returncode != 0 or len(data.stdout) > MAX_SCAN_BYTES:
                continue
            blob = data.stdout
        except OSError:
            continue
        for index, marker in enumerate(FORBIDDEN_MARKERS):
            if marker in blob:
                kind = "private-key-header" if b"BEGIN" in marker else "operational-value"
                findings.append({"file": relative, "kind": kind, "marker_index": str(index)})
    return findings


def stage_tracked_tree(
    repo: os.PathLike[str] | str,
    stage: os.PathLike[str] | str,
    *,
    extra_excluded_prefixes: Sequence[str] = (),
    allow_dirty: bool = False,
) -> dict[str, object]:
    """Copy the tracked allowlist into ``stage`` and emit its SOURCE-MANIFEST."""
    repository = Path(repo).resolve()
    destination = Path(stage).resolve()
    if destination == repository or repository in destination.parents:
        raise GateError("staging directory must live outside the repository")
    clean = repository_is_clean(repository)
    if not clean and not allow_dirty:
        raise GateError("working tree has uncommitted tracked changes; refuse to package a non-reproducible release (commit or use --allow-dirty for an explicit local dry-run)")
    destination.mkdir(parents=True, exist_ok=True)
    _extract_git_head(repository, destination)
    kept = 0
    for relative in collect_tracked_sources(repository):
        if any(relative == prefix or relative.startswith(prefix + "/") for prefix in extra_excluded_prefixes):
            (destination / relative).unlink(missing_ok=True)
            continue
        target = destination / relative
        if not target.is_file():
            raise GateError(f"git archive is missing an allowlisted file: {relative}")
        if target.is_symlink():
            raise GateError(f"symlink in staged content: {relative}")
        scan_file_markers(target)
        kept += 1
    # Remove internal-only documents from the git archive copy.
    for relative in git_tracked_files(repository):
        if is_internal_only_path(relative):
            candidate = destination / relative
            if candidate.exists() and candidate.is_file():
                candidate.unlink()
    manifest = build_manifest(destination, manifest_name="SOURCE-MANIFEST.sha256")
    (destination / "SOURCE-MANIFEST.sha256").write_text(manifest, encoding="utf-8", newline="\n")
    return {
        "files": kept,
        "commit": git_commit(repository),
        "tree_clean": clean,
        "manifest": manifest,
        "manifest_sha256": sha256_bytes(manifest.encode("utf-8")),
        "stage": str(destination),
    }


def build_manifest(root: os.PathLike[str] | str, *, manifest_name: str = "SOURCE-MANIFEST.sha256") -> str:
    directory = Path(root)
    entries: list[str] = []
    for entry in sorted(directory.rglob("*")):
        relative = entry.relative_to(directory)
        if not entry.is_file() or entry.is_symlink():
            continue
        if relative.name == manifest_name or ".git" in relative.parts:
            continue
        entries.append(f"{sha256_file(entry)}  {relative.as_posix()}\n")
    if not entries:
        raise GateError("refusing to emit an empty manifest")
    return "".join(entries)


def verify_manifest_lines(manifest_text: str, root: os.PathLike[str] | str, *, manifest_name: str = "SOURCE-MANIFEST.sha256") -> int:
    directory = Path(root)
    recorded: dict[str, str] = {}
    for line in manifest_text.splitlines():
        digest, separator, relative = line.partition("  ")
        if separator != "  " or not re.fullmatch(r"[0-9a-f]{64}", digest) or not relative:
            raise GateError(f"malformed manifest record: {line[:120]}")
        if relative in recorded:
            raise GateError(f"duplicate manifest record: {relative}")
        recorded[relative] = digest
    actual = {
        entry.relative_to(directory).as_posix()
        for entry in directory.rglob("*")
        if entry.is_file() and not entry.is_symlink() and entry.name != manifest_name and ".git" not in entry.relative_to(directory).parts
    }
    if set(recorded) != actual:
        missing = sorted(actual - set(recorded))[:5]
        extra = sorted(set(recorded) - actual)[:5]
        raise GateError(f"manifest file set mismatch (missing={missing}, extra={extra})")
    for relative, digest in recorded.items():
        if sha256_file(directory / relative) != digest:
            raise GateError(f"manifest hash mismatch: {relative}")
    return len(recorded)


# ---------------------------------------------------------------------------
# Deterministic archives
# ---------------------------------------------------------------------------


def deterministic_zip(
    directory: os.PathLike[str] | str,
    output: os.PathLike[str] | str,
    *,
    prefix: str,
    epoch: int,
    compression: int = zipfile.ZIP_DEFLATED,
    compresslevel: int = 9,
) -> str:
    root = Path(directory)
    fixed = time.gmtime(epoch)
    date_time = (max(fixed.tm_year, 1980), fixed.tm_mon, fixed.tm_mday, fixed.tm_hour, fixed.tm_min, fixed.tm_sec)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()
    names = sorted(entry.relative_to(root).as_posix() for entry in root.rglob("*") if entry.is_file() and not entry.is_symlink())
    with zipfile.ZipFile(destination, "w") as archive:
        for relative in names:
            source = root / relative
            info = zipfile.ZipInfo((prefix + relative) if not prefix.endswith("/") else prefix + relative, date_time)
            mode = source.stat().st_mode
            info.external_attr = ((0o755 if mode & 0o111 else 0o644) & 0xFFFF) << 16
            info.compress_type = compression
            archive.writestr(info, source.read_bytes(), compress_type=compression, compresslevel=compresslevel)
    return sha256_file(destination)


def deterministic_tar_gz(directory: os.PathLike[str] | str, output: os.PathLike[str] | str, *, epoch: int) -> str:
    import gzip

    root = Path(directory)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=epoch, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for entry in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
                relative = entry.relative_to(root).as_posix()
                info = tarfile.TarInfo("." if relative == "." else "./" + relative)
                info.mtime = epoch
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                if entry.is_dir() and not entry.is_symlink():
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                elif entry.is_file() and not entry.is_symlink():
                    data = entry.read_bytes()
                    info.type = tarfile.REGTYPE
                    info.size = len(data)
                    info.mode = 0o755 if entry.stat().st_mode & 0o111 else 0o644
                    import io

                    archive.addfile(info, io.BytesIO(data))
                else:
                    raise GateError(f"symlink or special file cannot be archived: {entry}")
    return sha256_file(destination)


# ---------------------------------------------------------------------------
# SBOM and build provenance
# ---------------------------------------------------------------------------


def read_toolchain_lock(root: os.PathLike[str] | str) -> dict[str, str]:
    lock = Path(root) / "TOOLCHAINS.lock"
    if not lock.is_file():
        raise ReleaseError("TOOLCHAINS.lock is missing")
    values: dict[str, str] = {}
    for raw in lock.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(" = ")
        if separator != " = " or not key or not value:
            raise ReleaseError(f"invalid TOOLCHAINS.lock entry: {line[:80]}")
        values[key.strip()] = value.strip()
    return values


def release_toolchains(root: os.PathLike[str] | str) -> dict[str, str]:
    lock = read_toolchain_lock(root)
    try:
        mapping = {
            "go": "go" + lock["Go release validation"],
            "node": "v" + lock["Node.js syntax validation"],
            "rust": lock["Rust stable"],
            "rust-ebpf": lock["Rust eBPF nightly"],
            "bpf-linker": lock["bpf-linker"],
        }
    except KeyError as error:
        raise ReleaseError(f"TOOLCHAINS.lock is missing the release toolchain {error}") from error
    return mapping


def _cargo_lock_packages(root: Path) -> list[dict[str, str]]:
    lock = root / "rust" / "Cargo.lock"
    if not lock.is_file():
        raise ReleaseError("rust/Cargo.lock is missing")
    packages: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in lock.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            if current:
                packages.append(current)
            current = {}
            continue
        if not current and not stripped:
            continue
        if " = " in stripped and current is not None:
            key, _, value = stripped.partition(" = ")
            if value.startswith('"') and value.endswith('"'):
                current[key.strip()] = value.strip('"')
    if current:
        packages.append(current)
    return [pkg for pkg in packages if "name" in pkg and "version" in pkg]


def build_spdx(
    root: os.PathLike[str] | str,
    *,
    version: str,
    epoch: int,
    commit: str,
    artifact_hashes: Mapping[str, str] | None = None,
) -> dict[str, object]:
    repository = Path(root).resolve()
    toolchains = release_toolchains(repository)
    namespace = f"https://visiongaia.technology/spdx/gedefense/{version}/{commit}"
    packages: list[dict[str, object]] = []

    def add_package(spdx_id: str, name: str, version_info: str, supplier: str = "NOASSERTION", purl: str | None = None) -> None:
        entry: dict[str, object] = {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version_info,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": supplier,
        }
        if purl:
            entry["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ]
        packages.append(entry)

    add_package("SPDXRef-Package-Gedefense", PRODUCT, version, supplier="Organization: VisionGaia Technology")
    for key in sorted(toolchains):
        add_package(f"SPDXRef-Package-Toolchain-{re.sub(r'[^A-Za-z0-9]+', '-', key)}", key, toolchains[key], supplier="NOASSERTION")
    seen: set[tuple[str, str]] = set()
    for package in _cargo_lock_packages(repository):
        identity = (package["name"], package["version"])
        if identity in seen:
            continue
        seen.add(identity)
        spdx_id = "SPDXRef-Crate-" + re.sub(r"[^A-Za-z0-9.]+", "-", f"{package['name']}-{package['version']}")
        add_package(spdx_id, package["name"], package["version"], purl=f"pkg:cargo/{package['name']}@{package['version']}")
    files: list[dict[str, object]] = []
    if artifact_hashes:
        for name in sorted(artifact_hashes):
            files.append(
                {
                    "SPDXID": "SPDXRef-File-" + re.sub(r"[^A-Za-z0-9.]+", "-", name),
                    "fileName": name,
                    "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_hashes[name]}],
                }
            )
    relationships: list[dict[str, object]] = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-Gedefense"}
    ]
    for package in packages[1:]:
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-Gedefense",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package["SPDXID"],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PRODUCT} {version} release SBOM",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
            "creators": ["Tool: vgt-release-tool-1.0.0", "Organization: VisionGaia Technology"],
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
        "comment": (
            "Generated offline from the tracked release tree. License values are NOASSERTION where no "
            "offline license source exists; this SBOM is an inventory, not a vulnerability assessment. "
            "Public CA/RFC3161/revocation/anti-rollback anchors remain external blockers."
        ),
    }


def git_metadata(root: os.PathLike[str] | str) -> dict[str, object]:
    repository = Path(root).resolve()

    def run(*arguments: str) -> str:
        result = subprocess.run(["git", "-C", str(repository), *arguments], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise ReleaseError(f"git {' '.join(arguments)} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
        return result.stdout.decode("utf-8", "replace").strip()

    commit = run("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ReleaseError("git HEAD could not be resolved to a commit hash")
    status = run("status", "--porcelain")
    return {"commit": commit, "tree_clean": not status}


def build_provenance(
    root: os.PathLike[str] | str,
    *,
    version: str,
    epoch: int,
    artifact_hashes: Mapping[str, str],
    sbom_sha256: str,
    source_manifest_sha256: str,
    created_at: str | None = None,
) -> dict[str, object]:
    repository = Path(root).resolve()
    git = git_metadata(repository)
    toolchains = release_toolchains(repository)
    lock_sha = sha256_file(repository / "TOOLCHAINS.lock")
    makefile = repository / "Makefile"
    build_flags = {
        "go": ["-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid="],
        "go_gateway": ["-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid= -extldflags=-Wl,--build-id=none"],
        "rust_ebpf": ["--locked", "--release", "--target", "bpfel-unknown-none", "-Z", "build-std=core"],
        "rust_core": ["--locked", "--release"],
        "cargo_lock_sha256": sha256_file(repository / "rust" / "Cargo.lock"),
        "makefile_sha256": sha256_file(makefile) if makefile.is_file() else "",
    }
    return {
        "schema": PROVENANCE_SCHEMA,
        "product": PRODUCT,
        "version": version,
        "commit": git["commit"],
        "tree_clean": git["tree_clean"],
        "source_date_epoch": epoch,
        "created_at": created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
        "toolchains": toolchains,
        "toolchains_lock_sha256": lock_sha,
        "build": build_flags,
        "source_manifest_sha256": source_manifest_sha256,
        "sbom_sha256": sbom_sha256,
        "artifacts": {name: {"sha256": artifact_hashes[name]} for name in sorted(artifact_hashes)},
        "limitations": [
            "Unsigned build attestation: provenance is bound to the signed release index/manifest, not to a remote CI attestation service.",
            "No public CA code-signing identity: the release Ed25519 key must be distributed out-of-band; RFC3161 timestamps and CRL/OCSP revocation are not available.",
            "No externally anchored anti-rollback channel: the installer enforces local version monotonicity and a local release floor only.",
            "Toolchain and dependency components are recorded from TOOLCHAINS.lock/go.mod/Cargo.lock; license conclusions are NOASSERTION without an offline license database.",
        ],
    }


# ---------------------------------------------------------------------------
# Semantic version monotonicity / anti-rollback
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^(?P<core>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$")


def parse_version(text: str) -> tuple[int, int, int, tuple[tuple[int, object], ...]]:
    match = _VERSION_RE.fullmatch(text.strip())
    if not match:
        raise ReleaseError(f"invalid semantic version: {text!r}")
    core = (int(match.group("core")), int(match.group("minor")), int(match.group("patch")))
    prerelease: list[tuple[int, object]] = []
    if match.group("pre"):
        for identifier in match.group("pre").split("."):
            if identifier.isdigit():
                prerelease.append((0, int(identifier)))
            else:
                prerelease.append((1, identifier))
    return core[0], core[1], core[2], tuple(prerelease)


def compare_versions(left: str, right: str) -> int:
    left_core = parse_version(left)[:3]
    right_core = parse_version(right)[:3]
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    left_pre = parse_version(left)[3]
    right_pre = parse_version(right)[3]
    if not left_pre and not right_pre:
        return 0
    if not left_pre:
        return 1
    if not right_pre:
        return -1
    for index in range(max(len(left_pre), len(right_pre))):
        if index >= len(left_pre):
            return -1
        if index >= len(right_pre):
            return 1
        left_kind, left_value = left_pre[index]
        right_kind, right_value = right_pre[index]
        if left_kind != right_kind:
            return 1 if left_kind > right_kind else -1
        if left_value != right_value:
            if left_kind == 0:
                return 1 if left_value > right_value else -1
            return 1 if str(left_value) > str(right_value) else -1
    return 0


@dataclass(frozen=True)
class VersionDecision:
    allowed: bool
    action: str
    reason: str
    candidate: str
    installed: str | None
    floor: str | None
    next_floor: str


def version_decision(
    candidate: str,
    *,
    installed: str | None = None,
    floor: str | None = None,
    allow_downgrade: bool = False,
) -> VersionDecision:
    """Decide whether installing ``candidate`` is permitted.

    Rules (fail closed):
    * a candidate below the recorded release floor is always refused,
    * a candidate below the installed version is refused unless
      ``allow_downgrade`` is set explicitly (recovery operation),
    * equal versions are re-installs and keep the floor,
    * otherwise the new floor becomes the candidate.
    """
    parse_version(candidate)
    effective_floor = floor
    for label, value in (("installed", installed), ("floor", floor)):
        if value is not None:
            parse_version(value)
    if floor is not None and compare_versions(candidate, floor) < 0:
        return VersionDecision(False, "refuse", f"candidate {candidate} is below the local release floor {floor}", candidate, installed, floor, floor)
    if installed is not None:
        comparison = compare_versions(candidate, installed)
        if comparison < 0:
            if not allow_downgrade:
                return VersionDecision(False, "refuse", f"downgrade from {installed} to {candidate} is refused (use --allow-downgrade for an explicit recovery)", candidate, installed, floor, max_floor(installed, candidate, floor))
            return VersionDecision(True, "downgrade", f"explicit recovery downgrade {installed} -> {candidate}", candidate, installed, effective_floor, max_floor(installed, candidate, floor))
        if comparison == 0:
            return VersionDecision(True, "reinstall", f"re-installing the already installed version {candidate}", candidate, installed, effective_floor, max_floor(installed, candidate, floor))
        return VersionDecision(True, "upgrade", f"upgrade {installed} -> {candidate}", candidate, installed, effective_floor, max_floor(installed, candidate, floor))
    return VersionDecision(True, "install", f"fresh install of {candidate}", candidate, installed, effective_floor, max_floor(candidate, floor))


def max_floor(*versions: str | None) -> str:
    present = [version for version in versions if version]
    if not present:
        raise ReleaseError("cannot compute an empty release floor")
    best = present[0]
    for version in present[1:]:
        if compare_versions(version, best) > 0:
            best = version
    return best


def read_floor(path: os.PathLike[str] | str) -> str | None:
    try:
        data = read_limited(path, limit=64 * 1024)
    except FileNotFoundError:
        return None
    except PermissionError:
        # Unprivileged --self-test cannot read the root-only floor file on an
        # installed host. The real installation runs as root (fail-closed
        # monotonicity is still enforced there); a missing floor means "no
        # recorded floor" for the read-only self-test.
        return None
    except OSError:
        return None
    document = load_json_bytes(data, "release floor")
    if not isinstance(document, dict) or document.get("schema") != "vgt.gedefense.release-floor.v1":
        raise ReleaseError("release floor document is invalid")
    version = document.get("highest_version")
    if not isinstance(version, str):
        raise ReleaseError("release floor version is invalid")
    parse_version(version)
    return version


def channel_for_version(version: str) -> str:
    parsed = parse_version(version)
    return "beta" if parsed[3] else "stable"


# ---------------------------------------------------------------------------
# Embedded verifier CLI (used by generated installers; no external imports)
# ---------------------------------------------------------------------------


def _load_public_key_argument(value: str) -> bytes:
    text = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    return load_release_public_key(text)


def _cmd_verify_index(args: Sequence[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="vgt_release_security.py verify-index")
    parser.add_argument("--index", required=True)
    parser.add_argument("--pubkey", required=True, help="32-byte hex public key or path to raw public key")
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--artifact-file", action="append", default=[], metavar="NAME=PATH")
    options = parser.parse_args(args)
    public = _load_public_key_argument(options.pubkey)
    artifacts: dict[str, str] = {}
    for item in options.artifact_file:
        name, separator, path = item.partition("=")
        if separator != "=" or not name or not path:
            raise ReleaseError(f"invalid --artifact-file value: {item}")
        artifacts[name] = path
    index = verify_release_index(
        read_limited(options.index, limit=MAX_MANIFEST_BYTES),
        public,
        expected_version=options.expected_version,
        artifact_files=artifacts,
    )
    print("index-ok version=%s channel=%s commit=%s artifacts=%d" % (index["version"], index["channel"], index["commit"], len(index["artifacts"])))
    return 0


def _cmd_verify_manifest(args: Sequence[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="vgt_release_security.py verify-manifest")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--pubkey", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--toolchains-json", default="")
    parser.add_argument("--artifact-dir", default="")
    options = parser.parse_args(args)
    public = _load_public_key_argument(options.pubkey)
    toolchains = None
    if options.toolchains_json:
        loaded = load_json_bytes(options.toolchains_json.encode("utf-8"), "expected toolchains")
        if not isinstance(loaded, dict):
            raise ReleaseError("expected toolchains must be a JSON object")
        toolchains = {str(key): str(value) for key, value in loaded.items()}
    verified = verify_go_manifest(
        read_limited(options.manifest, limit=MAX_MANIFEST_BYTES),
        public,
        expected_version=options.expected_version,
        expected_toolchains=toolchains,
        artifact_dir=options.artifact_dir or None,
    )
    print("manifest-ok version=%s signer=%s artifacts=%d" % (verified.envelope["version"], verified.signer, len(verified.envelope["artifacts"])))
    return 0


def _cmd_version_guard(args: Sequence[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="vgt_release_security.py version-guard")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--installed", default="")
    parser.add_argument("--floor", default="")
    parser.add_argument("--floor-file", default="")
    parser.add_argument("--allow-downgrade", action="store_true")
    options = parser.parse_args(args)
    floor = options.floor or None
    if options.floor_file:
        existing = read_floor(options.floor_file)
        if existing:
            floor = max_floor(existing, floor) if floor else existing
    decision = version_decision(
        options.candidate,
        installed=options.installed or None,
        floor=floor,
        allow_downgrade=options.allow_downgrade,
    )
    document = {
        "allowed": decision.allowed,
        "action": decision.action,
        "reason": decision.reason,
        "candidate": decision.candidate,
        "installed": decision.installed,
        "floor": decision.floor,
        "next_floor": decision.next_floor,
    }
    print(json.dumps(document, sort_keys=True))
    return 0 if decision.allowed else 3


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        print("usage: vgt_release_security.py {verify-index|verify-manifest|version-guard} ...", file=sys.stderr)
        return 2
    command, rest = arguments[0], arguments[1:]
    handlers = {
        "verify-index": _cmd_verify_index,
        "verify-manifest": _cmd_verify_manifest,
        "version-guard": _cmd_version_guard,
    }
    handler = handlers.get(command)
    if handler is None:
        print(f"unknown command: {command}", file=sys.stderr)
        return 2
    try:
        return handler(rest)
    except ReleaseError as error:
        print(f"RELEASE-VERIFICATION-FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
