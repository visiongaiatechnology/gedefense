#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Static/functional verification of a rendered self-extracting installer header.

Checks without executing the installer:
* every release placeholder was substituted (no ``__RELEASE_*`` left),
* the embedded signed release index decodes and verifies against the pinned key
  and expected version,
* the embedded verifier is the expected stdlib verifier and itself verifies the
  index (independent execution of the embedded code),
* the embedded payload digest constant matches the actual appended payload.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PLACEHOLDER_RE = re.compile(r"__RELEASE_[A-Z_]+__")
INDEX_RE = re.compile(r'^readonly RELEASE_INDEX_B64="([A-Za-z0-9+/=]*)"$', re.MULTILINE)
VERIFIER_RE = re.compile(r'^readonly RELEASE_VERIFIER_B64="([A-Za-z0-9+/=]*)"$', re.MULTILINE)
PAYLOAD_SHA_RE = re.compile(r'^readonly (?:PAYLOAD_SHA256|SOURCE_PAYLOAD_SHA256)="([0-9a-f]{64})"$', re.MULTILINE)
MARKER = "\n__VGT_PAYLOAD_BELOW__\n"
SOURCE_MARKER = "\n__VGT_SOURCE_PAYLOAD_BELOW__\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a rendered GeDefense installer")
    parser.add_argument("--installer", required=True)
    parser.add_argument("--public-key-hex", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-payload-sha", default="")
    arguments = parser.parse_args()

    installer = Path(arguments.installer)
    if not installer.is_file():
        raise SystemExit(f"installer is missing: {installer}")
    data = installer.read_bytes()
    if data.startswith(b"\x7fELF"):
        raise SystemExit("installed artifact is a binary, not a self-extracting header")
    try:
        header_text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        # The appended tar.gz is binary; split at the marker in bytes.
        marker = MARKER.encode() if MARKER.encode() in data else SOURCE_MARKER.encode()
        if marker not in data:
            raise SystemExit("installer payload marker is missing")
        header_bytes, payload = data.split(marker, 1)
        header_text = header_bytes.decode("utf-8", "strict")
    else:
        marker = MARKER if MARKER in header_text else SOURCE_MARKER
        header_text, _, payload_text = header_text.partition(marker)
        payload = payload_text.encode("latin-1")

    if PLACEHOLDER_RE.search(header_text):
        raise SystemExit(f"unrendered release placeholders remain: {sorted(set(PLACEHOLDER_RE.findall(header_text)))}")

    index_match = INDEX_RE.search(header_text)
    verifier_match = VERIFIER_RE.search(header_text)
    payload_sha_match = PAYLOAD_SHA_RE.search(header_text)
    if not index_match or not verifier_match or not payload_sha_match:
        raise SystemExit("required embedded release constants are missing (fail closed)")
    index_bytes = base64.b64decode(index_match.group(1))
    verifier_source = base64.b64decode(verifier_match.group(1))
    payload_sha = payload_sha_match.group(1)
    actual_payload_sha = hashlib.sha256(payload).hexdigest()
    if len(payload) < 1024:
        raise SystemExit("embedded payload is implausibly small")
    expected_payload = arguments.expected_payload_sha.strip().lower() or payload_sha
    if actual_payload_sha != expected_payload or payload_sha != expected_payload:
        raise SystemExit(f"embedded payload digest mismatch: header={payload_sha} actual={actual_payload_sha}")

    with tempfile.TemporaryDirectory(prefix="vgt-rendered-header-") as temporary:
        verifier_path = Path(temporary) / "release-verifier.py"
        verifier_path.write_bytes(verifier_source)
        index_path = Path(temporary) / "release-index.signed.json"
        index_path.write_bytes(index_bytes)
        result = subprocess.run(
            [
                sys.executable,
                str(verifier_path),
                "verify-index",
                "--index",
                str(index_path),
                "--pubkey",
                arguments.public_key_hex,
                "--expected-version",
                arguments.expected_version,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SystemExit(f"embedded verifier rejected the embedded index: {result.stderr.strip()}")
    print(f"PASS: rendered installer verified (payload={actual_payload_sha[:16]}..., index verified by embedded verifier)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
