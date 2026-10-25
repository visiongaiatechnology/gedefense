#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Render a self-extracting installer header from a template.

The generated header embeds, as base64 constants, the signed release index, the
trusted Ed25519 public key and a stdlib-only verifier (vgt_release_security.py).
All substitutions are plain ASCII, so no shell quoting is required and an
unfilled placeholder always fails closed at runtime.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

PLACEHOLDERS = {
    "__RELEASE_PUBKEY_HEX__": "public_key_hex",
    "__RELEASE_INDEX_B64__": "index_b64",
    "__RELEASE_VERIFIER_B64__": "verifier_b64",
    "__RELEASE_TRUST_MODE__": "trust_mode",
    "__PAYLOAD_SHA256__": "payload_sha256",
    "__CONTROL_SHA256__": "control_sha256",
    "__ACCESS_SHA256__": "access_sha256",
    "__SOURCE_PAYLOAD_SHA256__": "source_payload_sha256",
}


def render(
    template: Path,
    output: Path,
    *,
    public_key_hex: str,
    index_b64: str,
    verifier_b64: str,
    trust_mode: str,
    payload_sha256: str = "",
    control_sha256: str = "",
    access_sha256: str = "",
    source_payload_sha256: str = "",
) -> None:
    text = template.read_text(encoding="utf-8-sig")
    values = {
        "public_key_hex": public_key_hex,
        "index_b64": index_b64,
        "verifier_b64": verifier_b64,
        "trust_mode": trust_mode,
        "payload_sha256": payload_sha256,
        "control_sha256": control_sha256,
        "access_sha256": access_sha256,
        "source_payload_sha256": source_payload_sha256,
    }
    for placeholder, key in PLACEHOLDERS.items():
        if placeholder in text:
            value = values[key]
            if key != "public_key_hex" and value == "":
                # Keep the placeholder visible so the runtime fail-closed check
                # can reject a header that was never rendered.
                continue
            text = text.replace(placeholder, value)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a GeDefense installer header")
    parser.add_argument("--template", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--public-key-hex", required=True)
    parser.add_argument("--index", required=True)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--trust-mode", required=True, choices=["prebuilt", "source-signed"])
    parser.add_argument("--payload-sha256", default="")
    parser.add_argument("--control-sha256", default="")
    parser.add_argument("--access-sha256", default="")
    parser.add_argument("--source-payload-sha256", default="")
    options = parser.parse_args()
    verifier = Path(options.verifier).read_bytes()
    index = Path(options.index).read_bytes()
    render(
        Path(options.template),
        Path(options.output),
        public_key_hex=options.public_key_hex.strip().lower(),
        index_b64=base64.b64encode(index).decode("ascii"),
        verifier_b64=base64.b64encode(verifier).decode("ascii"),
        trust_mode=options.trust_mode,
        payload_sha256=options.payload_sha256,
        control_sha256=options.control_sha256,
        access_sha256=options.access_sha256,
        source_payload_sha256=options.source_payload_sha256,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
