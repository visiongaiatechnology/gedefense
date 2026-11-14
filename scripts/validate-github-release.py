#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
"""Validate GitHub release/CI contracts (F-25, G-SC-10, G-SC-11, G-SC-14).

Fails closed on: unpinned actions/containers, over-broad permissions,
pull_request_target, direct interpolation of workflow inputs into shell, version
drift (hardcoded/v4 labels), missing permanent supply-chain/SCA gates, and a
privileged self-hosted qualification workflow without environment/branch
protection.
"""

from __future__ import annotations

from pathlib import Path
import re


def fail(message: str) -> None:
    raise SystemExit(f"GitHub release validation failed: {message}")


root = Path(__file__).resolve().parent.parent
workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
if not workflows:
    fail("no workflows found")

action_pattern = re.compile(r"^\s*- uses:\s*[^\s@]+@([0-9a-f]{40})(?:\s+#.*)?$", re.MULTILINE)
uses_line = re.compile(r"^\s*- uses:\s*(\S+)", re.MULTILINE)
image_line = re.compile(r"^\s*image:\s*(\S+)", re.MULTILINE)

for workflow in workflows:
    name = workflow.read_text(encoding="utf-8")
    if "pull_request_target:" in name:
        fail(f"privileged pull_request_target trigger in {workflow.name}")
    for use in uses_line.findall(name):
        if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", use):
            fail(f"unpinned action in {workflow.name}: {use}")
    for image in image_line.findall(name):
        if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image):
            fail(f"unpinned container in {workflow.name}: {image}")
    if "permissions:\n  contents: read" not in name:
        fail(f"least-privilege permissions missing in {workflow.name}")
    if re.search(r"run:\s*[^\n]*\$\{\{\s*inputs\.", name):
        fail(f"workflow input interpolated directly into shell in {workflow.name}")
    if re.search(r"(?i)(beta v4|\bv4_4\.4\.1\b|publish_release_4)", name):
        fail(f"stale v4 release-channel label in {workflow.name} (G-SC-11)")

ci_path = root / ".github" / "workflows" / "ci.yml"
ci = ci_path.read_text(encoding="utf-8")
for anchor in (
    "supply-chain-gate",
    "make test-race",
    "make fuzz-smoke",
    "scripts/package-artifacts.sh",
    "scripts/sca-gate.sh --strict",
    "scripts/tests/check_installer_templates.sh",
    "scripts/tests/key_rotation_rehearsal.sh",
    "scripts/tests/tag_signing_rehearsal.sh",
    "scripts/tests/go_manifest_crosscheck.sh",
    "release-index.signed.json",
    "release-manifest.signed.json",
    "build-provenance.json",
    "sbom.spdx.json",
    "ubuntu@sha256:",
    "fedora@sha256:",
    "archlinux/archlinux@sha256:",
    "opensuse/tumbleweed@sha256:",
):
    if anchor not in ci:
        fail(f"CI release gate missing: {anchor}")
if "PRODUCT_VERSION:" in ci:
    fail("hardcoded PRODUCT_VERSION env reintroduces version drift (derive from VERSION)")
if "VERSION=$(tr -d" not in ci:
    fail("CI does not derive the product version from the VERSION file")
if "ephemeral CI rehearsal key" not in ci:
    fail("release pipeline CI rehearsal does not clearly mark test-signed artifacts")

host = (root / ".github" / "workflows" / "linux-host-qualification.yml").read_text(encoding="utf-8")
for anchor in (
    "validate-installed-linux-host.sh",
    "gedefense-kernel-test",
    "environment: privileged-linux-host",
    "if: github.ref == 'refs/heads/main'",
    "persist-credentials: false",
    "^[A-Za-z0-9_.:-]{1,32}$",
):
    if anchor not in host:
        fail(f"privileged concrete-host gate hardening missing: {anchor}")

required_files = (
    "scripts/vgt_release_security.py",
    "scripts/release-tool.py",
    "scripts/render-installer-header.py",
    "scripts/sca-gate.sh",
    "scripts/tests/check_installer_templates.sh",
    "scripts/tests/key_rotation_rehearsal.sh",
    "scripts/tests/tag_signing_rehearsal.sh",
    "scripts/tests/verify_rendered_installer.py",
)
for relative in required_files:
    if not (root / relative).is_file():
        fail(f"release-security tooling missing: {relative}")

if list((root / "scripts").glob("publish_release_4*.py")):
    fail("stale v4 publish scripts are still present (G-SC-11)")

print(f"GitHub release contracts: PASS ({len(workflows)} workflows)")
