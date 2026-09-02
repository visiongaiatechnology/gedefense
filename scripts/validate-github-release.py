#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
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
    text = workflow.read_text(encoding="utf-8")
    if "pull_request_target:" in text:
        fail(f"privileged pull_request_target trigger in {workflow.name}")
    for use in uses_line.findall(text):
        if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", use):
            fail(f"unpinned action in {workflow.name}: {use}")
    for image in image_line.findall(text):
        if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image):
            fail(f"unpinned container in {workflow.name}: {image}")
    if "permissions:\n  contents: read" not in text:
        fail(f"least-privilege permissions missing in {workflow.name}")
    if re.search(r"run:\s*[^\n]*\$\{\{\s*inputs\.", text):
        fail(f"workflow input interpolated directly into shell in {workflow.name}")

ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
for anchor in (
    "PRODUCT_VERSION: 3.0.0-beta.1",
    "make test-race",
    "make fuzz-smoke",
    "scripts/package-artifacts.sh",
    "ubuntu@sha256:",
    "fedora@sha256:",
    "archlinux/archlinux@sha256:",
    "opensuse/tumbleweed@sha256:",
):
    if anchor not in ci:
        fail(f"CI release gate missing: {anchor}")

host = (root / ".github" / "workflows" / "linux-host-qualification.yml").read_text(encoding="utf-8")
if "validate-installed-linux-host.sh" not in host or "gedefense-kernel-test" not in host:
    fail("privileged concrete-host gate is incomplete")

print(f"GitHub release contracts: PASS ({len(workflows)} workflows)")
