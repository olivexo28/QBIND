#!/usr/bin/env python3
"""Verify documentation append-only prefixes for the ingress clarification."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[5]
BASE = "2cafa1b21365e99d95aa0c759dd2dd90fa1e43af"
APPEND_ONLY = (
    "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md",
    "docs/security/evidence/recovery-resume-inventory-20261107/README.md",
    "docs/security/evidence/recovery-resume-inventory-20261107/CHANGED_PATHS.txt",
    "docs/security/evidence/recovery-resume-inventory-20261107/commands.txt",
    "docs/security/evidence/recovery-resume-inventory-20261107/catch-up-ingress-resource-boundary/README.md",
    "docs/security/evidence/recovery-resume-inventory-20261107/catch-up-ingress-resource-boundary/COMMANDS.txt",
    "docs/security/evidence/recovery-resume-inventory-20261107/catch-up-ingress-resource-boundary/check_artifacts.py",
    "docs/security/evidence/recovery-resume-inventory-20261107/catch-up-ingress-resource-boundary/integrity.txt",
    "docs/security/evidence/recovery-resume-inventory-20261107/catch-up-ingress-resource-boundary/SHA256SUMS",
)
AUDIT_REGISTER = "Audit/QBIND_SECURITY_FINDINGS_REGISTER.md"
CLARIFICATION = "docs/security/evidence/recovery-resume-inventory-20261107/catch-up-ingress-resource-boundary/CLARIFICATION.md"


def git_blob(path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{BASE}:{path}"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def main() -> int:
    errors = []
    for path in APPEND_ONLY:
        if not (ROOT / path).read_bytes().startswith(git_blob(path)):
            errors.append(f"historical prefix changed: {path}")
    if (ROOT / AUDIT_REGISTER).read_bytes() != git_blob(AUDIT_REGISTER):
        errors.append("audit register differs from clarification base")
    text = (ROOT / CLARIFICATION).read_text(encoding="utf-8")
    for marker in (
        "5 + len",
        "UNKNOWN / NOT ESTABLISHED",
        "second time",
        "nine inspected source paths",
        "FUTURE / NOT EXECUTED",
    ):
        if marker not in text:
            errors.append(f"clarification marker missing: {marker}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        "PASS: nine historical documentation/evidence prefixes preserved; "
        "audit register unchanged; clarification markers present"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
