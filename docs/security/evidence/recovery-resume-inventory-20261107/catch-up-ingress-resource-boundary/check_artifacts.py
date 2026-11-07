#!/usr/bin/env python3
"""Verify append-only prefixes, pinned ingress sources, and audit bytes."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[5]
BASE = "ad72aae3b0be5c3c5279463e5ceaf5e0e23d4702"
MAIN = "9bf0eb43e4e3c601d02d3886d220b0abeb3a103e"

APPEND_ONLY = (
    "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md",
    "docs/security/evidence/recovery-resume-inventory-20261107/README.md",
    "docs/security/evidence/recovery-resume-inventory-20261107/CHANGED_PATHS.txt",
    "docs/security/evidence/recovery-resume-inventory-20261107/commands.txt",
)
SOURCES = (
    "crates/qbind-net/src/framed_io.rs",
    "crates/qbind-net/src/transport.rs",
    "crates/qbind-node/src/secure_channel.rs",
    "crates/qbind-node/src/p2p_tcp.rs",
    "crates/qbind-node/src/p2p.rs",
    "crates/qbind-node/src/p2p_inbound.rs",
    "crates/qbind-node/src/p2p_node_builder.rs",
    "crates/qbind-node/src/peer_rate_limiter.rs",
    "crates/qbind-node/src/binary_consensus_loop.rs",
)
AUDIT_REGISTER = "Audit/QBIND_SECURITY_FINDINGS_REGISTER.md"


def git_blob(revision: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def main() -> int:
    errors = []
    for path in APPEND_ONLY:
        original = git_blob(BASE, path)
        current = (ROOT / path).read_bytes()
        if not current.startswith(original):
            errors.append(f"append-only prefix changed: {path}")
    original_audit = git_blob(BASE, AUDIT_REGISTER)
    if (ROOT / AUDIT_REGISTER).read_bytes() != original_audit:
        errors.append("audit register bytes changed")
    for path in SOURCES:
        if (ROOT / path).read_bytes() != git_blob(MAIN, path):
            errors.append(f"source differs from pinned main: {path}")

    evidence = ROOT / (
        "docs/security/evidence/recovery-resume-inventory-20261107/"
        "catch-up-ingress-resource-boundary/README.md"
    )
    text = evidence.read_text(encoding="utf-8")
    if MAIN not in text or "FUTURE / NOT EXECUTED" not in text:
        errors.append("pinned-source or future-status marker missing")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        "PASS: four append-only prefixes preserved; audit register unchanged; "
        "nine source files match pinned main; evidence markers present"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
