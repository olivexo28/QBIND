"""Documentation-only correction checks; no tests/builds are run."""

import hashlib
import re
import subprocess
from pathlib import Path

BASE = "6914c6257f11b55fddb0f24de42a1a0ed316ca7f"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "p1-provider-model-specification-correction"
P1 = ROOT / "p1-provider-model-specification"
APPENDS = [
    Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"),
    ROOT / "README.md",
    ROOT / "CHANGED_PATHS.txt",
    ROOT / "commands.txt",
]
DOC = (HERE / "README.md").read_text()


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(revision, path):
    return git("show", f"{revision}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(BASE, path)), path
print("PASS: four exact append-only prefixes at correction base")

historical = [
    Path(name)
    for name in git("ls-tree", "-r", "--name-only", BASE, str(ROOT)).decode().splitlines()
    if Path(name) not in APPENDS
]
for path in historical:
    assert path.read_bytes() == blob(BASE, path), path
assert Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md").read_bytes() == blob(
    BASE, "Audit/QBIND_SECURITY_FINDINGS_REGISTER.md"
)
print(f"PASS: {len(historical)} prior evidence files and audit register unchanged")

old_manifest_path = P1 / "SHA256SUMS"
old_entries = blob(BASE, old_manifest_path).decode().splitlines()
assert len(old_entries) == 39
for entry in old_entries:
    expected, name = entry.split("  ", 1)
    assert hashlib.sha256(blob(BASE, name)).hexdigest() == expected, name
assert (P1 / "README.md").read_bytes() == blob(BASE, P1 / "README.md")
print("PASS: original P1 manifest's 39 entries verified at producing commit")
print("PASS: original P1 specification bytes unchanged")

changed = set(git("diff", "--name-only", BASE).decode().splitlines())
untracked = set(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
allowed = set(APPENDS)
for name in changed | untracked:
    assert Path(name) in allowed or name.startswith(str(HERE) + "/"), name
assert not git(
    "diff", "--name-only", BASE, "--", "crates", "Cargo.toml", "Cargo.lock",
    ".cargo", ".github", "Audit"
).strip()
assert "CHANGES REQUIRED" in DOC and all(
    finding in DOC for finding in ["P1-SPEC-1", "P1-SPEC-2", "P1-SPEC-3"]
)
assert "FUTURE / NOT EXECUTED" in DOC
for token in [
    "ProviderReplaced", "ProviderDestroyed", "LeaseHeld", "LeaseExhausted",
    "DescriptorMismatch", "QBP1TEST", "QBE1TEST", "11,339", "19,389",
    "35,773", "A17-F1 / RS1-F7", "A33-F1 / E27",
    "test_strict_uniqueness_stage", "test_omitted_uniqueness_mutant",
    "16,384-byte ceiling test", "size-gate-only", "[0x10; 32]", "[i; 32]",
]:
    assert token in DOC, token
assert "Available" in DOC and "Unavailable" in DOC and "Stale" in DOC
assert "Conflict" in DOC and "Unknown" in DOC
print("PASS: documentation-only scope and all three correction findings")

for target in re.findall(r"(?<!!)\[[^]]+\]\(([^)]+)\)", DOC):
    if target.startswith(("https://", "http://", "mailto:", "#")):
        continue
    local_path = target.split("#", 1)[0]
    assert (HERE / local_path).is_file(), target
plan = Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md").read_text()
index = (ROOT / "README.md").read_text()
assert "## 48. P1 provider specification correction" in plan
assert "p1-provider-model-specification-correction/README.md" in plan
assert "## 20. P1 specification correction" in index
assert "p1-provider-model-specification-correction/README.md" in index
print("PASS: correction links and appended plan/index discoverability")

max_envelope = (
    12 + 12 * 6
    + 32 + 32 + 2 + 2 + 8 + 16 + 32 + 32 + 2
    + 1 + 8 * (32 + 2 + 1312 + 8)
    + 8 + 256
)
max_evidence = 12 + 1 + 8 * (2 + 2420)
assert max_envelope == 11339
assert max_evidence == 19389
assert 16384 + max_evidence == 35773
assert "11,339 bytes" in DOC and "19,389" in DOC and "35,773" in DOC
print("PASS: test framing arithmetic: envelope=11339, evidence=19389, combined=35773")

subprocess.run(["git", "diff", "--check"], check=True)
subprocess.run(["git", "diff", "--cached", "--check"], check=True)
print("PASS: whitespace checks; no Rust test/build execution")
print("NOT ESTABLISHED: production authority, wire compatibility, memory/runtime guarantees, application, signing, fencing or resume")
