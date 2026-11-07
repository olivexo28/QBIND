"""Verify test-only handoff scope and pinned historical evidence."""

import gzip
import hashlib
import subprocess
from pathlib import Path

BASE = "25a03a1e82aca9643ea86f8368a3c6cedfe2826f"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "p1-provider-verifier-handoff"
MODEL = Path("crates/qbind-consensus/tests/p1_provider_model_tests.rs")
TARGET = Path("crates/qbind-consensus/tests/p1_provider_verifier_handoff_tests.rs")
SUPPORT = Path("crates/qbind-consensus/tests/support/p1_provider_verifier_handoff.rs")
AUDIT = Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md")
APPENDS = {
    Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"),
    ROOT / "README.md",
    ROOT / "CHANGED_PATHS.txt",
    ROOT / "commands.txt",
}


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(path):
    return git("show", f"{BASE}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(path)), path
historical = [
    Path(name)
    for name in git("ls-tree", "-r", "--name-only", BASE, str(ROOT))
    .decode()
    .splitlines()
    if Path(name) not in APPENDS
]
for path in historical:
    assert path.read_bytes() == blob(path), path
assert AUDIT.read_bytes() == blob(AUDIT)
print(f"PASS: four append-only prefixes, {len(historical)} historical files and audit bytes")

manifest = ROOT / "p1-fixture-binding-correction/SHA256SUMS"
entries = blob(manifest).decode().splitlines()
for line in entries:
    expected, name = line.split("  ", 1)
    assert hashlib.sha256(blob(name)).hexdigest() == expected, name
print(f"PASS: {len(entries)} previous manifest entries against producing revision {BASE}")

change = (
    b'#[path = "support/p1_provider_verifier_handoff.rs"]\n'
    b"mod p1_provider_verifier_handoff;\n\n"
)
assert MODEL.read_bytes().replace(change, b"", 1) == blob(MODEL)
changed = set(git("diff", "--name-only", BASE).decode().splitlines())
changed.update(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
allowed = {str(MODEL), str(TARGET), str(SUPPORT), *(str(p) for p in APPENDS)}
assert all(name in allowed or name.startswith(str(HERE) + "/") for name in changed), changed
assert {str(MODEL), str(TARGET), str(SUPPORT)} <= changed
print("PASS: prior provider source differs only by test-module inclusion; scope restricted")

focused = gzip.decompress((HERE / "focused.log.gz").read_bytes()).decode()
regression = gzip.decompress((HERE / "provider-regression.log.gz").read_bytes()).decode()
discovery = gzip.decompress((HERE / "discovery.log.gz").read_bytes()).decode()
for name in [
    "matching_corrupted_and_restored_signature_reach_real_backend",
    "same_label_witness_replacement_strict_and_defective_selection_oracle",
    "currentness_and_provider_lifetime_refuse_before_backend_then_replacement_succeeds",
]:
    assert name in focused and name in discovery, name
for log in [focused, regression]:
    assert "22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in log
assert "HANDOFF selection: strict refused; witness-selected mutant verified B" in focused
print("PASS: three discovered handoff controls and focused/provider result counts")
print("NOT ESTABLISHED: authenticated currentness, quorum finality, application or resume")
