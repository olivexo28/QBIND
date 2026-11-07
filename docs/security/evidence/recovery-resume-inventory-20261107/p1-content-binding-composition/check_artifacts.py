"""Verify composition scope, historical bytes and producing-revision hashes."""

import gzip
import hashlib
import subprocess
from pathlib import Path

BASE = "af3110da83a5555da5307b981e276f1cff9d058b"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "p1-content-binding-composition"
MODEL = Path("crates/qbind-consensus/tests/p1_provider_model_tests.rs")
CONTENT = Path("crates/qbind-consensus/tests/content_binding_experiment_tests.rs")
TARGET = Path("crates/qbind-consensus/tests/p1_content_composition_tests.rs")
SUPPORT = Path("crates/qbind-consensus/tests/support/p1_content_composition.rs")
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

entries = blob(ROOT / "p1-provider-verifier-handoff/SHA256SUMS").decode().splitlines()
for line in entries:
    expected, name = line.split("  ", 1)
    assert hashlib.sha256(blob(name)).hexdigest() == expected, name
print(f"PASS: {len(entries)} previous manifest entries against producing revision {BASE}")

added = (
    b'#[path = "support/p1_content_composition.rs"]\n'
    b"mod p1_content_composition;\n\n"
)
assert MODEL.read_bytes().replace(added, b"", 1) == blob(MODEL)
assert CONTENT.read_bytes().replace(b"pub(crate) ", b"") == blob(CONTENT)
handoff = Path("crates/qbind-consensus/tests/support/p1_provider_verifier_handoff.rs")
assert handoff.read_bytes() == blob(handoff)
changed = set(git("diff", "--name-only", BASE).decode().splitlines())
changed.update(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
allowed = {str(MODEL), str(CONTENT), str(TARGET), str(SUPPORT), *(str(p) for p in APPENDS)}
assert all(name in allowed or name.startswith(str(HERE) + "/") for name in changed), changed
assert {str(MODEL), str(CONTENT), str(TARGET), str(SUPPORT)} <= changed
print("PASS: prior test bodies unchanged; only test-crate visibility and module declaration added")
print("PASS: changed paths restricted to test-only composition and append-only evidence")

def text(name):
    return gzip.decompress((HERE / name).read_bytes()).decode()


discovery = text("discovery.log.gz")
focused = text("focused.log.gz")
regressions = text("regressions.log.gz")
for name in [
    "composition_parent_content_mutations_and_restored_positive",
    "composition_duplicate_unauthorized_and_insufficient_stage_controls",
    "composition_same_label_selection_mutant_preserves_real_verification",
    "composition_currentness_replacement_and_destroyed_lease_precede_verification",
    "composition_requires_exact_fixture_threshold_weights_and_identity_mapping",
]:
    assert name in discovery and name in focused, name
assert "34 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in focused
assert regressions.count("34 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out") == 2
assert "7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in regressions
assert "error[E0433]" in text("visibility-failure.log.gz")
assert "COMPOSITION strict B refused; mutant B verified three signatures" in focused
print("PASS: five distinct composition tests, focused/regression counts and retained failed attempt")
print("NOT ESTABLISHED: authenticated currentness, protocol finality, application or resume")
