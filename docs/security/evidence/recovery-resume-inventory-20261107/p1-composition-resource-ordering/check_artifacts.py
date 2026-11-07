"""Verify resource-ordering evidence, preserving accepted test artifacts."""

import gzip
import hashlib
import re
import subprocess
from pathlib import Path

BASE = "58ea48c1bb1d20526143cf2737767c912fd0f365"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "p1-composition-resource-ordering"
MODEL = Path("crates/qbind-consensus/tests/p1_provider_model_tests.rs")
CONTENT = Path("crates/qbind-consensus/tests/content_binding_experiment_tests.rs")
COMPOSITION = Path("crates/qbind-consensus/tests/support/p1_content_composition.rs")
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

entries = blob(ROOT / "p1-content-binding-composition/SHA256SUMS").decode().splitlines()
for line in entries:
    expected, name = line.split("  ", 1)
    assert hashlib.sha256(blob(name)).hexdigest() == expected, name
print(f"PASS: {len(entries)} accepted composition manifest entries against producing revision {BASE}")

content_baseline = blob(CONTENT)
assert CONTENT.read_bytes() == content_baseline
model_baseline = blob(MODEL)
for old_name in re.findall(rb"#\[test\]\s*fn (\w+)\(", model_baseline):
    assert re.search(rb"#\[test\]\s*fn " + old_name + rb"\(", MODEL.read_bytes()), old_name
old_composition = blob(COMPOSITION).decode()
new_composition = COMPOSITION.read_text()
old_tests = set(re.findall(r"#\[test\]\s*fn (\w+)\(", old_composition))
new_tests = set(re.findall(r"#\[test\]\s*fn (\w+)\(", new_composition))
assert len(old_tests) == 5 and old_tests <= new_tests and len(new_tests) == 8
print("PASS: content experiment test bodies unchanged; five accepted composition tests retained")

changed = set(git("diff", "--name-only", BASE).decode().splitlines())
changed.update(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
allowed = {
    str(MODEL),
    str(CONTENT),
    str(COMPOSITION),
    *(str(path) for path in APPENDS),
}
assert all(name in allowed or name.startswith(str(HERE) + "/") for name in changed), changed
assert "Cargo.toml" not in changed and "Cargo.lock" not in changed
print("PASS: modified paths limited to test support and append-only evidence")


def output(name):
    return gzip.decompress((HERE / name).read_bytes()).decode()


discovery = output("discovery.log.gz")
focused = output("focused.log.gz")
regressions = output("regressions.log.gz")
for name in [
    "composition_preflight_limits_before_signature_copy_and_frame",
    "composition_provider_and_currentness_refuse_before_evidence_copy_or_frame",
    "defective_order_copies_and_frames_before_provider_refusal_is_detected",
]:
    assert name in discovery and name in focused, name
assert "37 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in focused
assert regressions.count("37 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out") == 2
assert "7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in regressions
assert "signature copies=7260 frame_constructions=1" in focused
assert "error[E0425]" in output("signature-length-compile-failure.log.gz")
assert "1 failed" in output("first-ordering-failure.log.gz")
print("PASS: three distinct ordering controls, result counts and intermediate failures retained")
print("NOT ESTABLISHED: allocator/total-memory bounds, production currentness, finality or resume")
