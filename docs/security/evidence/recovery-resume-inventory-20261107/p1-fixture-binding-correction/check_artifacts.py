"""Verify the P1-IMPL-1 evidence against its producing revisions."""

import gzip
import hashlib
import re
import subprocess
from pathlib import Path

BASE = "f4ed8a123762dfc9aa1f1a9bdcffa78942894eed"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "p1-fixture-binding-correction"
TEST = Path("crates/qbind-consensus/tests/p1_provider_model_tests.rs")
AUDIT = Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md")
APPENDS = {
    Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"),
    ROOT / "README.md",
    ROOT / "CHANGED_PATHS.txt",
    ROOT / "commands.txt",
}


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(revision, path):
    return git("show", f"{revision}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(BASE, path)), path
historical = [
    Path(name)
    for name in git("ls-tree", "-r", "--name-only", BASE, str(ROOT))
    .decode()
    .splitlines()
    if Path(name) not in APPENDS
]
for path in historical:
    assert path.read_bytes() == blob(BASE, path), path
assert AUDIT.read_bytes() == blob(BASE, AUDIT)
print(f"PASS: four append-only prefixes, {len(historical)} historical files and audit bytes")

manifest = ROOT / "p1-provider-model-implementation/SHA256SUMS"
entries = blob(BASE, manifest).decode().splitlines()
for line in entries:
    expected, name = line.split("  ", 1)
    assert hashlib.sha256(blob(BASE, name)).hexdigest() == expected, name
print(f"PASS: {len(entries)} previous manifest entries against producing revision {BASE}")

changed = set(git("diff", "--name-only", BASE).decode().splitlines())
changed.update(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
allowed = {str(TEST), *(str(path) for path in APPENDS)}
assert all(name in allowed or name.startswith(str(HERE) + "/") for name in changed), changed
assert str(TEST) in changed
old_names = set(re.findall(r"#\[test\]\s*fn (\w+)\(", blob(BASE, TEST).decode()))
new_names = set(re.findall(r"#\[test\]\s*fn (\w+)\(", TEST.read_text()))
assert len(old_names) == 17 and old_names <= new_names and len(new_names) == 19
print("PASS: changed-path scope and all 17 prior test names retained; 19 current tests")

baseline = gzip.decompress((HERE / "baseline.log.gz").read_bytes()).decode()
focused = gzip.decompress((HERE / "focused.log.gz").read_bytes()).decode()
regressions = gzip.decompress((HERE / "regressions.log.gz").read_bytes()).decode()
for variant in ["policy", "catalog"]:
    assert f"BASELINE {variant} admission: B matching candidate admitted" in baseline
    assert f"BASELINE {variant} use: A lease with B reaches sentinel" in baseline
    assert f"CORRECTED {variant}: same-ID substitution refused" in focused
assert "1 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out" in baseline
assert "19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in focused
assert "9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in regressions
assert "7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in regressions
print("PASS: baseline diagnostic and corrected/regression result counts")

print("NOT ESTABLISHED: production enforcement, real currentness, fencing or resume")
