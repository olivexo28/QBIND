"""Artifact checks only, not a rerun of accepted tests."""

import hashlib
import re
import subprocess
from pathlib import Path

BASE = "e531a7c5a96b978cd1b82b006396c08b24e0933e"
MAIN = "9bf0eb43e4e3c601d02d3886d220b0abeb3a103e"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "authority-context-experiment"
TEST = Path("crates/qbind-consensus/tests/authority_context_experiment_tests.rs")
APPENDS = [Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md")] + [
    ROOT / name for name in ["README.md", "CHANGED_PATHS.txt", "commands.txt"]
]


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(revision, path):
    return git("show", f"{revision}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(BASE, path)), path
print("PASS: four exact historical byte prefixes")
preserved = [
    Path(path) for path in git("ls-tree", "-r", "--name-only", BASE, str(ROOT), "Audit").decode().splitlines()
    if Path(path) not in APPENDS
]
for path in preserved:
    assert path.read_bytes() == blob(BASE, path), path
print(f"PASS: {len(preserved)} prior evidence/Audit files byte-identical")
assert hashlib.sha256(Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md").read_bytes()).hexdigest() == "6e68d3d05964f9a6dc0384ffda2bb53d81d7da97ffb786ce84f4bd5a4360c0d9"
print("PASS: audit-register SHA256 unchanged")
producers = [
    ("SHA256SUMS", "61028eb6dbb91f0834a5235f20c935bb0ff5b549"),
    ("CORRECTION-SHA256SUMS", "8344e92412d37882ef059b6158ead1959b0fa165"),
    ("CONTRACT-SHA256SUMS", "a4620f1e9363fbd30b23f06448e8f19174de8192"),
    ("AP1-CORRECTION-SHA256SUMS", "c12b46497a404171ca41c640f614f0c308ae514b"),
    ("WITNESS-SHA256SUMS", "e893d0bf7359deb87998ff67e63fbd92aabffd91"),
    ("BINDING-SHA256SUMS", "6ba38e9fa66f216e45906b3eb0575d67aa0cd071"),
    ("OPTIONS-SHA256SUMS", "0a405c6063d49d8b0d0a4211d091f5405d79b6a6"),
    ("TEST-PLAN-CORRECTION-SHA256SUMS", "3725ff080830df60e274fdaa080e390ccdbcc827"),
    ("STRUCTURAL-CONTROL-SHA256SUMS", "4ab46f22a66afdfae2363da7da3e493f56155451"),
    ("binding-sensitivity-execution/SHA256SUMS", "4162a9c20b2686f6a4d662e7e487eb536073e37a"),
    ("content-binding-experiment/SHA256SUMS", BASE),
]
total = 0
for name, revision in producers:
    entries = blob(revision, ROOT / name).decode().splitlines()
    for entry in entries:
        digest, path = entry.split("  ", 1)
        assert hashlib.sha256(blob(revision, path)).hexdigest() == digest, (name, path)
    total += len(entries)
    print(f"PASS: {name}: {len(entries)} entries at producer {revision}")
assert total == 166
print("PASS: eleven historical producer manifests / 166 entries, not current appended hashes")
source = TEST.read_text()
names = set(re.findall(r"#\[test\]\s*fn (\w+)", source))
listed = set(re.findall(r"^(\w+): test$", (HERE / "01-discovery.stdout").read_text(), re.M))
run = (HERE / "02-focused.stdout").read_text()
executed = set(re.findall(r"^test (\w+) \.\.\.", run, re.M))
assert names == listed == executed and len(names) == 9
assert "9 tests, 0 benchmarks" in (HERE / "01-discovery.stdout").read_text()
assert "9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in run
for name in ["01-discovery", "02-focused", "03-format"]:
    assert int((HERE / f"{name}.exit").read_text()) == 0
    assert (HERE / f"{name}.stdout").is_file() and (HERE / f"{name}.stderr").is_file()
for token in ["SENSITIVITY same label/new synthetic committee", "SENSITIVITY witness threshold/weight", "ACCOUNTING statement=358", "not pre-input-allocation"]:
    assert token in run, token
assert 102 + 256 == 358
assert 58 + 4 * (2 + 8 + 2 + 1312) == 5354
assert 358 + 5354 + 2 + 3 * (2 + 2 + 2420) == 12986
assert 358 + 5354 + 2 + 4 * (2 + 2 + 2420) == 15410
assert 4 * 1312 == 5248 and 3 * 2420 == 7260
print("PASS: nine discovered/executed passes, zero failed/ignored/filtered; accounting/sensitivity observations")
changed = set(git("diff", "--name-only", BASE).decode().splitlines())
untracked = set(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
for path in changed | untracked:
    assert Path(path) in APPENDS + [TEST] or path.startswith(str(HERE) + "/"), path
for path in git("ls-tree", "-r", "--name-only", BASE, "crates/qbind-consensus/tests").decode().splitlines():
    assert Path(path).read_bytes() == blob(BASE, path), path
assert set(git("diff", "--name-only", BASE, "--", "crates").decode().splitlines()) <= {str(TEST)}
assert not git("diff", "--name-only", BASE, "--", "Cargo.toml", "Cargo.lock", ".cargo", ".github").strip()
assert "expected: &Context" in source and "compare_context(expected, &witness.claims)?" in source
assert "TestDefect::None =>" in source and "MlDsa44Backend.verify_vote(" in source
assert "expected.members == claimed.members" in source
assert "previous.public == member.public" in source
for forbidden in ["qbind_node::", "std::fs::", "std::net::", "std::process::", "BasicHotStuffEngine", "include_bytes!", "unsafe {", "RefCell", "Mutex"]:
    assert forbidden not in source, forbidden
print("PASS: existing accepted tests/production/config unchanged; expected shared reference, exact context/key equality, private defects")
for path in [APPENDS[0], ROOT / "README.md"]:
    addition = path.read_bytes()[len(blob(BASE, path)):].decode()
    target = re.search(r"\]\(([^)]+authority-context-experiment/README.md)\)", addition)
    if target is None:
        target = re.search(r"\]\((authority-context-experiment/README.md)\)", addition)
    assert target and (path.parent / target.group(1)).is_file(), path
links = re.findall(r"https://github\.com/olivexo28/QBIND/blob/([0-9a-f]{40})/([^\s)#]+)#L(\d+)-L(\d+)", (HERE / "README.md").read_text())
assert len(links) == 3
for revision, path, first, last in links:
    assert revision == MAIN
    assert 1 <= int(first) <= int(last) <= len(blob(revision, path).decode().splitlines())
exception = f":!{HERE}/02-focused.stdout"
subprocess.run(["git", "diff", "--check", "--", ".", exception], check=True)
subprocess.run(["git", "diff", "--cached", "--check", "--", ".", exception], check=True)
print("PASS: navigation/source ranges and scoped whitespace; original cargo stdout EOF blank line retained")
print("NOT ESTABLISHED: external authority/quorum assumptions/currentness/finality/historical binding/application/signing/resume")
print("UNMEASURED: total memory/backend working set/work/runtime/cancellation/network admission")
