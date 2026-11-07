"""Artifact-only checks for the isolated hypothetical statement experiment."""

import hashlib
import re
import subprocess
from pathlib import Path

BASE = "4162a9c20b2686f6a4d662e7e487eb536073e37a"
MAIN = "9bf0eb43e4e3c601d02d3886d220b0abeb3a103e"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "content-binding-experiment"
TEST = Path("crates/qbind-consensus/tests/content_binding_experiment_tests.rs")
APPENDS = [
    Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"),
    ROOT / "README.md",
    ROOT / "CHANGED_PATHS.txt",
    ROOT / "commands.txt",
]


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(revision, path):
    return git("show", f"{revision}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(BASE, path)), path
print("PASS: all four appended documents preserve exact producing-base prefixes")

old_paths = git("ls-tree", "-r", "--name-only", BASE, str(ROOT), "Audit").decode().splitlines()
preserved = [Path(path) for path in old_paths if Path(path) not in APPENDS]
for path in preserved:
    assert path.read_bytes() == blob(BASE, path), path
print(f"PASS: {len(preserved)} historical evidence/Audit files byte-identical")
audit = Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md")
assert hashlib.sha256(audit.read_bytes()).hexdigest() == "6e68d3d05964f9a6dc0384ffda2bb53d81d7da97ffb786ce84f4bd5a4360c0d9"
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
    ("binding-sensitivity-execution/SHA256SUMS", BASE),
]
total = 0
for name, revision in producers:
    entries = blob(revision, ROOT / name).decode().splitlines()
    for entry in entries:
        digest, path = entry.split("  ", 1)
        assert hashlib.sha256(blob(revision, path)).hexdigest() == digest, (name, path)
    total += len(entries)
    print(f"PASS: {name}: {len(entries)} entries at producer {revision}")
assert total == 129
print("PASS: ten producing-revision manifests / 129 historical entries; not current appended hashes")

source = TEST.read_text()
names = set(re.findall(r"#\[test\]\s*fn (\w+)", source))
listed = set(re.findall(r"^(\w+): test$", (HERE / "02-discovery.stdout").read_text(), re.M))
run = (HERE / "03-focused.stdout").read_text()
executed = set(re.findall(r"^test (\w+) \.\.\.", run, re.M))
assert names == listed == executed and len(names) == 7
assert "7 tests, 0 benchmarks" in (HERE / "02-discovery.stdout").read_text()
assert "7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in run
for name, expected in [("01-discovery", 101), ("02-discovery", 0), ("03-focused", 0)]:
    assert int((HERE / f"{name}.exit").read_text()) == expected
    assert (HERE / f"{name}.stdout").is_file() and (HERE / f"{name}.stderr").is_file()
assert "found one with a size of 17" in (HERE / "01-discovery.stderr").read_text()
for token in ["BINDING seven", "SENSITIVITY omitted-field", "SENSITIVITY uniqueness", "ACCOUNTING statement=358", "pre-input-allocation"]:
    assert token in run, token
assert len(b"QBIND-TEST-CBND1") == 16
assert 16 + 2 + 2 + 8 + 8 + 32 + 32 + 2 == 102
assert 102 + 256 == 358
assert 358 + 2 + 3 * (4 + 2420) == 7632
assert 358 + 2 + 4 * (4 + 2420) == 10056
assert 4 * 1312 == 5248
print("PASS: seven exact discovered/executed tests, zero failures/ignored/filtered; failed compile retained")
print("PASS: statement/bundle/framing/key arithmetic and omission/counter observations")

changed = set(git("diff", "--name-only", BASE).decode().splitlines())
untracked = set(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
for path in changed | untracked:
    assert Path(path) in APPENDS + [TEST] or path.startswith(str(HERE) + "/"), path
existing_tests = git("ls-tree", "-r", "--name-only", BASE, "crates/qbind-consensus/tests").decode().splitlines()
for path in existing_tests:
    assert Path(path).read_bytes() == blob(BASE, path), path
assert set(git("diff", "--name-only", BASE, "--", "crates").decode().splitlines()) <= {str(TEST)}
assert not git("diff", "--name-only", BASE, "--", "Cargo.toml", "Cargo.lock", ".cargo", ".github").strip()
assert "MlDsa44Backend.verify_vote(" in source and "MlDsa44Backend::sign(" in source
assert "trace.backend_calls += 1" in source
assert "omit_field: Option<Field>" in source and "omit_uniqueness: bool" in source
for forbidden in ["qbind_node::", "std::fs::", "std::net::", "std::process::", "BasicHotStuffEngine", "mod binding_sensitivity_support", "include_bytes!", "unsafe {"]:
    assert forbidden not in source, forbidden
print("PASS: authorized scope only; every existing integration test byte-identical; production/config unchanged")
print("PASS: private defects only in new target; real raw backend; no node/store/network/engine imports")

for path in [APPENDS[0], ROOT / "README.md"]:
    addition = path.read_bytes()[len(blob(BASE, path)):].decode()
    link = re.search(r"\]\(([^)]+content-binding-experiment/README.md)\)", addition)
    if link is None:
        link = re.search(r"\]\((content-binding-experiment/README.md)\)", addition)
    assert link and (path.parent / link.group(1)).is_file(), path
links = re.findall(r"https://github\.com/olivexo28/QBIND/blob/([0-9a-f]{40})/([^\s)#]+)#L(\d+)-L(\d+)", (HERE / "README.md").read_text())
assert len(links) == 3
for revision, path, first, last in links:
    assert revision == MAIN
    assert 1 <= int(first) <= int(last) <= len(blob(revision, path).decode().splitlines())
print("PASS: append navigation and three pinned real-backend source ranges")

# Keep complete cargo stdout intact rather than trimming its final blank line.
exception = f":!{HERE}/03-focused.stdout"
subprocess.run(["git", "diff", "--check", "--", ".", exception], check=True)
subprocess.run(["git", "diff", "--cached", "--check", "--", ".", exception], check=True)
print("PASS: scoped whitespace; original cargo stdout trailing blank line preserved, explicitly excepted")
print("NOT ESTABLISHED: production protocol/finality/historical binding/currentness/application/ownership/signing/resume")
print("UNMEASURED: total retained memory/backend working set/work/runtime/cancellation/network admission")
