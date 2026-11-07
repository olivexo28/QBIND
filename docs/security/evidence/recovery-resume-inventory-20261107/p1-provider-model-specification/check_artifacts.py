"""Documentation/source integrity checks only; no tests/builds are run."""

import hashlib
import re
import subprocess
from pathlib import Path

BASE = "5d328c9ad5c15177960b5b5da50f8b181169b723"
MAIN = "9bf0eb43e4e3c601d02d3886d220b0abeb3a103e"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "p1-provider-model-specification"
APPENDS = [Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md")] + [
    ROOT / name for name in ["README.md", "CHANGED_PATHS.txt", "commands.txt"]
]
DOC = (HERE / "README.md").read_text()


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(revision, path):
    return git("show", f"{revision}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(BASE, path)), path
print("PASS: four exact historical append prefixes")
preserved = [
    Path(path) for path in git("ls-tree", "-r", "--name-only", BASE, str(ROOT), "Audit").decode().splitlines()
    if Path(path) not in APPENDS
]
for path in preserved:
    assert path.read_bytes() == blob(BASE, path), path
assert hashlib.sha256(Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md").read_bytes()).hexdigest() == "6e68d3d05964f9a6dc0384ffda2bb53d81d7da97ffb786ce84f4bd5a4360c0d9"
print(f"PASS: {len(preserved)} prior evidence/Audit files byte-identical; audit-register hash unchanged")

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
    ("content-binding-experiment/SHA256SUMS", "e531a7c5a96b978cd1b82b006396c08b24e0933e"),
    ("authority-context-experiment/SHA256SUMS", "1d5d12e85f7ad939b731e56bf929d20403d00d11"),
    ("authority-provenance-contract/SHA256SUMS", BASE),
]
total = 0
for name, revision in producers:
    entries = blob(revision, ROOT / name).decode().splitlines()
    for entry in entries:
        digest, path = entry.split("  ", 1)
        assert hashlib.sha256(blob(revision, path)).hexdigest() == digest, (name, path)
    total += len(entries)
    print(f"PASS: {name}: {len(entries)} entries at producer {revision}")
assert total == 221
print("PASS: thirteen producer manifests /221 entries; not current appended-file hashes")

changed = set(git("diff", "--name-only", BASE).decode().splitlines())
untracked = set(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
for path in changed | untracked:
    assert Path(path) in APPENDS or path.startswith(str(HERE) + "/"), path
assert not git("diff", "--name-only", BASE, "--", "crates", "Cargo.toml", "Cargo.lock", ".cargo", ".github", "Audit").strip()
assert "FUTURE / NOT EXECUTED" in DOC and "This task reruns no Rust tests/builds" in DOC
for token in ["P1_PRODUCTION=UNSELECTED", "P2_PRODUCTION=UNSELECTED", "B/C=UNSELECTED",
              "Available", "Unavailable", "Stale", "Conflict", "Unknown",
              "16,384", "16,385", "1,312", "2,420", "InvalidatedBeforeUse",
              "founder-bootstrap decision remains", "it has no application, store writer",
              "signer, quarantine-clear", "resume capability"]:
    assert token.lower() in DOC.lower(), token
matrix = DOC.split("## 3. Test-only entrypoints and oracles", 1)[1].split("## 4.", 1)[0]
assert "**FUTURE / NOT EXECUTED**" in matrix
rows = [line for line in matrix.splitlines() if line.startswith("| ") and not line.startswith("| Case") and not line.startswith("|---")]
assert len(rows) == 17, len(rows)
print("PASS: documentation-only scope, P1 boundary/bounds, currentness/oracle and FUTURE labeling")

links = re.findall(r"https://github\.com/olivexo28/QBIND/blob/([0-9a-f]{40})/([^\s)#]+)#L(\d+)-L(\d+)", DOC)
assert len(links) == 7, len(links)
FOUNDER_DECISION = "1d5d12e85f7ad939b731e56bf929d20403d00d11"
for revision, path, first, last in links:
    assert revision in [MAIN, BASE, FOUNDER_DECISION]
    lines = blob(revision, path).decode().splitlines()
    assert 1 <= int(first) <= int(last) <= len(lines), path
    assert any(line.strip() for line in lines[int(first) - 1:int(last)])
    if path.startswith("crates/"):
        assert revision == MAIN
        assert Path(path).read_bytes() == blob(MAIN, path), path
    else:
        assert revision in [BASE, FOUNDER_DECISION]
        assert Path(path).read_bytes() == blob(revision, path), path
print(f"PASS: {len(links)} exact pinned source/decision ranges; production bytes equal protected main")

for path in [APPENDS[0], ROOT / "README.md"]:
    addition = path.read_bytes()[len(blob(BASE, path)):].decode()
    target = re.search(r"\]\(([^)]+p1-provider-model-specification/README.md)\)", addition)
    if target is None:
        target = re.search(r"\]\((p1-provider-model-specification/README.md)\)", addition)
    assert target and (path.parent / target.group(1)).is_file(), path
print("PASS: specification discoverable from append-only plan and evidence index")
subprocess.run(["git", "diff", "--check"], check=True)
subprocess.run(["git", "diff", "--cached", "--check"], check=True)
print("PASS: documentation whitespace; no test/build execution")
print("NOT ESTABLISHED: external provenance/currentness/rollback/ownership/finality/application/signing/fencing/resume")
