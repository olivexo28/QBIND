"""Run from repository root; read-only bounded F002 scope/document checks."""
import hashlib
import re
import stat
import subprocess
import sys
from pathlib import Path

BASE = "305640e0dffa16872692906af052dbf15937b192"
PRODUCER = "149edffd8f7fd97c821d6df9a5a546eca4992b79"
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
EVIDENCE = "docs/security/evidence/f002/"
CODE = {
    "crates/qbind-gov/src/verify.rs",
    "crates/qbind-gov/src/hash.rs",
    "crates/qbind-gov/tests/envelope_cli_tests.rs",
}


def git(*args):
    return subprocess.check_output(["git", *args])


def section(data, number):
    return re.search(
        rb"^## " + str(number).encode() + rb"\. .*?(?=^## |\Z)",
        data,
        re.M | re.S,
    ).group()


print("Command: python docs/security/evidence/f002/check_scope.py")
print("Checked HEAD:", git("rev-parse", "HEAD").decode().strip())
print("Code/test producer:", PRODUCER)
baseline = git("show", f"{BASE}:{PLAN}")
current = Path(PLAN).read_bytes()
for number in [1, 2, 3, 5, 6, 7, 8, 9, 10, 12]:
    original = section(baseline, number)
    assert section(current, number) == original, number
    print(f"Section {number} byte-identical SHA-256:", hashlib.sha256(original).hexdigest())
without_f002 = lambda data: re.sub(rb"^\| QBIND-A1-F002 \|.*\n", b"", data, flags=re.M)
assert without_f002(section(baseline, 4)) == without_f002(section(current, 4))
print("Section 4 unchanged except F002 row; all other finding/alias rows retained")
assert git("show", f"{BASE}:Audit/QBIND_SECURITY_FINDINGS_REGISTER.md") == Path(
    "Audit/QBIND_SECURITY_FINDINGS_REGISTER.md"
).read_bytes()
print("Audit register byte-identical")
hash_path = "crates/qbind-gov/src/hash.rs"
assert git("show", f"{BASE}:{hash_path}").split(b"#[cfg(test)]")[0] == Path(
    hash_path
).read_bytes().split(b"#[cfg(test)]")[0]
print("hash.rs production bytes byte-identical")
for path in sorted(CODE):
    assert Path(path).read_bytes() == git("show", f"{PRODUCER}:{path}")
print("All three Rust paths equal exact tested producing revision")
changed = set(git("diff", "--name-only", BASE).decode().splitlines())
untracked = set(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
for path in sorted(changed | untracked):
    assert path in CODE or path == PLAN or path.startswith(EVIDENCE), path
    sys.stdout.flush()
    data = Path(path).read_bytes()
    checked = data.replace(b"\r\n", b"\n") if path.endswith(".log") else data
    assert b"\r" not in checked and checked.endswith(b"\n"), path
    mode = stat.S_IMODE(Path(path).stat().st_mode)
    assert mode == 0o644, (path, oct(mode))
    entry = git("ls-tree", BASE, "--", path).decode()
    if entry:
        assert entry.startswith("100644 blob "), entry
    print("Allowed path / mode 100644 / LF (logs may retain CRLF) / final newline:", path)
for doc, content in [
    (Path(PLAN), section(current, 13).decode()),
    (Path(EVIDENCE + "README.md"), Path(EVIDENCE + "README.md").read_text()),
]:
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
        if "://" not in target and not target.startswith("#"):
            assert (doc.parent / target.split("#")[0]).exists(), (doc, target)
print("Section 13 and evidence README relative links resolve")
subprocess.run(
    ["git", "-c", "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol",
     "diff", "--check", BASE],
    check=True,
)
print("git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol diff --check baseline: exit 0")
subprocess.run(["git", "merge-base", "--is-ancestor", BASE, PRODUCER], check=True)
subprocess.run(["git", "merge-base", "--is-ancestor", PRODUCER, "HEAD"], check=True)
print("Available-object ancestry baseline -> producer -> checked HEAD: exit 0")
print("PASS; exit_status=0")
