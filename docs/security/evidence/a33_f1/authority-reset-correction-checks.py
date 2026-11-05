"""Reproduce the correction's scope, preservation and formatting checks."""

import hashlib
import pathlib
import re
import subprocess

BASE = "e8f58a5c391f282c1996f4306c02743ace056fa5"
ROOT = pathlib.Path("docs/security/evidence/a33_f1")
SOURCE = "crates/qbind-node/src/pqc_authority_state_reset.rs"
TEST = "crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs"
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
MANIFEST = str(ROOT / "SHA256SUMS")
NEW = [
    "authority-reset-correction-checks.py",
    "authority-reset-correction-evidence.md",
    "authority-reset-correction-checks.log",
    "authority-reset-correction-checks-attempt-1.log",
    "authority-reset-correction-focused-tests.log",
    "authority-reset-correction-format.log",
    "authority-reset-correction-incomplete-registration.log",
    "authority-reset-correction-intermediate-5-tests.log",
    "authority-reset-correction-intermediate-6-tests.log",
    "authority-reset-correction-intermediate-regressions.log",
    "authority-reset-correction-platform.log",
    "authority-reset-correction-regressions.log",
]
ALLOWED = {SOURCE, TEST, PLAN, MANIFEST} | {str(ROOT / name) for name in NEW}


def git(*args):
    return subprocess.check_output(["git", *args])


for name in git("ls-tree", "-r", "--name-only", BASE).decode().splitlines():
    old = git("show", f"{BASE}:{name}") if name in ALLOWED else None
    if name in (PLAN, MANIFEST):
        assert pathlib.Path(name).read_bytes().startswith(old), name
    elif name not in (SOURCE, TEST):
        # Compare tracked bytes in one git operation below instead of reading
        # every repository object separately.
        assert name not in ALLOWED, name
subprocess.run(
    ["git", "diff", "--exit-code", BASE, "--", "."]
    + [f":(exclude){name}" for name in sorted(ALLOWED)],
    check=True,
)
changed = set(git("diff", "--name-only", BASE).decode().splitlines())
changed.update(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
assert changed <= ALLOWED, changed - ALLOWED
source = pathlib.Path(SOURCE).read_text()
old_source = git("show", f"{BASE}:{SOURCE}").decode().replace("\r\n", "\n")
assert source.split("#[cfg(test)]\nmod tests {")[1] == old_source.split(
    "#[cfg(test)]\nmod tests {"
)[1], "legacy module tests changed"
formatted = subprocess.check_output(
    ["rustfmt", "--emit", "stdout", "--edition", "2021", SOURCE], text=True
)
start = "fn check_authority_reset_audit_path("
end = "/// Persist an audit record (tmp + rename)"
assert source.split(start)[1].split(end)[0] == formatted.split(start)[1].split(end)[0]
subprocess.run(["rustfmt", "--check", "--edition", "2021", TEST], check=True)
print("PASS: new helper/test formatting; legacy tests retained verbatim.")
evidence = ROOT / "authority-reset-correction-evidence.md"
links = 0
for path, text in (
    (evidence, evidence.read_text()),
    (pathlib.Path(PLAN), pathlib.Path(PLAN).read_text().split("## 38.", 1)[1]),
):
    assert len(re.findall(r"^```", text, re.M)) % 2 == 0
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
        assert (path.parent / link).is_file(), link
        links += 1
log = (ROOT / "authority-reset-correction-focused-tests.log").read_text()
assert "6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in log
assert len(re.findall(r"case=([^;]+); returned=", log)) == 18
assert "marker_bytes_changed=true" not in log
regressions = (ROOT / "authority-reset-correction-regressions.log").read_text()
assert "18 passed; 0 failed; 0 ignored; 0 measured; 2204 filtered out" in regressions
print(f"PASS: {links} links, fences, six tests/18 scenarios and 18 regressions.")
print("PASS: prior plan/manifest prefixes and all other tracked bytes preserved.")
print("PASS: changed paths confined to explicit source/test/new evidence whitelist.")
for name in sorted(ALLOWED):
    if name == str(ROOT / "authority-reset-correction-checks.log"):
        continue
    print(hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest(), name)
