"""Verify test-only scope, historical bytes and successful-reset evidence."""

import pathlib
import re
import subprocess

BASE = "11bb930e005abd082a1dbb296f0b8fe90dcf4fc0"
ROOT = pathlib.Path("docs/security/evidence/a33_f1")
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
MANIFEST = str(ROOT / "SHA256SUMS")
TEST = "crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs"
NEW = [
    "authority-reset-verified-checks.py",
    "authority-reset-verified-checks.log",
    "authority-reset-verified-evidence.md",
    "authority-reset-verified-focused.log",
    "authority-reset-verified-format.log",
    "authority-reset-verified-intermediate.log",
    "authority-reset-verified-platform.log",
    "authority-reset-verified-regressions.log",
]
allowed = {PLAN, MANIFEST, TEST} | {str(ROOT / name) for name in NEW}


def git(*args):
    return subprocess.check_output(["git", *args])


for name in (PLAN, MANIFEST):
    assert pathlib.Path(name).read_bytes().startswith(git("show", f"{BASE}:{name}")), name
subprocess.run(
    ["git", "diff", "--exit-code", BASE, "--", "."]
    + [f":(exclude){name}" for name in sorted(allowed)],
    check=True,
)
changed = set(git("diff", "--name-only", BASE).decode().splitlines())
changed.update(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
assert changed <= allowed, changed - allowed
subprocess.run(["rustfmt", "--check", "--edition", "2021", TEST], check=True)
focused = (ROOT / "authority-reset-verified-focused.log").read_text()
regressions = (ROOT / "authority-reset-verified-regressions.log").read_text()
assert "1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in focused
assert "6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in focused
assert "22 passed; 0 failed; 0 ignored; 0 measured; 2204 filtered out" in regressions
assert len(re.findall(r"case=([^;]+); returned=", focused)) == 18
for observation in [
    "first reset: public success",
    "repeat reset: verified existing-marker success",
    "valid-input equal path: UnsafeAuditPath",
    "tampered signed bundle: real verification refusal",
    "tampered ratification signature: Strict enforcement refusal",
]:
    assert observation in focused, observation
print("PASS: verified success/negative controls, six path tests and 22 module regressions.")
links = 0
evidence = ROOT / "authority-reset-verified-evidence.md"
for path, text in [
    (evidence, evidence.read_text()),
    (pathlib.Path(PLAN), pathlib.Path(PLAN).read_text().split("## 40.", 1)[1]),
]:
    assert len(re.findall(r"^```", text, re.M)) % 2 == 0
    for link in re.findall(
        r"\[[^\]]+\]\(([^)]+)\)", re.sub(r"```.*?```", "", text, flags=re.S)
    ):
        assert (path.parent / link).is_file(), link
        links += 1
print(f"PASS: {links} local documentation links; balanced fences and test formatting.")
print("PASS: plan/manifest historical prefixes; production/audit/prior evidence unchanged.")
print("PASS: only the following test/new evidence/append-only paths changed:")
for name in sorted(allowed):
    print(name)
