"""Scope/preservation/format controls for stage-aware reset errors."""

import pathlib
import re
import subprocess

BASE = "6506faf18485769a2c852b7609149f908b807848"
ROOT = pathlib.Path("docs/security/evidence/a33_f1")
SOURCE = "crates/qbind-node/src/pqc_authority_state_reset.rs"
TEST = "crates/qbind-node/src/pqc_authority_state_reset_error_tests.rs"
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
MANIFEST = str(ROOT / "SHA256SUMS")
NEW = [
    "authority-reset-errors-checks.py",
    "authority-reset-errors-checks.log",
    "authority-reset-errors-evidence.md",
    "authority-reset-errors-unit.log",
    "authority-reset-errors-paths.log",
    "authority-reset-errors-format.log",
    "authority-reset-errors-platform.log",
]
allowed = {SOURCE, TEST, PLAN, MANIFEST} | {str(ROOT / name) for name in NEW}


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
old = git("show", f"{BASE}:{SOURCE}").decode().replace("\r\n", "\n")
source = pathlib.Path(SOURCE).read_text()
for start, end in [
    ("fn check_authority_reset_audit_path(", "/// Persist an audit record"),
    ("pub fn write_authority_reset_audit(", "// ============================================================================"),
    ("pub fn verify_authority_reset_inputs(", "/// Archive the existing"),
]:
    assert source.split(start)[1].split(end)[0] == old.split(start)[1].split(end)[0]
assert source.split("#[cfg(test)]\nmod tests {")[1] == old.split(
    "#[cfg(test)]\nmod tests {"
)[1]
formatted = subprocess.check_output(
    ["rustfmt", "--emit", "stdout", "--edition", "2021", SOURCE], text=True
)
for start, end in [
    ("fn attempt_failure(", "// ============================================================================"),
    ("pub fn execute_authority_state_reset(", "// ============================================================================\n// Tests"),
]:
    assert source.split(start)[1].split(end)[0] == formatted.split(start)[1].split(end)[0]
subprocess.run(["rustfmt", "--check", "--edition", "2021", TEST], check=True)
print("PASS: new helper/sequencing/test formatting; legacy formatting retained.")
print("PASS: verification, path guard, audit writer and legacy module tests unchanged.")
links = 0
evidence = ROOT / "authority-reset-errors-evidence.md"
for path, text in [
    (evidence, evidence.read_text()),
    (pathlib.Path(PLAN), pathlib.Path(PLAN).read_text().split("## 39.", 1)[1]),
]:
    assert len(re.findall(r"^```", text, re.M)) % 2 == 0
    for link in re.findall(
        r"\[[^\]]+\]\(([^)]+)\)", re.sub(r"```.*?```", "", text, flags=re.S)
    ):
        assert (path.parent / link).is_file(), link
        links += 1
unit = (ROOT / "authority-reset-errors-unit.log").read_text()
paths = (ROOT / "authority-reset-errors-paths.log").read_text()
assert "22 passed; 0 failed; 0 ignored; 0 measured; 2204 filtered out" in unit
assert "6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in paths
assert len(re.findall(r"case=([^;]+); returned=", paths)) == 18
for stage in ("VerificationRefusalAudit", "MarkerPersistence", "SuccessAudit"):
    assert f"stage: {stage}" in unit
for marker in ("NotAttempted", "AttemptedUncertain", "Acknowledged"):
    assert f"marker: {marker}" in unit
assert "marker_bytes_changed=true" not in paths
print(f"PASS: {links} links, fences, test counts, stages and marker outcomes.")
print("PASS: previous plan/manifest prefixes and all non-whitelisted tracked bytes preserved.")
print("PASS: changed paths confined to the following whitelist:")
for name in sorted(allowed):
    print(name)
