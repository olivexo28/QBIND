import hashlib
from pathlib import Path
import subprocess

base = "01e5731617a1ca2a9894bad4e7c5d54466587c39"
source = "crates/qbind-node/src/binary_consensus_loop.rs"
plan = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"


def baseline(path):
    return subprocess.check_output(["git", "show", f"{base}:{path}"])


old = baseline(source)
new = Path(source).read_bytes()
prefix = b"                    #[test]\r\n                    fn "
old_start = old.index(prefix + b"run422_f7_retained_qc_formed_tc_handlers_")
new_start = new.index(prefix + b"run422_f7_retained_qc_missing_locked_block_")
suffix = prefix + b"run422_f7_retained_qc_inbound_trigger_and_selected_"
assert old[:old_start] == new[:new_start], "bytes before test region changed"
assert old[old.index(suffix):] == new[new.index(suffix):], "bytes after test region changed"
assert new.count(b"\n") == new.count(b"\r\n"), "source CRLF changed"
print("PASS: only the focused cfg(test) region changed; source CRLF preserved")

old_plan = baseline(plan)
new_plan = Path(plan).read_bytes()
assert new_plan.startswith(old_plan), "historical plan bytes changed"
assert b"## 26. F7 retained-QC" in new_plan[len(old_plan):], "plan append missing"
print(f"PASS: all {len(old_plan)} historical plan bytes remain a prefix")

changed = subprocess.check_output(
    ["git", "diff", "--name-only", base], text=True
).splitlines()
allowed = {source, plan}
package = "docs/security/evidence/f7-retained-qc-fixture/"
assert all(path in allowed or path.startswith(package) for path in changed), changed
print("PASS: no other accepted tracked path changed")

for path in [source, plan, "Cargo.lock"]:
    data = Path(path).read_bytes()
    print(f"SHA256 {hashlib.sha256(data).hexdigest()} {path} ({len(data)} bytes)")

subprocess.run(
    [
        "git", "-c", "core.whitespace=cr-at-eol", "diff", "--check", base,
        "--", ".", f":(exclude){package}*.log",
    ],
    check=True,
)
print("PASS: CRLF-aware source/documentation whitespace check; verbatim logs excluded")
