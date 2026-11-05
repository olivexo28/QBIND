"""Run from the repository root to verify this bounded evidence package."""

import hashlib
from pathlib import Path
import re
import subprocess


START = "7268cbd047b559291cb5472f9c702543c6397f09"
PRODUCER = "4b055bd529ba6f19cec9619addeb08dc02e19347"
EVIDENCE = Path("docs/security/evidence/a6-f1-outbound-single-connection")
PLAN = Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md")
SOURCE = "crates/qbind-node/src/p2p_tcp.rs"


def git(*args):
    return subprocess.check_output(["git", "--no-pager", *args])


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


require(
    git("show", "-s", "--format=%T %P", PRODUCER).decode().strip()
    == f"2922d66a7f96dd6f12190fb5561fb532793226fc {START}",
    "Producer ancestry mismatch",
)
require(
    git("diff", "--name-only", START, PRODUCER).decode().splitlines() == [SOURCE],
    "Producer scope mismatch",
)
require(Path(SOURCE).read_bytes() == git("show", f"{PRODUCER}:{SOURCE}"), "Source changed")
require(
    git("ls-tree", PRODUCER, SOURCE).decode().strip()
    == f"100644 blob 0dd88492a6576b1184d8f7473fd0953043ea614e\t{SOURCE}",
    "Source identity mismatch",
)
print("Producer parent/tree and source mode/blob verified")

original = git("show", f"{START}:{PLAN}")
require(
    hashlib.sha256(original).hexdigest()
    == "3600af94967508ea5b0c6a0479fc081e3aba4a2c9d8659f35705b9ba58d8dc53",
    "Starting plan identity mismatch",
)
require(PLAN.read_bytes().startswith(original), "Earlier plan bytes changed")
require(
    PLAN.read_bytes()[len(original):].startswith(
        b"\n## 20. A6-F1 pre-existing outbound double-connection correction\n"
    ),
    "Plan is not append-only",
)
print("All earlier plan bytes preserved")

for directory in ["a6-f1-displaced-peer-cleanup", "a6-f1-implementation-correction"]:
    paths = git(
        "ls-tree", "-r", "--name-only", START, f"docs/security/evidence/{directory}"
    ).decode().splitlines()
    require(bool(paths), "Missing historical evidence")
    for name in paths:
        require(Path(name).read_bytes() == git("show", f"{START}:{name}"), name)
    print(f"Historical evidence unchanged: {directory}: {len(paths)} files")

total = 0
for name, counts in [
    ("lifecycle", [21]),
    ("secure-channel", [16]),
    ("compatibility", [6, 8, 10, 18]),
]:
    text = (EVIDENCE / f"{name}.log").read_text()
    require(f"producer: {PRODUCER}\n" in text, f"{name}: wrong producer")
    require(text.endswith("exit status: 0\n"), f"{name}: wrong exit")
    actual = [
        int(count)
        for count in re.findall(
            r"^test result: ok\. (\d+) passed; 0 failed; 0 ignored;", text, re.M
        )
    ]
    require(actual == counts, f"{name}: wrong results")
    total += sum(actual)
print(f"{total} selected producer tests passed")

for name in ["production-check", "format-whitespace"]:
    text = (EVIDENCE / f"{name}.log").read_text()
    require(f"producer: {PRODUCER}\n" in text, f"{name}: wrong producer")
    require(text.endswith("exit status: 0\n"), f"{name}: wrong exit")
baseline = (EVIDENCE / "baseline.log").read_text()
require("test result: FAILED. 0 passed; 4 failed;" in baseline, "Baseline result")
require(baseline.count("left: 2\n right: 1") == 4, "Baseline connection count")
require(baseline.endswith("exit status: 101\n"), "Baseline exit")
print("Producer checks passed; four expected baseline double-connect failures verified")

manifest = (EVIDENCE / "SHA256SUMS").read_text().splitlines()
names = []
for line in manifest:
    digest, name = line.split("  ", 1)
    require(Path(name).name == name, "Manifest entry must be a basename")
    require(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest() == digest, name)
    names.append(name)
require(len(names) == len(set(names)), "Duplicate manifest entries")
require(
    set(names) == {path.name for path in EVIDENCE.iterdir() if path.name != "SHA256SUMS"},
    "Manifest inventory mismatch",
)
print(f"SHA256SUMS: all {len(names)} evidence files verified")
