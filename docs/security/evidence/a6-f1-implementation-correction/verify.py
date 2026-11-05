"""Run from the repository root: python3 docs/security/evidence/a6-f1-implementation-correction/verify.py."""

import hashlib
from pathlib import Path
import re
import subprocess


START = "cbb774d438361f5787eced49b546cc886e90b59c"
PRODUCER = "e2e7bca7da935f1ecf46f83ba5abac2fc14857d3"
EVIDENCE = Path("docs/security/evidence/a6-f1-implementation-correction")
HISTORICAL = "docs/security/evidence/a6-f1-displaced-peer-cleanup"
PLAN = Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md")


def git(*args):
    return subprocess.check_output(["git", "--no-pager", *args])


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


require(
    git("show", "-s", "--format=%T %P", PRODUCER).decode().strip()
    == f"a4f87173d1e8da13e80fb1789cbc9fc767d419d6 {START}",
    "Producer tree/parent mismatch",
)
original_plan = git("show", f"{START}:{PLAN}")
require(
    hashlib.sha256(original_plan).hexdigest()
    == "b0fe8a8a386b8b8d91305534d61f6da51dc650d37a6a214adbbab3238ff7f27e",
    "Starting plan identity mismatch",
)
require(PLAN.read_bytes().startswith(original_plan), "Prior plan text changed")
require(
    PLAN.read_bytes()[len(original_plan):].startswith(
        b"\n## 19. A6-F1 bounded implementation-review corrections\n"
    ),
    "Correction is not an append after the starting plan",
)
print("Starting plan bytes preserved; correction append verified")

old_paths = git("ls-tree", "-r", "--name-only", START, HISTORICAL).decode().splitlines()
require(len(old_paths) == 7, "Historical evidence inventory mismatch")
for name in old_paths:
    require(Path(name).read_bytes() == git("show", f"{START}:{name}"), name)
print("All 7 historical evidence files unchanged")

producer_paths = git("diff", "--name-only", START, PRODUCER).decode().splitlines()
require(
    producer_paths
    == [
        "crates/qbind-node/src/p2p_tcp.rs",
        "crates/qbind-node/src/secure_channel.rs",
        "crates/qbind-node/src/secure_channel/encrypted_write_tests.rs",
    ],
    "Producer scope mismatch",
)
for name in producer_paths:
    require(Path(name).read_bytes() == git("show", f"{PRODUCER}:{name}"), name)
    print(git("ls-tree", PRODUCER, name).decode().strip())

total = 0
for name, counts in [
    ("lifecycle.log", [15]),
    ("secure-channel.log", [16]),
    ("compatibility.log", [6, 8, 10, 18]),
]:
    text = (EVIDENCE / name).read_text()
    require(f"producer: {PRODUCER}\n" in text, f"{name}: producer mismatch")
    require(text.endswith("exit status: 0\n"), f"{name}: exit mismatch")
    actual = [
        int(count)
        for count in re.findall(
            r"^test result: ok\. (\d+) passed; 0 failed; 0 ignored;", text, re.M
        )
    ]
    require(actual == counts, f"{name}: result mismatch")
    total += sum(actual)
print(f"{total} selected producer tests passed")

for name in ["production-check.log", "format-whitespace.log"]:
    text = (EVIDENCE / name).read_text()
    require(f"producer: {PRODUCER}\n" in text, f"{name}: producer mismatch")
    require(text.endswith("exit status: 0\n"), f"{name}: exit mismatch")
baseline = (EVIDENCE / "baseline-outcome-reproduction.log").read_text()
require("test result: FAILED. 0 passed; 2 failed;" in baseline, "Baseline result")
require(baseline.endswith("exit status: 101\n"), "Baseline exit mismatch")
print("Producer checks and expected baseline failures verified")

for line in (EVIDENCE / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split("  ", 1)
    require(Path(name).name == name, "Manifest entry must be a basename")
    require(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest() == digest, name)
print("SHA256SUMS: all entries verified")
