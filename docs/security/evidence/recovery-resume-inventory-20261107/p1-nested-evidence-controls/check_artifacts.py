"""Documentation-only nested evidence fixture and preservation checks."""

import hashlib
import struct
import subprocess
from pathlib import Path

BASE = "4c9b39fe17e7879fa6555dcf5adc151eea627e2a"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "p1-nested-evidence-controls"
PRIOR = ROOT / "p1-provider-model-specification-correction"
APPENDS = [
    Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"),
    ROOT / "README.md",
    ROOT / "CHANGED_PATHS.txt",
    ROOT / "commands.txt",
]
DOC = (HERE / "README.md").read_text()


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(revision, path):
    return git("show", f"{revision}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(BASE, path)), path
print("PASS: four exact append-only prefixes at supplied task tip")

historical = [
    Path(name)
    for name in git("ls-tree", "-r", "--name-only", BASE, str(ROOT)).decode().splitlines()
    if Path(name) not in APPENDS
]
for path in historical:
    assert path.read_bytes() == blob(BASE, path), path
assert Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md").read_bytes() == blob(
    BASE, "Audit/QBIND_SECURITY_FINDINGS_REGISTER.md"
)
print(f"PASS: {len(historical)} prior evidence files and audit register unchanged")

prior_manifest = blob(BASE, PRIOR / "SHA256SUMS").decode().splitlines()
assert len(prior_manifest) == 31
for entry in prior_manifest:
    expected, name = entry.split("  ", 1)
    assert hashlib.sha256(blob(BASE, name)).hexdigest() == expected, name
print("PASS: prior P1 correction manifest's 31 entries verified at producing tip")

def evidence_frame(entries):
    body = b"".join(struct.pack("<H", len(payload)) + payload for payload in entries)
    total = 13 + len(body)
    return b"QBE1TEST" + struct.pack("<I", total) + bytes([len(entries)]) + body


fixtures = {
    "count_positive": evidence_frame([bytes([i]) for i in range(1, 9)]),
    "count_negative": evidence_frame([bytes([i]) for i in range(1, 10)]),
    "length_positive": evidence_frame([bytes([0xA5]) * 2420]),
    "length_negative": evidence_frame([bytes([0xA5]) * 2421]),
}
expected_sizes = {
    "count_positive": 37,
    "count_negative": 40,
    "length_positive": 2435,
    "length_negative": 2436,
}
for key, data in fixtures.items():
    total = struct.unpack_from("<I", data, 8)[0]
    count = data[12]
    assert data[:8] == b"QBE1TEST"
    assert total == len(data) == expected_sizes[key], (key, total, len(data))
    assert count == len({"count_positive": range(8), "count_negative": range(9),
                         "length_positive": range(1), "length_negative": range(1)}[key])
    assert len(data) < 19389
assert 11339 + max(len(frame) for frame in fixtures.values()) < 35773
print("PASS: exact scanner fixture bytes: 37, 40, 2435, 2436; totals/counts consistent")

assert "FUTURE / NOT EXECUTED" in DOC
for token in [
    "19,389", "19,390", "11,339", "35,773", "EvidenceEntryCountExceeded",
    "EvidenceEntryTooLarge", "evidence_outer_size_checks",
    "evidence_frame_checks", "evidence_count_checks",
    "evidence_entry_length_checks", "evidence_decoder_calls",
    "crypto_calls == 0", "13 + 8 * (2 + 1) = 37",
    "13 + 9 * (2 + 1) = 40", "13 + 2 + 2,420 = 2,435",
    "13 + 2 + 2,421 = 2,436",
]:
    assert token in DOC, token
for refusal in ["outer 19,389-byte refusal", "malformed magic/total",
                "truncation, or trailing"]:
    assert refusal in DOC, refusal
assert (HERE / "COMMANDS.txt").is_file()
assert (HERE / "check_artifacts.py").is_file()
index = (ROOT / "README.md").read_text()
plan = Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md").read_text()
assert "## 21. P1 nested evidence scanner controls" in index
assert "## 49. P1 nested evidence scanner-control correction" in plan
print("PASS: nested-control oracles, preserved caps and append discoverability")

subprocess.run(["git", "diff", "--check"], check=True)
subprocess.run(["git", "diff", "--cached", "--check"], check=True)
assert not git(
    "diff", "--name-only", BASE, "--", "crates", "Cargo.toml", "Cargo.lock",
    ".cargo", ".github", "Audit"
).strip()
print("PASS: documentation-only paths and whitespace; no test/build execution")
print("NOT ESTABLISHED: cryptographic verification, production ingress or authority")
