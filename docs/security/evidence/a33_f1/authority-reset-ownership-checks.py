#!/usr/bin/env python3
"""Bounded scope, append-only evidence and changed-line formatting checks."""
import difflib
import hashlib
import pathlib
import subprocess

BASE = "f30cae3f502020101edf5e447bdf26aea9c9f0e1"
MAIN = "c9aaef40b045e896ddfa8b01bad230f6b680715e"
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
EVIDENCE = "docs/security/evidence/a33_f1/"
MANIFEST = EVIDENCE + "SHA256SUMS"
SOURCES = [
    "crates/qbind-node/src/main.rs",
    "crates/qbind-node/src/pqc_authority_state_reset.rs",
]
TESTS = [
    "crates/qbind-node/tests/a33_f1_authority_reset_destination_lock_tests.rs",
    "crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs",
    "crates/qbind-node/tests/support/authority_reset_cli.rs",
]


def git(*args):
    return subprocess.check_output(["git", *args])


assert git("branch", "--show-current").decode().strip() == "copilot/a33-f1-bounded-eviction"
assert git("rev-parse", "refs/heads/main").decode().strip() == MAIN
assert git("merge-base", "--is-ancestor", BASE, "HEAD") == b""
for path in [PLAN, MANIFEST]:
    previous = git("show", f"{BASE}:{path}")
    assert pathlib.Path(path).read_bytes().startswith(previous), path
    print("append-only:", path)

tracked = git("diff", "--name-only", BASE).decode().splitlines()
untracked = git("ls-files", "--others", "--exclude-standard").decode().splitlines()
allowed = set(SOURCES + TESTS + [PLAN, MANIFEST])
for path in sorted(set(tracked + untracked)):
    if path not in allowed:
        assert path.startswith(EVIDENCE + "authority-reset-ownership-"), path
        assert git("ls-tree", BASE, "--", path) == b"", "historical evidence changed: " + path
    print("changed:", path)

manifest_bytes = git("show", f"{BASE}:{MANIFEST}")
for line in manifest_bytes.decode().splitlines():
    if not line.strip() or line.startswith("#"):
        continue
    digest, filename = line.split(maxsplit=1)
    assert hashlib.sha256(pathlib.Path(EVIDENCE + filename.strip()).read_bytes()).hexdigest() == digest
print("all historical evidence checksums verified; audit register outside permitted scope")

for path in TESTS:
    subprocess.run(["rustfmt", "--edition", "2021", "--check", path], check=True)
print("rustfmt: all changed/new test files passed")

for path in SOURCES:
    original = git("show", f"{BASE}:{path}").decode().splitlines()
    current = pathlib.Path(path).read_text().splitlines()
    output = subprocess.check_output([
        "rustfmt", "--edition", "2021", "--config", "skip_children=true",
        "--emit", "stdout", path,
    ]).decode().splitlines()
    if output and output[0].endswith(path + ":"):
        output = output[2:]
    changed = set()
    for tag, _, _, start, end in difflib.SequenceMatcher(
        None, original, current, autojunk=False
    ).get_opcodes():
        if tag != "equal":
            changed.update(range(start, end))
    for tag, start, end, _, _ in difflib.SequenceMatcher(
        None, current, output, autojunk=False
    ).get_opcodes():
        if tag != "equal":
            assert not changed.intersection(range(start, max(end, start + 1))), (
                path, start + 1, end, "new-line formatting difference"
            )
    print("rustfmt changed-line check passed (legacy differences excluded):", path)
    print("baseline sha256:", hashlib.sha256(git("show", f"{BASE}:{path}")).hexdigest(), path)
    print("corrected sha256:", hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest(), path)

subprocess.run([
    "git", "-c", "core.whitespace=cr-at-eol,-blank-at-eof",
    "diff", "--check", BASE, "--", ".",
    ":(exclude)docs/security/evidence/a33_f1/authority-reset-ownership-*.log",
], check=True)
print("code/docs whitespace passed; raw task logs excluded to preserve formatter diff context/Cargo EOF blanks")
