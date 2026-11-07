#!/usr/bin/env python3
"""Check exact reviewed blobs, bounded scope and immutable evidence links."""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

BASE = "3926fd4d9e7c1ec68c4b22610e154f9e90460f1c"
REVIEWED = "748ee3ab2a4c88ffa0bfe8152eebd1c695f49c95"
SOURCE_TREE = "38d547f401e91a1c0753c002df7e01fcd3e0a997"
EVIDENCE = "docs/security/evidence/reset_integration/"
HISTORICAL = "docs/security/evidence/a33_f1/"
SOURCES = [
    "crates/qbind-node/src/main.rs",
    "crates/qbind-node/src/pqc_authority_state_reset.rs",
]
TESTS = [
    "crates/qbind-node/src/pqc_authority_state_reset_error_tests.rs",
    "crates/qbind-node/tests/a33_f1_authority_reset_audit_collision_tests.rs",
    "crates/qbind-node/tests/a33_f1_authority_reset_destination_lock_tests.rs",
    "crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs",
    "crates/qbind-node/tests/a33_f1_reset_marker_temp_identity_tests.rs",
    "crates/qbind-node/tests/support/authority_reset_cli.rs",
]
PUBLICATIONS = [
    ("authority-reset-collision-", "e8f58a5c391f282c1996f4306c02743ace056fa5"),
    ("authority-reset-correction-", "6506faf18485769a2c852b7609149f908b807848"),
    ("authority-reset-errors-", "11bb930e005abd082a1dbb296f0b8fe90dcf4fc0"),
    ("authority-reset-verified-", "f30cae3f502020101edf5e447bdf26aea9c9f0e1"),
    ("authority-reset-ownership-", "bc33bca493c154dac47c797c518b77290da61566"),
    ("i1-marker-temp-", REVIEWED),
]


def git(*args):
    return subprocess.check_output(["git", *args])


def reconstruct_source_tree():
    # The pre-evidence tree is not a commit ancestor; reconstruct it in a clone.
    with tempfile.TemporaryDirectory(prefix="reset-source-index-") as directory:
        environment = dict(os.environ, GIT_INDEX_FILE=directory + "/index")
        subprocess.run(["git", "read-tree", BASE], env=environment, check=True)
        for path in SOURCES + TESTS:
            mode, _, blob, _ = git("ls-tree", REVIEWED, "--", path).decode().split()
            subprocess.run(
                ["git", "update-index", "--add", "--cacheinfo", mode, blob, path],
                env=environment, check=True,
            )
        tree = subprocess.check_output(["git", "write-tree"], env=environment).decode().strip()
        assert tree == SOURCE_TREE, tree
        print("reconstructed tested source-only tree:", tree)


def historical_index():
    rows = ["publishing_revision\tpath\tsha256\timmutable_url"]
    for prefix, revision in PUBLICATIONS:
        manifest = git("show", f"{revision}:{HISTORICAL}SHA256SUMS").decode()
        expected = {}
        for line in manifest.splitlines():
            if line and not line.startswith("#"):
                digest, name = line.split(maxsplit=1)
                expected.setdefault(name.strip(), []).append(digest)
        paths = git("ls-tree", "-r", "--name-only", revision, HISTORICAL).decode()
        for path in paths.splitlines():
            if not path.startswith(HISTORICAL + prefix):
                continue
            digest = hashlib.sha256(git("show", f"{revision}:{path}")).hexdigest()
            assert digest in expected[path.removeprefix(HISTORICAL)], path
            url = f"https://github.com/olivexo28/QBIND/blob/{revision}/{path}"
            rows.append("\t".join([revision, path, digest, url]))
    print("selected historical complete-file checksums PASS:", len(rows) - 1)
    return "\n".join(rows) + "\n"


def check_results():
    expected_counts = {
        "focused-attempt-2": [6, 5, 1, 1],
        "reset-unit": [22],
        "existing-lock-regression": [1],
        "production-compile": [],
    }
    for label, counts in expected_counts.items():
        record = json.loads(Path(EVIDENCE + label + ".json").read_text())
        assert record["exit_code"] == 0, label
        output = Path(EVIDENCE + label + ".log").read_text()
        actual = re.findall(
            r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", output
        )
        assert [int(count) for count in actual] == counts, (label, actual)
        print("new candidate result PASS:", label, counts, "exit=0")
    output = Path(EVIDENCE + "focused-attempt-2.log").read_text()
    assert "CORRECTED: UnsafeAuditPath" in output
    assert "BASELINE ONLY:" not in output
    attempt = json.loads(Path(EVIDENCE + "focused-attempt-1.json").read_text())
    assert attempt["exit_code"] == 101
    print("unsuccessful missing-libclang build attempt retained: exit=101; not a test pass")


def seal():
    paths = git("diff", "--name-only", BASE).decode().splitlines()
    paths += git("ls-files", "--others", "--exclude-standard").decode().splitlines()
    paths += [EVIDENCE + name for name in (
        "changed-paths.txt", "SHA256SUMS", "seal-check.json", "seal-check.log",
    )]
    paths = sorted(set(paths))
    inventory = Path(EVIDENCE + "changed-paths.txt")
    manifest = Path(EVIDENCE + "SHA256SUMS")
    assert not inventory.exists() and not manifest.exists(), "do not overwrite a seal"
    inventory.write_text("\n".join(paths) + "\n", encoding="utf-8")
    excluded = {str(manifest), EVIDENCE + "seal-check.json", EVIDENCE + "seal-check.log"}
    rows = [
        hashlib.sha256(Path(path).read_bytes()).hexdigest() + "  " + path
        for path in paths if path not in excluded
    ]
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("sealed full inventory:", len(paths), "paths; checksum entries:", len(rows))


def verify_seal():
    inventory = Path(EVIDENCE + "changed-paths.txt").read_text().splitlines()
    paths = git("diff", "--name-only", BASE).decode().splitlines()
    paths += git("ls-files", "--others", "--exclude-standard").decode().splitlines()
    # The receipt JSON is written by the runner only after this check returns.
    paths += [EVIDENCE + "seal-check.json", EVIDENCE + "seal-check.log"]
    assert sorted(set(paths)) == inventory
    rows = Path(EVIDENCE + "SHA256SUMS").read_text().splitlines()
    excluded = {EVIDENCE + name for name in (
        "SHA256SUMS", "seal-check.json", "seal-check.log",
    )}
    assert {line.split(maxsplit=1)[1] for line in rows} == set(inventory) - excluded
    for line in rows:
        digest, path = line.split(maxsplit=1)
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest, path
    print("candidate current-file checksum PASS:", len(rows),
          "; full changed-path inventory PASS:", len(inventory))
    print("manifest self-hash and checksum receipt excluded to avoid circular hashes")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-index", action="store_true")
    parser.add_argument("--seal", action="store_true")
    parser.add_argument("--verify-seal", action="store_true")
    args = parser.parse_args()
    index = historical_index()
    index_path = Path(EVIDENCE + "historical-index.tsv")
    if args.write_index:
        assert not index_path.exists(), "do not overwrite prior evidence"
        index_path.write_text(index, encoding="utf-8")
    else:
        assert index_path.read_text(encoding="utf-8") == index
    reconstruct_source_tree()
    check_results()
    assert git("rev-parse", f"{BASE}^{{tree}}").decode().strip() == (
        "1a846b01962f7ea016ec971f8a11b71ce91a30c9"
    )
    for path in SOURCES + TESTS:
        current = Path(path).read_bytes()
        assert current == git("show", f"{REVIEWED}:{path}"), path
        assert current == git("show", f"{SOURCE_TREE}:{path}"), path
        print("reviewed/tested blob IDENTICAL:", git("hash-object", path).decode().strip(),
              hashlib.sha256(current).hexdigest(), path)
    source_changes = git("diff-tree", "--no-commit-id", "--name-only", "-r",
                         BASE, SOURCE_TREE).decode().splitlines()
    assert set(source_changes) == set(SOURCES + TESTS)
    changed = git("diff", "--name-only", BASE).decode().splitlines()
    untracked = git("ls-files", "--others", "--exclude-standard").decode().splitlines()
    for path in sorted(set(changed + untracked)):
        if path not in SOURCES + TESTS:
            assert path.startswith(EVIDENCE), path
            assert not git("ls-tree", BASE, "--", path), path
        print("candidate path:", path)
    protected = git("ls-tree", "-r", "--name-only", BASE, HISTORICAL).decode().splitlines()
    protected += ["docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"]
    for path in protected:
        assert Path(path).read_bytes() == git("show", f"{BASE}:{path}"), path
    manifest = Path(HISTORICAL + "SHA256SUMS").read_text().splitlines()
    assert len(manifest) == 19
    for line in manifest:
        digest, name = line.split(maxsplit=1)
        data = Path(HISTORICAL + name.strip()).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, name
    print("original 19 entries PASS; all 20 historical evidence files and plan byte-identical")
    for path in TESTS:
        subprocess.run(["rustfmt", "--edition", "2021", "--check", path], check=True)
    print("complete selected test/helper formatting PASS")
    for path in SOURCES:
        original = git("show", f"{BASE}:{path}").decode().splitlines()
        current = Path(path).read_text().splitlines()
        formatted = subprocess.check_output([
            "rustfmt", "--edition", "2021", "--config", "skip_children=true",
            "--emit", "stdout", path,
        ]).decode().splitlines()
        if formatted and formatted[0].endswith(path + ":"):
            formatted = formatted[2:]
        changed_lines = set()
        for tag, _, _, start, end in difflib.SequenceMatcher(
                None, original, current, autojunk=False).get_opcodes():
            if tag != "equal":
                changed_lines.update(range(start, end))
        for tag, start, end, _, _ in difflib.SequenceMatcher(
                None, current, formatted, autojunk=False).get_opcodes():
            if tag != "equal":
                assert not changed_lines.intersection(range(start, max(end, start + 1))), (
                    path, start + 1, end, "changed-line formatting difference"
                )
        print("changed production-line formatting PASS (legacy differences excluded):", path)
    print("scope PASS; every other tracked path remains at protected main")
    if args.seal:
        seal()
    if args.verify_seal:
        verify_seal()


if __name__ == "__main__":
    main()
