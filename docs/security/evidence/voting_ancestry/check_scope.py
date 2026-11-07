"""Check pinned producers, historical byte preservation and targeted formatting."""

import hashlib
import json
import pathlib
import re
import subprocess
import tempfile


BASE = "644a3c69dce095458c6e9e2208c200b29fc9fe0f"
BASELINE = "e4876fc2bef1217035d484568cd791fca1f88d69"
PRODUCER = "e57a337fd5afc5f1bd2f49ea43a50c0a866c86aa"
SOURCE = "crates/qbind-consensus/src/hotstuff_state_engine.rs"
TEST = "crates/qbind-consensus/tests/a33_f1_voting_ancestry_tests.rs"
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
PACKAGE = "docs/security/evidence/voting_ancestry/"


def git(*args):
    return subprocess.check_output(["git", *args])


def main():
    assert git("rev-parse", BASE + "^{tree}").strip() == (
        b"c708a1dfb7362b8dcc8165970b7519b0a9194146"
    )
    assert git("show", BASE + ":" + SOURCE) == git("show", BASELINE + ":" + SOURCE)
    assert git("show", BASELINE + ":" + TEST) == git("show", PRODUCER + ":" + TEST)
    for path in [SOURCE, TEST]:
        contents = pathlib.Path(path).read_bytes()
        assert contents == git("show", PRODUCER + ":" + path), path
        print("PRODUCER", git("ls-tree", PRODUCER, path).decode().strip())
        print("SHA256", hashlib.sha256(contents).hexdigest(), path)
    preserved = 0
    for line in git("ls-tree", "-r", BASE).decode().splitlines():
        metadata, path = line.split("\t", 1)
        mode, kind, blob = metadata.split()
        assert kind == "blob", (path, kind)
        current = pathlib.Path(path)
        assert current.exists(), path
        actual_mode = "100755" if current.stat().st_mode & 0o111 else "100644"
        assert mode == actual_mode, (path, mode, actual_mode)
        original = git("cat-file", "blob", blob)
        if path == SOURCE:
            continue
        if path == PLAN:
            assert current.read_bytes().startswith(original), "Historical plan prefix changed"
            print("PLAN PREFIX", len(original), hashlib.sha256(original).hexdigest())
        else:
            assert current.read_bytes() == original, path
            preserved += 1
    print("Unchanged baseline paths:", preserved)
    changed = git("diff", "--name-only", BASE).decode().splitlines()
    for path in changed:
        assert path in [SOURCE, TEST, PLAN] or path.startswith(PACKAGE), path
    for line in git("ls-files", "--others", "--exclude-standard").decode().splitlines():
        assert line.startswith(PACKAGE), line
    subprocess.run(["rustfmt", "--edition", "2021", "--check", TEST], check=True)
    text = pathlib.Path(SOURCE).read_text()
    start = text.index("    pub fn safety_decision(")
    end = text.index("    /// RUN 422", start)
    fragment = "impl Demo {\n" + text[start:end].rstrip() + "\n}\n"
    with tempfile.TemporaryDirectory(prefix="qbind-voting-format-") as directory:
        path = pathlib.Path(directory) / "safety_decision.rs"
        path.write_text(fragment)
        subprocess.run(["rustfmt", "--edition", "2021", "--check", str(path)], check=True)
    print("PASS: whole new test and complete changed production method formatting")
    subprocess.run(
        [
            "git", "-c", "core.whitespace=cr-at-eol", "diff", "--check", BASE, "--",
            SOURCE, TEST, PLAN, PACKAGE, ":(exclude)*.log",
        ],
        check=True,
    )
    print("PASS: targeted source/prose/script/JSON whitespace (raw logs excluded)")
    package = pathlib.Path(PACKAGE)
    for name in [
        "focused-tests", "consensus-regressions", "production-compile-attempt-2",
        "preserved-a33-manifest",
    ]:
        record = json.loads((package / (name + ".json")).read_text())
        assert record["exit_code"] == 0, name
        assert record["head"] == PRODUCER, name
    for name, expected in [("focused-tests", 9), ("consensus-regressions", 485)]:
        rows = re.findall(
            r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
            (package / (name + ".log")).read_text(),
        )
        assert sum(int(row[0]) for row in rows) == expected, name
        assert all(row[1:] == ("0", "0") for row in rows), name
        print("TEST PASSES", name, expected)
    baseline = json.loads((package / "baseline/results.json").read_text())
    fixed = json.loads((package / "fixed/results.json").read_text())
    assert baseline["producer"] == BASELINE
    assert fixed["producer"] == PRODUCER
    assert baseline["binary_sha256"] != fixed["binary_sha256"]
    assert len(baseline["cases"]) == len(fixed["cases"]) == 5
    assert [row["case"] for row in baseline["cases"]] == [
        row["case"] for row in fixed["cases"]
    ]
    for row in baseline["cases"]:
        assert row["observation"] == "TIMEOUT" and row["returncode"] == -9
        assert row["child_reaped"]
    for row in fixed["cases"]:
        assert row["observation"] == "RETURNED" and row["returncode"] == 0
        assert row["child_reaped"]
        assert b"1 passed; 0 failed" in (
            package / "fixed" / (row["case"] + ".log")
        ).read_bytes()
    print("PASS: five baseline timeout observations; five fixed returned tests; all reaped")


if __name__ == "__main__":
    main()
