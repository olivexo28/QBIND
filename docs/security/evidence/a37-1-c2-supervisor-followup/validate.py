#!/usr/bin/env python3
"""Verify follow-up producing identities, outcomes and strict preservation."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ENTRY = "d494ce2af1dd522e8ec0fc14c36b02a19e50b209"
PRODUCER = "e02047003a3ac5d099a12268dda5fb210ef69902"
E = Path("docs/security/evidence/a37-1-c2-supervisor-followup")
FIXTURE = "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh"
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
HISTORY = [
    ("docs/security/evidence/a37-1-c2/", "6fdc0f0dcfc45c65037de3e53215121f5332689a"),
    ("docs/security/evidence/a37-1-c2-correction/", ENTRY),
]


def git(*args):
    return subprocess.check_output(["git", *args])


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


result = dict(command=["python3", str(E/"validate.py")], entry=ENTRY,
              entry_tree=git("rev-parse", ENTRY+"^{tree}").decode().strip(),
              producing_commit=PRODUCER, producing_tree=git("rev-parse", PRODUCER+"^{tree}").decode().strip(),
              producing_parents=git("show", "-s", "--format=%P", PRODUCER).decode().split())
assert result["entry_tree"] == "8449e9aa7683f68c113a1fb00b1491a0e6e75d5b"
assert result["producing_parents"] == [ENTRY]
assert git("rev-parse", "HEAD").decode().strip() == PRODUCER
result["producing_files"] = {}
for path in [FIXTURE, str(E/"watchdog_cases.py"), str(E/"reproduce.py")]:
    raw = Path(path).read_bytes()
    assert raw == git("show", PRODUCER+":"+path)
    result["producing_files"][path] = dict(blob=git("rev-parse", PRODUCER+":"+path).decode().strip(),
                                          sha256=sha(raw))
result["historical_files"] = {}
result["historical_manifest_verification"] = {}
for directory, revision in HISTORY:
    for path in git("ls-tree", "-r", "--name-only", revision, directory).decode().splitlines():
        assert Path(path).read_bytes() == git("show", revision+":"+path), path
        result["historical_files"][path] = dict(revision=revision, sha256=sha(Path(path).read_bytes()))
    entries = []
    for line in git("show", revision+":"+directory+"SHA256SUMS").decode().splitlines():
        expected, path = line.split("  ", 1)
        assert sha(git("show", revision+":"+path)) == expected, path
        entries.append(path)
    result["historical_manifest_verification"][directory] = dict(revision=revision, entries=len(entries))
assert sha(Path(HISTORY[1][0]+"SHA256SUMS").read_bytes()) == (
    "70caf4651a3bd4266996334158f3c404728f54d19dadb6da5dd6343635f5490e")
for path in [
    "scripts/devnet/run_216_governance_execution_policy_release_binary.sh",
    "scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh",
]:
    assert Path(path).read_bytes() == git("show", ENTRY+":"+path)
result["production_scripts_unchanged"] = True
old, current = git("show", ENTRY+":"+PLAN), Path(PLAN).read_bytes()
assert old.split(b"## 14.", 1)[0] == current.split(b"## 14.", 1)[0]
result["plan_prefix_before_section_14_identical"] = True
paths = set(git("diff", "--name-only", ENTRY).decode().splitlines())
paths.update(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
for path in paths:
    assert path in (FIXTURE, PLAN) or path.startswith(str(E)+"/"), path
result["changed_paths"] = sorted(paths)
result["formats"] = {}
for path in (FIXTURE, PLAN):
    old, raw = git("show", ENTRY+":"+path), Path(path).read_bytes()
    assert raw.endswith(b"\n") == old.endswith(b"\n")
    assert (raw.count(b"\r\n") == raw.count(b"\n")) == (old.count(b"\r\n") == old.count(b"\n"))
    assert git("ls-tree", ENTRY, path).split()[0] == git("ls-files", "-s", path).split()[0]
    result["formats"][path] = dict(mode=git("ls-files", "-s", path).split()[0].decode(),
                                   crlf=raw.count(b"\r\n"), lf=raw.count(b"\n"),
                                   final_newline=raw.endswith(b"\n"))
syntax = subprocess.run(["bash", "-n"], input=Path(FIXTURE).read_bytes(), capture_output=True)
assert syntax.returncode == 0
ast.parse(Path(FIXTURE).read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
for path in E.glob("*.py"):
    ast.parse(path.read_text())
result["syntax"] = dict(bash=0, embedded_python="PASS", evidence_python="PASS")
whitespace = subprocess.run(["git", "-c", "core.whitespace=cr-at-eol", "diff", "--check", ENTRY],
                            capture_output=True, text=True)
assert whitespace.returncode == 0, whitespace.stdout+whitespace.stderr
result["whitespace"] = dict(command=whitespace.args, returncode=whitespace.returncode)

meta = json.loads((E/"focused/environment.json").read_text())
cases = json.loads((E/"focused/cases.json").read_text())
neg = [json.loads(line) for line in (E/"focused/supervisor-negative.jsonl").read_text().splitlines()]
ownership = [json.loads(line) for line in (E/"focused/watchdog-ownership.jsonl").read_text().splitlines()]
assert meta["producing_commit"] == PRODUCER and meta["exit_code"] == 0
assert meta["total_harness_invocations"] == 120 and len(cases) == 110 and len(neg) == len(ownership) == 10
historical = json.loads(Path(HISTORY[1][0]+"focused/cases.json").read_text())
assert {c["case"] for c in cases} == {c["case"] for c in historical}
for row in neg:
    assert not row["watchdog_rescued_groups"] and row["worker_status"] == 0
    assert row["independent_kernel_absent"] and row["independent_children_absent"]
for row in ownership:
    assert not row["cleanup_failures"] and row["owned_descriptors_closed"]
    assert row["cleanup"]["worker_reaped"] and row["cleanup"]["kernel_groups_absent"]
assert all(c["cleanup_verified"] for c in cases)
raw = [json.loads(line) for p in (E/"focused/raw").glob("*.jsonl") for line in p.read_text().splitlines()]
commands = sum(len(c["commands"]) for c in raw)
commands += sum(sum(json.loads(line)["kind"] == "REGRESSION" for line in c["guard_log"].splitlines()) for c in neg)
result["focused"] = dict(harness_invocations=120, matrix=110, supervisor_controls=10,
                         guarded_regression_commands=commands, rust_tests=0, rescues=0,
                         historical_case_ids_equal=True, producing_fixture_sha256=meta["fixture_sha256"])
assert meta["fixture_sha256"] == sha(Path(FIXTURE).read_bytes())
result["parent_faults"] = {}
for folder in ("parent-cases", "deletion-boundary"):
    rows = json.loads((E/folder/"results.json").read_text())
    assert len(rows) == 10
    assert sum(c["cleanup_pass"] for c in rows) == 9
    for row in rows:
        assert row["outer_status"] == 0 and row["descriptors_closed"]
        if row["mode"] == "unresolved_cleanup":
            assert row["outer_rescued_groups"] and not row["cleanup_pass"] and row["workspace_exists"]
            assert row["unsafe_groups"] and row["notes"]
        else:
            assert not row["outer_rescued_groups"] and row["worker_reaped"] and not row["workspace_exists"]
        assert not Path(row["workspace"]).exists(), row["workspace"]
    result["parent_faults"][folder] = dict(cases=10, cleanup_passes=9,
                                         deliberate_unresolved_cleanup_failures=1,
                                         outer_rescue_only_for_deliberate_failure=True)
deletions = [json.loads(line) for line in (E/"deletion-boundary-deletion.jsonl").read_text().splitlines()]
assert len(deletions) == 10 and all(c["kernel_absent_before_rmtree"] for c in deletions)
result["independently_observed_quiescent_deletions"] = len(deletions)
refusal = json.loads((E/"unsafe-refusal/results.json").read_text())
assert refusal["producing_commit"] == PRODUCER
assert refusal["fixture_sha256"] == sha(Path(FIXTURE).read_bytes())
assert not refusal["launch_attempts"] and len(refusal["outcomes"]) == 2
result["unsafe_launch_refusal"] = refusal
result["baseline"] = json.loads((E/"baseline/reproduction.json").read_text())
assert result["baseline"]["workspace_deleted_while_owned_processes_alive"]
assert result["baseline"]["independent_outer_cleanup"]
result["links"] = []
for path in [Path(PLAN), E/"README.md"]:
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", path.read_text()):
        if "://" in target or target.startswith("#"):
            continue
        assert (path.parent/target.split("#", 1)[0]).exists(), (str(path), target)
        result["links"].append(dict(source=str(path), target=target, exists=True))
(E/"validation.json").write_text(json.dumps(result, indent=2)+"\n")
print("PASS: producing identities, 120 suite controls, 20 inert parent cases, deletion boundaries, historical bytes/checksums, scope, formats and syntax")
