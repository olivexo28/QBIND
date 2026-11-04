#!/usr/bin/env python3
"""Verify exact producer, preserved historical bytes, bounded outcomes and scope."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess

ENTRY = "551e7cdd08eb01ce05914c4bba49562d8901b7ec"
PRODUCER = "b4669ab29ad31f82bb574800df4f5f21e8a1afb7"
E = Path("docs/security/evidence/a37-1-c2-handoff-followup")
FIXTURE = "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh"
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
HISTORY = [
    ("docs/security/evidence/a37-1-c2/", "6fdc0f0dcfc45c65037de3e53215121f5332689a"),
    ("docs/security/evidence/a37-1-c2-correction/", "d494ce2af1dd522e8ec0fc14c36b02a19e50b209"),
    ("docs/security/evidence/a37-1-c2-supervisor-followup/", ENTRY),
]


def git(*args):
    return subprocess.check_output(["git", *args])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


assert git("rev-parse", "HEAD").decode().strip() == PRODUCER
result = dict(command=["python3", str(E/"validate.py")], entry=ENTRY,
              entry_tree=git("rev-parse", ENTRY+"^{tree}").decode().strip(),
              producer=PRODUCER, producing_tree=git("rev-parse", PRODUCER+"^{tree}").decode().strip(),
              producing_parents=git("show", "-s", "--format=%P", PRODUCER).decode().split())
assert result["producing_parents"] == [ENTRY]
result["source"] = {}
for path in [FIXTURE, str(E/"creation_cases.py"), str(E/"reproduce.py")]:
    raw = Path(path).read_bytes()
    assert raw == git("show", PRODUCER+":"+path)
    result["source"][path] = dict(blob=git("rev-parse", PRODUCER+":"+path).decode().strip(), sha256=digest(raw))
result["historical"] = {}
for directory, revision in HISTORY:
    files = {}
    for path in git("ls-tree", "-r", "--name-only", revision, directory).decode().splitlines():
        raw = Path(path).read_bytes()
        assert raw == git("show", revision+":"+path), path
        files[path] = digest(raw)
    count = 0
    for line in git("show", revision+":"+directory+"SHA256SUMS").decode().splitlines():
        expected, path = line.split("  ", 1)
        assert digest(git("show", revision+":"+path)) == expected, path
        count += 1
    result["historical"][directory] = dict(revision=revision, files=files, manifest_entries=count)
for path in [
    "scripts/devnet/run_216_governance_execution_policy_release_binary.sh",
    "scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh",
]:
    assert Path(path).read_bytes() == git("show", ENTRY+":"+path)
result["production_scripts_identical"] = True
old, current = git("show", ENTRY+":"+PLAN), Path(PLAN).read_bytes()
assert old.split(b"## 14.", 1)[0] == current.split(b"## 14.", 1)[0]
result["protected_plan_prefix_before_section14_identical"] = True
result["formats"] = {}
for path in (PLAN, FIXTURE):
    old, raw = git("show", ENTRY+":"+path), Path(path).read_bytes()
    assert old.endswith(b"\n") == raw.endswith(b"\n")
    assert (old.count(b"\r\n") == old.count(b"\n")) == (raw.count(b"\r\n") == raw.count(b"\n"))
    assert git("ls-tree", ENTRY, path).split()[0] == git("ls-files", "-s", path).split()[0]
    result["formats"][path] = dict(mode=git("ls-files", "-s", path).split()[0].decode(),
                                   crlf=raw.count(b"\r\n"), lf=raw.count(b"\n"),
                                   final_newline=raw.endswith(b"\n"))
paths = set(git("diff", "--name-only", ENTRY).decode().splitlines())
paths.update(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
assert all(p in (FIXTURE, PLAN) or p.startswith(str(E)+"/") for p in paths)
result["scope"] = sorted(paths)
assert subprocess.run(["bash", "-n"], input=Path(FIXTURE).read_bytes()).returncode == 0
ast.parse(Path(FIXTURE).read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
for path in E.glob("*.py"):
    ast.parse(path.read_text())
assert subprocess.run(["git", "-c", "core.whitespace=cr-at-eol", "diff", "--check", ENTRY]).returncode == 0
result["syntax_whitespace"] = "Bash, embedded/evidence Python and CRLF-aware git diff --check PASS"
meta = json.loads((E/"focused/environment.json").read_text())
cases = json.loads((E/"focused/cases.json").read_text())
neg = [json.loads(line) for line in (E/"focused/supervisor-negative.jsonl").read_text().splitlines()]
assert meta["producing_commit"] == PRODUCER and meta["exit_code"] == 0
assert meta["fixture_sha256"] == digest(Path(FIXTURE).read_bytes())
assert meta["total_harness_invocations"] == 120 and len(cases) == 110 and len(neg) == 10
assert {c["case"] for c in cases} == {
    c["case"] for c in json.loads(Path(HISTORY[2][0]+"focused/cases.json").read_text())}
assert all(c["cleanup_verified"] for c in cases)
assert all(not c["watchdog_rescued_groups"] and c["independent_kernel_absent"]
           and c["independent_children_absent"] and c["worker_status"] == 0 for c in neg)
raw = [json.loads(line) for path in (E/"focused/raw").glob("*.jsonl") for line in path.read_text().splitlines()]
commands = sum(len(c["commands"]) for c in raw)
commands += sum(sum(json.loads(line)["kind"] == "REGRESSION" for line in c["guard_log"].splitlines()) for c in neg)
assert not Path(meta["workspace"]).exists()
result["suite"] = dict(invocations=120, matrix=110, existing_negative_controls=10,
                       guarded_regression_commands=commands, rust_tests=0, outer_rescues=0,
                       producing_fixture_sha256=meta["fixture_sha256"], workspace_removed=True)
rows = json.loads((E/"creation/results.json").read_text())
assert len(rows) == 12 and sum(c["cleanup_pass"] for c in rows) == 10
for c in rows:
    assert c["producing_commit"] == PRODUCER and c["fixture_sha256"] == meta["fixture_sha256"]
    assert c["outer_status"] == 0 and c["mask_restored"] and c["child_inherited_original_mask"]
    if c["mode"] == "unresolved":
        assert c["outer_rescues"] and not c["cleanup_pass"] and c["unsafe"] and c["workspace_retained"]
        assert c["notes"] and "KeyboardInterrupt" in c["error"]
    else:
        assert not c["outer_rescues"] and c["child_reaped"] and not c["workspace_retained"]
        assert all(r["kernel_absent_before_delete"] for r in c["deletion_observations"])
        expected = {"init_exception": "RuntimeError", "handoff_interrupt": "KeyboardInterrupt",
                    "creation_INT": "InterruptedError", "creation_TERM": "InterruptedError", "child_mask": "ValueError"}
        assert expected[c["mode"]] in c["error"]
    assert not Path(c["workspace"]).exists()
result["creation"] = dict(inert_cases=12, cleanup_passes=10, deliberately_failed_cleanup=2,
                          outer_rescues=2, rescued_cases_not_passes=True,
                          quiescent_deletion_observations=sum(len(c["deletion_observations"]) for c in rows),
                          masks_restored=True)
masked = json.loads((E/"masked-creation-completed/results.json").read_text())
assert len(masked) == 12 and sum(c["cleanup_pass"] for c in masked) == 10
for c in masked:
    assert c["producing_commit"] == PRODUCER and c["fixture_sha256"] == meta["fixture_sha256"]
    assert c["mask_restored"] and c["child_inherited_original_mask"] and c["outer_status"] == 0
    mask = json.loads((E/"masked-creation-completed"/(c["route"]+"-"+c["mode"])/"child-mask").read_text())
    assert 10 in mask, mask  # Linux SIGUSR1; nonempty inherited-mask control.
    if c["mode"] == "unresolved":
        assert c["outer_rescues"] and not c["cleanup_pass"] and c["workspace_retained"]
    else:
        assert not c["outer_rescues"] and c["child_reaped"] and c["deletion_observations"]
    assert not Path(c["workspace"]).exists()
result["nonempty_mask_creation"] = dict(cases=12, cleanup_passes=10, deliberately_failed_cleanup=2,
                                       outer_rescues=2, signal_usr1_remained_blocked=True)
result["baseline"] = json.loads((E/"baseline/reproduction.json").read_text())
assert result["baseline"]["outer_rescue_required"]
(E/"validation.json").write_text(json.dumps(result, indent=2)+"\n")
print("PASS: exact producer; 120 harness controls; 24 completed inert creation cases; three historical directories/manifests; scope, formats, syntax")
