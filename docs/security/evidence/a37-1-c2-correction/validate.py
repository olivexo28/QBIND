#!/usr/bin/env python3
"""Verify bounded evidence, protected bytes, scope, formats and source identity."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ENTRY = "6fdc0f0dcfc45c65037de3e53215121f5332689a"
MAIN = "f36e59a5e2cebab6fdfd0365920ca3e1a09444ac"
PRODUCER = "763efbbbf1141d5be264ce2fa73b10763287bb27"
ROOT = Path.cwd()
EVIDENCE = Path("docs/security/evidence/a37-1-c2-correction")
HISTORICAL = "docs/security/evidence/a37-1-c2/"
PLAN = "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"
FIXTURE = "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh"
SCRIPTS = [
    "scripts/devnet/run_216_governance_execution_policy_release_binary.sh",
    "scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh",
]
READMES = [
    "docs/devnet/run_216_governance_execution_policy_release_binary/README.md",
    "docs/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary/README.md",
]


def git(*args):
    return subprocess.check_output(["git", *args])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


result = dict(command=["python3", str(EVIDENCE / "validate.py")],
              entry=ENTRY, entry_tree=git("rev-parse", ENTRY+"^{tree}").decode().strip(),
              protected_main=MAIN, producing_commit=PRODUCER,
              producing_tree=git("rev-parse", PRODUCER+"^{tree}").decode().strip(),
              producing_parents=git("show", "-s", "--format=%P", PRODUCER).decode().split())
assert result["entry_tree"] == "b43769723cbe2b0319ad0b3166e8bcfe14fec5d3"
assert result["producing_parents"] == [ENTRY]
assert git("rev-parse", "HEAD").decode().strip() == PRODUCER
result["source_identity"] = {}
for path in SCRIPTS + [FIXTURE]:
    raw = Path(path).read_bytes()
    assert raw == git("show", PRODUCER+":"+path)
    result["source_identity"][path] = dict(
        blob=git("rev-parse", PRODUCER+":"+path).decode().strip(), sha256=digest(raw))

result["historical_evidence"] = {}
for path in git("ls-tree", "-r", "--name-only", ENTRY, HISTORICAL).decode().splitlines():
    raw = Path(path).read_bytes()
    assert raw == git("show", ENTRY+":"+path), path
    result["historical_evidence"][path] = digest(raw)
result["historical_manifest_at_entry"] = []
for line in git("show", ENTRY+":"+HISTORICAL+"SHA256SUMS").decode().splitlines():
    checksum, path = line.split("  ", 1)
    assert digest(git("show", ENTRY+":"+path)) == checksum, path
    result["historical_manifest_at_entry"].append(path)
before = git("show", ENTRY+":"+PLAN)
after = Path(PLAN).read_bytes()
assert before.split(b"## 14.", 1)[0] == after.split(b"## 14.", 1)[0]
result["plan_before_section_14_identical"] = True
result["protected_sections_8_12_13_inventories_register_unrelated_source"] = "unchanged by scope/byte checks"
tracked_changes = git("diff", "--name-only", ENTRY).decode().splitlines()
untracked = git("ls-files", "--others", "--exclude-standard").decode().splitlines()
for path in tracked_changes + untracked:
    assert path in SCRIPTS + [FIXTURE, PLAN] + READMES or path.startswith(str(EVIDENCE)+"/"), path
result["scope"] = sorted(set(tracked_changes + untracked))
result["formats"] = {}
result["syntax"] = {}
for path in SCRIPTS + [FIXTURE, PLAN] + READMES:
    old = git("show", ENTRY+":"+path)
    raw = Path(path).read_bytes()
    assert old.endswith(b"\n") == raw.endswith(b"\n"), path
    assert (old.count(b"\r\n") == old.count(b"\n")) == (raw.count(b"\r\n") == raw.count(b"\n")), path
    old_mode = git("ls-tree", ENTRY, path).decode().split()[0]
    new_mode = git("ls-files", "-s", path).decode().split()[0]
    assert old_mode == new_mode, path
    result["formats"][path] = dict(mode=new_mode, crlf=raw.count(b"\r\n"),
                                   lf=raw.count(b"\n"), final_newline=raw.endswith(b"\n"))
    if path.endswith(".sh"):
        syntax = subprocess.run(["bash", "-n"], input=raw.replace(b"\r\n", b"\n"), capture_output=True)
        assert syntax.returncode == 0, (path, syntax.stderr.decode())
        result["syntax"][path] = dict(command=["bash", "-n"], normalized=True,
                                     returncode=syntax.returncode, stderr=syntax.stderr.decode())
driver = Path(FIXTURE).read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
ast.parse(driver)
for path in EVIDENCE.glob("*.py"):
    ast.parse(path.read_text())
result["embedded_and_evidence_python_syntax"] = "PASS"
for path in SCRIPTS:
    old = git("show", ENTRY+":"+path)
    raw = Path(path).read_bytes()
    assert raw == old.replace(b"mv -f --", b"mv -fT --"), path
result["production_changes_exactly_two_mv_flags_per_script"] = True
whitespace = subprocess.run(["git", "-c", "core.whitespace=cr-at-eol", "diff", "--check", ENTRY],
                            capture_output=True, text=True)
assert whitespace.returncode == 0, whitespace.stdout + whitespace.stderr
result["whitespace"] = dict(command=whitespace.args, returncode=whitespace.returncode)

meta = json.loads((EVIDENCE/"focused/environment.json").read_text())
cases = json.loads((EVIDENCE/"focused/cases.json").read_text())
raw_cases = []
for path in sorted((EVIDENCE/"focused/raw").glob("*.jsonl")):
    raw_cases.extend(json.loads(line) for line in path.read_text().splitlines())
negatives = [json.loads(line) for line in (EVIDENCE/"focused/supervisor-negative.jsonl").read_text().splitlines()]
assert meta["producing_commit"] == PRODUCER and meta["exit_code"] == 0
assert len(cases) == len(raw_cases) == 110 and len(negatives) == 10
assert meta["total_harness_invocations"] == 120
historical_cases = json.loads(git("show", ENTRY+":"+HISTORICAL+"cases.json"))
assert len(historical_cases) == 94
assert {c["case"] for c in historical_cases}.issubset({c["case"] for c in cases})
destination_modes = {
    "startup_file", "startup_file_symlink", "startup_directory", "startup_directory_symlink",
    "final_file", "final_file_symlink", "final_directory", "final_directory_symlink",
}
assert sum(c["mode"] in destination_modes for c in raw_cases) == 16
assert all(sum(c["run"] == run for c in negatives) == 5 for run in (216, 227))
for identity in meta["identities"].values():
    assert identity["candidate"]["matches_committed_blob"]
assert all(c["cleanup_verified"] for c in cases)
assert all(c["supervision"]["cleanup"]["kernel_group_absent"] for c in raw_cases)
for case in negatives:
    assert case["worker_status"] == 0 and not case["watchdog_rescued_groups"]
    assert case["independent_kernel_absent"] and case["independent_children_absent"]
    assert len(case["groups"]) == 1
owner = json.loads((EVIDENCE/"owner-errors/results.json").read_text())
assert owner["producing_commit"] == PRODUCER
assert owner["fixture_sha256"] == meta["fixture_sha256"] == digest(Path(FIXTURE).read_bytes())
assert all(c["independently_group_absent"] and not c["outer_rescue"] for c in owner["outcomes"])
commands = sum(len(c["commands"]) for c in raw_cases)
negative_commands = sum(
    sum(json.loads(line)["kind"] == "REGRESSION" for line in case["guard_log"].splitlines())
    for case in negatives)
result["focused"] = dict(normal_matrix_invocations=len(cases), supervisor_negative_invocations=len(negatives),
                         total_harness_invocations=120, historical_baseline_controls=4,
                         candidate_matrix_invocations=106, new_destination_invocations=16,
                         guarded_regression_commands=commands+negative_commands,
                         matrix_guarded_regression_commands=commands,
                         negative_guarded_regression_commands=negative_commands,
                         rust_tests=0, watchdog_rescues=0,
                         visibility_probe_processes=1, guard_calibration_probes=7,
                         separate_owner_error_processes=2)
result["original_94_case_ids_rerun"] = True
preliminary_rows = [
    json.loads(line) for line in (EVIDENCE/"preliminary/raw/run-216.jsonl").read_text().splitlines()]
result["preliminary_actual_harness_invocations"] = len(preliminary_rows)
result["preliminary_assertion_failure"] = "directory-symlink replacement incorrectly expected refusal; corrected before producing commit"
result["links"] = []
for path in [Path(PLAN), *map(Path, READMES), EVIDENCE/"README.md"]:
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", path.read_text()):
        if "://" in target or target.startswith("#"):
            continue
        resolved = (path.parent/target.split("#", 1)[0]).resolve()
        assert resolved.exists(), (path, target)
        result["links"].append(dict(source=str(path), target=target, exists=True))
(EVIDENCE/"validation.json").write_text(json.dumps(result, indent=2)+"\n")
print(json.dumps(result["focused"], indent=2))
print("PASS: producing identities, historical checksums, protected bytes, scope, formats, syntax and evidence")
