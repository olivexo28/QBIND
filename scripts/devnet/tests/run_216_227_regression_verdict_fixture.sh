#!/usr/bin/env bash
# Only normalized temporary copies execute; no QBIND binary or Cargo is run.
set -euo pipefail
exec python3 - "$@" <<'PY'
import ctypes
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

BASE = "f36e59a5e2cebab6fdfd0365920ca3e1a09444ac"
ROOT = Path.cwd().resolve()
if len(sys.argv) != 2:
    sys.exit("usage (repository root): bash scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh EVIDENCE_DIR")
DEST = Path(sys.argv[1]).resolve()
if DEST.exists():
    sys.exit("evidence destination must not exist")
DEST.mkdir(parents=True)
RAW = DEST / "raw"
RAW.mkdir()
NAMES = {
    216: "run_216_governance_execution_policy_release_binary",
    227: "run_227_governance_evaluator_runtime_callsite_wiring_release_binary",
}
PINS = {216: "e084e64f1b7b8e3ca1af9d0419b4bd659e0644f8",
        227: "ce73b752eff9fd03377582938956d7f53a470390"}
ALLOW = ["awk", "basename", "cat", "dirname", "env", "find", "grep", "head",
         "ls", "mkdir", "mktemp", "mv", "rm", "sed", "sha256sum", "uname", "xargs"]
TOOLS = {name: shutil.which(name) for name in ALLOW}
assert all(TOOLS.values()), TOOLS
BASH = shutil.which("bash")
PYTHON = sys.executable
# Reap orphaned fixture grandchildren ourselves, not the shared environment's children.
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(36, 1, 0, 0, 0) == 0, "Linux subreaper unavailable"

def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT).decode().strip()

def digest(b):
    return hashlib.sha256(b).hexdigest()

META = {
    "command": ["bash", "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh", str(DEST)],
    "producing_commit": git("rev-parse", "HEAD"),
    "producing_tree": git("rev-parse", "HEAD^{tree}"),
    "baseline": BASE, "python": sys.version, "bash": subprocess.check_output([BASH, "--version"]).decode(),
    "platform": os.uname()._asdict() if hasattr(os.uname(), "_asdict") else list(os.uname()),
    "uid": os.getuid(), "utilities": TOOLS, "identities": {},
    "started_utc": datetime.now(timezone.utc).isoformat(),
    "fixture_sha256": digest((ROOT/"scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh").read_bytes()),
    "tool_versions": {},
}
for tool, args in [("git", ["--version"]), ("mktemp", ["--version"]), ("mv", ["--version"]),
                   ("grep", ["--version"]), ("sed", ["--version"]), ("sha256sum", ["--version"]),
                   ("find", ["--version"]), ("xargs", ["--version"]), ("awk", ["-W", "version"])]:
    probe = subprocess.run([shutil.which(tool), *args], capture_output=True, text=True)
    META["tool_versions"][tool] = dict(command=[tool, *args], exit_code=probe.returncode,
                                      output=probe.stdout+probe.stderr)
STUB = r'''
import json, os, pathlib, signal, subprocess, sys, time
P = pathlib.Path
cfg = json.loads(P(os.environ["FIXTURE_CONFIG"]).read_text())
root = P(cfg["root"]).resolve()
out = P(cfg["out"])
name = P(sys.argv[0]).name
a = sys.argv[1:]
def event(kind, **kw):
    fd = os.open(cfg["guard"], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.write(fd, (json.dumps(dict(kind=kind, command=name, args=a, pid=os.getpid(), **kw))+"\n").encode())
    os.close(fd)
def reject(why):
    event("REJECT", reason=why)
    sys.exit(97)
def inside(p):
    return P(p).resolve().is_relative_to(root)
def fault(kind):
    event("FAULT", fault=kind)
    with open(cfg["faults"], "a") as f: f.write(kind+"\n")
def pause(phase):
    P(cfg["marker"]).write_text(phase)
    event("PAUSE", phase=phase)
    time.sleep(20)
def tamper():
    mode = cfg["mode"]
    m = out/"exit_codes/regression_results.tsv"
    if not m.exists(): reject("manifest not reached for tamper")
    lines = m.read_text().splitlines(True)
    if mode == "malformed_state": lines[2] = lines[2].replace("\treturned\t", "\tbogus\t")
    elif mode == "malformed_rc": lines[2] = lines[2].rsplit("\t",1)[0]+"\t256\n"
    elif mode == "duplicate": lines.append(lines[2])
    elif mode == "stale": lines[0] = "run_id=earlier\n"
    elif mode == "missing_row": del lines[2]
    elif mode == "unknown": lines[2] = "run999:test:unknown\treturned\t0\n"
    elif mode == "manifest_header": lines[1] = "wrong\tstate\trc\n"
    elif mode == "unterminated": lines[-1] = lines[-1].rstrip("\n")
    elif mode == "manifest_nul": lines[2] = lines[2].replace("returned", "retur\0ned")
    elif mode.startswith("status_"):
        p = out/("exit_codes/test_"+cfg["targets"][0]+".rc")
        if mode == "status_missing": p.unlink()
        elif mode == "status_extra": p.write_text("0\n\n")
        elif mode == "status_nul": p.write_bytes(b"0\0\n")
        else: p.write_text("9\n")
    else: reject("unknown tamper")
    m.write_text("".join(lines)); fault(mode)
event("ALLOW")
mode = cfg["mode"]
if name in cfg["utilities"]:
    if name == "rm":
        paths = [x for x in a if not x.startswith("-")]
        if not paths or any(not inside(p) or P(p).resolve() == root for p in paths):
            reject("out-of-root cleanup")
    if name in ("mkdir", "mktemp"):
        if any(not inside(p) for p in a if not p.startswith("-")): reject("out-of-root write")
    if name == "mktemp":
        stage = "final" if (out/"exit_codes/regression_results.tsv").exists() else "startup"
        if mode == stage+"_write" and not P(cfg["faults"]).exists():
            p = out/("summary.txt.tmp.injected-"+stage)
            p.mkdir()
            print(p)
            fault(mode)
            sys.exit(0)
    if name == "mv":
        src, dst = a[-2:]
        # Check the directory entry, not a symlink's referent.
        if not inside(P(src).parent) or not inside(P(dst).parent): reject("out-of-root rename")
        text = P(src).read_text()
        stage = "final" if "\naggregate: " in text else "startup"
        if mode == "final_directory" or mode == "final_directory_symlink":
            if stage == "final":
                P(dst).unlink()
                if mode == "final_directory": P(dst).mkdir()
                else: P(dst).symlink_to(out/"summary-target", target_is_directory=True)
                fault(mode)
        if mode == "final_file" or mode == "final_file_symlink":
            if stage == "final":
                P(dst).unlink()
                if mode == "final_file": P(dst).write_text("old final\n")
                else: P(dst).symlink_to(out/"summary-target")
                fault(mode)
        event("REPLACEMENT_ATTEMPT", stage=stage, source=src, destination=dst)
        if mode == stage+"_rename" and not P(cfg["faults"]).exists():
            fault(mode); sys.exit(73)
        if mode.startswith("after_") and "\nverdict: PASS\n" in text:
            result = subprocess.run([cfg["utilities"][name], *a])
            if result.returncode: sys.exit(result.returncode)
            pause("after")
            sys.exit(0)
    if name == "env":
        pos = 0
        while pos < len(a):
            if a[pos] == "-u": pos += 2
            elif "=" in a[pos]: pos += 1
            else: break
        if pos >= len(a) or P(a[pos]).absolute() != root/"target/release/qbind-node":
            reject("unexpected env executable")
    if name == "xargs":
        # Only the existing local denylist grep pipeline is allowed.
        if a[:2] != ["-0", "grep"]: reject("unexpected xargs executable")
    os.execv(cfg["utilities"][name], [name]+a)
if name == "git":
    if a[:2] != ["-C", str(root)]: reject("unexpected git root")
    if a[2:] == ["rev-parse", "HEAD"]: print(cfg["source_commit"])
    elif a[2:] == ["rev-parse", "--abbrev-ref", "HEAD"]: print("fixture")
    elif a[2:] != ["status", "--short"]: reject("unexpected git args")
elif name == "rustc":
    if a != ["--version"]: reject("rustc invocation")
    print("rustc fixture (not executed)")
elif name == "file":
    if len(a) != 1 or not inside(a[0]): reject("unexpected file args")
    print("fixture stub BuildID[sha1]=0000")
elif name == "cargo":
    if a == ["--version"]: print("cargo fixture (not executed)")
    elif a[:1] == ["build"]:
        valid = [
          ["build","--release","-p","qbind-node","--bin","qbind-node"],
          ["build","--release","-p","qbind-node","--example",cfg["helper"]],
        ]
        if a not in valid: reject("unexpected build")
        if cfg["variant"] == "candidate":
            text = (out/"summary.txt").read_text()
            if not text.startswith("run_id=run") or not text.endswith("verdict: INCOMPLETE\n"):
                reject("startup sentinel absent before work")
            event("STARTUP_SENTINEL_OBSERVED", summary=text)
        if mode in ("early_build", "seeded_pass_build_failure"): fault(mode); sys.exit(41)
    elif a[:3] == ["test","-p","qbind-node"]:
        if a[-2:] != ["--","--test-threads=1"]: reject("test suffix")
        mid = a[3:-2]
        if len(mid) == 2 and mid[0] == "--test" and mid[1] in cfg["targets"]:
            key = "test:"+mid[1]
        elif mid == ["--lib","pqc_authority"]: key = "lib:pqc_authority"
        elif mid == ["--lib"]: key = "lib:lib_all"
        else: reject("unexpected regression command")
        event("REGRESSION", key=key)
        first = "test:"+cfg["targets"][0]
        if key == first:
            if mode.startswith("supervisor_"):
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
                event("SUPERVISOR_CHILD", child=child.pid)
                if mode == "supervisor_malformed_marker":
                    P(cfg["marker"]).mkdir()
                elif mode != "supervisor_missing_marker":
                    P(cfg["marker"]).write_text("wrong" if mode == "supervisor_wrong_phase" else "before")
                P(cfg["marker"]+".ready").write_text("ready")
                time.sleep(20)
            if mode.startswith("before_"): pause("before")
            if mode in ("log_error", "failure_and_capture"):
                (out/("test_results/test_"+cfg["targets"][1]+".log")).mkdir(); fault(mode)
            if mode == "rc_io":
                (out/("exit_codes/test_"+cfg["targets"][0]+".rc")).mkdir(); fault(mode)
            if mode == "manifest_io":
                p = out/"exit_codes/regression_results.tsv"; p.unlink(); p.mkdir(); fault(mode)
        if key == "lib:lib_all" and mode in cfg["tamper_modes"]: tamper()
        status = cfg["failures"].get(key, 0)
        print("controlled Cargo stub", key, "status", status)
        if status: fault("cargo:"+key+":"+str(status))
        sys.exit(status)
    else: reject("unexpected Cargo invocation")
elif name == "qbind-node":
    if a == ["--help"]:
        if mode == "help_fail": fault(mode); sys.exit(43)
        print("fixture help")
    elif a[:1] == ["--print-genesis-hash"] and "--env" in a:
        if "bogus-policy" in a:
            print("invalid governance-execution policy selector; no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call")
            event("S6_EXPECTED_REJECTION"); sys.exit(2)
        print("fixture genesis")
    else: reject("unexpected node invocation")
elif name == cfg["helper"]:
    if len(a) != 1 or not inside(a[0]): reject("unexpected helper args")
    if mode == "helper_fail": fault(mode); sys.exit(42)
    p = P(a[0]); p.mkdir(parents=True, exist_ok=True)
    (p/"helper_summary.txt").write_text("table fixture\ntotal_pass: 1\ntotal_fail: 0\nverdict: PASS\n")
    if mode == "denylist":
        (p/"injected.txt").write_text("DummySig\n"); fault(mode)
else: reject("unexpected executable")
'''
TAMPER = ["malformed_state", "malformed_rc", "duplicate", "stale", "missing_row",
          "unknown", "manifest_header", "unterminated", "status_mismatch",
          "status_missing", "status_extra", "manifest_nul", "status_nul"]
MODES = [
    "success", "first", "middle", "last", "lib_first", "lib_last", "multiple",
    "missing", "log_error", "failure_and_capture", "launch_failure", *TAMPER, "rc_io", "manifest_io",
    "startup_write", "startup_rename", "final_write", "final_rename",
    "seeded_pass_build_failure", "early_build", "helper_fail", "help_fail", "denylist",
    "before_INT", "before_TERM", "before_HUP", "before_KILL",
    "after_INT", "after_TERM", "after_HUP", "after_KILL",
    "reuse_success", "reuse_failure",
    "startup_file", "startup_file_symlink", "startup_directory", "startup_directory_symlink",
    "final_file", "final_file_symlink", "final_directory", "final_directory_symlink",
]
RECORDS = []
UNSAFE_GROUPS = set()
SUPERVISION = []
WATCHDOG_REPORT_FD = None

def group_members(pgid):
    found = []
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            fields = (p/"stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid:
                found.append((int(p.name), fields[0]))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return found

def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False

def validate_process_visibility():
    pid = os.getpid()
    own = Path("/proc/self/stat").read_text()
    visible_pid = int(own.split(" ", 1)[0])
    fields = own.rsplit(")", 1)[1].split()
    assert visible_pid == pid and int(fields[2]) == os.getpgrp(), (
        "unsupported /proc PID/process-group namespace", pid, visible_pid, fields[2], os.getpgrp())
    assert (Path("/proc")/str(pid)/"stat").read_text().split(" ", 1)[0] == str(pid)
    assert any(member == pid for member, state in group_members(os.getpgrp())), (
        "unsupported /proc process visibility")
    META["process_visibility"] = dict(pid=pid, pgid=os.getpgrp(), proc_pid=visible_pid,
                                      self_visible=True, kernel_group_alive=group_alive(os.getpgrp()))

def cleanup_group(p, timeout=3):
    initial = group_members(p.pid)
    # Kernel group existence, never an empty /proc scan, controls containment.
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    until = time.monotonic()+timeout
    reaped = []
    p.wait(timeout=max(.01, until-time.monotonic()))
    while time.monotonic() < until:
        while True:
            try:
                pid, status = os.waitpid(-p.pid, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
            reaped.append([pid, status])
        left = group_members(p.pid)
        alive = group_alive(p.pid)
        if not alive and not left:
            return dict(pgid=p.pid, initial=initial, reaped=reaped, remaining=[],
                        kernel_group_absent=True)
        time.sleep(.02)
    raise AssertionError(("children survived cleanup", p.pid, left, group_alive(p.pid)))

@contextmanager
def owned_process(p, supervision, case):
    original = None
    try:
        if WATCHDOG_REPORT_FD is not None:
            os.write(WATCHDOG_REPORT_FD, (json.dumps(dict(started_group=p.pid))+"\n").encode())
        yield p
    except BaseException as error:
        original = error
        supervision["original_error"] = repr(error)
        raise
    finally:
        try:
            supervision["cleanup"] = cleanup_group(p)
        except BaseException as error:
            UNSAFE_GROUPS.add(p.pid)
            supervision["cleanup_error"] = repr(error)
            if original is not None:
                original.add_note("separate fixture cleanup failure: "+repr(error))
            else:
                original = error
                raise
        finally:
            SUPERVISION.append(dict(case=case, **supervision))
            try:
                (DEST/"supervision.json").write_text(json.dumps(SUPERVISION, indent=2)+"\n")
            except BaseException as error:
                if original is None:
                    raise
                original.add_note("separate supervision evidence failure: "+repr(error))
                print("supervision evidence failure: "+repr(error), file=sys.stderr)

@contextmanager
def fixture_workspace():
    temp = Path(tempfile.mkdtemp(prefix="qbind-verdict-fixture-"))
    META["workspace"] = str(temp)
    try:
        yield temp
    finally:
        if UNSAFE_GROUPS:
            META["retained_workspace"] = str(temp)
            META["unsafe_groups"] = sorted(UNSAFE_GROUPS)
            print("cleanup failed; retaining workspace: "+str(temp), file=sys.stderr)
        else:
            shutil.rmtree(temp)

def run_case(work, run, variant, mode, raw, targets):
    assert not UNSAFE_GROUPS, ("refusing cases after unsafe cleanup", UNSAFE_GROUPS)
    case = f"{run}-{variant}-{mode}"
    # Reuse only the two explicitly sequential cases; all preceding children are reaped.
    out = work/"out"/("sequential" if mode.startswith("reuse_") else case)
    out.mkdir(parents=True, exist_ok=True)
    old = "run_id=earlier\nverdict: PASS\n"
    if mode not in ("reuse_failure",):
        (out/"summary.txt").write_text(old)
    if mode.startswith(("startup_", "final_")) and mode.endswith(
            ("_file", "_file_symlink", "_directory", "_directory_symlink")):
        target = out/"summary-target"
        if "directory" in mode:
            target.mkdir()
            (target/"sentinel").write_text("preserve\n")
        else:
            target.write_text("referent must remain unchanged\n")
        if mode.startswith("startup_"):
            (out/"summary.txt").unlink()
            if mode == "startup_directory": (out/"summary.txt").mkdir()
            elif mode.endswith("_symlink"): (out/"summary.txt").symlink_to(target)
            else: (out/"summary.txt").write_text(old)
    failures = {}
    if mode in ("first", "multiple", "reuse_failure", "failure_and_capture"):
        failures["test:"+targets[0]] = 17
    if mode == "launch_failure":
        failures["test:"+targets[0]] = 127
    if mode == "middle":
        target = ("run_180_onchain_governance_marker_integration_tests" if run == 216
                  else "run_220_governance_execution_runtime_consumption_tests")
        failures["test:"+target] = 23
    if mode == "last": failures["test:"+targets[-1]] = 29
    if mode in ("lib_first", "multiple"): failures["lib:pqc_authority"] = 31
    if mode == "lib_last": failures["lib:lib_all"] = 37
    script = work/"scripts/devnet"/(NAMES[run]+".sh")
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_bytes(raw.replace(b"\r\n", b"\n"))
    # Textual reachability fixtures only; no Rust source is compiled or executed.
    src = work/"crates/qbind-node/src"
    src.mkdir(parents=True, exist_ok=True)
    for name in ("lib.rs", "main.rs", "pqc_live_trust_reload.rs",
                 "pqc_governance_execution_evaluator_runtime_integration.rs",
                 "pqc_governance_execution_evaluator.rs"):
        (src/name).write_bytes(raw.replace(b"\r\n", b"\n"))
    tests = work/"crates/qbind-node/tests"
    tests.mkdir(parents=True, exist_ok=True)
    for t in targets:
        (tests/(t+".rs")).write_text("// fixture target presence only\n")
    if mode == "missing":
        (tests/(targets[0]+".rs")).unlink()
    cfg = dict(root=str(work), out=str(out), mode=mode, targets=targets, variant=variant,
               source_commit=BASE if variant == "baseline" else META["producing_commit"],
               helper=NAMES[run]+"_helper", utilities=TOOLS, failures=failures,
               guard=str(work/"guard.jsonl"), faults=str(work/"faults.txt"),
               marker=str(work/"marker"), tamper_modes=TAMPER)
    for key in ("guard", "faults", "marker"):
        p = Path(cfg[key])
        if p.is_dir(): p.rmdir()
        else: p.unlink(missing_ok=True)
    Path(cfg["marker"]+".ready").unlink(missing_ok=True)
    conf = work/"config.json"
    conf.write_text(json.dumps(cfg))
    for name in ("qbind-node", cfg["helper"]):
        p = work/("target/release/qbind-node" if name == "qbind-node" else "target/release/examples/"+name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.unlink(missing_ok=True)
        p.symlink_to(work/"bin"/name)
    env = dict(PATH=str(work/"bin"), HOME=str(work), LANG="C", LC_ALL="C",
               OUTDIR=str(out), FIXTURE_CONFIG=str(conf))
    stdout = work/"stdout"
    stderr = work/"stderr"
    supervision = {}
    with stdout.open("wb") as so, stderr.open("wb") as se:
        p = subprocess.Popen([BASH, str(script)], cwd=work, env=env,
                             stdout=so, stderr=se, start_new_session=True)
        with owned_process(p, supervision, case):
            deadline = time.monotonic()+30
            if mode.startswith(("before_", "after_", "supervisor_")):
                phase, sig = mode.split("_") if not mode.startswith("supervisor_") else ("before", "INT")
                ready = Path(cfg["marker"]+".ready") if mode.startswith("supervisor_") else Path(cfg["marker"])
                while not ready.exists() and p.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                assert Path(cfg["marker"]).read_text() == phase, (case, "phase not reached", stderr.read_text())
                assert p.poll() is None, (case, "harness already exited")
                if mode == "supervisor_exception": raise KeyboardInterrupt("injected driver BaseException")
                if mode == "supervisor_evidence_read": (out/"missing-evidence").read_text()
                text = (out/"summary.txt").read_text()
                assert ("verdict: PASS" in text) == (phase == "after"), (case, text)
                supervision.update(phase=phase, alive_before_signal=True, summary_before_signal=text,
                                   signal=sig, pgid=p.pid)
                os.killpg(p.pid, getattr(signal, "SIG"+sig))
                try:
                    rc = p.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    supervision["containment_kill"] = True
                    os.killpg(p.pid, signal.SIGKILL)
                    rc = p.wait(timeout=3)
            else:
                try:
                    rc = p.wait(timeout=max(.1, deadline-time.monotonic()))
                except subprocess.TimeoutExpired:
                    raise AssertionError((case, "unexpected timeout"))
    directory_destination = mode in ("startup_directory", "final_directory")
    summary = None if directory_destination else (out/"summary.txt").read_text()
    guard = Path(cfg["guard"]).read_text()
    events = [json.loads(x) for x in guard.splitlines()]
    calls = [e["key"] for e in events if e["kind"] == "REGRESSION"]
    faults = Path(cfg["faults"]).read_text() if Path(cfg["faults"]).exists() else ""
    expected = ["test:"+t for t in targets]+["lib:pqc_authority", "lib:lib_all"]
    artifact = {}
    for folder in ("logs", "exit_codes", "test_results"):
        for f in sorted((out/folder).rglob("*")):
            if f.is_file():
                artifact[str(f.relative_to(out))] = f.read_text()
    for f in ("negative_invariants.txt", "provenance.txt"):
        if (out/f).is_file():
            artifact[f] = (out/f).read_text()
    record = dict(case=case, harness=run, variant=variant, mode=mode,
                  invocation_command=[BASH, str(script)], invocation_environment=env,
                  parent_observed_returncode=rc, normal_zero_exit=(rc == 0),
                  summary=summary, stdout=stdout.read_text(), stderr=stderr.read_text(),
                  commands=calls, guard_log=guard, fault_triggers=faults,
                  supervision=supervision, artifacts=artifact)
    # Persist raw evidence even when an assertion below fails.
    with (RAW/f"run-{run}.jsonl").open("a") as f:
        f.write(json.dumps(record)+"\n")
    assert not any(e["kind"] == "REJECT" for e in events), (case, "unexpected guarded command")
    if variant == "baseline":
        assert rc == 0 and summary.endswith("verdict: PASS\n"), (case, record)
        assert calls == expected, (case, calls)
        if mode == "first":
            assert artifact["exit_codes/test_"+targets[0]+".rc"] == "17\n"
        verdict = "PASS"
    else:
        success = mode in ("success", "reuse_success", "startup_file", "startup_file_symlink",
                           "final_file", "final_file_symlink",
                           "startup_directory_symlink", "final_directory_symlink")
        complete_fail = mode in ("first", "middle", "last", "lib_first", "lib_last", "multiple", "missing", "reuse_failure", "launch_failure")
        verdict = "PASS" if success else "FAIL" if complete_fail else "INCOMPLETE"
        if directory_destination:
            assert rc != 0 and summary is None and (out/"summary.txt").is_dir(), (case, record)
            assert (out/"summary.txt").is_symlink() == mode.endswith("_symlink")
            assert sorted(p.name for p in (out/"summary.txt").iterdir()) == (
                ["sentinel"] if mode.endswith("_symlink") else []), (case, "directory modified")
            assert (out/"summary-target/sentinel").read_text() == "preserve\n"
            assert "cannot overwrite directory" in record["stderr"] or "cannot overwrite" in record["stderr"]
            if mode.startswith("startup_"):
                assert "summary initialization failed" in record["stderr"] and not calls
                assert not any(e["command"] in ("cargo", "qbind-node", cfg["helper"]) for e in events)
            else:
                assert "cannot publish final summary" in record["stderr"] and calls == expected
                assert mode in faults
            verdict = "DIRECTORY_REFUSED"
        elif mode in ("startup_write", "startup_rename"):
            assert summary == old and not calls and rc != 0, (case, record)
            assert "untrusted" in record["stderr"]
            verdict = "OLD_UNTRUSTED"
        elif mode == "after_KILL":
            assert rc == -signal.SIGKILL and summary.endswith("verdict: PASS\n")
            verdict = "PASS_WITHOUT_SUCCESSFUL_COMPLETION"
        else:
            assert summary.endswith("verdict: "+verdict+"\n"), (case, record)
            assert (rc == 0) == success, (case, rc, verdict)
            ids = re.findall(r"^run_id=(.+)$", summary, re.M)
            assert len(ids) == 1 and "run_id="+ids[0] in record["stderr"], (case, "invocation mismatch")
        if success and mode.endswith(("_file", "_file_symlink", "_directory_symlink")):
            assert (out/"summary.txt").is_file() and not (out/"summary.txt").is_symlink()
            if mode.endswith("_directory_symlink"):
                assert sorted(p.name for p in (out/"summary-target").iterdir()) == ["sentinel"]
                assert (out/"summary-target/sentinel").read_text() == "preserve\n"
            else:
                assert (out/"summary-target").read_text() == "referent must remain unchanged\n"
            attempts = [e for e in events if e["kind"] == "REPLACEMENT_ATTEMPT"]
            assert attempts and all(e["args"][:2] == ["-fT", "--"] for e in attempts)
            assert calls == expected
            if mode.startswith("final_"): assert mode in faults
        if mode in ("success", "first", "middle", "last", "lib_first", "lib_last", "multiple",
                    "reuse_success", "reuse_failure", "launch_failure", *TAMPER, "rc_io", "manifest_io",
                    "final_write", "final_rename"):
            assert calls == expected, (case, calls)
        if mode in ("missing", "log_error", "failure_and_capture"):
            excluded = expected[0 if mode == "missing" else 1]
            assert calls == [k for k in expected if k != excluded], (case, calls)
        if mode in ("early_build", "seeded_pass_build_failure", "helper_fail", "help_fail", "denylist"):
            assert not calls and faults, (case, calls, faults)
            diagnostic = {"early_build": "qbind-node build failed", "seeded_pass_build_failure": "qbind-node build failed",
                          "helper_fail": "helper failed", "help_fail": "help failed", "denylist": None}[mode]
            if diagnostic:
                assert diagnostic in record["stderr"], (case, "intended gate not reached")
            else:
                assert "FAIL pattern present: DummySig" in artifact["negative_invariants.txt"]
        if mode in (*TAMPER, "log_error", "rc_io", "manifest_io", "startup_write", "startup_rename", "final_write", "final_rename"):
            assert mode in faults, (case, "fault did not trigger")
        for fault_mode, diagnostic in {
            "log_error": "cannot capture", "failure_and_capture": "cannot capture",
            "rc_io": "status write failed", "manifest_io": "manifest write failed",
            "startup_write": "summary initialization failed", "startup_rename": "summary initialization failed",
            "final_rename": "cannot publish final summary",
        }.items():
            if mode == fault_mode:
                assert diagnostic in record["stderr"], (case, "intended I/O fault not observed")
        if mode in ("log_error", "failure_and_capture", "rc_io", "manifest_io", "startup_write", "final_write"):
            assert "Is a directory" in record["stderr"], (case, "redirection denial not observed")
        if success or complete_fail:
            manifest = artifact["exit_codes/regression_results.tsv"]
            lines = manifest.splitlines()
            assert len(lines) == len(expected)+2
            assert lines[0] == "run_id="+ids[0]
            assert lines[1] == "command_key\tstate\trc"
            for row, key in zip(lines[2:], expected):
                full, state, status = row.split("\t")
                assert full == f"run{run}:"+key
                if mode == "missing" and key == expected[0]:
                    assert state == "missing_target" and status == ""
                else:
                    assert state == "returned" and int(status) == failures.get(key, 0)
                    stem = key.replace(":", "_", 1)
                    assert artifact["exit_codes/"+stem+".rc"] == status+"\n"
                    assert "test_results/"+stem+".log" in artifact
                assert "  "+row+"\n" in summary, (case, "not incorporated", row)
            if run == 227:
                assert any(e["kind"] == "S6_EXPECTED_REJECTION" for e in events)
                assert artifact["exit_codes/S6_selector_invalid.rc"] == "2\n"
            for section in ("release-binary scenario verdicts:", "release-helper verdicts:",
                            "denylist result:", "regression test verdicts:", "honest_limits:"):
                assert section in summary
        if mode.startswith(("before_", "after_")):
            assert rc != 0
            if not mode.endswith("KILL"):
                assert rc == {"INT": 130, "TERM": 143, "HUP": 129}[mode.split("_")[1]]
                assert "interrupted by SIG"+mode.split("_")[1] in record["stderr"]
                assert not supervision.get("containment_kill"), (case, "handler did not complete")
            if mode.startswith("before_"): assert calls == expected[:1], (case, calls)
            if mode.endswith("KILL"): assert rc == -signal.SIGKILL
    RECORDS.append(dict(case=case, verdict=verdict, returncode=rc, required_count=len(expected),
                        attempted_count=len(calls), fault_triggers=faults.splitlines(),
                        cleanup_verified=True))
    print(case, "OK", "rc="+str(rc), "attempted="+str(len(calls)), flush=True)

def supervisor_negative(work, run, mode, raw, targets):
    # A separate watchdog owns the tested driver. Rescue is always a failure.
    read_fd, write_fd = os.pipe()
    worker = os.fork()
    if worker == 0:
        os.close(read_fd)
        global WATCHDOG_REPORT_FD
        WATCHDOG_REPORT_FD = write_fd
        try:
            assert libc.prctl(36, 1, 0, 0, 0) == 0
            expected = {"supervisor_wrong_phase": AssertionError,
                        "supervisor_missing_marker": FileNotFoundError,
                        "supervisor_malformed_marker": IsADirectoryError,
                        "supervisor_evidence_read": FileNotFoundError,
                        "supervisor_exception": KeyboardInterrupt}[mode]
            try:
                run_case(work, run, "candidate", mode, raw, targets)
            except expected as error:
                assert SUPERVISION[-1]["cleanup"]["kernel_group_absent"]
                assert len(SUPERVISION[-1]["cleanup"]["initial"]) >= 2
                assert str(error) and {
                    "supervisor_wrong_phase": "phase not reached",
                    "supervisor_missing_marker": "/marker",
                    "supervisor_malformed_marker": "/marker",
                    "supervisor_evidence_read": "/missing-evidence",
                    "supervisor_exception": "injected driver BaseException",
                }[mode] in str(error), ("wrong driver fault", mode, repr(error))
                result = dict(expected_error=repr(error), supervision=SUPERVISION[-1])
            else:
                raise AssertionError("injected driver error did not escape")
            os.write(write_fd, (json.dumps(dict(result=result))+"\n").encode())
            os._exit(0)
        except BaseException as error:
            os.write(write_fd, (json.dumps(dict(worker_error=repr(error)))+"\n").encode())
            os._exit(1)
    os.close(write_fd)
    os.set_blocking(read_fd, False)
    data = b""
    status = None
    deadline = time.monotonic()+12
    while time.monotonic() < deadline:
        try:
            data += os.read(read_fd, 65536)
        except BlockingIOError:
            pass
        found, status = os.waitpid(worker, os.WNOHANG)
        if found:
            break
        time.sleep(.02)
    else:
        status = None
    try:
        while chunk := os.read(read_fd, 65536):
            data += chunk
    except BlockingIOError:
        pass
    os.close(read_fd)
    messages = [json.loads(line) for line in data.splitlines()]
    groups = [m["started_group"] for m in messages if "started_group" in m]
    rescued = []
    for pgid in groups:
        if group_alive(pgid):
            rescued.append(pgid)
            # Independent containment only; never credit it to the tested owner.
            class Child:
                pid = pgid
                def wait(self, timeout):
                    return None
            try:
                cleanup_group(Child())
            except BaseException:
                UNSAFE_GROUPS.add(pgid)
    if status is None:
        UNSAFE_GROUPS.add(worker)
        os.kill(worker, signal.SIGKILL)
        os.waitpid(worker, 0)
    events = [json.loads(line) for line in (work/"guard.jsonl").read_text().splitlines()]
    children = [e["child"] for e in events if e["kind"] == "SUPERVISOR_CHILD"]
    record = dict(run=run, mode=mode, worker_status=status, messages=messages,
                  watchdog_rescued_groups=rescued, groups=groups,
                  independent_kernel_absent=all(not group_alive(g) for g in groups),
                  owned_children=children,
                  independent_children_absent=all(not Path("/proc", str(pid)).exists() for pid in children),
                  stdout=(work/"stdout").read_text(), stderr=(work/"stderr").read_text(),
                  guard_log=(work/"guard.jsonl").read_text())
    with (DEST/"supervisor-negative.jsonl").open("a") as f:
        f.write(json.dumps(record)+"\n")
    assert status == 0 and not rescued and groups and children, record
    assert record["independent_kernel_absent"] and record["independent_children_absent"], record
    assert any("result" in m for m in messages), record
    print(f"{run}-{mode} OK; independent watchdog rescue=0", flush=True)

try:
    validate_process_visibility()
    # Validate that a false-empty scan cannot pass preflight.
    real_members = group_members
    try:
        group_members = lambda pgid: []
        try:
            validate_process_visibility()
        except AssertionError as error:
            META["unsupported_visibility_control"] = repr(error)
        else:
            raise AssertionError("empty process visibility accepted")
    finally:
        group_members = real_members
    with fixture_workspace() as temp:
        work = Path(temp)
        with owned_process(subprocess.Popen([PYTHON, "-c", "import time; time.sleep(20)"],
                                            start_new_session=True), {}, "visibility-probe") as probe:
            assert os.getpgid(probe.pid) == probe.pid
            assert any(pid == probe.pid for pid, state in group_members(probe.pid)), (
                "unsupported owned-group /proc visibility")
            assert group_alive(probe.pid)
        bin = work/"bin"
        bin.mkdir()
        stub = work/"stub.py"
        stub.write_text("#!"+PYTHON+"\n"+STUB)
        stub.chmod(0o755)
        names = ALLOW+["git", "rustc", "file", "cargo", "qbind-node",
                      *[n+"_helper" for n in NAMES.values()],
                      "curl", "wget", "ssh", "scp", "nc", "ncat", "socat", "python3",
                      "bash", "sh", "make", "rustup", "timeout", "sleep"]
        for name in names:
            (bin/name).symlink_to(stub)
        # Calibrate guard rejection and local utility dispatch before any reproduction.
        cfg = work/"config.json"
        calibration = dict(root=str(work), out=str(work/"out"), mode="calibration",
                           guard=str(work/"guard-calibration.jsonl"), faults=str(work/"fault-calibration"),
                           utilities=TOOLS, helper="not-a-helper")
        cfg.write_text(json.dumps(calibration))
        env = dict(PATH=str(bin), FIXTURE_CONFIG=str(cfg))
        checks = []
        for cmd, expected_rc in [
            (["cargo", "unexpected"], 97), (["curl", "http://127.0.0.1/"], 97),
            (["rm", "-rf", "/not-a-fixture-path"], 97), (["git", "fetch"], 97),
            (["env", "/bin/false"], 97), (["xargs", "sh"], 97),
            (["mkdir", str(work/"calibrated")], 0),
        ]:
            result = subprocess.run([str(bin/cmd[0]), *cmd[1:]], env=env, capture_output=True)
            assert result.returncode == expected_rc, (cmd, result)
            checks.append(dict(command=cmd, expected=expected_rc, actual=result.returncode))
        (DEST/"calibration.json").write_text(json.dumps(dict(checks=checks,
            guard_log=Path(calibration["guard"]).read_text()), indent=2)+"\n")
        # Baseline copies are pinned, unmodified except explicit CRLF normalization.
        for run, name in NAMES.items():
            path = "scripts/devnet/"+name+".sh"
            baseline = subprocess.check_output(["git", "show", BASE+":"+path], cwd=ROOT)
            assert git("rev-parse", BASE+":"+path) == PINS[run]
            candidate = (ROOT/path).read_bytes()
            targets = re.search(rb"^TEST_TARGETS=\(([^)]+)\)", baseline, re.M)[1].decode().split()
            assert targets == re.search(rb"^TEST_TARGETS=\(([^)]+)\)", candidate, re.M)[1].decode().split()
            assert len(targets) == (35 if run == 216 else 8)
            META["identities"][str(run)] = {}
            for variant, raw in (("baseline", baseline), ("candidate", candidate)):
                normalized = raw.replace(b"\r\n", b"\n")
                META["identities"][str(run)][variant] = dict(raw_sha256=digest(raw),
                    normalized_sha256=digest(normalized),
                    raw_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),
                    matches_committed_blob=(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
                                            == git("rev-parse", (BASE if variant == "baseline" else "HEAD")+":"+path)),
                    normalized_bytes=len(normalized), raw_bytes=len(raw))
                syntax = subprocess.run([BASH, "-n"], input=normalized, capture_output=True)
                assert syntax.returncode == 0, syntax.stderr.decode()
                if variant == "candidate":
                    text = normalized.decode()
                    assert "$(run_test_target" not in text and "$(run_lib_test" not in text
                    assert "if run_regression test" in text and "if run_regression lib" in text
                for mode in (["success", "first"] if variant == "baseline" else MODES):
                    run_case(work, run, variant, mode, raw, targets)
                if variant == "candidate":
                    for mode in ("supervisor_wrong_phase", "supervisor_missing_marker", "supervisor_malformed_marker",
                                 "supervisor_evidence_read", "supervisor_exception"):
                        supervisor_negative(work, run, mode, raw, targets)
    META["case_count"] = len(RECORDS)
    META["candidate_case_count"] = sum("-candidate-" in r["case"] for r in RECORDS)
    META["supervisor_negative_invocations"] = 10
    META["total_harness_invocations"] = len(RECORDS)+10
    META["exit_code"] = 0
    META["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (DEST/"cases.json").write_text(json.dumps(RECORDS, indent=2)+"\n")
    (DEST/"environment.json").write_text(json.dumps(META, indent=2)+"\n")
    print("PASS:", len(RECORDS), "actual harness invocations; fixture evidence only")
except BaseException as e:
    META["exit_code"] = 1
    META["error"] = repr(e)
    (DEST/"environment.json").write_text(json.dumps(META, indent=2)+"\n")
    raise
PY
