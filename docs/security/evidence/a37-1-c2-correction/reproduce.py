#!/usr/bin/env python3
"""Bounded historical reproductions; no real release commands execute."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

REV = "6fdc0f0dcfc45c65037de3e53215121f5332689a"
ROOT = Path.cwd()
DEST = Path(sys.argv[1]).resolve()
DEST.mkdir(parents=True, exist_ok=False)
results = []


def historical(path):
    return subprocess.check_output(["git", "show", REV + ":" + path]).replace(b"\r\n", b"\n").decode()


for run, name in [
    (216, "run_216_governance_execution_policy_release_binary"),
    (227, "run_227_governance_evaluator_runtime_callsite_wiring_release_binary"),
]:
    source = historical("scripts/devnet/" + name + ".sh")
    function = source[source.index("publish_incomplete() {"):source.index("\nfinish() {")]
    for kind in ("file", "directory", "directory_symlink"):
        with tempfile.TemporaryDirectory(prefix="qbind-publish-repro-") as tmp:
            root = Path(tmp)
            summary = root / "summary.txt"
            target = root / "target"
            target.mkdir()
            (target / "sentinel").write_text("preserve\n")
            if kind == "file":
                summary.write_text("old\n")
            elif kind == "directory":
                summary.mkdir()
            else:
                summary.symlink_to(target, target_is_directory=True)
            command = function + '\nSUMMARY="$1"; RUN_ID=reproduction; publish_incomplete\n'
            p = subprocess.run(["bash", "-c", command, "repro", str(summary)], capture_output=True, text=True)
            moved = sorted(x.name for x in summary.iterdir()) if summary.is_dir() else []
            record = dict(run=run, destination=kind, command=command, returncode=p.returncode,
                          stdout=p.stdout, stderr=p.stderr, is_symlink=summary.is_symlink(),
                          is_file=summary.is_file(), is_directory=summary.is_dir(), contents=moved)
            assert p.returncode == 0
            assert summary.is_file() if kind == "file" else any(".tmp." in x for x in moved)
            results.append(record)

# Execute unchanged historical run_case with only its Popen launch replaced by
# an inert live process tree. The independent outer owner always contains it.
fixture = historical("scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh")
driver = fixture.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
prefix = driver[:driver.index("\ntry:\n    with tempfile.TemporaryDirectory")]
old_argv = sys.argv
sys.argv = ["historical-driver", str(DEST / "historical-driver")]
ns = {"__name__": "historical_reproduction"}
exec(compile(prefix, "historical-driver", "exec"), ns)
sys.argv = old_argv
real_popen = subprocess.Popen
owned = []
cleanup_calls = []
original_cleanup = ns["cleanup_group"]


def spy_cleanup(*args, **kwargs):
    cleanup_calls.append(args[0].pid)
    return original_cleanup(*args, **kwargs)


def surrogate(*args, **kwargs):
    cfg = json.loads(Path(kwargs["env"]["FIXTURE_CONFIG"]).read_text())
    code = (
        "import os,pathlib,subprocess,sys,time;"
        "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)']);"
        "pathlib.Path(sys.argv[1]).write_text(str(c.pid));"
        "pathlib.Path(sys.argv[2]).write_text('wrong');time.sleep(20)"
    )
    p = real_popen([sys.executable, "-c", code, cfg["marker"] + ".child", cfg["marker"]],
                   start_new_session=True, stdout=kwargs["stdout"], stderr=kwargs["stderr"])
    owned.append(p)
    return p


ns["cleanup_group"] = spy_cleanup
surrogate_raw = historical("scripts/devnet/run_216_governance_execution_policy_release_binary.sh").encode()
with tempfile.TemporaryDirectory(prefix="qbind-owner-repro-") as tmp:
    work = Path(tmp)
    subprocess.Popen = surrogate
    observation = {}
    try:
        ns["run_case"](work, 216, "candidate", "before_INT",
                       surrogate_raw, ["inert_fixture"])
        raise RuntimeError("expected phase assertion did not raise")
    except AssertionError as error:
        assert owned
        os.killpg(owned[0].pid, 0)
        observation = dict(error=repr(error), cleanup_calls=list(cleanup_calls),
                           leader_alive=owned[0].poll() is None,
                           group_alive=True, pgid=owned[0].pid)
        assert not cleanup_calls and observation["leader_alive"]
    finally:
        subprocess.Popen = real_popen
        for p in owned:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=3)
            until = time.monotonic() + 3
            reaped = []
            while time.monotonic() < until:
                try:
                    pid, status = os.waitpid(-p.pid, os.WNOHANG)
                    if pid:
                        reaped.append([pid, status])
                except ChildProcessError:
                    pass
                try:
                    os.killpg(p.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(.02)
            else:
                raise RuntimeError("independent outer containment failed; retain workspace")
            observation.update(outer_cleanup_required=True, outer_reaped=reaped, group_absent=True)
    results.append(dict(supervisor_reproduction=observation))
(DEST / "reproduction.json").write_text(json.dumps(dict(revision=REV, outcomes=results), indent=2) + "\n")
print("Historical publication: 2 regular controls, 4 directory defects reproduced.")
print("Historical supervisor: live assertion bypassed cleanup; independent outer owner contained/reaped.")
