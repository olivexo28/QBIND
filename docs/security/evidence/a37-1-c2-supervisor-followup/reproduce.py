#!/usr/bin/env python3
"""Reproduce the unchanged historical watchdog-parent interruption defect."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

REV = "d494ce2af1dd522e8ec0fc14c36b02a19e50b209"
path = "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh"
source = subprocess.check_output(["git", "show", REV + ":" + path]).decode()
driver = source.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
prefix = driver[:driver.index("\ntry:\n    validate_process_visibility()")]
ns = {"__name__": "historical_watchdog"}
exec(compile(prefix, path, "exec"), ns)
dest = ns["DEST"]
real_wait = os.waitpid
parent = os.getpid()
owned_worker = []
surrogate_code = (
    "import pathlib,subprocess,sys,time;"
    "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
    "pathlib.Path(sys.argv[1]).write_text(str(c.pid));time.sleep(30)"
)


def inert(work, *args):
    p = subprocess.Popen([sys.executable, "-c", surrogate_code, str(work / "child")],
                         start_new_session=True)
    (work / "group").write_text(str(p.pid))
    ns["SUPERVISION"].append({"cleanup": {"kernel_group_absent": False, "initial": []}})
    while True:
        time.sleep(1)


def interrupt_wait(pid, flags):
    if os.getpid() == parent and flags == os.WNOHANG:
        owned_worker.append(pid)
        deadline = time.monotonic() + 3
        while not (work / "child").exists() and time.monotonic() < deadline:
            time.sleep(.01)
        raise KeyboardInterrupt("injected historical parent waitpid interruption")
    return real_wait(pid, flags)


ns["run_case"] = inert
record = {"revision": REV, "kind": "isolated unchanged-function reproduction; not a harness run"}
try:
    with ns["fixture_workspace"]() as work:
        try:
            os.waitpid = interrupt_wait
            ns["supervisor_negative"](work, 216, "supervisor_wrong_phase", b"", [])
        except KeyboardInterrupt as error:
            worker = owned_worker[0]
            group = int((work / "group").read_text())
            child = int((work / "child").read_text())
            os.kill(worker, 0)
            os.killpg(group, 0)
            record.update(original_error=repr(error), worker=worker, group=group, child=child,
                          worker_alive=True, group_alive=True, unsafe_groups=list(ns["UNSAFE_GROUPS"]))
            assert not ns["UNSAFE_GROUPS"]
        finally:
            os.waitpid = real_wait
    record["workspace_deleted_while_owned_processes_alive"] = not work.exists()
    assert record["workspace_deleted_while_owned_processes_alive"]
finally:
    os.waitpid = real_wait
    if owned_worker:
        os.kill(owned_worker[0], signal.SIGKILL)
        real_wait(owned_worker[0], 0)
    if "group" in record:
        os.killpg(record["group"], signal.SIGKILL)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                while real_wait(-record["group"], os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
            if not ns["group_alive"](record["group"]):
                break
            time.sleep(.02)
        else:
            raise RuntimeError("independent historical-reproducer containment failed")
        record.update(independent_outer_cleanup=True, worker_reaped=True, group_absent=True)
(dest / "reproduction.json").write_text(json.dumps(record, indent=2) + "\n")
print("REPRODUCED: parent interruption leaked worker/group and deleted workspace; outer owner contained/reaped.")
