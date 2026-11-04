#!/usr/bin/env python3
"""Pinned handoff reproduction; separate outer owner contains the inert child."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

REV = "551e7cdd08eb01ce05914c4bba49562d8901b7ec"
SOURCE = "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh"
driver = subprocess.check_output(["git", "show", REV+":"+SOURCE]).decode().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
ns = {}
exec(compile(driver[:driver.index("\ntry:\n    validate_process_visibility()")], SOURCE, "exec"), ns)
dest = ns["DEST"]
real_popen = subprocess.Popen
owned = []
original_owner = ns["owned_process"]


def inert(*args, **kwargs):
    p = real_popen([sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True)
    owned.append(p)
    return p


def interrupt_handoff(*args):
    raise KeyboardInterrupt("injected after Popen return before ownership entry")


ns["owned_process"] = interrupt_handoff
subprocess.Popen = inert
record = {"revision": REV, "kind": "isolated function probe, not full harness"}
try:
    with ns["fixture_workspace"]() as work:
        try:
            ns["run_case"](work, 216, "candidate", "before_INT", b"#!/bin/bash\n", ["inert"])
        except KeyboardInterrupt as error:
            p = owned[0]
            os.killpg(p.pid, 0)
            record.update(original_error=repr(error), child=p.pid, child_alive=p.poll() is None,
                          unsafe_groups=sorted(ns["UNSAFE_GROUPS"]))
    record["workspace_deleted_while_child_alive"] = not work.exists()
    assert record["child_alive"] and not record["unsafe_groups"] and record["workspace_deleted_while_child_alive"]
finally:
    subprocess.Popen = real_popen
    for p in owned:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(timeout=3)
        assert not ns["group_alive"](p.pid)
    record["outer_rescue_required"] = True
    record["outer_reaped_group_absent"] = True
(dest/"reproduction.json").write_text(json.dumps(record, indent=2)+"\n")
print("REPRODUCED: unowned live child and workspace deletion; separate outer rescue/reaping required.")
