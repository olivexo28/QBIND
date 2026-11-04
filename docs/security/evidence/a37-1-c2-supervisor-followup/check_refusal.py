#!/usr/bin/env python3
"""Verify unsafe state refuses both entry routes before process creation."""
import json
import os
from pathlib import Path
import subprocess
import sys

source = Path("scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh")
driver = source.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
prefix = driver[:driver.index("\ntry:\n    validate_process_visibility()")]
ns = {"__name__": "unsafe_refusal"}
exec(compile(prefix, str(source), "exec"), ns)
dest = ns["DEST"]
ns["UNSAFE_GROUPS"].add(os.getpid())
real_fork, real_pipe, real_popen = os.fork, os.pipe, subprocess.Popen
attempts = []


def forbidden(*args, **kwargs):
    attempts.append("process/pipe creation attempted")
    raise RuntimeError("unsafe-state refusal occurred too late")


os.fork = os.pipe = subprocess.Popen = forbidden
outcomes = []
try:
    for name in ("run_case", "supervisor_negative"):
        try:
            ns[name](None, 216, "candidate", "unused", b"", []) if name == "run_case" else ns[name](
                None, 216, "supervisor_wrong_phase", b"", [])
        except AssertionError as error:
            assert "unsafe cleanup" in str(error)
            outcomes.append(dict(entry=name, refused=repr(error)))
        else:
            raise AssertionError("unsafe state accepted")
    assert not attempts
finally:
    os.fork, os.pipe, subprocess.Popen = real_fork, real_pipe, real_popen
(dest/"results.json").write_text(json.dumps(dict(
    producing_commit=ns["META"]["producing_commit"], fixture_sha256=ns["META"]["fixture_sha256"],
    launch_attempts=attempts, outcomes=outcomes), indent=2)+"\n")
print("PASS: unsafe state refuses case and watchdog entry; zero process/pipe launches")
