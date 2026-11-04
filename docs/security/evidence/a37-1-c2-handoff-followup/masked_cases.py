#!/usr/bin/env python3
"""Repeat actual inert tests with a nonempty inherited signal mask."""
import runpy
import signal
import json
from pathlib import Path

old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
exists = Path.exists
def ready(path):
    if path.name != "child-mask":
        return exists(path)
    if not exists(path):
        return False
    try:
        json.loads(path.read_text())
    except json.JSONDecodeError:
        return False
    return True

Path.exists = ready
try:
    runpy.run_path("docs/security/evidence/a37-1-c2-handoff-followup/creation_cases.py", run_name="__main__")
finally:
    Path.exists = exists
    signal.pthread_sigmask(signal.SIG_SETMASK, old)
