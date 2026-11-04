#!/usr/bin/env python3
"""Independently observe kernel quiescence at each actual workspace deletion."""
import json
import os
from pathlib import Path
import runpy
import shutil
import sys

dest = Path(sys.argv[1]).resolve()
real_rmtree = shutil.rmtree
log = dest.parent / (dest.name + "-deletion.jsonl")
assert not log.exists()


def observed_rmtree(path, *args, **kwargs):
    p = Path(path)
    if p.name.startswith("qbind-verdict-fixture-"):
        identities = []
        for identity in dest.glob("*/identity.json"):
            record = json.loads(identity.read_text())
            for group in (record["worker"], record["group"]):
                try:
                    os.killpg(group, 0)
                except ProcessLookupError:
                    continue
                raise AssertionError(("workspace deletion while owned group alive", str(p), group))
            for owned in (record["worker"], record["group"]):
                assert not Path("/proc", str(owned)).exists(), (str(p), owned)
            child_path = identity.parent / "child"
            if child_path.exists():
                child = int(child_path.read_text())
                assert not Path("/proc", str(child)).exists(), (str(p), child)
                record["child"] = child
            identities.append(record)
        with log.open("a") as f:
            f.write(json.dumps(dict(workspace=str(p), owned=identities,
                                   kernel_absent_before_rmtree=True, observer_pid=os.getpid()))+"\n")
    return real_rmtree(path, *args, **kwargs)


shutil.rmtree = observed_rmtree
try:
    sys.argv = ["watchdog_cases.py", str(dest)]
    runpy.run_path("docs/security/evidence/a37-1-c2-supervisor-followup/watchdog_cases.py", run_name="__main__")
finally:
    shutil.rmtree = real_rmtree
