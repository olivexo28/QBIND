#!/usr/bin/env python3
"""Exercise producing fixture ownership errors without any harness invocation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path.cwd()
source = root / "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh"
driver = source.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
prefix = driver[:driver.index("\ntry:\n    validate_process_visibility()")]
ns = {"__name__": "owner_error_checks"}
exec(compile(prefix, str(source), "exec"), ns)
dest = ns["DEST"]
ns["validate_process_visibility"]()
real_cleanup = ns["cleanup_group"]
records = []


def fail_after_cleanup(p):
    real_cleanup(p)
    raise RuntimeError("injected cleanup-report failure after independently contained group")


original = AssertionError("original live-driver assertion")
workspace = None
p = None
ns["cleanup_group"] = fail_after_cleanup
try:
    with ns["fixture_workspace"]() as workspace:
        supervision = {}
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"], start_new_session=True)
        with ns["owned_process"](p, supervision, "cleanup-error-preserves-original"):
            (workspace / "sentinel").write_text("must retain on reported cleanup failure\n")
            raise original
except AssertionError as observed:
    assert observed is original
    assert any("separate fixture cleanup failure" in note for note in observed.__notes__)
    assert "cleanup_error" in supervision
    assert workspace.is_dir() and (workspace / "sentinel").is_file()
    assert not ns["group_alive"](p.pid) and not ns["group_members"](p.pid)
    records.append(dict(case="cleanup_error", original=repr(observed), notes=observed.__notes__,
                        supervision=supervision, workspace_retained=True,
                        independently_group_absent=True, outer_rescue=False))
finally:
    ns["cleanup_group"] = real_cleanup
    if p is not None and ns["group_alive"](p.pid):
        # A rescue cannot turn this test into a pass.
        real_cleanup(p)
        raise AssertionError("owner-error test required independent rescue")
    if workspace is not None and workspace.exists():
        shutil.rmtree(workspace)
    if p is not None:
        ns["UNSAFE_GROUPS"].discard(p.pid)

# A failed evidence write must not mask the original driver exception either.
blocker = dest / "not-a-directory"
blocker.write_text("block evidence write\n")
ns["DEST"] = blocker
original = KeyboardInterrupt("original unexpected driver termination")
supervision = {}
p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"], start_new_session=True)
try:
    with ns["owned_process"](p, supervision, "evidence-error-preserves-original"):
        raise original
except KeyboardInterrupt as observed:
    assert observed is original
    assert any("separate supervision evidence failure" in note for note in observed.__notes__)
    assert not ns["group_alive"](p.pid) and not ns["group_members"](p.pid)
    records.append(dict(case="evidence_write_error", original=repr(observed), notes=observed.__notes__,
                        supervision=supervision, independently_group_absent=True, outer_rescue=False))
finally:
    ns["DEST"] = dest
    if ns["group_alive"](p.pid):
        real_cleanup(p)
        raise AssertionError("evidence-error test required independent rescue")

(dest / "results.json").write_text(json.dumps(dict(
    producing_commit=ns["META"]["producing_commit"], producing_tree=ns["META"]["producing_tree"],
    fixture_sha256=ns["META"]["fixture_sha256"], outcomes=records), indent=2) + "\n")
print("PASS: 2 owned-process error checks; original errors preserved; outer rescue=0")
