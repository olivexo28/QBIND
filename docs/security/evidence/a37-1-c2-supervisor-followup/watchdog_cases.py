#!/usr/bin/env python3
"""Inert parent-fault cases with a distinct bounded outer containment owner."""
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path.cwd()
DEST = Path(sys.argv[1]).resolve()
DEST.mkdir(parents=True, exist_ok=False)
SOURCE = "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh"
driver = Path(SOURCE).read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
prefix = driver[:driver.index("\ntry:\n    validate_process_visibility()")]
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
CASES = ["before_registration", "after_registration", "pipe_error", "wait_error",
         "parent_TERM", "parent_HUP", "malformed", "incomplete", "timeout", "unresolved_cleanup"]
results = []
for mode in CASES:
    case = DEST / mode
    case.mkdir()
    tester = os.fork()
    if tester == 0:
        try:
            sys.argv = ["fixture-functions", str(case / "driver")]
            ns = {"__name__": "watchdog_parent_faults"}
            exec(compile(prefix, SOURCE, "exec"), ns)
            ns["validate_process_visibility"]()
            real_wait, real_read, real_pipe, real_pidfd = os.waitpid, os.read, os.pipe, os.pidfd_open
            parent = os.getpid()
            owned_fds = []
            seen = False
            injected = False

            def pipe():
                fds = real_pipe()
                owned_fds.extend(fds)
                return fds

            def pidfd(pid, flags=0):
                fd = real_pidfd(pid, flags)
                owned_fds.append(fd)
                return fd

            def inert(work, *args):
                p = subprocess.Popen(
                    [sys.executable, "-c",
                     "import pathlib,subprocess,sys,time;"
                     "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(40)']);"
                     "pathlib.Path(sys.argv[1]).write_text(str(c.pid));time.sleep(40)",
                     str(case / "child")], process_group=0)
                (case / "identity.json").write_text(json.dumps(dict(
                    worker=os.getpid(), group=p.pid, session=os.getsid(0))))
                while not (case / "child").exists():
                    time.sleep(.005)
                fd = ns["WATCHDOG_REPORT_FD"]
                if mode != "before_registration":
                    os.write(fd, (json.dumps(dict(started_group=p.pid))+"\n").encode())
                if mode == "malformed":
                    os.write(fd, b'{"bad":\n')
                    os._exit(0)
                if mode == "incomplete":
                    os._exit(0)
                while True:
                    time.sleep(.1)

            def ready():
                return (case / "child").exists()

            def read(fd, count):
                global seen, injected
                if os.getpid() == parent and ready() and mode == "pipe_error" and not injected:
                    injected = True
                    raise OSError("injected parent pipe read failure")
                data = real_read(fd, count)
                if os.getpid() == parent and b"started_group" in data:
                    seen = True
                return data

            def wait(pid, flags):
                global injected
                if os.getpid() == parent and flags == os.WNOHANG and ready() and not injected:
                    if mode in ("before_registration", "unresolved_cleanup") or (
                            mode == "after_registration" and seen):
                        injected = True
                        raise KeyboardInterrupt("injected parent interruption "+mode)
                    if mode == "wait_error":
                        injected = True
                        raise OSError("injected parent wait failure")
                    if mode.startswith("parent_"):
                        injected = True
                        os.kill(parent, getattr(signal, "SIG"+mode.split("_")[1]))
                return real_wait(pid, flags)

            ns["run_case"] = inert
            if mode == "unresolved_cleanup":
                def refuse_cleanup(*args, **kwargs):
                    raise RuntimeError("injected unresolved containment; no success claimed")
                ns["cleanup_watchdog"] = refuse_cleanup
            os.pipe, os.read, os.waitpid, os.pidfd_open = pipe, read, wait, pidfd
            caught = None
            try:
                with ns["fixture_workspace"]() as work:
                    try:
                        ns["supervisor_negative"](work, 216, "supervisor_wrong_phase", b"", [])
                    except BaseException as error:
                        caught = error
                    else:
                        raise AssertionError("fault unexpectedly succeeded")
                assert caught is not None
            finally:
                os.pipe, os.read, os.waitpid, os.pidfd_open = real_pipe, real_read, real_wait, real_pidfd
            identity = json.loads((case / "identity.json").read_text())
            identity["child"] = int((case / "child").read_text())
            report = dict(mode=mode, original_error=repr(caught),
                          notes=getattr(caught, "__notes__", []), identity=identity,
                          workspace=str(work), workspace_exists=work.exists(),
                          unsafe_groups=sorted(ns["UNSAFE_GROUPS"]), descriptors=owned_fds)
            for fd in owned_fds:
                try:
                    os.fstat(fd)
                except OSError:
                    continue
                raise AssertionError(("descriptor still open", fd))
            report["descriptors_closed"] = True
            if mode == "unresolved_cleanup":
                assert work.exists() and ns["UNSAFE_GROUPS"] and report["notes"]
                assert ns["group_alive"](identity["group"])
                report["tested_cleanup"] = "FAILED; expected unresolved refusal; outer containment required"
            else:
                assert not work.exists() and not ns["UNSAFE_GROUPS"]
                assert not ns["session_members"](identity["worker"])
                assert not ns["group_alive"](identity["group"])
                assert not Path("/proc", str(identity["child"])).exists()
                try:
                    real_wait(identity["worker"], os.WNOHANG)
                except ChildProcessError:
                    report["worker_reaped"] = True
                else:
                    raise AssertionError("worker not reaped")
                report["tested_cleanup"] = "quiescent before workspace deletion"
            expected = {"before_registration": KeyboardInterrupt, "after_registration": KeyboardInterrupt,
                        "pipe_error": OSError, "wait_error": OSError, "malformed": json.JSONDecodeError,
                        "parent_TERM": InterruptedError, "parent_HUP": InterruptedError,
                        "incomplete": AssertionError, "timeout": AssertionError,
                        "unresolved_cleanup": KeyboardInterrupt}[mode]
            assert isinstance(caught, expected), (mode, repr(caught))
            (case / "result.json").write_text(json.dumps(report, indent=2)+"\n")
            os._exit(0)
        except BaseException as error:
            (case / "tester-error.txt").write_text(repr(error))
            os._exit(1)
    deadline = time.monotonic()+22
    status = None
    while time.monotonic() < deadline:
        found, value = os.waitpid(tester, os.WNOHANG)
        if found:
            status = value
            break
        time.sleep(.02)
    rescued = []
    identity_path = case / "identity.json"
    if identity_path.exists():
        identity = json.loads(identity_path.read_text())
        # Contain only this test's recorded owned session/group and worker.
        for pgid in (identity["worker"], identity["group"]):
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                continue
            rescued.append(pgid)
            os.killpg(pgid, signal.SIGKILL)
        until = time.monotonic()+3
        owned = {identity["worker"], identity["group"]}
        if (case / "child").exists():
            owned.add(int((case / "child").read_text()))
        while time.monotonic() < until:
            for pid in owned:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
            if all(not Path("/proc", str(pid)).exists() for pid in owned):
                break
            time.sleep(.02)
        else:
            raise RuntimeError(("outer containment failed", mode, owned))
    if status is None:
        os.kill(tester, signal.SIGKILL)
        os.waitpid(tester, 0)
    report = json.loads((case / "result.json").read_text()) if (case / "result.json").exists() else {}
    report.update(outer_status=status, outer_rescued_groups=rescued,
                  cleanup_pass=not rescued and status == 0 and mode != "unresolved_cleanup")
    results.append(report)
    (DEST / "results.json").write_text(json.dumps(results, indent=2)+"\n")
    assert status == 0, (mode, status, (case / "tester-error.txt").read_text())
    if mode == "unresolved_cleanup":
        assert rescued and not report["cleanup_pass"]
        # Deliberately retained workspace is removed only after outer quiescence.
        import shutil
        shutil.rmtree(Path(report["workspace"]))
    else:
        assert not rescued, ("outer rescue is a failed cleanup test", mode, rescued)
    print(mode, "PASS" if report["cleanup_pass"] else "EXPECTED CLEANUP FAILURE; outer rescue recorded", flush=True)
