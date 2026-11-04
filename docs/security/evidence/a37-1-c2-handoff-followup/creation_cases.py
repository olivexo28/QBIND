#!/usr/bin/env python3
"""Live creation-boundary tests with independent bounded outer containment."""
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import shutil

DEST = Path(sys.argv[1]).resolve()
DEST.mkdir(parents=True, exist_ok=False)
SOURCE = "scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh"
driver = Path(SOURCE).read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
prefix = driver[:driver.index("\ntry:\n    validate_process_visibility()")]
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
results = []
for route in ("case", "visibility"):
    for mode in ("init_exception", "handoff_interrupt", "creation_INT", "creation_TERM",
                 "child_mask", "unresolved"):
        folder = DEST/(route+"-"+mode)
        folder.mkdir()
        tester = os.fork()
        if tester == 0:
            try:
                sys.argv = ["fixture", str(folder/"driver")]
                ns = {}
                exec(compile(prefix, SOURCE, "exec"), ns)
                ns["validate_process_visibility"]()
                init = subprocess.Popen.__init__
                cleanup = ns["cleanup_group"]
                parent = os.getpid()
                original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                child_code = (
                    "import json,pathlib,signal,sys,time;"
                    "pathlib.Path(sys.argv[1]).write_text(json.dumps(sorted(int(s) for s in "
                    "signal.pthread_sigmask(signal.SIG_BLOCK,set()))));time.sleep(30)")

                def injected_init(self, args, **kwargs):
                    # Preserve the actual owner's exec launcher and its mask restoration.
                    args = args[:3]+[sys.executable, "-c", child_code, str(folder/"child-mask")]
                    kwargs.pop("cwd", None)
                    kwargs.pop("env", None)
                    init(self, args, **kwargs)
                    (folder/"identity.json").write_text(json.dumps(dict(child=self.pid)))
                    until = time.monotonic()+3
                    while not (folder/"child-mask").exists() and time.monotonic() < until:
                        time.sleep(.005)
                    assert (folder/"child-mask").exists()
                    if mode == "init_exception":
                        raise RuntimeError("injected post-spawn initialization exception")
                    if mode == "child_mask":
                        raise ValueError("mask control completed; end inert case before body")
                    if mode.startswith("creation_"):
                        os.kill(parent, getattr(signal, "SIG"+mode.split("_")[1]))

                def interrupt_trace(frame, event, arg):
                    if (mode in ("handoff_interrupt", "unresolved") and event == "line"
                            and frame.f_code.co_name == "owned_process"
                            and getattr(frame.f_locals.get("p"), "pid", None)
                            and not (folder/"injected").exists()):
                        (folder/"injected").write_text("handoff")
                        raise KeyboardInterrupt("injected owned creation handoff")
                    return interrupt_trace

                if mode == "unresolved":
                    def refusal(*args, **kwargs):
                        raise RuntimeError("deliberately unresolved child containment")
                    ns["cleanup_group"] = refusal
                subprocess.Popen.__init__ = injected_init
                sys.settrace(interrupt_trace)
                caught = None
                observed = []
                rmtree = shutil.rmtree
                def deletion(path, *args, **kwargs):
                    identity = json.loads((folder/"identity.json").read_text())
                    assert not ns["group_alive"](identity["child"])
                    assert not Path("/proc", str(identity["child"])).exists()
                    observed.append(dict(path=str(path), kernel_absent_before_delete=True))
                    return rmtree(path, *args, **kwargs)
                shutil.rmtree = deletion
                try:
                    with ns["fixture_workspace"]() as work:
                        try:
                            if route == "case":
                                ns["run_case"](work, 216, "candidate", "before_INT", b"#!/bin/bash\n", ["inert"])
                            else:
                                with ns["owned_process"]([sys.executable, "-c", "pass"], {},
                                                         "visibility-probe", start_new_session=True):
                                    pass
                        except BaseException as error:
                            caught = error
                finally:
                    sys.settrace(None)
                    subprocess.Popen.__init__ = init
                    shutil.rmtree = rmtree
                identity = json.loads((folder/"identity.json").read_text())
                child = identity["child"]
                assert json.loads((folder/"child-mask").read_text()) == sorted(int(s) for s in original_mask)
                assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask
                record = dict(route=route, mode=mode, child=child, error=repr(caught),
                              notes=getattr(caught, "__notes__", []), workspace=str(work),
                              workspace_retained=work.exists(), deletion_observations=observed,
                              mask_restored=True, child_inherited_original_mask=True,
                              unsafe=sorted(ns["UNSAFE_GROUPS"]),
                              producing_commit=ns["META"]["producing_commit"],
                              fixture_sha256=ns["META"]["fixture_sha256"])
                if mode == "unresolved":
                    assert caught and work.exists() and ns["UNSAFE_GROUPS"] and ns["group_alive"](child)
                    for entry in ("run_case", "owned_process"):
                        try:
                            if entry == "run_case": ns[entry](None, 216, "candidate", "unused", b"", [])
                            else:
                                with ns[entry]([], {}, "refuse"):
                                    pass
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError("unsafe reuse accepted")
                    record["cleanup_pass"] = False
                else:
                    assert not work.exists() and not ns["group_alive"](child)
                    assert not Path("/proc", str(child)).exists() and observed
                    try:
                        os.waitpid(child, os.WNOHANG)
                    except ChildProcessError:
                        record["child_reaped"] = True
                    else:
                        raise AssertionError("child not reaped")
                    record["cleanup_pass"] = True
                    if mode != "child_mask": assert caught is not None
                (folder/"result.json").write_text(json.dumps(record, indent=2)+"\n")
                os._exit(0)
            except BaseException as error:
                (folder/"error.txt").write_text(repr(error))
                os._exit(1)
        deadline = time.monotonic()+10
        status = None
        while time.monotonic() < deadline:
            found, value = os.waitpid(tester, os.WNOHANG)
            if found:
                status = value
                break
            time.sleep(.02)
        rescued = []
        if (folder/"identity.json").exists():
            child = json.loads((folder/"identity.json").read_text())["child"]
            try:
                os.killpg(child, 0)
            except ProcessLookupError:
                pass
            else:
                rescued.append(child)
                os.killpg(child, signal.SIGKILL)
            until = time.monotonic()+3
            while time.monotonic() < until:
                try:
                    os.waitpid(child, os.WNOHANG)
                except ChildProcessError:
                    pass
                if not Path("/proc", str(child)).exists():
                    break
                time.sleep(.02)
            else:
                raise RuntimeError("outer containment failed")
        if status is None:
            os.kill(tester, signal.SIGKILL)
            os.waitpid(tester, 0)
        record = json.loads((folder/"result.json").read_text()) if (folder/"result.json").exists() else {}
        record.update(outer_status=status, outer_rescues=rescued)
        results.append(record)
        (DEST/"results.json").write_text(json.dumps(results, indent=2)+"\n")
        assert status == 0, (route, mode, (folder/"error.txt").read_text()
                             if (folder/"error.txt").exists() else "outer timeout; failed cleanup test")
        if mode == "unresolved":
            assert rescued and not record["cleanup_pass"]
            shutil.rmtree(Path(record["workspace"]))
        else:
            assert not rescued, "outer rescue is failed tested cleanup"
        print(route, mode, "CLEANUP PASS" if record["cleanup_pass"] else "EXPECTED CLEANUP FAILURE; outer rescue", flush=True)
