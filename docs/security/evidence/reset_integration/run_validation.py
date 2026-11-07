#!/usr/bin/env python3
"""Retain exact command output and status for this synthetic candidate."""

import argparse
import datetime
import json
import os
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("label")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required")
    evidence = Path(__file__).resolve().parent
    root = evidence.parents[3]
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log = evidence / f"{args.label}.log"
    if log.exists() or (evidence / f"{args.label}.json").exists():
        parser.error("use a new label; prior attempts must not be overwritten")
    with log.open("wb") as output:
        result = subprocess.run(
            command, cwd=root, stdout=output, stderr=subprocess.STDOUT, check=False
        )
    record = {
        "command": command,
        "shell_display": shlex.join(command),
        "cwd": str(root),
        "started_utc": started,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "exit_code": result.returncode,
        "log": log.name,
        "environment_overrides": {
            key: os.environ[key]
            for key in ("CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "QBIND_I1_BASELINE")
            if key in os.environ
        },
    }
    (evidence / f"{args.label}.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(record, indent=2))
    print(log.read_text(encoding="utf-8", errors="replace")[-6000:])
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
