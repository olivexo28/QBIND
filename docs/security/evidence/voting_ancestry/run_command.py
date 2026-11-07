"""Retain exact validation argv, revision, UTC times, exit code and raw output."""

import datetime
import json
import pathlib
import subprocess
import sys


def main():
    prefix = pathlib.Path(sys.argv[1])
    argv = sys.argv[2:]
    if not argv or prefix.with_suffix(".json").exists():
        raise SystemExit("Require command and a fresh output prefix")
    prefix.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "argv": argv,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(),
        "status": subprocess.check_output(["git", "status", "--porcelain=v1"], text=True),
        "start_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    with prefix.with_suffix(".log").open("wb") as output:
        result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT)
    record["end_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    record["exit_code"] = result.returncode
    prefix.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
