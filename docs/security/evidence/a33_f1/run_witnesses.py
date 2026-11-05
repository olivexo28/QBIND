"""Run engine witnesses as isolated children, never as a node/network harness."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import time


CASES = [
    "locked_self_cycle_outside_candidate",
    "locked_multi_cycle_outside_candidate",
    "own_qc_self_cycle_outside_candidate",
    "own_qc_multi_cycle_outside_candidate",
    "registration_before_vote_catchup_witness_scaled",
    "registration_before_vote_catchup_witness_default_capacity",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("producer")
    parser.add_argument("expected", choices=["timeout", "return"])
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    results = {
        "producer": args.producer,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "outer_timeout_seconds": 3,
        "cases": [],
    }
    for case in CASES:
        start = time.monotonic()
        child = subprocess.Popen(
            [str(binary), "--exact", case, "--nocapture"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            output, _ = child.communicate(timeout=3)
            observation = "RETURNED"
        except subprocess.TimeoutExpired:
            child.kill()
            output, _ = child.communicate(timeout=3)
            observation = "TIMEOUT"
        (args.output / (case + ".log")).write_bytes(output)
        row = {
            "case": case,
            "observation": observation,
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "child_returncode": child.returncode,
            "child_reaped": child.poll() is not None,
        }
        results["cases"].append(row)
        print(json.dumps(row), flush=True)
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    if args.expected == "timeout":
        matched = all(row["observation"] == "TIMEOUT" for row in results["cases"])
    else:
        matched = all(
            row["observation"] == "RETURNED"
            and row["child_returncode"] == 0
            and b"1 passed; 0 failed" in (args.output / (row["case"] + ".log")).read_bytes()
            for row in results["cases"]
        )
    raise SystemExit(0 if matched else 1)


if __name__ == "__main__":
    main()
