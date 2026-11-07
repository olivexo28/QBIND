"""Observe isolated real-engine tests with an outer deadline and child reaping."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import time


CASES = [
    "state_self_cycle_outside_candidate",
    "state_multi_cycle_outside_candidate",
    "proposal_self_cycle_outside_candidate",
    "proposal_multi_cycle_outside_candidate",
    "verified_refusal_retains_exact_evidence_and_earlier_effects",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("producer")
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    results = {
        "producer": args.producer,
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "outer_timeout_seconds": 3,
        "cases": [],
    }
    for case in CASES:
        argv = [str(binary), "--exact", case, "--nocapture"]
        start = time.monotonic()
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            output, _ = child.communicate(timeout=3)
            observation = "RETURNED"
        except subprocess.TimeoutExpired:
            child.kill()
            output, _ = child.communicate(timeout=3)
            observation = "TIMEOUT"
        (args.output / (case + ".log")).write_bytes(output)
        row = {
            "argv": argv,
            "case": case,
            "observation": observation,
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "returncode": child.returncode,
            "child_reaped": child.poll() is not None,
        }
        results["cases"].append(row)
        print(json.dumps(row), flush=True)
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    # Timeout is only an observation. It is never a passing test.
    print("Passing returned tests:", sum(
        row["observation"] == "RETURNED" and row["returncode"] == 0
        for row in results["cases"]
    ))


if __name__ == "__main__":
    main()
