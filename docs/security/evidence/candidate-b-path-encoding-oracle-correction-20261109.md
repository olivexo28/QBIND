# QBIND — Path-encoding test-oracle correction

**TEST-ONLY CHARACTERIZATION — NOT PRODUCTION ENFORCEMENT.** This evidence
corrects two test-control gaps identified in review of the prior baseline:
the consensus open oracle now rejects every `Ok`, including `Ok(None)`, and
a separate adapter test asserts that a requested persistent-open failure
must not execute transactions in memory. The earlier baseline's accepted
observations and raw logs are preserved unchanged.

The prior baseline remains **PASS WITH LIMITATIONS** as an author-run
characterization and **FAIL** against the proposed refusal contract. This
branch does not make the baseline or crate integration-ready. The
no-replacement-database finding, CB-1, and CB-FIXTURE-1 remain within their
accepted scopes. No destination authority, object binding, race
resistance, fencing, recovery, or Candidate B enforcement follows.
A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED; public
DevNet remains NO-GO.

## Pinned revisions and changed scope

| Item | Identity |
|---|---|
| Reviewed baseline endpoint | `e5820cec9b942002c95dc14eeb22a1302f3e9a63`, tree `ef1adec8184a3b14e4d5f4e13aec498b956608a9` |
| Pinned main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Source commit used for final compile and run | `ba8465e5dfe57ef7a9f5e1f14ba1c932985f2446`, tree `652990423e7c3c611ebc0ef85157e0cccc4f8871`, parent `6dd49f892c1872f6b33e2b8fad8ddb9ddcac0287` |
| Test source blob at final compile and run | `crates/qbind-node/tests/candidate_b_storage_path_encoding_baseline_tests.rs`: `e4eeb601169562ea476b88f9b952c72307990780` |
| Earlier accepted baseline evidence | `docs/security/evidence/candidate-b-path-encoding-baseline-20261109.md` at reviewed endpoint `e5820cec9b942002c95dc14eeb22a1302f3e9a63` |

Relative to the reviewed endpoint, the completed correction adds three
commits and changes four paths: the existing test source, this report, and
the two new full-output logs. Relative to main, the branch contains the
inherited specifications, tests, and evidence as well as this correction;
the correction slice must not be described as the entire main-relative
package.

## Commands, inputs, and environment

The final source was committed before both commands. The isolated run root
was `/tmp/qbind-path-oracle-correction.HABJDd`, with its `tmp` and Cargo
target directories below that root. Exact commands:

```text
ROOT=$(cat /tmp/qbind-path-oracle-correction-runroot.txt); CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_storage_path_encoding_baseline_tests --no-run > "$ROOT/final-compile.log" 2>&1; status=$?; printf 'RUN_ROOT=%s\n' "$ROOT"; printf 'EXIT_STATUS=%s\n' "$status"; tail -30 "$ROOT/final-compile.log"; exit "$status"
  exit status: 0 (later appended to the retained full output)

ROOT=$(cat /tmp/qbind-path-oracle-correction-runroot.txt); CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_storage_path_encoding_baseline_tests -- --nocapture > "$ROOT/final-focused.log" 2>&1; status=$?; printf 'RUN_ROOT=%s\n' "$ROOT"; printf 'EXIT_STATUS=%s\n' "$status"; tail -115 "$ROOT/final-focused.log"; exit "$status"
  exit status: 101 (later appended to the retained full output)
```

The complete command outputs, including recorded exit statuses, are
retained at [`compile output`](candidate-b-path-encoding-oracle-correction-compile-20261109.txt)
(SHA-256 `44ea2fa3429a01e3370e2d17f0c29ec73882b06ba796c3440a3de0ed7b368691`)
and [`focused output`](candidate-b-path-encoding-oracle-correction-focused-20261109.txt)
(SHA-256 `607a217bc4a8c687fc4debfd9cd7d3a6724d11a822a0bb798da4078433a3c5e3`).
The `--no-run` build succeeded. The focused target ran 7 tests: 3 passed,
4 failed, 0 ignored. It was not a full crate suite.

Observed environment: Linux x86_64, kernel `6.12.8+`, ext4 on `/dev/vdb`;
`rustc 1.99.1 (58cf8f9c3 2026-10-13)` and `cargo 1.99.1 (5f94df478
2026-08-27)`. `cargo tree --locked -p qbind-node -i rocksdb` resolved
`rocksdb v0.22.0`; Cargo.lock SHA-256 was
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`.
No independent archive identity claim is made. The invalid-byte tests are
Unix-only and ran on this Linux filesystem; other platforms are untested.

## Consensus open-result oracle

`consensus_nonrepresentable_path_contract_baseline` now retains the
actual `Result` category. An `Ok` is inspected as a successful open,
including its epoch value; an `Err` is logged using the error's actual
`Debug` and `Display` representations. The contract assertion accepts only
`Err`. Path-tree and lossy-fixture observations remain separate from this
result-category assertion.

The new sensitivity control opens a real, valid empty consensus database,
observes `get_current_epoch() == Ok(None)`, and confirms that
`consensus_open_is_refusal` returns false for the successful `Ok`. This
proves that an empty success cannot satisfy the refusal oracle; it is not a
test of an error-category implementation.

On the non-representable raw ancestor, the actual consensus API returned
`Ok` with epoch `Some(305419896)` from the lossy-spelling fixture. The
refusal assertion failed. This rejects the contract independently of
filesystem observations; the test also observed raw-path effects and
changed lossy database entries. Those filesystem observations do not prove
the exact wrapper call or establish a pre-wrapper boundary.

No path-encoding error was returned for the tested invalid path, so no
encoding-specific classification could be checked. The current consensus
`StorageError` exposes `Io`, `Codec`, `IncompatibleSchema`, `Corruption`,
`IncompleteEpochTransition`, and `Other`; no path-encoding variant exists
in the pinned source. A separate ordinary parent-file control returned
`Io("Failed to create RocksDB directory: ... NotADirectory ...")`, with
display text `storage I/O error: Failed to create RocksDB directory:
... Not a directory`. That ordinary I/O diagnostic is not evidence of a
path-encoding refusal. A future distinguishable encoding error requires
an owner-approved error contract and implementation; no variant or exact
message is invented here.

## Adapter refusal oracle and observation limit

The prior passing test remains a historical characterization:
with a configured persistent path blocked by a regular file, the public
adapter logged fallback to in-memory and applied one transaction. Its
separate explicitly selected in-memory control also applied one
transaction. The former passing assertion is not contract conformance.

The new `execution_adapter_requested_persistent_failure_requires_refusal`
test separately submits a block with persistent storage requested and
asserts that zero transactions are applied. On this run, one transaction
was applied, so the new conformance assertion failed (`left: 1`,
`right: 0`) as required to detect the observed fallback.

This is the maximum meaningful observation available through the tested
public API without a new seam: `submit_block` reports enqueue success,
while `ExecutionMetrics` exposes applied transaction counts. There is no
returned worker startup/open/refusal result or completion signal for a
refused block. The test samples for up to three seconds; a zero count would
mean only that no transaction was observed in that window, not that the
adapter affirmatively refused. Therefore a future passing zero-count
assertion alone would not prove refusal or distinguish it from stalled or
unprocessed work. A production refusal result/observable completion
contract or a separately approved test seam is still needed for a
positive refusal claim. This actual-adapter test is not a synthetic model.
Nothing establishes that ordinary P2P startup reaches this adapter.

## Results and limitations

| Test/control | Result | Meaning |
|---|---|---|
| `consensus_refusal_oracle_rejects_successful_empty_database` | Passed | Actual `Ok` plus absent epoch is rejected by the result-category refusal oracle. |
| Existing `execution_adapter_persistent_failure_falls_back_but_memory_is_explicit` | Passed characterization | Actual adapter fallback and explicit in-memory behavior were both observed; fallback is not accepted as conformance. |
| `representable_paths_and_ordinary_storage_errors_control` | Passed | Existing UTF-8 positive controls and ordinary errors remained distinguishable; ordinary storage errors are not path-encoding errors. |
| `account_create_nonrepresentable_path_contract_baseline` | Failed | Existing raw-path effects violate the proposed refusal-before-effects assertion. |
| `account_existing_only_nonrepresentable_path_contract_baseline` | Failed | Actual API returned the distinguishable lossy marker and filesystem entries changed. |
| `consensus_nonrepresentable_path_contract_baseline` | Failed | Actual API returned `Ok(Some(0x12345678))`; the corrected oracle rejected it. |
| `execution_adapter_requested_persistent_failure_requires_refusal` | Failed | Actual adapter applied one transaction after configured persistent open failure; the zero-applied assertion rejected the fallback. |

The three storage contract failures preserve the accepted baseline
observations; they are not passing tests. The new adapter refusal failure
is also an observed contract mismatch. Since the intentional failures are
in the ordinary Cargo integration-test target, default discovery of this
target remains red and this branch is not integration-ready.

The test does not establish same-captured-path identity, wrapper-call
absence, pre-wrapper refusal, all backend effects, or startup ordering.
No node was started and no startup path was exercised. The bounded metric
window cannot positively prove adapter refusal. No production source,
manifest, lockfile, operational key, or historical evidence was modified;
no migration, provisioning, deployment, PR, or merge was performed.
