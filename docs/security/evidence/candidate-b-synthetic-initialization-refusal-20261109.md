# QBIND — Synthetic initialization-refusal oracle evidence

**SYNTHETIC TEST-ONLY MODEL — NOT ADAPTER ENFORCEMENT.** This evidence
records a self-contained model of the independently reviewed
required-persistence initialization contract. The model tests one checker
against success, identifiable refusal, explicit memory, fallback, ordering,
instance correlation, pending/infrastructure outcomes, and worker
termination states. It does not call the production execution adapter or
storage APIs and adds no production observation seam.

The prior path-encoding baseline remains not integration-ready, with its
four recorded contract failures unchanged. The corrected consensus
result-category oracle remains CLOSED within its test scope. The
no-replacement-database finding, CB-1, and CB-FIXTURE-1 remain within
their accepted scopes. A23-F1 and A33-F1 / E27 remain OPEN; activation
remains DISABLED; public DevNet remains NO-GO.

## Pinned basis and source identity

| Item | Identity |
|---|---|
| Reviewed specification endpoint | `c2b86892fb2235a593cdea9d829a7cf861345d08`, tree `38dd8c876e9610db530c9084c5ed6dbbddd1006a` |
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Test source at compile and run | `6c94eaa340965d6d0986e2ba403b5bb90a7e4b54`, tree `ed1adabebb5b08e6c63ff0dc49141865b23197dc`, parent `c2b86892fb2235a593cdea9d829a7cf861345d08` |
| Test source blob | `crates/qbind-node/tests/candidate_b_synthetic_initialization_refusal_tests.rs`: `0fd980cc1dbf5cff39e7022c0e8b22e9c3514c13` |
| Reviewed initialization specification | `docs/security/evidence/candidate-b-required-persistence-initialization-spec-20261109.md` at `c2b86892fb2235a593cdea9d829a7cf861345d08` |
| Reviewed current-adapter assessment | `docs/security/evidence/candidate-b-adapter-refusal-observability-assessment-20261109.md` at `b2b5378a705e7cbdd8e087f636107029785b0f48` |
| Historical adapter and path-baseline evidence | Reviewed test endpoint `2c387809e9a58d80ff9e9a92d7e14708f824f6aa`; raw logs are preserved there and were not rerun or changed |

The synthetic file uses local Rust structs/enums and one `classify`
function. All ten tests invoke that same checker. The model has no imports
from `qbind-node`, `qbind-ledger`, or the real adapter; this isolates the
oracle but necessarily limits the evidence to model behavior.

## Commands, output, and environment

The test source was committed before compilation. Build and temporary
files were isolated below `/tmp/qbind-synthetic-init-refusal.tqXzr2`.
Commands from the repository root:

```text
ROOT=$(mktemp -d /tmp/qbind-synthetic-init-refusal.XXXXXX); printf '%s\n' "$ROOT" > /tmp/qbind-synthetic-init-refusal-runroot.txt; mkdir -p "$ROOT/tmp"; CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_synthetic_initialization_refusal_tests --no-run > "$ROOT/compile.log" 2>&1; status=$?; printf 'RUN_ROOT=%s\n' "$ROOT"; printf 'EXIT_STATUS=%s\n' "$status"; cat "$ROOT/compile.log"; exit "$status"
  exit status: 0

ROOT=$(cat /tmp/qbind-synthetic-init-refusal-runroot.txt); CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_synthetic_initialization_refusal_tests -- --nocapture > "$ROOT/focused.log" 2>&1; status=$?; printf 'RUN_ROOT=%s\n' "$ROOT"; printf 'EXIT_STATUS=%s\n' "$status"; cat "$ROOT/focused.log"; exit "$status"
  exit status: 0
```

Full outputs, including warnings and final exit-status lines:

- [`compile output`](candidate-b-synthetic-initialization-refusal-compile-20261109.txt),
  SHA-256 `7392ec27480c09f113f56dec3f55a304649093c5fa1e9c390bf3be7553742721`
- [`focused output`](candidate-b-synthetic-initialization-refusal-focused-20261109.txt),
  SHA-256 `d934650f5644890a3a4b82ea1cb3ed5d04babf7597ff35eae3382c00251444a7`

The compile-only command succeeded. The focused run executed **10 passed,
0 failed, 0 ignored**. No compile, infrastructure, or test failures
occurred. No unchanged historical test target or full suite was rerun.

Environment observed: Linux `x86_64`, kernel `6.12.8+`, ext4 on `/dev/vdb`;
`rustc 1.99.1 (58cf8f9c3 2026-10-13)` and
`cargo 1.99.1 (5f94df478 2026-08-27)`. Cargo.lock SHA-256:
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`.
`cargo tree --locked -p qbind-node -i rocksdb` resolved
`rocksdb v0.22.0`; this pure model does not use RocksDB. No independent
archive identity claim is made.

## Model assertions and results

The checker classifies each synthetic trace as persistent ready,
explicit-memory ready, persistent-open refused, contract violation, or
inconclusive. Refusal requires a failed open for the same initialization
identifier, an identifiable persistent-open refusal, no submitted work,
and either no worker or an observed terminated worker. Publication as
persistent requires a successful open for the same identifier at a
strictly earlier sequence number. Requested-persistence publication as
in-memory is rejected.

| Test control | Result | What it establishes in the model |
|---|---|---|
| `matching_persistent_open_precedes_same_instance_availability` | Passed | Matching successful open precedes publication of the persistent capability. |
| `open_failure_is_identifiable_early_refusal_without_submission` | Passed | An early refusal can be valid with no service publication and no attempted submission. |
| `explicitly_selected_in_memory_is_a_separate_positive_case` | Passed | Explicit memory configuration is separately accepted, with no persistent open. |
| `fallback_after_requested_persistent_open_failure_is_rejected` | Passed sensitivity | The checker rejects an executable in-memory publication after requested persistent open failure. |
| `publication_before_matching_open_success_is_rejected` | Passed sensitivity | The checker rejects publication before the matching open succeeds. |
| `another_initializations_open_cannot_satisfy_this_instance` | Passed sensitivity | Another initialization's successful open cannot authorize this instance. |
| `another_initializations_failed_open_cannot_satisfy_this_refusal` | Passed sensitivity | Another initialization's failed open cannot justify this instance's refusal. |
| `pending_timeout_panic_missing_response_and_setup_failure_are_not_refusal` | Passed sensitivity | Pending, timeout, panic, missing response, setup failure, and unrelated setup refusal classify as inconclusive, not successful persistent-open refusal. |
| `started_worker_must_terminate_or_refusal_remains_unresolved` | Passed sensitivity | Observed termination permits the modeled refusal; running, cancellation requested, waiter dropped, or unknown remain inconclusive. |
| `refusal_with_submitted_work_is_not_an_early_refusal` | Passed sensitivity | An alleged early refusal after submission is rejected as a contract violation. |

These are model assertions, not observations of a real service, storage
open, thread, cancellation, timeout, panic, or termination. In particular,
the synthetic `Terminated` value is only an input to the checker; the test
does not create or join a worker.

## Limits and preserved findings

The model does **not** establish actual adapter enforcement, real worker
termination, persistent-storage durability, exact service-publication
ordering in production, normal P2P startup ordering, or node reachability.
It does not resolve a public API, error type, worker ownership mechanism,
or production observation seam. It does not prove that the current
execution adapter refuses on open failure; retained actual-adapter
characterization instead records fallback and remains historical evidence.

The model does not alter or reclassify prior baseline results. Its green
synthetic focused run does not make the prior path-encoding branch
integration-ready and does not change the accepted four contract failures.
No production code, existing tests, manifests, lockfiles, or historical
evidence were changed. No node was started, no operational keys were used,
and no provisioning, PR, merge, or deployment occurred.
