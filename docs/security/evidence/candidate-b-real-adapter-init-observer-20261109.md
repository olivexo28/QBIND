# QBIND — Real-adapter initialization observer evidence

**TEST-ONLY CHARACTERIZATION — NOT REFUSAL CONFORMANCE.** The observer is
compiled only under `cfg(test)` and records events at the existing VM-v0
worker's actual `RocksDbAccountState::open` and backend-selection branches.
The tests use temporary paths and the real RocksDB open. No fake opener,
production refusal, public interface change, operational key, live node,
provisioning, PR, merge, or deployment was used.

The prior path-encoding branch remains not integration-ready. Actual
adapter refusal, same-path and pre-wrapper checks, backend effects, and
startup ordering remain OPEN. The synthetic checker remains limited to
truthful, well-formed supplied histories; it does not validate
contradictory or untrusted histories and is not evidence of actual adapter
behavior. A23-F1 and A33-F1 / E27 remain OPEN; activation remains
DISABLED; public DevNet remains NO-GO.

## Pinned revisions

| Item | Identity |
|---|---|
| Reviewed synthetic-checker endpoint | `049d84dbe164e3ea0c436c82eb0e75f2413f09ad`, tree `595a1db54672a5212e89fbd17360ab5571a159b5` |
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Source commit used by focused test and final library check | `e0f86a96f6a3ded7b720b119e200ba860f160c32`, tree `6b6ce315e7d26e6b956075e27709dd2210744a37`, parent `82ccbf3f3dd132dc7bcfaccfbaf3d5ba7b5c1a75` |
| Changed source blob at that commit | `crates/qbind-node/src/execution_adapter.rs`: `538c9940b32a192f9501a43a04741aaf598aafc7` |
| Current fallback and explicit-memory historical test | `crates/qbind-node/tests/candidate_b_storage_path_encoding_baseline_tests.rs` at reviewed endpoint `049d84dbe164e3ea0c436c82eb0e75f2413f09ad`, lines 377-417 |
| Existing adapter behavior | `crates/qbind-node/src/execution_adapter.rs` at `049d84dbe164e3ea0c436c82eb0e75f2413f09ad`, lines 910-1000 |

## What the observer establishes

The test-only event carries an initialization ID and worker ID. The test
helper allocates both from a process-local monotonic atomic counter and
installs a thread-local observer in the worker thread. Every event is
delivered over that initialization's private channel with both IDs
attached. Tests run successful and failing persistent opens concurrently,
assert the identifiers differ, and verify each receiver sees only its
own open result and backend selection.

At `execution_adapter.rs:934-988`, the observer records:

- persistent open attempted immediately before the existing
  `RocksDbAccountState::open(path)` call;
- success or failure from the actual `Result` match arm; and
- the backend branch selected by that same worker: persistent on success,
  in-memory on failure, or in-memory with no open attempt when memory was
  explicitly configured.

The four new tests at `execution_adapter.rs:1415-1510` establish:

| Case | Observed events and result |
|---|---|
| Valid temporary persistent path | Worker started; actual open attempted and succeeded; persistent backend selected; worker subsequently joined normally. |
| Temporary file used as parent of a persistent path | Worker started; actual open attempted and failed; in-memory fallback selected; worker subsequently joined normally. This is current behavior characterization, not desired conformance. |
| Explicit `vm_v0()` memory configuration | Worker started; in-memory backend selected with no persistent-open event; worker subsequently joined normally. |
| Two simultaneous initializations | Different initialization and worker IDs; each channel reports only its own real open result and selected backend. |

No submission is needed to observe these initialization branches. These
tests do not establish service readiness or availability ordering through
the public constructor, nor do they claim successful block execution,
durable flush, destination binding, complete filesystem effects, or
absence of wrapper calls.

## Worker lifetime and instrumentation limits

The test helper retains the actual `JoinHandle` and the task-channel sender.
With the sender retained, the test observes that `JoinHandle::is_finished`
does not become true before its short observation deadline and classifies
the worker as `UnresolvedAtDeadline`; it retains the handle. It then drops
the sender, allowing the existing worker loop to exit when `recv` sees
channel closure, and calls `join()`. The observed result is
`TerminatedNormally`. The worker loop's final log line is not used as
termination evidence.

The join-result mapper distinguishes a normal join from a panic
(`WorkerJoinOutcome::Panicked`). No panic was induced or observed in these
tests; panic classification is therefore available from the real join
result but is not a tested adapter-panic outcome. If the deadline expires,
the handle remains owned and termination is explicitly unresolved until
the later join. No cancellation request or dropped waiter is treated as
termination.

To retain a join handle without changing production shutdown or the public
constructor, the test helper starts the same private `worker_loop` with
the configured receiver and values, rather than calling
`SingleThreadExecutionService::with_config`, which discards its join
handle. Thus this evidence exercises the actual worker and open path, but
not the public constructor's lifecycle or service-availability boundary.
The test helper's private event-channel sends add scheduling points around
the open result and backend branch. They do not replace the opener or
alter the selection branch, but this test-only schedule is not evidence
about release-build timing.

All event definitions, the thread-local observer, instrumentation calls,
helper, and tests are under `cfg(test)`. The source diff against the
reviewed endpoint contains only those test-gated additions (plus a final
newline); the actual open call, match branches, fallback behavior, public
API, readiness, shutdown, and production wiring are unchanged. The
non-test library check below passed with the instrumentation compiled
out. This source comparison does not imply anything about release-build
runtime timing beyond the absence of the test-only code.

## Commands, outputs, and environment

Commands ran from the repository root with the following common
environment:

```text
CARGO_TARGET_DIR=/tmp/qbind-synthetic-checker-correction.8lNhI8/target
TMPDIR=/tmp/qbind-real-adapter-observer.rqaAzt/tmp
```

The full Cargo outputs, including warnings and test logs, are retained as
separate files:

| Command | Exit | Output file | SHA-256 |
|---|---:|---|---|
| `CARGO_TARGET_DIR=/tmp/qbind-synthetic-checker-correction.8lNhI8/target TMPDIR=/tmp/qbind-real-adapter-observer.rqaAzt/tmp cargo check --locked -p qbind-node --lib` | 0 | [`library check`](candidate-b-real-adapter-init-observer-library-check-20261109.txt) | `4bc86d89984842604136b247d2af3ce1efda64fbf9d0ee162aa0db86d4ae5045` |
| `CARGO_TARGET_DIR=/tmp/qbind-synthetic-checker-correction.8lNhI8/target TMPDIR=/tmp/qbind-real-adapter-observer.rqaAzt/tmp cargo test --locked -p qbind-node --lib execution_adapter::tests::test_observ --no-run` | 0 | [`focused compile`](candidate-b-real-adapter-init-observer-compile-20261109.txt) | `2bf9c51415b1dd42553e8d2655fd85413ce96b2608f2e6e64cfceb4102e07d53` |
| `CARGO_TARGET_DIR=/tmp/qbind-synthetic-checker-correction.8lNhI8/target TMPDIR=/tmp/qbind-real-adapter-observer.rqaAzt/tmp cargo test --locked -p qbind-node --lib execution_adapter::tests::test_observ -- --nocapture` | 0 | [`focused tests`](candidate-b-real-adapter-init-observer-focused-20261109.txt) | `07027fa59057a1c598752dc475d59f2fafc8079825b0311cfb70764b10d8f4f6` |

The initial focused invocation was
`CARGO_TARGET_DIR=/tmp/qbind-synthetic-checker-correction.8lNhI8/target TMPDIR=/tmp/qbind-real-adapter-observer.rqaAzt/tmp cargo test --locked -p qbind-node --lib execution_adapter::tests::test_observ -- --nocapture`
with exit 101. It failed to compile because the test helper used the
`std::sync::mpsc::Sender` type where the task queue requires
`crossbeam_channel::Sender`. This was a compile failure, not an assertion
or infrastructure failure. The type was corrected; the failed output is
retained at
[`initial compile failure`](candidate-b-real-adapter-init-observer-initial-compile-failure-20261109.txt),
SHA-256 `4f1bffd214c16c6a9b38969ae6de8bb8d691d0b7a3fce49ffa9371b1d07228be`.
The corrected compile-only and focused test commands then passed. Four
tests passed, zero failed or ignored; 2,251 unrelated unit tests were
filtered out and not run. No unchanged historical tests were rerun.

Environment: Linux `x86_64`, kernel `6.12.8+`; `rustc 1.99.1
(58cf8f9c3 2026-10-13)`; `cargo 1.99.1 (5f94df478 2026-08-27)`.
`Cargo.lock` SHA-256:
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`.
The library check emitted existing dead-code warnings; no dependency
manifest or lockfile changed.
