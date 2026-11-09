# QBIND — Adapter refusal observability assessment

**DOCUMENTATION-ONLY ASSESSMENT — PROPOSAL, NOT AN IMPLEMENTATION OR
APPROVED API.** This document considers how to test the owner-approved
required-persistence behavior for the VM-v0 execution adapter: when
persistent storage is requested and cannot be opened, execution must refuse
rather than silently switch to in-memory state. It selects no production
API, error type, test seam, startup behavior, or migration policy.

The prior adapter test remains an author-run characterization of current
fallback, not conformance. The existing four path-encoding contract test
failures and their retained evidence remain unchanged; the reviewed test
branch remains not integration-ready. The corrected consensus result
category is CLOSED within its test scope: its oracle rejects every `Ok`,
including an empty successful result. Same-captured-path identity,
pre-wrapper refusal, complete backend effects, and startup ordering remain
open. The no-replacement-database finding, CB-1, and CB-FIXTURE-1 retain
their accepted scopes. A23-F1 and A33-F1 / E27 remain OPEN; activation
remains DISABLED; public DevNet remains NO-GO.

## Pinned basis

| Reference | Revision |
|---|---|
| Main source baseline | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed test and evidence endpoint | `2c387809e9a58d80ff9e9a92d7e14708f824f6aa`, tree `134d2f5d3070d31aa40e2df49ce3acbed7c4c3ed` |
| Earlier baseline characterization | `e5820cec9b942002c95dc14eeb22a1302f3e9a63`, tree `ef1adec8184a3b14e4d5f4e13aec498b956608a9` |

Production-source line citations below refer to pinned main. The corrected
test and baseline evidence are cited at the reviewed test endpoint.

## Current public observations and gaps

### Initialization and worker lifetime

`SingleThreadExecutionServiceConfig::vm_v0_persistent(path)` selects
`ExecutionProfile::VmV0` and stores a `Some(path)`, while `vm_v0()` selects
VM-v0 with `state_dir: None` (main `crates/qbind-node/src/execution_adapter.rs:449-596`).
`SingleThreadExecutionService::with_config` returns a service directly,
without a `Result`; it spawns a worker thread and discards the `JoinHandle`
(main `execution_adapter.rs:639-692`). The worker performs the persistent
open asynchronously after construction returns (main `execution_adapter.rs:879-928`).
Consequently, a returned service handle establishes neither successful
backend initialization nor that the worker remains live.

For `Some(path)`, the current worker catches `RocksDbAccountState::open`
failure, logs the error, and enters the VM-v0 loop with
`InMemoryAccountState`; for `None`, it also uses in-memory state, but logs
that this was selected without persistence (main `execution_adapter.rs:879-928`).
The public service does not expose a worker-initialization outcome, its
chosen backend, or a terminal startup error. The current open failure is
therefore not a public refusal.

### Submission, execution, and shutdown

The public `AsyncExecutionService::submit_block` is non-blocking and
returns only `Ok(())`, `QueueFull`, or `ShuttingDown`; `Ok(())` means that
the task entered the bounded queue, not that it was received, executed,
committed, flushed, or completed (main `execution_adapter.rs:380-437, 1150-1185`). The `QueueFull` path rejects
that submission. `ShuttingDown`
can result from the shutdown flag or a disconnected receiver. Because
checking the flag and attempting enqueue are separate operations, a
shutdown race can also leave uncertainty about work submitted around
worker exit.

The optional metrics expose an aggregate, relaxed `txs_applied_total`
counter (main `crates/qbind-node/src/metrics.rs:4414-4422`). It counts
successful transactions, not submissions, completed blocks, refusals,
worker health, or persistence. In particular:

- A zero count after any finite wait cannot distinguish refusal from
  queued-but-stalled work, a live worker that has not processed the item,
  a stopped/panicked worker, an item whose transactions all failed, or a
  missing metrics instance. Zero is not a refusal outcome.
- A positive count establishes that some successful transactions were
  counted, but not that a particular submitted block has completed or that
  it used durable storage. The metric is aggregate and is not correlated
  with a work identifier.
- `submit_block == Ok(())` establishes enqueue admission only. A timeout
  or absent later metric does not turn admission into a refusal.

The VM-v0 loop updates successful-transaction metrics after execution.
Persistence flush failures are logged and do not produce a caller-visible
completion result (main `execution_adapter.rs:1023-1044`). Per-transaction
execution failures are represented in internal results and logged or
counted, but the submitter receives no result for that block. Queue length
is approximate and can be stale; it does not establish work completion
(main `execution_adapter.rs:433-438, 1184-1186`).

`shutdown()` sets an atomic flag and returns; it does not drain, join, or
report a final worker state. Both profile loops check the flag and then
block on `receiver.recv()` (main `execution_adapter.rs:746-756, 962-972`).
Setting the flag does not wake a worker already blocked in `recv`. Since
the service's sender remains alive until the service is dropped, an
explicit `shutdown()` while retaining the service may leave the worker
blocked until channel disconnection; dropping the service eventually
drops that sender after `Drop` sets the flag. The `JoinHandle` is
unavailable (main `execution_adapter.rs:1137-1147, 1199-1205`).
Pending work at shutdown, worker termination, and final flush status
cannot be established through this interface. A worker that panics or
remains blocked has no public health or join observation. Shutdown success
therefore cannot be treated as work completion or proof of termination.

### Historical direct-API evidence

At the reviewed endpoint, the existing focused test separately:

- submits a block after a configured persistent open is forced to fail,
  observes one applied transaction, and asserts that observation for the
  historical fallback characterization (`crates/qbind-node/tests/candidate_b_storage_path_encoding_baseline_tests.rs:377-407`);
- selects `vm_v0()` without a path and observes one applied transaction as
  the explicit in-memory positive control (same test);
- contains a separate required-persistence contract assertion, which
  observes one applied transaction and fails its zero-count assertion
  (`...baseline_tests.rs:424-453`).

The retained oracle-correction report records these results and explicitly
notes the bounded metric limitation
(`docs/security/evidence/candidate-b-path-encoding-oracle-correction-20261109.md`,
reviewed endpoint). Its logs remain historical evidence and are not
modified by this assessment. No pinned source establishes that ordinary
P2P startup reaches this adapter; no such reachability is claimed here.

## Candidate observable contracts

These are design alternatives for review. Each requires explicit decisions
about failure propagation, pending work, service lifetime, and correlation;
none is selected by this assessment.

| Contract shape | What a test would need to observe | Unresolved design questions |
|---|---|---|
| **Refusal before service availability** | A fallible initialization operation returns a typed or otherwise unambiguous refusal for requested persistence, and does not publish an executable service handle. The test must distinguish that refusal from constructor failure, thread-spawn failure, panic, timeout, and an unavailable response. It must establish that no work can be submitted through the rejected service and account for any started worker's termination. | Is storage initialization synchronous before service publication, or does an explicit readiness handshake gate availability? Who owns and joins a worker if startup fails after spawning? What is the error/result contract, and how are cleanup and startup side effects reported? |
| **Refusal at submission** | Submission returns a refusal outcome associated with the attempted block and distinguishes it from `QueueFull`, `ShuttingDown`, and other infrastructure errors. A refusal must mean the block was not admitted or executed; if initialization is still pending, the API needs a defined wait/retry result rather than treating delay as refusal. | Is readiness checked before enqueue? Can the worker fail after acceptance? What does `Ok` guarantee? How are rejected work, backpressure, shutdown races, and retry-safe ownership of the block represented? |
| **Explicit outcome for admitted work** | Each accepted submission yields a correlation handle or identifier with an observable terminal result: execution/completion, explicit refusal, or a defined execution/flush failure. The observer waits for that exact result; pending remains pending, and timeout is inconclusive. Shutdown must resolve or explicitly preserve pending outcomes and make worker termination/finalization observable. | What counts as completion: execution, transaction receipts, durable flush, or all of these? Is refusal possible after admission, and if so how is it distinguished from execution errors? Are outcomes exactly once and retained long enough? Who resolves queued work on shutdown, panic, or worker loss? |

For any option, initialization errors, submission errors, worker failures,
execution results, storage flush errors, pending operations, and shutdown
must not be collapsed into one success-shaped or absent response. A timeout
or missing response remains inconclusive; it is not evidence of refusal.

## Test design independent of API selection

### Accepting valid early refusal

If a future contract refuses before the service is available, a
conformance test must accept that explicit, contract-defined refusal
without requiring `submit_block` to succeed. It should submit no block if
initialization returns a refusal and no service handle. It should assert
the returned refusal category and the operation/requested-persistence
context; the test must not treat a constructor panic, missing response,
thread loss, timeout, or generic setup error as a valid refusal. If the
contract starts a worker before refusing, the contract must also expose
how that worker is joined or otherwise proven terminated, and what cleanup
was completed.

### Rejecting fallback after a requested persistent failure

To reject actual execution after a required persistent open fails, a
future test must identify the request and its terminal outcome. A
correlated admitted-work result that says refused, or an explicit
initialization refusal that prevents admission, can satisfy the proposed
oracle. A correlated execution outcome or successful-transaction receipt
after a required open failure must fail it. A zero metric, zero queue
length, elapsed timeout, or missing completion must remain inconclusive,
not pass as refusal.

The test also needs a sensitivity control proving that its oracle rejects
the current behavior when the adapter actually falls back and processes
the submitted work. The retained author-run fallback observation can
serve as historical evidence of the current behavior, but the eventual
conformance suite should not require that fallback to continue. It must
not preserve an assertion that fallback is correct simply to keep the
historical test green.

### Explicit in-memory positive control

Use the separately selected no-persistence configuration (`vm_v0()` /
`state_dir: None`) and prove a correlated accepted block reaches its
defined completion or execution outcome. The control must also establish
from the selected configuration/initialization result that persistence was
not requested. It must not infer intentional memory mode merely because a
configured persistent open failed or because an effect was absent. Compare
the requested-persistent failure case and explicit-memory case as separate
configurations with distinct work identifiers and outcomes.

## Can the current public API support the proposed observations?

Not fully. It can exercise the real adapter's current fallback, observe
successful transaction counts when metrics are supplied, observe the
coarse queue and shutdown indicators, and observe enqueue rejection for a
full queue or shutting-down/disconnected service. It cannot provide a
positive refusal outcome, a correlated completion result, initialization
readiness, selected-backend identity, worker panic/health, a join result,
or a definitive status for pending work. As the reviewed test demonstrates,
the metric-based assertion detects the currently observed fallback when a
transaction is applied, but **a zero metric within a timeout cannot prove
refusal**.

Possible narrow observation mechanisms to evaluate are:

1. A test-only controlled state-open result/factory plus a worker
   initialization/result channel, to force and directly observe the
   persistent-open failure and chosen path. This would test the adapter
   control flow only if the real worker consumes that seam; a stand-alone
   model or fake state machine would be synthetic evidence, not proof of
   production behavior.
2. A test-only per-submission completion observer or channel reporting
   correlated accepted/refused/completed outcomes, coupled with a worker
   join/termination observation. If kept strictly behind test
   configuration, it can expose current execution sequencing but cannot
   prove an eventual public API contract or production wiring.
3. A public fallible readiness/initialization result, submission result,
   or completion handle. Each implies production-interface decisions
   about API compatibility, outcome semantics, pending tasks, queue-full
   behavior, persistence flush, worker panic, and shutdown. None is
   approved or proposed here as the selected interface.

Any seam must be narrowly scoped and reviewed for whether it observes the
real code path, rather than substituting a synthetic oracle. Tests using
only a model can validate that an oracle handles refusal, execution, and
pending outcomes correctly, but cannot establish adapter enforcement.
No test seam or production interface is added in this assessment.

## FUTURE / NOT EXECUTED test matrix

All rows are **FUTURE / NOT EXECUTED**. The table describes outcomes a
future reviewable test should classify; it does not prescribe an API.

| Scenario | Expected classification | Required observation and sensitivity |
|---|---|---|
| Persistent initialization fails and service is refused before availability | **Valid early refusal** only if a contract-defined refusal is returned and no usable service is published. | No successful enqueue is required. Distinguish refusal from setup error, panic, timeout, missing response, or orphan worker; account for worker termination and cleanup. |
| Persistent initialization is stalled or the worker is stalled before processing | **Inconclusive / pending**, never refusal. | A deadline expiring, zero applied count, or nonzero queue is not terminal. The test must report pending/stalled and preserve the worker lifetime result if observable. |
| Work is admitted, then the adapter emits an explicit refusal for that identified work | **Valid refusal** if the contract allows post-admission refusal and the terminal outcome correlates to that work. | Assert no execution outcome for that work, resolve whether it was removed from the queue, and account for shutdown/pending semantics. A missing outcome is inconclusive. |
| Persistent open fails but the adapter executes the work in memory | **Contract failure / unintended fallback.** | The correlated work outcome must show execution, or a sufficiently specific observed execution effect tied to the work must contradict refusal. Keep the existing actual-adapter fallback result as a sensitivity reference; do not make fallback a required passing behavior. |
| Persistent open fails and only zero applied transactions or no completion is observed | **Inconclusive**, not refusal. | Classify as pending/unknown unless an explicit refusal outcome and worker/service state establish refusal. |
| In-memory mode is explicitly selected with no persistent path | **Positive control.** | Establish explicit configuration and correlated successful completion/execution. Keep separate from the requested-persistent failure case. |
| Submission returns `QueueFull` or `ShuttingDown` | **Rejected submission / infrastructure state**, not a persistence refusal unless a separately approved contract explicitly defines it so. | Verify that work was not admitted; identify queue/shutdown state. Do not relabel generic admission failures as the required-persistence decision. |
| Accepted work executes, returns transaction errors, flush fails, or the worker exits/panics | **Distinct terminal or infrastructure outcome required; otherwise inconclusive.** | The contract must distinguish VM receipts, durability failure, worker failure, and completion. Aggregate applied metrics alone cannot establish these outcomes. |

The earlier adapter characterization and its logs remain available at the
reviewed endpoint. An eventual conformance suite should preserve that
history as separate evidence or an explicitly historical characterization,
while testing the new required-persistence contract independently. It must
not require continued fallback behavior. No tests were run for this
documentation-only assessment; no node was started and no operational keys
were used.

## Open owner and implementation-entry decisions

- Which observable contract shape is desired: refusal before publication,
  rejection at submission, or correlated terminal outcomes for admitted
  work?
- What constitutes completion: execution, transaction outcome, persistent
  flush, and/or worker lifecycle termination?
- How should pending work resolve on shutdown, worker panic, storage
  failure, queue saturation, or late initialization?
- Is worker creation performed only after persistent storage is ready, or
  is there an explicit readiness stage? Who owns worker join and teardown?
- Which production-interface compatibility and error-propagation changes
  are acceptable? No exact error type, method signature, or message is
  selected.
- Which narrowly scoped test seam, if any, can directly observe the real
  adapter rather than only a synthetic model?
- How will the explicitly selected in-memory mode be represented and
  distinguished from fallback after a requested persistent open?
- Which independent evidence, if any, establishes that a normal P2P
  startup reaches this adapter? The pinned source review here does not
  establish that connection.

Until these decisions and required observations are independently
reviewed, a zero count, timeout, successful enqueue, or service handle
cannot be cited as proof that required persistence was refused.
