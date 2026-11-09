# Shared-State Blocker Controls and Design Assessment

Status: test-only characterization and design assessment; the required-
persistence candidate remains **NOT ACCEPTED / NOT INTEGRATION-READY**.
Activation remains DISABLED; public DevNet remains NO-GO.

## Pinned source and base

- Reviewed correction branch endpoint: `6a127fff955de04e3636b6e12b6c2e7e400bc37a`
- Endpoint tree: `68b5b45361435b3eda6adc6b2686d5d6e459a6b5`
- Expected main: `aa382fa28b2d3e97e6203d47fa8231b5f2269741`
- Test-only source commit: `6d212fe563bc47a43fba5d3fdf9a365aa387aa73`
- Test-only source tree: `8043b44b78922295e32b5cb0a6f328c71073a070`
- Parent: `6a127fff955de04e3636b6e12b6c2e7e400bc37a`
- `crates/qbind-node/src/execution_adapter.rs` blob:
  `13adcb22f3317485c47ed019daf019599193e721`

The only changed source path is `crates/qbind-node/src/execution_adapter.rs`.
The additional instrumentation and all new control cases are `#[cfg(test)]`.
The production library compiled without test instrumentation. The non-test
branches retain the prior lock, write, worker, and join behavior; no production
write-failure, panic-recovery, quarantine, or service API policy was added.

## Focused controls and observed outcomes

All controls use temporary RocksDB paths and the actual `PersistentVmV0State`
and `SingleThreadExecutionService` worker. Gates and completion channels provide
bounded synchronization; no sleep is used as ordering proof.

| Finding | Control and observation | Interpretation and limits |
|---|---|---|
| RPC-1 | The worker receives an empty block, acquires the operation mutex, then pauses before block execution. A public read's test probe observes that the mutex is held, and the read completes after the gate is released. | This exercises the real worker lock and a public read. It establishes exclusion at that point, not overlapping state mutations or whole-block atomicity. |
| RPC-1 sensitivity | With only a test-only bypass enabled, the public read completes while the worker still holds the operation mutex. | This is an intentional negative control: bypassing the synchronization removes the exclusion. It does not model a production configuration. |
| RPC-2 | While a worker is held inside the locked block operation, service drop signals immediately before its actual `JoinHandle::join`. A competing constructor gets `BackendAlreadyOwned`. After release, the test observes a normal join and drop completion; a subsequent constructor succeeds. | The claim remains held during a pending join. The signals do not substitute for the join result; both join and drop completion are observed before reacquisition. |
| RPC-3 public path | The actual RocksDB put succeeds; test-only instrumentation then substitutes an injected error for its returned result at the public result-handling point. The caller receives `Err`, and the cache retains its prior value. A direct database read sees the newly written value. | This detects suppression and checks cache behavior at the result boundary. It is deliberately **not** a RocksDB failure: the post-call override creates an ambiguous outcome and demonstrates that a reported error does not imply no storage effect. |
| RPC-3 worker path | Test-only instrumentation supplies an error from the worker put helper before RocksDB is called. The real worker proceeds through the `AccountStateUpdater` path; the sender and recipient database values stay unchanged, but the transaction and block success metrics each increment. | This is an injected result, not a real storage failure. It directly characterizes suppression by the void updater and the absence of persistence-failure reporting in the execution result/metrics. |
| RPC-4 | A real worker transaction successfully writes the sender account to RocksDB; a test-only panic is raised immediately after that put and before cache refresh or the recipient update. Drop observes `join()` returning panic, logs the panic, releases the backend claim, and a new service can claim the same handle. | The same live RocksDB handle reads the sender's partial update, the cache reads its old value, and the recipient remains absent. This is an observed partial effect and claim release after panic—not proof of durable flush, rollback, corruption, or safe recovery. The test does not execute work on the replacement service. |

The expected worker panic appears in the retained output; its test passes because
the test is characterizing that outcome. No assertion failed, no coordination
timeout occurred, and no infrastructure or compilation failure occurred.
`cargo test --no-run` compiled the test target but did not run other tests.

## Source-anchored design assessment

### Returning write failures

At this pinned source, `AccountStateUpdater::set_account_state` returns `()` in
`crates/qbind-ledger/src/execution.rs:1138-1140`. `VmV0ExecutionEngine::execute_tx`
returns a transaction result and calls the updater for the sender and then the
recipient (`:2147-2198`); `execute_block` returns only `Vec<VmV0TxResult>`
(`:2508-2522`). The adapter's `PersistentWorkerState` checks the put result only
with `.is_ok()` and does nothing on error
(`crates/qbind-node/src/execution_adapter.rs:621-675`). The worker later counts
the transaction results and block metrics, and logs flush failures rather than
returning them (`:1348-1387`). `AsyncExecutionService::submit_block` reports
enqueue success/failure, not the eventual execution result (`:475`,
`:1492-1518`).

Consequently, a worker-side storage error cannot currently be returned as an
execution outcome. A viable design needs a result-bearing state-update path and
an execution result that distinguishes storage failure from a VM transaction
failure. Because service submission is asynchronous, it also needs an owned
per-block completion/error channel or an explicitly designed service-health
contract; enqueue success cannot stand in for execution success.

The existing internal `CachedPersistentAccountState` has a separate,
pre-existing limitation: it mutates its cache first and discards the persistent
put error (`crates/qbind-ledger/src/execution.rs:1806-1813`). Correcting only
the adapter's shared public write path does not fix that implementation or
close the worker write-error obligation.

### Partial effects, transactionality, and continued work

The VM-v0 transfer path performs separate sender and recipient updates, in that
order (`crates/qbind-ledger/src/execution.rs:2183-2196`). Persistent puts are
individual RocksDB `put` operations returning `Result`
(`:1258-1279`, `:1469-1485`); the execution path does not wrap them in a
transaction. Transactions within a block are executed in sequence
(`:2508-2522`). Therefore an earlier account write or transaction may already
have changed the backend when a later write fails. The current code provides no
rollback, block-atomic commit, or explicit refusal of later work after a
suppressed put error. A subsequent flush cannot prove that a put whose error was
discarded succeeded.

The smallest safe candidate depends on an owner decision that is not made here:

- If block atomicity is required, state changes must be staged and committed
  transactionally (including coordinated cache publication); simply changing
  the updater signature cannot undo earlier RocksDB puts.
- If partial effects are permitted, persistence failure must reach an
  observable block/service outcome, and the service/backend needs a reviewed
  fail-closed state that prevents further execution or reuse until separately
  authorized recovery. That still does not roll back prior writes.

These are alternatives for owner and independent review, not a selected policy.

### Panic and unknown outcomes

The current service owns a worker `JoinHandle`. On drop it joins, logs if the
thread panicked, and then clears the persistent backend claim regardless of the
join outcome (`crates/qbind-node/src/execution_adapter.rs:1540-1562`). The
characterization shows that after a panic following a real first put, the
service can be dropped and the backend claimed again. This establishes
termination of that worker and the implementation's claim-release behavior; it
does not establish that the database is a valid execution boundary or that
retry/recovery is safe.

A future design must decide whether any panic or unknown execution outcome
quarantines the backend and how that quarantine survives process restart. Safe
reuse would require independently authorized recovery plus evidence of the
canonical execution position and the durable state boundary (including which
effects committed). No recovery authority, durable marker, format, rollback
mechanism, or policy is selected here. Without sufficient authenticated
evidence, the safe behavior would be to refuse further execution rather than
infer a clean state from join completion, a flush, or a successful reopen.

### Prospective smallest reviewable candidate

The smallest candidate that can make write failure observable without
success-shaped fallback would still cross component boundaries:

- `crates/qbind-ledger/src/execution.rs`: make account mutation failure
  representable; thread it through normal and gas-aware transaction/block
  execution without confusing it with transaction validation failure.
- `crates/qbind-node/src/execution_adapter.rs`: preserve the error through
  persistent state updates, block execution, and an asynchronous completion or
  service-health boundary; define ownership after write failure or panic.
- Existing updater implementations and their users must be inventoried and
  adapted. The pinned search finds implementations for in-memory state,
  cached persistent state, the parallel test state, and the adapter worker
  (`crates/qbind-ledger/src/execution.rs:1194`,
  `:1806`; `crates/qbind-ledger/src/parallel_exec.rs:726`;
  `crates/qbind-node/src/execution_adapter.rs:667`). This is not a complete
  downstream inventory of this public Rust API.
- Tests must cover a write error before any effect and after an earlier effect,
  distinguish enqueue from execution outcome, prove later submissions are
  refused if that is the selected policy, and prove no backend claim is
  released/reacquired without the chosen recovery authority. If atomicity is
  chosen, tests must exercise the real transaction/batch implementation.

Before implementation, owners must choose block atomicity versus explicit
partial-effect semantics; the observable async failure/readiness contract;
whether and how panic/write failure quarantines the backend; and what
independent evidence and authority permits reuse. Those decisions materially
affect API compatibility, ledger engine implementations, test harnesses, and
downstream callers. This control branch does not implement them.

## Validation and retained output

All commands below ran on the pinned test source commit, author-run locally.
The complete command output and exit codes are in
[`shared-state-blocker-controls-output-20261109.txt`](shared-state-blocker-controls-output-20261109.txt),
SHA-256 `9418254723df3e169bfc614c28d264a9917dfb41e4e7df20d2156ed209973005`.

- Six exact focused `cargo test -p qbind-node --lib ... -- --exact --nocapture`
  invocations, one per named control above: each exit 0, one passed.
- `cargo test -p qbind-node --lib --no-run`: exit 0.
- `cargo check -p qbind-node --lib`: exit 0; production/non-test
  configuration compiled. Existing unrelated warnings remain.
- `rustfmt --edition 2021 --config skip_children=true --check crates/qbind-node/src/execution_adapter.rs`:
  exit 0.
- `git diff --check`: exit 0.

Environment: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `cargo 1.99.1
(5f94df478 2026-08-27)`, `git 2.51.1`, Linux
`6.12.8+ #1 SMP Thu Jul 30 23:01:31 UTC 2026 x86_64`.
No release build, full test suite, live node, operational key, provisioning,
deployment, merge, or PR was run.

## Scope and status

New slice relative to `6a127fff955de04e3636b6e12b6c2e7e400bc37a`:

- `crates/qbind-node/src/execution_adapter.rs`
- `docs/security/evidence/shared-state-blocker-controls-20261109.md`
- `docs/security/evidence/shared-state-blocker-controls-output-20261109.txt`

Full branch scope relative to main `aa382fa28b2d3e97e6203d47fa8231b5f2269741`
is the preceding required-persistence candidate and shared-state correction,
plus those three paths. The source branch before this slice is
`6a127fff955de04e3636b6e12b6c2e7e400bc37a`; the exact full changed-path
inventory is reported at delivery.

Prior raw logs and accepted scoped findings were not changed. Path encoding,
destination authority, startup ordering, worker shutdown, durability, and
recovery remain open. A23-F1 and A33-F1 / E27 remain OPEN; activation remains
DISABLED; public DevNet remains NO-GO.
