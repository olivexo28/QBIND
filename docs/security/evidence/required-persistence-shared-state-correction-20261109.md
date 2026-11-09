# Required-Persistence Candidate: Shared-State Correction

Status: correction candidate for independent review; NOT ACCEPTED. Activation
remains DISABLED; public DevNet remains NO-GO.

## Verified source and branch

- Correction branch: `fix/required-persistence-shared-state`
- Reviewed evidence endpoint: `3c202cc76d2bea48031056c776fafa110873e47f`,
  tree `8c466d5387f2b8297aeb43f4ecbe64ba3a075a30`
- Reviewed source: `c615834eb97461fb8cfef3f5ddf38896ac6995bd`,
  tree `9397a95653383f36f06af6ef5506c1d318b7247f`, parent
  `aa382fa28b2d3e97e6203d47fa8231b5f2269741`
- Expected main: `aa382fa28b2d3e97e6203d47fa8231b5f2269741`
- Correction source commit: `38cbeda15fd4fce4b9c1718a653c2b95a5bf06d2`
- Correction source tree: `c93357a47548a7342b0f9e7ebfe989b681305e0c`
- Correction parent: `3c202cc76d2bea48031056c776fafa110873e47f`
- `execution_adapter.rs` source blob:
  `a8a208f6a99d8563edbd461eff240b717846014e`

The five source/caller paths in the correction commit are:

- `crates/qbind-node/src/execution_adapter.rs`
- `crates/qbind-node/tests/t166_testnet_alpha_cluster_harness.rs`
- `crates/qbind-node/tests/t221_dag_coupling_cluster_tests.rs`
- `crates/qbind-node/tests/t222_consensus_chaos_harness.rs`
- `crates/qbind-node/tests/t238_multi_region_latency_harness.rs`

The reviewed candidate source and historical output logs were preserved
unchanged.

## Selected shared-state and ownership design

The shared interface is retained because the persistent cluster harnesses
initialize, inspect, and flush account state while a VM-v0 worker exists.
`PersistentVmV0State` remains cloneable, but its public state reads, writes and
flushes use one operation mutex. A persistent worker holds that same mutex over
the entire block operation, including state reads, nonce/balance checking,
updates and flush. This serializes public shared writes against complete worker
execution operations; it is not merely per-account cache locking.

Only one worker can claim a backend, enforced by an atomic compare-exchange
within the real public service construction path. A competing construction
returns `ExecutionServiceInitError::BackendAlreadyOwned`. Service drop signals
shutdown, joins the worker, then releases the claim. Both worker loops use a
25 ms receive timeout so an idle worker notices shutdown. `shutdown()` alone is
only a request and does not release ownership. A queued or in-progress task can
make drop wait longer; a permanently stalled task can make drop block
indefinitely. This lifecycle change is deliberate so a later claim is not
permitted merely because a service handle was dropped or shutdown was
requested.

The real-constructor test rejects a second worker while the first owns the
backend, then drops the first service and successfully constructs a replacement.
That re-acquisition occurs only after `Drop` has called `JoinHandle::join`;
the test does not use a sleep or treat a cancellation/shutdown request as
termination evidence. A failed join reports a worker panic to stderr; the
thread is nevertheless joined before the ownership flag is released.

The public `set_account_state` now returns `Result<(), StorageError>`. It writes
the database first and updates the cache only after a successful put. A
test-only injected failure verifies the returned error and that both the
previous cache value and persisted value remain unchanged. The injection is
before the RocksDB put; it is not a real RocksDB/OS failure.

## Error boundary that remains open

The public shared-write path no longer hides a put failure. However,
`AccountStateUpdater::set_account_state` has no error return. The private
worker adapter therefore cannot report write failures through execution
results; it only updates the cache when the RocksDB put returns success and
still discards the error otherwise. A later successful flush does not prove a
prior put succeeded.

Separately, the pre-existing
`qbind_ledger::CachedPersistentAccountState` implementation at
`crates/qbind-ledger/src/execution.rs:1806-1815` updates its cache and ignores
the persistent put error. This behavior predates the new public shared-state
API and remains an unresolved worker-write/error-propagation obligation.
Closing it requires redesigning the persistence/update trait and execution
error path; this candidate does not claim that broader work is complete.

## Focused controls and results

All commands below were author-run locally against the correction source tree,
not independently rerun or hosted. The test-only put and worker-spawn failures
are injected, not real database or OS failures.

| Exact command | Result | Full output and SHA-256 |
|---|---|---|
| `cargo test -p qbind-node --lib execution_adapter::tests -- --nocapture` | exit 0; 28 passed, 0 failed | [`required-persistence-shared-state-unit-output-20261109.txt`](required-persistence-shared-state-unit-output-20261109.txt), `fb82df00486719f84a84c32c908b6b378a233dbc5c36489070793ac585ed6f52` |
| `cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness test_testnet_alpha_cluster_vm_v0_fifo_smoke -- --nocapture` | exit 0; 1 passed, 0 failed | [`required-persistence-shared-state-t166-output-20261109.txt`](required-persistence-shared-state-t166-output-20261109.txt), `4c6257d9e99ddf94105a4e02768846883ff6ce512949aacf18760cb55ebc8108` |
| `cargo check -p qbind-node --tests` | exit 0 | [`required-persistence-shared-state-check-output-20261109.txt`](required-persistence-shared-state-check-output-20261109.txt), `620460acc4d089de45e1ccb836578c2b5f7917c222d4369f94d9ad7cf8773d2b` |
| `rustfmt --edition 2021 --config skip_children=true --check crates/qbind-node/src/execution_adapter.rs` | exit 0 | Adapter formatting check |

The focused unit tests cover persistent-open refusal, explicit VM-v0
in-memory operation, NonceOnly-with-path refusal, persistent state transfer,
path mismatch, worker-spawn failure and backend reopenability, public-write
contention, injected public put failure, and competing worker claim plus
post-join reacquisition. Worker-spawn tests inject the failure before creating
an OS thread; they do not simulate OS resource exhaustion.

The T166 smoke test's actual assertions include successful cluster start,
initial sender balance read from node 0, 50 harness steps, and the number of
nodes in the metrics snapshot. It does **not** assert the transfer's final
balances or cross-validator state agreement, despite broader wording in that
test's doc comment.

The `cargo check` compiles test targets, including the updated T166, T221, T222,
and T238 callers; it does not execute those other harnesses. Existing unrelated
compiler warnings remain. No compilation, assertion, or infrastructure
failures occurred in the final commands.

Environment: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `cargo 1.99.1
(5f94df478 2026-08-27)`, `git 2.51.1`, Linux
`6.12.8+ #1 SMP Thu Jul 30 23:01:31 UTC 2026 x86_64`.

## Compatibility, remaining risks, and scope

- The initial synchronous-open refusal, no-service-on-open-failure, transfer
  of the same opened backend, explicit VM-v0 memory mode,
  NonceOnly-with-path refusal, and distinct worker-spawn error are retained.
- `PersistentVmV0State::set_account_state` now returns a storage result; the
  four in-repository harness initialization wrappers explicitly fail if
  initialization writes fail. Downstream usage is not exhaustively inventoried.
- `SingleThreadExecutionService` now retains and joins its worker during drop.
  Drop can block until an in-progress task exits; there is no timeout or
  forced cancellation. This is a behavioral/lifecycle change for downstream
  users.
- `shutdown()` does not itself wait for termination. Ownership is released only
  when service drop joins the worker.
- Worker-side persistence errors still cannot be surfaced through the current
  void-returning update trait. Flush failures also remain logged rather than
  returned through the async execution service.
- No claim is made about destination authentication, path-encoding protection,
  startup enforcement, durability, recovery, normal P2P reachability, or
  release-build enforcement.
- No operational keys, live node, provisioning or deployment were used.

## Changed paths

Correction slice relative to `3c202cc76d2bea48031056c776fafa110873e47f`:

- The five source/caller paths listed above.
- `docs/security/evidence/required-persistence-shared-state-correction-20261109.md`
- `docs/security/evidence/required-persistence-shared-state-unit-output-20261109.txt`
- `docs/security/evidence/required-persistence-shared-state-t166-output-20261109.txt`
- `docs/security/evidence/required-persistence-shared-state-check-output-20261109.txt`

Complete branch scope relative to main `aa382fa28b2d3e97e6203d47fa8231b5f2269741`:

- `crates/qbind-node/src/execution_adapter.rs`
- `crates/qbind-node/src/lib.rs`
- `crates/qbind-node/tests/t155_async_execution_integration_tests.rs`
- `crates/qbind-node/tests/t157_parallel_execution_integration_tests.rs`
- `crates/qbind-node/tests/t160_devnet_cluster_harness.rs`
- `crates/qbind-node/tests/t163_vm_v0_integration_tests.rs`
- `crates/qbind-node/tests/t166_testnet_alpha_cluster_harness.rs`
- `crates/qbind-node/tests/t177_vm_v0_pipeline_proptests.rs`
- `crates/qbind-node/tests/t179_gas_pipeline_proptests.rs`
- `crates/qbind-node/tests/t221_dag_coupling_cluster_tests.rs`
- `crates/qbind-node/tests/t222_consensus_chaos_harness.rs`
- `crates/qbind-node/tests/t238_multi_region_latency_harness.rs`
- `docs/security/evidence/required-persistence-adapter-unit-output-20261109.txt`
- `docs/security/evidence/required-persistence-refusal-candidate-20261109.md`
- `docs/security/evidence/required-persistence-t166-initial-duplicate-open-output-20261109.txt`
- `docs/security/evidence/required-persistence-t166-smoke-output-20261109.txt`
- `docs/security/evidence/required-persistence-test-check-output-20261109.txt`
- `docs/security/evidence/required-persistence-shared-state-correction-20261109.md`
- `docs/security/evidence/required-persistence-shared-state-unit-output-20261109.txt`
- `docs/security/evidence/required-persistence-shared-state-t166-output-20261109.txt`
- `docs/security/evidence/required-persistence-shared-state-check-output-20261109.txt`

A23-F1 and A33-F1 / E27 remain OPEN.
