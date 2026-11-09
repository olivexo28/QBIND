# Required-Persistence Adapter Candidate

Status: implementation candidate for independent review; not accepted or
integration-ready. Activation remains disabled and public DevNet remains NO-GO.

## Source identity

- Branch: `feat/required-persistence-refusal`
- Starting main: commit `aa382fa28b2d3e97e6203d47fa8231b5f2269741`,
  tree `f1a7d40993bfefbe18635bd637a100ad5527d875`
- Reviewed observer reference: commit
  `33ad915644fa8ff051cb5a4ced8067bbc1188ff7`, tree
  `c89f3be95753c5cbbb4065ffcc165d82abcae0f2`; it was not merged or cherry-picked.
- Tested source commit: `c615834eb97461fb8cfef3f5ddf38896ac6995bd`
- Tested source tree: `9397a95653383f36f06af6ef5506c1d318b7247f`
- Parent: `aa382fa28b2d3e97e6203d47fa8231b5f2269741`
- `crates/qbind-node/src/execution_adapter.rs` blob:
  `80de5234c281a43f8b9383c0e3f58ce8d5bea391`

The source commit changes only:

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

## Candidate behavior and compatibility

`SingleThreadExecutionService::with_config` now returns
`Result<_, ExecutionServiceInitError>`. Requested VM-v0 persistence is opened
synchronously before worker creation; an open error is returned as
`PersistentOpen`, and the same opened handle is moved to the worker. There is no
memory fallback. `NonceOnly` plus a state path returns
`InvalidConfiguration`; VM-v0 without a path remains explicit in-memory mode.
Thread creation failure is distinct as `WorkerSpawn`.

The public `PersistentVmV0State` and
`with_config_and_persistent_state` support callers that need to initialize or
inspect a persistent database while its worker runs. Clones share the same
RocksDB handle and account cache, and the configured path must equal the
opened handle's path. This replaces the duplicate-open pattern in the T166,
T221, T222, and T238 persistent test harnesses. T160's NonceOnly caller now
propagates initialization errors.

Downstream callers of `with_config` must handle its new `Result`; the
`ExecutionServiceInitError` and shared-state API are new public exports.
`SingleThreadExecutionService::new` remains an infallible default-config
convenience method. Downstream usage has not been exhaustively inventoried.

## Verification

Environment: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `cargo 1.99.1
(5f94df478 2026-08-27)`, `git 2.51.1`, Linux
`6.12.8+ #1 SMP Thu Jul 30 23:01:31 UTC 2026 x86_64`.

Final commands and results:

| Command | Result | Full output |
|---|---:|---|
| `cargo test -p qbind-node --lib execution_adapter::tests -- --nocapture` | exit 0; 24 passed, 0 failed | [`required-persistence-adapter-unit-output-20261109.txt`](required-persistence-adapter-unit-output-20261109.txt), SHA-256 `17cf9d3d384f206fd593fd7e1cfb1971825a020adbe7883e40451f4af510c4cd` |
| `cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness test_testnet_alpha_cluster_vm_v0_fifo_smoke -- --nocapture` | exit 0; 1 passed, 0 failed | [`required-persistence-t166-smoke-output-20261109.txt`](required-persistence-t166-smoke-output-20261109.txt), SHA-256 `86b18f6b207170c725c52f5debdd904bd6b9eb1479783ae95152f92e283cc66b` |
| `cargo check -p qbind-node --tests` | exit 0 | [`required-persistence-test-check-output-20261109.txt`](required-persistence-test-check-output-20261109.txt), SHA-256 `ac60bff3276783c8a292d871aa7e2607c96e0ad753b5fde0e235262606f6cb5f` |
| `rustfmt --edition 2021 --config skip_children=true --check crates/qbind-node/src/execution_adapter.rs` | exit 0 | Formatting check for the changed adapter source |

The all-test-target check compiles the updated in-repository callers; it does
not execute the entire integration suite. The final commands had no compilation
or assertion failures. Existing unrelated compiler warnings remain.

An earlier run of the T166 smoke command, before its caller was changed, exited
101 because the harness held a RocksDB open while `with_config` tried opening
the same path again (`lock hold by current process`). This was a caller
ownership issue, not an infrastructure outage. The complete diagnostic is
retained at
[`required-persistence-t166-initial-duplicate-open-output-20261109.txt`](required-persistence-t166-initial-duplicate-open-output-20261109.txt),
SHA-256 `bdc88c67cee12594ac41d4b83ffdee9df79316a4b7f51cb6fec32c502243fedf`.
The shared opened-state handle removed the second open; the final T166 smoke
then passed.

A repository-wide `cargo fmt --all -- --check` was also attempted and failed on
pre-existing formatting differences across unrelated files. Formatting-only
changes from that attempt were removed; it is not evidence of an adapter test
failure.

## Evidence limits and unresolved boundaries

- The open-refusal test calls the public constructor and matches the typed
  `PersistentOpen` error; no service value is returned on that path.
- The successful persistent test executes a transfer and observes updated
  state through the same shared handle or after reopening the path. Source
  inspection shows that this opened handle is passed to the worker. These tests
  do not prove worker join or complete shutdown behavior.
- The worker-spawn failure test uses a test-only injected failure that drops
  the worker closure, then verifies that the database can be opened again.
  It does not induce an operating-system thread-spawn failure.
- The initial T166 duplicate-open failure and its correction demonstrate why
  affected persistent callers now share a single opened backend. The test
  does not establish every harness's runtime behavior; all test targets only
  received a compile/check, except the named T166 smoke.
- No claim is made about path representability before the RocksDB wrapper,
  pre-wrapper checks, destination authority or binding, earlier startup
  effects, later flush failure handling, worker shutdown/join or recovery,
  normal P2P reachability, startup gating, operational provisioning, or
  release-build enforcement.
- No node, operational keys, provisioning, deployment, or production runtime
  was used.
