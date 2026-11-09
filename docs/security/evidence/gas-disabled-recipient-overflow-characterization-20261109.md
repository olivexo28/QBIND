# Gas-disabled recipient-overflow characterization

Observation only; no overflow/error policy is selected. The required-persistence
candidate remains **NOT ACCEPTED / NOT INTEGRATION-READY**.

## Verified basis and tested source

Remote refs were verified before changes: the reviewed decision-brief branch
`docs/worker-write-recovery-decision-brief` was at
`9c062236abedde8f71d559388cca2d1f3b640cb2`, tree
`3dc512de4f0f0d2765c6fc302c30595fb78a9709`; main was
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`. The worktree was clean.
The separate branch is `test/gas-disabled-recipient-overflow`.

Both runs used this test source:

- Commit: `055215befd512f01b66d46ec80046745abb5f4f3`
- Tree: `e66bbcd2845972d8ceb39fe4a8153975b7f7d801`
- Parent: `9c062236abedde8f71d559388cca2d1f3b640cb2`
- Test: `crates/qbind-ledger/tests/gas_disabled_recipient_overflow_characterization.rs`
- Test blob: `68f5bb804aa4763bc955f3499ff3ac39d8e1d5c7`
- Test SHA-256: `fb48a8f533af39f7e5fcd7288d23a529a6a7a30d9968d989e1f7d864fbaf23ab`
- Unchanged `crates/qbind-ledger/src/execution.rs` blob:
  `fe78bed4bddc5f00aa0ea2c8a464050106d84093`

Pinned source references in this document refer to that commit. The actual
`VmV0ExecutionEngine::new()` explicitly disables gas
(`crates/qbind-ledger/src/execution.rs:2103-2108`).
The gas-disabled path writes the sender first (`:2183-2188`), then computes
recipient balance with ordinary `+` before writing the recipient (`:2190-2196`).
The test calls that public engine directly with `InMemoryAccountState`;
no worker, service, RocksDB state, live node, or operational key is used.

## Fixture, oracle, and actual results

Distinct synthetic account IDs are `[0x31; 32]` and `[0x42; 32]`. The sender
starts at nonce 4, balance 100; the recipient starts at nonce 9. The transfer
amount is 1. The overflow case uses recipient balance `u128::MAX`, with a
matching sender transaction nonce of 4.

The harness asserts gas is disabled and panic mode is unwind. It separately
measures this build's arithmetic with a non-constant `black_box(MAX) + 1`
probe, then invokes the actual engine inside `catch_unwind`. Only the exact
overflow panic message is accepted; a different panic, unexpected result,
unexpected state, or disagreeing arithmetic probe fails an assertion.
The two positive/refusal controls are not caught as expected panics. Thus an
arbitrary fixture failure is not accepted as characterized overflow.

| Case | Debug/test result | Release result | Account state afterward |
|---|---|---|---|
| Overflow, recipient `MAX`, nonce 4 | Probe panics; engine panics at `execution.rs:2194:22`, message `attempt to add with overflow`; no returned `VmV0TxResult` | Probe wraps to 0; engine returns `success=true, error=None`; recipient wraps to 0 | Both: sender `(nonce=5, balance=99)`. Debug: recipient `(9, MAX)`. Release: recipient `(9, 0)`. |
| Positive, recipient 20, nonce 4 | Returns success, no error | Returns success, no error | Sender `(5, 99)`, recipient `(9, 21)` in both. |
| Validation refusal, recipient `MAX`, nonce 3 | Returns `success=false`, `NonceMismatch { expected: 4, got: 3 }` | Same | Sender `(4, 100)`, recipient `(9, MAX)` unchanged in both. |

Every returned result also reports `gas_used=0`, `fee_paid=0`,
`fee_burned=0`, `fee_to_proposer=0`; full `Debug` results are in the raw logs.
`MAX` is `340282366920938463463374607431768211455`.

Both test invocations returned exit 0 with **3 passed, 0 failed**.
That means the characterization assertions passed, not that panic after an
already-applied sender update or success with wrapped balance is desirable.
The debug panic hook prints two expected messages (probe, then engine) even
though both panics are caught. Release had no panic. No compile, infrastructure,
or assertion failure occurred; no case is unexecuted.

## Commands, flags, and environment

Exact commands, run from the repository root:

```sh
cargo test -vv -p qbind-ledger --test gas_disabled_recipient_overflow_characterization -- --nocapture --test-threads=1
ROCKSDB_LIB_DIR=/workspaces/QBIND/olivexo28/QBIND/target/debug/build/librocksdb-sys-99da6cff1b808b15/out ROCKSDB_STATIC=1 CARGO_BUILD_JOBS=2 cargo test -vv --release -p qbind-ledger --test gas_disabled_recipient_overflow_characterization -- --nocapture --test-threads=1
```

Full stdout/stderr, including verbose compiler invocations and appended actual
exit statuses, are retained without filtering:

| Output | SHA-256 |
|---|---|
| `gas-disabled-recipient-overflow-debug-20261109.txt` | `bc5d9bd971f38e4ea944367c5f195694ba222caf98cf42f20acc53ae886eab15` |
| `gas-disabled-recipient-overflow-release-20261109.txt` | `84adb87fbcdc5c1e56d4a83d23e0f358fea913190d02df6ff6ec40bc35f89f6b` |

No `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `RUSTUP_TOOLCHAIN`,
`CARGO_BUILD_TARGET`, or `CARGO_PROFILE_*` override was supplied in the
environment. Workspace `Cargo.toml:32-40` sets debug info off, symbol stripping,
and incremental compilation off for dev/test, with no overflow or panic
override. The verbose invocations show debug/test without `-C opt-level`,
release with `-C opt-level=3`, and both with `-C strip=debuginfo`; neither
explicitly passes `-C overflow-checks` or `-C panic`.

Runtime observations, not the profile labels, establish `debug_assertions=true`,
`panic_unwind=true`, and checked addition/panic in debug; release reports
`debug_assertions=false`, `panic_unwind=true`, and wrapping addition.
The actual engine outcome independently matches the probe in each build.
These observations apply only to these recorded builds, not every possible
build configuration.

Environment: Linux `adc-sandbox 6.12.8+ #1 SMP Thu Jul 30 23:01:31 UTC 2026
x86_64`; host `x86_64-unknown-linux-gnu`; `rustc 1.99.1
(58cf8f9c3 2026-10-13)`, LLVM `23.1.1`; `cargo 1.99.1
(5f94df478 2026-08-27)`; git `2.51.1`.
`CARGO_HOME=/usr/local/cargo`, `RUSTUP_HOME=/usr/local/rustup`.

The ledger package has an unconditional RocksDB dependency even though this
test never opens a database. With only 233 MiB initially available, the release
build reused the existing native RocksDB archive through the documented
environment variables, rather than recompiling that C++ archive. Its SHA-256
was `8846f77e1db3c3e98cdd44a5c3e6c2502ca15ff608615d1d9c83743a0c79f824`.
All relevant Rust engine/test code was compiled for release as shown in the
verbose log; this is not a storage-behavior experiment. The release build
completed, then available space reached zero. Only the task-created
`target/release` directory was removed afterward, restoring space; no preexisting
debug artifacts or historical logs were removed.

Executed test-binary SHA-256 values before cleanup:

- Debug `gas_disabled_recipient_overflow_characterization-8d2fce108c405b4c`:
  `71d7f1c4ad80a19bc4661e0e46de013657c254d9a2c216328e4f7107c5782b2b`
- Release `gas_disabled_recipient_overflow_characterization-79831736177bdc1b`:
  `8bfb59742b5b2ccc6da124bd58504a8ab28db3f191b7f6ad1fcd4aef2143f459`

`rustfmt --edition 2021 --check crates/qbind-ledger/tests/gas_disabled_recipient_overflow_characterization.rs`
and the source whitespace check returned exit 0. No historical suites were
rerun and no dependency, manifest, lockfile, or production source was changed.
The later staged whole-evidence `git diff --cached --check` returned exit 2
for two trailing spaces in verbatim tool output (the debug panic-test heading
and a release dependency's multiline metadata). These raw bytes are preserved;
this is an evidence whitespace diagnostic, not a compile or test failure.

## Scope and retained limitations

The new slice relative to `9c062236abedde8f71d559388cca2d1f3b640cb2`
contains only the new test above and these three evidence paths:

- `docs/security/evidence/gas-disabled-recipient-overflow-characterization-20261109.md`
- `docs/security/evidence/gas-disabled-recipient-overflow-debug-20261109.txt`
- `docs/security/evidence/gas-disabled-recipient-overflow-release-20261109.txt`

The full branch scope relative to main is the inherited 24-path candidate,
controls and decision-brief package plus these four paths (28 paths total).
It is not a standalone four-path package based on main.

Complete changed-path inventory relative to main:

```text
crates/qbind-ledger/tests/gas_disabled_recipient_overflow_characterization.rs
crates/qbind-node/src/execution_adapter.rs
crates/qbind-node/src/lib.rs
crates/qbind-node/tests/t155_async_execution_integration_tests.rs
crates/qbind-node/tests/t157_parallel_execution_integration_tests.rs
crates/qbind-node/tests/t160_devnet_cluster_harness.rs
crates/qbind-node/tests/t163_vm_v0_integration_tests.rs
crates/qbind-node/tests/t166_testnet_alpha_cluster_harness.rs
crates/qbind-node/tests/t177_vm_v0_pipeline_proptests.rs
crates/qbind-node/tests/t179_gas_pipeline_proptests.rs
crates/qbind-node/tests/t221_dag_coupling_cluster_tests.rs
crates/qbind-node/tests/t222_consensus_chaos_harness.rs
crates/qbind-node/tests/t238_multi_region_latency_harness.rs
docs/security/evidence/gas-disabled-recipient-overflow-characterization-20261109.md
docs/security/evidence/gas-disabled-recipient-overflow-debug-20261109.txt
docs/security/evidence/gas-disabled-recipient-overflow-release-20261109.txt
docs/security/evidence/required-persistence-adapter-unit-output-20261109.txt
docs/security/evidence/required-persistence-refusal-candidate-20261109.md
docs/security/evidence/required-persistence-shared-state-check-output-20261109.txt
docs/security/evidence/required-persistence-shared-state-correction-20261109.md
docs/security/evidence/required-persistence-shared-state-t166-output-20261109.txt
docs/security/evidence/required-persistence-shared-state-unit-output-20261109.txt
docs/security/evidence/required-persistence-t166-initial-duplicate-open-output-20261109.txt
docs/security/evidence/required-persistence-t166-smoke-output-20261109.txt
docs/security/evidence/required-persistence-test-check-output-20261109.txt
docs/security/evidence/shared-state-blocker-controls-20261109.md
docs/security/evidence/shared-state-blocker-controls-output-20261109.txt
docs/security/evidence/worker-write-failure-backend-reuse-decision-brief-20261109.md
```

Prior ATOM-1/M18 findings remain within their reviewed scopes. ATOM-1's gas/state
atomicity requirement is recorded at `docs/whitepaper/QBIND_WHITEPAPER.md:2052-2061`;
this gas-disabled, volatile-state observation neither proves durable atomicity
nor changes that requirement. M18 checked arithmetic and prevalidation in the
gas-aware path (`crates/qbind-ledger/src/execution.rs:2260-2477`) are a different
execution route: these tests do not rerun or invalidate its accepted scoped
controls, nor extend their guarantees to the gas-disabled route.

No durable corruption, storage failure, rollback, recovery, production
reachability, or exploitability is established. No production policy is
implemented or approved. Recovery identity, authoritative history, snapshot
authority, storage failure handling and startup reachability remain OPEN.
A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED; public
DevNet remains NO-GO.
