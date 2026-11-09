# Gas-disabled checked-arithmetic oracle: test-only red baseline

**Conformance tests against the owner-approved test contract; no production
correction. Both focused test commands FAIL.** Expected nonconformance is not
reclassified as a passing characterization.

## Verified basis and executed source

Before starting, remote `test/sequential-direct-stage-b-overflow` matched
`b123a4e3757eec0d1a615c5001904b42ad2d4879`, tree
`987627a5c801003e0b1113bbe74d7516b83054a1`; remote main matched
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`. Local HEAD matched and worktree
was clean. A separate branch, `test/gas-disabled-checked-arithmetic-oracle`,
was created from that endpoint.

Executed source commit: `08f72bff797d6a8692967e921a5c7b9d8e6c8679`.
Tree: `4e1d61d347886cfb69862e5c85a490bdbaa6274c`.
Parent: `b123a4e3757eec0d1a615c5001904b42ad2d4879`.
The evidence-only successor does not change executed code.

| Executed file | Git blob | SHA-256 |
|---|---|---|
| `crates/qbind-ledger/src/checked_arithmetic_oracle_tests.rs` | `9ba82b76a29e7873068fb216093f0c1a6b39bfaa` | `22cbae542f44616011e488599b4c2dd694bc085978829306675937a38deb716d` |
| `crates/qbind-ledger/src/parallel_exec.rs` | `9791f74b5c54655796edb823743c98d98817b33c` | `f4fbb0a42d1a37be6155455920cc040364942efda7ac60533b78bab9d2902f94` |

All source citations below are pinned to this executed source commit.
Earlier characterization tests/logs and the reviewed compatibility assessment
are unchanged. Their observations remain historical evidence, not this oracle.

## Contract and observable boundaries

The oracle preserves malformed-payload, nonce-mismatch and insufficient-balance
precedence. After those checks, it requires
`ArithmeticOverflow { operation: "nonce increment" }` before
`ArithmeticOverflow { operation: "recipient balance increment" }` when both
would fail. It rejects every panic and every success on arithmetic-refusal
fixtures. It requires unchanged account values/membership and zero transaction
updater calls where those calls are directly observable.

Successful transfers require the original two-call debit/credit shape,
including self-transfers: sufficient funding remains required, nonce increases
once, balance is restored. Maximum-balance self-transfer is not tested as
original-balance-plus-amount. Zero amount retains both calls and absent-recipient
materialization. An observing wrapper excludes fixture initialization writes.

Three independently reported paths run the same cases and result/state oracle:

1. **Sequential transaction:** actual default gas-disabled
   `VmV0ExecutionEngine::execute_tx` on an `ObservingState` implementing
   `AccountStateUpdater`/`AccountStateView`. Every updater call, ID and value
   is captured before delegating to the in-memory state.
2. **Stage B internal transaction:** actual
   `execute_tx_on_stage_b_state` in `parallel_exec.rs`, not a duplicate transfer
   implementation. A narrowly configured observer records every invocation
   of `StageBPerAccountState::set`, including attempted call order and values.
   The test retains that state across unwind and inspects the recorded calls.
   This observes transaction setter calls, not storage writes or read-triggered
   materialization. It is not a claim about a returned public block state.
3. **Direct public Stage B:** actual `execute_block_stage_b` with one transaction,
   executed in a dedicated two-thread Rayon pool. It tests result and returned
   account membership/values only. Its local observer is not exported by the
   API, so `writes=None` is an explicit **observation gap**, never interpreted
   as zero calls. Panic means result and final state are unavailable.

The direct one-transaction API is deliberately distinct from an adapter call.
Returned stats report one level/transaction and `used_parallel=false`; pool size
two does not make this a concurrent-transaction test. Multi-transaction direct
API characterization remains in the prior retained evidence, not rerun here.

### Test-configuration containment

All 15 added lines in `parallel_exec.rs` are guarded by `#[cfg(test)]`: the
observer field, both initializers, recording statement and test-module
declaration. The new file is included only by that guarded module. Non-test
state layout and setter statements are unchanged by configuration expansion;
there is no non-test trait, API, arithmetic or error-policy change.
The observer records before the real setter body and introduces test-only
allocation/mutex overhead; tests are not production performance evidence.

A non-test library build was separately executed and succeeded (exit 0).
Its retained rustc invocation has `--crate-type lib`, without `--test`.
This verifies non-test compilation plus source-level configuration containment,
not byte-identical binaries or a complete behavioral-equivalence proof.

## Executed cases and actual outcomes

Each named case expands into three tests, one per path. Default fixture:
distinct A=`[0x51;32]`, B=`[0x62;32]`, sender `(nonce=4,balance=100)`,
recipient `(9,20)`, transaction nonce 4, amount 1.
The logs print each complete fixture, returned result/panic, state and available
write trace before the assertion.

| Case group | Explicit changes / oracle | Debug | Release |
|---|---|---|---|
| `nonce_increment_overflow` | Sender/tx nonce `u64::MAX`; nonce arithmetic error, no updates | 3 FAIL | 3 FAIL |
| `recipient_balance_overflow` | Recipient `u128::MAX`, amount 1; recipient arithmetic error, no updates | 3 FAIL | 3 FAIL |
| `simultaneous_overflow` | Both maxima; nonce arithmetic error first, no updates | 3 FAIL | 3 FAIL |
| `malformed_precedence` | Malformed payload plus wrong nonce, insufficient funding and nonce overflow | 3 pass | 3 pass |
| `nonce_precedence` | Wrong nonce plus insufficient funding and recipient overflow | 3 pass | 3 pass |
| `balance_precedence` | Amount 101, balance 100, matched maximum nonce | 3 pass | 3 pass |
| `maximum_self_transfer` | Original balance `u128::MAX`, amount 1; restored balance, two calls where observable | 3 pass | 3 pass |
| `ordinary_self_transfer` | Balance 100, amount 1; restored balance, two calls where observable | 3 pass | 3 pass |
| `self_transfer_balance_refusal` | Amount 101, balance 100; insufficient-balance refusal | 3 pass | 3 pass |
| `zero_existing_recipient` | Amount 0, recipient maximum balance; nonce increases, two calls where observable | 3 pass | 3 pass |
| `zero_absent_recipient` | Amount 0, recipient absent; materialized `(0,0)` | 3 pass | 3 pass |
| `zero_self_transfer` | Amount 0, alias; nonce increases, balance retained | 3 pass | 3 pass |
| `valid_boundary` | Sender nonce `u64::MAX-1`, balance `u128::MAX`; recipient `u128::MAX-1`, amount 1 | 3 pass | 3 pass |
| `maximum_amount` | Sender balance and amount `u128::MAX`, recipient absent | 3 pass | 3 pass |
| `ordinary_transfer` | Default valid fixture | 3 pass | 3 pass |
| Runtime arithmetic probe | Measure actual addition behavior, not a refusal conformance test | 1 pass: caught overflow panic | 1 pass: wrapped to zero |
| Same-oracle synthetic sensitivity | Reject deliberately altered observations with unchanged oracle | 1 pass | 1 pass |

**Totals per build: 38 passed, 9 failed, 0 ignored, 368 filtered out. Actual
cargo/timeout exit: 101, not 0.** No compile failure, infrastructure failure,
timeout or skipped/unsupported case occurred. There were intentional failed
conformance assertions after reporting caught arithmetic panics or wrong returned
results. These are actual red tests, not `should_panic` or expected-failure passes.

Debug nonce and simultaneous-overflow transactions panicked before any setter
call in the sequential/internal Stage B observations, leaving accounts unchanged.
That is still failure: a panic is not the required typed arithmetic error.
Debug recipient overflow panicked after one sender call, leaving sender `(5,99)`
and recipient `(9,u128::MAX)` at those two retained transaction boundaries.
Public Stage B returned no final state on these panics.

Release nonce overflow returned success with sender nonce wrapping to 0 and
the transfer applied. Release recipient overflow returned success with recipient
balance wrapping to 0. Simultaneous overflow wrapped both. Sequential/internal
Stage B traces show two calls, not zero. Direct Stage B returned corresponding
wrong success/states without a public call-count observation.

### Sensitivity scope

The same `oracle` function rejects synthetic observations representing:
unchecked-success bypass, write-then-restore despite unchanged final state,
recipient-before-nonce arithmetic precedence, arithmetic-before-balance
validation precedence, single-write self-transfer and omitted zero-recipient
materialization. A compliant synthetic observation first passes that same
oracle, avoiding a reject-everything sensitivity control.

These are explicitly **test-only observation mutations**, not production
branch patches or evidence that a corrected engine exists. Only the sensitivity
control's assertion that bad observations are rejected passes. It does not turn
the nine actual engine conformance failures into passes. Real engine bypass
mutation testing after a future correction would be additional evidence.

### Default discovery and unexercised service boundary

The 47 new tests are ordinary, non-ignored library unit tests. Unfiltered
`cargo test -p qbind-ledger` or workspace test discovery includes them and, on
the tested current builds, is expected to be red because of these nine tests.
No default full suite was executed. Only the new module filter ran; historical
tests were compiled as part of the unit-test binary but not executed.

The adapter route/publication boundary was not exercised. Inspected existing
`ExecutionAdapterTestHooks` (`crates/qbind-node/src/execution_adapter.rs:518-545`)
coordinates block entry, injected put outcomes, lock attempts and joins; it
does not provide this ledger test with per-transaction setter traces or complete
`apply_state_changes` publication observations (`:149-157,1321-1358`).
Extending node instrumentation/tests would be a separate boundary, not a result
from these direct APIs.

**FUTURE / NOT EXECUTED:** a separately scoped adapter control should prove
Stage B selection with a multi-transaction block and directly record snapshot
publication calls, including refused-transaction entries, cache/backend outcomes
and bounded worker completion. One transaction or unchanged final values would
not prove selection or zero service writes.

## Commands, environment and complete retained output

Run on 2026-11-09 from `/workspaces/QBIND/olivexo28/QBIND`:

```sh
timeout --signal=TERM --kill-after=15s 600s env CARGO_BUILD_JOBS=2 cargo test -vv -p qbind-ledger --lib checked_arithmetic_oracle -- --nocapture --test-threads=1
timeout --signal=TERM --kill-after=15s 600s env ROCKSDB_LIB_DIR=/workspaces/QBIND/olivexo28/QBIND/target/debug/build/librocksdb-sys-99da6cff1b808b15/out ROCKSDB_STATIC=1 CARGO_BUILD_JOBS=2 cargo test -vv --release -p qbind-ledger --lib checked_arithmetic_oracle -- --nocapture --test-threads=1
timeout --signal=TERM --kill-after=15s 600s env CARGO_BUILD_JOBS=2 cargo build -vv -p qbind-ledger --lib
```

Each command redirected all stdout/stderr to its new raw log, preceded by
`COMMAND:` and followed by captured `ACTUAL_EXIT_STATUS`. Logs retain warnings
and failed assertions, not only summaries. Exit statuses respectively:
**101, 101, 0**. Runtime `catch_unwind` catches unwind engine outcomes, then
the conformance assertion fails honestly. Pools returned/propagated panic
through `install` and were dropped; this is not an explicit worker-join test.
Timeouts bound each cargo process; none fired.

Environment: Ubuntu 24.04.3 LTS; x86_64 Linux `6.12.8+`;
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`, LLVM 23.1.1,
host `x86_64-unknown-linux-gnu`;
`cargo 1.99.1 (5f94df478 2026-08-27)`.
`CARGO_HOME=/usr/local/cargo`, `RUSTUP_HOME=/usr/local/rustup`.
Inspected inherited build variables contained no RUSTFLAGS, encoded rustflags,
profile or RocksDB override; overrides used for release are explicit above.

Actual verbose rustc settings: debug library test has `--test`,
`-C strip=debuginfo`, no optimization override; release has `--test`,
`-C opt-level=3 -C strip=debuginfo`. Workspace dev/test profiles disable debug
information and incremental compilation (`Cargo.toml:32-40` at the source pin).
Neither inspected profile sets overflow checks or panic explicitly.
Runtime prints confirm unwind in both builds, debug assertions true/false
respectively, overflow probe panic/wrap respectively. No explicit-overflow-check
override matrix or abort build ran; no claim is derived solely from profile names.

Initial disk availability was 143 MiB. Release reused the existing native
RocksDB archive via explicit environment variables to avoid rebuilding it;
Rust ledger/test code compiled in release. No database was opened. After
hashing the executable, only this task's newly created `target/release` directory
was removed to recover space. Existing debug artifacts and historical logs
were preserved.

Raw logs alongside this document:

| File | Lines / bytes | SHA-256 |
|---|---|---|
| `checked-arithmetic-oracle-debug-20261109.txt` | 6,066 / 391,122 | `85e5194462fb3a727067d39d2e899d2b92a5e0caec15ec0794d28a732b8e91b0` |
| `checked-arithmetic-oracle-release-20261109.txt` | 9,917 / 909,810 | `7f8cbf520553b4be9aeaa07a90d86844b985708a5ae37b91bf8fbc2391a62a34` |
| `checked-arithmetic-oracle-nontest-build-20261109.txt` | 974 / 53,018 | `7cd6a5350e5b470435c55962431e215c46c0809a20eeb5c6e733c2d8a111145a` |

Executed binary SHA-256:
debug `target/debug/deps/qbind_ledger-72b82d59c834f0fc`:
`a48bafea9555f81f7886be85aecb1ce53d76bdffc1a4a5665a2de96322ba2835`;
release `target/release/deps/qbind_ledger-5162086cd07c177b` (before cleanup):
`9afecf143163a3bc9ee72f4055461ce4f1c3c854bea516ac7b93a53f4179fd98`.

## Delivery scope and limits

Relative to reviewed `b123a4e3757eec0d1a615c5001904b42ad2d4879`, the slice
is six paths: one new test module, the test-configured `parallel_exec.rs`
instrumentation, this report and three new raw logs. Relative to main the
complete scope is **40 paths**: 34 inherited plus all six slice paths, including
`parallel_exec.rs`, which was unchanged relative to main at the reviewed endpoint.
Inherited unaccepted production work remains part of that full branch; the
new slice itself introduces no non-test production behavior.

No manifests, lockfiles, historical tests or historical raw logs changed.
No production fix, ruleset activation, replay/upgrade policy, operational keys,
live node, PR, merge or deployment. The test contract does not establish
storage-error propagation, durable transaction/block atomicity, service-boundary
zero writes, quarantine or safe recovery.

Prior ATOM-1/M18 acceptances remain within reviewed scopes. Recipient overflow
remains OPEN; required-persistence candidate remains NOT ACCEPTED /
NOT INTEGRATION-READY. A23-F1 and A33-F1 / E27 remain OPEN; activation remains
DISABLED; public DevNet remains NO-GO.
