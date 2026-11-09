# Checked-arithmetic owner test-contract follow-up

**Owner-supplied decision in this session; test scope only.** No message ID,
URL, prior approval or timestamp is asserted. The decision does not authorize
production behavior, mutation promotion, ruleset transition, replay/upgrade
policy, activation or deployment.

## Decision recorded and source identity

The owner approved these test expectations: preserve malformed-payload, nonce
mismatch, then insufficient-balance precedence; nonce overflow refuses with
`ArithmeticOverflow { operation: "nonce increment" }`; recipient overflow
refuses with `ArithmeticOverflow { operation: "recipient balance increment" }`;
nonce overflow wins if both arithmetic checks overflow; arithmetic refusal
precedes all transaction-level updates; successful self-transfer retains its
observed final balance and two updater calls for this test contract only; and
zero amount/absent recipient preserve existing successful writes and
materialization. The owner additionally approved gas/fee assertions and a
synthetic false-overflow self-transfer regression control.

The prior baseline had said no traceable approval was then substantiated. That
statement accurately describes the historical report state and is not evidence
of an earlier decision. This owner-supplied session decision is now recorded
here and in the test module comment; it is scoped to test expectations only.

Reviewed qualifications endpoint: `a09f5a7412481a1f6da1be2309eb6fd10cede1d5`,
tree `537a9389fe580a83e34ac483feb814837368ac68`.

Follow-up tests were executed from source commit
`b04315ff71360e0db01b0e36e3a6180ceb3da412`, tree
`7c5e2df4833cb9c44f901ddf5cb4b9cd77807627`, parent
`a09f5a7412481a1f6da1be2309eb6fd10cede1d5`.

| Follow-up source | Git blob | SHA-256 |
|---|---|---|
| `crates/qbind-ledger/src/checked_arithmetic_oracle_tests.rs` | `eb29644c7f8e68b3784ec2642d1d3552d2370e06` | `d7e1c58ed0de4560b802ac7465ca44b87f68cf90e6b10be9e68190b2139575a3` |

The test module includes the source-level observation discussion and the
synthetic controls. No production arithmetic or existing test-configuration
instrumentation changed in this follow-up.

## Oracle additions and synthetic regression control

The same oracle now compares `success`, `error`, `gas_used`, `fee_paid`,
`fee_burned` and `fee_to_proposer`. Its gas-disabled expected results have all
four gas/fee fields zero. The same-oracle sensitivity loop alters each one
independently and verifies the otherwise compliant synthetic observation is
rejected. These are synthetic observation mutations, not real-engine mutants.

The false-overflow regression constructs a maximum-balance self-transfer:
sender balance `u128::MAX`, amount 1, same sender/recipient. The synthetic
calculation `original_balance.checked_add(amount)` returns `None`, which would
falsely label this transfer an overflow if checked before the debit. The
compliant expected path models the existing debit-then-restoration ordering:
the first update changes balance to `MAX-1`; the subsequent aliased recipient
read sees `MAX-1`, and crediting 1 restores `MAX`. Its expected result is
success with the test-contract's two observed updates. The synthetic
false-refusal result has unchanged state and no updates; the same oracle accepts
the compliant synthetic observation and rejects the false refusal.

This is a **synthetic regression guard**, not a mutation of either real engine.
The current implementation does perform ordinary post-debit restoration for
the tested successful maximum-balance self-transfer; this does not establish
that it implements the proposed checked arithmetic behavior on overflow cases.
No synthetic mutant was promoted to a production path.

## Actual focused follow-up results

The same filtered module ran 47 tests in each profile. Both runs reported:
**38 passed, 9 failed, 0 ignored, 368 filtered out; exit 101**. These are new
follow-up measurements, not carried-forward historical counts. The nine
failures are ordinary red conformance failures (three each for nonce overflow,
recipient overflow and simultaneous overflow, across sequential transaction,
instrumented Stage B transaction, and direct Stage B API). They are not
expected-failure tests or passes.

| Actual engine behavior in this follow-up | Debug | Release |
|---|---|---|
| Nonce overflow | Sequential and instrumented Stage B paths panic before transaction update; direct Stage B returns no result/state after panic. Conformance fails because a panic is not the typed refusal. | All paths return wrapped-success behavior; nonce becomes 0 and transaction updates occur. Conformance fails. |
| Recipient overflow | Sequential and instrumented Stage B paths panic after sender update; direct Stage B returns no result/state after panic. Conformance fails. | All paths return success with recipient balance wrapped to 0 and updates occur. Conformance fails. |
| Both arithmetic overflows | Same pre-update debug panic; conformance fails rather than receiving nonce-overflow error. | Both arithmetic values wrap with success; conformance fails. |
| Earlier validation precedence | Malformed payload, nonce mismatch and insufficient balance controls pass on all three boundaries. | Same; pass on all three boundaries. |
| Successful max-balance self-transfer | Actual sequential, internal Stage B, and direct Stage B controls pass: sender/recipient alias ends at balance MAX; internal/sequential traces show two calls. | Same; pass. |
| Other valid/self/zero/materialization/boundary controls | Pass. | Pass. |
| Synthetic oracle sensitivity | Altered gas/fee fields rejected; single-write nonempty trace rejected; false-overflow self-transfer refusal rejected while compliant expectation passes; earlier synthetic bypass/reordering controls rejected. Sensitivity test passes. | Same; sensitivity test passes. |
| Runtime arithmetic probe | Addition panics; `debug_assertions=true`, unwind. | Addition wraps to zero; `debug_assertions=false`, unwind. |

The direct one-transaction Stage B API records `writes=None`; its returned
result/state does not establish zero setter calls. Sequential updater counts
and instrumented Stage B setter counts apply only to their transaction
boundaries. None establishes adapter snapshot-publication, service or storage
updater-call counts. The void updater and infallible read interface do not
establish storage validity, durability or successful publication.

All cases ran; no cases were skipped. There were no compile/infrastructure
failures, timeout, abort or unhandled panic. In debug the three real-engine
overflow conditions raised caught runtime panics, then the ordinary conformance
assertions failed. In release they returned wrong wrapped-success outcomes and
the assertions failed. Panic-hook output for caught panics is retained in the
full logs. The synthetic controls passed; they do not make real-engine
conformance pass.

The 47 tests are ordinary, non-ignored library unit tests and remain in default
discovery. Since nine tests fail in both tested builds, unfiltered ledger or
workspace test discovery remains red. No unrelated historical suite was rerun.

## Exact commands, toolchain, flags and retained outputs

Run on 2026-11-09 in `/workspaces/QBIND/olivexo28/QBIND`:

```sh
timeout --signal=TERM --kill-after=15s 600s env CARGO_BUILD_JOBS=2 cargo test -vv -p qbind-ledger --lib checked_arithmetic_oracle -- --nocapture --test-threads=1
timeout --signal=TERM --kill-after=15s 600s env ROCKSDB_LIB_DIR=/workspaces/QBIND/olivexo28/QBIND/target/debug/build/librocksdb-sys-99da6cff1b808b15/out ROCKSDB_STATIC=1 CARGO_BUILD_JOBS=2 cargo test -vv --release -p qbind-ledger --lib checked_arithmetic_oracle -- --nocapture --test-threads=1
```

Both invocations captured complete stdout and stderr into the raw logs below,
with command and actual exit status. Actual statuses: **101 and 101**.
`CARGO_HOME=/usr/local/cargo`, `RUSTUP_HOME=/usr/local/rustup`;
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`, LLVM 23.1.1,
host `x86_64-unknown-linux-gnu`;
`cargo 1.99.1 (5f94df478 2026-08-27)`;
Ubuntu 24.04.3 LTS, x86_64 Linux kernel `6.12.8+`.
No inherited RUSTFLAGS, encoded rustflags, profile or RocksDB override was
present in the inspected build-variable environment. The release overrides
shown in its command reuse an existing native RocksDB archive; no database was
opened.

Verbose compiler invocations show debug test `--test`, `-C strip=debuginfo`,
with no optimization override; release test `--test`,
`-C opt-level=3 -C strip=debuginfo`. Workspace dev/test profile settings are
pinned in `Cargo.toml:32-40` at the source commit. Neither profile specifies
overflow checks or panic explicitly. Runtime probes establish measured
overflow behavior; no explicit-check override matrix or abort build ran.
The release test compiled Rust sources in release mode. After hashing its
executable, the task-created `target/release` directory was removed to recover
disk space. Existing debug artifacts and historical logs were preserved.

| Complete raw output | Lines / bytes | SHA-256 |
|---|---:|---|
| `checked-arithmetic-owner-followup-debug-20261109.txt` | 6,067 / 391,468 | `164dccb1a7cb7d5bc9725bbeff4683a63c40d5be8cca1d68d0cbe77a0d06930f` |
| `checked-arithmetic-owner-followup-release-20261109.txt` | 9,917 / 909,928 | `e6c58cf9ce47c4d9079752bceec2948f34aa350f94198952c9543e806ec9fcaf` |

Executed test binary SHA-256:
debug `target/debug/deps/qbind_ledger-72b82d59c834f0fc`:
`bcd8261804e25c26edf24d1c5f901e4513cc17a4cef524784b31d431afa92296`;
release `target/release/deps/qbind_ledger-5162086cd07c177b` (before cleanup):
`f333aa51052b7019f13d3d6cf0074785a045ef3621d3c869f764eeb5bbbcae27`.

The raw files preserve full output and ordinary assertion failures. The previous
baseline logs have not been edited or rerun; their producing source remains
commit `08f72bff797d6a8692967e921a5c7b9d8e6c8679` and blobs recorded in the
historical baseline report. The later attribution-only source edit was likewise
not the producer of those logs.

## Boundaries and status

This follow-up changes only test code and evidence. It does not implement
checked arithmetic in production. It establishes no storage-error propagation,
atomicity, adapter selection/publication, service/storage update counts, worker
ownership/shutdown/recovery, mixed-version/replay safety, authoritative history
or recovery authority.

Recipient overflow remains OPEN. Candidate remains NOT ACCEPTED /
NOT INTEGRATION-READY. Prior ATOM-1/M18, CB-1, CB-FIXTURE-1,
no-replacement-database, consensus-oracle and RPC dispositions remain within
reviewed scopes. A23-F1 and A33-F1 / E27 remain OPEN; activation remains
DISABLED; public DevNet remains NO-GO.
