# Sequential and direct Stage B overflow characterization

**Author-run synthetic characterization, not approved overflow behavior.**
No production changes or policy selection. Recipient overflow remains OPEN.

## Verified basis and reproducibility identity

Remote `docs/gas-disabled-arithmetic-transition-assessment` matched
`04aeaa996df84109419e0259c1cd1d3da585497d`, tree
`7268ebc7041d6391e207727823be32e5b6837140`; remote main matched
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`. Local HEAD matched and worktree
was clean before creating `test/sequential-direct-stage-b-overflow`.

Executed test-source commit: `6ba19d85bae291fde7d42d5f4f35a4bd317b8656`.
Its tree: `f802999f9fca4df437987c18e80ef6ac62eb520c`.
Its parent: `04aeaa996df84109419e0259c1cd1d3da585497d`.
The later evidence-only commit does not change executed test/source bytes.

Test path:
`crates/qbind-ledger/tests/sequential_direct_stage_b_overflow_characterization.rs`.
Test Git blob: `42b9f895d92bd5a8e3a4ac6538824c8e0ad7ed74`.
Test SHA-256:
`c81976430cc72f62f4e30100334381068d680a062ae9cbe7fb5922c007206671`.

Source citations below are pinned to **6ba19d85bae291fde7d42d5f4f35a4bd317b8656**:

- `crates/qbind-ledger/src/execution.rs:2103-2109,2147-2198,2508-2522`:
  default gas-disabled engine, transfer mutation order and sequential block API.
- `crates/qbind-ledger/src/parallel_exec.rs:475-525,567-643`:
  separate arithmetic implementation and direct Stage B block API.
- `crates/qbind-node/src/execution_adapter.rs:1321-1358,149-157`:
  adapter's multi-transaction scheduling branch and separate snapshot publication.
  These adapter APIs were **not** invoked.

## Fixture and exact API boundaries

Each case uses four distinct accounts and two ordered, disjoint transfers:

| Account | Identifier | Initial nonce | Initial balance |
|---|---|---|---|
| A | `[0x11;32]` | 4 | 100 |
| B | `[0x22;32]` | 9 | MAX for overflow/refusal, 20 for positive |
| C | `[0x33;32]` | 2 | 50 |
| D | `[0x44;32]` | 7 | 20 |

`MAX = u128::MAX = 340282366920938463463374607431768211455`.
Transaction 0 transfers 1 from A to B with nonce 4, except the refusal case
uses nonce 3. Transaction 1 transfers 3 from C to D with nonce 2 and is
always valid. Transactions use `QbindTransaction::new` and encoded
`TransferPayload`; empty synthetic signature bytes are not operational keys
or an authorization test.

The sequential path calls `VmV0ExecutionEngine::new()` (asserting gas disabled)
then **`engine.execute_block(&mut sequential_state, &txs)`**.
The Stage B path independently calls **`execute_block_stage_b(&txs, &initial)`**
inside a dedicated two-thread Rayon pool. Both receive equivalent initial
state and the same transaction vector. Stage B internally copies its input;
unchanged input is not evidence that its private working state was unchanged.

The harness records each API outcome before the comparison summary and checks
each against a fixture oracle, not against the other path. It records full
returned transaction results, including fee/gas fields, and all four account
values. An independent runtime addition probe records overflow checking instead
of assuming it from a profile name. Only the exact expected addition-overflow
panic is accepted; unexpected panics, pool construction failures, missing
results and mismatched account values fail the harness.

`catch_unwind` handles the measured unwind builds, including Rayon propagation
out of `install`. Each `install` returned or propagated a panic; the dedicated
pool was then dropped. No asynchronous work was launched by the harness after
that boundary. This does not claim an explicit thread-join observation.
An external timeout bounds the complete cargo invocation. A timeout, abort or
unsupported panic strategy would not count as a passing case. No such case
occurred; no cases were skipped.

## Independent results

Notation: account values are `(nonce,balance)`, in A/B/C/D order.
The tables are observations for the recorded builds, not required future
contract semantics.

### Sequential engine

| Case | Debug result and caller-owned state | Release result and final state |
|---|---|---|
| Overflow plus separate valid transfer | Caught `attempt to add with overflow` at `execution.rs:2194`; no block results returned. State `[(5,99),(9,MAX),(2,50),(7,20)]`; sender changed and second transaction not reached. | Both transaction results success/no error; state `[(5,99),(9,0),(3,47),(7,23)]`. |
| Two valid transfers | Both success/no error; `[(5,99),(9,21),(3,47),(7,23)]`. | Both success/no error; `[(5,99),(9,21),(3,47),(7,23)]`. |
| Nonce refusal plus separate valid transfer | First failure `NonceMismatch { expected:4, got:3 }`, second success; `[(4,100),(9,MAX),(3,47),(7,23)]`. | First failure `NonceMismatch { expected:4, got:3 }`, second success; `[(4,100),(9,MAX),(3,47),(7,23)]`. |

### Direct Stage B API

| Case | Debug outcome | Release outcome |
|---|---|---|
| Overflow plus separate valid transfer | Caught `attempt to add with overflow` at `parallel_exec.rs:521`. Results, final state and stats **unavailable** because the API panicked before returning. No inference about the private partial state or second transaction's progress. | Both success/no error; final `[(5,99),(9,0),(3,47),(7,23)]`. |
| Two valid transfers | Both success/no error; final `[(5,99),(9,21),(3,47),(7,23)]`. | Both success/no error; final `[(5,99),(9,21),(3,47),(7,23)]`. |
| Nonce refusal plus separate valid transfer | First failure `NonceMismatch { expected:4, got:3 }`, second success; final `[(4,100),(9,MAX),(3,47),(7,23)]`. | First failure `NonceMismatch { expected:4, got:3 }`, second success; final `[(4,100),(9,MAX),(3,47),(7,23)]`. |

Every returned Stage B result had stats: two transactions, one level,
maximum/average level size 2, `used_parallel=true`, `workers_used=2`.
Returned transaction results on both paths had zero gas/fee fields.

Only after these independent observations: both paths panicked in the debug
overflow case; both returned wrapped success in release. Returned controls
matched the independent expected values. This is not a general equivalence
proof, scheduling determinism proof, network divergence observation or a
desirable arithmetic-refusal outcome.

## Exact execution commands, output and environment

Working directory: `/workspaces/QBIND/olivexo28/QBIND`.
Commands on 2026-11-09 (each redirected stdout and stderr together to its
new raw log, preceded by command/timeout labels and followed by the captured
`ACTUAL_EXIT_STATUS`):

```sh
timeout --signal=TERM --kill-after=15s 600s env CARGO_BUILD_JOBS=2 cargo test -vv -p qbind-ledger --test sequential_direct_stage_b_overflow_characterization -- --nocapture --test-threads=1
timeout --signal=TERM --kill-after=15s 600s env ROCKSDB_LIB_DIR=/workspaces/QBIND/olivexo28/QBIND/target/debug/build/librocksdb-sys-99da6cff1b808b15/out ROCKSDB_STATIC=1 CARGO_BUILD_JOBS=2 cargo test -vv --release -p qbind-ledger --test sequential_direct_stage_b_overflow_characterization -- --nocapture --test-threads=1
```

Both commands actually exited **0**: three tests passed, zero failed, zero
ignored per build. No compile failures, infrastructure failures, timeouts,
unhandled panics or test-assertion failures occurred. Debug panic-hook messages
include the deliberately caught probe on all three cases and the two caught
engine panics on the overflow case; they are not unhandled test failures.
Dependency warnings are retained in full, not suppressed or relabeled.
Only the changed test target ran; no historical tests were rerun.

Environment: Ubuntu 24.04.3 LTS, x86_64 Linux kernel `6.12.8+`;
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`, LLVM 23.1.1,
host `x86_64-unknown-linux-gnu`;
`cargo 1.99.1 (5f94df478 2026-08-27)`.
`CARGO_HOME=/usr/local/cargo`, `RUSTUP_HOME=/usr/local/rustup`.
No inherited `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, profile overrides or
RocksDB overrides were present in the inspected build-variable environment.
No repository `.cargo` directory was present.

The verbose logs retain actual compiler invocations. Debug test compilation
has no optimization flag and uses `-C strip=debuginfo`; release has
`-C opt-level=3 -C strip=debuginfo`. Workspace dev/test profiles disable debug
info and incremental compilation; neither profile specifies an explicit
overflow-check or panic override (`Cargo.toml:32-40` at the source pin).
Runtime measurements were debug assertions true, unwind true, overflow probe
panicked for debug; debug assertions false, unwind true, probe wrapped to 0
for release. The API outcomes above independently confirm the engine behavior.
No additional explicit-overflow-check or panic-abort configurations were run.

Disk was initially 159 MiB free. Release reused the existing native RocksDB
archive through the explicit variables above to avoid a native rebuild; the
Rust engine, Stage B and test were compiled in release. No database was opened.
After successful execution and binary hashing, the newly created
`target/release` directory was removed to recover space. Existing debug
artifacts and historical evidence were not removed or altered.

SHA-256 evidence inventory (raw logs are complete):

| Artifact | SHA-256 |
|---|---|
| `sequential-direct-stage-b-overflow-debug-20261109.txt` (5,923 lines; 344,874 bytes) | `1d350419eacb71e388b3bac4b3522110bca7f8e486b07cdff4c599ff8f973de4` |
| `sequential-direct-stage-b-overflow-release-20261109.txt` (9,786 lines; 864,313 bytes) | `518966af531ca475cdee4affe25a1b8da8729d0f1927c540b9d32272adbdb4d5` |
| Debug executable `target/debug/deps/sequential_direct_stage_b_overflow_characterization-cea331806b0d53e9` | `e4ae4486d23dc9a7a625d51a4c368c030aec02da79bc6639561b66e933336952` |
| Release executable `target/release/deps/sequential_direct_stage_b_overflow_characterization-9cf244acc25bc5f9` (hashed before cleanup) | `edd5ec5f6f6e692b45b32a85705d06ed17b217fe11d12fc7b0ec8e6f123edd2f` |

Raw logs reside alongside this report under `docs/security/evidence/`.

## Scope and retained limitations

The new slice relative to `04aeaa996df84109419e0259c1cd1d3da585497d`
adds exactly four paths: the focused test, this report and its two raw logs.
Full scope relative to main is the inherited 30-path package plus those four:
**34 paths**, including inherited unaccepted production work. It is not a
four-file production candidate based directly on main.

No production code, manifests, lockfiles or historical logs changed. No
overflow/error policy was implemented. Direct Stage B invocation does not
establish adapter or node selection; a one-transaction adapter block would
not take its Stage B branch even when enabled. No zero underlying
service/storage updater-call claim is made: adapter snapshot publication is
a separate unexercised boundary. This in-memory work establishes no storage
failure behavior, durability, exploitability, ordinary P2P reachability,
network divergence, rollback, exclusive signer control or safe recovery.

Prior ATOM-1/M18 accepted findings retain their reviewed scopes, as do the
limitations in the pinned arithmetic assessment and earlier characterization.
No operational keys, live node, real storage failure, PR, merge, deployment
or activation. Recipient overflow remains OPEN; required-persistence candidate
remains NOT ACCEPTED / NOT INTEGRATION-READY. A23-F1 and A33-F1 / E27 remain
OPEN; activation remains DISABLED; public DevNet remains NO-GO.
