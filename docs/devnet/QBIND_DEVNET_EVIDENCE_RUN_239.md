# QBIND DevNet evidence — Run 239

**Title.** Release-binary governance evaluator durable replay-state backend
boundary evidence.

**Status.** PASS (release-binary). Run 239 is the release-binary evidence run
for the Run 238 source/test governance evaluator **durable replay-state backend
boundary**
(`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_backend.rs`). It
proves, in release mode, that the durable backend boundary contract is exercised
through release-built code: the pure operations `read_decision_state`,
`observe_decision_if_absent`, `mark_consumed_after_success`, and the
compare-and-set primitive `compare_and_mark_consumed` over the
reader / writer / atomic traits and a DevNet/TestNet
`FixtureDurableReplayBackend`; the deterministic digest helpers; the
crash-window classifier; and the
`DurableRecordState` / `DurableBackendOutcome` / `DurableConsumeOutcome` /
`CrashWindow` / `DurableBackendKind` / `DurableMutationCompletion` taxonomies.
Run 230 proved a typed replay/freshness state boundary, Run 231 closed its
release-binary evidence, Run 232 composed that boundary into the evaluator
runtime path as a mandatory pre-mutation gate, Run 233 closed that composition's
release-binary evidence, Run 234 added the strict after-success-only consume
boundary, Run 235 closed it, Run 236 composed the consume boundary onto the
replay/freshness runtime integration, Run 237 closed it, and Run 238 specified
the durable replay-state backend contract (durability, atomicity, crash-window,
and fail-closed semantics a real persistent store would have to honour) plus a
DevNet/TestNet in-memory fixture at the source/test level. Run 239 proves on
real `target/release/qbind-node` plus a release-built helper that the
release-built code exposes and exercises the boundary: a first-seen
DevNet/TestNet decision records `ObservedFresh` and reads `ProceedKnownFresh`; a
not-yet-effective decision reads deferred (not a mutation approval); expired /
stale decisions read fail-closed; an explicit consume after a modeled successful
mutation marks consumed, after which the decision reads `FailClosedConsumed`;
read-only validation, rollback, and failed-apply never consume; observe-only and
consumed state both survive an in-process fixture restart snapshot (a value
clone, never a file format); `compare_and_mark_consumed` consumes only on an
exactly-`ObservedFresh` record and rejects a wrong expected state; the
crash-window classifier types every window and never silently approves an
after-mutation-before-consume window; the durable digests are deterministic in
release mode; production / MainNet durable backends are callable but always fail
closed unavailable; and MainNet peer-driven apply remains refused even when the
fixture reads fresh.

Run 239 is **release-binary evidence only**. It implements **no** real
persistent replay backend, **no** RocksDB schema, **no** file format, **no**
database migration, **no** real governance execution engine, **no** real
mutation engine, **no** real on-chain governance proof verifier, **no** real
KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet governance
enablement, **no** MainNet peer-driven apply enablement, and **no** validator-set
rotation. It changes **no** wire, schema, marker, sequence, or trust-bundle
format and introduces **no** storage-format change or database migration.

## Strict scope

* Release-binary evidence only.
* Uses a release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behavior change.
* No real persistent replay backend; no RocksDB schema; no file format; no
  database migration; no storage-format change.
* No real governance execution engine; no real mutation engine; no real
  on-chain governance proof verifier.
* No MainNet governance enablement; no MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend; no RemoteSigner backend.
* No network wire schema change; no trust-bundle / authority-marker / sequence
  schema change.
* No autonomous apply; no automatic apply on receipt; no peer-majority
  authority.
* Does not weaken Runs 070, 130–238, and does not claim full C4 or C5 closure.

## Release helper

`crates/qbind-node/examples/run_239_governance_evaluator_replay_durable_backend_release_binary_helper.rs`

The release-built helper exercises the Run 238 durable-backend symbols through
production library code and emits a tabular PASS/FAIL corpus
(`accepted` / `rejection` / `reachability`) plus a fixture dump (durable backend
key / record / operation-transcript / crash-window transcript digests, durable
record-state / backend-outcome / consume-outcome / crash-window values,
before/after fixture durable-backend snapshots including restart snapshots, and
a symbol inventory). Every operation runs through the pure
`read_decision_state` / `observe_decision_if_absent` /
`mark_consumed_after_success` / `compare_and_mark_consumed` /
`classify_crash_window` entry points over the reader / writer / atomic traits and
the DevNet/TestNet `FixtureDurableReplayBackend`.

### Accepted / compatible cases (A1–A25)

* **A1** — first-seen DevNet fixture decision records `ObservedFresh`.
* **A2** — first-seen TestNet fixture decision records `ObservedFresh`.
* **A3** — known fresh decision reads as `ProceedKnownFresh`.
* **A4** — not-yet-effective decision records/reads as deferred and is not a
  mutation approval.
* **A5** — expired decision records/reads as fail-closed expired.
* **A6** — stale decision records/reads as fail-closed stale.
* **A7** — explicit consume after successful mutation marks consumed.
* **A8** — same decision after consume reads as consumed / fail-closed.
* **A9** — read-only validation does not mark consumed.
* **A10** — observe-only state survives fixture restart snapshot.
* **A11** — consumed state survives fixture restart snapshot.
* **A12** — rollback after observe does not mark consumed.
* **A13** — apply-failed after observe does not mark consumed.
* **A14** — after-mutation-before-consume crash window is typed and not silently
  approved.
* **A15** — after-consume crash window reads consumed / fail-closed for a repeat
  decision.
* **A16** — durable backend key digest is deterministic in release mode.
* **A17** — durable record digest is deterministic in release mode.
* **A18** — durable operation transcript digest is deterministic in release
  mode.
* **A19** — crash-window transcript digest is deterministic in release mode.
* **A20** — production durable backend is callable and fails closed unavailable.
* **A21** — MainNet durable backend is callable and fails closed
  unavailable/refused.
* **A22** — Run 236 consume runtime integration remains compatible when the
  durable backend is not wired.
* **A23** — Run 237 release consume-runtime behavior remains compatible.
* **A24** — Run 235 release consume-boundary behavior remains compatible.
* **A25** — Run 233 release replay/freshness runtime behavior remains
  compatible.

### Rejection cases (R1–R37)

R1 wrong replay state key digest, R2 wrong source identity digest, R3 wrong
request digest, R4 wrong response digest, R5 wrong transcript digest, R6 wrong
decision digest, R7 wrong proposal id, R8 wrong decision id, R9 wrong lifecycle
action, R10 wrong candidate digest, R11 wrong authority-domain sequence, R12
wrong effective epoch, R13 wrong expiry epoch, R14 wrong replay nonce, R15 wrong
environment, R16 wrong chain, R17 wrong genesis, R18 wrong validation surface,
R19 wrong mutation surface, R20 malformed backend record, R21 replay detected,
R22 consumed decision, R23 superseded decision, R24 backend unavailable, R25
production backend unavailable, R26 MainNet backend unavailable/refused, R27
compare-and-mark-consumed with wrong expected state, R28 consume attempted
before observe, R29 consume attempted before successful mutation, R30 consume
attempted after failed apply, R31 consume attempted after rollback, R32 local
operator cannot satisfy the durable replay backend policy, R33 peer majority
cannot satisfy the durable replay backend policy, R34 validator-set rotation
unsupported, R35 policy-change action unsupported, R36 rejection produces no
Run 070 call / no live trust swap / no session eviction / no sequence write / no
marker write, R37 MainNet peer-driven apply remains refused even when the
durable backend fixture says fresh. Every rejection surfaces as a typed
`DurableBackendOutcome` / `DurableConsumeOutcome` fail-closed / non-consume
variant returned from a pure operation; the writer is never called on a
non-consume path and a malformed observe records nothing at all.

## Release harness

`scripts/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary.sh`

The harness:

* builds `target/release/qbind-node` and the release helper;
* captures the helper binary SHA-256 + ELF Build ID and the `qbind-node`
  release binary SHA-256 + ELF Build ID;
* records the git commit hash and `rustc` / `cargo` versions;
* runs the helper A1–A25 / R1–R37 corpus and asserts `verdict: PASS`;
* runs real-binary surface scenarios (`--help`, default DevNet/TestNet/MainNet,
  hidden governance-execution selector parse + invalid-selector fail-closed) and
  asserts the binary never claims an active durable-backend / persistent-replay /
  governance surface;
* writes source-reachability grep proof for the Run 238 symbols
  (`pqc_governance_evaluator_replay_durable_backend`,
  `DurableBackendDecisionInput`, `DurableBackendDecisionExpectations`,
  `DurableRecordState`, `DurableBackendOutcome`, `DurableConsumeOutcome`,
  `CrashWindow`, `DurableBackendKind`, `DurableMutationCompletion`, the
  reader / writer / atomic traits, `read_decision_state`,
  `observe_decision_if_absent`, `mark_consumed_after_success`,
  `compare_and_mark_consumed`, the fixture restart snapshot, `classify_crash_window`,
  the durable backend key / record / operation-transcript / crash-window
  transcript digest helpers, the production unavailable path, the MainNet
  unavailable/refused path, and the MainNet peer-driven refusal guard);
* proves an empty denylist across captured logs (no MainNet apply, no autonomous
  apply, no apply-on-receipt, no peer-majority authority, no real governance
  engine / mutation engine / on-chain verifier / persistent replay backend /
  KMS / HSM / RemoteSigner / custody active claim, no validator-set rotation, no
  RocksDB/file/schema/migration/storage-format/wire/marker/sequence change, no
  marker write before sequence commit, and no marker/sequence write on
  validation-only surfaces);
* records the no-mutation / mutation proofs;
* runs the regression test targets below.

## Validation commands

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_239_governance_evaluator_replay_durable_backend_release_binary_helper`
* `bash scripts/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary.sh`
* `cargo test -p qbind-node --test run_238_governance_evaluator_replay_durable_backend_tests`
* `cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests`
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests`
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`

(Plus the Run 222 / 220 / 217 / 215 / 213 / 211 / 157 / 152 / 150 / 148 / 142
regression targets exercised by the harness.) The exact captured commands,
stdout/stderr logs, per-scenario exit codes, durable backend digests, durable
record-state / backend-outcome / consume-outcome / crash-window values, and
before/after fixture durable-backend snapshots are recorded under
`docs/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary/`
(generated artifacts are `.gitignore`d; `summary.txt` is tracked).

## Acceptance mapping

1. The release-built helper exercises the Run 238 durable backend boundary
   through release library symbols.
2. Fixture backend observed / consumed / replayed / superseded states are
   release-evidenced (A1–A8 / A15 / R21–R23).
3. Fixture restart snapshot durability is release-evidenced without a real file
   format — observe-only and consumed state both survive an in-process value
   clone (A10 / A11).
4. Compare-and-mark-consumed atomicity is release-evidenced — it consumes only
   on an exactly-`ObservedFresh` record and rejects a wrong expected state
   (A7 / R27).
5. Production / MainNet durable backend remains unavailable / fail-closed
   (A20 / A21 / R24–R26).
6. Rejections are non-mutating — the operations are pure, the writer is never
   called on a non-consume path, and a malformed observe records nothing
   (R20 / R28–R31 / R36).
7. MainNet peer-driven apply remains refused and never observes or consumes even
   when the fixture reads fresh (A21 / R37).
8. No RocksDB / file / schema / migration / storage-format change is claimed.
9. Existing Run 237, Run 235, Run 233, Run 231, and Run 229 release behavior
   remains compatible (A22–A25).
10. No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 239 is release-binary durable replay-state backend boundary evidence. The
  durable backend boundary is release-evidenced as a **typed contract only**; it
  performs no I/O and authorizes no mutation directly.
* The fixture durable backend remains DevNet/TestNet evidence-only (the
  `FixtureDurableReplayBackend` is an in-process map; it reads as unavailable for
  a MainNet environment and introduces no storage format).
* The fixture restart snapshot models durability only for source/test evidence —
  `restart_snapshot` / `from_snapshot` is an in-process value clone, never a real
  file format, database, or migration.
* Production / MainNet durable backend remains unavailable / fail-closed.
* No real persistent replay backend is implemented.
* No RocksDB / file / schema / migration / storage-format change is implemented.
* No real governance engine, mutation engine, or on-chain proof verifier is
  implemented. No real KMS / HSM / RemoteSigner backend.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains OPEN.
* C5 remains OPEN.
