# QBIND DevNet evidence — Run 238

**Title.** Source/test governance evaluator replay-state durable backend boundary.

**Status.** PASS (source/test only). Run 238 defines a typed, pure **durable
backend contract** for the governance evaluator replay/freshness state: the
durability, atomicity, crash-window, and fail-closed semantics that a real
persistent replay-state store would have to honour, plus a DevNet/TestNet
**in-memory fixture** that models those semantics. Run 230 proved a typed
replay/freshness state boundary, Run 232 composed it into the evaluator-runtime
integration path as a mandatory pre-mutation gate, Run 234 added the strict
after-success-only consume boundary, and Run 236 wired the freshness-gated
mutation authorization directly into the after-success-only consume step. What
was still missing was a typed contract describing how the replay state must be
**durably persisted** — what durability, atomicity, and crash-recovery
guarantees a backend must provide, and how it must fail closed when those
guarantees cannot be met. Run 238 closes that gap at the source/test level by
defining the contract and a fixture that honours it, **without** implementing any
real persistence.

Run 238 is **source/test only**. It implements **no** real RocksDB backend,
**no** file format, **no** schema, **no** database migration, **no** storage
format change, **no** real governance execution engine, **no** real mutation
engine, **no** real on-chain governance proof verifier, **no** real KMS/HSM
backend, **no** real RemoteSigner backend, **no** MainNet governance enablement,
**no** MainNet peer-driven apply enablement, and **no** validator-set rotation.
It changes **no** wire, schema, marker, sequence, or trust-bundle format.
Restart durability is modeled **only** through a source/test fixture snapshot
(an in-process value clone, not a file). Release-binary durable-backend evidence
is deferred to **Run 239**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to Run 239).
* A pure, typed durable replay-state backend boundary only; fail-closed by
  default.
* Fixture durable backend is DevNet/TestNet source-test only.
* Production/MainNet durable backend remains unavailable/fail-closed.
* Restart durability is modeled only through a source/test fixture snapshot
  (in-process value clone), not a real file format.
* No RocksDB schema change; no file-format change; no database migration; no
  storage-format change; no persistent storage.
* No real governance execution engine; no real mutation engine; no real on-chain
  governance proof verifier.
* No KMS/HSM backend implementation; no RemoteSigner backend implementation.
* No MainNet governance enablement; no MainNet peer-driven apply enablement; no
  validator-set rotation.
* No wire/schema/marker/sequence/trust-bundle change.
* Run 238 does not weaken any prior run (Runs 070, 130–237) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_backend.rs`

Run 238 adds a new source module (registered in `lib.rs`) that defines the typed
durable backend contract over the Run 230 replay/freshness state binding. It
defines:

* `DurableBackendDecisionInput` / `DurableBackendDecisionExpectations` — the
  typed decision binding, derived from a Run 230 `EvaluatorReplayFreshnessInput`
  via `from_freshness_input`, carrying the Run 230 `replay_state_key_digest` so
  the durable boundary composes with (and cannot disagree with) the Run 230
  freshness binding.
* `DurableRecordState` — the typed persisted record state a backend can report:
  `Missing`, `ObservedFresh`, `ObservedDeferred`, `ObservedExpired`,
  `ObservedStale`, `Consumed`, `ReplayDetected`, `Superseded`,
  `MalformedRecord`, `BackendUnavailable`, `ProductionBackendUnavailable`,
  `MainNetBackendUnavailable`.
* `DurableBackendOutcome` — the typed read/observe outcome:
  `ProceedFirstSeen`, `ProceedKnownFresh`, `ProceedDeferred`, and the typed
  `FailClosed*` rejections (expired, stale, replay, consumed, superseded,
  malformed record, backend unavailable, production unavailable, MainNet
  unavailable).
* `DurableConsumeOutcome` — the typed atomic consume outcome:
  `ConsumedAfterSuccess` plus typed rejections (not observed, not fresh, already
  consumed, replay/superseded, malformed, mutation not succeeded, unsupported
  surface, MainNet peer-driven apply refused, production/MainNet unavailable).
* `CrashWindow` — the typed crash-recovery classification:
  `BeforeObserve`, `AfterObserveBeforeMutation`, `AfterMutationBeforeConsume`,
  `AfterConsume`, `RollbackAfterObserve`, `ApplyFailedAfterObserve`,
  `UnknownCrashWindow`, `ProductionCrashWindowUnavailable`,
  `MainNetCrashWindowUnavailable`.
* `DurableBackendKind` — `FixtureDevNet`, `FixtureTestNet`, `Production`,
  `MainNet`. Production and MainNet are always unavailable/fail-closed.
* `DurableMutationCompletion` — `NotAttempted`, `AuthorizedButNotApplied`,
  `AppliedSuccessfully`, `ApplyFailed`, `RolledBack`.
* Reader/Writer/Atomic traits
  (`GovernanceEvaluatorReplayDurableBackendReader` / `Writer` / `Atomic`) and the
  high-level pure operations `read_decision_state`, `observe_decision_if_absent`,
  `mark_consumed_after_success`, `compare_and_mark_consumed`.
* A DevNet/TestNet in-memory fixture backend that models observed / consumed /
  replayed / superseded states and **restart durability** via `restart_snapshot`
  / `from_snapshot` over a `DurableBackendSnapshot` value clone (no file format).
* Production and MainNet backend stubs that always report
  unavailable/fail-closed.
* Crash-window classification (`classify_crash_window`) and grep-verifiable
  fail-closed/invariant helpers, including
  `mainnet_peer_driven_apply_remains_refused_under_durable_backend`,
  `production_mainnet_durable_backend_remains_unavailable`, and
  `validator_set_rotation_remains_unsupported_under_durable_backend`.

## Durability / atomicity / crash-window contract

The contract is pure: it performs no I/O, writes no marker, writes no sequence,
swaps no live trust, evicts no sessions, and never invokes Run 070. The only
state mutation the fixture can cause is an explicit in-process observe/consume
write on its in-memory map; every rejection is non-mutating.

* **Durability.** Observed/consumed state survives a fixture restart only through
  the explicit source/test `restart_snapshot` → `from_snapshot` round trip (an
  in-process value clone). No real file, schema, or storage format is implemented.
* **Atomicity.** `compare_and_mark_consumed` is the typed compare-and-set primitive:
  it consumes **only** when the persisted state is exactly `ObservedFresh` and the
  mutation completed successfully; any concurrent supersession, prior consume, or
  non-fresh state fails closed without mutating.
* **Fail-closed.** Every guard short-circuits MainNet peer-driven refusal first,
  then binding mismatch, then backend-kind availability (Production/MainNet always
  unavailable; a fixture kind under a MainNet environment is unavailable).
* **Crash window.** `classify_crash_window` maps an interrupted lifecycle to a
  typed window so recovery is deterministic and fail-closed; production/MainNet
  crash-window classification is itself unavailable.

## Tests

`crates/qbind-node/tests/run_238_governance_evaluator_replay_durable_backend_tests.rs`
(68 tests, PASS).

* **A1–A22** — first-seen observe proceeds; known-fresh read proceeds;
  deferred read proceeds without consume; expired/stale/replayed/consumed/
  superseded/malformed states fail closed; observe of an already-observed record
  is detected as replay; consume succeeds only on an exactly-fresh observed
  record after a successful mutation; fixture restart snapshot preserves observed
  and consumed state; compare-and-mark-consumed atomicity succeeds once and fails
  closed on a second attempt; typed accessors and outcome predicates classify
  each variant.
* **R1–R37** — every wrong-bound decision field (environment, validator-set,
  chain-id, genesis-hash, surface, key digest, etc.) is rejected before any
  observe/consume; consume before apply / after failed apply / after rollback is
  rejected; consume on a validation-only / unsupported surface is rejected;
  production / MainNet durable backend unavailable is rejected; validator-set
  rotation / policy-change action remain unsupported; rejections are non-mutating.
* **Crash-window classification** — each lifecycle interruption point maps to the
  expected typed `CrashWindow`; production/MainNet crash-window classification is
  unavailable.
* **MainNet refusal** — MainNet peer-driven apply remains refused and never
  observes or consumes even when the would-be state is fresh.
* **Compatibility** — composes with Runs 236, 234, 232, 230, 228, 226, 224
  without weakening them.

## Acceptance mapping

1. A typed durable replay state backend boundary exists — the module's contract
   types, traits, and pure operations.
2. The fixture backend models observed / consumed / replayed / superseded states.
3. Fixture restart snapshot models durability without a real file format —
   `restart_snapshot` / `from_snapshot` over a `DurableBackendSnapshot` value clone.
4. Compare-and-mark-consumed atomicity is tested — `compare_and_mark_consumed`
   succeeds once and fails closed on a second attempt / non-fresh state.
5. Production / MainNet durable backend remains unavailable / fail-closed.
6. Rejections are non-mutating (the contract is pure; the writer is never called
   on a rejection path).
7. MainNet peer-driven apply remains refused —
   `mainnet_peer_driven_apply_remains_refused_under_durable_backend`.
8. No RocksDB / file / schema / migration / storage-format change is claimed.
9. Release-binary evidence is deferred to Run 239.
10. No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 238 is source/test only — there is **no** release-binary durable-backend
  evidence in this run; it is deferred to **Run 239**.
* It defines a typed durable backend contract but does **not** implement
  production persistence.
* The fixture durable backend is DevNet/TestNet source-test only; the production /
  MainNet backends remain callable-but-unavailable / fail-closed.
* Restart durability is modeled only through a source/test fixture snapshot
  (in-process value clone), not a real file format.
* No RocksDB / file / schema / migration / storage-format change is implemented.
* No real governance engine, mutation engine, or on-chain proof verifier is
  implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
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
