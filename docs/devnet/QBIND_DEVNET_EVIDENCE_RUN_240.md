# QBIND DevNet evidence — Run 240

**Title.** Source/test governance evaluator durable replay backend runtime
integration.

**Status.** PASS (source/test only). Run 240 wires the Run 238 typed durable
replay-state backend boundary into the Run 236 / 232 / 230 replay/freshness +
after-success-only consume runtime path as the **durable state provider**. Run
230 proved a typed replay/freshness state boundary, Run 232 composed it into the
evaluator-runtime integration path as a mandatory pre-mutation gate, Run 234
added the strict after-success-only consume boundary, Run 236 wired the
freshness-gated mutation authorization directly into the after-success-only
consume step, and Run 238 defined a typed durable backend contract (durability,
atomicity, crash-window, fail-closed) plus a DevNet/TestNet in-memory fixture.
What was still missing was a composition that uses the durable backend as the
authoritative state provider for the runtime path: a durable read/observe that
runs **before** mutation authorization, a durable compare-and-mark-consumed that
runs **only** after a modeled successful mutation, a typed crash-window recovery
that fails closed, and a runtime call-site wiring. Run 240 closes that gap at the
source/test level.

Run 240 is **source/test only**. It implements **no** real persistent replay
backend, **no** RocksDB backend, **no** file format, **no** schema, **no**
database migration, **no** storage-format change, **no** real governance
execution engine, **no** real mutation engine, **no** real on-chain governance
proof verifier, **no** real KMS/HSM backend, **no** real RemoteSigner backend,
**no** MainNet governance enablement, **no** MainNet peer-driven apply
enablement, and **no** validator-set rotation. It changes **no** wire, schema,
marker, sequence, or trust-bundle format. Fixture restart durability is modeled
**only** through a source/test fixture snapshot (an in-process value clone, not a
file). Release-binary durable-runtime integration evidence is deferred to **Run
241**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to Run 241).
* The durable replay backend is integrated as a typed runtime state provider
  only; the integration is a pure composition, fail-closed by default.
* Fixture durable backend remains DevNet/TestNet source-test only.
* Production/MainNet durable backend remains unavailable/fail-closed.
* Fixture restart snapshot models durability only for source/test evidence
  (in-process value clone), not a real file format.
* No real persistent replay backend; no RocksDB schema change; no file-format
  change; no database migration; no storage-format change.
* No real governance execution engine; no real mutation engine; no real on-chain
  governance proof verifier.
* No KMS/HSM backend implementation; no RemoteSigner backend implementation.
* No MainNet governance enablement; no MainNet peer-driven apply enablement; no
  validator-set rotation.
* No wire/schema/marker/sequence/trust-bundle change.
* Run 240 does not weaken any prior run (Runs 070, 130–239) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_runtime_integration.rs`

Run 240 adds a new source module (registered in `lib.rs`) that composes the Run
238 durable backend primitives with the Run 230 replay/freshness runtime
evaluation. It defines:

* `DurableReplayRuntimeIntegrationInput` — the caller binding: a Run 238
  `DurableBackendDecisionInput` / `DurableBackendDecisionExpectations`, a Run 230
  `EvaluatorReplayFreshnessInput` / `EvaluatorReplayFreshnessExpectations`, the
  `DurableBackendKind`, the `ReplayStatePolicy`, and the modeled
  `DurableMutationCompletion`. Typed accessors expose the mutation/validation
  surface, environment, chain, genesis, canonical epoch, read-only-validation
  classification, and the MainNet peer-driven classification.
* `DurableReplayRuntimeOutcome` — the typed integration outcome:
  `ProceedLegacyBypassNoDurableWrite`, `ProceedDeferredObserved`,
  `ProceedFreshObserved`, `ProceedKnownFresh`, `ProceedMutationAuthorized`,
  `ConsumeDurableAfterMutationSuccess`, `DoNotConsumeBeforeApply`,
  `DoNotConsumeApplyFailed`, `DoNotConsumeRolledBack`, `CrashWindowFailClosed`,
  `DurableReplayFailClosed`, `ReplayRuntimeFailClosed`, `ConsumeRuntimeFailClosed`,
  `ProductionDurableUnavailable`, `MainNetDurableUnavailable`, and
  `MainNetPeerDrivenApplyRefused`, plus the predicates `authorizes_consume`,
  `authorizes_mutation`, `is_deferred`, `is_proceed`, `is_fail_closed`,
  `is_crash_window_fail_closed`, `is_mainnet_peer_driven_apply_refused`, and a
  stable `tag`.
* `integrate_durable_replay_runtime` — the entry composition: it refuses MainNet
  peer-driven apply first, honours the Run 214 legacy bypass, performs the
  durable read **before** mutation authorization, runs the Run 230 / 232
  replay/freshness runtime evaluation, observes a first-seen fresh decision,
  authorizes a mutation only on a fresh observed record, and performs a durable
  compare-and-mark-consumed **only** after a modeled `AppliedSuccessfully`
  mutation on an exactly-`ObservedFresh` record.
* `recover_durable_replay_runtime_crash_window` — typed crash-window recovery
  that refuses MainNet peer-driven apply first, treats production/MainNet
  crash-window classification as unavailable, and fails closed on every
  determinable crash window (including the after-consume window).
* `wire_durable_replay_runtime_callsite` — the runtime call-site wiring that maps
  the integration outcome into a `Result`, returning a
  `DurableReplayRuntimeCallsiteFailClosed` on any non-proceed outcome.
* Grep-verifiable invariant helpers, including
  `durable_observe_happens_before_mutation_authorization`,
  `consume_only_after_successful_mutation_under_durable_runtime`,
  `crash_window_ambiguity_fails_closed_under_durable_runtime`,
  `restart_snapshot_is_fixture_source_test_only_under_durable_runtime`,
  `mainnet_peer_driven_apply_remains_refused_under_durable_runtime`,
  `production_mainnet_durable_remains_unavailable_under_durable_runtime`,
  `no_rocksdb_file_schema_migration_change_under_durable_runtime`,
  `validator_set_rotation_remains_unsupported_under_durable_runtime`, and
  `durable_runtime_rejection_is_non_mutating`.

## Composition / ordering contract

The integration is pure: it performs no I/O, writes no marker, writes no
sequence, swaps no live trust, evicts no sessions, and never invokes Run 070. The
only state mutation it can cause is the explicit fixture durable observe /
compare-and-mark-consumed write on a proceed/consume path; every fail-closed
outcome leaves the backend untouched.

* **Durable read before mutation authorization.** The durable read/observe runs
  before the runtime can authorize a mutation, so a consumed / superseded /
  malformed / unavailable durable state fails closed before any mutation.
* **Freshness still gates authorization.** The Run 230 / 232 replay/freshness
  runtime must classify the decision fresh; an expired / stale / replay-detected
  decision fails closed via `ReplayRuntimeFailClosed`, and a deferred decision is
  observed but never authorizes a mutation.
* **Consume only after success.** A durable compare-and-mark-consumed happens
  **only** after a modeled `AppliedSuccessfully` mutation on an exactly-
  `ObservedFresh` record; a consume before observe, before success, after a
  failed apply, or after a rollback fails closed without consuming.
* **Read-only validation never consumes.** A read-only validation surface
  observes/reads but never authorizes a mutation or consumes, even when a
  successful mutation is modeled.
* **Crash window fails closed.** Every determinable crash window fails closed;
  recovery never silently re-authorizes or re-applies an in-flight or already-
  applied decision.
* **MainNet peer-driven apply refused.** The MainNet peer-driven apply refusal is
  guarded before any durable read, so a fresh durable state can never bypass it.

## Tests

`crates/qbind-node/tests/run_240_governance_evaluator_replay_durable_runtime_integration_tests.rs`
(63 tests, PASS).

* **A1–A21** — legacy bypass performs no durable write; first-seen fresh decisions
  are observed on DevNet/TestNet; a known-fresh re-read proceeds idempotently; a
  deferred decision is observed without authorizing a mutation; a fresh decision
  authorizes a mutation only after the durable observe; a modeled successful
  mutation consumes durably on DevNet/TestNet; a re-read after consume fails
  closed; a read-only validation surface observes but never consumes; apply
  failed / rolled back never consume; crash windows fail closed; fixture restart
  snapshot preserves observed and consumed state through the integration;
  production/MainNet durable backends are unavailable; MainNet peer-driven apply
  is refused even when the durable state reads fresh; the Run 236 and Run 238
  layers remain compatible.
* **R1–R38** — expired / stale / replay-detected decisions fail closed before any
  mutation; consumed / superseded / malformed / unavailable durable records fail
  closed; production / MainNet durable backends are unavailable; every wrong-bound
  decision field (environment, chain-id, genesis-hash, surfaces, key digest,
  source/request/response/transcript/decision digests, proposal/decision id,
  lifecycle action, candidate digest, authority-domain sequence, replay nonce) is
  rejected before any observe/consume; compare-and-mark with a wrong expected
  state is rejected; consume before observe / before success / after failed apply
  / after rollback is rejected; an ambiguous crash window fails closed; local
  operator and peer majority cannot satisfy the durable runtime policy;
  validator-set rotation and policy-change action remain unsupported; rejections
  are non-mutating; MainNet peer-driven apply is refused even when the durable
  state says fresh.
* **Ordering / callsite** — the durable observe happens before mutation
  authorization, a consume requires a prior observe, and the call-site wiring
  returns `Ok` on a proceed and `Err` on a fail-closed outcome.

## Acceptance mapping

1. The durable replay backend is integrated as a typed runtime state provider —
   `integrate_durable_replay_runtime` composes the Run 238 backend with the Run
   230 / 232 / 236 runtime path.
2. The durable read/observe runs before mutation authorization.
3. A durable compare-and-mark-consumed runs only after a modeled successful
   mutation on an exactly-fresh observed record.
4. Fixture restart snapshot durability is preserved through the integration —
   `restart_snapshot` / `from_snapshot` over an in-process value clone, no file
   format.
5. Production / MainNet durable backend remains unavailable / fail-closed.
6. Rejections are non-mutating (the composition is pure; the backend is never
   written on a rejection path).
7. MainNet peer-driven apply remains refused —
   `mainnet_peer_driven_apply_remains_refused_under_durable_runtime`.
8. No real persistent replay backend / RocksDB / file / schema / migration /
   storage-format change is claimed.
9. Release-binary durable-runtime integration evidence is deferred to Run 241.
10. No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 240 is source/test only — there is **no** release-binary durable-runtime
  integration evidence in this run; it is deferred to **Run 241**.
* The durable replay backend is integrated as a typed runtime state provider
  only; no real persistent replay backend is implemented.
* The fixture durable backend remains DevNet/TestNet source-test only; the
  production / MainNet backends remain callable-but-unavailable / fail-closed.
* Fixture restart durability is modeled only through a source/test fixture
  snapshot (in-process value clone), not a real file format.
* No RocksDB / file / schema / migration / storage-format change is implemented.
* No real governance engine, mutation engine, or on-chain proof verifier is
  implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_240_governance_evaluator_replay_durable_runtime_integration_tests`
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