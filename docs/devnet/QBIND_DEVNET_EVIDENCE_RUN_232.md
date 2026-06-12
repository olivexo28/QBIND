# QBIND DevNet evidence — Run 232

**Title.** Source/test governance evaluator replay/freshness runtime
integration.

**Status.** PASS (source/test only). Run 232 composes the Run 230
replay/freshness state boundary into the existing Run 224 / Run 226 evaluator
runtime integration path as a **mandatory pre-mutation gate**. Run 230 proved a
typed, pure, fail-closed replay/freshness state boundary, and Run 231 closed its
release-binary evidence — but that boundary was not yet integrated into the
runtime evaluator integration path: runtime consumption + evaluator evaluation
(Run 224 / Run 226) and the replay/freshness boundary (Run 230) were proven
independently but never composed. Run 232 closes that gap at the source/test
level: the runtime integration path now calls replay/freshness validation
before any mutation authorization, and mutation is authorized only after the
evaluator and the replay/freshness state both agree that the decision is fresh.

Run 232 is **source/test only**. It implements **no** real governance execution
engine, **no** real on-chain governance proof verifier, **no** real KMS/HSM
backend, **no** real RemoteSigner backend, **no** MainNet governance
enablement, **no** MainNet peer-driven apply enablement, and **no** validator-set
rotation. It changes **no** wire, schema, marker, sequence, or trust-bundle
format and introduces **no** RocksDB schema, file format, or database migration.
Release-binary replay/freshness runtime-integration evidence is deferred to
**Run 233**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to Run 233).
* Composition of Run 230 replay/freshness into the Run 224 evaluator-runtime
  integration path only; fail-closed by default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend implementation.
* No RocksDB schema change; no file-format change; no database migration.
* No wire/schema/marker/sequence/trust-bundle change.
* Run 232 does not weaken any prior run (Runs 070, 130–231) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_evaluator_replay_runtime_integration.rs`

Run 232 adds a new source module (registered in `lib.rs`) that composes:

* **Run 224** evaluator-runtime integration
  (`integrate_governance_evaluator_runtime_consumption`);
* **Run 226** runtime call-site integration
  (`wire_governance_evaluator_runtime_callsite`);
* **Run 228** peer evaluator context where relevant
  (`evaluate_peer_evaluator_context`); and
* **Run 230** replay/freshness state boundary
  (`gate_evaluator_replay_freshness`).

It defines:

* `GovernanceEvaluatorReplayRuntimeIntegrationContext` — the typed inputs
  (the Run 224 / Run 226 integration context plus the Run 230 replay policy,
  input, and expectations).
* `GovernanceEvaluatorReplayRuntimeOutcome` — the typed outcome:
  `ProceedLegacyBypass`, `ProceedDeferred`, `ProceedFresh`,
  `ReplayFreshnessFailClosed`, `RuntimeIntegrationFailClosed`,
  `MainNetPeerDrivenApplyRefused`. Only `ProceedFresh` authorizes a mutation,
  and only after the Run 224 layer authorized a mutate **and** the Run 230
  replay/freshness state classified the decision fresh. `ProceedDeferred` is
  explicitly **not** an approval for mutation.
* `integrate_governance_evaluator_replay_runtime` — the pure composed
  integration entry point.
* `wire_governance_evaluator_replay_runtime_callsite` — the runtime call-site
  wiring that consumes the outcome (`Ok` for legacy bypass / fresh mutate,
  `Err(GovernanceEvaluatorReplayRuntimeCallsiteFailClosed)` for every
  non-proceed outcome, including a deferral).
* `wire_governance_evaluator_replay_runtime_peer_context` — the Run 228
  peer-context composition that applies the Run 230 replay/freshness gate on top
  of a routed peer-context mutate.
* Grep-verifiable fail-closed / refusal helpers:
  `mainnet_peer_driven_apply_remains_refused_under_replay_runtime`,
  `fresh_replay_state_required_before_mutation`,
  `deferred_is_never_mutation_approval`,
  `production_mainnet_replay_state_remains_unavailable`,
  `validator_set_rotation_remains_unsupported_under_replay_runtime`,
  `policy_change_action_remains_unsupported_under_replay_runtime`.

## Ordering contract

The composed integration enforces the exact pipeline ordering: selector
resolution → sidecar/load-status derivation → runtime consumption → evaluator
request construction → evaluator evaluation → governance execution decision
validation → **replay/freshness validation** → lifecycle/governance/custody/
custody-attestation checks where applicable → mutation authorization **only**
after replay/freshness returns fresh. Steps 1–6 are delegated to the Run 224 /
Run 226 layer; only a Run 224 `ProceedMutate` reaches the Run 230
replay/freshness validation, so replay/freshness validation necessarily happens
before any mutation authorization. Every entry point is pure — it performs no
I/O, writes no marker, writes no sequence, swaps no live trust, evicts no
sessions, never invokes Run 070, and never marks a decision consumed.

## Tests

`crates/qbind-node/tests/run_232_governance_evaluator_replay_runtime_integration_tests.rs`
(47 tests, PASS).

* **A1** — disabled policy + absent carrier preserves the legacy bypass and
  never reaches the replay/freshness boundary.
* **A2–A3** — DevNet/TestNet fixture evaluator decision with fresh replay state
  reaches `ProceedFresh`.
* **A4** — not-yet-effective decision reaches `ProceedDeferred`, not mutation
  authorization (even though the Run 224 evaluator approves).
* **A5** — fresh decision at the effective epoch authorizes only after the
  evaluator and the replay state both agree.
* **A6** — explicit consume marks consumed only after a successful fixture
  authorization; a re-evaluation then classifies the decision already-consumed.
* **A7** — read-only validation does not mark consumed.
* **A8** — production replay reader is reached and fails closed unavailable.
* **A9** — MainNet replay reader is reached and fails closed unavailable.
* **A10** — MainNet peer-driven apply remains refused even when the replay state
  is fresh.
* **R1–R5** — expired / stale / replayed / already-consumed / superseded
  decisions are rejected before mutation.
* **R6–R20** — wrong environment / chain / genesis / validation surface /
  source-identity digest / request digest / response digest / transcript digest
  / proposal id / decision id / lifecycle action / candidate digest /
  authority-domain sequence / replay nonce / malformed replay state are
  rejected as wrong-binding fail-closed.
* **R21–R23** — replay state / production replay state / MainNet replay state
  unavailable are rejected.
* **R24–R25** — validator-set rotation / policy-change action remain
  unsupported.
* **R26** — validation-only rejection writes no marker and no sequence (the
  fixture store records nothing).
* **R27** — a mutating rejection is non-mutating (the pure integration records
  no observation and no consume; the call-site wiring returns `Err`).
* Plus ordering (the replay/freshness validation gates mutation), a runtime
  integration fail-closed test, a not-wired-replay-policy fail-closed test, a
  call-site wiring test, MainNet refusal tests, and compatibility tests with the
  Run 230 / 228 / 226 / 224 / 222 layers.

## Acceptance mapping

* Replay/freshness validation is composed into the evaluator runtime
  integration path — `integrate_governance_evaluator_replay_runtime`.
* Fresh is required before mutation authorization — only `ProceedFresh`
  authorizes a mutation, produced only after the Run 230 validation returns
  fresh.
* Deferred is not approval — `ProceedDeferred` never authorizes a mutation.
* Expired / stale / replayed / consumed / superseded decisions fail closed
  before mutation.
* Read-only validation does not consume; explicit consume remains fixture-only
  and is performed by the caller after a fresh authorization.
* Production / MainNet replay state remains unavailable / fail-closed.
* Rejections are non-mutating (the boundary is pure).
* MainNet peer-driven apply remains refused even when state is fresh.
* No storage / schema / migration / RocksDB / file-format change is claimed.
* Release-binary evidence is deferred to Run 233.
* No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 232 is source/test only — there is **no** release-binary replay/freshness
  runtime-integration evidence in this run; it is deferred to **Run 233**.
* Fixture replay state remains DevNet/TestNet source-test only; the production /
  MainNet replay readers remain callable-but-unavailable / fail-closed and no
  real governance engine or on-chain proof verifier is implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`