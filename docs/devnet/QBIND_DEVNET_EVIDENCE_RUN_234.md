# QBIND DevNet evidence — Run 234

**Title.** Source/test governance evaluator post-mutation replay consume
boundary.

**Status.** PASS (source/test only). Run 234 adds a typed, pure
**post-mutation consume boundary** that separates four phases — pre-mutation
freshness validation (Run 230 / Run 232), mutation authorization, successful
mutation completion, and an explicit replay-state consume **after success
only**. Run 230 proved a typed replay/freshness state boundary, Run 231 closed
its release-binary evidence, Run 232 composed that boundary into the Run 224
evaluator-runtime integration path as a mandatory pre-mutation gate, and Run 233
closed that composition's release-binary evidence. What was still missing was a
strict after-success-only consume step: replay/freshness validation now happens
before mutation authorization, but the consume step that records a decision as
consumed was not modeled as a strict step that runs **only** after the mutation
succeeds. A governance decision must not be marked consumed before mutation
succeeds, and a successfully-applied decision must not be left untracked in
fixture evidence. Run 234 closes that gap at the source/test level.

Run 234 is **source/test only**. It implements **no** real governance execution
engine, **no** real on-chain governance proof verifier, **no** real KMS/HSM
backend, **no** real RemoteSigner backend, **no** MainNet governance
enablement, **no** MainNet peer-driven apply enablement, and **no** validator-set
rotation. It changes **no** wire, schema, marker, sequence, or trust-bundle
format and introduces **no** RocksDB schema, file format, or database migration.
It does **not** implement persistent storage. Release-binary consume-boundary
evidence is deferred to **Run 235**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to Run 235).
* A pure post-mutation consume boundary only; fail-closed by default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend implementation.
* No RocksDB schema change; no file-format change; no database migration; no
  persistent storage.
* No wire/schema/marker/sequence/trust-bundle change.
* Run 234 does not weaken any prior run (Runs 070, 130–233) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_boundary.rs`

Run 234 adds a new source module (registered in `lib.rs`) that models the
consume boundary as a pure function composing with the Run 230 reader/writer
traits. It defines:

* `MutationAuthorizationOutcome` — the projected result of the upstream Run 232
  mutation-authorization phase (`LegacyBypass` / `Deferred` / `AuthorizedFresh`
  / `FreshnessFailClosed` / `ValidationOnly` / `MainNetRefused`), with
  `from_replay_runtime_outcome` projecting a Run 232
  `GovernanceEvaluatorReplayRuntimeOutcome` into this view.
* `MutationCompletionStatus` — the mutation-completion phase status
  (`NotAttempted` / `AuthorizedButNotApplied` / `AppliedSuccessfully` /
  `ApplyFailed` / `RolledBack` / `ValidationOnly` / `UnsupportedSurface` /
  `MainNetRefused`).
* `PostMutationConsumeInput` / `PostMutationConsumeExpectations` — the typed
  consume binding (replay state key digest, evaluator source-identity / request
  / response / transcript / decision digests, proposal id, decision id,
  lifecycle action, candidate digest, authority-domain sequence, effective /
  expiry epoch, replay nonce, environment, chain id, genesis hash, validation
  surface, mutation surface, mutation authorization outcome, and mutation
  completion status), with `from_freshness_input` deriving both from a Run 230
  `EvaluatorReplayFreshnessInput`.
* `ConsumeBoundaryOutcome` — the typed outcome: `DoNotConsumeLegacyBypass`,
  `DoNotConsumeDeferred`, `DoNotConsumeValidationOnly`,
  `DoNotConsumeBeforeApply`, `DoNotConsumeApplyFailed`,
  `DoNotConsumeRolledBack`, `DoNotConsumeUnsupportedSurface`,
  `DoNotConsumeMainNetRefused`, `ConsumeFixtureAfterSuccess`,
  `FailClosedConsumeUnavailable`, `FailClosedProductionConsumeUnavailable`,
  `FailClosedMainNetConsumeUnavailable`, `FailClosedWrongBinding`. Only
  `ConsumeFixtureAfterSuccess` authorizes a consume, and only after
  `MutationCompletionStatus::AppliedSuccessfully`.
* `evaluate_post_mutation_consume` — the pure boundary evaluation.
* `perform_post_mutation_consume` — evaluates the boundary and, only on the
  after-success consume path, performs the explicit
  `GovernanceEvaluatorReplayStateWriter::mark_consumed` write against a Run 230
  writer (the DevNet/TestNet fixture writer records consumed only after success;
  the callable-but-unavailable production / MainNet writers always return
  `false`, downgrading to a fail-closed).
* Deterministic digest helpers: `consume_authorization_digest`,
  `consume_transcript_digest`, `post_mutation_consume_record_digest`.
* Grep-verifiable invariant / fail-closed helpers:
  `consume_only_after_successful_mutation`, `deferred_is_never_consumed`,
  `validation_only_is_never_consumed`,
  `production_mainnet_consume_remains_unavailable`,
  `mainnet_peer_driven_apply_remains_refused_under_consume_boundary`,
  `local_operator_cannot_satisfy_consume_policy`,
  `peer_majority_cannot_satisfy_consume_policy`,
  `validator_set_rotation_remains_unsupported_under_consume_boundary`,
  `policy_change_action_remains_unsupported_under_consume_boundary`.

## Ordering contract

The consume boundary preserves the strict phase ordering: replay/freshness
validation first (Run 230 / Run 232), then evaluator runtime integration
authorization, then the mutation attempt, then the mutation success proof, then
consume **only** after success. Evaluation guards MainNet peer-driven apply
refusal first (so a fresh state can never authorize a MainNet consume), then the
structural non-consume reasons (legacy bypass, deferral, validation-only), then
the binding check, then the mutation-completion phase. The boundary is pure: it
performs no I/O, writes no marker, writes no sequence, swaps no live trust,
evicts no sessions, and never invokes Run 070. The only state mutation it can
cause is the explicit fixture `mark_consumed` write on the after-success consume
path; a non-consume decision never calls the writer.

## Tests

`crates/qbind-node/tests/run_234_governance_evaluator_replay_consume_boundary_tests.rs`
(58 tests, PASS).

* **A1** — legacy bypass does not consume.
* **A2** — `ProceedDeferred` does not consume.
* **A3** — validation-only success does not consume.
* **A4** — authorized-but-not-applied does not consume.
* **A5** — apply failed does not consume.
* **A6** — rolled-back mutation does not consume.
* **A7** — unsupported surface does not consume.
* **A8** — MainNet refused does not consume.
* **A9** — DevNet fixture consume records consumed only after
  `AppliedSuccessfully`.
* **A10** — TestNet fixture consume records consumed only after
  `AppliedSuccessfully`.
* **A11** — after fixture consume, the same decision validates as
  already-consumed / fail-closed through the Run 230 state.
* **A12–A14** — consume authorization / transcript / post-mutation consume
  record digests are deterministic.
* **A15** — the consume binding includes every required field (replay state
  key, request / response / decision digests, lifecycle action, candidate
  digest, sequence, replay nonce, environment, chain id, genesis hash,
  validation surface, mutation surface, and mutation completion status).
* **A16** — the production consume writer is callable and fails closed
  unavailable.
* **A17** — the MainNet consume writer is callable and fails closed
  unavailable / refused.
* **A18** — the Run 232 replay/freshness runtime integration remains compatible
  (still authorizes a fresh mutate) when the consume boundary is not wired, and
  its outcome projects into the consume authorization view.
* **R1–R19** — wrong replay state key / source identity / request / response /
  transcript / decision digest / proposal id / decision id / lifecycle action /
  candidate digest / authority-domain sequence / effective epoch / expiry epoch
  / replay nonce / environment / chain / genesis / validation surface / mutation
  surface are rejected as wrong-binding fail-closed.
* **R20–R24** — consume before apply / after failed apply / after rollback / on
  a validation-only surface / on an unsupported surface are rejected.
* **R25–R26** — production / MainNet consume unavailable are rejected.
* **R27–R30** — local operator / peer majority cannot satisfy the consume
  policy; validator-set rotation / policy-change action remain unsupported.
* **R31** — malformed consume state is rejected.
* **R32** — a consume rejection is non-mutating (the fixture store records
  nothing — no Run 070 call, no live trust swap, no session eviction, no
  sequence write, no marker write).
* **R33** — MainNet peer-driven apply remains refused and does not consume even
  when the replay state is fresh.
* Plus focused invariant coverage: consume-after-success-only across every
  completion status, validation-only surfaces never consume, failed/rolled-back
  mutations never consume, fixture consume updates state only after an explicit
  success call, fixture consume without a prior observation fails closed,
  disabled-policy consume fails closed, and the consume binding references the
  exact Run 230 replay state key digest.

## Acceptance mapping

* A typed post-mutation consume boundary exists —
  `evaluate_post_mutation_consume` / `perform_post_mutation_consume`.
* Consume is allowed only after successful mutation completion — only
  `ConsumeFixtureAfterSuccess` (after `AppliedSuccessfully`) consumes.
* Deferred is not consumed — `DoNotConsumeDeferred`.
* Validation-only is not consumed — `DoNotConsumeValidationOnly`.
* Failed/rolled-back mutation is not consumed — `DoNotConsumeApplyFailed` /
  `DoNotConsumeRolledBack`.
* Fixture consume remains DevNet/TestNet source-test only.
* Production / MainNet consume remains unavailable / fail-closed.
* Rejections are non-mutating (the boundary is pure; the writer is never called
  on a non-consume path).
* MainNet peer-driven apply remains refused and does not consume.
* No storage / schema / migration / RocksDB / file-format change is claimed.
* Release-binary evidence is deferred to Run 235.
* No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 234 is source/test only — there is **no** release-binary consume-boundary
  evidence in this run; it is deferred to **Run 235**.
* Fixture consume remains DevNet/TestNet source-test only; the production /
  MainNet consume writers remain callable-but-unavailable / fail-closed and no
  real governance engine or on-chain proof verifier is implemented.
* No persistent storage is implemented — the fixture store is an in-process map.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* No RocksDB/file/schema/migration/storage-format change is implemented.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests`
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`
