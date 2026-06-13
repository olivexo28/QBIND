# QBIND DevNet evidence — Run 236

**Title.** Source/test governance evaluator replay consume runtime integration.

**Status.** PASS (source/test only). Run 236 composes the Run 232
replay/freshness **runtime integration** path with the Run 234 post-mutation
**consume boundary** into a single lifecycle integration layer that models the
full strict ordering end to end: validate replay/freshness first, authorize a
mutation only when the replay state is fresh, model the mutation completion, and
consume the replay state **only after a successful mutation completion**. Run 230
proved a typed replay/freshness state boundary, Run 231 closed its release-binary
evidence, Run 232 composed that boundary into the Run 224 evaluator-runtime
integration path as a mandatory pre-mutation gate, Run 233 closed that
composition's release-binary evidence, Run 234 added the strict after-success-only
consume boundary, and Run 235 closed that boundary's release-binary evidence.
What was still missing was a single runtime-integration layer that wires the
freshness-gated mutation authorization (Run 232) directly into the
after-success-only consume step (Run 234), so the two layers cannot disagree:
the consume layer must consume only the exact decision the freshness layer
authorized, and only after that mutation actually succeeds. Run 236 closes that
gap at the source/test level.

Run 236 is **source/test only**. It implements **no** real governance execution
engine, **no** real on-chain governance proof verifier, **no** real KMS/HSM
backend, **no** real RemoteSigner backend, **no** MainNet governance enablement,
**no** MainNet peer-driven apply enablement, and **no** validator-set rotation.
It changes **no** wire, schema, marker, sequence, or trust-bundle format and
introduces **no** RocksDB schema, file format, or database migration. It does
**not** implement persistent storage. Release-binary consume-runtime-integration
evidence is deferred to **Run 237**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to Run 237).
* A pure replay/consume runtime-integration layer only; fail-closed by default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend implementation.
* No RocksDB schema change; no file-format change; no database migration; no
  persistent storage.
* No wire/schema/marker/sequence/trust-bundle change.
* Run 236 does not weaken any prior run (Runs 070, 130–235) and does not claim
  full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_runtime_integration.rs`

Run 236 adds a new source module (registered in `lib.rs`) that composes the
Run 232 runtime integration and the Run 234 consume boundary into one lifecycle
function. It defines:

* `ReplayConsumeRuntimeIntegrationInput` — the typed integration binding,
  holding a borrowed Run 232 `GovernanceEvaluatorReplayRuntimeIntegrationContext`,
  a borrowed Run 234 `PostMutationConsumeInput` / `PostMutationConsumeExpectations`,
  and a `ReplayStatePolicy` consume-writer selector, with accessors
  (`mutation_surface`, `mutation_completion_status`, `validation_surface`,
  `environment`, `chain_id`, `genesis_hash`).
* `ReplayConsumeRuntimeOutcome` — the composed typed outcome:
  `ProceedLegacyBypassNoConsume`, `ProceedDeferredNoConsume`,
  `ProceedValidationOnlyNoConsume`, `ProceedFreshMutationAuthorized`,
  `ConsumeFixtureAfterMutationSuccess`, `DoNotConsumeBeforeApply`,
  `DoNotConsumeApplyFailed`, `DoNotConsumeRolledBack`,
  `DoNotConsumeUnsupportedSurface`, `DoNotConsumeMainNetRefused`,
  `ReplayRuntimeFailClosed(GovernanceEvaluatorReplayRuntimeOutcome)`,
  `ConsumeFailClosed { reason }`, `ProductionConsumeUnavailable`,
  `MainNetConsumeUnavailable`, and `MainNetPeerDrivenApplyRefused`. Only
  `ConsumeFixtureAfterMutationSuccess` authorizes a consume, and only after a
  successful mutation completion. Helper predicates: `authorizes_consume`,
  `no_consume`, `is_proceed`, `is_fail_closed`,
  `is_mainnet_peer_driven_apply_refused`, `tag`.
* `integrate_replay_consume_runtime` — the pure composition. It runs the Run 232
  replay/freshness runtime integration first; any non-`ProceedFresh` outcome maps
  directly to the matching non-consuming Run 236 outcome **without** calling the
  consume writer. Only on `ProceedFresh` does it override the consume layer's
  mutation-authorization outcome with the Run 232-derived `AuthorizedFresh` (so
  the two layers cannot disagree), run `perform_post_mutation_consume`, and
  project the Run 234 `ConsumeBoundaryOutcome` into the composed Run 236 outcome.
* `ReplayConsumeRuntimeCallsiteFailClosed` / `wire_replay_consume_runtime_callsite`
  — the fail-closed-by-default callsite wiring.
* Grep-verifiable invariant / fail-closed helpers:
  `consume_integrated_as_after_success_only_post_mutation_step`,
  `fresh_required_before_mutation_authorization_under_consume_runtime`,
  `deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime`,
  `mainnet_peer_driven_apply_remains_refused_under_consume_runtime`,
  `production_mainnet_consume_remains_unavailable_under_consume_runtime`,
  `validator_set_rotation_remains_unsupported_under_consume_runtime`,
  `policy_change_action_remains_unsupported_under_consume_runtime`.

## Ordering contract

The integration preserves the strict phase ordering end to end: replay/freshness
validation first (Run 230 / Run 232), then evaluator runtime integration
authorization, then the mutation attempt, then the mutation success proof, then
consume **only** after success. The composition guards MainNet peer-driven apply
refusal first (the Run 232 layer refuses before any mutation authorization, so a
fresh state can never authorize a MainNet consume), then maps the structural
non-consume reasons (legacy bypass, deferral, validation-only), and only enters
the Run 234 consume boundary on a fresh authorization. Because the Run 236 layer
overrides the consume binding's mutation-authorization outcome with the Run 232
result, the consume layer can only ever consume the exact decision the freshness
layer authorized. The composition is pure: it performs no I/O, writes no marker,
writes no sequence, swaps no live trust, evicts no sessions, and never invokes
Run 070. The only state mutation it can cause is the explicit fixture
`mark_consumed` write on the after-success consume path; every non-consume
outcome never calls the writer.

## Tests

`crates/qbind-node/tests/run_236_governance_evaluator_replay_consume_runtime_integration_tests.rs`
(56 tests, PASS).

* **A1** — legacy bypass proceeds without consume.
* **A2** — deferred proceeds without consume.
* **A3** — validation-only proceeds without consume.
* **A4** — fresh authorization before apply proceeds without consume.
* **A5–A7** — DevNet/TestNet fixture consume records consumed only after a
  successful mutation completion.
* **A8** — after fixture consume, the same decision validates as
  already-consumed / fail-closed through the Run 230 state.
* **A9–A11** — typed input accessors expose the bound fields; the composed
  outcome predicates (`is_proceed`, `is_fail_closed`, `authorizes_consume`)
  classify each variant.
* **A12** — MainNet peer-driven apply remains refused and does not consume even
  when the replay state is fresh.
* **A13–A14** — production / MainNet consume remains unavailable / fail-closed.
* **A15** — MainNet peer-driven refusal precedes and overrides any consume.
* **A16–A17** — the consume layer cannot consume a decision the freshness layer
  did not authorize (the Run 232 authorization overrides the consume binding).
* **R1–R21** — wrong / expired / stale / replayed / already-consumed / superseded
  replay state and every wrong-bound freshness field are rejected before consume
  as a Run 232 replay-runtime fail-closed.
* **R22** — malformed consume state is rejected.
* **R23–R25** — consume before apply / after failed apply / after rollback is
  rejected.
* **R26–R27** — consume on a validation-only / unsupported surface is rejected.
* **R28–R29** — production / MainNet consume unavailable is rejected.
* **R30–R31** — local operator / peer majority cannot satisfy the consume policy.
* **R32–R33** — validator-set rotation / policy-change action remain unsupported.
* **R34** — a rejection is non-mutating (the fixture store records nothing — no
  Run 070 call, no live trust swap, no session eviction, no sequence write, no
  marker write).
* **R35** — MainNet peer-driven apply remains refused and does not consume even
  if the replay state is fresh.
* Plus focused invariant coverage: consume only after a successful mutation
  completion, fixture consume without a prior observation fails closed, and the
  typed input accessors expose the exact bound fields.

## Acceptance mapping

* Replay consume is integrated as a post-success-only runtime step —
  `integrate_replay_consume_runtime`; only `ConsumeFixtureAfterMutationSuccess`
  consumes.
* Fresh is required before mutation authorization — the Run 232 layer must reach
  `ProceedFresh` before the consume boundary is entered.
* Consume is allowed only after successful mutation completion.
* Deferred is not consumed — `ProceedDeferredNoConsume`.
* Validation-only is not consumed — `ProceedValidationOnlyNoConsume`.
* Failed/rolled-back mutation is not consumed — `DoNotConsumeApplyFailed` /
  `DoNotConsumeRolledBack`.
* Fixture consume remains DevNet/TestNet source-test only.
* Production / MainNet consume remains unavailable / fail-closed —
  `ProductionConsumeUnavailable` / `MainNetConsumeUnavailable`.
* Rejections are non-mutating (the composition is pure; the writer is never
  called on a non-consume path).
* MainNet peer-driven apply remains refused and does not consume —
  `MainNetPeerDrivenApplyRefused`.
* No storage / schema / migration / RocksDB / file-format change is claimed.
* Release-binary evidence is deferred to Run 237.
* No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 236 is source/test only — there is **no** release-binary
  consume-runtime-integration evidence in this run; it is deferred to **Run 237**.
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
* `cargo test -p qbind-node --test run_236_governance_evaluator_replay_consume_runtime_integration_tests`
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests`
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`
