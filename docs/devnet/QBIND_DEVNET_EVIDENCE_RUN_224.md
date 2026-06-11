# QBIND DevNet evidence — Run 224

**Title.** Source/test governance evaluator runtime integration.

**Status.** PASS (source/test only). Run 224 adds a typed integration layer
that composes the Run 222 production governance execution **evaluator
interface** into the Run 220 governance-execution **runtime-consumption**
pipeline at the source/test level. Runs 220–221 proved the runtime can
consume selected governance-execution policy and real sidecar load status,
and Runs 222–223 proved the typed evaluator interface boundary, but the
evaluator interface was not yet integrated as the production evaluation
target *inside* the runtime-consumption pipeline. Run 224 closes that
integration gap at the source/test level — the runtime-consumption path can
now call the evaluator interface as the next evaluation stage, while
production/on-chain/MainNet evaluators remain unavailable/fail-closed.

Run 224 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no**
real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, and **no** validator-set rotation. Release-binary
evidence for this integration is deferred to **Run 225**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 225).
* Integration layer only; fail-closed by default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend
  implementation.
* No schema/wire/marker/sequence/trust-bundle change.
* Run 224 does not weaken any prior run (Runs 070, 130–223) and does not
  claim full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`

The module is pure: every public function performs no network or file I/O,
writes no marker, writes no sequence, mutates no live trust, evicts no
sessions, and never invokes Run 070 apply. It is a composition layer over
the existing Run 220 runtime consumption, Run 222 evaluator interface,
Run 211 governance execution decision validation, and Run 213 payload
material — it adds no new schema, wire, marker, or sequence surface.

### Integration outcome

`GovernanceEvaluatorRuntimeIntegrationOutcome` distinguishes:

* `ProceedLegacyBypass` — disabled arming with an absent carrier preserves
  the Run 220 legacy bypass;
* `ProceedMutate { .. }` — runtime consumption accepted **and** the
  evaluator authorized the same lifecycle action / candidate digest /
  authority-domain sequence (the only mutation-authorizing outcome, and a
  precondition for the existing ordered mutating path, not a mutation
  itself);
* `RuntimeConsumptionFailClosed(..)` — the runtime consumption stage failed
  closed (required-but-absent or malformed carrier);
* `EvaluatorRejected(..)` — the evaluator stage rejected (any binding
  mismatch, unavailable production/on-chain/MainNet evaluator, cross-stage
  governance-decision-invalid, or invalid evaluator response);
* `MainNetPeerDrivenApplyRefused` — MainNet peer-driven apply remains
  refused even where a fixture evaluator would otherwise approve.

### Ordering

The integration preserves the required ordering: selector resolution →
sidecar/load-status derivation → runtime consumption (`consume_surface`) →
evaluator request construction → evaluator evaluation
(`evaluate_governance_decision_source` then
`verify_governance_evaluator_response`) → governance execution decision
validation → reconciliation. Mutation authorization is produced **only**
after both the runtime-consumption stage and the evaluator stage agree;
either stage rejecting yields a non-mutating outcome.

## Composition

* Composes **Run 220** runtime consumption
  (`GovernanceExecutionRuntimeConsumption` / `consume_surface`) as the first
  evaluation stage; the disabled-arming legacy bypass is preserved.
* Composes the **Run 222** evaluator request/response/interface
  (`ProductionGovernanceExecutionEvaluator`, `EvaluatorRequest`,
  `EvaluatorResponse`, `EvaluatorOutcome`) as the next evaluation stage.
* Composes **Run 211** governance execution decision validation
  (`GovernanceExecutionInput` / `Decision` / `Expectations`,
  `GovernanceAction`) for the cross-stage decision-validity reconciliation.
* Composes **Run 213** payload material: the evaluator request's
  `governance_execution_input_digest` carries the Run 211 input digest the
  Run 213 carrier transports.

## Tests

`crates/qbind-node/tests/run_224_governance_evaluator_runtime_integration_tests.rs`
— 48 tests covering A1–A12, R1–R30, ordering (evaluator evaluation happens
before any mutation authorization), deterministic digest binding, the
non-mutation guarantee for every rejection path, the MainNet peer-driven
apply refusal invariant, and compatibility with Run 220 (all runtime
surfaces reach `ProceedMutate` when both stages agree) and Run 222 (the
disabled evaluator policy fails closed).

## Invariants restated

* Run 224 is source/test evaluator-runtime integration.
* The evaluator interface is now composed into runtime consumption at the
  source/test level.
* Production/on-chain/MainNet evaluator remains unavailable/fail-closed.
* Fixture evaluator remains DevNet/TestNet source-test only.
* Emergency fixture evaluator is explicit and non-production.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* No real governance engine or on-chain proof verifier is implemented.
* Release-binary evidence is deferred to Run 225.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests`
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`
