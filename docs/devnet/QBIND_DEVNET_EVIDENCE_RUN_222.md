# QBIND DevNet evidence — Run 222

**Title.** Source/test production governance execution evaluator interface
boundary.

**Status.** PASS (source/test only). Run 222 adds a typed production
governance execution **evaluator interface** that models how a *future*
governance engine supplies decisions from a decision source, validates
decision provenance, tracks replay, checks proposal/decision state, and
returns fail-closed production outcomes — **without** implementing a real
governance execution engine or a real on-chain governance proof verifier.
Run 219 identified that the runtime can already consume governance-execution
policy and payload status (Runs 211–220) but that the production evaluator
was still only a boundary/fixture concept with no typed interface. Run 222
closes that interface gap at the source/test level.

Run 222 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no**
real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, and **no** validator-set rotation. Release-binary
evaluator-interface evidence is deferred to **Run 223**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 223).
* Evaluator interface boundary only; fail-closed by default.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No authority-set rotation beyond existing lifecycle boundary checks.
* No real KMS implementation; no real HSM implementation; no real
  RemoteSigner backend; no production signing-key custody.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No schema/wire/marker/sequence/trust-bundle change.
* Run 222 does not weaken any prior run (Runs 070, 130–221) and does not
  claim full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_execution_evaluator.rs`

The module is pure: every public function and trait method performs no
network or file I/O, writes no marker, writes no sequence, mutates no live
trust, evicts no sessions, and never invokes Run 070 apply.

### Evaluator source kind

`EvaluatorSourceKind` — `Disabled` (default), `FixtureDecisionSource`,
`EmergencyCouncilFixtureSource`, `OnChainDecisionSourceUnavailable`,
`ProductionDecisionSourceUnavailable`, `MainnetDecisionSourceUnavailable`,
`Unknown`.

### Evaluator policy

`EvaluatorPolicy` — `Disabled` (default), `FixtureDecisionSourceAllowed`,
`EmergencyCouncilFixtureSourceAllowed`, `ProductionDecisionSourceRequired`,
`MainnetDecisionSourceRequired`.

**Default.** `EvaluatorPolicy::Disabled` — every decision source fails
closed. `ProductionDecisionSourceRequired` and
`MainnetDecisionSourceRequired` require a real governance engine; Run 222
has none, so they fail closed (fixture material is rejected as
non-production; production sources are rejected as unavailable).

### Typed records

* `DecisionSourceIdentity` binds the source id, governance class,
  issuer/authority class, environment, chain id, genesis hash,
  authority-root fingerprint, governance proof digest, on-chain proof
  digest (where applicable), custody attestation digest (where
  applicable), evaluator version, and the freshness / replay window.
* `EvaluatorRequest` binds the governance-execution input digest, proposal
  id, decision id, governance / lifecycle action, candidate digest,
  authority-domain sequence, effective/expiry epoch, replay nonce, quorum
  metadata, emergency flag, and the decision-source-identity digest.
* `EvaluatorResponse` binds the request digest, decision digest,
  approved/rejected decision, authorized governance / lifecycle action,
  authorized candidate digest, authorized authority-domain sequence,
  effective/expiry epoch, replay nonce, evaluator/source id, response
  freshness/expiry, and a placeholder response commitment.

### Deterministic digest helpers

`DecisionSourceIdentity::source_identity_digest`,
`EvaluatorRequest::request_digest`, `EvaluatorResponse::response_digest`,
and `evaluator_transcript_digest` — all SHA3-256, domain-separated, and
length-prefixed so they can never collide with any other QBIND canonical
digest.

### Trait / interface

`ProductionGovernanceExecutionEvaluator` with
`evaluate_governance_decision_source` and
`verify_governance_evaluator_response`. Implementations:

* `FixtureGovernanceExecutionEvaluatorInterface` — DevNet/TestNet
  source/test only.
* `EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface` —
  explicit and non-production.
* `ProductionDecisionSourceEvaluatorInterface`,
  `OnChainDecisionSourceEvaluatorInterface`,
  `MainnetDecisionSourceEvaluatorInterface` — callable but fail closed as
  unavailable.

### Typed outcomes

`EvaluatorOutcome` distinguishes fixture / emergency acceptance, response
authorization, evaluator-disabled, production / on-chain / MainNet
unavailable, every binding mismatch (environment, chain, genesis, authority
root, governance / on-chain / custody proof digests, proposal id, decision
id, lifecycle action, candidate digest, sequence, effective epoch), expired
/ stale-replayed decisions, quorum insufficiency, emergency-action
authorization, validator-set-rotation / policy-change unsupported, malformed
source identity / request / response, unsupported evaluator version, invalid
response commitment, and the local-operator / peer-majority cannot-satisfy
fail-closed helpers.

## Composition

* Composes with the **Run 211** governance execution input/decision types
  (`GovernanceAction`, `GovernanceExecutionClass`,
  `GovernanceQuorumThreshold`) bound directly into the evaluator records.
* Composes with the **Run 213** payload material: the
  `governance_execution_input_digest` carries the Run 211 input digest the
  Run 213 carrier transports.
* Composes with the **Run 220** runtime consumption as a *future*
  production evaluator target: the `Disabled` evaluator policy is inert, so
  the Run 220 runtime-consumption behaviour is unchanged.

## Tests

`crates/qbind-node/tests/run_222_governance_execution_evaluator_tests.rs`
— 60 tests covering A1–A16, R1–R40, deterministic digest determinism,
source / request / response binding, rotate / revoke / emergency action
authorization, fixture-vs-production separation, the no-I/O guarantee for
production / on-chain / MainNet evaluator paths, the no-mutation guarantee,
the MainNet refusal invariant, and Run 211 / 213 / 220 compatibility.

## Invariants restated

* Run 222 is source/test production governance execution evaluator
  interface boundary work.
* No real governance execution engine is implemented.
* No real on-chain governance proof verifier is implemented.
* Fixture evaluator is DevNet/TestNet source/test only.
* Emergency fixture evaluator is explicit and non-production.
* Production/on-chain/MainNet evaluator remains unavailable/fail-closed.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* KMS/HSM/RemoteSigner/custody-attestation remain boundary-only.
* Release-binary evaluator-interface evidence is deferred to Run 223.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests`
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
* `cargo test -p qbind-node --lib`
