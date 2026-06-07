# QBIND DevNet evidence — Run 211

**Title.** Source/test governance execution policy boundary.

**Status.** PASS (source/test only). Run 211 adds a typed governance
execution policy boundary that models how an approved governance decision
authorizes an authority lifecycle action: typed governance execution
inputs, decisions, policies, action authorization, enactment windows,
quorum/threshold policy, replay protection, emergency-mode separation, and
fail-closed production behavior.

Run 211 is **source/test only**. It implements **no** real governance
execution engine, **no** real on-chain governance proof verifier, **no**
MainNet governance, and **no** validator-set rotation. Release-binary
governance execution policy-boundary evidence is deferred to **Run 212**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 212).
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No authority-set rotation beyond existing lifecycle boundary checks.
* No real KMS implementation.
* No real HSM implementation.
* No real RemoteSigner backend.
* No production signing-key custody.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No marker schema change; no sequence-file schema change; no trust-bundle
  core schema change; no wire/schema change unless strictly additive and
  source/test-only.
* Run 211 does not weaken any prior run (Runs 070, 130–210) and does not
  claim full C4 or C5 closure.

## Module

`crates/qbind-node/src/pqc_governance_execution_policy.rs`

The module is pure: every public function and trait method performs no
network or file I/O, writes no marker, writes no sequence, mutates no live
trust, evicts no sessions, and never invokes Run 070 apply.

### Governance execution class

`GovernanceExecutionClass` — `Disabled` (default), `FixtureGovernance`,
`EmergencyCouncilFixture`, `OnChainGovernanceUnavailable`,
`ProductionGovernanceUnavailable`, `MainnetGovernanceUnavailable`,
`Unknown`.

### Governance execution policy

`GovernanceExecutionPolicy` — `Disabled` (default),
`FixtureGovernanceAllowed`, `EmergencyCouncilFixtureAllowed`,
`ProductionGovernanceRequired`, `MainnetGovernanceRequired`.

**Default.** `GovernanceExecutionPolicy::Disabled` — every governance
execution fails closed; existing GenesisBound / EmergencyCouncil /
OnChainGovernance proof-carrier behavior and custody / RemoteSigner /
KMS-HSM / custody-attestation paths remain unchanged.

### Governance action

`GovernanceAction` — authority signing-key initial activation, rotate,
retire, revoke, emergency revoke, policy-change request, custody-policy
change request, remote-signer-policy change request,
custody-attestation-policy change request, validator-set rotation request
placeholder, and unknown action. Only the five lifecycle-bearing actions
map to a Run 159 `LocalLifecycleAction`; the policy-change and
validator-set-rotation placeholders are rejected as unsupported.

### Typed inputs / decisions / expectations

* `GovernanceExecutionInput` binds environment, chain id, genesis hash,
  governance class, proposal id, decision id, authority root fingerprint,
  current / candidate / revoked signing-key fingerprints, governance
  action, lifecycle action, candidate digest, authority-domain sequence,
  governance proof digest, on-chain proof digest (where applicable),
  custody attestation digest (where applicable), suite id, effective /
  activation epoch, expiry epoch, replay nonce, quorum/threshold metadata,
  and emergency flag.
* `GovernanceExecutionDecision` binds proposal id, decision id,
  approved/rejected decision, authorized governance + lifecycle action,
  authorized authority root, authorized candidate digest, authorized
  sequence, effective epoch, expiry epoch, decision commitment, issuer /
  authority class, emergency flag, and replay nonce.
* `GovernanceExecutionExpectations` carries the trust-domain-derived
  expectations (including the expected governance / on-chain / custody
  digests and the logical `now_epoch`) the calling surface supplies.

### Deterministic digest helpers

* `GovernanceExecutionInput::input_digest`
* `GovernanceExecutionDecision::decision_digest`
* `governance_execution_transcript_digest`
* `governance_execution_policy_digest` (optional)

All four are domain-separated SHA3-256 hex digests.

### Evaluator trait and implementations

* `GovernanceExecutionEvaluator` / `evaluate_governance_execution_policy`.
* `FixtureGovernanceExecutionEvaluator` — DevNet/TestNet source/test only.
* `ProductionGovernanceExecutionEvaluator`,
  `OnChainGovernanceExecutionEvaluator`,
  `MainnetGovernanceExecutionEvaluator` — callable but fail closed as
  unavailable.

### Typed outcomes

`GovernanceExecutionOutcome` distinguishes every accept/reject case the
task enumerates (disabled; fixture / emergency-council fixture accepted;
production / on-chain / MainNet unavailable; fixture and emergency-fixture
rejected under production/MainNet policy; unknown class; wrong environment
/ chain / genesis / authority root / lifecycle action / candidate digest /
sequence / governance proof digest / on-chain proof digest / custody
attestation digest / proposal id / decision id / effective epoch; expired
decision; stale/replayed decision; quorum threshold insufficient;
emergency action not authorized; validator-set rotation unsupported;
policy-change action unsupported; governance decision rejected; malformed
input / decision; unsupported version; local operator / peer majority
cannot satisfy).

### Composition / fail-closed helpers

* `evaluate_governance_execution_with_peer_driven_guard` — refuses MainNet
  peer-driven apply up front (regardless of any fixture approval) and
  otherwise wraps the evaluator outcome.
* `mainnet_peer_driven_apply_remains_refused_under_governance_execution`.
* `local_operator_cannot_satisfy_governance_execution`.
* `peer_majority_cannot_satisfy_governance_execution`.
* `validator_set_rotation_remains_unsupported`.

## Required behavior (as implemented)

* The governance execution boundary composes with Run 159 lifecycle
  actions, and binds Run 163/178/205 governance / on-chain / custody
  material **only as opaque digests**, changing none of those boundaries.
* Production governance paths return unavailable/fail-closed.
* Fixture governance is DevNet/TestNet source/test only and cannot run on
  a MainNet trust domain.
* No marker write, sequence write, live trust swap, session eviction, or
  Run 070 call occurs on any path.
* MainNet peer-driven apply remains refused even if fixture governance
  approves.

## Tests

`crates/qbind-node/tests/run_211_governance_execution_policy_tests.rs`

Covers A1–A15 and R1–R38, deterministic digest tests, proposal/decision
binding tests, action authorization tests, emergency action separation,
fixture-vs-production governance separation, the no-I/O guarantee for the
production governance path, the no-mutation guarantee, the MainNet refusal
invariant, and compatibility with the lifecycle, governance proof,
OnChainGovernance, custody, RemoteSigner, KMS/HSM, and custody-attestation
paths.

## Validation commands and results

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
  — PASS (55 tests).
* Regression targets re-run and PASS, e.g.
  `run_209_custody_attestation_policy_selector_tests` (29),
  `run_205_custody_attestation_verifier_tests` (32),
  `run_178_onchain_governance_proof_tests` (46),
  `run_163_governance_authority_verifier_tests` (59),
  `run_159_authority_signing_key_lifecycle_tests` (51),
  `cargo test -p qbind-node --lib pqc_authority` (164).

The remaining task-listed regression targets exercise unchanged surfaces;
Run 211 adds only a new source module and a new test target, so they
remain unaffected. If an exact target name differs in a later tree, locate
the nearest existing target and document the exact command/result.

## Status of guarantees after Run 211

* A typed governance execution policy boundary exists.
* Fixture governance execution is DevNet/TestNet source-test only.
* Production and MainNet governance execution remain
  unavailable/fail-closed.
* Governance input/decision/transcript digests are deterministic and
  domain-bound.
* Governance execution authorizes a lifecycle action only when the action,
  candidate digest, and sequence match.
* Emergency action is separate and explicit.
* Validator-set rotation remains unsupported.
* KMS/HSM/RemoteSigner/custody-attestation remain boundary-only.
* Governance execution boundary does **not** enable MainNet peer-driven
  apply.
* Release-binary governance execution policy-boundary evidence is deferred
  to **Run 212**.
* Full C4 remains **OPEN**. C5 remains **OPEN**.
