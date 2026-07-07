# QBIND DevNet Evidence — Run 305

Source/test validator-set rotation application / epoch-transition executor
boundary implementation.

Run 305 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 306.

---

## 1. Exact verdict

**PASS — Run 305 source/test validator-set rotation application / epoch-transition executor boundary implemented.**

A new narrow source/test boundary consumes a verified Run 303/304 non-mutating
validator-set rotation *plan* (the accepted `ProductionValidatorSetRotationDecision`
output that `is_accept()` and carries `Some(plan)`) and produces a typed,
deterministic, policy-gated, **non-mutating** application decision / intent for a
future executor. Default posture is `Disabled` / fail-closed. MainNet stays
refused, no live validator set, consensus state, epoch counter, or trust state is
mutated, `BasicHotStuffEngine::transition_to_epoch` is never called, and Full
C4 / C5 remain OPEN. The new validator-set rotation application / epoch-transition
executor matrix row moves Red → Yellow (source/test implementation landed,
release-binary evidence pending Run 306). The pre-existing Run 303/304
validator-set rotation intent row stays Green-for-scope.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_validator_set_rotation_application_executor.rs` — boundary module.
* `crates/qbind-node/tests/run_305_production_validator_set_rotation_application_executor_tests.rs` — 126 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_305.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_validator_set_rotation_application_executor;`.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — qualified stale non-closure prose; added a new validator-set rotation application / epoch-transition executor row Red → Yellow; refreshed status line; added Run 305 changelog entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/whitepaper/contradiction.md` — narrow Run 305 changelog entries.

---

## 3. Boundary design summary

`ProductionValidatorSetRotationApplicationExecutor` takes:

* a `ProductionValidatorSetRotationApplicationRequest` (a
  `ValidatorSetRotationApplicationAuthoritySource` plus optional custody /
  attestation / durable-replay bindings, an epoch-transition target, and an
  application nonce),
* `ProductionValidatorSetRotationApplicationInputs` (operator-trusted expected
  values, trust domain, evidence requirements, replay/freshness anchors), and
* a `ValidatorSetRotationApplicationReplaySet`.

`evaluate_validator_set_rotation_application` returns a
`ProductionValidatorSetRotationApplicationDecision` carrying a typed
`ProductionValidatorSetRotationApplicationOutcome`, an `application_id`, a
`request_id`, an optional `ProductionValidatorSetRotationApplicationIntent`, an
`intent_digest`, and a `transcript_digest`.

Ordered fail-closed gates:

1. preflight — `Disabled` default → MainNet gate → MainNet policy → production
   policy → reserved kind → config/inputs well-formedness;
2. resolve authority source (only `VerifiedRotationPlan` carrying a Run 303/304
   accept decision with `Some(plan)` can proceed);
3. rotation-plan integrity and decision↔plan consistency (plan digest,
   transcript digest, request id, integrity re-derivation);
4. field-by-field binding check vs trusted inputs (environment / chain /
   genesis / authority root / governance domain / governance epoch / proposal id
   / governance execution decision/request/intent digests / rotation decision id
   / lifecycle action / rotation action / authority sequence / quorum /
   threshold);
5. validator-set binding — current/proposed snapshot digests, delta digest,
   validator-set epoch/version, rotation nonce;
6. epoch-transition binding — the requested epoch-transition target must equal
   the plan's `validator_set_epoch` (monotonic future target derived from the
   accepted plan);
7. replay / freshness (persisted application sequence, replay set, min
   governance epoch, authority sequence, validator-set epoch/version staleness,
   equivocation);
8. evidence check (custody / attestation / durable replay);
9. application-decision-kind derivation from the plan kind;
10. application-intent construction;
11. accept.

All digests use domain-separated SHA3-256 over length-prefixed label+value
fields then `hex::encode`. Domain tags:
`QBIND:run305-validator-set-rotation-application-intent:v1`,
`QBIND:run305-validator-set-rotation-application-request:v1`,
`QBIND:run305-validator-set-rotation-application-transcript:v1`. No `Debug`
formatting and no wall-clock are used in any digest.

The boundary is pure: it never mutates the request, inputs, or replay set, never
touches `LivePqcTrustState`, never mutates a live validator set, consensus state,
or epoch counter, never calls `BasicHotStuffEngine::transition_to_epoch`, never
writes `meta:current_epoch`, never injects a reconfig block, and never writes any
files.

---

## 4. Application policy / kind / decision taxonomy

Policies (`ProductionValidatorSetRotationApplicationPolicy`):

* `Disabled` — default, fail-closed before any binding.
* `AllowSourceTestValidatorSetRotationApplication` — the only accepting policy;
  DevNet/TestNet source/test scope only.
* `RequireProductionValidatorSetRotationApplication` — reachable but fails closed
  → `ProductionValidatorSetRotationApplicationUnavailable`.
* `MainnetProductionValidatorSetRotationApplicationRequired` — reachable but
  fails closed → `MainNetProductionValidatorSetRotationApplicationUnavailable`.

Kinds (`ProductionValidatorSetRotationApplicationKind`): `Disabled` (default),
`SourceTestValidatorSetRotationApplication`,
`ProductionValidatorSetRotationApplication` (reserved / fails closed).

Application-decision kinds (`ValidatorSetRotationApplicationDecisionKind`),
derived 1:1 from the plan kind via `from_plan_kind`:
`ApplyNoOpAlreadySynchronized`, `ApplyValidatorAdd`, `ApplyValidatorRemove`,
`ApplyValidatorMetadataUpdate`, `ApplyValidatorIdentityRotation`,
`ApplyValidatorRetirement`, `ApplyEmergencyValidatorRemoval`,
`ApplyAuthoritySetSynchronization`, `ApplyBulkValidatorSetRotation`,
`UnsupportedApplication` (refused; reserved plan kind maps here).

---

## 5. Run 303/304 validator-set rotation plan binding

`ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan { decision }`
— where `decision` is a Run 303/304 `ProductionValidatorSetRotationDecision` that
`is_accept()` and carries `Some(ProductionValidatorSetRotationPlan)` — is the
**only** accepted authority source. The executor re-checks plan digest,
transcript digest, request id, and integrity re-derivation, then binds every plan
field (environment, chain, genesis, authority root, governance domain/epoch,
proposal id, governance execution decision/request/intent digests, rotation
decision id, lifecycle/rotation action, authority sequence, quorum/threshold,
current/proposed validator-set digests, delta digest, validator-set epoch/version,
rotation nonce, and any represented custody/attestation/durable bindings) against
operator-trusted inputs, then binds the epoch-transition target to
`plan.validator_set_epoch`, before it will construct an application intent.

Accepted tests (`a01`–`a30`) compose the real Run 303
`ProductionValidatorSetRotationBoundary::source_test().evaluate_validator_set_rotation(...)`
to produce a genuine accepted decision + plan, then derive the Run 305 inputs
from `decision.plan`, proving end-to-end composition with the real rotation
boundary rather than a hand-crafted stub.

---

## 6. Application-decision model

An accepted evaluation yields
`AcceptedSourceTestValidatorSetRotationApplicationDecision` carrying the derived
`decision_kind`, `environment`, `epoch_transition_target`, and `application_nonce`,
plus a populated, deterministic `ProductionValidatorSetRotationApplicationIntent`
with a stable `intent_digest`. The intent is an instruction for a *future*
executor run; it never applies a rotation. The accept outcome is non-mutating and
only `authorizes_future_mutation_only()`.

---

## 7. Accepted source/test evidence

A well-formed DevNet/TestNet request under
`AllowSourceTestValidatorSetRotationApplication`, backed by a verified Run 303/304
accept decision whose bound rotation-plan fields match every trusted input, whose
epoch-transition target equals the plan's validator-set epoch, and whose evidence
requirements are satisfied, yields
`AcceptedSourceTestValidatorSetRotationApplicationDecision` with a populated,
deterministic application intent and stable `intent_digest`. Accept is proven
across all supported application actions (`f10`, `a01`–`a30`).

---

## 8. Rejection / fail-closed evidence

Typed fail-closed outcomes are proven by tests (`b01`–`b55`, `c01`–`c09`),
including: `Disabled`, `ValidatorSetRotationApplicationBoundaryUnavailable`,
`ProductionValidatorSetRotationApplicationUnavailable`,
`MainNetProductionValidatorSetRotationApplicationUnavailable`,
`VerifiedRotationPlanRequired`, `UnverifiedRotationPlanRejected`,
`GovernanceProofAloneRejected`, `GovernanceExecutionIntentAloneRejected`,
`FixtureRotationPlanRejectedAsProductionAuthority`, `LocalOperatorProofRejected`,
`PeerMajorityProofRejected`, `CustodyOnlyProofRejected`,
`RemoteSignerOnlyProofRejected`, `CustodyAttestationOnlyProofRejected`,
`ArbitraryValidatorSetBytesRejected`, `RotationPlanDigestMismatch`,
`RotationPlanTranscriptMismatch`, `RotationPlanRequestIdMismatch`,
`RotationPlanIntegrityMismatch`, `WrongEnvironment`, `WrongChain`, `WrongGenesis`,
`WrongAuthorityRoot`, `WrongGovernanceDomain`, `WrongGovernanceEpoch`,
`WrongProposalId`, `WrongGovernanceExecutionDecisionId`,
`WrongGovernanceExecutionRequestId`, `WrongGovernanceExecutionIntentDigest`,
`WrongRotationDecisionId`, `WrongLifecycleAction`, `WrongRotationAction`,
`WrongAuthoritySequence`, `WrongQuorum`, `WrongThreshold`,
`WrongCurrentValidatorSetDigest`, `WrongProposedValidatorSetDigest`,
`WrongValidatorSetDeltaDigest`, `WrongValidatorSetEpoch`,
`WrongValidatorSetVersion`, `WrongRotationNonce`, `UnsupportedApplicationDecision`,
`WrongEpochTransitionTarget`, `CustodyBackendEvidenceRequired`,
`CustodyBackendMismatch`, `CustodyAttestationRequired`,
`CustodyAttestationMismatch`, `DurableReplayEvidenceRequired`,
`DurableReplayMismatch`, `DurableReplayUnavailable`, `ApplicationReplayRejected`,
`StaleGovernanceEpoch`, `StaleAuthoritySequence`, `StaleValidatorSetEpoch`,
`StaleValidatorSetVersion`, `ConflictingApplicationForSameRotation`,
`ValidatorSetRotationApplicationAmbiguous`, `MainNetRefused`. Every reject outcome
returns no intent and is non-mutating.

---

## 9. MainNet refusal / authority policy evidence

MainNet trust domains and MainNet policies fail closed with `MainNetRefused` /
`MainNetProductionValidatorSetRotationApplicationUnavailable`. A valid source/test
DevNet/TestNet accept does not enable any MainNet behavior. Fixture,
local-operator, peer-majority, governance-proof-alone,
governance-execution-intent-alone, custody-only, RemoteSigner-only,
custody-attestation-only, and arbitrary-validator-set-bytes "authority" are all
rejected as production authority. These paths are covered by the C-group tests.

---

## 10. Replay / recovery / idempotency evidence

`recover_validator_set_rotation_application_window` compares a candidate
application intent against a prior recorded window and returns a
`ProductionValidatorSetRotationApplicationRecoveryOutcome`: a clean
`NoPriorApplicationWindow` when there is no prior window, an
`IdempotentReplayObserved` re-derivation for a byte-identical intent, and
`RecoveryDisabled` when the policy is `Disabled`. Conflicting application intents
for the same rotation fail closed (`ConflictingApplicationForSameRotation`), and
stale governance epoch, authority sequence, validator-set epoch, and validator-set
version fail closed in evaluation. Recovery outcomes are non-mutating and claim no
durable mutation (`d01`–`d08`).

---

## 11. Non-mutation evidence

The executor returns application decisions/intents only. It never applies a plan,
never mutates a live validator set, consensus state, or epoch counter, never
mutates `LivePqcTrustState`, never calls
`BasicHotStuffEngine::transition_to_epoch`, never writes `meta:current_epoch`,
never injects a reconfig block, never writes trust-bundle sequence or
authority-marker files, and never calls Run 070. Tests `e01`–`e14` assert that
accept and reject outcomes are non-mutating, the boundary never falls back, has no
default runtime wiring, requires a verified rotation plan, reports non-mutation on
every outcome, and that only accept `authorizes_future_mutation_only()`. Named
invariant free functions back these assertions.

---

## 12. Tests run and results

* `cargo build -p qbind-node --lib` — Finished.
* `cargo test -p qbind-node --test run_305_production_validator_set_rotation_application_executor_tests` — **126 passed; 0 failed**.
* `cargo test -p qbind-node --test run_303_production_validator_set_rotation_intent_tests` — passed.
* `cargo test -p qbind-node --test run_301_production_governance_execution_engine_tests` — passed.
* `cargo test -p qbind-node --lib` — passed.

---

## 13. Security scan results

* Secret scan over all changed files — **no secrets detected**.
* CodeQL (`rust`) — the Run 305 changes are a self-contained, non-mutating, pure
  evaluation module with no unsafe code, no external I/O, no file writes, and no
  network calls; residual security risk is low. Release-mode CodeQL coverage is
  expected as part of Run 306.

---

## 14. C4/C5 matrix taxonomy status

* Validator-set rotation / authority-set synchronization intent (Run 303/304) — Green-for-scope only.
* Validator-set rotation application / epoch-transition executor — **Red → Yellow**: source/test implementation landed, release-binary evidence pending Run 306.
* MainNet authority rotation/revocation under production custody — Red.
* Production signing audit trail / crypto-agility activation / incident response — Red.
* Full MainNet release-binary evidence under production custody — Red.
* Full C4 — OPEN. C5 — OPEN.

---

## 15. Honest limitations

* Run 305 is source/test only; no release binary was built or exercised.
* No default runtime wiring and no CLI flag were added; the boundary is inert
  unless explicitly constructed and invoked in source/test.
* MainNet remains refused; MainNet authority rotation/revocation under production
  custody remains unproven (Red).
* The boundary produces application decisions/intents only; it never applies a
  rotation or an epoch transition to a live validator set, consensus, or trust
  state.

---

## 16. C4/C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 305 does not close either and
does not weaken any prior Green-for-scope status.

---

## 17. Suggested Run 306 next step

Build a real `target/release/qbind-node` plus a release-built helper, exercise the
Run 305 validator-set rotation application / epoch-transition executor boundary in
release mode, prove verified source/test DevNet/TestNet rotation plans produce
only typed non-mutating application decisions/intents, prove
missing/unverified/governance-proof-alone/governance-execution-intent-alone/
fixture/local-operator/peer-majority/custody-only/remote-signer-only/
custody-attestation-only/arbitrary-bytes rejection, prove
wrong-field / validator-set-binding / epoch-transition / replay / freshness /
evidence fail-closed behavior, prove production binary surfaces remain
Disabled/silent with no CLI flag, preserve prior Green-for-scope rows, keep
MainNet authority rotation/revocation Red, and preserve Full C4 OPEN / C5 OPEN.