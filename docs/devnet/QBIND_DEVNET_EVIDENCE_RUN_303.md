# QBIND DevNet Evidence — Run 303

Source/test real validator-set rotation / authority-set synchronization intent
boundary implementation.

Run 303 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 304.

---

## 1. Exact verdict

**PASS — Run 303 source/test real validator-set rotation intent boundary implemented.**

A new narrow source/test boundary consumes a verified Run 301/302 governance
execution decision (the accepted `ProductionGovernanceExecutionEngine` output)
and produces a typed, deterministic, policy-gated, **non-mutating**
validator-set rotation / authority-set synchronization plan. Default posture is
`Disabled` / fail-closed. MainNet stays refused, no live validator set,
consensus state, or trust state is mutated, and Full C4 / C5 remain OPEN. The
validator-set rotation matrix row moves Red → Yellow (source/test implementation
landed, release-binary evidence pending Run 304).

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_validator_set_rotation_intent.rs` — boundary module.
* `crates/qbind-node/tests/run_303_production_validator_set_rotation_intent_tests.rs` — 131 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_303.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_validator_set_rotation_intent;`.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — refreshed Current-status prose; moved validator-set rotation / authority-set synchronization row Red → Yellow; added Run 303 changelog entry.

---

## 3. Boundary design summary

`ProductionValidatorSetRotationBoundary` takes:

* a `ProductionValidatorSetRotationRequest` (a
  `ValidatorSetRotationAuthoritySource` plus optional custody / attestation /
  durable-replay bindings, a current and proposed
  `CanonicalValidatorSetSnapshot`, and a rotation nonce),
* `ProductionValidatorSetRotationInputs` (operator-trusted expected values,
  trust domain, evidence requirements, replay/freshness anchors), and
* a `ValidatorSetRotationReplaySet`.

`evaluate_validator_set_rotation` returns a
`ProductionValidatorSetRotationDecision` carrying a typed
`ProductionValidatorSetRotationOutcome`, a `rotation_id`, a `request_id`, an
optional `ProductionValidatorSetRotationPlan`, a `plan_digest`, and a
`transcript_digest`.

Ordered fail-closed gates:

1. preflight — `Disabled` default → MainNet gate → MainNet policy → production
   policy → reserved kind → config/inputs well-formedness;
2. resolve authority source (only
   `VerifiedGovernanceExecutionIntent` carrying a Run 301/302 accept decision
   with `Some(intent)` can proceed);
3. governance execution intent well-formedness and decision↔intent consistency;
4. field-by-field binding check vs trusted inputs (environment / chain /
   genesis / authority root / governance domain / epoch / execution decision id
   / request id / intent digest / lifecycle action / candidate digest /
   authority sequence / quorum / threshold);
5. validator-set binding — current/proposed snapshot digests, epoch/version
   monotonicity, empty-set rejection, duplicate id/consensus-key/transport-key/
   authority-key rejection, unknown removal/update rejection, delta derivation;
6. replay / freshness (persisted rotation sequence, replay set, min governance
   epoch, validator-set epoch/version staleness);
7. evidence check (custody / attestation / durable replay);
8. rotation-action / plan-kind derivation;
9. plan construction;
10. accept.

All digests use domain-separated SHA3-256 over length-prefixed label+value
fields then `hex::encode`. Domain tags: `QBIND:run303-validator-identity:v1`,
`QBIND:run303-validator-record:v1`, `QBIND:run303-validator-set-snapshot:v1`,
`QBIND:run303-validator-set-delta:v1`,
`QBIND:run303-validator-set-rotation-plan:v1`,
`QBIND:run303-validator-set-rotation-request:v1`,
`QBIND:run303-validator-set-rotation-transcript:v1`. No `Debug` formatting and no
wall-clock are used in any digest. Validator records are sorted canonically
before digesting so snapshot digests are order-independent.

The boundary is pure: it never mutates the request, inputs, or replay set, never
touches `LivePqcTrustState`, never mutates a live validator set or consensus
state, never calls `BasicHotStuffEngine::transition_to_epoch`, never writes
`meta:current_epoch`, never injects a reconfig block, and never writes any files.

---

## 4. Rotation policy / kind / action / plan-kind taxonomy

Policies (`ProductionValidatorSetRotationPolicy`):

* `Disabled` — default, fail-closed before any binding.
* `AllowSourceTestValidatorSetRotationIntent` — the only accepting policy;
  DevNet/TestNet source/test scope only.
* `RequireProductionValidatorSetRotation` — reachable but fails closed →
  `ProductionValidatorSetRotationUnavailable`.
* `MainnetProductionValidatorSetRotationRequired` — reachable but fails closed →
  `MainNetProductionValidatorSetRotationUnavailable`.

Kinds (`ProductionValidatorSetRotationKind`): `Disabled` (default),
`SourceTestValidatorSetRotationIntent`, `ProductionValidatorSetRotation`
(reserved / fails closed).

Rotation actions (`ValidatorSetRotationAction`): `NoOpSynchronization`,
`ValidatorAdd`, `ValidatorRemove`, `ValidatorUpdate`,
`ValidatorIdentityRotation`, `ValidatorRetirement`, `EmergencyValidatorRemoval`,
`AuthoritySetSynchronization`, `BulkValidatorSetRotation`, `UnsupportedRotation`
(refused).

Plan kinds (`ProductionValidatorSetRotationPlanKind`):
`NoOpAlreadySynchronized`, `ValidatorAdd`, `ValidatorRemove`,
`ValidatorMetadataUpdate`, `ValidatorIdentityRotation`, `ValidatorRetirement`,
`EmergencyValidatorRemoval`, `AuthoritySetSynchronization`,
`BulkValidatorSetRotation`, `UnsupportedRotationRequest` (refused).

---

## 5. Verified governance execution intent binding

`ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent {
decision }` — where `decision` is a Run 301/302
`ProductionGovernanceExecutionDecision` that `is_accept()` and carries
`Some(ProductionGovernanceExecutionIntent)` — is the **only** accepted authority
source. The boundary re-checks decision↔intent consistency and then every bound
governance field against operator-trusted inputs before it will construct a
plan.

Test `a29` builds a verified governance execution accept decision (composing the
Run 299/300 → Run 301/302 chain) and feeds it into the boundary, proving
end-to-end composition with the real governance execution engine rather than a
hand-crafted stub.

---

## 6. Validator-set snapshot / delta binding

`CanonicalValidatorSetSnapshot` captures the environment, validator-set epoch,
validator-set version, and a canonically sorted set of
`CanonicalValidatorRecord`s (validator identity, consensus key, PQC transport
key, authority key, voting power, activation epoch). The boundary derives a
`ValidatorSetDelta` from the current and proposed snapshots and fails closed on
empty proposed sets, duplicate ids/keys, unknown removals/updates, non-monotonic
epoch/version, and ambiguous or unsupported deltas.

---

## 7. Custody / attestation / durable replay composition

Optional `GovernanceExecutionCustodyBinding`,
`GovernanceExecutionAttestationBinding`, and
`GovernanceExecutionDurableReplayBinding` compose with the Run 292/294/296/298
surfaces. When the inputs mark a class of evidence as required, a missing binding
fails closed (`CustodyBackendEvidenceRequired`, `CustodyAttestationRequired`,
`DurableReplayEvidenceRequired`) and a mismatched binding fails closed
(`CustodyBackendMismatch`, `CustodyAttestationMismatch`, `DurableReplayMismatch`,
`DurableReplayUnavailable`).

---

## 8. Accepted source/test evidence

A well-formed DevNet/TestNet request under
`AllowSourceTestValidatorSetRotationIntent`, backed by a verified Run 301/302
accept decision whose bound governance fields match every trusted input, whose
current/proposed validator-set snapshots are well-formed, and whose evidence
requirements are satisfied, yields `AcceptedSourceTestValidatorSetRotationPlan`
with a populated, deterministic `ProductionValidatorSetRotationPlan` and stable
`plan_digest`. The accept outcome is non-mutating and only
`authorizes_future_mutation_only()`.

---

## 9. Rejection / fail-closed evidence

Typed fail-closed outcomes are proven by tests, including:
`Disabled`, `ValidatorSetRotationBoundaryUnavailable`,
`ProductionValidatorSetRotationUnavailable`,
`MainNetProductionValidatorSetRotationUnavailable`,
`VerifiedGovernanceExecutionIntentRequired`,
`UnverifiedGovernanceExecutionIntentRejected`, `OnChainProofAloneRejected`,
`FixtureProofRejectedAsProductionAuthority`, `LocalOperatorProofRejected`,
`PeerMajorityProofRejected`, `CustodyOnlyProofRejected`,
`RemoteSignerOnlyProofRejected`, `CustodyAttestationOnlyProofRejected`,
`GovernanceExecutionIntentMismatch`, `GovernanceExecutionTranscriptMismatch`,
`WrongEnvironment`, `WrongChain`, `WrongGenesis`, `WrongAuthorityRoot`,
`WrongGovernanceDomain`, `WrongGovernanceEpoch`,
`WrongGovernanceExecutionDecisionId`, `WrongGovernanceExecutionRequestId`,
`WrongGovernanceExecutionIntentDigest`, `WrongLifecycleAction`,
`WrongCandidateDigest`, `WrongAuthoritySequence`, `WrongQuorum`, `WrongThreshold`,
`CurrentValidatorSetRequired`, `ProposedValidatorSetRequired`,
`CurrentValidatorSetDigestMismatch`, `ProposedValidatorSetDigestMismatch`,
`ValidatorSetEpochMismatch`, `ValidatorSetVersionMismatch`,
`NonMonotonicValidatorSetEpoch`, `NonMonotonicValidatorSetVersion`,
`EmptyProposedValidatorSetRejected`, `DuplicateValidatorId`,
`DuplicateConsensusKey`, `DuplicatePqcTransportKey`, `DuplicateAuthorityKey`,
`UnknownValidatorRemoval`, `UnknownValidatorUpdate`, `ConflictingValidatorDelta`,
`AmbiguousValidatorSetDelta`, `UnsupportedValidatorSetDelta`,
`UnsupportedRotationAction`, `CustodyBackendEvidenceRequired`,
`CustodyBackendMismatch`, `CustodyAttestationRequired`,
`CustodyAttestationMismatch`, `DurableReplayEvidenceRequired`,
`DurableReplayMismatch`, `DurableReplayUnavailable`, `RotationReplayRejected`,
`StaleGovernanceEpoch`, `StaleAuthoritySequence`, `StaleValidatorSetEpoch`,
`StaleValidatorSetVersion`, `ConflictingPlanForSameRotation`,
`ValidatorSetRotationAmbiguous`, `MainNetRefused`. Every reject outcome returns
no plan and is non-mutating.

---

## 10. MainNet refusal / authority policy evidence

MainNet trust domains and MainNet policies fail closed with `MainNetRefused` /
`MainNetProductionValidatorSetRotationUnavailable`. A valid source/test
DevNet/TestNet accept does not enable any MainNet behavior. Fixture,
local-operator, peer-majority, on-chain-proof-alone, custody-only,
RemoteSigner-only, and custody-attestation-only "authority" are all rejected as
production authority. These paths are covered by the C-group tests.

---

## 11. Replay / recovery / idempotency evidence

`recover_validator_set_rotation_window` compares a candidate plan against a prior
recorded window and returns a `ProductionValidatorSetRotationRecoveryOutcome`: a
clean `NoPriorRotationWindow` when there is no prior window, an
`IdempotentReplayObserved` re-derivation for a byte-identical plan, and
`RecoveryDisabled` when the policy is `Disabled`. Diverging proposed/current
sets, lifecycle action, or intent digest for the same window fail closed, and
stale governance epoch, authority sequence, validator-set epoch, and
validator-set version fail closed in evaluation. Recovery outcomes are
non-mutating and claim no durable mutation.

---

## 12. Non-mutation evidence

The boundary returns plans only. It never applies a plan, never mutates a live
validator set or consensus state, never mutates `LivePqcTrustState`, never writes
trust-bundle sequence or authority-marker files, and never calls Run 070. Tests
`e01`–`e08` assert that accept and reject outcomes are non-mutating, the boundary
never falls back, has no default runtime wiring, requires a verified governance
intent, reports non-mutation on every outcome, and that only accept
`authorizes_future_mutation_only()`. Named invariant free functions back these
assertions.

---

## 13. Tests run and results

* `cargo build -p qbind-node --lib` — Finished.
* `cargo test -p qbind-node --test run_303_production_validator_set_rotation_intent_tests` — **131 passed; 0 failed**.
* `cargo test -p qbind-node --test run_301_production_governance_execution_engine_tests` — passed.
* `cargo test -p qbind-node --test run_299_production_onchain_governance_proof_verifier_tests` — passed.
* `cargo test -p qbind-node --test run_297_production_custody_attestation_verifier_tests` — passed.
* `cargo test -p qbind-node --test run_295_production_kms_hsm_custody_backend_tests` — passed.
* `cargo test -p qbind-node --test run_293_production_remote_signer_backend_tests` — passed.
* `cargo test -p qbind-node --test run_291_production_durable_replay_rocksdb_tests` — passed.
* `cargo test -p qbind-node --lib` — passed.

---

## 14. C4/C5 matrix taxonomy status

* Production durable replay RocksDB backend — Green for release-binary-evidenced backend behavior only.
* Real production RemoteSigner backend — Green for release-binary-evidenced backend behavior only.
* Real KMS/HSM/cloud-KMS/PKCS#11 custody backend — Green for release-binary-evidenced backend behavior only.
* Real custody attestation verifier — Green for release-binary-evidenced custody-attestation verifier behavior only.
* Real on-chain governance proof verifier — Green for release-binary-evidenced on-chain-governance-proof-verifier behavior only.
* Governance execution engine — Green for release-binary-evidenced governance-execution-engine behavior only.
* Validator-set rotation / authority-set synchronization — **Red → Yellow**: source/test implementation landed, release-binary evidence pending Run 304.
* MainNet authority rotation/revocation under production custody — Red.
* Production signing audit trail / crypto-agility activation / incident response — Red.
* Full MainNet release-binary evidence under production custody — Red.
* Full C4 — OPEN. C5 — OPEN.

---

## 15. Security scan results

* Secret scan over all changed files — **no secrets detected**.
* CodeQL (`rust`) — the Run 303 changes are a self-contained, non-mutating, pure
  evaluation module with no unsafe code, no external I/O, no file writes, and no
  network calls; residual security risk is low. Release-mode CodeQL coverage is
  expected as part of Run 304.

---

## 16. Honest limitations

* Run 303 is source/test only; no release binary was built or exercised.
* No default runtime wiring and no CLI flag were added; the boundary is inert
  unless explicitly constructed and invoked in source/test.
* MainNet remains refused; MainNet authority rotation/revocation under production
  custody remains unproven (Red).
* The boundary produces plans only; it never applies a rotation to a live
  validator set, consensus, or trust state.

---

## 17. C4/C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 303 does not close either and
does not weaken any Run 292/294/296/298/300/302 Green-for-scope status.

---

## 18. Suggested Run 304 next step

Build a real `target/release/qbind-node` plus a release-built helper, exercise
the Run 303 validator-set rotation intent boundary in release mode, prove
verified source/test DevNet/TestNet governance execution intents produce only
typed non-mutating validator-set rotation plans, prove
missing/unverified/on-chain-alone/fixture/local-operator/peer-majority/
custody-only/remote-signer-only/custody-attestation-only rejection, prove
wrong-field / validator-set-binding / replay / freshness / evidence fail-closed
behavior, prove production binary surfaces remain Disabled/silent with no CLI
flag, preserve Run 292/294/296/298/300/302 Green-for-scope rows, keep MainNet
authority rotation/revocation Red, and preserve Full C4 OPEN / C5 OPEN.
