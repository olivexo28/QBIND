# QBIND DevNet Evidence — Run 301

Source/test real governance execution engine implementation.

Run 301 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 302.

---

## 1. Exact verdict

**PASS — Run 301 source/test real governance execution engine implemented.**

A new narrow source/test engine consumes a verified Run 299/300 on-chain
governance proof decision and produces a typed, deterministic, policy-gated,
**non-mutating** authority-lifecycle execution intent. Default posture is
`Disabled` / fail-closed. MainNet stays refused, validator-set rotation stays
unsupported (Red), and Full C4 / C5 remain OPEN.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_governance_execution_engine.rs` — engine module.
* `crates/qbind-node/tests/run_301_production_governance_execution_engine_tests.rs` — 117 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_301.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_governance_execution_engine;`.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — refreshed Current-status prose; moved governance execution engine row Red → Yellow.
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
* `docs/whitepaper/contradiction.md` — added Run 301 entry.

---

## 3. Engine design summary

`ProductionGovernanceExecutionEngine` takes:

* a `ProductionGovernanceExecutionRequest` (a `GovernanceExecutionProofSource`
  plus optional custody / attestation / durable-replay bindings),
* `ProductionGovernanceExecutionInputs` (operator-trusted expected values, trust
  domain, evidence requirements, replay/freshness anchors), and
* a `GovernanceExecutionReplaySet`.

`evaluate_production_governance_execution` returns a
`ProductionGovernanceExecutionDecision` carrying a typed
`ProductionGovernanceExecutionOutcome`, a `decision_id`, a `request_id`, an
optional `ProductionGovernanceExecutionIntent`, an `intent_digest`, and a
`transcript_digest`.

Ordered fail-closed gates in `evaluate_core`:

1. preflight — `Disabled` default → MainNet gate → MainNet policy → production
   policy → reserved kind → config/inputs well-formedness;
2. resolve proof source (only `VerifiedOnChainGovernanceProof` with a Run 299
   accept decision can proceed);
3. binding well-formedness;
4. decision ↔ binding consistency;
5. field-by-field binding check vs trusted inputs;
6. replay / freshness (persisted sequence, replay set, min governance epoch);
7. evidence check (custody / attestation / durable replay);
8. validator-set-rotation refusal gate;
9. requested-operation match;
10. `ActivateInitial` refusal;
11. intent construction;
12. accept.

All digests use domain-separated SHA3-256 over length-prefixed label+value
fields (`hash_field`) then `hex::encode`. Domain tags:
`QBIND:run301-gov-exec-intent:v1`, `QBIND:run301-gov-exec-request:v1`,
`QBIND:run301-gov-exec-transcript:v1`. No `Debug` formatting and no wall-clock
are used in any digest.

The engine is pure: it never mutates the request, inputs, or replay set, never
touches `LivePqcTrustState`, and never writes any files.

---

## 4. Governance execution policy / kind / intent taxonomy

Policies (`ProductionGovernanceExecutionEnginePolicy`):

* `Disabled` — default, fail-closed.
* `AllowSourceTestVerifiedGovernanceExecution` — the only accepting policy;
  DevNet/TestNet source/test scope only.
* `RequireProductionGovernanceExecution` — fails closed →
  `ProductionGovernanceExecutionUnavailable`.
* `MainnetProductionGovernanceExecutionRequired` — fails closed →
  `MainNetProductionGovernanceExecutionUnavailable`.

Kinds (`ProductionGovernanceExecutionEngineKind`): `Disabled` (default),
`SourceTestGovernanceExecutionEngine`, `ProductionGovernanceExecutionEngine`
(reserved / fails closed).

Requested operations (`GovernanceExecutionRequestedOperation`):
`AuthorityLifecycleRotation`, `AuthorityLifecycleRetirement`,
`AuthorityLifecycleRevocation`, `EmergencyRevocation`,
`BundleSigningKeyAuthorization`, `BundleSigningKeyRetirement`,
`BundleSigningKeyRevocation`, `GovernanceNoOp`, `ValidatorSetRotation`
(refused).

Intent kinds (`ProductionGovernanceExecutionIntentKind`):
`AuthorityLifecycleRotationIntent`, `AuthorityLifecycleRetirementIntent`,
`AuthorityLifecycleRevocationIntent`, `EmergencyRevocationIntent`,
`BundleSigningKeyAuthorizationIntent`, `BundleSigningKeyRetirementIntent`,
`BundleSigningKeyRevocationIntent`, `GovernanceNoOpIntent`. No intent kind maps
to validator-set rotation.

---

## 5. Verified on-chain governance proof binding

`GovernanceExecutionProofBinding` captures the environment, chain, genesis,
authority root, governance domain, governance epoch, proposal id, proposal
digest, proposal outcome, lifecycle action, candidate digest, authority-domain
sequence, decision id, quorum (`OnChainGovernanceQuorum`), threshold
(`GovernanceThreshold`), and proof transcript digest.

Only `GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof { decision,
binding }` — where `decision` is a Run 299
`ProductionOnChainGovernanceProofDecision` with an
`AcceptedProductionOnChainGovernanceProof` outcome — is eligible. The engine
re-checks decision↔binding consistency and then every binding field against
operator-trusted inputs before it will construct an intent.

Test `a32` builds a real Run 299 Merkle inclusion proof, verifies it with
`RealMerkleInclusionVerifier` under `AllowSourceTestProductionProof`, and feeds
the resulting accept decision into the engine, proving end-to-end composition
with the Run 299 verifier rather than a hand-crafted stub.

---

## 6. Custody / attestation / durable replay composition

Optional `GovernanceExecutionCustodyBinding`,
`GovernanceExecutionAttestationBinding`, and
`GovernanceExecutionDurableReplayBinding` compose with Run 292/294/296/298/300
surfaces. When the inputs mark a class of evidence as required, a missing
binding fails closed (`CustodyBackendEvidenceRequired`,
`CustodyAttestationRequired`, `DurableReplayEvidenceRequired`) and a mismatched
binding fails closed (`CustodyBackendMismatch`, `CustodyAttestationMismatch`,
`DurableReplayMismatch`, `DurableReplayUnavailable`).

---

## 7. Accepted source/test evidence

A well-formed DevNet/TestNet request under
`AllowSourceTestVerifiedGovernanceExecution`, backed by a verified Run 299 accept
decision whose binding matches every trusted input and whose evidence
requirements are satisfied, yields
`AcceptedSourceTestGovernanceExecutionIntent` with a populated, deterministic
`ProductionGovernanceExecutionIntent` and stable `intent_digest`. The accept
outcome is non-mutating and only `authorizes_future_mutation_only()`.

---

## 8. Rejection / fail-closed evidence

Typed fail-closed outcomes are proven by tests, including:
`Disabled`, `GovernanceExecutionEngineUnavailable`,
`ProductionGovernanceExecutionUnavailable`,
`MainNetProductionGovernanceExecutionUnavailable`,
`VerifiedOnChainGovernanceProofRequired`, `UnverifiedGovernanceProofRejected`,
`FixtureGovernanceProofRejectedAsProductionAuthority`,
`LocalOperatorProofRejected`, `PeerMajorityProofRejected`,
`CustodyOnlyProofRejected`, `RemoteSignerOnlyProofRejected`,
`CustodyAttestationOnlyProofRejected`, `GovernanceProofTranscriptMismatch`,
`WrongEnvironment`, `WrongChain`, `WrongGenesis`, `WrongAuthorityRoot`,
`WrongGovernanceDomain`, `WrongGovernanceEpoch`, `WrongProposalId`,
`WrongProposalDigest`, `WrongProposalOutcome`, `WrongLifecycleAction`,
`WrongCandidateDigest`, `WrongAuthoritySequence`, `WrongDecisionId`,
`WrongQuorum`, `WrongThreshold`, `CustodyBackendEvidenceRequired`,
`CustodyBackendMismatch`, `CustodyAttestationRequired`,
`CustodyAttestationMismatch`, `DurableReplayEvidenceRequired`,
`DurableReplayMismatch`, `DurableReplayUnavailable`, `DecisionReplayRejected`,
`StaleGovernanceEpoch`, `StaleAuthoritySequence`,
`ConflictingIntentForSameDecision`, `UnsupportedLifecycleAction`,
`ValidatorSetRotationUnsupported`, `GovernanceExecutionAmbiguous`,
`MainNetRefused`. Every reject outcome returns no intent and is non-mutating.

---

## 9. MainNet refusal / authority policy evidence

MainNet trust domains and MainNet policies fail closed with `MainNetRefused` /
`MainNetProductionGovernanceExecutionUnavailable`. A valid source/test
DevNet/TestNet accept does not enable any MainNet behavior. Fixture, local
operator, and peer-majority "proofs" are rejected as production authority. These
paths are covered by the C-group tests.

---

## 10. Replay / recovery / idempotency evidence

`recover_production_governance_execution_window` compares a candidate decision
against a prior recorded window and returns a
`ProductionGovernanceExecutionRecoveryOutcome`: a clean no-op when there is no
prior window, an idempotent match for a byte-identical intent, and a fail-closed
conflict (`ConflictingIntentForSameDecision` / `GovernanceExecutionAmbiguous`)
for any diverging proposal digest, candidate digest, lifecycle action, proof
transcript, custody evidence, or attestation evidence. Stale governance epoch
and stale authority sequence fail closed. Recovery outcomes are non-mutating.

---

## 11. Non-mutation evidence

The engine returns intents only. It never applies an intent, never mutates
`LivePqcTrustState`, never writes trust-bundle sequence or authority-marker
files, and never calls Run 070. Tests `e01`–`e10` assert that accept and reject
outcomes are non-mutating, evaluation does not mutate the replay set, and
repeated evaluation is pure/repeatable. Named invariant helpers (`is_accept`,
`is_reject`, `is_non_mutating`, `authorizes_future_mutation_only`) back these
assertions.

---

## 12. Tests run and results

* `cargo build -p qbind-node --lib` — Finished, no warnings.
* `cargo test -p qbind-node --test run_301_production_governance_execution_engine_tests` — **117 passed; 0 failed**.
* `cargo test -p qbind-node --test run_299_production_onchain_governance_proof_verifier_tests` — 63 passed.
* `cargo test -p qbind-node --test run_297_production_custody_attestation_verifier_tests` — 69 passed.
* `cargo test -p qbind-node --test run_295_production_kms_hsm_custody_backend_tests` — 89 passed.
* `cargo test -p qbind-node --test run_293_production_remote_signer_backend_tests` — 105 passed.
* `cargo test -p qbind-node --test run_291_production_durable_replay_rocksdb_tests` — 83 passed.
* `cargo test -p qbind-node --test run_186_onchain_governance_production_verifier_boundary_tests` — 46 passed.
* `cargo test -p qbind-node --test run_178_onchain_governance_proof_tests` — 44 passed.
* `cargo test -p qbind-node --lib` — 1377 passed; 0 failed.

---

## 13. C4/C5 matrix taxonomy status

* Production durable replay RocksDB backend — Green for release-binary-evidenced backend behavior only.
* Real production RemoteSigner backend — Green for release-binary-evidenced backend behavior only.
* Real KMS/HSM/cloud-KMS/PKCS#11 custody backend — Green for release-binary-evidenced backend behavior only.
* Real custody attestation verifier — Green for release-binary-evidenced custody-attestation verifier behavior only.
* Real on-chain governance proof verifier — Green for release-binary-evidenced on-chain-governance-proof-verifier behavior only.
* Governance execution engine — **Red → Yellow**: source/test implementation landed, release-binary evidence pending Run 302.
* Validator-set rotation / authority-set synchronization — Red.
* MainNet authority rotation/revocation under production custody — Red.
* Production signing audit trail / crypto-agility activation / incident response — Red.
* Full MainNet release-binary evidence under production custody — Red.
* Full C4 — OPEN. C5 — OPEN.

---

## 14. Security scan results

* Secret scan over all changed files — **no secrets detected**.
* CodeQL (`rust`) — **0 alerts**; the analysis was **skipped because the CodeQL
  database size is too large** for this repository in the sandbox. This is an
  honest environment limitation, not a clean pass. The Run 301 changes are a
  self-contained, non-mutating, pure evaluation module with no unsafe code, no
  external I/O, no file writes, and no network calls; residual security risk is
  low. Release-mode CodeQL coverage is expected as part of Run 302.

---

## 15. Honest limitations

* Run 301 is source/test only; no release binary was built or exercised.
* No default runtime wiring and no CLI flag were added; the engine is inert unless explicitly constructed and invoked in source/test.
* MainNet remains refused; validator-set rotation remains unsupported (Red).
* The pre-existing, unrelated `m16_epoch_transition_hardening_tests.rs` compile
  issue is not part of the Run 301 corpus and was not touched.

---

## 16. C4/C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 301 does not close either and
does not weaken any Run 292/294/296/298/300 Green-for-scope status.

---

## 17. Suggested Run 302 next step

Build a real `target/release/qbind-node` plus a release-built helper, exercise
the Run 301 engine in release mode, prove verified source/test DevNet/TestNet
governance decisions produce only typed non-mutating execution intents, prove
missing/malformed/unverified/replayed/wrong-domain/wrong-proof/wrong-custody/
wrong-attestation/wrong-durable-replay fail-closed behavior, prove production
binary surfaces remain Disabled/silent with no CLI flag, preserve
Run 292/294/296/298/300 Green-for-scope rows, keep validator-set rotation Red,
and preserve Full C4 OPEN / C5 OPEN.