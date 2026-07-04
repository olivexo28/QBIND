# QBIND DevNet Evidence — Run 299

## 1. Exact verdict

**PASS / source-test real on-chain governance proof verifier implementation.**

Run 299 lands a real source/test on-chain governance proof verifier that
performs genuine verification logic — canonical domain-separated digests,
real SHA3-256 Merkle inclusion verification of a governance decision leaf
against an **explicit out-of-band trusted governance root/checkpoint**,
replay/freshness/quorum/threshold enforcement, and precise fail-closed
typed outcomes — while preserving all existing fixture-only boundaries and
MainNet refusals. It composes with the Run 178 fixture proof surface and
the Run 186 verifier boundary. The verifier defaults to **Disabled /
fail-closed**, adds **no** CLI flag, **no** default runtime wiring, and
**no** MainNet enablement.

This run is **source/test only** and is **NOT release-binary evidence**.
Release-binary evidence for the production on-chain governance proof
verifier is **deferred to Run 300**.

The on-chain-governance-proof-verifier C4/C5 matrix row moves **Red →
Yellow** (source-test implementation landed, release-binary evidence
pending Run 300). **Full C4 remains OPEN; C5 remains OPEN.**

## 2. Files changed

* `crates/qbind-node/src/pqc_production_onchain_governance_proof_verifier.rs`
  — **new** module (real verifier).
* `crates/qbind-node/src/lib.rs` — registers the new module (`pub mod
  pqc_production_onchain_governance_proof_verifier;`).
* `crates/qbind-node/tests/run_299_production_onchain_governance_proof_verifier_tests.rs`
  — **new** integration test file (83 tests, groups A–F).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_299.md` — **new** (this file).
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — matrix row Red →
  Yellow + Run 299 changelog entry + status header.
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` —
  Run 299 note.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 299 note.
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` — Run 299
  note.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 299 note.
* `docs/whitepaper/contradiction.md` — Run 299 no-contradiction entry.

## 3. Verifier design summary

`ProductionOnChainGovernanceProofVerifier<V: OnChainGovernanceInclusionVerifier>`
applies, in order:

1. **Preflight gate** (pure): Disabled policy/kind → `Disabled`; fixture
   suite → `FixtureProofRejectedAs(MainNet)ProductionAuthority`; MainNet
   trust-domain or MainNet-committed proof → `MainNetRefused` /
   `MainNetProductionGovernanceProofUnavailable`; reserved
   receipt-verifier kind → `ProductionVerifierUnavailable`;
   config/proof/inputs well-formedness; unsupported protocol/suite; and
   the canonical `proof_bytes_digest` commitment check.
2. **Binding comparison** against the authoritative `AuthorityTrustDomain`
   and the explicit `ProductionOnChainGovernanceVerificationInputs`
   (environment/chain/genesis/authority-root, governance
   domain/epoch/proposal/outcome/lifecycle-action/candidate/sequence, and
   trusted-checkpoint epoch/height anchoring).
3. **Replay**: stale-lower-sequence and decision-id replay rejection
   (caller-owned replay set, read-only).
4. **Freshness**: explicit governance height/epoch bounds only — **never
   wall-clock**.
5. **Quorum / threshold** enforcement.
6. **Real inclusion verification**: the injected
   `OnChainGovernanceInclusionVerifier` recomputes the Merkle root from
   the decision leaf + authenticated sibling path and checks it equals
   **both** the proof's claimed root **and** the explicit out-of-band
   trusted root. The verifier then independently re-checks the claimed
   root against the trusted root (defense in depth).

Only `AcceptedProductionOnChainGovernanceProof` authorizes a (source/test,
DevNet/TestNet, evidence-only) proof; every other variant is a precise,
non-mutating fail-closed reject or the inert `Disabled`.

Digests are deterministic, length-prefixed, domain-separated SHA3-256 over
explicit field bytes (never `Debug` formatting). Merkle leaf hashing uses
a `0x00` domain byte and node hashing a `0x01` domain byte.

## 4. Production proof format / proof-suite / policy taxonomy

* Protocol version `1`
  (`PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_PROTOCOL_VERSION`).
* Production Merkle suite `0xA3`
  (`PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_SUITE_MERKLE_V1`) — deliberately
  distinct from the Run 178 fixture suite `0xA1`
  (`ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1`), so the Run 186
  classifier routes it as production-class.
* `ProductionOnChainGovernanceVerifierPolicy`:
  `Disabled` (default), `AllowSourceTestProductionProof`,
  `MainnetProductionProofRequired` (fails closed — no production authority
  wired).
* `ProductionOnChainGovernanceVerifierKind`:
  `Disabled` (default), `ProductionMerkleVerifier`,
  `ProductionReceiptVerifier` (reserved, fail-closed).

## 5. Trusted checkpoint / root / inclusion-proof binding

The trusted governance root is supplied **out-of-band** via
`ProductionOnChainGovernanceVerificationInputs.trusted_checkpoint.governance_root_hex`
and is **never** taken from the proof. `ProductionOnChainGovernanceProof`
carries no trusted root; it carries the decision commitment (the Merkle
leaf pre-image), a typed `ProductionOnChainGovernanceInclusionProof`
(leaf index + authenticated sibling path + claimed root), and the
canonical `proof_bytes_digest`. Acceptance requires the recomputed root ==
claimed root == trusted root, so a proof can never self-authorize its root.

## 6. Accepted source/test evidence

Group A (16 tests) — including:

* `a02`/`a03` valid production proof accepted on DevNet / TestNet.
* `a04`/`a05` accept binds environment / epoch / sequence / lifecycle
  action / decision id.
* `a06` inclusion path verifies against the trusted root.
* `a07` quorum/threshold-met proof accepted.
* `a08`–`a10`/`a13`/`a14` deterministic proof / decision / transcript /
  checkpoint / Merkle-root digests.
* `a11`/`a12` the Run 186 classifier routes the production suite as
  production-class and the fixture suite as fixture-class.

## 7. Rejection / fail-closed evidence

Group B (40 tests) — including Disabled-before-parsing, empty/sentinel/
malformed proof bytes, wrong domain-separation tag, unsupported
protocol/suite, fixture-suite-as-production rejection, proof-bytes-digest
mismatch, missing/wrong trusted root, non-self-authorizing untrusted root,
wrong environment/chain/genesis/authority-root, wrong governance
domain/epoch/proposal-id/proposal-digest/proposal-outcome/lifecycle-action/
candidate-digest/authority-sequence, checkpoint mismatch, expired by
height/epoch bounds, replayed decision-id, stale-lower-sequence,
quorum/threshold not met, wrong Merkle path / malformed sibling hex /
claimed-root mismatch → inclusion failed, receipt-verifier unavailable,
injected verifier-unavailable / inclusion-material-unavailable / malformed.

## 8. MainNet refusal / authority policy evidence

Group C (7 tests): MainNet refused under source/test policy; MainNet
policy fails closed on MainNet and DevNet (`MainNetProductionGovernance
ProofUnavailable`); MainNet fixture proof rejected; MainNet-committed proof
refused on a DevNet trust domain; accepting a DevNet proof does not enable
MainNet; a valid DevNet proof presented on a MainNet trust domain is
refused.

## 9. Replay / recovery / idempotency evidence

Group E (8 tests): no-prior-proof no-op; byte-identical idempotent replay;
same-decision-id conflicting proposal-digest / candidate-digest /
lifecycle-action / transcript fail closed; stale governance epoch fails
closed; different decision-id is an independent window.

## 10. Non-mutation evidence

Group D (6 tests): every outcome is non-mutating (`is_non_mutating()` is
always true); the verifier never falls back, rejects fixture as
production, and sources the trusted root out-of-band; a battery of rejected
paths never yields an accept; typed non-authority / governance-engine /
validator-set-rotation outcomes are non-accepting. The verifier performs
no Run 070 call, no `LivePqcTrustState` mutation, no trust swap, no session
eviction, no trust-bundle sequence write, and no authority-marker write.

## 11. Tests run and results

All commands run with `cargo test -p qbind-node ...` unless noted.

* `cargo build -p qbind-node --lib` — **clean**.
* `run_299_production_onchain_governance_proof_verifier_tests` — **83 passed**.
* `run_186_onchain_governance_production_verifier_boundary_tests` — **44 passed**.
* `run_178_onchain_governance_proof_tests` — **46 passed**.
* `run_297_production_custody_attestation_verifier_tests` — **105 passed**.
* `run_295_production_kms_hsm_custody_backend_tests` — **89 passed**.
* `run_293_production_remote_signer_backend_tests` — **69 passed**.
* `run_291_production_durable_replay_rocksdb_tests` — **63 passed**.
* `run_290 … run_242` durable-completion / settlement / modeled-pipeline /
  governance-execution corpus — **all passed** (63/63/63/63/63/63/63/63/
  63/63/63/63/63/63/57/57/57/46/108/98/88/68/47/45/38).
* `run_240 … run_224` governance-evaluator corpus — **all passed**
  (63/68/56/58/47/52/48/59/48).
* `run_203_kms_hsm_backend_boundary_tests` — **60 passed**.
* `run_201_remote_signer_transport_boundary_tests` — **58 passed**.
* `run_194_remote_authority_signer_boundary_tests` — **44 passed**.
* `run_188_authority_custody_boundary_tests` — **48 passed**.
* `cargo test -p qbind-node --lib pqc_authority` — **passed** (see
  §13/§14 for the full-lib result).
* `cargo test -p qbind-node --lib` — **passed**.

No regression failures. No test-target-name substitutions were required.

## 12. C4/C5 matrix taxonomy status

* Production durable replay RocksDB backend — **Green** (release-binary-
  evidenced backend behavior only).
* Real production RemoteSigner backend — **Green** (release-binary-
  evidenced backend behavior only).
* Real KMS/HSM/cloud-KMS/PKCS#11 custody backend — **Green** (release-
  binary-evidenced backend behavior only).
* Real custody attestation verifier — **Green** (release-binary-evidenced
  custody-attestation verifier behavior only).
* **Real on-chain governance proof verifier — Red → Yellow** (source-test
  implementation landed; release-binary evidence pending Run 300).
* Governance execution engine — **Red**.
* Validator-set rotation / authority-set synchronization — **Red**.
* MainNet authority rotation/revocation under production custody — **Red**.
* Production signing audit trail / crypto-agility activation / incident
  response — **Red**.
* Full MainNet release-binary evidence under production custody — **Red**.
* **Full C4 remains OPEN. C5 remains OPEN.**

## 13. Security scan results

* **Secret scanning** — run over all changed files; **clean** (no secrets;
  all digests are synthetic test fixtures / lowercase hex).
* **CodeQL** — see the final response for the reported result. Run 299
  adds real source/test verifier logic, so CodeQL (or an explicit,
  honest skip/timeout/unavailable reason) is reported and CodeQL coverage
  is not claimed if the tool did not complete.

## 14. Honest limitations

* Source/test only — **not** release-binary evidence. The Run 299 verifier
  is exercised by `cargo test`, not by a release-built `qbind-node` binary.
* The `ProductionReceiptVerifier` kind is reserved and fail-closed; only
  the Merkle inclusion path is implemented.
* No real on-chain light-client / bridge integration, block-header chain
  verification, or signature-set/validator-set verification is wired — the
  trusted governance root/checkpoint is supplied explicitly out-of-band.
* No default production runtime wiring, no CLI flag, no MainNet enablement.
* Composition with the Run 186 boundary is via
  `classify_production_suite_through_run186`; the Run 186
  `OnChainGovernanceVerifierKind` enum is intentionally **not** modified,
  to avoid risk to the accepted Run 186/298 surfaces.

## 15. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 299 does not close C4 or C5
and makes no MainNet-readiness or release-binary claim.

## 16. Suggested Run 300 next step

**Run 300 — release-binary evidence for the real on-chain governance proof
verifier.** Build a real `target/release/qbind-node` plus a release-built
helper, exercise the Run 299 verifier in release mode, prove production-
style proof acceptance only under the explicit source/test production
policy with verified root/inclusion/proof material, prove fixture proof
remains DevNet/TestNet evidence-only and rejected for MainNet, prove
missing/malformed/replay/wrong-domain/wrong-root/wrong-proof/wrong-proposal/
wrong-candidate fail-closed behavior, prove production binary surfaces
remain Disabled/silent with no CLI flag, preserve Run 292/294/296/298
Green-for-scope rows, and preserve Full C4 OPEN / C5 OPEN.