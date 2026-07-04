# QBIND DevNet Evidence — Run 297

Source/test production custody attestation verifier.

## 1. Exact verdict

**PASS / source-test production custody attestation verifier implementation.**

A real source/test custody attestation verifier landed. It composes with the
Run 295 KMS/HSM custody request/response/transcript surfaces, defaults to
`Disabled`/fail-closed, rejects fixture attestation for MainNet, holds the
production cloud-KMS / PKCS#11 / generic KMS / generic HSM attestation classes
reachable-but-fail-closed absent real verification material, refuses
RemoteSigner-only / local-operator-only / peer-majority evidence for KMS/HSM
custody attestation, and is non-mutating on every rejected path. Run 297 is
**source/test only and NOT release-binary evidence**; release-binary evidence
is deferred to Run 298. **Full C4 remains OPEN. C5 remains OPEN.**

## 2. Files changed

Added:

* `crates/qbind-node/src/pqc_production_custody_attestation_verifier.rs`
  (source module, 1881 lines).
* `crates/qbind-node/tests/run_297_production_custody_attestation_verifier_tests.rs`
  (105 tests, 1781 lines).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_297.md` (this document).

Modified:

* `crates/qbind-node/src/lib.rs` — registered
  `pub mod pqc_production_custody_attestation_verifier;`.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status → Run 297; custody
  attestation verifier row Red → Yellow; Run 297 narrative entry.
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 297 narrative
  entry.
* `docs/whitepaper/contradiction.md` — Run 297 "no contradiction" entry.

No storage/wire/marker/sequence/trust-bundle/CLI change.

## 3. Verifier design summary

`ProductionCustodyAttestationVerifier<V: CustodyAttestationEvidenceVerifier>`
is generic over an injected, mockable evidence verifier (mirroring the Run 295
`ProductionKmsHsmCustodyBackend<T>` transport-injection pattern). The trait
`GovernanceProductionCustodyAttestationVerifier` exposes
`build_attestation_challenge`, `verify_custody_attestation`,
`evaluate_custody_attestation`, and `recover_attestation_window`.

Verification flow in `verify_custody_attestation`:

1. **Pre-verification gate** — `Disabled` → `DisabledNoVerification`;
   unsupported request kind; RemoteSigner / local-operator / peer / unknown
   custody class refused; MainNet gate (fixture rejected, non-MainNet-policy
   refused, production unavailable); structural well-formedness → `Malformed`;
   protocol-version pin; class-vs-policy match.
2. **Binding check** — field-by-field over provider / key / custody-class /
   signer / request-id / request / response / transcript / candidate / action /
   authority trust domain.
3. **Challenge / nonce** — bound-request-id + replay comparison.
4. **Trust root** presence + match.
5. **Measurement** presence + match.
6. Delegate to the injected evidence verifier (production stubs fail closed).
7. Accept **fixture only**, and only under an explicit fixture policy on
   DevNet/TestNet.

All digests are deterministic length-prefixed domain-separated SHA3-256
(`hash_field` / `hash_opt`); no `Debug` formatting is used for any bound field
and freshness is proven by a typed nonce/challenge/sequence, never wall-clock.
The default `ProductionCustodyAttestationVerifierPolicy` is `Disabled` via
`#[derive(Default)]` + `#[default]`.

## 4. Attestation class and policy taxonomy

`ProductionCustodyAttestationClass`: `Disabled` (default), `FixtureKmsAttestation`,
`FixtureHsmAttestation`, `ProductionCloudKmsAttestation`,
`ProductionPkcs11HsmAttestation`, `ProductionGenericKmsAttestation`,
`ProductionGenericHsmAttestation`, `RemoteSignerAttestation`, `Unknown`.

`ProductionCustodyAttestationVerifierPolicy`: `Disabled` (default),
`FixtureKmsAttestationAllowed`, `FixtureHsmAttestationAllowed`,
`ProductionCloudKmsAttestationRequired`, `ProductionPkcs11HsmAttestationRequired`,
`ProductionGenericKmsAttestationRequired`, `ProductionGenericHsmAttestationRequired`,
`MainnetProductionCustodyAttestationRequired`.

`ProductionCustodyAttestationError`: `AttestationMissing`, `AttestationUnavailable`,
`MalformedAttestation`, `TrustRootMissing`, `QuoteVerifierUnavailable`,
`VerificationMaterialUnavailable`, `MeasurementUnverified`, `UnsupportedClass`,
`UnsupportedProtocol{version}`.

`ProductionCustodyAttestationOutcome`: `DisabledNoVerification`,
`FixtureKmsAttestationVerified` / `FixtureHsmAttestationVerified` (the only
evidence-authorizing variants), `ProductionAttestationVerified` (represented
for Run 298, unreachable in Run 297), and the fail-closed rejects
(`ProductionAttestationUnavailable` / `Unverified` / `Malformed` /
`UnsupportedClass` / `UnsupportedProtocol` / `TrustRootMissing` /
`TrustRootMismatch` / `ProviderMismatch` / `KeyHandleMismatch` /
`SignerMismatch` / `CustodyClassMismatch` / `RequestIdMismatch` /
`BackendTranscriptMismatch` / `RequestEnvelopeMismatch` /
`ResponseEnvelopeMismatch` / `CandidateDigestMismatch` / `ActionMismatch` /
`DomainMismatch` / `NonceReplay` / `MeasurementMismatch` / `EvidenceAmbiguous`),
plus `FixtureAttestationRejectedForMainNet`,
`RemoteSignerAttestationIsNotKmsHsmCustody`,
`MainNetProductionCustodyAttestationUnavailable`, `MainNetRefused`,
`GovernanceVerifierUnavailable`, `ValidatorSetRotationUnsupported`,
`PolicyChangeUnsupported`, `AmbiguousFailClosed`.

## 5. Evidence / request / response / transcript / domain binding

`ProductionCustodyAttestationBinding` binds every attestation to: environment /
chain id / genesis hash / authority-root fingerprint / authority-domain
sequence (authority trust domain); custody class; provider kind + provider id;
key handle + key fingerprint; signer identity; custody request id; request
envelope digest; response envelope digest; backend transcript digest; candidate
digest; authorized action. `ProductionCustodyAttestationBinding::from_submitted_request`
projects a real Run 295 `SubmittedCustodyRequest` (request + response + backend
transcript) into the binding — this is the composition point with Run 295. The
challenge binds the custody request id and a typed nonce; the trust root and
measurement are bound by deterministic digest.

## 6. Accepted source/test evidence

Group A (20 tests, `a01`–`a20`) exercises fixture-KMS and fixture-HSM accept
under `FixtureKmsAttestationAllowed` / `FixtureHsmAttestationAllowed` on
DevNet/TestNet: valid evidence yields `FixtureKmsAttestationVerified` /
`FixtureHsmAttestationVerified`; the production classes are reachable and yield
their precise fail-closed outcomes (`ProductionAttestationUnavailable` /
`Unverified` / `TrustRootMissing`) with the injected verifier's call recorded.
Acceptance is evidence-only and non-mutating.

## 7. Rejection / fail-closed evidence

Group B (40 tests, `b01`–`b40`) proves fail-closed on: disabled policy,
missing/empty proof, sentinel/malformed proof, unsupported protocol,
class-vs-policy mismatch, and every binding mismatch — wrong provider, provider
id, key handle, key fingerprint, signer, custody class, request id, request
envelope, response envelope, backend transcript, candidate digest, action,
environment, chain, genesis, authority-root, authority-domain sequence — plus
wrong / replayed challenge nonce, missing / wrong trust root, wrong measurement,
and wrong certificate proof. Production classes fail closed as
unavailable/unverified without real verification material.

## 8. MainNet refusal / authority policy evidence

Group C (11 tests, `c01`–`c11`): fixture-KMS and fixture-HSM attestation are
rejected for MainNet (`FixtureAttestationRejectedForMainNet`); RemoteSigner
attestation is refused (`RemoteSignerAttestationIsNotKmsHsmCustody`); local
operator and peer/unknown custody are refused (`CustodyClassMismatch`); the
MainNet production policy is unavailable (`MainNetProductionCustodyAttestationUnavailable`);
a non-MainNet policy on a MainNet domain is `MainNetRefused`; the MainNet
production policy on a non-MainNet domain is unavailable; the `Disabled` default
refuses MainNet with `DisabledNoVerification`. No MainNet path reaches
verification; all are gated before the evidence verifier is called.

## 9. Replay / recovery / idempotency evidence

Group E (8 tests, `e01`–`e08`) via `recover_attestation_window`: a no-prior
window is a clean no-op; a byte-identical duplicate is idempotent; the same
attestation id with a different transcript, key handle, or measurement fails
closed; the same nonce reused across a different request id fails closed; an
unrelated request id is treated as no-prior. Run 297 persists no durable replay
state and `e08` asserts no durable attestation acceptance is claimed.

## 10. Non-mutation evidence

Group D (6 tests, `d01`–`d06`) proves every rejected path is non-mutating: no
Run 070 call, no `LivePqcTrustState` mutation, no trust swap, no session
eviction, no PQC trust-bundle sequence write, no authority marker write, no
durable replay overwrite, no custody backend acceptance under wrong policy, no
fallback to fixture under production policy, and no fallback to RemoteSigner
under KMS/HSM policy. Grep-verifiable scope helpers assert these invariants
(`production_custody_attestation_verifier_is_non_mutating`, etc.).

## 11. Tests run and results

* `cargo test -p qbind-node --test run_297_production_custody_attestation_verifier_tests`
  → **105 passed; 0 failed**.
* Regression corpus — all PASS:
  * run_295 (89), run_293 (69), run_291 (63)
  * run_203 (60), run_201 (58), run_194 (44), run_188 (48)
  * run_290 → run_256 durable-completion batch (46–63 each)
  * run_254 → run_224 modeled/governance batch (38–108 each)
* `cargo test -p qbind-node --lib` → **1377 passed; 0 failed**.

Substitution note: no target-name substitutions were required; the Run
188/194/201/203 boundary targets exist under their listed names. The unrelated
pre-existing test target `m16_epoch_transition_hardening_tests.rs` fails to
compile against the current `RocksDbConsensusStorage` API (missing
`set_inject_write_failure` / `clear_epoch_transition_marker`); this is a
pre-existing failure not touched by Run 297 and is reported honestly rather than
hidden. It is not in the Run 297 required regression corpus, so the corpus was
run via explicit `--test` targets.

## 12. C4/C5 matrix taxonomy status

* Production durable replay RocksDB backend — 🟢 Green (for scope), release-binary-evidenced only.
* Real production RemoteSigner backend — 🟢 Green (for scope), release-binary-evidenced only.
* Real KMS/HSM/cloud-KMS/PKCS#11 custody backend — 🟢 Green (for scope), release-binary-evidenced only.
* Real custody attestation verifier — 🟡 **Yellow** (Red → Yellow): source-test implementation landed, release-binary evidence pending Run 298.
* Real on-chain governance proof verifier — 🔴 Red.
* Governance execution engine — 🔴 Red.
* Validator-set rotation / authority-set synchronization — 🔴 Red.
* MainNet authority rotation/revocation under production custody — 🔴 Red.
* Production signing audit trail / crypto-agility activation / incident response — 🔴 Red.
* Full MainNet release-binary evidence under production custody — 🔴 Red.
* **Full C4 remains OPEN. C5 remains OPEN.**

## 13. Security scan results

* Secret scanning over changed files — **clean**. No secrets, tokens, KMS
  credentials, HSM PINs, cloud account identifiers, real provider endpoints,
  real certificate chains, or real hardware quotes are present. All attestation
  material in tests is synthetic DevNet/TestNet fixture data.
* CodeQL — **not completed. CodeQL analysis was skipped because the CodeQL
  database size is too large.** No CodeQL coverage is claimed for the Run 297
  changes. This is reported explicitly rather than hidden; the skip is a tooling
  limitation, not a clean result.

## 14. Honest limitations

* Run 297 is **source/test only** and is **not** release-binary evidence.
* No real cloud-KMS / PKCS#11 / HSM provider credential, session, quote
  verifier, or certificate-chain integration exists; production attestation
  classes are reachable but fail closed.
* `ProductionAttestationVerified` is represented for Run 298 but is unreachable
  in Run 297 (no real verification material).
* No public CLI flag, no default production runtime wiring, no MainNet
  enablement.
* No durable replay persistence; replay recovery is in-memory only.
* No on-chain governance proof verification, governance execution engine,
  validator-set rotation, settlement, or external publication.

## 15. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 297 does not close C4 or C5, does
not claim production attestation closure, does not claim MainNet readiness, and
does not weaken the Run 292 / 294 / 296 Green-for-scope statuses.

## 16. Suggested Run 298 next step

**Run 298 — release-binary evidence for the production custody attestation
verifier.** Build real `target/release/qbind-node` plus a release-built helper,
exercise the Run 297 verifier in release mode, prove fixture-attestation accept
only under explicit DevNet/TestNet fixture policy, prove production attestation
classes are reachable-but-fail-closed without real verification material, prove
request/response/transcript/domain/key/provider binding, prove
missing/malformed/replay/wrong-domain/wrong-key/wrong-transcript fail-closed
behavior, prove production binary surfaces remain Disabled/silent with no CLI
flag, preserve Run 292/294/296 Green-for-scope rows, and preserve Full C4 OPEN /
C5 OPEN.