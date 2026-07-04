# QBIND DevNet evidence — Run 298

**Title.** Release-binary evidence for the Run 297 production custody attestation verifier.

**Status.** PASS (release-binary evidence). Run 298 is the release-binary evidence run for the Run 297 source/test **production custody attestation verifier** in `crates/qbind-node/src/pqc_production_custody_attestation_verifier.rs`.

Run 298 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_298_production_custody_attestation_verifier_release_binary_helper.rs` that the Run 297 production library symbols are present and exercised in release mode. The helper drives the **real** Run 297 `ProductionCustodyAttestationVerifier` over source/test fixture KMS/HSM attestation evidence verifiers, reachable-but-fail-closed production attestation verifier stubs, and a programmable mock evidence verifier, only for DevNet/TestNet identities on the accept path, and remains dead code from the production runtime: the production binary never constructs the verifier, adds no CLI flag, and enables neither the verifier by default nor MainNet.

## What Run 298 states

* Run 298 is release-binary evidence for the Run 297 production custody attestation verifier.
* Run 298 does not add new production runtime wiring.
* Run 298 does not add a public CLI flag.
* Run 298 does not enable custody attestation by default.
* Run 298 does not enable MainNet.
* Run 298 does not implement real cloud-KMS / PKCS#11 / HSM provider credential, session, quote-verifier, certificate-chain, or hardware-proof integration.
* Run 298 does not implement on-chain governance proof verification.
* Run 298 does not implement a governance execution engine.
* Run 298 does not implement validator-set rotation.
* Run 298 does not implement settlement or external publication.
* Run 298 does not call Run 070.
* Run 298 does not mutate `LivePqcTrustState`.
* Run 298 does not write trust-bundle sequence or authority marker files.
* The default `ProductionCustodyAttestationVerifierPolicy` is `Disabled` (fails closed with no verification before any evidence-verifier call); `MainNet` is refused absent production authority criteria and verified production custody attestation; DevNet/TestNet fixture KMS/HSM attestation accept only under an explicit fixture policy.
* Under a production policy the verifier never accepts and never falls back to fixture KMS/HSM attestation, RemoteSigner, or local material; production cloud-KMS / PKCS#11 / generic attestation classes remain reachable but fail closed as unavailable/misconfigured without real trust root / quote verifier / certificate chain / hardware proof.
* The release helper exercises the Run 297 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, and the Run 296 KMS/HSM custody backend row each remain Green **only** for their release-binary-evidenced scope; the Real custody attestation verifier row is now Green **only** for release-binary-evidenced custody-attestation verifier behavior. None of these close C4/C5.
* Red production rows (on-chain governance proof verifier, governance execution engine, validator-set rotation, MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Verifier symbols exercised

* Policy: `ProductionCustodyAttestationVerifierPolicy` (`Disabled`, `FixtureKmsAttestationAllowed`, `FixtureHsmAttestationAllowed`, production-required classes, `MainnetProductionCustodyRequired`).
* Config: `ProductionCustodyAttestationVerifierConfig`.
* Verifier: `ProductionCustodyAttestationVerifier::new(config, policy, evidence_verifier)` with public field `evidence_verifier` (`.call_count()`).
* Trait `GovernanceProductionCustodyAttestationVerifier`: `build_attestation_challenge`, `verify_custody_attestation`, `evaluate_custody_attestation`, `recover_attestation_window`.
* Evidence-verifier scaffolding: `FixtureKmsCustodyAttestationVerifier`, `FixtureHsmCustodyAttestationVerifier`, `ProductionCustodyAttestationVerifierStub`, and a programmable mock evidence verifier.
* Types: `ProductionCustodyAttestationChallenge`, `ProductionCustodyAttestationEvidence`, `ProductionCustodyAttestationTrustRoot`, `ProductionCustodyAttestationMeasurement`, `ProductionCustodyAttestationExpectations`, `ProductionCustodyAttestationBinding`, `ProductionCustodyAttestationClass`, `ProductionCustodyAttestationDecision`, `ProductionCustodyAttestationOutcome`, `ProductionCustodyAttestationError`, `ProductionCustodyAttestationRecoveryOutcome`.
* Digest helpers: `challenge.challenge_digest()`, `evidence.evidence_digest()`, `evidence.provider_identity_digest()`, `trust_root.trust_root_digest()`, `production_custody_attestation_transcript_digest(...)`, `production_custody_attestation_decision_digest(&transcript, tag)`; domain-separation constants `PRODUCTION_CUSTODY_ATTESTATION_*_DOMAIN_TAG`, `PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION`.

**Name substitutions.** The task lists `production_custody_attestation_challenge_digest` and `production_custody_attestation_evidence_digest` as free functions; the real implementation exposes them as the methods `challenge.challenge_digest()` and `evidence.evidence_digest()`. This substitution is recorded in the helper module doc and in the canonical evidence file.

**Test-target substitution.** The Run 203 / 201 / 194 / 188 boundary targets are `run_203_kms_hsm_backend_boundary_tests`, `run_201_remote_signer_transport_boundary_tests`, `run_194_remote_authority_signer_boundary_tests`, `run_188_authority_custody_boundary_tests`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `20/0`, rejection_fail_closed `40/0`, mainnet_authority_policy `11/0`, replay_recovery_idempotency `8/0`, non_mutation `6/0`, reachability_taxonomy `21/0`; total `106` pass, `0` fail. The helper constructs the real Run 297 verifier over source/test fixture/stub/mock evidence verifiers, builds challenges, verifies/evaluates custody attestation, and asserts every failure surfaces as a typed `ProductionCustodyAttestationOutcome` / `ProductionCustodyAttestationError`. It emits `fixtures/run_298_deterministic_digests.txt` (challenge, evidence, provider-identity, trust-root, transcript, decision digests), and the harness runs the helper twice and diffs this fixture to prove deterministic-digest stability.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`), S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes. S6 fails closed before any mutation with the `invalid governance-execution policy selector` message. Every captured log was asserted silent on custody-attestation-verifier enablement claims. No new public CLI surface was added for Run 298. The denylist of forbidden patterns was clean across captured logs and helper output (excluding the help text and helper summary).

## C4/C5 matrix taxonomy verification

The harness greps the C4/C5 closure-criteria matrix and confirms the taxonomy clarification remains present: the matrix separates **boundary readiness** from **production readiness**; the Run 292 durable replay RocksDB, Run 294 RemoteSigner, and Run 296 KMS/HSM custody backend rows remain Green **for release-binary-evidenced scope only**; the Real custody attestation verifier row is now Green **for release-binary-evidenced custody-attestation verifier behavior only** (not default-wired, no CLI flag, MainNet refused absent production authority criteria and verified production custody attestation, production cloud-KMS / PKCS#11 / generic attestation classes fail-closed without real trust root / quote verifier / certificate chain / hardware proof, does not implement on-chain verifier / governance engine / validator-set rotation, does not close C4/C5); Red production rows remain Red until production implementation **and** release-binary evidence both exist. Run 298 does not reinterpret the matrix clarification as C4/C5 closure. Full C4 remains **OPEN**; C5 remains **OPEN**.

## Validation

The harness `bash scripts/devnet/run_298_production_custody_attestation_verifier_release_binary.sh` passed and ran the required release builds plus the regression corpus (`run_297`, the preceding even release-binary evidence corpus `run_295` … `run_224`, `run_203_kms_hsm_backend_boundary_tests`, `run_201_remote_signer_transport_boundary_tests`, `run_194_remote_authority_signer_boundary_tests`, `run_188_authority_custody_boundary_tests`, `--lib pqc_authority`, and `--lib`), all `rc=0`. The canonical machine-readable run summary is regenerated into the tracked `summary.txt` of `docs/devnet/run_298_production_custody_attestation_verifier_release_binary/` (committed alongside `README.md` and `.gitignore`; all other per-run artifacts under that directory remain git-ignored). The completed run reports `verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)`, helper corpus `total_pass: 106` / `total_fail: 0`, and final harness exit code `0`.

## Security scanning

Secret scanning was run over the changed files during the evidence pass and reported **no secrets**. CodeQL result is reported honestly in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_298.md`. The underlying Run 297 production module is re-run unchanged and is unaffected by this pass.

## Honest limitations

Run 298 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the custody attestation verifier into the default runtime, and does not implement real cloud-KMS / PKCS#11 / HSM provider credentials, sessions, quote verifiers, certificate chains, or hardware proofs, an on-chain governance proof verifier, a governance execution engine, validator-set rotation, settlement, or external publication. Run 298 closes only the Run 297 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 Green-for-scope statuses. Full C4 remains **OPEN** and C5 remains **OPEN**.

## Suggested Run 299 next step

Run 299 should begin the next Red-row closure campaign: source/test **real on-chain governance proof verifier** implementation. After Run 298, durable replay, RemoteSigner, KMS/HSM custody backend, and custody attestation verifier can all be Green-for-scope, so the next highest-value Red row is the real on-chain governance proof verifier that gates production authority lifecycle decisions before governance execution / validator-set rotation. Keep the same pattern — source/test only, default `Disabled`/fail-closed, MainNet refused unless production authority criteria are satisfied, with release-binary evidence deferred to Run 300.
