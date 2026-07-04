# QBIND DevNet evidence — Run 300

**Title.** Release-binary evidence for the Run 299 production on-chain governance proof verifier.

**Status.** PASS (release-binary evidence). Run 300 is the release-binary evidence run for the Run 299 source/test **production on-chain governance proof verifier** in `crates/qbind-node/src/pqc_production_onchain_governance_proof_verifier.rs`.

Run 300 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_300_production_onchain_governance_proof_verifier_release_binary_helper.rs` that the Run 299 production library symbols are present and exercised in release mode. The helper drives the **real** Run 299 `ProductionOnChainGovernanceProofVerifier` over a real SHA3-256 Merkle inclusion verifier, reachable-but-fail-closed unavailable inclusion-verifier stubs, and a programmable mock inclusion verifier, only for DevNet/TestNet identities on the accept path, and remains dead code from the production runtime: the production binary never constructs the verifier, adds no CLI flag, and enables neither the verifier by default nor MainNet. The trusted governance root/checkpoint is always supplied explicitly out-of-band and the proof can never self-authorize its root.

## What Run 300 states

* Run 300 is release-binary evidence for the Run 299 production on-chain governance proof verifier.
* Run 300 does not add new production runtime wiring.
* Run 300 does not add a public CLI flag.
* Run 300 does not enable the verifier by default.
* Run 300 does not enable MainNet.
* Run 300 does not implement a real light-client / bridge / header-chain / validator-set verification path.
* Run 300 does not implement a governance execution engine.
* Run 300 does not implement validator-set rotation.
* Run 300 does not implement settlement or external publication.
* Run 300 does not call Run 070.
* Run 300 does not mutate `LivePqcTrustState`.
* Run 300 does not write trust-bundle sequence or authority marker files.
* The default `ProductionOnChainGovernanceVerifierPolicy` is `Disabled` (fails closed with no verification before any parsing/verification); `MainNet` is refused absent production authority criteria; DevNet/TestNet production-style proofs are accepted only under the explicit source/test production policy when the represented Merkle inclusion path verifies against the explicit out-of-band trusted governance root.
* Under a production policy the verifier fails closed on missing/malformed/unsupported/replay/wrong-domain/wrong-root/failed-inclusion/expired/quorum-not-met/threshold-not-met and never falls back to fixture / local-operator / peer-majority / RemoteSigner / custody proof material; the fixture proof (suite `0xA1`) is rejected as production authority and refused for MainNet.
* The release helper exercises the Run 299 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, and the Run 298 custody attestation verifier row each remain Green **only** for their release-binary-evidenced scope; the Real on-chain governance proof verifier row is now Green **only** for release-binary-evidenced on-chain-governance-proof-verifier behavior. None of these close C4/C5.
* Red production rows (governance execution engine, validator-set rotation / authority-set synchronization, MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Verifier symbols exercised

* Policy: `ProductionOnChainGovernanceVerifierPolicy` (default `Disabled`, explicit source/test production policy) and `ProductionOnChainGovernanceVerifierKind`.
* Config: `ProductionOnChainGovernanceProofVerifierConfig`.
* Verifier: `ProductionOnChainGovernanceProofVerifier<V: OnChainGovernanceInclusionVerifier>` constructed over a real Merkle inclusion verifier, unavailable stubs, and a programmable mock inclusion verifier.
* Trait `GovernanceProductionOnChainGovernanceProofVerifier`: `verify_production_onchain_governance_proof_real`, `evaluate_production_onchain_governance_proof`, `recover_proof_window`.
* Inclusion-verifier boundary: trait `OnChainGovernanceInclusionVerifier`, `RealMerkleInclusionVerifier` (`.call_count()`), `UnavailableInclusionVerifierStub`, `MockInclusionVerifier`; `build_merkle_inclusion_proof(&leaves, index)`.
* Types: `ProductionOnChainGovernanceProof`, `ProductionOnChainGovernanceVerificationInputs`, `ProductionOnChainGovernanceTrustedCheckpoint`, `ProductionOnChainGovernanceInclusionProof`, `ProductionOnChainGovernanceProofOutcome`, `ProductionOnChainGovernanceProofError`, `ProductionOnChainGovernanceRecoveryOutcome`, `ProductionOnChainGovernanceReplaySet`.
* Digest helpers: `production_onchain_governance_decision_digest(&commitment)`, `production_onchain_governance_proof_digest(&proof)`, `production_onchain_governance_transcript_digest(...)`; constants `PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_PROTOCOL_VERSION`, `PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_SUITE_MERKLE_V1` (`0xA3`), `PRODUCTION_ONCHAIN_GOVERNANCE_DOMAIN_SEPARATION_TAG`, `PRODUCTION_ONCHAIN_GOVERNANCE_INVALID_PROOF_SENTINEL`.
* Composition: `classify_production_suite_through_run186(...)` routes the Run 299 production Merkle suite (`0xA3`) as production-class and the Run 178 fixture suite (`ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1`, `0xA1`) as fixture-class.

**Name substitutions.** The task lists the verifier entry points generically; the real implementation exposes them as the trait methods `verify_production_onchain_governance_proof_real`, `evaluate_production_onchain_governance_proof`, and `recover_proof_window`, and the fixture-suite discriminator constant `ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1` lives in the composed Run 178 module `pqc_onchain_governance_proof.rs`. These substitutions are recorded in the helper module doc and in the canonical evidence file, and the harness proves each required symbol across the combined source + composed-module + helper corpus.

**Test-target substitution.** The Run 186 / 178 boundary targets are `run_186_onchain_governance_production_verifier_boundary_tests` and `run_178_onchain_governance_proof_tests`; the Run 203 / 201 / 194 / 188 boundary targets are `run_203_kms_hsm_backend_boundary_tests`, `run_201_remote_signer_transport_boundary_tests`, `run_194_remote_authority_signer_boundary_tests`, `run_188_authority_custody_boundary_tests`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `14/0`, rejection_fail_closed `30/0`, mainnet_authority_policy `7/0`, replay_recovery_idempotency `8/0`, non_mutation `5/0`, reachability_taxonomy `7/0`; total `71` pass, `0` fail. The helper constructs the real Run 299 verifier over source/test real-Merkle / unavailable-stub / mock inclusion verifiers, builds Merkle inclusion proofs against an explicit out-of-band trusted governance root, verifies/evaluates production proofs, and asserts every failure surfaces as a typed `ProductionOnChainGovernanceProofOutcome` / `ProductionOnChainGovernanceProofError`. It emits `fixtures/run_300_deterministic_digests.txt` (proof, decision, checkpoint, Merkle-root, transcript digests), and the harness runs the helper twice and diffs this fixture to prove deterministic-digest stability.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`), S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes. S6 fails closed before any mutation with the `invalid governance-execution policy selector` message. Every captured log was asserted silent on on-chain-governance-proof-verifier enablement claims. No new public CLI surface was added for Run 300. The denylist of forbidden patterns was clean across captured logs and helper output (excluding the help text and helper summary).

## C4/C5 matrix taxonomy verification

The harness greps the C4/C5 closure-criteria matrix and confirms the taxonomy clarification remains present: the matrix separates **boundary readiness** from **production readiness**; the Run 292 durable replay RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody backend, and Run 298 custody attestation verifier rows remain Green **for release-binary-evidenced scope only**; the Real on-chain governance proof verifier row is now Green **for release-binary-evidenced on-chain-governance-proof-verifier behavior only** (not wired by default into production runtime, no public CLI flag, MainNet refused absent production authority criteria, trusted governance root/checkpoint supplied explicitly out-of-band, proof cannot self-authorize its root, production proof acceptance is source/test evidence using verified Merkle inclusion against the explicit trusted root, no real light-client / bridge / header-chain / validator-set verification, does not implement governance execution engine / validator-set rotation, does not close C4/C5); Red production rows remain Red until production implementation **and** release-binary evidence both exist. Run 300 does not reinterpret the matrix clarification as C4/C5 closure. Full C4 remains **OPEN**; C5 remains **OPEN**.

## Validation

The harness `bash scripts/devnet/run_300_production_onchain_governance_proof_verifier_release_binary.sh` passed and ran the required release builds plus the regression corpus (`run_299`, `run_186`, `run_178`, `run_297`, the preceding even release-binary evidence corpus `run_295` … `run_224`, `run_203_kms_hsm_backend_boundary_tests`, `run_201_remote_signer_transport_boundary_tests`, `run_194_remote_authority_signer_boundary_tests`, `run_188_authority_custody_boundary_tests`, `--lib pqc_authority`, and `--lib`), all `rc=0`. The canonical machine-readable run summary is regenerated into the tracked `summary.txt` of `docs/devnet/run_300_production_onchain_governance_proof_verifier_release_binary/` (committed alongside `README.md` and `.gitignore`; all other per-run artifacts under that directory remain git-ignored). The completed run reports `verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)`, helper corpus `total_pass: 71` / `total_fail: 0`, and final harness exit code `0`.

## Security scanning

Secret scanning was run over the changed files during the evidence pass and reported **no secrets**. CodeQL result is reported honestly in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_300.md`. The underlying Run 299 production module is re-run unchanged and is unaffected by this pass.

## Honest limitations

Run 300 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the on-chain governance proof verifier into the default runtime, and does not implement a real light-client / bridge / header-chain / validator-set verification path, a governance execution engine, validator-set rotation, settlement, or external publication. Run 300 closes only the Run 299 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 Green-for-scope statuses. Full C4 remains **OPEN** and C5 remains **OPEN**.

## Suggested Run 301 next step

Run 301 should begin the next Red-row closure campaign: the source/test real **governance execution engine** that consumes verified on-chain governance proof decisions to drive authority-set changes. After Run 300, durable replay, RemoteSigner, KMS/HSM custody backend, custody attestation verifier, and the on-chain governance proof verifier can all be Green-for-scope, so the next highest-value Red row is the governance execution engine that gates validator-set rotation / authority-set synchronization. Keep the same pattern — source/test only, default `Disabled`/fail-closed, MainNet refused unless production authority criteria are satisfied, with release-binary evidence deferred to Run 302.
