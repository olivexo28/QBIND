# QBIND DevNet evidence — Run 296

**Title.** Release-binary evidence for the Run 295 production KMS/HSM/cloud-KMS/PKCS#11 custody backend.

**Status.** PASS (release-binary evidence). Run 296 is the release-binary evidence run for the Run 295 source/test **production KMS/HSM/cloud-KMS/PKCS#11 custody backend** in `crates/qbind-node/src/pqc_production_kms_hsm_custody_backend.rs`.

Run 296 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_296_production_kms_hsm_custody_backend_release_binary_helper.rs` that the Run 295 production library symbols are present and exercised in release mode. The helper drives the **real** Run 295 `ProductionKmsHsmCustodyBackend` over source/test fixture KMS/HSM providers, reachable-but-fail-closed production provider stubs, and a programmable mock transport, only for DevNet/TestNet identities on the accept path, and remains dead code from the production runtime: the production binary never constructs the backend, adds no CLI flag, and enables neither the backend by default nor MainNet.

## What Run 296 states

* Run 296 is release-binary evidence for the Run 295 production KMS/HSM/cloud-KMS/PKCS#11 custody backend.
* Run 296 does not add new production runtime wiring.
* Run 296 does not add a public CLI flag.
* Run 296 does not enable KMS/HSM custody by default.
* Run 296 does not enable MainNet.
* Run 296 does not implement real provider credentials / real cloud-KMS account integration / real PKCS#11 session integration / real HSM module loading.
* Run 296 does not implement custody attestation verifier closure.
* Run 296 does not implement on-chain governance proof verification.
* Run 296 does not implement a governance execution engine.
* Run 296 does not implement validator-set rotation.
* Run 296 does not implement settlement or external publication.
* Run 296 does not call Run 070.
* Run 296 does not mutate `LivePqcTrustState`.
* Run 296 does not write trust-bundle sequence or authority marker files.
* The default `ProductionKmsHsmCustodyBackendPolicy` is `Disabled` (fails closed before any provider call); `MainNet` is refused absent production authority criteria and custody attestation; DevNet/TestNet fixture KMS/HSM accept only under an explicit fixture policy.
* Under a production policy the backend never accepts and never falls back to fixture KMS/HSM, RemoteSigner, local signing, or raw local keys; production cloud-KMS / PKCS#11 / generic provider paths remain reachable but fail closed as unavailable/misconfigured without real provider config.
* The release helper exercises the Run 295 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The production durable replay RocksDB backend row remains Green **only** for release-binary-evidenced backend behavior (Run 292); the Real production RemoteSigner backend row remains Green **only** for release-binary-evidenced RemoteSigner backend behavior (Run 294); the Real KMS/HSM/cloud-KMS/PKCS#11 custody backend row is now Green **only** for release-binary-evidenced KMS/HSM custody backend behavior. None of these close C4/C5.
* Red production backend rows (custody attestation verifier, on-chain governance proof verifier, governance execution engine, validator-set rotation, MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Backend symbols exercised

No type/function substitutions were required in the backend surface. Every type, function, trait, and `Error`/`Outcome` variant named by the Run 296 task resolves directly to an implemented Run 295 symbol in `crates/qbind-node/src/pqc_production_kms_hsm_custody_backend.rs` (registered in `crates/qbind-node/src/lib.rs`), with the exception of a small number of task-suggested names whose actual implemented spelling is used and documented below.

* Policy: `ProductionKmsHsmCustodyBackendPolicy` (`Disabled`, `FixtureKmsAllowed`, `FixtureHsmAllowed`, `ProductionCloudKmsRequired`, `ProductionPkcs11HsmRequired`, `ProductionGenericKmsRequired`, `ProductionGenericHsmRequired`, `MainnetProductionCustodyRequired`).
* Config: `ProductionKmsHsmCustodyBackendConfig::default()`.
* Request spec: `ProductionCustodyRequestSpec` (+ `ProductionCustodyRequestKind`, `ProductionCustodyProviderKind`).
* Backend: `ProductionKmsHsmCustodyBackend::new(config, policy, transport)`.
* Trait `GovernanceProductionKmsHsmCustodyBackend`: `build_custody_request`, `submit_custody_signing_request`, `verify_custody_response`, `evaluate_custody_backend`, `recover_custody_request_window`.
* Transport trait `KmsHsmCustodyProviderTransport`; scaffolding transports `FixtureKmsCustodyProvider`, `FixtureHsmCustodyProvider`, `ProductionCustodyProviderStub` (`cloud_kms` / `pkcs11_hsm` / `generic_kms` / `generic_hsm`), `MockKmsHsmCustodyTransport`.
* Digest helpers `production_kms_hsm_custody_request_id`, `production_kms_hsm_custody_transcript_digest`; constants `PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION`, `PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES`.
* Run 203 pure verifier composition boundary `verify_authority_custody_backend_response` (referenced directly by the helper and composed internally by the backend); optional Run 291 `durable_replay_record_digest` composition point.
* Envelope / outcome / error / recovery taxonomies `ProductionCustodyRequest`, `ProductionCustodyResponse`, `ProductionCustodyOutcome`, `ProductionCustodyError`, `ProductionCustodyRecoveryOutcome`, `SubmittedCustodyRequest`, and the module invariant helpers (`production_kms_hsm_custody_backend_default_is_disabled`, `…_mainnet_refuses_fixture_material`, `…_never_falls_back`, `…_is_non_mutating`, `…_loads_no_raw_local_key`, `…_remote_signer_is_not_kms_hsm`, `…_is_source_test_not_release_binary_evidence`).

**Name substitutions.** The task's suggested `ProductionCustodyRequest`/`ProductionCustodyResponse` names exist as-is; the task's `submit`/`verify` verbs map to the real trait methods `submit_custody_signing_request` / `verify_custody_response` / `evaluate_custody_backend`. The build entry point is `build_custody_request` (not `build_request_envelope`).

**Test-target substitution.** The task's suggested `run_203_kms_hsm_backend_tests` target name differs from the actual name. The harness runs the real target `run_203_kms_hsm_backend_boundary_tests`. The Run 201 / 194 / 188 targets are `run_201_remote_signer_transport_boundary_tests`, `run_194_remote_authority_signer_boundary_tests`, `run_188_authority_custody_boundary_tests`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `18/0`, rejection_fail_closed `36/0`, mainnet_authority_policy `9/0`, replay_recovery_idempotency `7/0`, non_mutation `5/0`, reachability `1/0`; total `76` pass, `0` fail. The helper constructs the real Run 295 backend over source/test fixture/stub/mock transports, submits requests, verifies responses, and asserts every failure surfaces as a typed `ProductionCustodyOutcome`. It emits `fixtures/run_296_deterministic_digests.txt` (request id, request/response envelope digests, response transcript digest, backend transcript digest), and the harness runs the helper twice and diffs this fixture to prove deterministic-digest stability.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`, rc=1 as those surfaces require `--genesis-path`), S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes. S6 fails closed before any mutation with the `invalid governance-execution policy selector` message. Every captured log was asserted silent on KMS/HSM custody-backend enablement claims. No new public CLI surface was added for Run 296. The denylist of forbidden patterns (32 patterns) was clean across captured logs and helper output (excluding the help text and helper summary).

## C4/C5 matrix taxonomy verification

The harness greps the C4/C5 closure-criteria matrix and confirms the taxonomy clarification remains present: the matrix separates **boundary readiness** from **production readiness**; the production durable replay RocksDB backend and Real production RemoteSigner backend rows remain Green **for release-binary-evidenced scope only**; the Real KMS/HSM/cloud-KMS/PKCS#11 custody backend row is now Green **for release-binary-evidenced KMS/HSM custody backend behavior only** (not default-wired, no CLI flag, MainNet refused absent production authority criteria and custody attestation, production cloud-KMS / PKCS#11 / generic provider paths fail-closed without real config, does not implement custody attestation verifier / on-chain verifier / governance engine / validator-set rotation, does not close C4/C5); Red production backend rows remain Red until production implementation **and** release-binary evidence both exist. Run 296 does not reinterpret the matrix clarification as C4/C5 closure. Full C4 remains **OPEN**; C5 remains **OPEN**.

## Validation

The harness `bash scripts/devnet/run_296_production_kms_hsm_custody_backend_release_binary.sh` passed and ran the required release builds plus the regression corpus (`run_295`, `run_293`, `run_291` down through `run_224`, `run_203_kms_hsm_backend_boundary_tests`, `run_201_remote_signer_transport_boundary_tests`, `run_194_remote_authority_signer_boundary_tests`, `run_188_authority_custody_boundary_tests`, `--lib pqc_authority`, and `--lib`), all `rc=0`. The canonical machine-readable run summary is regenerated into the tracked `summary.txt` of `docs/devnet/run_296_production_kms_hsm_custody_backend_release_binary/` (committed alongside `README.md` and `.gitignore`; all other per-run artifacts under that directory remain git-ignored). The completed run reports `verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)`, helper corpus `total_pass: 76` / `total_fail: 0`, release-binary scenarios `S1_help=0 S2=1 S3=1 S4=1 S5=1 S6=1`, and final harness exit code `0`.

## Security scanning

Secret scanning was run over the changed files during the evidence pass and reported **no secrets**. CodeQL result is reported honestly in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_296.md`. The underlying Run 295 production module is re-run unchanged and is unaffected by this pass.

## Honest limitations

Run 296 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the KMS/HSM custody backend into the default runtime, and does not implement real provider credentials, real cloud-KMS accounts, real PKCS#11 sessions, real HSM module loading, a custody attestation verifier, an on-chain governance proof verifier, a governance execution engine, validator-set rotation, settlement, or external publication. Run 296 closes only the Run 295 release-binary evidence gap. Full C4 remains **OPEN** and C5 remains **OPEN**.

## Suggested Run 297 next step

Run 297 should begin the next Red-row closure campaign: source/test **production custody attestation verifier** implementation. After Run 296 the KMS/HSM custody backend is Green-for-scope, but C5 still requires production custody *with attestation*, so the next highest-value Red row is a real custody attestation verifier that validates provider attestation evidence and rejects unverified custody material. Keep the same pattern — source/test only, default `Disabled`/fail-closed, MainNet refused unless production authority criteria are satisfied, with release-binary evidence deferred to Run 298.
