# QBIND DevNet evidence — Run 294

**Title.** Release-binary evidence for the Run 293 production RemoteSigner backend.

**Status.** PASS (release-binary evidence). Run 294 is the release-binary evidence run for the Run 293 source/test **production RemoteSigner backend** in `crates/qbind-node/src/pqc_production_remote_signer_backend.rs`.

Run 294 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_294_production_remote_signer_backend_release_binary_helper.rs` that the Run 293 production library symbols are present and exercised in release mode. The helper drives the **real** Run 293 `ProductionRemoteSignerBackend` over source/test loopback/mock transports, only for DevNet/TestNet identities on the accept path, and remains dead code from the production runtime: the production binary never constructs the backend, adds no CLI flag, and enables neither the backend by default nor MainNet.

## What Run 294 states

* Run 294 is release-binary evidence for the Run 293 production RemoteSigner backend.
* Run 294 does not add new production runtime wiring.
* Run 294 does not add a public CLI flag.
* Run 294 does not enable RemoteSigner by default.
* Run 294 does not enable MainNet.
* Run 294 does not implement KMS/HSM/cloud-KMS/PKCS#11 custody.
* Run 294 does not implement custody attestation.
* Run 294 does not implement on-chain governance proof verification.
* Run 294 does not implement a governance execution engine.
* Run 294 does not implement validator-set rotation.
* Run 294 does not implement settlement or external publication.
* Run 294 does not call Run 070.
* Run 294 does not mutate `LivePqcTrustState`.
* Run 294 does not write trust-bundle sequence or authority marker files.
* The default `ProductionRemoteSignerBackendPolicy` is `Disabled` (fails closed before any transport call); `MainNet` is refused absent production authority criteria; DevNet/TestNet loopback accept only.
* Under a production policy the backend never accepts and never falls back to fixture/loopback/local signing.
* The release helper exercises the Run 293 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The production durable replay RocksDB backend row remains Green **only** for release-binary-evidenced backend behavior (Run 292); the Real production RemoteSigner backend row is now Green **only** for release-binary-evidenced RemoteSigner backend behavior. Neither closes C4/C5.
* Red production backend rows (KMS/HSM/cloud-KMS/PKCS#11 custody, custody attestation, on-chain governance proof verifier, governance execution engine, validator-set rotation, MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Backend symbols exercised

No type/function substitutions were required. Every type, function, trait, and `Error`/`Outcome` variant named by the Run 294 task resolves directly to an implemented Run 293 symbol in `crates/qbind-node/src/pqc_production_remote_signer_backend.rs` (registered in `crates/qbind-node/src/lib.rs`). The helper and harness use the real implemented names.

* Policy: `ProductionRemoteSignerBackendPolicy` (`Disabled`, `DevTestLoopbackEnabled`, `ProductionRequired`, `MainnetProductionRequired`).
* Config: `ProductionRemoteSignerBackendConfig::from_transport_config(transport_config)`.
* Request spec: `ProductionRemoteSignerRequestSpec` (+ `ProductionRemoteSignerRequestKind`).
* Backend: `ProductionRemoteSignerBackend::new(config, policy, transport)`.
* Trait `GovernanceProductionRemoteSignerBackend`: `build_request_envelope`, `submit_remote_signing_request`, `verify_remote_signer_response`, `evaluate_remote_signer_backend`, `recover_remote_signer_request_window`.
* Transport trait `RemoteSignerBackendTransport`; scaffolding transports `LoopbackRemoteSignerService`, `MockRemoteSignerBackendTransport`.
* Digest helpers `production_remote_signer_request_id`, `production_remote_signer_backend_transcript_digest`; constants `PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION`, `PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES`.
* Composition boundaries `validate_remote_signer_transport` (Run 201) and `validate_remote_signer` (Run 194); optional Run 291 `durable_replay_record_digest` composition point.
* Outcome/error/recovery taxonomies `ProductionRemoteSignerOutcome`, `ProductionRemoteSignerError`, `ProductionRemoteSignerRecoveryOutcome`, `SubmittedRemoteSignerRequest`, and the module invariant helpers.

**Test-target substitution.** The task's suggested Run 194 / Run 201 test target names differ from the actual names. The harness runs the real targets: `run_194_remote_authority_signer_boundary_tests` and `run_201_remote_signer_transport_boundary_tests`.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `14/0`, rejection_fail_closed `32/0`, mainnet_authority_policy `7/0`, replay_recovery_idempotency `8/0`, non_mutation `4/0`, reachability `1/0`; total `66` pass, `0` fail. The helper constructs the real Run 293 backend over source/test loopback/mock transports, submits requests, verifies responses, and asserts every failure surfaces as a typed `ProductionRemoteSignerOutcome`. It emits `fixtures/run_294_deterministic_digests.txt` (request id, request/response envelope digests, transport transcript digest, backend transcript digest), and the harness runs the helper twice and diffs this fixture to prove deterministic-digest stability.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`, rc=1 as those surfaces require `--genesis-path`), S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes. S6 fails closed before any mutation with the `invalid governance-execution policy selector` message. Every captured log was asserted silent on RemoteSigner-backend enablement claims. No new public CLI surface was added for Run 294 (the pre-existing generic `remote-signer` signer-mode flag is a separate, long-standing surface). The denylist of forbidden patterns (42 patterns) was clean across captured logs and helper output (excluding the help text and helper summary).

## C4/C5 matrix taxonomy verification

The harness greps the C4/C5 closure-criteria matrix and confirms the taxonomy clarification remains present: the matrix separates **boundary readiness** from **production readiness**; the production durable replay RocksDB backend row remains Green **for release-binary-evidenced scope only**; the Real production RemoteSigner backend row is now Green **for release-binary-evidenced RemoteSigner backend behavior only** (not default-wired, no CLI flag, MainNet refused absent production authority criteria, does not close C4/C5); Red production backend rows remain Red until production implementation **and** release-binary evidence both exist. Run 294 does not reinterpret the matrix clarification as C4/C5 closure. Full C4 remains **OPEN**; C5 remains **OPEN**.

## Validation

The harness `bash scripts/devnet/run_294_production_remote_signer_backend_release_binary.sh` passed and ran the required release builds plus the regression corpus (`run_293`, `run_291` down through `run_224`, `run_201_remote_signer_transport_boundary_tests`, `run_194_remote_authority_signer_boundary_tests`, `--lib pqc_authority`, and `--lib`), all `rc=0`. The canonical machine-readable run summary is regenerated into the tracked `summary.txt` of `docs/devnet/run_294_production_remote_signer_backend_release_binary/` (committed alongside `README.md` and `.gitignore`; all other per-run artifacts under that directory remain git-ignored). The completed run reports `verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)`, helper corpus `total_pass: 66` / `total_fail: 0`, release-binary scenarios `S1_help=0 S2=1 S3=1 S4=1 S5=1 S6=1`, and final harness exit code `0`.

## Security scanning

Secret scanning was run over the changed files during the evidence pass and reported **no secrets**. CodeQL was invoked (language: rust) but did **not** complete — the analysis timed out / was skipped because the database size is too large, so no CodeQL coverage is claimed. CodeQL results are reported honestly in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_294.md`. The underlying Run 293 production module is re-run unchanged and is unaffected by this pass.

## Honest limitations

Run 294 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the RemoteSigner backend into the default runtime, and does not implement any KMS/HSM/cloud-KMS/PKCS#11 custody backend, custody attestation verifier, on-chain governance proof verifier, governance execution engine, validator-set rotation, settlement, or external publication. Run 294 closes only the Run 293 release-binary evidence gap. Full C4 remains **OPEN** and C5 remains **OPEN**.

## Suggested Run 295 next step

Run 295 should begin the next Red-row closure campaign: source/test **production KMS/HSM/cloud-KMS/PKCS#11 custody backend** implementation, or source/test **production custody attestation verifier** implementation. In either case keep the same pattern — real backend implementation at source/test level, default `Disabled`/fail-closed, MainNet refused unless production authority criteria are satisfied, with release-binary evidence deferred to Run 296.