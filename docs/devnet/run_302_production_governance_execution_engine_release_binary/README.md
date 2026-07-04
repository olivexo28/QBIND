# QBIND DevNet evidence — Run 302

**Title.** Release-binary evidence for the Run 301 production governance execution engine.

**Status.** PASS (release-binary evidence). Run 302 is the release-binary evidence run for the Run 301 source/test **production governance execution engine** in `crates/qbind-node/src/pqc_production_governance_execution_engine.rs`.

Run 302 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_302_production_governance_execution_engine_release_binary_helper.rs` that the Run 301 production library symbols are present and exercised in release mode. The helper drives the **real** Run 301 `ProductionGovernanceExecutionEngine` over the **real** Run 299 verified on-chain governance proof decision, only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating authority-lifecycle execution intents. The engine remains dead code from the production runtime: the production binary never constructs the engine, adds no CLI flag, and enables neither the engine by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionGovernanceExecutionOutcome` variant; the engine never turns a verified proof into a live mutation.

## What Run 302 states

* Run 302 is release-binary evidence for the Run 301 real governance execution engine.
* Run 302 does not add new production runtime wiring.
* Run 302 does not add a public CLI flag.
* Run 302 does not enable the engine by default.
* Run 302 does not enable MainNet.
* Run 302 does not implement validator-set rotation.
* Run 302 does not implement settlement or external publication.
* Run 302 does not call Run 070.
* Run 302 does not mutate `LivePqcTrustState`.
* Run 302 does not write trust-bundle sequence or authority marker files.
* Run 302 does not accept fixture / local-operator / peer-majority proof as production authority.
* Run 302 does not weaken the Run 292 / 294 / 296 / 298 / 300 Green-for-scope statuses.
* The default `ProductionGovernanceExecutionEnginePolicy` is `Disabled` (fails closed with no execution before any parsing/verification); `MainNet` is refused absent production authority criteria; DevNet/TestNet production-style intents are accepted only under the explicit source/test production policy when they bind a verified Run 299 on-chain governance proof decision.
* Under a production policy the engine fails closed on missing/malformed/unsupported/replay/wrong-domain/wrong-binding/unverified-proof/expired/quorum-not-met/threshold-not-met and never falls back to fixture / local-operator / peer-majority / RemoteSigner / custody-only / custody-attestation material; the fixture proof (suite `0xA1`) is rejected as production authority and refused for MainNet.
* The release helper exercises the Run 301 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, the Run 298 custody attestation verifier row, and the Run 300 on-chain governance proof verifier row each remain Green **only** for their release-binary-evidenced scope; the governance execution engine row is now Green **only** for release-binary-evidenced governance-execution-engine behavior. None of these close C4/C5.
* Red production rows (validator-set rotation / authority-set synchronization, MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Engine symbols exercised

* Policy: `ProductionGovernanceExecutionEnginePolicy` (default `Disabled`, explicit source/test production policy) and `ProductionGovernanceExecutionEngineKind`.
* Config: `ProductionGovernanceExecutionEngineConfig`.
* Engine: `ProductionGovernanceExecutionEngine` constructed over the real Run 299 verified on-chain governance proof decision and an in-memory replay set.
* Proof binding: `GovernanceExecutionProofBinding`, `GovernanceExecutionProofSource`, exercised over the real Run 299 `ProductionOnChainGovernanceProofVerifier` decision.
* Entry points: `evaluate_production_governance_execution`, `recover_production_governance_execution_window`, `production_governance_execution_request_id`, `production_governance_execution_intent_digest`, `production_governance_execution_transcript_digest`.
* Replay set: trait `GovernanceExecutionReplaySet` and `EmptyGovernanceExecutionReplaySet`.
* Taxonomy: `ProductionGovernanceExecutionOutcome`, `ProductionGovernanceExecutionRecoveryOutcome`, `ProductionGovernanceExecutionIntentKind`.

**Name substitutions.** The task lists a generic `ProductionGovernanceExecutionError` type; the real implementation surfaces every failure as a typed non-mutating variant of `ProductionGovernanceExecutionOutcome` (there is no separate `Error` enum). This substitution is recorded in the helper module doc and in the canonical evidence file, and the harness proves each required symbol across the combined source + verified-proof-verifier module + helper corpus.

## Helper corpus results

Release helper verdict: PASS. Tables: accepted_compatible `33/0`, rejection_fail_closed `43/0`, mainnet_authority_policy `8/0`, replay_recovery_idempotency `13/0`, non_mutation `10/0`, reachability_taxonomy `11/0`; total `118` pass, `0` fail. The helper constructs the real Run 301 engine over the real Run 299 verified on-chain governance proof decision, evaluates production governance execution intents, and asserts every failure surfaces as a typed non-mutating `ProductionGovernanceExecutionOutcome`. It emits `fixtures/run_302_deterministic_digests.txt` (request-id, intent, transcript digests), and the harness runs the helper twice and diffs this fixture to prove deterministic-digest stability.

## Real-binary scenarios

S1 `--help` (rc=0), S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`), S5 hidden governance-execution selector parse, and S6 invalid governance-execution selector fail-closed all completed with expected return codes. S6 fails closed before any mutation with the `invalid governance-execution policy selector` message. Every captured log was asserted silent on governance-execution-engine enablement claims. No new public CLI surface was added for Run 302. The denylist of forbidden patterns was clean across captured logs and helper output (excluding the help text and helper summary).

## C4/C5 matrix taxonomy verification

The harness greps the C4/C5 closure-criteria matrix and confirms the taxonomy clarification remains present: the matrix separates **boundary readiness** from **production readiness**; the Run 292 durable replay RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody backend, Run 298 custody attestation verifier, and Run 300 on-chain governance proof verifier rows remain Green **for release-binary-evidenced scope only**; the governance execution engine row is now Green **for release-binary-evidenced governance-execution-engine behavior only** (not wired by default into production runtime, no public CLI flag, MainNet refused absent production authority criteria, consumes verified on-chain governance proof decisions and produces typed non-mutating authority-lifecycle execution intents, does not call Run 070, does not mutate `LivePqcTrustState`, does not write trust-bundle sequence or authority marker files, does not implement validator-set rotation / authority-set synchronization, does not prove MainNet authority rotation/revocation, does not close C4/C5); Red production rows remain Red until production implementation **and** release-binary evidence both exist. Run 302 does not reinterpret the matrix clarification as C4/C5 closure. Full C4 remains **OPEN**; C5 remains **OPEN**.

## Validation

The harness `bash scripts/devnet/run_302_production_governance_execution_engine_release_binary.sh` passed and ran the required release builds plus the regression corpus (`run_301` first, then `run_299`, `run_297`, `run_295`, `run_293`, `run_291`, `run_186`, `run_178`, `run_203`, `run_201`, `run_194`, `run_188`, the preceding even release-binary evidence corpus `run_290` … `run_224`, `--lib pqc_authority`, and `--lib`), all `rc=0`. The canonical machine-readable run summary is regenerated into the tracked `summary.txt` of `docs/devnet/run_302_production_governance_execution_engine_release_binary/` (committed alongside `README.md` and `.gitignore`; all other per-run artifacts under that directory remain git-ignored). The completed run reports `verdict: PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN)`, helper corpus `total_pass: 118` / `total_fail: 0`, and final harness exit code `0`.

## Security scanning

Secret scanning was run over the changed files during the evidence pass and reported **no secrets**. CodeQL result is reported honestly in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_302.md`. The underlying Run 301 production module is re-run unchanged and is unaffected by this pass.

## Honest limitations

Run 302 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the governance execution engine into the default runtime, and does not implement validator-set rotation / authority-set synchronization, settlement, or external publication. Run 302 closes only the Run 301 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 Green-for-scope statuses. Full C4 remains **OPEN** and C5 remains **OPEN**.

## Suggested Run 303 next step

Run 303 should begin the next Red-row closure campaign: the source/test **validator-set rotation / authority-set synchronization intent boundary**. After Run 302, durable replay, RemoteSigner, KMS/HSM custody backend, custody attestation verifier, on-chain governance proof verifier, and the governance execution engine can all be Green-for-scope, so the next highest-value Red row is validator-set rotation / authority-set synchronization. Keep the same pattern — source/test only, deterministic, default `Disabled`/fail-closed, MainNet refused unless production authority criteria are satisfied, non-mutating on rejection, producing a typed rotation/synchronization plan or intent only, with release-binary evidence deferred to Run 304.
