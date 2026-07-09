# QBIND DevNet evidence — Run 316

**Title.** Release-binary evidence for the Run 315 live epoch-transition execution preparation boundary.

**Status.** PASS (release-binary evidence). Run 316 is the release-binary evidence run for the Run 315 source/test **live epoch-transition execution preparation boundary** in `crates/qbind-node/src/pqc_production_live_epoch_transition_execution_preparation.rs`.

Run 316 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_316_production_live_epoch_transition_execution_preparation_release_binary_helper.rs` that the Run 315 production library symbols are present and exercised in release mode. The helper drives the **real** Run 315 `ProductionLiveEpochTransitionExecutionPreparationExecutor` over the **real** Run 313/314 verified epoch-transition runtime handoff accept decision (`is_accept()` with `Some(handoff_package)`; itself composing the Run 311/312 verified guarded epoch-transition mutation-execution accept decision, the Run 309/310 verified staged live validator-set / epoch-transition application accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept decision), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating live-execution preparation artifacts describing exactly what a future live production mutation executor would apply. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionLiveEpochTransitionExecutionPreparationOutcome` variant; the boundary never applies a live production validator-set change and never transitions a consensus epoch. Any positive fixture-state application is explicitly caller-owned, in-memory, source/test-only (`LiveEpochTransitionExecutionPreparationFixtureState`), and is not production runtime state.

## What Run 316 states

* Run 316 is release-binary evidence for the Run 315 real live epoch-transition execution preparation boundary.
* Run 316 does not add new production runtime wiring.
* Run 316 does not add a public CLI flag.
* Run 316 does not enable the boundary by default.
* Run 316 does not enable MainNet.
* Run 316 does not apply a live production validator-set change.
* Run 316 does not perform a production epoch transition.
* Run 316 does not mutate a live validator set, consensus state, or epoch counter.
* Run 316 does not call `BasicHotStuffEngine::transition_to_epoch` on production runtime state.
* Run 316 does not write `meta:current_epoch`.
* Run 316 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 316 does not implement settlement or external publication.
* Run 316 does not call Run 070.
* Run 316 does not mutate `LivePqcTrustState`.
* Run 316 does not write trust-bundle sequence or authority marker files.
* Run 316 exercises the caller-owned in-memory `LiveEpochTransitionExecutionPreparationFixtureState` only as explicit source/test evidence, clearly distinct from production runtime state.
* Run 316 does not accept missing / unverified / accepted-without-package runtime-handoff decisions, nor guarded-mutation-decision-alone / staged-application-alone / live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 316 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 / 312 / 314 Green-for-scope statuses.
* The default `ProductionLiveEpochTransitionExecutionPreparationExecutorPolicy` is `Disabled` (fails closed with no artifact construction before any runtime-handoff-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test execution-preparation requests are accepted only under the explicit source-test policy when they bind a verified Run 313/314 epoch-transition runtime handoff accept decision that carries `Some(handoff_package)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-package / wrong-binding / runtime-handoff-decision-integrity / current-validator-set-epoch-version-preflight / mismatch / replay / stale inputs and never falls back to runtime-handoff-decision-alone / guarded-mutation-decision-alone / staged-application-decision-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 315 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, the Run 298 custody attestation verifier row, the Run 300 on-chain governance proof verifier row, the Run 302 governance execution engine row, the Run 303/304 validator-set rotation intent boundary row, the Run 305/306 validator-set rotation application / epoch-transition executor row, the Run 307/308 live validator-set application / epoch-transition authorization row, the Run 309/310 staged live validator-set / epoch-transition application executor row, the Run 311/312 guarded epoch-transition mutation executor row, and the Run 313/314 epoch-transition runtime handoff / live-mutation preflight row each remain Green **only** for their release-binary-evidenced scope; the live epoch-transition execution preparation row is now Green **only** for release-binary-evidenced live-epoch-transition-execution-preparation-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionLiveEpochTransitionExecutionPreparationExecutorPolicy` (default `Disabled`, explicit source-test policy) and `ProductionLiveEpochTransitionExecutionPreparationExecutorKind`.
* Config: `ProductionLiveEpochTransitionExecutionPreparationConfig`, `ProductionLiveEpochTransitionExecutionPreparationProtocolVersion`.
* Executor: `ProductionLiveEpochTransitionExecutionPreparationExecutor` constructed over the real Run 313/314 verified epoch-transition runtime handoff accept decision and an in-memory replay set.
* Authority source: `LiveEpochTransitionExecutionPreparationAuthoritySource`, exercised over the real Run 313/314 `ProductionEpochTransitionRuntimeHandoffDecision`.
* Inputs / request / decision / artifact: `ProductionLiveEpochTransitionExecutionPreparationInputs`, `ProductionLiveEpochTransitionExecutionPreparationRequest`, `ProductionLiveEpochTransitionExecutionPreparationDecision`, `ProductionLiveEpochTransitionExecutionPreparationArtifact`.
* Entry points: `evaluate_live_epoch_transition_execution_preparation`, `recover_live_epoch_transition_execution_preparation_window`, `production_live_epoch_transition_execution_preparation_content_digest`, `production_live_epoch_transition_execution_preparation_request_id`, `production_live_epoch_transition_execution_preparation_id`, `production_live_epoch_transition_execution_preparation_transcript_digest`.
* Replay set: trait `LiveEpochTransitionExecutionPreparationReplaySet` and `EmptyLiveEpochTransitionExecutionPreparationReplaySet`.
* Source/test fixture state: `LiveEpochTransitionExecutionPreparationFixtureState` (caller-owned, in-memory, source/test-only apply path; not production runtime state).
* Taxonomy: `ProductionLiveEpochTransitionExecutionPreparationOutcome`, `ProductionLiveEpochTransitionExecutionPreparationRecoveryOutcome`, `LiveEpochTransitionExecutionPreparationKind`.

## Substitution notes

* The Run 315 executor surfaces every failure as a typed `ProductionLiveEpochTransitionExecutionPreparationOutcome` fail-closed variant; there is no separate `ProductionLiveEpochTransitionExecutionPreparationError` enum, so that symbol is intentionally not required by the reachability greps.
* The Run 315 boundary produces a non-mutating `ProductionLiveEpochTransitionExecutionPreparationArtifact` (rather than a mutation "record"); the artifact captures the exact future-executor preconditions (current/proposed set digests, current-validator-set epoch/version fail-closed preflight, delta digest, target epoch, required governance epoch / authority sequence / replay window), and the `recover_live_epoch_transition_execution_preparation_window` recovery path over the artifact is exercised directly by the helper as an explicit non-mutating recovery/idempotency fixture.

## How to reproduce

```bash
scripts/devnet/run_316_production_live_epoch_transition_execution_preparation_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 315 boundary symbols for reachability across the source module + the Run 313/314 epoch-transition runtime handoff module + the Run 311/312 guarded mutation executor module + the Run 309/310 staged application executor module + the Run 307/308 live validator-set application authorization module + the Run 305/306 validator-set rotation application executor module + the Run 303/304 validator-set rotation intent module + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, records a no-mutation proof, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts.
* `.gitignore` — excludes the per-run generated artifacts.
