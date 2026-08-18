# QBIND DevNet evidence — Run 350

**Title.** Release-binary evidence for the Run 349 live epoch-transition authority-activation final-execution boundary.

**Status.** PASS (release-binary evidence). Run 350 is the release-binary evidence run for the Run 349 source/test **live epoch-transition authority-activation final-execution boundary** in `crates/qbind-node/src/pqc_production_live_epoch_transition_authority_activation_final_execution.rs`.

Run 350 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_350_production_live_epoch_transition_authority_activation_final_execution_release_binary_helper.rs` that the Run 349 production library symbols are present and exercised in release mode. The helper drives the **real** Run 349 `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionExecutor` over the **real** Run 347/348 verified live epoch-transition authority-activation execution-preparation / final-execution preflight accept decision (`is_accept()` with `Some(authority_activation_execution_preparation_artifact)`; itself composing the Run 345/346 authority-activation authorization accept decision and the full prior Run 301–344 ancestor accept-decision chain), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating live authority-activation final-execution artifacts describing exactly what a future live production authority-activation execution executor would perform. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionOutcome` variant; the boundary never writes a production final-execution, authority-activation, authority-activation-execution-preparation, authority-activation-authorization, final-settlement, authority-lifecycle-completion, settlement, settlement-finalization, settlement-execution, external publication, durable-audit publication, audit ledger, durable replay record, receipt/audit record, never applies a live production validator-set change, and never transitions a consensus epoch. Any positive fixture-state application is explicitly caller-owned, in-memory, source/test-only (`LiveEpochTransitionAuthorityActivationFinalExecutionFixtureState`), and is not production runtime state.

## What Run 350 states

* Run 350 is release-binary evidence for the Run 349 real live epoch-transition authority-activation final-execution boundary.
* Run 350 does not add new production runtime wiring.
* Run 350 does not add a public CLI flag.
* Run 350 does not enable the boundary by default.
* Run 350 does not enable MainNet.
* Run 350 does not apply a live production validator-set change.
* Run 350 does not perform a production epoch transition.
* Run 350 does not perform a production commit or finalization.
* Run 350 does not write a production final-execution, authority-activation, authority-activation-execution-preparation, authority-activation-authorization, final-settlement, authority-lifecycle-completion, settlement, settlement-finalization, settlement-execution, external-publication, durable-audit publication, or audit record.
* Run 350 does not mutate a live validator set, consensus state, or epoch counter.
* Run 350 does not call `BasicHotStuffEngine::transition_to_epoch` on production runtime state.
* Run 350 does not write `meta:current_epoch`.
* Run 350 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 350 does not implement final execution, authority activation, final settlement, authority-lifecycle completion, settlement, settlement-finalization, publication, external publication, audit-finalization, or durable-audit publication.
* Run 350 does not call Run 070.
* Run 350 does not mutate `LivePqcTrustState`.
* Run 350 does not write trust-bundle sequence or authority marker files.
* Run 350 exercises the caller-owned in-memory `LiveEpochTransitionAuthorityActivationFinalExecutionFixtureState` only as explicit source/test evidence, clearly distinct from production runtime, durable replay, receipt, audit, settlement, publication, external-publication, and final-execution state.
* Run 350 does not accept missing / unverified / accepted-without-artifact authority-activation-execution-preparation decisions, nor execution-preparation-decision-alone / authorization-decision-alone / commit-authorization-decision-alone / mutation-execution-decision-alone / runtime-handoff-decision-alone / guarded-mutation-decision-alone / staged-application-alone / live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 350 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 / 312 / 314 / 316 / 318 / 320 / 322 / 324 / 326 / 328 / 330 / 332 / 334 / 336 / 338 / 340 / 342 / 344 / 346 / 348 Green-for-scope statuses.
* The default `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionExecutorPolicy` is `Disabled` (fails closed with no artifact construction before any authority-activation-execution-preparation-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test authority-activation-final-execution requests are accepted only under the explicit source-test policy when they bind a verified Run 347/348 live epoch-transition authority-activation execution-preparation / final-execution preflight accept decision that carries `Some(authority_activation_execution_preparation_artifact)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-artifact / wrong-binding / authority-activation-execution-preparation-decision-integrity / mismatch / replay / stale inputs and never falls back to any lower-layer decision-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 349 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The prior Green-for-scope rows through Run 347/348 each remain Green **only** for their release-binary-evidenced scope; the live epoch-transition authority-activation execution-preparation / final-execution preflight row is now joined by the live epoch-transition authority-activation final-execution row, which is Green **only** for release-binary-evidenced live-epoch-transition-authority-activation-final-execution-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionExecutorPolicy` (default `Disabled`, explicit source-test policy) and `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionExecutorKind`.
* Config: `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionConfig`, `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionProtocolVersion`.
* Executor: `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionExecutor` constructed over the real Run 347/348 verified live epoch-transition authority-activation execution-preparation / final-execution preflight accept decision and an in-memory replay set.
* Authority source: `LiveEpochTransitionAuthorityActivationFinalExecutionAuthoritySource`, exercised over the real Run 347/348 `ProductionLiveEpochTransitionAuthorityActivationExecutionPreparationDecision`.
* Inputs / request / decision / artifact: `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionInputs`, `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionRequest`, `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionDecision`, `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionArtifact`.
* Entry points: `evaluate_live_epoch_transition_authority_activation_final_execution`, `recover_live_epoch_transition_authority_activation_final_execution_window`, `production_live_epoch_transition_authority_activation_final_execution_content_digest`, `production_live_epoch_transition_authority_activation_final_execution_request_id`, `production_live_epoch_transition_authority_activation_final_execution_id`, `production_live_epoch_transition_authority_activation_final_execution_transcript_digest`.
* Replay set: trait `LiveEpochTransitionAuthorityActivationFinalExecutionReplaySet` and `EmptyLiveEpochTransitionAuthorityActivationFinalExecutionReplaySet`.
* Source/test fixture state: `LiveEpochTransitionAuthorityActivationFinalExecutionFixtureState` (caller-owned, in-memory, source/test-only apply path; not production runtime state).
* Taxonomy: `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionOutcome`, `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionRecoveryOutcome`, `LiveEpochTransitionAuthorityActivationFinalExecutionKind`.

## Substitution notes

* The Run 349 executor surfaces every failure as a typed `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionOutcome` fail-closed variant; there is no separate `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionError` enum, so that symbol is intentionally not required by the reachability greps.
* The Run 349 boundary produces a non-mutating `ProductionLiveEpochTransitionAuthorityActivationFinalExecutionArtifact` (rather than a settlement/receipt/audit "record"); the artifact captures the exact future-executor postconditions, and the `recover_live_epoch_transition_authority_activation_final_execution_window` recovery path over the artifact is exercised directly by the helper as an explicit non-mutating recovery/idempotency fixture.
* The helper corpus is 175 checks across accepted-compatible / rejection-fail-closed / MainNet-authority-policy / replay-recovery-idempotency / fixture-state / non-mutation / reachability-taxonomy tables.
* The `supp_*` supplemental tests live in a private nested submodule that is not reachable from the helper entry point; the helper registers the core `d_*` boundary cases that cover the required accepted-compatible / rejection-fail-closed / MainNet-refusal / replay-recovery / determinism / non-mutation properties.
* The harness `TEST_TARGETS` list begins with `run_349_..._authority_activation_final_execution_tests` and `run_347_..._authority_activation_execution_preparation_tests` followed by the real Run-345 chain (`run_345_..._authority_activation_authorization_tests`, `run_343_..._post_completion_attestation_tests`, …) and the remaining ancestor / backend suites; all present targets are run and recorded.

## How to reproduce

```bash
scripts/devnet/run_350_production_live_epoch_transition_authority_activation_final_execution_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 349 boundary symbols for reachability across the source module + the Run 347/348 live epoch-transition authority-activation execution-preparation / final-execution preflight module + the ancestor chain modules + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, records a no-mutation proof, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts. It is generated by the harness during the run; if generated before the final commit it records `git_status: dirty`, and the dirty/untracked entries are exactly the Run 350 deliverables (the helper, the harness, this evidence archive, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_350.md`, and the narrow C4/C5 + protocol/ops/whitepaper doc updates).
* `.gitignore` — excludes the per-run generated artifacts.
