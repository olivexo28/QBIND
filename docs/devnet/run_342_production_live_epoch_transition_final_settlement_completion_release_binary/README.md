# QBIND DevNet evidence — Run 342

**Title.** Release-binary evidence for the Run 341 live epoch-transition final settlement / authority-lifecycle completion boundary.

**Status.** PASS (release-binary evidence). Run 342 is the release-binary evidence run for the Run 341 source/test **live epoch-transition final settlement / authority-lifecycle completion boundary** in `crates/qbind-node/src/pqc_production_live_epoch_transition_final_settlement_completion.rs`.

Run 342 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_342_production_live_epoch_transition_final_settlement_completion_release_binary_helper.rs` that the Run 341 production library symbols are present and exercised in release mode. The helper drives the **real** Run 341 `ProductionLiveEpochTransitionFinalSettlementCompletionExecutor` over the **real** Run 339/340 verified live epoch-transition settlement / finalization execution accept decision (`is_accept()` with `Some(settlement_execution_artifact)`; itself composing the Run 337/338 settlement / finalization execution-preparation, Run 335/336 settlement / finalization-preparation, Run 333/334 external-publication, Run 331/332 durable-audit publication, Run 329/330 audit-ledger commitment, Run 327/328 durable-audit finalization, Run 325/326 post-commit audit, Run 323/324 commit-receipt, Run 321/322 commit execution, Run 319/320 commit authorization, Run 317/318 mutation execution, Run 315/316 execution preparation, Run 313/314 runtime handoff, Run 311/312 guarded mutation, Run 309/310 staged application, Run 307/308 authorization, Run 305/306 application, Run 303/304 rotation-plan, and Run 301/302 governance-execution accept decisions), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating live final-settlement / authority-lifecycle completion artifacts describing exactly what a future live production authority-lifecycle completion step would perform. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionLiveEpochTransitionFinalSettlementCompletionOutcome` variant; the boundary never writes a production final-settlement, authority-lifecycle-completion, settlement, settlement-finalization, settlement-execution, external publication, durable-audit publication, audit ledger, durable replay record, receipt/audit record, final-execution record, never applies a live production validator-set change, and never transitions a consensus epoch. Any positive fixture-state application is explicitly caller-owned, in-memory, source/test-only (`LiveEpochTransitionFinalSettlementCompletionFixtureState`), and is not production runtime state.

## What Run 342 states

* Run 342 is release-binary evidence for the Run 341 real live epoch-transition final settlement / authority-lifecycle completion boundary.
* Run 342 does not add new production runtime wiring.
* Run 342 does not add a public CLI flag.
* Run 342 does not enable the boundary by default.
* Run 342 does not enable MainNet.
* Run 342 does not apply a live production validator-set change.
* Run 342 does not perform a production epoch transition.
* Run 342 does not perform a production commit or finalization.
* Run 342 does not write a production final-settlement, authority-lifecycle-completion, settlement, settlement-finalization, settlement-execution, external-publication, durable-audit publication, final-execution, or audit record.
* Run 342 does not mutate a live validator set, consensus state, or epoch counter.
* Run 342 does not call `BasicHotStuffEngine::transition_to_epoch` on production runtime state.
* Run 342 does not write `meta:current_epoch`.
* Run 342 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 342 does not implement final settlement, authority-lifecycle completion, settlement, settlement-finalization, publication, external publication, audit-finalization, durable-audit publication, or final execution.
* Run 342 does not call Run 070.
* Run 342 does not mutate `LivePqcTrustState`.
* Run 342 does not write trust-bundle sequence or authority marker files.
* Run 342 exercises the caller-owned in-memory `LiveEpochTransitionFinalSettlementCompletionFixtureState` only as explicit source/test evidence, clearly distinct from production runtime, durable replay, receipt, audit, settlement, publication, external-publication, and final-execution state.
* Run 342 does not accept missing / unverified / accepted-without-artifact settlement-execution decisions, nor settlement-execution-decision-alone / settlement-execution-preparation-decision-alone / settlement-preparation-decision-alone / external-publication-decision-alone / durable-audit-publication-decision-alone / audit-ledger-commitment-decision-alone / durable-audit-finalization-decision-alone / post-commit-audit-decision-alone / commit-receipt-decision-alone / commit-execution-decision-alone / commit-authorization-decision-alone / mutation-execution-decision-alone / execution-preparation-decision-alone / runtime-handoff-decision-alone / guarded-mutation-decision-alone / staged-application-alone / live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 342 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 / 312 / 314 / 316 / 318 / 320 / 322 / 324 / 326 / 328 / 330 / 332 / 334 / 336 / 338 / 340 Green-for-scope statuses.
* The default `ProductionLiveEpochTransitionFinalSettlementCompletionExecutorPolicy` is `Disabled` (fails closed with no artifact construction before any settlement-execution-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test final-settlement-completion requests are accepted only under the explicit source-test policy when they bind a verified Run 339/340 live epoch-transition settlement / finalization execution accept decision that carries `Some(settlement_execution_artifact)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-artifact / wrong-binding / settlement-execution-decision-integrity / mismatch / replay / stale inputs and never falls back to any lower-layer decision-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 341 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The prior Green-for-scope rows through Run 339/340 each remain Green **only** for their release-binary-evidenced scope; the live epoch-transition final settlement / authority-lifecycle completion row is now Green **only** for release-binary-evidenced live-epoch-transition-final-settlement-completion-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionLiveEpochTransitionFinalSettlementCompletionExecutorPolicy` (default `Disabled`, explicit source-test policy) and `ProductionLiveEpochTransitionFinalSettlementCompletionExecutorKind`.
* Config: `ProductionLiveEpochTransitionFinalSettlementCompletionConfig`, `ProductionLiveEpochTransitionFinalSettlementCompletionProtocolVersion`.
* Executor: `ProductionLiveEpochTransitionFinalSettlementCompletionExecutor` constructed over the real Run 339/340 verified live epoch-transition settlement / finalization execution accept decision and an in-memory replay set.
* Authority source: `LiveEpochTransitionFinalSettlementCompletionAuthoritySource`, exercised over the real Run 339/340 `ProductionLiveEpochTransitionSettlementExecutionDecision`.
* Inputs / request / decision / artifact: `ProductionLiveEpochTransitionFinalSettlementCompletionInputs`, `ProductionLiveEpochTransitionFinalSettlementCompletionRequest`, `ProductionLiveEpochTransitionFinalSettlementCompletionDecision`, `ProductionLiveEpochTransitionFinalSettlementCompletionArtifact`.
* Entry points: `evaluate_live_epoch_transition_final_settlement_completion`, `recover_live_epoch_transition_final_settlement_completion_window`, `production_live_epoch_transition_final_settlement_completion_content_digest`, `production_live_epoch_transition_final_settlement_completion_request_id`, `production_live_epoch_transition_final_settlement_completion_id`, `production_live_epoch_transition_final_settlement_completion_transcript_digest`.
* Replay set: trait `LiveEpochTransitionFinalSettlementCompletionReplaySet` and `EmptyLiveEpochTransitionFinalSettlementCompletionReplaySet`.
* Source/test fixture state: `LiveEpochTransitionFinalSettlementCompletionFixtureState` (caller-owned, in-memory, source/test-only apply path; not production runtime state).
* Taxonomy: `ProductionLiveEpochTransitionFinalSettlementCompletionOutcome`, `ProductionLiveEpochTransitionFinalSettlementCompletionRecoveryOutcome`, `LiveEpochTransitionFinalSettlementCompletionKind`.

## Substitution notes

* The Run 341 executor surfaces every failure as a typed `ProductionLiveEpochTransitionFinalSettlementCompletionOutcome` fail-closed variant; there is no separate `ProductionLiveEpochTransitionFinalSettlementCompletionError` enum, so that symbol is intentionally not required by the reachability greps.
* The Run 341 boundary produces a non-mutating `ProductionLiveEpochTransitionFinalSettlementCompletionArtifact` (rather than a settlement/receipt/audit "record"); the artifact captures the exact future-executor postconditions, and the `recover_live_epoch_transition_final_settlement_completion_window` recovery path over the artifact is exercised directly by the helper as an explicit non-mutating recovery/idempotency fixture.
* The helper corpus is 175 checks across accepted-compatible / rejection-fail-closed / MainNet-authority-policy / replay-recovery-idempotency / fixture-state / non-mutation / reachability-taxonomy tables.
* The harness `TEST_TARGETS` list begins with `run_341_..._final_settlement_completion_tests` followed by the real Run-339 chain (`run_339_..._settlement_execution_tests`, `run_337_..._settlement_execution_preparation_tests`, …) and the remaining ancestor / backend suites; all present targets are run and recorded.

## How to reproduce

```bash
scripts/devnet/run_342_production_live_epoch_transition_final_settlement_completion_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 341 boundary symbols for reachability across the source module + the Run 339/340 live epoch-transition settlement / finalization execution module + the ancestor chain modules + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, records a no-mutation proof, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts. It is generated by the harness during the run; if generated before the final commit it records `git_status: dirty`, and the dirty/untracked entries are exactly the Run 342 deliverables (the helper, the harness, this evidence archive, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_342.md`, and the narrow C4/C5 + protocol/ops/whitepaper doc updates).
* `.gitignore` — excludes the per-run generated artifacts.