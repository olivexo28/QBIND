# QBIND DevNet evidence — Run 334

**Title.** Release-binary evidence for the Run 333 live epoch-transition external-publication / settlement-preparation boundary.

**Status.** PASS (release-binary evidence). Run 334 is the release-binary evidence run for the Run 333 source/test **live epoch-transition external-publication / settlement-preparation boundary** in `crates/qbind-node/src/pqc_production_live_epoch_transition_external_publication.rs`.

Run 334 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_334_production_live_epoch_transition_external_publication_release_binary_helper.rs` that the Run 333 production library symbols are present and exercised in release mode. The helper drives the **real** Run 333 `ProductionLiveEpochTransitionExternalPublicationExecutor` over the **real** Run 331/332 verified live epoch-transition durable-audit publication accept decision (`is_accept()` with `Some(durable_audit_publication_artifact)`; itself composing the Run 329/330 verified live epoch-transition audit-ledger commitment accept decision, the Run 327/328 verified live epoch-transition durable-audit finalization accept decision, the Run 325/326 verified live epoch-transition post-commit audit accept decision, the Run 323/324 verified live epoch-transition commit-receipt accept decision, the Run 321/322 verified live epoch-transition commit execution accept decision, the Run 319/320 verified live epoch-transition commit authorization accept decision, the Run 317/318 verified live epoch-transition mutation execution accept decision, the Run 315/316 verified live epoch-transition execution preparation accept decision, the Run 313/314 verified epoch-transition runtime handoff accept decision, the Run 311/312 verified guarded epoch-transition mutation-execution accept decision, the Run 309/310 verified staged live validator-set / epoch-transition application accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept decision), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating live external-publication / settlement-preparation artifacts describing exactly what a future live production external-publication step would perform. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionLiveEpochTransitionExternalPublicationOutcome` variant; the boundary never writes a production durable-audit publication, audit ledger, durable replay record, settlement/publication record, never applies a live production validator-set change, and never transitions a consensus epoch. Any positive fixture-state application is explicitly caller-owned, in-memory, source/test-only (`LiveEpochTransitionExternalPublicationFixtureState`), and is not production runtime state.

## What Run 334 states

* Run 334 is release-binary evidence for the Run 333 real live epoch-transition external-publication / settlement-preparation boundary.
* Run 334 does not add new production runtime wiring.
* Run 334 does not add a public CLI flag.
* Run 334 does not enable the boundary by default.
* Run 334 does not enable MainNet.
* Run 334 does not apply a live production validator-set change.
* Run 334 does not perform a production epoch transition.
* Run 334 does not perform a production commit or finalization.
* Run 334 does not write a production durable-audit publication or audit record.
* Run 334 does not mutate a live validator set, consensus state, or epoch counter.
* Run 334 does not call `BasicHotStuffEngine::transition_to_epoch` on production runtime state.
* Run 334 does not write `meta:current_epoch`.
* Run 334 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 334 does not implement settlement, publication, audit-finalization, or external publication.
* Run 334 does not call Run 070.
* Run 334 does not mutate `LivePqcTrustState`.
* Run 334 does not write trust-bundle sequence or authority marker files.
* Run 334 exercises the caller-owned in-memory `LiveEpochTransitionExternalPublicationFixtureState` only as explicit source/test evidence, clearly distinct from production runtime, durable replay, receipt, audit, settlement, and publication state.
* Run 334 does not accept missing / unverified / accepted-without-artifact durable-audit-publication decisions, nor durable-audit-publication-decision-alone / commit-receipt-decision-alone / commit-authorization-decision-alone / mutation-execution-decision-alone / execution-preparation-decision-alone / runtime-handoff-decision-alone / guarded-mutation-decision-alone / staged-application-alone / live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 334 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 / 312 / 314 / 316 / 318 / 320 / 322 / 324 / 326 / 328 / 330 Green-for-scope statuses.
* The default `ProductionLiveEpochTransitionExternalPublicationExecutorPolicy` is `Disabled` (fails closed with no artifact construction before any durable-audit-publication-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test durable-audit-publication requests are accepted only under the explicit source-test policy when they bind a verified Run 331/332 live epoch-transition durable-audit publication accept decision that carries `Some(durable_audit_publication_artifact)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-artifact / wrong-binding / commit-receipt-decision-integrity / current-validator-set-epoch-version-preflight / mismatch / replay / stale inputs and never falls back to durable-audit-publication-decision-alone / commit-receipt-decision-alone / commit-authorization-decision-alone / mutation-execution-decision-alone / execution-preparation-decision-alone / runtime-handoff-decision-alone / guarded-mutation-decision-alone / staged-application-decision-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 333 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 291/292 durable replay RocksDB, Run 293/294 RemoteSigner backend, Run 295/296 KMS/HSM custody backend, Run 297/298 custody attestation verifier, Run 299/300 on-chain governance proof verifier, Run 301/302 governance execution engine, Run 303/304 validator-set rotation intent, Run 305/306 validator-set rotation application executor, Run 307/308 live validator-set application authorization, Run 309/310 staged live validator-set / epoch-transition application executor, Run 311/312 guarded epoch-transition mutation executor, Run 313/314 epoch-transition runtime handoff, Run 315/316 live epoch-transition execution preparation, Run 317/318 live epoch-transition mutation execution, Run 319/320 live epoch-transition commit authorization, Run 323/324 live epoch-transition commit receipt, and Run 331/332 live epoch-transition durable-audit publication rows each remain Green **only** for their release-binary-evidenced scope; the live epoch-transition external-publication / settlement-preparation row is now Green **only** for release-binary-evidenced live-epoch-transition-external-publication-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionLiveEpochTransitionExternalPublicationExecutorPolicy` (default `Disabled`, explicit source-test policy) and `ProductionLiveEpochTransitionExternalPublicationExecutorKind`.
* Config: `ProductionLiveEpochTransitionExternalPublicationConfig`, `ProductionLiveEpochTransitionExternalPublicationProtocolVersion`.
* Executor: `ProductionLiveEpochTransitionExternalPublicationExecutor` constructed over the real Run 331/332 verified live epoch-transition durable-audit publication accept decision and an in-memory replay set.
* Authority source: `LiveEpochTransitionExternalPublicationAuthoritySource`, exercised over the real Run 331/332 `ProductionLiveEpochTransitionDurableAuditPublicationDecision`.
* Inputs / request / decision / artifact: `ProductionLiveEpochTransitionExternalPublicationInputs`, `ProductionLiveEpochTransitionExternalPublicationRequest`, `ProductionLiveEpochTransitionExternalPublicationDecision`, `ProductionLiveEpochTransitionExternalPublicationArtifact`.
* Entry points: `evaluate_live_epoch_transition_external_publication`, `recover_live_epoch_transition_external_publication_window`, `production_live_epoch_transition_external_publication_content_digest`, `production_live_epoch_transition_external_publication_request_id`, `production_live_epoch_transition_external_publication_id`, `production_live_epoch_transition_external_publication_transcript_digest`.
* Replay set: trait `LiveEpochTransitionExternalPublicationReplaySet` and `EmptyLiveEpochTransitionExternalPublicationReplaySet`.
* Source/test fixture state: `LiveEpochTransitionExternalPublicationFixtureState` (caller-owned, in-memory, source/test-only apply path; not production runtime state).
* Taxonomy: `ProductionLiveEpochTransitionExternalPublicationOutcome`, `ProductionLiveEpochTransitionExternalPublicationRecoveryOutcome`, `LiveEpochTransitionExternalPublicationKind`.

## Substitution notes

* The Run 333 executor surfaces every failure as a typed `ProductionLiveEpochTransitionExternalPublicationOutcome` fail-closed variant; there is no separate `ProductionLiveEpochTransitionExternalPublicationError` enum, so that symbol is intentionally not required by the reachability greps.
* The Run 333 boundary produces a non-mutating `ProductionLiveEpochTransitionExternalPublicationArtifact` (rather than a receipt/audit "record"); the artifact captures the exact future-executor postconditions (expected previous durable-audit-publication artifact digest, resulting set digest + epoch/version, target consensus epoch, delta digest, required governance epoch / authority sequence / replay window, durable-replay / audit-sink availability), and the `recover_live_epoch_transition_external_publication_window` recovery path over the artifact is exercised directly by the helper as an explicit non-mutating recovery/idempotency fixture.
* The harness `TEST_TARGETS` list is the real Run-333 chain — `run_331_..._external_publication_tests`, `run_329_..._durable_audit_publication_tests`, `run_327_..._durable_audit_finalization_tests`, `run_325_..._post_commit_audit_tests`, `run_323_..._commit_receipt_tests`, and the remaining ancestor / backend suites; all targets exist and pass.

## How to reproduce

```bash
scripts/devnet/run_334_production_live_epoch_transition_external_publication_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 333 boundary symbols for reachability across the source module + the Run 331/332 live epoch-transition durable-audit publication module + the Run 323/324 live epoch-transition commit receipt module + the ancestor chain modules + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, records a no-mutation proof, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts. It was generated by the harness during the run, before the final commit, so it records `git_status: dirty`; the dirty/untracked entries are exactly the Run 334 deliverables (the helper, the harness, this evidence archive, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_334.md`, and the narrow C4/C5 + protocol/ops/whitepaper doc updates).
* `.gitignore` — excludes the per-run generated artifacts.