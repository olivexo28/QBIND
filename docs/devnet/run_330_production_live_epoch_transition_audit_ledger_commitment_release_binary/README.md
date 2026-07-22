# QBIND DevNet evidence — Run 330

**Title.** Release-binary evidence for the Run 329 live epoch-transition audit-ledger commitment / durable-audit publication preparation boundary.

**Status.** PASS (release-binary evidence). Run 330 is the release-binary evidence run for the Run 329 source/test **live epoch-transition audit-ledger commitment / durable-audit publication preparation boundary** in `crates/qbind-node/src/pqc_production_live_epoch_transition_audit_ledger_commitment.rs`.

Run 330 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary_helper.rs` that the Run 329 production library symbols are present and exercised in release mode. The helper drives the **real** Run 329 `ProductionLiveEpochTransitionAuditLedgerCommitmentExecutor` over the **real** Run 327/328 verified live epoch-transition durable-audit finalization accept decision (`is_accept()` with `Some(durable_audit_finalization_artifact)`; itself composing the Run 323/324 verified live epoch-transition commit-receipt accept decision, the Run 321/322 verified live epoch-transition commit execution accept decision, the Run 319/320 verified live epoch-transition commit authorization accept decision, the Run 317/318 verified live epoch-transition mutation execution accept decision, the Run 315/316 verified live epoch-transition execution preparation accept decision, the Run 313/314 verified epoch-transition runtime handoff accept decision, the Run 311/312 verified guarded epoch-transition mutation-execution accept decision, the Run 309/310 verified staged live validator-set / epoch-transition application accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept decision), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating live audit-ledger commitment / durable-audit publication preparation artifacts describing exactly what a future live production audit-ledger commitment / durable-audit publication step would perform. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionLiveEpochTransitionAuditLedgerCommitmentOutcome` variant; the boundary never writes a production durable-audit finalization, audit ledger, durable replay record, settlement/publication record, never applies a live production validator-set change, and never transitions a consensus epoch. Any positive fixture-state application is explicitly caller-owned, in-memory, source/test-only (`LiveEpochTransitionAuditLedgerCommitmentFixtureState`), and is not production runtime state.

## What Run 330 states

* Run 330 is release-binary evidence for the Run 329 real live epoch-transition audit-ledger commitment / durable-audit publication preparation boundary.
* Run 330 does not add new production runtime wiring.
* Run 330 does not add a public CLI flag.
* Run 330 does not enable the boundary by default.
* Run 330 does not enable MainNet.
* Run 330 does not apply a live production validator-set change.
* Run 330 does not perform a production epoch transition.
* Run 330 does not perform a production commit or finalization.
* Run 330 does not write a production durable-audit finalization or audit record.
* Run 330 does not mutate a live validator set, consensus state, or epoch counter.
* Run 330 does not call `BasicHotStuffEngine::transition_to_epoch` on production runtime state.
* Run 330 does not write `meta:current_epoch`.
* Run 330 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 330 does not implement settlement, publication, audit-finalization, or external publication.
* Run 330 does not call Run 070.
* Run 330 does not mutate `LivePqcTrustState`.
* Run 330 does not write trust-bundle sequence or authority marker files.
* Run 330 exercises the caller-owned in-memory `LiveEpochTransitionAuditLedgerCommitmentFixtureState` only as explicit source/test evidence, clearly distinct from production runtime, durable replay, receipt, audit, settlement, and publication state.
* Run 330 does not accept missing / unverified / accepted-without-artifact durable-audit-finalization decisions, nor durable-audit-finalization-decision-alone / commit-receipt-decision-alone / commit-authorization-decision-alone / mutation-execution-decision-alone / execution-preparation-decision-alone / runtime-handoff-decision-alone / guarded-mutation-decision-alone / staged-application-alone / live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 330 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 / 312 / 314 / 316 / 318 / 320 / 322 / 324 / 326 / 328 Green-for-scope statuses.
* The default `ProductionLiveEpochTransitionAuditLedgerCommitmentExecutorPolicy` is `Disabled` (fails closed with no artifact construction before any durable-audit-finalization-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test durable-audit-finalization requests are accepted only under the explicit source-test policy when they bind a verified Run 327/328 live epoch-transition durable-audit finalization accept decision that carries `Some(durable_audit_finalization_artifact)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-artifact / wrong-binding / commit-receipt-decision-integrity / current-validator-set-epoch-version-preflight / mismatch / replay / stale inputs and never falls back to durable-audit-finalization-decision-alone / commit-receipt-decision-alone / commit-authorization-decision-alone / mutation-execution-decision-alone / execution-preparation-decision-alone / runtime-handoff-decision-alone / guarded-mutation-decision-alone / staged-application-decision-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 329 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 291/292 durable replay RocksDB, Run 293/294 RemoteSigner backend, Run 295/296 KMS/HSM custody backend, Run 297/298 custody attestation verifier, Run 299/300 on-chain governance proof verifier, Run 301/302 governance execution engine, Run 303/304 validator-set rotation intent, Run 305/306 validator-set rotation application executor, Run 307/308 live validator-set application authorization, Run 309/310 staged live validator-set / epoch-transition application executor, Run 311/312 guarded epoch-transition mutation executor, Run 313/314 epoch-transition runtime handoff, Run 315/316 live epoch-transition execution preparation, Run 317/318 live epoch-transition mutation execution, Run 319/320 live epoch-transition commit authorization, Run 323/324 live epoch-transition commit receipt, and Run 327/328 live epoch-transition durable-audit finalization rows each remain Green **only** for their release-binary-evidenced scope; the live epoch-transition audit-ledger commitment / durable-audit publication preparation row is now Green **only** for release-binary-evidenced live-epoch-transition-audit-ledger-commitment-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionLiveEpochTransitionAuditLedgerCommitmentExecutorPolicy` (default `Disabled`, explicit source-test policy) and `ProductionLiveEpochTransitionAuditLedgerCommitmentExecutorKind`.
* Config: `ProductionLiveEpochTransitionAuditLedgerCommitmentConfig`, `ProductionLiveEpochTransitionAuditLedgerCommitmentProtocolVersion`.
* Executor: `ProductionLiveEpochTransitionAuditLedgerCommitmentExecutor` constructed over the real Run 327/328 verified live epoch-transition durable-audit finalization accept decision and an in-memory replay set.
* Authority source: `LiveEpochTransitionAuditLedgerCommitmentAuthoritySource`, exercised over the real Run 327/328 `ProductionLiveEpochTransitionDurableAuditFinalizationDecision`.
* Inputs / request / decision / artifact: `ProductionLiveEpochTransitionAuditLedgerCommitmentInputs`, `ProductionLiveEpochTransitionAuditLedgerCommitmentRequest`, `ProductionLiveEpochTransitionAuditLedgerCommitmentDecision`, `ProductionLiveEpochTransitionAuditLedgerCommitmentArtifact`.
* Entry points: `evaluate_live_epoch_transition_audit_ledger_commitment`, `recover_live_epoch_transition_audit_ledger_commitment_window`, `production_live_epoch_transition_audit_ledger_commitment_content_digest`, `production_live_epoch_transition_audit_ledger_commitment_request_id`, `production_live_epoch_transition_audit_ledger_commitment_id`, `production_live_epoch_transition_audit_ledger_commitment_transcript_digest`.
* Replay set: trait `LiveEpochTransitionAuditLedgerCommitmentReplaySet` and `EmptyLiveEpochTransitionAuditLedgerCommitmentReplaySet`.
* Source/test fixture state: `LiveEpochTransitionAuditLedgerCommitmentFixtureState` (caller-owned, in-memory, source/test-only apply path; not production runtime state).
* Taxonomy: `ProductionLiveEpochTransitionAuditLedgerCommitmentOutcome`, `ProductionLiveEpochTransitionAuditLedgerCommitmentRecoveryOutcome`, `LiveEpochTransitionAuditLedgerCommitmentKind`.

## Substitution notes

* The Run 329 executor surfaces every failure as a typed `ProductionLiveEpochTransitionAuditLedgerCommitmentOutcome` fail-closed variant; there is no separate `ProductionLiveEpochTransitionAuditLedgerCommitmentError` enum, so that symbol is intentionally not required by the reachability greps.
* The Run 329 boundary produces a non-mutating `ProductionLiveEpochTransitionAuditLedgerCommitmentArtifact` (rather than a receipt/audit "record"); the artifact captures the exact future-executor postconditions (expected previous durable-audit-finalization artifact digest, resulting set digest + epoch/version, target consensus epoch, delta digest, required governance epoch / authority sequence / replay window, durable-replay / audit-sink availability), and the `recover_live_epoch_transition_audit_ledger_commitment_window` recovery path over the artifact is exercised directly by the helper as an explicit non-mutating recovery/idempotency fixture.
* The harness `TEST_TARGETS` list is the real Run-328 chain — `run_329_..._audit_ledger_commitment_tests`, `run_325_..._durable_audit_finalization_tests`, `run_323_..._commit_receipt_tests`, `run_319_..._commit_authorization_tests`, and the remaining ancestor / backend suites; all targets exist and pass.

## How to reproduce

```bash
scripts/devnet/run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 329 boundary symbols for reachability across the source module + the Run 327/328 live epoch-transition durable-audit finalization module + the Run 323/324 live epoch-transition commit receipt module + the ancestor chain modules + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, records a no-mutation proof, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts. It was generated by the harness during the run, before the final commit, so it records `git_status: dirty`; the dirty/untracked entries are exactly the Run 330 deliverables (the helper, the harness, this evidence archive, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_328.md`, and the narrow C4/C5 + protocol/ops/whitepaper doc updates).
* `.gitignore` — excludes the per-run generated artifacts.