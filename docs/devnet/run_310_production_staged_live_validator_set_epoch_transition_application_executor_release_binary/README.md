# QBIND DevNet evidence — Run 310

**Title.** Release-binary evidence for the Run 309 staged live validator-set / epoch-transition application executor boundary.

**Status.** PASS (release-binary evidence). Run 310 is the release-binary evidence run for the Run 309 source/test **staged live validator-set / epoch-transition application executor boundary** in `crates/qbind-node/src/pqc_production_staged_live_validator_set_epoch_transition_application_executor.rs`.

Run 310 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_310_production_staged_live_validator_set_epoch_transition_application_executor_release_binary_helper.rs` that the Run 309 production library symbols are present and exercised in release mode. The helper drives the **real** Run 309 `ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor` over the **real** Run 307/308 verified live validator-set application authorization accept decision (`is_accept()` with `Some(authorization_intent)`; itself composing the Run 305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept decision), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating staged epoch-transition application records describing what a future mutating epoch-transition executor would apply. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome` variant; the boundary never applies a live validator-set change and never transitions a consensus epoch.

## What Run 310 states

* Run 310 is release-binary evidence for the Run 309 real staged live validator-set / epoch-transition application executor boundary.
* Run 310 does not add new production runtime wiring.
* Run 310 does not add a public CLI flag.
* Run 310 does not enable the boundary by default.
* Run 310 does not enable MainNet.
* Run 310 does not apply a live validator-set change.
* Run 310 does not transition a consensus epoch.
* Run 310 does not mutate a live validator set, consensus state, or epoch counter.
* Run 310 does not call `BasicHotStuffEngine::transition_to_epoch`.
* Run 310 does not write `meta:current_epoch`.
* Run 310 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 310 does not implement settlement or external publication.
* Run 310 does not call Run 070.
* Run 310 does not mutate `LivePqcTrustState`.
* Run 310 does not write trust-bundle sequence or authority marker files.
* Run 310 does not accept missing / unverified / accepted-without-authorization-intent authorization decisions, nor application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 310 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 Green-for-scope statuses.
* The default `ProductionStagedLiveValidatorSetEpochTransitionApplicationPolicy` is `Disabled` (fails closed with no staged-record construction before any authorization-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test staged-application requests are accepted only under the explicit source-test policy when they bind a verified Run 307/308 live validator-set application authorization accept decision that carries `Some(authorization_intent)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-authorization-intent / wrong-binding / mismatch / replay / stale inputs and never falls back to authorization-decision-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 309 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, the Run 298 custody attestation verifier row, the Run 300 on-chain governance proof verifier row, the Run 302 governance execution engine row, the Run 303/304 validator-set rotation intent boundary row, the Run 305/306 validator-set rotation application / epoch-transition executor row, and the Run 307/308 live validator-set application / epoch-transition authorization row each remain Green **only** for their release-binary-evidenced scope; the staged live validator-set / epoch-transition application executor row is now Green **only** for release-binary-evidenced staged-live-validator-set-epoch-transition-application-executor-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionStagedLiveValidatorSetEpochTransitionApplicationPolicy` (default `Disabled`, explicit source-test policy) and `ProductionStagedLiveValidatorSetEpochTransitionApplicationKind`.
* Config: `ProductionStagedLiveValidatorSetEpochTransitionApplicationConfig`, `ProductionStagedLiveValidatorSetEpochTransitionApplicationProtocolVersion`.
* Executor: `ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor` constructed over the real Run 307/308 verified live validator-set application authorization accept decision and an in-memory replay set.
* Authority source: `StagedLiveValidatorSetEpochTransitionApplicationAuthoritySource`, exercised over the real Run 307/308 `ProductionLiveValidatorSetApplicationAuthorizationDecision`.
* Inputs / request / decision / record: `ProductionStagedLiveValidatorSetEpochTransitionApplicationInputs`, `ProductionStagedLiveValidatorSetEpochTransitionApplicationRequest`, `ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision`, `ProductionStagedLiveValidatorSetEpochTransitionApplicationRecord`.
* Entry points: `evaluate_staged_live_validator_set_epoch_transition_application`, `recover_staged_live_validator_set_epoch_transition_application_window`, `production_staged_live_validator_set_epoch_transition_application_intent_digest`, `production_staged_live_validator_set_epoch_transition_application_request_id`, `production_staged_live_validator_set_epoch_transition_application_transcript_digest`.
* Replay set: trait `StagedLiveValidatorSetEpochTransitionApplicationReplaySet` and `EmptyStagedLiveValidatorSetEpochTransitionApplicationReplaySet`.
* Taxonomy: `ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome`, `ProductionStagedLiveValidatorSetEpochTransitionApplicationRecoveryOutcome`, `StagedLiveValidatorSetEpochTransitionApplicationKind`.

## Substitution notes

* The Run 309 executor surfaces every failure as a typed `ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome` fail-closed variant; there is no separate `ProductionStagedLiveValidatorSetEpochTransitionApplicationError` enum, so that symbol is intentionally not required by the reachability greps.
* There is no `WrongStagedApplicationNonce` outcome variant and no `expected_staged_application_nonce` input field: the staged-application nonce binds the deterministic `request_id` / staged record, so task item 38 ("wrong staged-application nonce fails closed") is proven honestly through staged-application replay-rejection (`StagedApplicationReplayRejected`) and independent-clean-recovery behavior when the staged nonce differs (a divergent staged nonce yields a different `request_id` / `staged_application_id`, so a persisted window is not idempotently matched and cannot be replayed into an accept), rather than through a dedicated wrong-nonce reject variant.

## How to reproduce

```bash
scripts/devnet/run_310_production_staged_live_validator_set_epoch_transition_application_executor_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 309 boundary symbols for reachability across the source module + the Run 307/308 live validator-set application authorization module + the Run 305/306 validator-set rotation application executor module + the Run 303/304 validator-set rotation intent module + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, records a no-mutation proof, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts.
* `.gitignore` — excludes the per-run generated artifacts.
