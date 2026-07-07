# QBIND DevNet evidence — Run 306

**Title.** Release-binary evidence for the Run 305 validator-set rotation application / epoch-transition executor boundary.

**Status.** PASS (release-binary evidence). Run 306 is the release-binary evidence run for the Run 305 source/test **validator-set rotation application / epoch-transition executor boundary** in `crates/qbind-node/src/pqc_production_validator_set_rotation_application_executor.rs`.

Run 306 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_306_production_validator_set_rotation_application_executor_release_binary_helper.rs` that the Run 305 production library symbols are present and exercised in release mode. The helper drives the **real** Run 305 `ProductionValidatorSetRotationApplicationExecutor` over the **real** Run 303/304 verified validator-set rotation plan accept decision (itself composing the Run 301/302 verified governance execution accept decision), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating validator-set rotation application decisions/intents. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionValidatorSetRotationApplicationOutcome` variant; the boundary never applies a verified plan as a live validator-set mutation.

## What Run 306 states

* Run 306 is release-binary evidence for the Run 305 real validator-set rotation application / epoch-transition executor boundary.
* Run 306 does not add new production runtime wiring.
* Run 306 does not add a public CLI flag.
* Run 306 does not enable the boundary by default.
* Run 306 does not enable MainNet.
* Run 306 does not apply a live validator-set change.
* Run 306 does not mutate a live validator set, consensus state, or epoch counter.
* Run 306 does not call `BasicHotStuffEngine::transition_to_epoch`.
* Run 306 does not write `meta:current_epoch`.
* Run 306 does not inject a reconfig block.
* Run 306 does not implement settlement or external publication.
* Run 306 does not call Run 070.
* Run 306 does not mutate `LivePqcTrustState`.
* Run 306 does not write trust-bundle sequence or authority marker files.
* Run 306 does not accept governance-proof-alone / governance-execution-intent-alone / fixture / unverified-rotation-plan / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 306 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 Green-for-scope statuses.
* The default `ProductionValidatorSetRotationApplicationPolicy` is `Disabled` (fails closed with no application-intent construction before any plan/validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test application decisions are accepted only under the explicit `AllowSourceTestValidatorSetRotationApplication` policy when they bind a verified Run 303/304 validator-set rotation plan accept decision.
* Under a production policy the boundary fails closed on missing/unverified/wrong-binding/mismatch/replay/stale inputs and never falls back to governance-proof-alone / governance-execution-intent-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 305 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, the Run 298 custody attestation verifier row, the Run 300 on-chain governance proof verifier row, the Run 302 governance execution engine row, and the Run 303/304 validator-set rotation intent boundary row each remain Green **only** for their release-binary-evidenced scope; the validator-set rotation application / epoch-transition executor row is now Green **only** for release-binary-evidenced validator-set-rotation-application-executor-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionValidatorSetRotationApplicationPolicy` (default `Disabled`, explicit `AllowSourceTestValidatorSetRotationApplication` policy) and `ProductionValidatorSetRotationApplicationKind`.
* Config: `ProductionValidatorSetRotationApplicationConfig`, `ProductionValidatorSetRotationApplicationProtocolVersion`.
* Executor: `ProductionValidatorSetRotationApplicationExecutor` constructed over the real Run 303/304 verified validator-set rotation plan accept decision and an in-memory replay set.
* Authority source: `ValidatorSetRotationApplicationAuthoritySource`, exercised over the real Run 303/304 `ProductionValidatorSetRotationDecision` / `ProductionValidatorSetRotationPlan`.
* Inputs / request / decision / intent: `ProductionValidatorSetRotationApplicationInputs`, `ProductionValidatorSetRotationApplicationRequest`, `ProductionValidatorSetRotationApplicationDecision`, `ProductionValidatorSetRotationApplicationIntent`.
* Entry points: `evaluate_validator_set_rotation_application`, `recover_validator_set_rotation_application_window`, `production_validator_set_rotation_application_intent_digest`, `production_validator_set_rotation_application_request_id`, `production_validator_set_rotation_application_transcript_digest`.
* Replay set: trait `ValidatorSetRotationApplicationReplaySet` and `EmptyValidatorSetRotationApplicationReplaySet`.
* Taxonomy: `ProductionValidatorSetRotationApplicationOutcome`, `ProductionValidatorSetRotationApplicationRecoveryOutcome`, `ValidatorSetRotationApplicationDecisionKind`.

## Substitution note

The Run 305 executor surfaces every failure as a typed `ProductionValidatorSetRotationApplicationOutcome` fail-closed variant; there is no separate `ProductionValidatorSetRotationApplicationError` enum, so that symbol from the task symbol list is intentionally not required by the reachability greps.

## How to reproduce

```bash
scripts/devnet/run_306_production_validator_set_rotation_application_executor_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 305 boundary symbols for reachability across the source module + the Run 303/304 validator-set rotation intent module + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts.
* `.gitignore` — excludes the per-run generated artifacts.
