# QBIND DevNet evidence — Run 304

**Title.** Release-binary evidence for the Run 303 validator-set rotation / authority-set synchronization intent boundary.

**Status.** PASS (release-binary evidence). Run 304 is the release-binary evidence run for the Run 303 source/test **validator-set rotation / authority-set synchronization intent boundary** in `crates/qbind-node/src/pqc_production_validator_set_rotation_intent.rs`.

Run 304 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_304_production_validator_set_rotation_intent_release_binary_helper.rs` that the Run 303 production library symbols are present and exercised in release mode. The helper drives the **real** Run 303 `ProductionValidatorSetRotationBoundary` over the **real** Run 301/302 verified governance execution accept decision, only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating validator-set rotation plans. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionValidatorSetRotationOutcome` variant; the boundary never turns a verified intent into a live validator-set mutation.

## What Run 304 states

* Run 304 is release-binary evidence for the Run 303 real validator-set rotation / authority-set synchronization intent boundary.
* Run 304 does not add new production runtime wiring.
* Run 304 does not add a public CLI flag.
* Run 304 does not enable the boundary by default.
* Run 304 does not enable MainNet.
* Run 304 does not mutate a live validator set or consensus state.
* Run 304 does not call `BasicHotStuffEngine::transition_to_epoch`.
* Run 304 does not write `meta:current_epoch`.
* Run 304 does not inject a reconfig block.
* Run 304 does not implement settlement or external publication.
* Run 304 does not call Run 070.
* Run 304 does not mutate `LivePqcTrustState`.
* Run 304 does not write trust-bundle sequence or authority marker files.
* Run 304 does not accept fixture / unverified-governance-intent / on-chain-proof-alone / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only material as production authority.
* Run 304 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 Green-for-scope statuses.
* The default `ProductionValidatorSetRotationPolicy` is `Disabled` (fails closed with no plan construction before any governance/validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test rotation intents are accepted only under the explicit `AllowSourceTestValidatorSetRotationIntent` policy when they bind a verified Run 301/302 governance execution accept decision.
* Under a production policy the boundary fails closed on missing/unverified/wrong-binding/duplicate/unknown/ambiguous/unsupported/non-monotonic/stale/replay inputs and never falls back to fixture / local-operator / peer-majority / on-chain-proof-alone / RemoteSigner-only / custody-only / custody-attestation-only material.
* The release helper exercises the Run 303 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, the Run 298 custody attestation verifier row, the Run 300 on-chain governance proof verifier row, and the Run 302 governance execution engine row each remain Green **only** for their release-binary-evidenced scope; the validator-set rotation / authority-set synchronization row is now Green **only** for release-binary-evidenced validator-set-rotation-intent-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionValidatorSetRotationPolicy` (default `Disabled`, explicit `AllowSourceTestValidatorSetRotationIntent` policy) and `ProductionValidatorSetRotationKind`.
* Config: `ProductionValidatorSetRotationConfig`.
* Boundary: `ProductionValidatorSetRotationBoundary` constructed over the real Run 301/302 verified governance execution accept decision and an in-memory replay set.
* Authority source: `ValidatorSetRotationAuthoritySource`, exercised over the real Run 301/302 `ProductionGovernanceExecutionDecision` / `ProductionGovernanceExecutionIntent`.
* Canonical validator-set model: `CanonicalValidatorIdentity`, `CanonicalValidatorRecord`, `CanonicalValidatorSetSnapshot`, `ValidatorSetChange`, `ValidatorSetChangeKind`, `ValidatorSetDelta`, `ValidatorSetRotationAction`.
* Entry points: `evaluate_validator_set_rotation`, `recover_validator_set_rotation_window`, `production_validator_set_rotation_plan_digest`, `production_validator_set_rotation_request_id`, `production_validator_set_rotation_transcript_digest`.
* Replay set: trait `ValidatorSetRotationReplaySet` and `EmptyValidatorSetRotationReplaySet`.
* Taxonomy: `ProductionValidatorSetRotationOutcome`, `ProductionValidatorSetRotationRecoveryOutcome`, `ProductionValidatorSetRotationPlanKind`, `ProductionValidatorSetRotationDecision`, `ProductionValidatorSetRotationPlan`.

## Substitution note

The Run 303 boundary surfaces every failure as a typed `ProductionValidatorSetRotationOutcome` fail-closed variant; there is no separate `ProductionValidatorSetRotationError` enum, so that symbol from the task symbol list is intentionally not required by the reachability greps.

## How to reproduce

```bash
scripts/devnet/run_304_production_validator_set_rotation_intent_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 303 boundary symbols for reachability across the source module + the Run 301/302 governance execution engine module + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts.
* `.gitignore` — excludes the per-run generated artifacts.