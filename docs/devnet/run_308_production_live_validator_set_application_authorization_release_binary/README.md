# QBIND DevNet evidence — Run 308

**Title.** Release-binary evidence for the Run 307 live validator-set application / epoch-transition authorization boundary.

**Status.** PASS (release-binary evidence). Run 308 is the release-binary evidence run for the Run 307 source/test **live validator-set application / epoch-transition authorization boundary** in `crates/qbind-node/src/pqc_production_live_validator_set_application_authorization.rs`.

Run 308 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_308_production_live_validator_set_application_authorization_release_binary_helper.rs` that the Run 307 production library symbols are present and exercised in release mode. The helper drives the **real** Run 307 `ProductionLiveValidatorSetApplicationAuthorizationExecutor` over the **real** Run 305/306 verified validator-set rotation application accept decision (`is_accept()` with `Some(application_intent)`; itself composing the Run 303/304 verified validator-set rotation plan accept decision and the Run 301/302 verified governance execution accept decision), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating live-application authorization intents for a future mutating executor. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionLiveValidatorSetApplicationAuthorizationOutcome` variant; the boundary never applies a live validator-set change.

## What Run 308 states

* Run 308 is release-binary evidence for the Run 307 real live validator-set application / epoch-transition authorization boundary.
* Run 308 does not add new production runtime wiring.
* Run 308 does not add a public CLI flag.
* Run 308 does not enable the boundary by default.
* Run 308 does not enable MainNet.
* Run 308 does not apply a live validator-set change.
* Run 308 does not mutate a live validator set, consensus state, or epoch counter.
* Run 308 does not call `BasicHotStuffEngine::transition_to_epoch`.
* Run 308 does not write `meta:current_epoch`.
* Run 308 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 308 does not implement settlement or external publication.
* Run 308 does not call Run 070.
* Run 308 does not mutate `LivePqcTrustState`.
* Run 308 does not write trust-bundle sequence or authority marker files.
* Run 308 does not accept missing / unverified / accepted-without-application-intent application decisions, nor rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 308 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 Green-for-scope statuses.
* The default `ProductionLiveValidatorSetApplicationAuthorizationPolicy` is `Disabled` (fails closed with no authorization-intent construction before any application-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test authorization requests are accepted only under the explicit source-test policy when they bind a verified Run 305/306 validator-set rotation application accept decision that carries `Some(application_intent)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-application-intent / wrong-binding / mismatch / replay / stale inputs and never falls back to rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 307 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, the Run 298 custody attestation verifier row, the Run 300 on-chain governance proof verifier row, the Run 302 governance execution engine row, the Run 303/304 validator-set rotation intent boundary row, and the Run 305/306 validator-set rotation application / epoch-transition executor row each remain Green **only** for their release-binary-evidenced scope; the live validator-set application / epoch-transition authorization row is now Green **only** for release-binary-evidenced live-validator-set-application-authorization-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionLiveValidatorSetApplicationAuthorizationPolicy` (default `Disabled`, explicit source-test policy) and `ProductionLiveValidatorSetApplicationAuthorizationKind`.
* Config: `ProductionLiveValidatorSetApplicationAuthorizationConfig`, `ProductionLiveValidatorSetApplicationAuthorizationProtocolVersion`.
* Executor: `ProductionLiveValidatorSetApplicationAuthorizationExecutor` constructed over the real Run 305/306 verified validator-set rotation application accept decision and an in-memory replay set.
* Authority source: `LiveValidatorSetApplicationAuthorizationAuthoritySource`, exercised over the real Run 305/306 `ProductionValidatorSetRotationApplicationDecision`.
* Inputs / request / decision / intent: `ProductionLiveValidatorSetApplicationAuthorizationInputs`, `ProductionLiveValidatorSetApplicationAuthorizationRequest`, `ProductionLiveValidatorSetApplicationAuthorizationDecision`, `ProductionLiveValidatorSetApplicationAuthorizationIntent`.
* Entry points: `evaluate_live_validator_set_application_authorization`, `recover_live_validator_set_application_authorization_window`, `production_live_validator_set_application_authorization_intent_digest`, `production_live_validator_set_application_authorization_request_id`, `production_live_validator_set_application_authorization_transcript_digest`.
* Replay set: trait `LiveValidatorSetApplicationAuthorizationReplaySet` and `EmptyLiveValidatorSetApplicationAuthorizationReplaySet`.
* Taxonomy: `ProductionLiveValidatorSetApplicationAuthorizationOutcome`, `ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome`, `LiveValidatorSetApplicationAuthorizationKind`.

## Substitution note

The Run 307 executor surfaces every failure as a typed `ProductionLiveValidatorSetApplicationAuthorizationOutcome` fail-closed variant; there is no separate `ProductionLiveValidatorSetApplicationAuthorizationError` enum, so that symbol from the task symbol list is intentionally not required by the reachability greps.

## How to reproduce

```bash
scripts/devnet/run_308_production_live_validator_set_application_authorization_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 307 boundary symbols for reachability across the source module + the Run 305/306 validator-set rotation application executor module + the Run 303/304 validator-set rotation intent module + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts.
* `.gitignore` — excludes the per-run generated artifacts.
