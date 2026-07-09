# QBIND DevNet evidence — Run 314

**Title.** Release-binary evidence for the Run 313 epoch-transition runtime handoff / live-mutation preflight boundary.

**Status.** PASS (release-binary evidence). Run 314 is the release-binary evidence run for the Run 313 source/test **epoch-transition runtime handoff / live-mutation preflight boundary** in `crates/qbind-node/src/pqc_production_epoch_transition_runtime_handoff.rs`.

Run 314 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_314_production_epoch_transition_runtime_handoff_release_binary_helper.rs` that the Run 313 production library symbols are present and exercised in release mode. The helper drives the **real** Run 313 `ProductionEpochTransitionRuntimeHandoffExecutor` over the **real** Run 311/312 verified guarded epoch-transition mutation-execution accept decision (`is_accept()` with `Some(staged_application_record)`; itself composing the Run 309/310 verified staged live validator-set / epoch-transition application accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept decision), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating runtime handoff / live-mutation preflight packages describing exactly what a future live mutating epoch-transition run would apply. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionEpochTransitionRuntimeHandoffOutcome` variant; the boundary never applies a live production validator-set change and never transitions a consensus epoch. Any positive fixture-state application is explicitly caller-owned, in-memory, source/test-only (`EpochTransitionRuntimeHandoffFixtureState`), and is not production runtime state.

## What Run 314 states

* Run 314 is release-binary evidence for the Run 313 real epoch-transition runtime handoff / live-mutation preflight boundary.
* Run 314 does not add new production runtime wiring.
* Run 314 does not add a public CLI flag.
* Run 314 does not enable the boundary by default.
* Run 314 does not enable MainNet.
* Run 314 does not apply a live production validator-set change.
* Run 314 does not perform a production epoch transition.
* Run 314 does not mutate a live validator set, consensus state, or epoch counter.
* Run 314 does not call `BasicHotStuffEngine::transition_to_epoch` on production runtime state.
* Run 314 does not write `meta:current_epoch`.
* Run 314 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 314 does not implement settlement or external publication.
* Run 314 does not call Run 070.
* Run 314 does not mutate `LivePqcTrustState`.
* Run 314 does not write trust-bundle sequence or authority marker files.
* Run 314 exercises the caller-owned in-memory `EpochTransitionRuntimeHandoffFixtureState` only as explicit source/test evidence, clearly distinct from production runtime state.
* Run 314 does not accept missing / unverified / accepted-without-guarded-record guarded decisions, nor staged-application-alone / live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 314 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 / 312 Green-for-scope statuses.
* The default `ProductionEpochTransitionRuntimeHandoffExecutorPolicy` is `Disabled` (fails closed with no package construction before any guarded-mutation-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test runtime-handoff requests are accepted only under the explicit source-test policy when they bind a verified Run 311/312 guarded epoch-transition mutation-execution accept decision that carries `Some(staged_application_record)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-guarded-record / wrong-binding / guarded-mutation-decision-integrity / current-validator-set-epoch-version-preflight / mismatch / replay / stale inputs and never falls back to guarded-mutation-decision-alone / staged-application-decision-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 313 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, the Run 298 custody attestation verifier row, the Run 300 on-chain governance proof verifier row, the Run 302 governance execution engine row, the Run 303/304 validator-set rotation intent boundary row, the Run 305/306 validator-set rotation application / epoch-transition executor row, the Run 307/308 live validator-set application / epoch-transition authorization row, the Run 309/310 staged live validator-set / epoch-transition application executor row, and the Run 311/312 guarded epoch-transition mutation executor row each remain Green **only** for their release-binary-evidenced scope; the epoch-transition runtime handoff / live-mutation preflight row is now Green **only** for release-binary-evidenced epoch-transition-runtime-handoff-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionEpochTransitionRuntimeHandoffExecutorPolicy` (default `Disabled`, explicit source-test policy) and `ProductionEpochTransitionRuntimeHandoffExecutorKind`.
* Config: `ProductionEpochTransitionRuntimeHandoffConfig`, `ProductionEpochTransitionRuntimeHandoffProtocolVersion`.
* Executor: `ProductionEpochTransitionRuntimeHandoffExecutor` constructed over the real Run 311/312 verified guarded epoch-transition mutation-execution accept decision and an in-memory replay set.
* Authority source: `EpochTransitionRuntimeHandoffAuthoritySource`, exercised over the real Run 311/312 `ProductionGuardedEpochTransitionMutationDecision`.
* Inputs / request / decision / package: `ProductionEpochTransitionRuntimeHandoffInputs`, `ProductionEpochTransitionRuntimeHandoffRequest`, `ProductionEpochTransitionRuntimeHandoffDecision`, `ProductionEpochTransitionRuntimeHandoffPackage`.
* Entry points: `evaluate_epoch_transition_runtime_handoff`, `recover_epoch_transition_runtime_handoff_window`, `production_epoch_transition_runtime_handoff_content_digest`, `production_epoch_transition_runtime_handoff_request_id`, `production_epoch_transition_runtime_handoff_id`, `production_epoch_transition_runtime_handoff_transcript_digest`.
* Replay set: trait `EpochTransitionRuntimeHandoffReplaySet` and `EmptyEpochTransitionRuntimeHandoffReplaySet`.
* Source/test fixture state: `EpochTransitionRuntimeHandoffFixtureState` (caller-owned, in-memory, source/test-only apply path; not production runtime state).
* Taxonomy: `ProductionEpochTransitionRuntimeHandoffOutcome`, `ProductionEpochTransitionRuntimeHandoffRecoveryOutcome`, `EpochTransitionRuntimeHandoffKind`.

## Substitution notes

* The Run 313 executor surfaces every failure as a typed `ProductionEpochTransitionRuntimeHandoffOutcome` fail-closed variant; there is no separate `ProductionEpochTransitionRuntimeHandoffError` enum, so that symbol is intentionally not required by the reachability greps.
* The Run 313 boundary produces a non-mutating `ProductionEpochTransitionRuntimeHandoffPackage` (rather than a mutation "record"); the package captures the exact future-executor preconditions (current/proposed set digests, current-validator-set epoch/version fail-closed preflight, delta digest, target epoch, required governance epoch / authority sequence / replay window), so the `ProductionEpochTransitionRuntimeHandoffProtocolVersion` and `ProductionEpochTransitionRuntimeHandoffPackage` symbols are proven reachable in the source module rather than being separately exercised by the helper.

## How to reproduce

```bash
scripts/devnet/run_314_production_epoch_transition_runtime_handoff_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 313 boundary symbols for reachability across the source module + the Run 311/312 guarded mutation executor module + the Run 309/310 staged application executor module + the Run 307/308 live validator-set application authorization module + the Run 305/306 validator-set rotation application executor module + the Run 303/304 validator-set rotation intent module + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, records a no-mutation proof, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts.
* `.gitignore` — excludes the per-run generated artifacts.