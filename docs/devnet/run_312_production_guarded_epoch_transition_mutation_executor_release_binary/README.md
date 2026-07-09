# QBIND DevNet evidence — Run 312

**Title.** Release-binary evidence for the Run 311 guarded epoch-transition mutation executor boundary.

**Status.** PASS (release-binary evidence). Run 312 is the release-binary evidence run for the Run 311 source/test **guarded epoch-transition mutation executor boundary** in `crates/qbind-node/src/pqc_production_guarded_epoch_transition_mutation_executor.rs`.

Run 312 proves on real `target/release/qbind-node` plus the release-built helper `crates/qbind-node/examples/run_312_production_guarded_epoch_transition_mutation_executor_release_binary_helper.rs` that the Run 311 production library symbols are present and exercised in release mode. The helper drives the **real** Run 311 `ProductionGuardedEpochTransitionMutationExecutor` over the **real** Run 309/310 verified staged live validator-set / epoch-transition application accept decision (`is_accept()` with `Some(staged_application_record)`; itself composing the Run 307/308 verified live validator-set application authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept decision), only for DevNet/TestNet source-test identities on the accept path, and produces typed non-mutating guarded mutation-execution records describing what a future live mutating epoch-transition executor would apply. The boundary remains dead code from the production runtime: the production binary never constructs the boundary, adds no CLI flag, and enables neither the boundary by default nor MainNet. Every failure surfaces as a typed non-mutating `ProductionGuardedEpochTransitionMutationOutcome` variant; the boundary never applies a live validator-set change and never transitions a consensus epoch. Any positive fixture-ledger application is explicitly caller-owned, in-memory, source/test-only (`GuardedEpochTransitionFixtureLedger`), and is not production runtime state.

## What Run 312 states

* Run 312 is release-binary evidence for the Run 311 real guarded epoch-transition mutation executor boundary.
* Run 312 does not add new production runtime wiring.
* Run 312 does not add a public CLI flag.
* Run 312 does not enable the boundary by default.
* Run 312 does not enable MainNet.
* Run 312 does not apply a live production validator-set change.
* Run 312 does not perform a production epoch transition.
* Run 312 does not mutate a live validator set, consensus state, or epoch counter.
* Run 312 does not call `BasicHotStuffEngine::transition_to_epoch` on production runtime state.
* Run 312 does not write `meta:current_epoch`.
* Run 312 does not inject a `PAYLOAD_KIND_RECONFIG` block.
* Run 312 does not implement settlement or external publication.
* Run 312 does not call Run 070.
* Run 312 does not mutate `LivePqcTrustState`.
* Run 312 does not write trust-bundle sequence or authority marker files.
* Run 312 exercises the caller-owned in-memory `GuardedEpochTransitionFixtureLedger` only as explicit source/test evidence, clearly distinct from production runtime state.
* Run 312 does not accept missing / unverified / accepted-without-staged-record staged decisions, nor application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-validator-set-bytes material as production authority.
* Run 312 does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 Green-for-scope statuses.
* The default `ProductionGuardedEpochTransitionMutationExecutorPolicy` is `Disabled` (fails closed with no record construction before any staged-application-decision / validator-set binding); `MainNet` is refused absent production authority criteria; DevNet/TestNet source-test guarded-mutation requests are accepted only under the explicit source-test policy when they bind a verified Run 309/310 staged live validator-set / epoch-transition application accept decision that carries `Some(staged_application_record)`.
* Under a production policy the boundary fails closed on missing / unverified / accepted-without-staged-record / wrong-binding / mismatch / replay / stale inputs and never falls back to staged-application-decision-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material.
* The release helper exercises the Run 311 production library symbols in release mode and remains dead code from the production runtime.
* The C4/C5 matrix taxonomy clarification remains present and separates boundary readiness from production readiness.
* The Run 292 durable replay RocksDB row, the Run 294 RemoteSigner backend row, the Run 296 KMS/HSM custody backend row, the Run 298 custody attestation verifier row, the Run 300 on-chain governance proof verifier row, the Run 302 governance execution engine row, the Run 303/304 validator-set rotation intent boundary row, the Run 305/306 validator-set rotation application / epoch-transition executor row, the Run 307/308 live validator-set application / epoch-transition authorization row, and the Run 309/310 staged live validator-set / epoch-transition application executor row each remain Green **only** for their release-binary-evidenced scope; the guarded epoch-transition mutation executor row is now Green **only** for release-binary-evidenced guarded-epoch-transition-mutation-executor-boundary behavior. None of these close C4/C5.
* Red production rows (MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production custody) remain Red.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## Boundary symbols exercised

* Policy: `ProductionGuardedEpochTransitionMutationExecutorPolicy` (default `Disabled`, explicit source-test policy) and `ProductionGuardedEpochTransitionMutationExecutorKind`.
* Config: `ProductionGuardedEpochTransitionMutationConfig`, `ProductionGuardedEpochTransitionMutationProtocolVersion`.
* Executor: `ProductionGuardedEpochTransitionMutationExecutor` constructed over the real Run 309/310 verified staged live validator-set / epoch-transition application accept decision and an in-memory replay set.
* Authority source: `GuardedEpochTransitionMutationAuthoritySource`, exercised over the real Run 309/310 `ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision`.
* Inputs / request / decision / record: `ProductionGuardedEpochTransitionMutationInputs`, `ProductionGuardedEpochTransitionMutationRequest`, `ProductionGuardedEpochTransitionMutationDecision`, `ProductionGuardedEpochTransitionMutationRecord`.
* Entry points: `evaluate_guarded_epoch_transition_mutation`, `recover_guarded_epoch_transition_mutation_window`, `production_guarded_epoch_transition_mutation_intent_digest`, `production_guarded_epoch_transition_mutation_request_id`, `production_guarded_epoch_transition_mutation_transcript_digest`.
* Replay set: trait `GuardedEpochTransitionMutationReplaySet` and `EmptyGuardedEpochTransitionMutationReplaySet`.
* Source/test fixture ledger: `GuardedEpochTransitionFixtureLedger` (caller-owned, in-memory, source/test-only apply path; not production runtime state).
* Taxonomy: `ProductionGuardedEpochTransitionMutationOutcome`, `ProductionGuardedEpochTransitionMutationRecoveryOutcome`, `GuardedEpochTransitionMutationKind`.

## Substitution notes

* The Run 311 executor surfaces every failure as a typed `ProductionGuardedEpochTransitionMutationOutcome` fail-closed variant; there is no separate `ProductionGuardedEpochTransitionMutationError` enum, so that symbol is intentionally not required by the reachability greps.
* Unlike the Run 309 staged boundary, the Run 311 guarded boundary exposes an explicit `WrongStagedApplicationNonce` outcome variant and an `expected_staged_application_nonce` input field, so task item 38 ("wrong staged-application nonce fails closed") is proven directly through a dedicated wrong-nonce reject in addition to guarded-mutation replay-rejection / independent-clean-recovery behavior.

## How to reproduce

```bash
scripts/devnet/run_312_production_guarded_epoch_transition_mutation_executor_release_binary.sh
```

The harness builds the real release `qbind-node` binary and the release helper, runs the helper corpus twice (checking deterministic-digest stability), captures real-binary CLI scenarios proving no public CLI flag / no enablement banner / default production silence, greps the Run 311 boundary symbols for reachability across the source module + the Run 309/310 staged application executor module + the Run 307/308 live validator-set application authorization module + the Run 305/306 validator-set rotation application executor module + the Run 303/304 validator-set rotation intent module + the release helper, verifies the C4/C5 matrix taxonomy, proves the denylist empty, records a no-mutation proof, and runs the associated test targets. Generated artifacts (`logs/`, `exit_codes/`, `reachability/`, `test_results/`, `data/`, `helper_evidence/`, `provenance.txt`, `negative_invariants.txt`, `no_mutation_proof.txt`) contain absolute paths and are `.gitignore`d; only `README.md`, `summary.txt`, and `.gitignore` are tracked.

## Tracked artifacts

* `README.md` — this file.
* `summary.txt` — top-level verdict, binary/helper hashes, helper corpus tables, deterministic digests, real-binary scenarios, reachability/taxonomy/denylist status, and test verdicts.
* `.gitignore` — excludes the per-run generated artifacts.
