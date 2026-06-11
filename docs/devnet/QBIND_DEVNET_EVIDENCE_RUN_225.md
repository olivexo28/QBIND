# QBIND DevNet evidence — Run 225

**Title.** Release-binary governance evaluator runtime integration evidence.

**Status.** PASS target (release-binary). Run 225 is the release-binary evidence run for the Run 224 source/test governance evaluator **runtime integration** layer (`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`). It closes the release-binary limitation Run 224 recorded: the integration entry points, the typed integration context and outcome, and the composition of Run 220 runtime consumption with the Run 222 evaluator interface, Run 211 decision validation, and Run 213 payload material are now proven to be exposed and exercised on the real release binary and through a release-built helper using production library symbols.

## Scope and required statements

Run 225 proves with real `target/release/qbind-node` and a release-built helper that:

* Run 225 is release-binary governance evaluator runtime integration evidence;
* runtime consumption and the evaluator interface are composed and release-evidenced;
* the evaluator request/response binding is deterministic and field-checked in release mode;
* mutation authorization (`ProceedMutate`) is produced only when **both** the Run 220 runtime-consumption stage and the Run 222 evaluator stage agree, after the documented ordering (selector resolution → sidecar/load-status derivation → runtime consumption → evaluator request construction → evaluator evaluation → governance execution decision validation → mutation only after all required checks pass);
* the default Disabled-policy + absent-carrier legacy bypass (`ProceedLegacyBypass`, Run 214 compatibility) is preserved;
* the production / on-chain / MainNet evaluator paths are reached and fail closed as unavailable (`EvaluatorRejected`);
* the fixture evaluator remains DevNet/TestNet evidence-only;
* the emergency fixture evaluator is explicit and non-production;
* MainNet peer-driven apply remains refused (`MainNetPeerDrivenApplyRefused`) even with a fixture evaluator approval;
* validator-set rotation remains unsupported;
* no real governance execution engine is implemented;
* no real on-chain governance proof verifier is implemented;
* existing Run 221 runtime-consumption and Run 223 evaluator-interface behaviour remains compatible;
* no real KMS/HSM backend, RemoteSigner backend, or production signing-key custody is implemented;
* full C4 remains open; C5 remains open.

## Deliverables

* Helper: `crates/qbind-node/examples/run_225_governance_evaluator_runtime_integration_release_binary_helper.rs`.
* Harness: `scripts/devnet/run_225_governance_evaluator_runtime_integration_release_binary.sh`.
* Evidence archive: `docs/devnet/run_225_governance_evaluator_runtime_integration_release_binary/` (`README.md`, `summary.txt`, `.gitignore` tracked; generated artifacts ignored).
* Canonical report: this file.

## What is new versus Run 224

Run 224 landed the integration layer at the source/test level (48 tests, A1–A12 / R1–R30) but explicitly deferred release-binary evidence to Run 225. Run 225 is the release-binary proof: the release-built helper drives the full A1–A15 / R1–R30 matrix from `task/RUN_225_TASK.txt` through the production library symbols (`integrate_governance_evaluator_runtime_consumption` / `..._from_optional_sidecar_value`, `GovernanceEvaluatorRuntimeIntegrationContext`, the typed `GovernanceEvaluatorRuntimeIntegrationOutcome`, and the composed Run 220 / Run 222 / Run 211 / Run 213 symbols), records the deterministic evaluator source/request/response digests and the Run 213 governance-execution payload digest, and confirms the accept/reject classification, the production/on-chain/MainNet unavailable fail-closed paths, the preserved legacy bypass, and the MainNet peer-driven apply refusal — all in release mode.

The Run 224 integration layer has no runtime CLI/env selector and no production call-site wiring: it composes the Run 220 runtime consumption, the Run 222 evaluator interface, the Run 211 decision validation, and the Run 213 payload material as a *future* production evaluation pipeline, and the `Disabled` policy / `Disabled` evaluator policy remain inert, so the Run 221 and Run 223 behaviour is unchanged. Full positive `ProceedMutate` authorization with a real proposal binding is therefore exercised through the release-built helper using the same library symbols a future production call site would use; the real binary's default surfaces remain silent on the integration.

## Release-helper corpus

The helper records typed tables under `helper_evidence/run_225/tables/`, all driven through the Run 224 integration library symbols (`pass=112`, `fail=0`):

* **Accepted A1–A15:** disabled-policy + absent-carrier legacy bypass (A1); DevNet (A2) and TestNet (A3) fixture runtime consumption composing with the fixture evaluator to `ProceedMutate`; emergency-council fixture accepting only an explicit emergency action (A4); deterministic evaluator request (A5) and response (A6) field binding; rotate (A7) and revoke (A8) authorized only when runtime consumption, the evaluator response, the governance decision, the candidate digest, and the sequence all match; production (A9), on-chain (A10), and MainNet (A11) evaluator paths reached and failing closed as unavailable; MainNet peer-driven apply refused even with fixture approval (A12); integration ordering proven by flipping either stage independently to reject (A13); Run 221 runtime-consumption compatibility across every runtime surface (A14); and Run 223 evaluator-interface compatibility — Disabled evaluator policy and production-unavailable fail-closed (A15).
* **Rejection R1–R30:** required-but-absent (R1) and malformed (R2) carrier runtime-consumption fail-closed; wrong evaluator source (R3); every trust-domain / proposal / decision / lifecycle / candidate / sequence / proof-digest / custody-digest binding mismatch (R4–R15); expired (R16), stale/replayed (R17), quorum-insufficient (R18), emergency-not-authorized (R19), validator-set-rotation (R20), policy-change (R21) rejections; production (R22), on-chain (R23), MainNet (R24) evaluator unavailable; local-operator (R25) and peer-majority (R26) cannot-satisfy fail-closed; evaluator-valid-but-governance-decision-invalid (R27) and governance-decision-valid-but-evaluator-response-invalid (R28) cross-stage reconciliation; validation-only non-mutation pure/repeatable (R29); and mutating-surface non-mutation pure/repeatable (R30).
* **Reachability:** both integration entry points reaching the same `ProceedMutate`, the sidecar-deriving wrapper reaching `ProceedMutate` for a present sidecar and failing closed for `None`, the integration-outcome predicate partitioning, the explicit fail-closed helper symbols, and the MainNet fixture refusal off the peer-driven path.

The helper also writes a fixture dump (`helper_evidence/run_225/fixtures/`) with the Run 213 governance-execution input/decision, the Run 222 decision-source identity / request / response, the deterministic digests, the captured `ProceedMutate` integration outcome, and an integration-layer inventory enumerating the entry points, context/outcome types, outcome variants, and composed-layer symbols the release binary exposes.

## Real-binary surface invariants

The harness drives the real release binary:

* `--help` exposes no evaluator-runtime integration surface (no evaluator-runtime-integration, governance-evaluator-runtime, integration entry-point, integration-outcome, or run-224/run-225 text).
* The default DevNet/TestNet/MainNet surfaces emit no governance-execution, production-governance, MainNet-governance, on-chain-verifier, evaluator-runtime-integration, production-decision-source, validator-set-rotation, KMS/HSM, RemoteSigner, autonomous-apply, apply-on-receipt, peer-majority, or MainNet peer-driven-apply enablement claim.

## Required source/release reachability proof

The harness writes `reachability/source_reachability.txt`, `reachability/module_registration.txt`, `reachability/run_220_consumption_reachability.txt`, `reachability/run_222_evaluator_reachability.txt`, and `reachability/no_mutation_before_integration.txt` for:

* `pqc_governance_execution_evaluator_runtime_integration` (module, registered in `lib.rs`);
* `integrate_governance_evaluator_runtime_consumption` and `integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value` (integration entry points);
* `GovernanceEvaluatorRuntimeIntegrationContext`, `GovernanceEvaluatorRuntimeIntegrationOutcome`;
* the outcome variants `ProceedLegacyBypass`, `ProceedMutate`, `RuntimeConsumptionFailClosed`, `EvaluatorRejected`, `MainNetPeerDrivenApplyRefused`;
* the Run 220 runtime-consumption call (`consume_surface` / `GovernanceExecutionRuntimeConsumption`) proven unchanged;
* the Run 222 evaluator calls (`ProductionGovernanceExecutionEvaluator`, `evaluate_governance_decision_source`, `verify_governance_evaluator_response`) proven unchanged;
* the Run 211 governance-execution validation (`GovernanceExecutionExpectations`) and Run 213 payload usage (`GovernanceExecutionLoadStatus`);
* the MainNet peer-driven guard and the "no mutation before integration success" invariant (the only mutate authorization is the terminal `ProceedMutate` variant, gated on `is_mutate_authorized`).

## Mutation/no-mutation and denylist

The Run 224 integration layer is pure: it performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, and never invokes Run 070 apply — the layer exposes no mutation API. Mutation authorization is only ever the terminal `ProceedMutate` variant, produced after **both** the Run 220 runtime-consumption stage and the Run 222 evaluator stage agree. Every rejected integration outcome is a typed value returned from a pure function: no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active DummySig/DummyKem/DummyAead. R29 confirms a validation-only rejection is pure/repeatable and non-mutating; R30 confirms a mutating-surface rejection is pure/repeatable and non-mutating; A12 confirms MainNet peer-driven apply is refused even with fixture approval. An accepted `ProceedMutate` outcome is at most a precondition for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation → Run 055 sequence commit → v2 marker persist), which Run 225 does not exercise.

The denylist proves no MainNet apply, autonomous apply, apply-on-receipt, peer-majority authority, real governance execution engine active claim, production governance active claim, MainNet governance enabled claim, real on-chain governance proof verifier active claim, evaluator-runtime-integration active claim, real KMS/HSM/RemoteSigner backend claim, custody-attestation production-active claim, validator-set rotation enabled claim, fallback to `--p2p-trusted-root`, active DummySig/DummyKem/DummyAead, marker-write-before-sequence-commit, or schema/wire/metric drift across the captured logs (24 forbidden patterns proven empty).

## Captured metadata

The harness captures qbind-node and helper SHA-256 plus ELF Build ID, git commit, rustc/cargo versions, exact commands, stdout/stderr logs, per-scenario exit codes, the evaluator source/request/response digests, the governance-execution payload digest, the captured integration outcome, the integration-layer inventory, mutation/no-mutation notes, and denylist grep results in the evidence archive. The regenerated `summary.txt` contains the observed SHA-256 and Build IDs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_225_governance_evaluator_runtime_integration_release_binary_helper
bash scripts/devnet/run_225_governance_evaluator_runtime_integration_release_binary.sh
cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests
cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests
cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests
cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests
cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests
cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests
cargo test -p qbind-node --test run_211_governance_execution_policy_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

All recorded results are PASS (helper corpus `pass=112`, `fail=0`; all regression targets `rc=0`).

## Why C4 / C5 remain OPEN

Run 225 is evidence-only. It adds no real governance execution engine, no real on-chain verifier, no KMS/HSM or RemoteSigner backend, no MainNet governance enablement, no validator-set rotation, no autonomous apply, no apply-on-receipt, no peer-majority authority, and no schema/wire/marker/sequence/trust-bundle change. The Run 224 integration layer is a pure typed composition surface; it cannot make production/on-chain/MainNet governance available and cannot weaken MainNet peer-driven apply refusal. The fixture evaluator remains evidence-only and refused for MainNet production purposes. **Full C4 remains OPEN; C5 remains OPEN.**