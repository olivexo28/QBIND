# QBIND DevNet evidence — Run 223

**Title.** Release-binary governance-execution evaluator-interface evidence.

**Status.** PASS target (release-binary). Run 223 is the release-binary evidence run for the Run 222 source/test production governance execution **evaluator interface** boundary (`crates/qbind-node/src/pqc_governance_execution_evaluator.rs`). It closes the release-binary limitation Run 222 recorded: the typed evaluator interface, the deterministic digest helpers, the fixture/emergency-fixture acceptance, the production/on-chain/MainNet unavailable fail-closed behaviour, and the MainNet peer-driven apply refusal guard are now proven to be exposed and exercised on the real release binary and through a release-built helper using production library symbols.

## Scope and required statements

Run 223 proves with real `target/release/qbind-node` and a release-built helper that:

* Run 223 is release-binary governance-execution evaluator-interface evidence;
* the evaluator interface is typed and release-evidenced;
* the deterministic source/request/response/transcript digests are stable and field-binding in release mode;
* the fixture evaluator accepts only DevNet/TestNet decision sources under the explicit `FixtureDecisionSourceAllowed` policy;
* the emergency-council fixture evaluator accepts only an explicit emergency decision under the explicit `EmergencyCouncilFixtureSourceAllowed` policy;
* an evaluator response authorizes a lifecycle action only when the authorized action, candidate digest, and sequence all match;
* the production / on-chain / MainNet evaluator boundaries are callable and return the typed unavailable / fail-closed outcome;
* the Run 220 runtime-consumption behaviour remains compatible when the evaluator policy is `Disabled` (inert);
* `evaluate_governance_evaluator_with_peer_driven_guard` preserves the MainNet peer-driven apply refusal even when a fixture evaluator would otherwise approve;
* no real governance execution engine is implemented;
* no real on-chain governance proof verifier is implemented;
* the fixture evaluator remains DevNet/TestNet evidence-only;
* the emergency fixture evaluator is explicit and non-production;
* production/on-chain/MainNet evaluator remains unavailable/fail-closed;
* MainNet peer-driven apply remains refused;
* validator-set rotation remains unsupported;
* existing Run 221 runtime-consumption behaviour remains compatible;
* no real KMS/HSM backend, RemoteSigner backend, or production signing-key custody is implemented;
* full C4 remains open; C5 remains open.

## Deliverables

* Helper: `crates/qbind-node/examples/run_223_governance_execution_evaluator_release_binary_helper.rs`.
* Harness: `scripts/devnet/run_223_governance_execution_evaluator_release_binary.sh`.
* Evidence archive: `docs/devnet/run_223_governance_execution_evaluator_release_binary/` (`README.md`, `summary.txt`, `.gitignore` tracked; generated artifacts ignored).
* Canonical report: this file.

## What is new versus Run 222

Run 222 landed the typed evaluator interface at the source/test level (60 tests) but explicitly deferred release-binary evidence to Run 223. Run 223 is the release-binary proof: the release-built helper drives the full A1–A18 / R1–R40 matrix from `task/RUN_223_TASK.txt` through the production library symbols (`ProductionGovernanceExecutionEvaluator` trait, `EvaluatorSourceKind` / `EvaluatorPolicy` selectors, `DecisionSourceIdentity` / `EvaluatorRequest` / `EvaluatorResponse` records, the four deterministic digest helpers, the typed `EvaluatorOutcome` / `EvaluatorComposedOutcome`, and `evaluate_governance_evaluator_with_peer_driven_guard`), records the deterministic digests, and confirms the accept/reject classification, the production/on-chain/MainNet unavailable fail-closed paths, and the MainNet peer-driven apply refusal — all in release mode.

The Run 222 evaluator interface has no runtime CLI/env selector and no production call-site wiring: it composes with the Run 220 runtime consumption as a *future* production evaluator target, and the `Disabled` evaluator policy is inert, so the Run 221 runtime-consumption behaviour is unchanged. Full positive evaluator acceptance with a real proposal binding is therefore exercised through the release-built helper using the same library symbols a future production call site would use; the real binary's default surfaces remain silent on the evaluator interface.

## Release-helper corpus

The helper records typed tables under `helper_evidence/run_223/tables/`, all driven through the Run 222 evaluator-interface library symbols (`pass=111`, `fail=0`):

* **Accepted A1–A18:** fixture acceptance on DevNet (A1) and TestNet (A2) under the explicit fixture policy; emergency-council fixture acceptance under the explicit emergency policy/action (A3); deterministic source-identity / request / response / transcript digests with field binding (A4–A7); request and response field binding (A8–A9); rotate (A10) and revoke (A11) authorization only with matching action/candidate-digest/sequence; emergency revoke only under the explicit emergency fixture policy (A12); production (A13), on-chain (A14), and MainNet (A15) evaluator boundaries callable and returning the typed unavailable outcome; the `Disabled` evaluator policy inert for Run 220 runtime-consumption compatibility (A16); the peer-driven guard preserving the MainNet refusal while accepting a non-MainNet round-trip (A17); and the evaluator interface remaining pure and repeatable with inputs unchanged (A18).
* **Rejection R1–R40:** disabled-policy rejection (R1); fixture/emergency rejected under production/MainNet-required policies (R2–R4); production/on-chain/MainNet evaluators unavailable (R5–R7, R37); unknown source (R8); every trust-domain / proposal / decision / lifecycle / candidate / sequence / epoch / proof-digest binding mismatch (R9–R21); expired (R22), stale/replayed (R23), quorum-insufficient (R24), emergency-not-authorized (R25), validator-set-rotation (R26), policy-change (R27) rejections; malformed source identity / request / response (R28–R30); unsupported evaluator version (R31); invalid response commitment (R32); local-operator / peer-majority cannot-satisfy fail-closed helpers (R33–R34); evaluator-valid-but-governance-invalid (R35) and governance-valid-but-response-invalid (R36) cross-checks; validation-only non-mutation (R38); mutating-rejection non-mutation through the composed guard (R39); and the MainNet peer-driven apply refusal even with fixture approval (R40).
* **Reachability:** source-kind / policy helpers, every trait implementation presenting its kind, the fixture trait verify path reaching authorize, the four deterministic digest helpers non-empty, and the explicit fail-closed helper symbols.

The helper also writes a fixture dump (`helper_evidence/run_223/fixtures/`) with the decision-source identity / request / response / expectations, the four digests, and an evaluator-interface inventory enumerating the source kinds, policies, evaluator implementations, and digest/eval helpers the release binary exposes.

## Real-binary surface invariants

The harness drives the real release binary:

* `--help` exposes no evaluator-interface surface (no governance-execution evaluator, decision-source identity, evaluator policy/request/response, or run-222/run-223 text).
* The default DevNet/TestNet/MainNet surfaces emit no governance-execution, production-governance, MainNet-governance, on-chain-verifier, governance-execution-evaluator, production-decision-source, validator-set-rotation, KMS/HSM, RemoteSigner, autonomous-apply, apply-on-receipt, peer-majority, or MainNet peer-driven-apply enablement claim.

## Required source/release reachability proof

The harness writes `reachability/source_reachability.txt`, `reachability/module_registration.txt`, and `reachability/run_220_consumption_reachability.txt` for:

* `pqc_governance_execution_evaluator` (module, registered in `lib.rs`);
* `ProductionGovernanceExecutionEvaluator`, `EvaluatorSourceKind`, `EvaluatorPolicy`;
* `DecisionSourceIdentity`, `EvaluatorRequest`, `EvaluatorResponse`, `EvaluatorOutcome`, `EvaluatorComposedOutcome`, `EvaluatorExpectations`;
* the deterministic digest helpers (`source_identity_digest`, `request_digest`, `response_digest`, `evaluator_transcript_digest`);
* the fixture, emergency-council fixture, production, on-chain, and MainNet evaluator implementations;
* `evaluate_governance_decision_source`, `verify_governance_evaluator_response`, `evaluate_governance_evaluator_with_peer_driven_guard`;
* the explicit fail-closed helpers (`mainnet_peer_driven_apply_remains_refused_under_evaluator`, `validator_set_rotation_remains_unsupported_under_evaluator`, `local_operator_cannot_satisfy_evaluator_policy`, `peer_majority_cannot_satisfy_evaluator_policy`);
* the Run 220 runtime-consumption symbols (`GovernanceExecutionRuntimeConsumption` / `consume_surface`) the evaluator interface composes with as a future target, proven unchanged.

## Mutation/no-mutation and denylist

The Run 222 evaluator module is pure: every public function and trait method performs no network or file I/O, writes no marker, writes no sequence, mutates no live trust, evicts no sessions, and never invokes Run 070 apply — the module exposes no mutation API. Every rejected evaluator outcome is a typed value returned from a pure function: no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active DummySig/DummyKem/DummyAead. R38 confirms the inputs are unchanged after a rejecting evaluation; R39 confirms the composed peer-driven guard rejects without mutation; R40 confirms MainNet peer-driven apply is refused even with fixture approval. An accepted evaluator outcome is at most a precondition for the real binary's existing ordered mutating path (Run 211 governance-execution evaluation → Run 055 sequence commit → v2 marker persist), which Run 223 does not exercise.

The denylist proves no MainNet apply, autonomous apply, apply-on-receipt, peer-majority authority, real governance execution engine active claim, production governance active claim, MainNet governance enabled claim, real on-chain governance proof verifier active claim, real KMS/HSM/RemoteSigner backend claim, custody-attestation production-active claim, validator-set rotation enabled claim, fallback to `--p2p-trusted-root`, active DummySig/DummyKem/DummyAead, or schema/wire/metric drift across the captured logs.

## Captured metadata

The harness captures qbind-node and helper SHA-256 plus ELF Build ID, git commit, rustc/cargo versions, exact commands, stdout/stderr logs, per-scenario exit codes, the evaluator source/request/response/transcript digests, the fixture inventory and hashes, the evaluator-interface inventory, mutation/no-mutation notes, and denylist grep results in the evidence archive. The regenerated `summary.txt` contains the observed SHA-256 and Build IDs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_223_governance_execution_evaluator_release_binary_helper
bash scripts/devnet/run_223_governance_execution_evaluator_release_binary.sh
cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests
cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests
cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests
cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests
cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests
cargo test -p qbind-node --test run_211_governance_execution_policy_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

All recorded results are PASS (helper corpus `pass=111`, `fail=0`; all regression targets `rc=0`).

## Why C4 / C5 remain OPEN

Run 223 is evidence-only. It adds no real governance execution engine, no real on-chain verifier, no KMS/HSM or RemoteSigner backend, no MainNet governance enablement, no validator-set rotation, no autonomous apply, no apply-on-receipt, no peer-majority authority, and no schema/wire/marker/sequence/trust-bundle change. The Run 222 evaluator interface is a pure typed validation surface; it cannot make production/on-chain/MainNet governance available and cannot weaken MainNet peer-driven apply refusal. The fixture evaluator remains evidence-only and refused for MainNet production purposes. **Full C4 remains OPEN; C5 remains OPEN.**
