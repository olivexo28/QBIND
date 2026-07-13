# QBIND DevNet Evidence — Run 317

Source/test **live epoch-transition mutation execution** boundary implementation.

Run 317 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 318.

---

## 1. Exact verdict

**PASS — Run 317 source/test live epoch-transition mutation execution boundary
implemented.**

A new narrow source/test boundary consumes a verified Run 315/316 non-mutating
live epoch-transition **execution preparation decision** (the accepted
`ProductionLiveEpochTransitionExecutionPreparationDecision` output that
`is_accept()` and carries `Some(preparation_artifact)`) and produces a typed,
deterministic, policy-gated **live-mutation execution artifact** that describes
exactly what a future live production mutation executor (Run 318+ / release)
would apply, together with the exact future-executor postconditions. Default
posture is `Disabled` / fail-closed.

This boundary produces **only a live-mutation execution artifact** and may, on a
source/test-bounded path, mutate **only** an explicit caller-owned in-memory
`LiveEpochTransitionMutationExecutionFixtureState`. It **does not** wire into
production runtime. It **does not** add a public CLI flag. It **does not** enable
MainNet. It **does not** apply a live production validator-set change. It **does
not** perform a production epoch transition. It **does not** call
`BasicHotStuffEngine::transition_to_epoch` on production runtime state. It **does
not** write `meta:current_epoch`. It **does not** inject a `PAYLOAD_KIND_RECONFIG`
block. It mutates no production consensus validator state, epoch counters,
`LivePqcTrustState`, trust-bundle sequence files, authority markers, sessions,
settlement, publication, audit-finalization, or external-publication state. It
calls neither Run 070 nor any runtime wiring. MainNet remains refused. Full C4
remains OPEN. C5 remains OPEN.

The live epoch-transition mutation execution boundary matrix row moves
**Red → Yellow** (source/test implementation landed; release-binary evidence
pending Run 318). It is **not** marked Green. No release-binary evidence, live
production validator-set mutation, production epoch transition, MainNet
readiness, C4 closure, or C5 closure is claimed. Prior Green-for-scope rows (Run
316 execution-preparation release-binary, Run 314 runtime handoff
release-binary, Run 312 guarded mutation executor release-binary, etc.) are
unchanged and not reinterpreted.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_live_epoch_transition_mutation_execution.rs` — boundary module.
* `crates/qbind-node/tests/run_317_production_live_epoch_transition_mutation_execution_tests.rs` — 149 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_317.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_live_epoch_transition_mutation_execution;`.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — added a new live epoch-transition mutation execution row Red → Yellow; refreshed status line; added Run 317 changelog entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/whitepaper/contradiction.md` — narrow Run 317 changelog entries.

---

## 3. Boundary design summary

`ProductionLiveEpochTransitionMutationExecutionExecutor` takes:

* a `ProductionLiveEpochTransitionMutationExecutionRequest` (a mutation-execution
  authority source, an explicit proposed epoch-transition target, a
  mutation-execution nonce, plus optional custody / attestation / durable-replay
  bindings),
* `ProductionLiveEpochTransitionMutationExecutionInputs` (operator-trusted
  expected values including the `expected_execution_preparation_*` and the
  re-exposed `expected_runtime_handoff_*` bindings, trust domain, evidence
  requirements, replay/freshness anchors, and the current-validator-set
  epoch/version fail-closed preflight preconditions), and
* a mutation-execution replay set.

`evaluate_live_epoch_transition_mutation_execution` returns a
`ProductionLiveEpochTransitionMutationExecutionDecision` carrying a typed
outcome, an execution id, a deterministic request id, an optional
`ProductionLiveEpochTransitionMutationExecutionArtifact`, an execution (content)
digest, and a transcript digest.

`recover_live_epoch_transition_mutation_execution_window` provides non-mutating
idempotency/recovery over a prepared execution window.

`LiveEpochTransitionMutationExecutionFixtureState` is a plain in-memory,
caller-owned struct that is the *only* thing a positive path may mutate; its
`apply_prepared_execution` advances only its own in-memory epoch / version /
digest fields and is idempotent per execution id.

All digests are length-prefixed, domain-separated SHA3-256 (hex-encoded); `Debug`
output is never used as canonical bytes and no wall-clock is read (freshness uses
explicit `min_governance_epoch` / `min_validator_set_epoch` /
`min_validator_set_version` / `persisted_sequence` anchors, and
`required_replay_window` is an operator precondition, never a wall-clock value and
never a reject path in Run 317).

---

## 4. Policy / kind / execution taxonomy

* `ProductionLiveEpochTransitionMutationExecutionExecutorPolicy` — default
  `Disabled`; a reserved DevNet/TestNet source/test policy authorizes only the
  non-mutating source/test execution path; the production and MainNet policies
  are reachable but fail closed as unavailable.
* `ProductionLiveEpochTransitionMutationExecutionExecutorKind` — the reserved
  mutation-execution kind; production/MainNet kinds fail closed.
* `LiveEpochTransitionMutationExecutionKind` — the artifact kind, derived from
  the consumed staged-application kind via `from_staged_application_kind`.

---

## 5. Run 315/316 execution-preparation artifact binding

The accept path consumes only a Run 315/316
`ProductionLiveEpochTransitionExecutionPreparationDecision` that `is_accept()`
and carries `Some(preparation_artifact)`. It binds the artifact to the consumed
decision's `preparation_id` / `request_id` / `preparation_digest` /
`transcript_digest` and the artifact's `execution_preparation_nonce`, re-exposes
and binds the Run 313/314 runtime-handoff decision id/request/intent/transcript
digests + `runtime_handoff_nonce`, and verifies the re-exposed guarded-mutation /
staged-application / authorization / application / rotation / governance /
validator-set tuple against the operator-trusted expected values. The artifact's
`content_digest()` must equal the execution-preparation decision's bound
`preparation_digest` (`ExecutionPreparationDecisionIntegrityMismatch` otherwise),
the execution-preparation nonce must match `expected_execution_preparation_nonce`
(`WrongExecutionPreparationNonce` otherwise), and the re-exposed runtime-handoff
nonce must match `expected_runtime_handoff_nonce` (`WrongRuntimeHandoffNonce`
otherwise).

---

## 6. Live-mutation execution artifact model

The `ProductionLiveEpochTransitionMutationExecutionArtifact` re-exposes the full
consumed tuple (execution-preparation, runtime-handoff, guarded-mutation,
staged-application, live-authorization, application, rotation-plan,
governance-execution-intent, governance-proof, validator-set) plus the bound
`execution_preparation_*` and `runtime_handoff_*` decision tuples and nonces, the
epoch-transition target, all nonces, the newly proposed `mutation_execution_nonce`,
and the exact future-executor postconditions (expected previous validator-set
digest + epoch/version, resulting validator-set digest + epoch/version, delta
digest, target consensus epoch, required governance epoch / authority sequence /
replay window, required current-committed-epoch source status, required
production-runtime-handle availability). It is a description only — no mutation is
implied by its construction.

---

## 7. Accepted source/test evidence

Accept tests compose the real Run 303/304 → Run 305/306 → Run 307/308 → Run
309/310 → Run 311/312 → Run 313/314 → Run 315/316 accept chain and assert the
artifact is produced with deterministic execution/request/content/transcript
digests that are stable across independent evaluations and encode the
future-executor postconditions, including the re-exposed runtime-handoff tuple.

---

## 8. Rejection / fail-closed evidence

Missing/unverified execution-preparation decision, accepted-without-artifact,
execution-preparation-decision alone, runtime-handoff-decision alone,
guarded-mutation-decision alone, staged-application alone, live-authorization
alone, application-decision alone, rotation-plan alone, governance-execution-
intent alone, governance-proof alone, fixture-only, local-operator,
peer-majority, custody-only / RemoteSigner-only / custody-attestation-only, and
arbitrary validator-set bytes are all rejected; every wrong-field /
execution-preparation-decision-integrity / runtime-handoff binding /
current-validator-set-epoch-version preflight / nonce / replay / stale case fails
closed. The default policy is `Disabled` and refuses before any binding.

---

## 9. MainNet refusal evidence

MainNet is refused under the source/test policy
(`mainnet_domain_refused_under_source_test_policy`); the production and MainNet
policies/kind are reachable but fail closed as unavailable absent production
authority criteria.

---

## 10. Replay / idempotency evidence

`recover_live_epoch_transition_mutation_execution_window` returns a stable,
non-mutating recovery outcome over a prepared execution window; repeated
evaluation with the same replay set yields identical digests.

---

## 11. Fixture-state evidence

`LiveEpochTransitionMutationExecutionFixtureState::apply_prepared_execution`
advances only its own in-memory epoch / version / digest fields and is idempotent
per execution id; it is the only mutation any path performs and is distinct from
production runtime state.

---

## 12. Non-mutation evidence

No path makes a `BasicHotStuffEngine::transition_to_epoch` call, writes
`meta:current_epoch`, injects a `PAYLOAD_KIND_RECONFIG` block, calls Run 070, or
mutates consensus/validator/epoch-counter/`LivePqcTrustState`/trust-bundle-sequence/
authority-marker/session/settlement/publication/audit-finalization/external-publication
state. The boundary produces only a description (artifact); it performs no live
mutation.

---

## 13. Tests run

* `cargo build -p qbind-node --lib` — success, zero warnings.
* `cargo test -p qbind-node --test run_317_production_live_epoch_transition_mutation_execution_tests` — **149 passed**.
* `cargo test -p qbind-node --test run_315_production_live_epoch_transition_execution_preparation_tests` — 139 passed.
* `cargo test -p qbind-node --test run_313_production_epoch_transition_runtime_handoff_tests` — 151 passed.
* `cargo test -p qbind-node --test run_311_production_guarded_epoch_transition_mutation_executor_tests` — 124 passed.
* `cargo test -p qbind-node --test run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests` — 121 passed.
* `cargo test -p qbind-node --test run_307_production_live_validator_set_application_authorization_tests` — 135 passed.
* `cargo test -p qbind-node --test run_305_production_validator_set_rotation_application_executor_tests` — 126 passed.
* `cargo test -p qbind-node --test run_303_production_validator_set_rotation_intent_tests` — 131 passed.
* `cargo test -p qbind-node --test run_301_production_governance_execution_engine_tests` — 117 passed.
* `cargo test -p qbind-node --lib` — 1377 passed.

No test target names required substitution.

---

## 14. Security scans

* **Secret scanning** — ran over all changed source/test/docs files; **no
  secrets detected**.
* **CodeQL** — the CodeQL checker was invoked over the new Rust source module
  and test file (changes classified non-trivial). The run **timed out** before
  returning results, so **no CodeQL alerts were reported** and, per tool policy,
  it was not re-run. **No CodeQL coverage is therefore claimed for Run 317.** The
  changes are a self-contained, non-mutating source/test boundary that performs
  no I/O, no `unsafe`, no deserialization of untrusted external input, and no
  network/filesystem access, mutating only a caller-owned in-memory fixture
  struct.

---

## 15. C4/C5 matrix status

The live epoch-transition mutation execution boundary row is added/moved
**Red → Yellow** in `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`. It is
**not** Green. Release-binary evidence is deferred to Run 318. No prior
Green-for-scope row is weakened or reinterpreted.

---

## 16. Honest limitations

* Source/test only; no release-binary evidence in Run 317.
* No production or MainNet authority is wired; those paths fail closed.
* The boundary never wires into production runtime, never applies a live
  production validator-set change, epoch transition, or trust-state mutation;
  only an in-memory test fixture state is ever mutated.
* No runtime wiring and no public CLI flag are added.
* The boundary produces only a live-mutation execution artifact; it does not
  itself perform any live mutation.

---

## 17. C4/C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 317 does not close, and does
not claim to close, either criterion, nor does it claim live production
validator-set mutation, production epoch transition, or MainNet readiness.

---

## 18. Suggested Run 318 next step

Capture **release-binary evidence** for the live epoch-transition mutation
execution boundary (example helper + devnet harness script + curated
`docs/devnet/run_318_*/` evidence dir), moving this row **Yellow → Green** for
scope, still without live production validator-set mutation, epoch transition,
MainNet enablement, runtime wiring, or CLI flag.