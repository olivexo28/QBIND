# QBIND DevNet Evidence — Run 313

Source/test **epoch-transition runtime handoff** boundary implementation.

Run 313 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 314.

---

## 1. Exact verdict

**PASS — Run 313 source/test epoch-transition runtime handoff boundary
implemented.**

A new narrow source/test boundary consumes a verified Run 311/312 non-mutating
guarded epoch-transition mutation-execution **decision** (the accepted
`ProductionGuardedEpochTransitionMutationDecision` output that `is_accept()` and
carries `Some(staged_application_record)`) and produces a typed, deterministic,
policy-gated **runtime handoff / live-mutation preflight package** that describes
exactly what a future live mutating run (Run 314+) would apply, together with the
exact future-executor preconditions. Default posture is `Disabled` / fail-closed.

This boundary produces **only a runtime handoff / live-mutation preflight
package** and may, on a source/test-bounded path, mutate **only** an explicit
caller-owned in-memory `EpochTransitionRuntimeHandoffFixtureState`. It **does
not** wire into production runtime. It **does not** add a public CLI flag. It
**does not** enable MainNet. It **does not** apply a live production
validator-set change. It **does not** call
`BasicHotStuffEngine::transition_to_epoch` on production runtime state. It
**does not** write `meta:current_epoch`. It **does not** inject a
`PAYLOAD_KIND_RECONFIG` block. It mutates no production consensus validator
state, epoch counters, `LivePqcTrustState`, trust-bundle sequence files,
authority markers, sessions, settlement, publication, audit-finalization, or
external-publication state. It calls neither Run 070 nor any runtime wiring.
MainNet remains refused. Full C4 remains OPEN. C5 remains OPEN.

The epoch-transition runtime handoff / live-mutation preflight boundary matrix
row moves **Red → Yellow** (source/test implementation landed; release-binary
evidence pending Run 314). It is **not** marked Green. No release-binary
evidence, live production validator-set mutation, production epoch transition,
MainNet readiness, C4 closure, or C5 closure is claimed. Prior Green-for-scope
rows (Run 312 guarded mutation executor release-binary, Run 310 staged
application executor, etc.) are unchanged and not reinterpreted.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_epoch_transition_runtime_handoff.rs` — boundary module (already committed on this branch).
* `crates/qbind-node/tests/run_313_production_epoch_transition_runtime_handoff_tests.rs` — 151 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_313.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_epoch_transition_runtime_handoff;` (already committed on this branch).
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — added a new epoch-transition runtime handoff / live-mutation preflight row Red → Yellow; refreshed status line; added Run 313 changelog entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/whitepaper/contradiction.md` — narrow Run 313 changelog entries.

---

## 3. Boundary design summary

`ProductionEpochTransitionRuntimeHandoffExecutor` takes:

* a `ProductionEpochTransitionRuntimeHandoffRequest` (an
  `EpochTransitionRuntimeHandoffAuthoritySource`, an explicit proposed
  epoch-transition target, a runtime-handoff nonce, plus optional custody /
  attestation / durable-replay bindings),
* `ProductionEpochTransitionRuntimeHandoffInputs` (operator-trusted expected
  values, trust domain, evidence requirements, replay/freshness anchors, and the
  current-validator-set epoch/version fail-closed preflight preconditions), and
* an `EpochTransitionRuntimeHandoffReplaySet`.

`evaluate_epoch_transition_runtime_handoff` returns a
`ProductionEpochTransitionRuntimeHandoffDecision` carrying a typed
`ProductionEpochTransitionRuntimeHandoffOutcome`, a `handoff_id`, a deterministic
`request_id`, an optional `ProductionEpochTransitionRuntimeHandoffPackage`, a
handoff (content) digest, and a transcript digest.

`recover_epoch_transition_runtime_handoff_window` provides non-mutating
idempotency/recovery over a prepared runtime-handoff window.

`EpochTransitionRuntimeHandoffFixtureState` is a plain in-memory, caller-owned
struct that is the *only* thing a positive path may mutate; its
`apply_prepared_execution` advances only its own in-memory epoch / version /
digest fields and is idempotent per execution id.

All digests are length-prefixed, domain-separated SHA3-256 (hex-encoded) via a
module-local `hash_field` helper; `Debug` output is never used as canonical
bytes and no wall-clock is read (freshness uses explicit
`min_governance_epoch` / `min_validator_set_epoch` / `min_validator_set_version`
/ `persisted_sequence` anchors, and `required_replay_window` is an operator
precondition, never a wall-clock value and never a reject path in Run 313).

---

## 4. Policy / kind / handoff taxonomy

**Policy** (`ProductionEpochTransitionRuntimeHandoffExecutorPolicy`):
`Disabled` (default, fail-closed),
`AllowSourceTestEpochTransitionRuntimeHandoff` (DevNet/TestNet source/test),
`RequireProductionEpochTransitionRuntimeHandoff` (reachable, fails closed — no
production authority wired),
`MainnetProductionEpochTransitionRuntimeHandoffRequired` (reachable, fails
closed — no MainNet authority wired).

**Kind** (`ProductionEpochTransitionRuntimeHandoffExecutorKind`): `Disabled`
(inert default), `SourceTestEpochTransitionRuntimeHandoff` (real source/test
construction), `ProductionEpochTransitionRuntimeHandoff` (reserved production
kind, fail-closed as unavailable). MainNet availability is refused by the
MainNet gate rather than a distinct kind.

**Handoff kind** (`EpochTransitionRuntimeHandoffKind`): one-to-one with the
consumed Run 311/312 `GuardedEpochTransitionMutationKind`
(StageApply{NoOp,ValidatorAdd,ValidatorRemove,ValidatorMetadataUpdate,
ValidatorIdentityRotation,ValidatorRetirement,EmergencyValidatorRemoval,
AuthoritySetSynchronization,BulkValidatorSetRotation}), plus the reserved
`UnsupportedStagedApplication`.

Other taxonomy: `ProductionEpochTransitionRuntimeHandoffRequest`,
`ProductionEpochTransitionRuntimeHandoffInputs`,
`ProductionEpochTransitionRuntimeHandoffDecision`,
`ProductionEpochTransitionRuntimeHandoffPackage`,
`ProductionEpochTransitionRuntimeHandoffOutcome`,
`ProductionEpochTransitionRuntimeHandoffRecoveryOutcome`,
`EpochTransitionRuntimeHandoffReplaySet`,
`EpochTransitionRuntimeHandoffFixtureState`, and named digest helpers for
request / handoff id / content (handoff) digest / transcript.

---

## 5. Run 311/312 guarded mutation record binding

The **only** accepted authority source is
`EpochTransitionRuntimeHandoffAuthoritySource::VerifiedGuardedMutationDecision`
carrying a Run 311/312 guarded mutation-execution decision that `is_accept()`
and carries `Some(staged_application_record)`. The executor binds:

* the consumed guarded-mutation decision transcript — `staged_application_id`
  (guarded mutation decision id), `request_id`, `intent_digest`,
  `transcript_digest`, plus a re-derivation integrity check
  (`record.intent_digest() == decision.intent_digest`);
* the re-exposed Run 311/312 staged-application decision tuple
  (`staged_application_decision_id`, `staged_application_request_id`,
  `staged_application_intent_digest`, `staged_application_transcript_digest`) and
  staged-application nonce;
* the re-exposed live-authorization decision tuple and authorization policy id;
* the re-exposed Run 305/306 application-decision tuple and application policy
  id, plus application / live-application / staged-application / guarded-mutation
  nonces;
* environment, chain id, genesis hash, authority root fingerprint + suite id;
* governance domain / epoch / proposal / execution decision-request-intent
  digests, quorum, threshold, lifecycle + rotation actions, authority-domain
  sequence;
* rotation decision / request / transcript / plan digests;
* current / proposed / delta validator-set digests, validator-set epoch /
  version, proposed validator count, rotation nonce;
* the current-validator-set epoch/version fail-closed preflight preconditions
  (operator-declared current epoch/version must not lead the record's bound
  validator-set epoch/version);
* the explicit epoch-transition target (matched against both the operator-trusted
  input and the consumed record);
* custody / attestation / durable-replay bindings where represented.

Any divergence yields a precise typed fail-closed outcome; every non-authority
source (staged-application-decision-alone, live-authorization-alone,
application-decision-alone, rotation-plan-alone, governance-execution-intent-
alone, governance-proof-alone, fixture-only, local-operator, peer-majority,
custody-only, RemoteSigner-only, custody-attestation-only, arbitrary
validator-set bytes, missing/unverified/record-less guarded decision) is
rejected.

---

## 6. Runtime handoff package model

An accepted evaluation returns
`AcceptedSourceTestEpochTransitionRuntimeHandoff { handoff_kind, environment,
epoch_transition_target, runtime_handoff_nonce }` and a prepared
`ProductionEpochTransitionRuntimeHandoffPackage`. The decision exposes a
deterministic `handoff_id`, `request_id`, `handoff_digest`, and
`transcript_digest`. The package re-derives its own content digest
deterministically across re-evaluations and re-exposes the full guarded-mutation
/ staged-application / authorization / application / governance / rotation /
validator-set / epoch-transition / nonce evidence tuple, the consumed
guarded-mutation decision transcript, the newly proposed `runtime_handoff_nonce`,
**and** the exact future-executor preconditions
(`precondition_current_validator_set_digest`,
`precondition_current_validator_set_epoch`,
`precondition_current_validator_set_version`,
`precondition_proposed_validator_set_digest`, `precondition_delta_digest`,
`precondition_target_epoch`, `precondition_required_governance_epoch`,
`precondition_required_authority_sequence`,
`precondition_required_replay_window`). The package is non-mutating; a future
live run (Run 314+) is the only thing that could apply it against production
state.

---

## 7. Accepted source/test evidence

* `accept_all_scenarios_devnet` / `accept_all_scenarios_testnet` and the
  per-scenario `scenario_accept_*` / `scenario_testnet_accept_*` tests exercise
  all nine handoff kinds on DevNet and TestNet.
* `accept_binds_guarded_mutation_decision_transcript`,
  `accept_reexposes_staged_application_tuple`,
  `accept_reexposes_live_authorization_tuple`,
  `accept_reexposes_application_and_governance_tuple`,
  `accept_package_carries_future_executor_preconditions` verify the bound tuple
  and the preflight preconditions.
* `accept_deterministic_digests_under_reevaluation`,
  `accept_package_digest_matches_named_helper`,
  `accept_decision_and_package_identifiers_agree`,
  `accept_distinct_scenarios_have_distinct_digests`,
  `distinct_environments_yield_distinct_digests`,
  `handoff_id_and_request_id_are_domain_separated` verify
  determinism/uniqueness/domain-separation.

---

## 8. Rejection / fail-closed evidence

* Guarded-mutation-decision binding mismatches:
  `reject_wrong_guarded_mutation_decision_id`,
  `..._request_id`, `..._intent_digest`, `..._transcript_digest`,
  `reject_wrong_guarded_mutation_nonce`, and
  `reject_guarded_mutation_integrity_mismatch`.
* Binding mismatches: staged-application id/request/intent/transcript/nonce,
  live-authorization id/request/intent/transcript/policy, application
  id/request/intent/transcript/policy, environment/chain/genesis/authority-root,
  governance domain/epoch/proposal/decision/request/intent, rotation
  ids/digests, lifecycle/rotation action, authority sequence, quorum/threshold,
  current/proposed/delta digests, validator-set epoch/version, proposed count,
  rotation nonce, current-validator-set epoch/version preflight preconditions,
  epoch-transition target (both input and request paths), application/live-
  application nonce.
* Authority-source rejections for all fifteen non-authority / unverified /
  record-less sources (including staged-application-alone and
  live-authorization-alone).

---

## 9. MainNet refusal evidence

* `reject_mainnet_trust_domain` → `MainNetRefused`.
* `reject_mainnet_policy_unavailable` /
  `reject_mainnet_policy_on_mainnet_domain_unavailable` →
  `MainNetProductionEpochTransitionRuntimeHandoffUnavailable`.
* `reject_production_policy_unavailable` →
  `ProductionEpochTransitionRuntimeHandoffUnavailable`.
* `reject_production_boundary_kind_unavailable` →
  `EpochTransitionRuntimeHandoffBoundaryUnavailable`.
* `reject_disabled_policy` → `Disabled`.

MainNet is refused absent complete production authority; the production and
MainNet policy/kind paths are reachable but fail closed as unavailable.

---

## 10. Replay / idempotency evidence

* `reject_replayed_handoff` → `StagedApplicationReplayRejected` for a replayed
  internal handoff id; `accept_when_replay_set_has_unrelated_id` stays accept.
* `recovery_clean_when_no_prior_window`,
  `recovery_idempotent_replay_observed`,
  `recovery_disabled_under_disabled_policy`,
  `recovery_independent_window_for_different_nonce`.
* Freshness: `reject_stale_governance_epoch`, `reject_stale_authority_sequence`,
  `reject_stale_validator_set_epoch`, `reject_stale_validator_set_version`.

---

## 11. Fixture-state evidence

* The only mutation performed on any path is against the caller-owned in-memory
  `EpochTransitionRuntimeHandoffFixtureState`
  (`fixture_state_apply_advances_state`, `fixture_state_apply_is_idempotent`,
  `fixture_state_starts_unapplied`, and the per-scenario `scenario_accept_*`
  fixture-application step). No production consensus / epoch / trust state is
  touched. This fixture state is not wired into node runtime and is used
  exclusively by these tests.

---

## 12. Non-mutation evidence

* `invariant_all_outcomes_non_mutating`,
  `invariant_accept_authorizes_future_mutation_only`, and the module invariant
  functions (`..._default_is_disabled`,
  `..._is_source_test_not_release_binary_evidence`, `..._mainnet_refused`,
  `..._is_non_mutating`, `..._never_falls_back`, `..._no_default_runtime_wiring`,
  `..._requires_verified_application_decision`).
* Every `ProductionEpochTransitionRuntimeHandoffOutcome::is_non_mutating()`
  returns `true`; the accepted outcome only `authorizes_future_mutation_only()`
  and never applies anything in Run 313.

---

## 13. Tests run

* `cargo build -p qbind-node --lib` — success.
* `cargo test -p qbind-node --test run_313_production_epoch_transition_runtime_handoff_tests` — **151 passed**.
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
* **CodeQL** — **Skipped: all changes classified trivial.** The CodeQL checker
  was invoked and returned `Skipped: all changes are trivial.` The Run 313
  completion work committed in this session is **documentation-only** (this
  evidence file plus narrow C4/C5 matrix/changelog and protocol/ops/whitepaper
  changelog entries); the Run 313 source module
  (`crates/qbind-node/src/pqc_production_epoch_transition_runtime_handoff.rs`)
  and its test corpus were committed in prior sessions and are unchanged here.
  Because CodeQL did not analyze code in this session, **no CodeQL coverage is
  claimed** for Run 313. The skip is due solely to the trivial (docs-only)
  classification, not to hiding a failed or errored result.

---

## 15. C4/C5 matrix status

The epoch-transition runtime handoff / live-mutation preflight boundary row is
added/moved **Red → Yellow** in
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`. It is **not** Green.
Release-binary evidence is deferred to Run 314. No prior Green-for-scope row is
weakened or reinterpreted.

---

## 16. Honest limitations

* Source/test only; no release-binary evidence in Run 313.
* No production or MainNet authority is wired; those paths fail closed.
* The boundary never wires into production runtime, never applies a live
  production validator-set change, epoch transition, or trust-state mutation;
  only an in-memory test fixture state is ever mutated.
* No runtime wiring and no public CLI flag are added.
* The boundary produces only a runtime handoff / live-mutation preflight
  package; it does not itself perform any live mutation.

---

## 17. C4/C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 313 does not close, and does
not claim to close, either criterion, nor does it claim live production
validator-set mutation, production epoch transition, or MainNet readiness.

---

## 18. Suggested Run 314 next step

Capture **release-binary evidence** for the epoch-transition runtime handoff /
live-mutation preflight boundary (example helper + devnet harness script +
curated `docs/devnet/run_314_*/` evidence dir), moving this row **Yellow →
Green** for scope, still without live production validator-set mutation, epoch
transition, MainNet enablement, or C4/C5 closure.
