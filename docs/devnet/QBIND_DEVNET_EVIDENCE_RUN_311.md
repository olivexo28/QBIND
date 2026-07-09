# QBIND DevNet Evidence — Run 311

Source/test **guarded epoch-transition mutation executor** boundary
implementation.

Run 311 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 312.

---

## 1. Exact verdict

**PASS — Run 311 source/test guarded epoch-transition mutation executor
boundary implemented.**

A new narrow source/test boundary consumes a verified Run 309/310 non-mutating
staged live validator-set / epoch-transition application **decision** (the
accepted `ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision`
output that `is_accept()` and carries `Some(staged_application_record)`) and
produces a typed, deterministic, policy-gated **guarded mutation-execution
decision** carrying a prepared, non-mutating mutation-execution record that
describes what a future live mutating executor would apply. Default posture is
`Disabled` / fail-closed.

This boundary produces **only a prepared mutation-execution record** and may, on
a source/test-bounded path, mutate **only** an explicit caller-owned in-memory
`GuardedEpochTransitionFixtureLedger`. It **does not** apply a live validator-set
change to production state, **does not** transition a production consensus epoch,
**does not** call `BasicHotStuffEngine::transition_to_epoch`, **does not** write
`meta:current_epoch`, and **does not** inject a `PAYLOAD_KIND_RECONFIG` block. It
mutates no production consensus validator state, epoch counters,
`LivePqcTrustState`, trust-bundle sequence files, authority markers, sessions,
settlement, or publication. It calls neither Run 070 nor any runtime wiring, and
adds no CLI flag. MainNet remains refused. Full C4 remains OPEN. C5 remains OPEN.

The guarded epoch-transition mutation executor matrix row moves **Red → Yellow**
(source/test implementation landed; release-binary evidence pending Run 312). It
is **not** marked Green. No release-binary evidence, live mutation, epoch
transition, MainNet readiness, C4 closure, or C5 closure is claimed. Prior
Green-for-scope rows (Run 310 staged application executor, Run 308 live
application authorization, Run 306 rotation application, etc.) are unchanged and
not reinterpreted.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_guarded_epoch_transition_mutation_executor.rs` — boundary module.
* `crates/qbind-node/tests/run_311_production_guarded_epoch_transition_mutation_executor_tests.rs` — 124 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_311.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_guarded_epoch_transition_mutation_executor;`.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — added a new guarded epoch-transition mutation executor row Red → Yellow; refreshed status line; added Run 311 changelog entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/whitepaper/contradiction.md` — narrow Run 311 changelog entries.

---

## 3. Boundary design summary

`ProductionGuardedEpochTransitionMutationExecutor` takes:

* a `ProductionGuardedEpochTransitionMutationRequest` (a
  `GuardedEpochTransitionMutationAuthoritySource`, an explicit proposed
  epoch-transition target, a guarded-mutation nonce, plus optional custody /
  attestation / durable-replay bindings),
* `ProductionGuardedEpochTransitionMutationInputs` (operator-trusted expected
  values, trust domain, evidence requirements, replay/freshness anchors), and
* a `GuardedEpochTransitionMutationReplaySet`.

`evaluate_guarded_epoch_transition_mutation` returns a
`ProductionGuardedEpochTransitionMutationDecision` carrying a typed
`ProductionGuardedEpochTransitionMutationOutcome`, a `staged_application_id`, a
deterministic `request_id`, an optional
`ProductionGuardedEpochTransitionMutationRecord`, an intent digest, and a
transcript digest.

`recover_guarded_epoch_transition_mutation_window` provides non-mutating
idempotency/recovery over a prepared mutation-execution window.

`GuardedEpochTransitionFixtureLedger` is a plain in-memory, caller-owned struct
that is the *only* thing a positive path may mutate; its
`apply_prepared_execution` advances only its own in-memory epoch / version /
digest fields and is idempotent per execution id.

All digests are length-prefixed, domain-separated SHA3-256 (hex-encoded) via a
module-local `hash_field` helper; `Debug` output is never used as canonical
bytes and no wall-clock is read (freshness uses explicit
`min_governance_epoch` / `min_validator_set_epoch` / `min_validator_set_version`
/ `persisted_sequence` anchors).

---

## 4. Policy / kind / execution taxonomy

**Policy** (`ProductionGuardedEpochTransitionMutationExecutorPolicy`):
`Disabled` (default, fail-closed),
`AllowSourceTestGuardedEpochTransitionMutation` (DevNet/TestNet source/test),
`RequireProductionGuardedEpochTransitionMutation` (reachable, fails closed — no
production authority wired),
`MainnetProductionGuardedEpochTransitionMutationRequired` (reachable, fails
closed — no MainNet authority wired).

**Kind** (`ProductionGuardedEpochTransitionMutationExecutorKind`): `Disabled`
(inert default), `SourceTestGuardedEpochTransitionMutation` (real source/test
construction), `ProductionGuardedEpochTransitionMutation` (reserved production
kind, fail-closed as unavailable). `MainNet` availability is refused by the
MainNet gate rather than a distinct kind.

**Mutation kind** (`GuardedEpochTransitionMutationKind`): one-to-one with the
consumed Run 309/310 `StagedLiveValidatorSetEpochTransitionApplicationKind`
(StageApply{NoOp,ValidatorAdd,ValidatorRemove,ValidatorMetadataUpdate,
ValidatorIdentityRotation,ValidatorRetirement,EmergencyValidatorRemoval,
AuthoritySetSynchronization,BulkValidatorSetRotation}), plus the reserved
`UnsupportedStagedApplication`.

Other taxonomy: `ProductionGuardedEpochTransitionMutationRequest`,
`ProductionGuardedEpochTransitionMutationInputs`,
`ProductionGuardedEpochTransitionMutationDecision`,
`ProductionGuardedEpochTransitionMutationRecord`,
`ProductionGuardedEpochTransitionMutationOutcome`,
`ProductionGuardedEpochTransitionMutationRecoveryOutcome`,
`GuardedEpochTransitionMutationReplaySet`,
`GuardedEpochTransitionFixtureLedger`, and named digest helpers for
request / record (intent) / transcript.

---

## 5. Run 309/310 staged-record binding

The **only** accepted authority source is
`GuardedEpochTransitionMutationAuthoritySource::VerifiedStagedApplicationDecision`
carrying a Run 309/310 staged decision that `is_accept()` and carries
`Some(staged_application_record)`. The executor binds:

* the consumed staged decision transcript — `staged_application_id`,
  `request_id`, `intent_digest`, `transcript_digest`, plus a re-derivation
  integrity check (`record.intent_digest() == decision.intent_digest`);
* the re-exposed live-authorization decision tuple (`authorization_decision_id`,
  `authorization_request_id`, `authorization_intent_digest`,
  `authorization_transcript_digest`) and authorization policy id;
* the re-exposed Run 305/306 application-decision tuple and application policy
  id, plus application / live-application / staged-application nonces;
* environment, chain id, genesis hash, authority root fingerprint + suite id;
* governance domain / epoch / proposal / execution decision-request-intent
  digests, quorum, threshold, lifecycle + rotation actions, authority-domain
  sequence;
* rotation decision / request / transcript / plan digests;
* current / proposed / delta validator-set digests, validator-set epoch /
  version, proposed validator count, rotation nonce;
* the explicit epoch-transition target (matched against both the operator-trusted
  input and the consumed record);
* custody / attestation / durable-replay bindings where represented.

Any divergence yields a precise typed fail-closed outcome; every non-authority
source (application-decision-alone, rotation-plan-alone, governance-execution-
intent-alone, governance-proof-alone, fixture-only, local-operator, peer-
majority, custody-only, RemoteSigner-only, custody-attestation-only, arbitrary
validator-set bytes, missing/unverified/record-less staged decision) is rejected.

---

## 6. Guarded mutation-execution decision model

An accepted evaluation returns
`AcceptedSourceTestGuardedEpochTransitionMutation { staged_kind, environment,
epoch_transition_target, staged_application_nonce }` and a prepared
`ProductionGuardedEpochTransitionMutationRecord`. The decision exposes a
deterministic `staged_application_id`, `request_id`, `intent_digest`, and
`transcript_digest`. The record re-derives its own intent digest deterministically
across re-evaluations and binds the full staged-decision / authorization /
application / governance / rotation / validator-set / epoch-transition / nonce
evidence tuple plus the newly proposed `guarded_mutation_nonce`. The record is
non-mutating; a future live executor (Run 312+) is the only thing that could
apply it against production state.

---

## 7. Accepted source/test evidence

* `accept_all_scenarios_devnet` / `accept_all_scenarios_testnet` and the
  per-scenario `scenario_accept_*` / `scenario_testnet_accept_*` tests exercise
  all nine mutation kinds on DevNet and TestNet.
* `accept_binds_staged_decision_transcript`,
  `accept_reexposes_live_authorization_tuple`,
  `accept_reexposes_application_and_governance_tuple` verify the bound tuple.
* `accept_deterministic_digests_under_reevaluation`,
  `accept_record_intent_digest_matches_named_helper`,
  `accept_distinct_scenarios_have_distinct_digests`,
  `distinct_environments_yield_distinct_digests` verify determinism/uniqueness.

---

## 8. Rejection / fail-closed evidence

* Binding mismatches: staged-application id/request/intent/transcript/nonce,
  live-authorization id/request/intent/transcript/policy, application
  id/request/intent/transcript/policy, environment/chain/genesis/authority-root,
  governance domain/epoch/proposal/decision/request/intent, rotation
  ids/digests, lifecycle/rotation action, authority sequence, quorum/threshold,
  current/proposed/delta digests, validator-set epoch/version, proposed count,
  rotation nonce, epoch-transition target, application/live-application nonce.
* Authority-source rejections for all fourteen non-authority / unverified /
  record-less sources.

---

## 9. MainNet refusal evidence

* `reject_mainnet_trust_domain` → `MainNetRefused`.
* `reject_mainnet_policy_unavailable` /
  `reject_mainnet_policy_on_mainnet_domain_unavailable` →
  `MainNetProductionGuardedEpochTransitionMutationUnavailable`.
* `reject_production_policy_unavailable` →
  `ProductionGuardedEpochTransitionMutationUnavailable`.
* `reject_production_boundary_kind_unavailable` →
  `GuardedEpochTransitionMutationBoundaryUnavailable`.
* `reject_disabled_policy` → `Disabled`.

MainNet is refused absent complete production authority; the production and
MainNet policy/kind paths are reachable but fail closed as unavailable.

---

## 10. Replay / idempotency evidence

* `reject_replayed_staged_application` → `StagedApplicationReplayRejected` for a
  replayed internal execution id; `accept_when_replay_set_has_unrelated_id`
  stays accept.
* `recovery_clean_when_no_prior_window`,
  `recovery_idempotent_replay_observed`,
  `recovery_disabled_under_disabled_policy`,
  `recovery_independent_window_for_different_nonce`.
* Freshness: `reject_stale_governance_epoch`, `reject_stale_authority_sequence`,
  `reject_stale_validator_set_epoch`, `reject_stale_validator_set_version`.

---

## 11. Non-mutation evidence

* `invariant_all_outcomes_non_mutating` and the module invariant functions
  (`..._is_source_test_not_release_binary_evidence`, `..._mainnet_refused`,
  `..._is_non_mutating`, `..._never_falls_back`, `..._no_default_runtime_wiring`,
  `..._requires_verified_application_decision`).
* The only mutation performed on any path is against the caller-owned in-memory
  `GuardedEpochTransitionFixtureLedger` (`fixture_ledger_apply_advances_state`,
  `fixture_ledger_apply_is_idempotent`, `fixture_ledger_starts_unapplied`). No
  production consensus / epoch / trust state is touched.

---

## 12. Tests run

* `cargo build -p qbind-node --lib` — success.
* `cargo test -p qbind-node --test run_311_production_guarded_epoch_transition_mutation_executor_tests` — **124 passed**.
* `cargo test -p qbind-node --test run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests` — 121 passed.
* `cargo test -p qbind-node --test run_307_production_live_validator_set_application_authorization_tests` — 135 passed.
* `cargo test -p qbind-node --test run_305_production_validator_set_rotation_application_executor_tests` — 126 passed.
* `cargo test -p qbind-node --test run_303_production_validator_set_rotation_intent_tests` — 131 passed.
* `cargo test -p qbind-node --test run_301_production_governance_execution_engine_tests` — 117 passed.
* `cargo test -p qbind-node --lib` — 1377 passed.

No test target names required substitution.

---

## 13. Security scans

* **Secret scanning** — ran over the three changed source/test/lib files; **no
  secrets detected**.
* **CodeQL** — attempted via the automated checker for the `rust` language.
  Result: **analysis was skipped because the CodeQL database size is too
  large.** No CodeQL coverage is claimed for Run 311. The change is not trivial;
  the skip is due solely to database size, not classification. No failed or
  skipped CodeQL result is hidden.

---

## 14. C4/C5 matrix status

The guarded epoch-transition mutation executor row is added/moved **Red →
Yellow** in `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`. It is **not** Green.
Release-binary evidence is deferred to Run 312. No prior Green-for-scope row is
weakened or reinterpreted.

---

## 15. Honest limitations

* Source/test only; no release-binary evidence in Run 311.
* No production or MainNet authority is wired; those paths fail closed.
* The boundary never applies a live validator-set change, epoch transition, or
  trust-state mutation to production; only an in-memory test fixture ledger.
* No runtime wiring and no CLI flag are added.
* CodeQL did not run (database too large); no static-analysis coverage claimed.

---

## 16. C4/C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. Run 311 does not close, and does
not claim to close, either criterion, nor does it claim live validator-set
rotation, epoch transition, or MainNet readiness.

---

## 17. Suggested Run 312 next step

Capture **release-binary evidence** for the guarded epoch-transition mutation
executor boundary (example helper + devnet harness script + curated
`docs/devnet/run_312_*/` evidence dir), moving this row **Yellow → Green** for
scope, still without live production mutation, epoch transition, MainNet
enablement, or C4/C5 closure.