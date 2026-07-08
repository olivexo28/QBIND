# QBIND DevNet Evidence — Run 309

Source/test **staged live validator-set / epoch-transition application executor**
boundary implementation.

Run 309 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 310.

---

## 1. Exact verdict

**PASS — Run 309 source/test staged live validator-set / epoch-transition
application executor boundary implemented.**

A new narrow source/test boundary consumes a verified Run 307/308 non-mutating
live validator-set application **authorization decision** (the accepted
`ProductionLiveValidatorSetApplicationAuthorizationDecision` output that
`is_accept()` and carries `Some(authorization_intent)`) and produces a typed,
deterministic, policy-gated, **non-mutating staged epoch-transition application
record** describing what a future mutating epoch-transition executor (Run 310+)
would apply. Default posture is `Disabled` / fail-closed.

This boundary produces **only a staged epoch-transition application record**. It
**does not** apply a live validator-set change, **does not** call
`BasicHotStuffEngine::transition_to_epoch`, **does not** write
`meta:current_epoch`, and **does not** inject a `PAYLOAD_KIND_RECONFIG` block. It
mutates no consensus validator state, epoch counters, `LivePqcTrustState`,
trust-bundle sequence files, authority markers, sessions, settlement, or
publication. MainNet remains refused. Full C4 remains OPEN. C5 remains OPEN.

The staged live validator-set / epoch-transition application executor matrix row
moves **Red → Yellow** (source/test implementation landed; release-binary
evidence pending Run 310). It is **not** marked Green. No release-binary
evidence, live mutation, epoch transition, MainNet readiness, C4 closure, or C5
closure is claimed. The pre-existing Run 307/308 live validator-set application
authorization row and Run 305/306 rotation application row stay unchanged.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_staged_live_validator_set_epoch_transition_application_executor.rs` — boundary module (committed prior in this branch).
* `crates/qbind-node/tests/run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests.rs` — 121 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_309.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_staged_live_validator_set_epoch_transition_application_executor;` (committed prior in this branch).
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — added a new staged live validator-set / epoch-transition application executor row Red → Yellow; refreshed status line; added Run 309 changelog entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/whitepaper/contradiction.md` — narrow Run 309 changelog entries.

---

## 3. Boundary design summary

`ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor` takes:

* a `ProductionStagedLiveValidatorSetEpochTransitionApplicationRequest` (a
  `StagedLiveValidatorSetEpochTransitionApplicationAuthoritySource`, an explicit
  proposed epoch-transition target, a staged-application nonce, plus optional
  custody / attestation / durable-replay bindings),
* `ProductionStagedLiveValidatorSetEpochTransitionApplicationInputs`
  (operator-trusted expected values, trust domain, evidence requirements,
  replay/freshness anchors), and
* a `StagedLiveValidatorSetEpochTransitionApplicationReplaySet`.

`evaluate_staged_live_validator_set_epoch_transition_application` returns a
`ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision` carrying a
typed `ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome`, a
`staged_application_id`, a deterministic `request_id`, an optional
`ProductionStagedLiveValidatorSetEpochTransitionApplicationRecord`, an intent
digest, and a transcript digest.

`recover_staged_live_validator_set_epoch_transition_application_window` provides
non-mutating idempotency/recovery over a prepared staged-application window.

---

## 4. Policy / kind / staged-record taxonomy

**Policy** (`ProductionStagedLiveValidatorSetEpochTransitionApplicationPolicy`):
`Disabled` (default, fail-closed),
`AllowSourceTestStagedLiveValidatorSetEpochTransitionApplication`
(DevNet/TestNet source/test),
`RequireProductionStagedLiveValidatorSetEpochTransitionApplication`
(reachable, fails closed — no production authority wired),
`MainnetProductionStagedLiveValidatorSetEpochTransitionApplicationRequired`
(reachable, fails closed — no MainNet authority wired).

**Kind** (`…ApplicationKind`): `Disabled` (inert default),
`SourceTestStagedLiveValidatorSetEpochTransitionApplication` (real source/test
construction), `ProductionStagedLiveValidatorSetEpochTransitionApplication`
(reserved, fail-closed in Run 309).

**Staged record kind** (`StagedLiveValidatorSetEpochTransitionApplicationKind`):
`StageApplyNoOpAlreadySynchronized`, `StageApplyValidatorAdd`,
`StageApplyValidatorRemove`, `StageApplyValidatorMetadataUpdate`,
`StageApplyValidatorIdentityRotation`, `StageApplyValidatorRetirement`,
`StageApplyEmergencyValidatorRemoval`, `StageApplyAuthoritySetSynchronization`,
`StageApplyBulkValidatorSetRotation`, and the reserved
`UnsupportedStagedApplication`.
`StagedLiveValidatorSetEpochTransitionApplicationKind::from_authorization_kind`
maps each Run 307/308 `LiveValidatorSetApplicationAuthorizationKind` to its
staged counterpart, with `UnsupportedAuthorization → UnsupportedStagedApplication`.

---

## 5. Run 307/308 authorization binding

The only accepted authority source is
`VerifiedLiveApplicationAuthorization { decision }` where the Run 307/308
`ProductionLiveValidatorSetApplicationAuthorizationDecision` `is_accept()` **and**
carries `Some(authorization_intent)`. The bound authorization-decision
transcript (`authorization_id`, `request_id`, `intent_digest`,
`transcript_digest`) must equal the operator-trusted expected values, and the
carried authorization intent must reproduce its digest
(`intent.intent_digest() == decision.intent_digest`) or the boundary returns
`AuthorizationDecisionIntegrityMismatch`.

Every other source
(`MissingLiveApplicationAuthorization`,
`UnverifiedLiveApplicationAuthorization`,
`AcceptedAuthorizationWithoutAuthorizationIntent`,
`ApplicationDecisionWithoutLiveApplicationAuthorization`,
`RotationPlanWithoutLiveApplicationAuthorization`,
`GovernanceExecutionIntentWithoutLiveApplicationAuthorization`,
`GovernanceProofWithoutLiveApplicationAuthorization`, `LocalOperatorAssertion`,
`PeerMajorityAssertion`, `CustodyOnlyEvidence`, `RemoteSignerOnlyEvidence`,
`CustodyAttestationOnlyEvidence`, `FixtureOnlyLiveApplicationAuthorization`,
`ArbitraryValidatorSetBytes`) is rejected with a precise fail-closed outcome.

The re-exposed Run 301/303/305/307 tuple (authorization/application policy ids,
environment, chain, genesis, authority root, governance domain/epoch/proposal,
governance-execution ids/digests, rotation ids/digests, lifecycle/rotation
actions, authority sequence, quorum, threshold, current/proposed/delta validator
set digests, validator-set epoch/version, proposed count, rotation nonce,
application decision/request ids and digests, application & live-application
nonces, epoch-transition target) is bound against operator-trusted expected
values.

---

## 6. Staged epoch-transition application record model

On accept the boundary emits a
`ProductionStagedLiveValidatorSetEpochTransitionApplicationRecord` that
re-exposes the full authorization/application/rotation/governance tuple, the
epoch-transition target, the live-application and staged-application nonces, the
bound authorization-decision authority tuple, and any represented custody /
attestation / durable-replay evidence. Its `intent_digest()` is a deterministic
domain-separated SHA3-256 hex digest. The record **describes** a future
epoch-transition application; it is **never applied** by this boundary.

---

## 7. Accepted source/test evidence

For each of the nine staged-record scenarios (add, remove, metadata update,
no-op already-synchronized, identity rotation, retirement, emergency removal,
authority-set synchronization, bulk rotation) across DevNet and TestNet, the
boundary accepts and emits the expected `staged_kind`, environment, epoch target
(≥ current epoch), and staged-application nonce, with a matching non-mutating
record. Accept is deterministic under re-evaluation (identical decision and
record intent digest). Matching represented custody evidence is accepted.

---

## 8. Rejection / fail-closed evidence

All fifteen non-authority / unverified / no-intent authority sources are
rejected with precise outcomes. Wrong environment / chain / genesis / authority
root; wrong governance domain / epoch / proposal / execution ids / intent
digest; wrong rotation ids / transcript / plan digest; wrong lifecycle / rotation
action; wrong authority sequence; wrong quorum / threshold; wrong current /
proposed / delta validator-set digests; wrong validator-set epoch / version;
wrong proposed validator count; wrong rotation nonce; wrong application decision
/ request / intent-digest / transcript; wrong authorization decision / request /
intent-digest / transcript; authorization integrity mismatch; wrong
epoch-transition target (inputs and request); wrong application nonce; wrong
live-application nonce; and required-but-missing / mismatched custody,
attestation, and durable-replay evidence each fail closed with the corresponding
typed outcome and no record.

---

## 9. MainNet refusal evidence

A MainNet trust domain (or MainNet binding environment) is refused with
`MainNetRefused` under the source/test policy and
`MainNetProductionStagedLiveValidatorSetEpochTransitionApplicationUnavailable`
under the MainNet production policy. Refusal is non-mutating and record-less.

---

## 10. Replay / idempotency evidence

A persisted staged-application replay id (equal to the decision `request_id`)
causes `StagedApplicationReplayRejected` with no record. Stale governance epoch,
authority sequence, validator-set epoch, and validator-set version each fail
closed. The recovery window returns `NoPriorStagedApplicationWindow` (clean),
`IdempotentReplayObserved` for a byte-identical prior record in the same window,
`RecoveryDisabled` under `Disabled`, and treats a differing nonce as an
independent window — all non-mutating.

---

## 11. Non-mutation evidence

Every outcome is non-mutating (`outcome.is_non_mutating()` and every recovery
outcome `is_non_mutating()`). Accepted decisions only
`authorizes_future_mutation_only()` (they carry a prepared record but apply
nothing). Rejections and MainNet refusal carry no record. This boundary does not
apply a live validator-set change, does not call
`BasicHotStuffEngine::transition_to_epoch`, does not write `meta:current_epoch`,
does not inject `PAYLOAD_KIND_RECONFIG`, and mutates no consensus validator
state, epoch counters, `LivePqcTrustState`, trust-bundle sequence files,
authority markers, sessions, settlement, or publication.

---

## 12. Tests run

* `cargo build -p qbind-node --lib` — **Finished (pass).**
* `cargo test -p qbind-node --test run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests` — **121 passed; 0 failed.**
* `cargo test -p qbind-node --test run_307_production_live_validator_set_application_authorization_tests` — **135 passed; 0 failed.**
* `cargo test -p qbind-node --test run_305_production_validator_set_rotation_application_executor_tests` — **126 passed; 0 failed.**
* `cargo test -p qbind-node --test run_303_production_validator_set_rotation_intent_tests` — **131 passed; 0 failed.**
* `cargo test -p qbind-node --test run_301_production_governance_execution_engine_tests` — **117 passed; 0 failed.**
* `cargo test -p qbind-node --lib` — **1377 passed; 0 failed.**

No target-name substitutions were required.

---

## 13. Security scans

* Secret scanning over changed files — **no secrets detected.**
* CodeQL — see the final report for exact status.

---

## 14. C4 / C5 matrix status

The staged live validator-set / epoch-transition application executor row moves
**Red → Yellow** (source/test implementation landed; tests and evidence pass;
release-binary evidence pending Run 310). It is **not** Green. Full C4 remains
**OPEN**. C5 remains **OPEN**.

---

## 15. Honest limitations

* Run 309 is source/test only; it is **not** release-binary evidence.
* Release-binary evidence is deferred to Run 310.
* The boundary produces **only a staged epoch-transition application record**;
  it does **not** apply a live validator-set change.
* It does **not** call `BasicHotStuffEngine::transition_to_epoch`.
* It does **not** write `meta:current_epoch`.
* It does **not** inject `PAYLOAD_KIND_RECONFIG`.
* It mutates no consensus validator state, epoch counters, `LivePqcTrustState`,
  trust-bundle sequence files, authority markers, sessions, settlement, or
  publication.
* MainNet remains refused.
* Full C4 remains OPEN. C5 remains OPEN.

---

## 16. C4 / C5 status

Full C4: **OPEN.** C5: **OPEN.** No closure is claimed.

---

## 17. Suggested Run 310 next step

Produce Run 310 release-binary evidence for the Run 309 staged live
validator-set / epoch-transition application executor boundary (example helper +
devnet script + `docs/devnet/run_310_.../` archive), moving its C4/C5 matrix row
Yellow → Green for scope, without claiming live mutation, epoch transition,
MainNet readiness, or C4/C5 closure.