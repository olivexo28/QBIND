# QBIND DevNet Evidence — Run 347

Source/test **live epoch-transition authority-activation execution-preparation /
final-execution preflight** boundary implementation.

Run 347 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 348.

---

## 1. Exact verdict

**PASS — Run 347 source/test live epoch-transition authority-activation
execution-preparation / final-execution preflight boundary implemented.**

A new narrow source/test boundary consumes a verified Run 345/346 non-mutating
live epoch-transition **authority-activation authorization / final-execution
readiness decision** (the accepted
`ProductionLiveEpochTransitionAuthorityActivationAuthorizationDecision` output
that `is_accept()` and carries
`Some(authority_activation_authorization_artifact)`) and produces a typed,
deterministic, policy-gated **live authority-activation execution-preparation /
final-execution preflight artifact** that describes exactly what a future live
production authority-activation / final-execution executor (Run 348+ / release)
would re-verify, together with the exact future-executor preconditions and
postconditions. Default posture is `Disabled` / fail-closed.

Despite the name, Run 347 **does not** write a production authority-activation
authorization record, post-completion attestation record, activation-readiness
record, authority-lifecycle-completion record, final-settlement record,
settlement record, settlement-finalization record, settlement-execution record,
publication record, external-publication record, durable-audit-publication
record, audit-ledger commitment, audit-ledger record, audit-finalization record,
audit seal, audit record, receipt record, durable replay record, final-execution
record, authority marker, trust-bundle sequence file, or any runtime state. It
produces **only** a typed artifact and may, on a source/test-bounded path, mutate
**only** an explicit caller-owned in-memory
`LiveEpochTransitionAuthorityActivationExecutionPreparationFixtureState`. It
**does not** wire into production runtime. It **does not** add a public CLI flag.
It **does not** enable MainNet. It **does not** apply a live production
validator-set change. It **does not** perform a production epoch transition. It
**does not** commit or finalize production runtime state. It **does not** call
`BasicHotStuffEngine::transition_to_epoch` on production runtime state. It **does
not** write `meta:current_epoch`. It **does not** inject a `PAYLOAD_KIND_RECONFIG`
block. It mutates no production consensus validator state, epoch counters,
`LivePqcTrustState`, trust-bundle sequence files, authority markers, or sessions.
It calls neither Run 70 nor any runtime wiring. Production and MainNet
authority-activation-execution-preparation / final-execution-preflight kinds are
reachable but fail closed as unavailable. MainNet remains refused. Full C4
remains OPEN. C5 remains OPEN.

The live epoch-transition authority-activation execution-preparation /
final-execution preflight boundary matrix row moves **Red → Yellow**
(source/test implementation landed; release-binary evidence pending Run 348). It
is **not** marked Green. No release-binary evidence, live production
validator-set mutation, production epoch transition, production
commit/finalization, production receipt/audit write, production audit seal,
production audit-finalization write, production audit-ledger commitment,
durable-audit-publication write, durable replay write, settlement,
settlement-finalization, settlement-execution, final settlement,
authority-lifecycle completion, activation-readiness write,
post-completion-attestation publication, authority-activation authorization,
authority activation, final-execution readiness write, publication, external
publication, final execution, MainNet readiness, C4 closure, or C5 closure is
claimed. The Run 345/346 authority-activation authorization / final-execution
readiness row remains Green-for-scope only and is not reinterpreted; all other
prior Green-for-scope rows are unchanged.

---

## 2. Files changed

Added:

* `crates/qbind-node/src/pqc_production_live_epoch_transition_authority_activation_execution_preparation.rs`
  — the Run 347 boundary module (source).
* `crates/qbind-node/tests/run_347_production_live_epoch_transition_authority_activation_execution_preparation_tests.rs`
  — the Run 347 test target (732 tests total in the target; 175 new
  authority-activation-execution-preparation source/test cases — 143 self-layer
  cases appended after the verbatim Run 345 predecessor test body plus 32
  supplemental Run 347 boundary cases).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_347.md` — this evidence file.

Modified (narrow):

* `crates/qbind-node/src/lib.rs` — registered
  `pub mod pqc_production_live_epoch_transition_authority_activation_execution_preparation;`
  with a source/test-only scope comment. No runtime wiring, no CLI flag.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — header/current-status area
  updated to "as of Run 347"; added a Red → Yellow matrix row and narrative for
  the authority-activation execution-preparation / final-execution preflight
  boundary; preserved the Run 345/346 row as Green-for-scope only.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_346.md` — Run 346 doc-hygiene cleanup
  (section 16 row name; section 17 next-step heading/content). No Run 346
  hashes, helper counts, S1–S6 findings, or test results were altered.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — narrow Run 347 note.
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — narrow
  Run 347 note.
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` — narrow Run 347
  note.
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 347 note.
* `docs/whitepaper/contradiction.md` — narrow Run 347 note.

Non-goals honored: no runtime wiring, no CLI flag, no MainNet enablement, no
mutation of production state, no release-binary claim.

---

## 3. Boundary design summary

The boundary follows the established Run N pattern: a policy-gated executor that
accepts **only** a verified predecessor decision and emits a typed,
deterministic, non-mutating artifact plus a fail-closed outcome taxonomy.

* Executor policy:
  `ProductionLiveEpochTransitionAuthorityActivationExecutionPreparationExecutorPolicy`
  with the default variant `Disabled` (refuses every request before any
  binding). Other variants
  (`AllowSourceTestLiveEpochTransitionAuthorityActivationExecutionPreparation`,
  `RequireProductionLiveEpochTransitionAuthorityActivationExecutionPreparation`,
  and the MainNet production policy) are reachable but the production / MainNet
  policies fail closed as unavailable.
* Accepted authority source:
  `LiveEpochTransitionAuthorityActivationExecutionPreparationAuthoritySource::VerifiedAuthorityActivationAuthorizationDecision`
  carrying a Run 345/346
  `ProductionLiveEpochTransitionAuthorityActivationAuthorizationDecision` that
  `is_accept()` **and** carries
  `Some(authority_activation_authorization_artifact)`. Every other
  authority-source variant (missing / unverified / accepted-without-artifact /
  every lower-layer decision-alone / fixture-only / local-operator /
  peer-majority / custody-only / RemoteSigner-only / attestation-only /
  arbitrary-bytes) is rejected with a precise fail-closed outcome.
* Output: a typed
  `ProductionLiveEpochTransitionAuthorityActivationExecutionPreparationArtifact`
  with deterministic `authority_activation_execution_preparation_id`,
  `request_id`, `authority_activation_execution_preparation_digest`,
  `content_digest()`, and `transcript_digest`, bound to the full re-exposed
  predecessor chain window.
* Domain separation tags are the Run 347 family
  `QBIND:347-epoch-transition-authority-activation-execution-preparation-*:v1`
  (`-id`, `-intent`, `-request`, `-transcript`).
* Composition: the boundary composes the real
  Run 303/304 → … → Run 345/346 accept chain via the predecessor decision;
  it never bypasses any layer.

---

## 4. Policy / kind / authority-activation-execution-preparation taxonomy

* **Policy** (`…ExecutorPolicy`): `Disabled` (default, fail-closed),
  `AllowSourceTestLiveEpochTransitionAuthorityActivationExecutionPreparation`
  (DevNet/TestNet source/test only),
  `RequireProductionLiveEpochTransitionAuthorityActivationExecutionPreparation`
  (reachable, fails closed — no production prerequisites wired), and the MainNet
  production policy (reachable, fails closed — no MainNet authority).
* **Kind** (`LiveEpochTransitionAuthorityActivationExecutionPreparationKind`): the
  fixed staged-application window —
  `StageApplyNoOpAlreadySynchronized`, `StageApplyValidatorAdd`,
  `StageApplyValidatorRemove`, `StageApplyValidatorMetadataUpdate`,
  `StageApplyValidatorIdentityRotation`, `StageApplyValidatorRetirement`,
  `StageApplyEmergencyValidatorRemoval`,
  `StageApplyAuthoritySetSynchronization`, `StageApplyBulkValidatorSetRotation`,
  and the reserved `UnsupportedStagedApplication`. Each kind reports
  `is_non_mutating() == true`; `from_staged_application_kind()` maps the
  consumed Run 345/346 kind; `is_unsupported()` flags the reserved kind.
* **Authority source**
  (`LiveEpochTransitionAuthorityActivationExecutionPreparationAuthoritySource`):
  one accepted variant (`VerifiedAuthorityActivationAuthorizationDecision`) plus
  the full set of rejected non-authority variants enumerated in §3 and §8.
* **Replay set**
  (`LiveEpochTransitionAuthorityActivationExecutionPreparationReplaySet`):
  deterministic replay / idempotency window used by the recovery path.

---

## 5. Run 345/346 authority-activation-authorization artifact binding

The executor accepts only a verified Run 345/346 authority-activation
authorization decision and binds, into the produced authority-activation
execution-preparation / final-execution preflight artifact and its transcript,
the consumed decision's `authority_activation_authorization_id`, `request_id`,
content(authority-activation-authorization) digest, `transcript_digest`, and
authority-activation-authorization nonce, plus the full re-exposed deep window
carried forward from the predecessor chain: post-completion-attestation,
final-settlement-completion, settlement-execution, commit-authorization,
mutation-execution, execution-preparation, runtime-handoff, guarded-mutation, and
staged-application decision id/request/artifact(or intent)/content/transcript
digests and nonces; the authorization / application / rotation / governance /
validator-set tuple; the epoch-transition target; validator-set
current/proposed/delta digests and epoch/version; and quorum/threshold and
custody/attestation/durable-replay bindings where represented. An explicit
authority-activation-authorization-decision-integrity check rejects any tampered
or mismatched predecessor decision.

---

## 6. Live authority-activation execution-preparation / final-execution preflight artifact model

The produced artifact is a **description of future work**, not an action. It
encodes the exact future production authority-activation / final-execution
preconditions and postconditions — expected previous authority-activation
authorization / post-completion-attestation / settlement-execution /
settlement-preparation / external-publication / durable-audit-publication /
audit-ledger-commitment / durable-audit-finalization / post-commit-audit artifact
digests; resulting set digest + epoch/version; target consensus epoch; the
relevant domain separators; and the required governance epoch / authority
sequence / replay window / no-prior-activation-readiness /
no-prior-authority-activation-authorization /
no-prior-authority-activation-execution-preparation / no-prior-final-execution
markers and runtime-handle / durable-replay / audit-sink / audit-ledger /
publication-sink / external-publication-sink / settlement-sink /
settlement-finalization-sink / final-settlement-sink /
authority-lifecycle-completion-sink / activation-readiness-sink /
authority-activation-authorization-sink / authority-activation-sink /
final-execution-sink availability requirements — **none of which are written**.
All digests (`authority_activation_execution_preparation_digest`,
`content_digest()`, `request` and `transcript` digests) are deterministic
functions of the bound inputs.

---

## 7. Accepted source/test evidence

Under `AllowSourceTestLiveEpochTransitionAuthorityActivationExecutionPreparation`,
a verified Run 345/346 authority-activation authorization decision carrying
`Some(authority_activation_authorization_artifact)` yields an accepted outcome
with a typed authority-activation execution-preparation / final-execution
preflight artifact for each supported staged-application kind. The 143 new
appended self-layer tests plus 32 supplemental Run 347 boundary tests exercise
accepted-compatible construction, deterministic-digest stability, kind mapping,
and artifact-binding round trips. Full target: **732 tests pass** (see §13).

---

## 8. Rejection / fail-closed evidence

Rejected with precise fail-closed outcomes (no artifact produced): missing /
unverified / accepted-without-artifact authority-activation-authorization
decision; each lower-layer decision presented alone (post-completion-attestation,
final-settlement-completion, settlement-execution, settlement-execution-
preparation, settlement-preparation, external-publication,
durable-audit-publication, audit-ledger-commitment, durable-audit-finalization,
post-commit-audit, commit-receipt, commit-execution, commit-authorization,
mutation-execution, execution-preparation, runtime-handoff, guarded-mutation,
staged-application, live-application authorization, application, rotation plan,
governance execution intent, governance proof); fixture-only authority;
local-operator assertion; peer-majority assertion; custody-only evidence;
RemoteSigner-only evidence; attestation-only evidence; arbitrary validator-set
bytes; and a decision-integrity mismatch on any bound field (wrong id /
request-id / content / transcript / nonce / validator-set epoch / version / delta
digest, etc.). The `Disabled` default refuses before any binding.

---

## 9. MainNet refusal evidence

The MainNet production policy is reachable but fails closed as unavailable: no
MainNet production authority criteria are wired, so a MainNet request is refused
rather than served. The boundary does not enable MainNet, does not add a CLI
flag, and does not wire itself into the production binary.

---

## 10. Replay / idempotency evidence

The recovery path uses a deterministic
`LiveEpochTransitionAuthorityActivationExecutionPreparationReplaySet` so that a
repeated request with identical bound inputs is idempotent (same
`authority_activation_execution_preparation_id` / digests, no duplicate side
effects), and a recovery outcome is produced without re-mutating any state.
Replay / idempotency / recovery tests are included in the appended cases.

---

## 11. Fixture-state evidence

The only mutable state the boundary can touch is an explicit caller-owned
in-memory
`LiveEpochTransitionAuthorityActivationExecutionPreparationFixtureState`, used
solely by tests and explicitly distinct from production runtime state. Applying
an accepted artifact to this fixture updates only the in-memory fixture; it
writes no runtime files and touches no production state.

---

## 12. Non-mutation evidence

Every `Kind::is_non_mutating()` returns `true`. The boundary never applies a live
production validator-set change; never mutates a live validator set, consensus
state, epoch counter, or `LivePqcTrustState`; never calls
`BasicHotStuffEngine::transition_to_epoch` on production runtime state; never
writes `meta:current_epoch`; never injects a `PAYLOAD_KIND_RECONFIG` block; does
not call Run 070; and writes no runtime files, receipts, audit records, audit
seals, audit-finalization/audit-ledger/commitment records,
durable-audit-publication or durable-replay records, settlement /
settlement-finalization / settlement-execution / final-settlement records,
authority-lifecycle-completion / activation-readiness /
post-completion-attestation / authority-activation-authorization /
authority-activation-execution-preparation / final-execution-readiness records,
publication / external-publication records, final-execution records, authority
markers, or trust-bundle sequence files.

---

## 13. Tests run

All commands run with `cargo` on the workspace. Results (actual, this run):

* `cargo build -p qbind-node --lib` — **OK** (compiles clean).
* `cargo test -p qbind-node --test run_347_production_live_epoch_transition_authority_activation_execution_preparation_tests` — **ok, 732 passed; 0 failed**.
* `cargo test -p qbind-node --test run_345_production_live_epoch_transition_authority_activation_authorization_tests` — **ok, 700 passed; 0 failed**.
* `cargo test -p qbind-node --test run_343_production_live_epoch_transition_authority_lifecycle_post_completion_attestation_tests` — **ok, 700 passed; 0 failed**.
* `cargo test -p qbind-node --test run_341_production_live_epoch_transition_final_settlement_completion_tests` — **ok, 525 passed; 0 failed**.
* `cargo test -p qbind-node --test run_339_production_live_epoch_transition_settlement_execution_tests` — **ok, 350 passed; 0 failed**.
* `cargo test -p qbind-node --test run_337_production_live_epoch_transition_settlement_execution_preparation_tests` — **ok, 175 passed; 0 failed**.
* `cargo test -p qbind-node --test run_335_production_live_epoch_transition_settlement_preparation_tests` — **ok, 175 passed; 0 failed**.
* `cargo test -p qbind-node --test run_333_production_live_epoch_transition_external_publication_tests` — **ok, 175 passed; 0 failed**.
* `cargo test -p qbind-node --test run_331_production_live_epoch_transition_durable_audit_publication_tests` — **ok, 175 passed; 0 failed**.
* `cargo test -p qbind-node --test run_329_production_live_epoch_transition_audit_ledger_commitment_tests` — **ok, 175 passed; 0 failed**.
* `cargo test -p qbind-node --test run_327_production_live_epoch_transition_durable_audit_finalization_tests` — **ok, 175 passed; 0 failed**.
* `cargo test -p qbind-node --test run_325_production_live_epoch_transition_post_commit_audit_tests` — **ok, 175 passed; 0 failed**.
* `cargo test -p qbind-node --test run_323_production_live_epoch_transition_commit_receipt_tests` — **ok, 175 passed; 0 failed**.
* `cargo test -p qbind-node --test run_321_production_live_epoch_transition_commit_execution_tests` — **ok, 167 passed; 0 failed**.
* `cargo test -p qbind-node --test run_319_production_live_epoch_transition_commit_authorization_tests` — **ok, 158 passed; 0 failed**.
* `cargo test -p qbind-node --test run_317_production_live_epoch_transition_mutation_execution_tests` — **ok, 149 passed; 0 failed**.
* `cargo test -p qbind-node --test run_315_production_live_epoch_transition_execution_preparation_tests` — **ok, 139 passed; 0 failed**.
* `cargo test -p qbind-node --test run_313_production_epoch_transition_runtime_handoff_tests` — **ok, 151 passed; 0 failed**.
* `cargo test -p qbind-node --test run_311_production_guarded_epoch_transition_mutation_executor_tests` — **ok, 124 passed; 0 failed**.
* `cargo test -p qbind-node --test run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests` — **ok, 121 passed; 0 failed**.
* `cargo test -p qbind-node --test run_307_production_live_validator_set_application_authorization_tests` — **ok, 135 passed; 0 failed**.
* `cargo test -p qbind-node --test run_305_production_validator_set_rotation_application_executor_tests` — **ok, 126 passed; 0 failed**.
* `cargo test -p qbind-node --test run_303_production_validator_set_rotation_intent_tests` — **ok, 131 passed; 0 failed**.
* `cargo test -p qbind-node --test run_301_production_governance_execution_engine_tests` — **ok, 117 passed; 0 failed**.
* `cargo test -p qbind-node --lib` — **ok, 1377 passed; 0 failed**.

Target-name substitutions: none. Every required target name resolved to a real
target. The Run 347 target was created at the canonical name
`run_347_production_live_epoch_transition_authority_activation_execution_preparation_tests`
to match the required test command exactly. The Run 347 target carries **732
tests total** (well above the required ≥175), of which 175 are the new
authority-activation-execution-preparation / final-execution-preflight
boundary cases (143 self-layer cases appended after the verbatim predecessor
chain builders plus 32 supplemental Run 347 boundary cases).

---

## 14. Security scans

* **Secret scanning:** run over the changed files (new source module, new test
  file, `lib.rs`, and the modified docs). No secrets detected. No API keys,
  tokens, or credentials are present in any changed file.
* **CodeQL:** run via the repository CodeQL checker over the Run 347 changes.
  The Run 347 changes add new Rust source and tests, so CodeQL was requested
  (non-trivial). **Result: 0 alerts reported; the Rust analysis was skipped
  because the CodeQL database size is too large.** Because CodeQL analysis did not
  complete, **no CodeQL coverage is claimed** for Run 347. This is the exact
  recorded reason. Secret scanning did complete and reported no secrets.

---

## 15. C4/C5 matrix status

The live epoch-transition authority-activation execution-preparation /
final-execution preflight boundary row moves **Red → Yellow** (source/test
implementation landed; release-binary evidence pending Run 348). It is **not**
Green. The Run 345/346 authority-activation authorization / final-execution
readiness row remains **Green-for-scope only** and is not reinterpreted. All
other prior Green-for-scope rows are unchanged. Full C4 remains **OPEN**; C5
remains **OPEN**.

---

## 16. Honest limitations

Run 347 is source/test only. It provides no release-binary evidence (deferred to
Run 348), no production runtime wiring, no CLI flag, no MainNet enablement, and
no production side effects of any kind. Production and MainNet
authority-activation-execution-preparation / final-execution-preflight kinds are
reachable but fail closed as unavailable. The produced artifact is a typed
description of future work; nothing is activated, executed, completed, published,
settled, or finalized in production. The boundary does not prove live production
validator-set mutation, production epoch transition, production
commit/finalization, settlement, authority-lifecycle completion, authority
activation, final execution, MainNet readiness, C4 closure, or C5 closure.

---

## 17. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. No closure is claimed. MainNet
remains refused.

---

## 18. Suggested Run 348 next step

Add the Run 348 **release-binary evidence** for this boundary: a release-mode
example helper and a devnet script that exercise the real Run 347 executor in
release mode across accepted-compatible / rejection-fail-closed /
MainNet-authority-policy / replay-recovery-idempotency / fixture-state /
non-mutation / reachability-taxonomy tables, composing the real
Run 303/304 → … → Run 345/346 accept chain, with a
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_348.md` evidence file. Only upon landing
that release-binary evidence should the authority-activation execution-preparation
/ final-execution preflight matrix row move **Yellow → Green-for-scope**. Run 348
must remain non-mutating, add no CLI flag, wire nothing into production runtime,
and keep MainNet refused.