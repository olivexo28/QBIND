# QBIND DevNet Evidence — Run 327

Source/test **live epoch-transition durable-audit finalization / audit-ledger
preparation** boundary implementation.

Run 327 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 328.

---

## 1. Exact verdict

**PASS — Run 327 source/test live epoch-transition durable-audit finalization /
audit-ledger preparation boundary implemented.**

A new narrow source/test boundary consumes a verified Run 325/326 non-mutating
live epoch-transition **post-commit audit decision** (the accepted
`ProductionLiveEpochTransitionPostCommitAuditDecision` output that `is_accept()`
and carries `Some(post_commit_audit_artifact)`) and produces a typed,
deterministic, policy-gated **live durable-audit-finalization / audit-ledger-preparation
artifact** that describes exactly what a future live production audit-ledger /
audit-finalization step (Run 328+ / release) would perform, together with the
exact future-executor preconditions and postconditions. Default posture is
`Disabled` / fail-closed.

Despite the name, Run 327 **does not** write a production audit-ledger entry,
audit-finalization record, audit seal, receipt record, durable replay record,
settlement record, publication record, external-publication record, authority
marker, trust-bundle sequence file, or any runtime state. It produces **only** a
typed artifact and may, on a source/test-bounded path, mutate **only** an
explicit caller-owned in-memory
`LiveEpochTransitionDurableAuditFinalizationFixtureState`. It **does not** wire
into production runtime. It **does not** add a public CLI flag. It **does not**
enable MainNet. It **does not** apply a live production validator-set change. It
**does not** perform a production epoch transition. It **does not** commit or
finalize production runtime state. It **does not** call
`BasicHotStuffEngine::transition_to_epoch` on production runtime state. It **does
not** write `meta:current_epoch`. It **does not** inject a `PAYLOAD_KIND_RECONFIG`
block. It mutates no production consensus validator state, epoch counters,
`LivePqcTrustState`, trust-bundle sequence files, authority markers, or sessions.
It calls neither Run 070 nor any runtime wiring. Production and MainNet
durable-audit-finalization / audit-ledger kinds are reachable but fail closed as
unavailable. MainNet remains refused. Full C4 remains OPEN. C5 remains OPEN.

The live epoch-transition durable-audit finalization / audit-ledger preparation
boundary matrix row moves **Red → Yellow** (source/test implementation landed;
release-binary evidence pending Run 328). It is **not** marked Green. No
release-binary evidence, live production validator-set mutation, production epoch
transition, production commit/finalization, production receipt/audit write,
production audit seal, production audit-finalization write, durable replay write,
settlement, publication, external publication, MainNet readiness, C4 closure, or
C5 closure is claimed. Prior Green-for-scope rows (Run 326 post-commit-audit-seal
/ durable-audit-authorization release-binary, Run 324 commit-receipt
release-binary, Run 322 commit-execution release-binary, etc.) are unchanged and
not reinterpreted.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_live_epoch_transition_durable_audit_finalization.rs` — boundary module.
* `crates/qbind-node/tests/run_327_production_live_epoch_transition_durable_audit_finalization_tests.rs` — 175 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_327.md` — this evidence file.

Modified (narrowly):

* `crates/qbind-node/src/lib.rs` — registers the new module with a scope comment.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — adds the new Yellow matrix row and the Run 327 chronological entry; confirms the Run 325/326 post-commit-audit-seal / durable-audit-authorization boundary is Green-for-scope after Run 326.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
* `docs/whitepaper/contradiction.md`
* `docs/devnet/run_326_.../summary.txt` — docs-hygiene helper-hash label fix (see §14).

No production runtime code, CLI surface, or MainNet configuration is changed.

---

## 3. Boundary design summary

The boundary sits one rung above the Run 325/326 post-commit-audit boundary in
the non-mutating live epoch-transition authority ladder. It accepts **only** a
verified, accepted Run 325/326 post-commit-audit decision carrying
`Some(post_commit_audit_artifact)`, re-verifies the entire consumed artifact and
the full re-exposed ancestor tuple, and emits a typed durable-audit-finalization
/ audit-ledger-preparation artifact that encodes exactly what a future production
audit-ledger step must re-verify and perform. All digests are deterministic,
length-prefixed, and domain-separated; no `Debug` formatting or wall-clock
freshness is used.

The default policy is `Disabled` and fails closed **before** any binding or
artifact construction. The production and MainNet policies/kinds are reachable
but fail closed as unavailable. The only mutation any positive path performs is
against a caller-owned in-memory
`LiveEpochTransitionDurableAuditFinalizationFixtureState` used exclusively by
tests, explicitly distinct from production state.

---

## 4. Policy / kind / durable-audit-finalization taxonomy

* `ProductionLiveEpochTransitionDurableAuditFinalizationExecutorPolicy`
  * `Disabled` (default; fails closed)
  * `AllowSourceTestLiveEpochTransitionDurableAuditFinalization`
  * `RequireProductionLiveEpochTransitionDurableAuditFinalization`
  * `MainnetProductionLiveEpochTransitionDurableAuditFinalizationRequired`
* `ProductionLiveEpochTransitionDurableAuditFinalizationExecutorKind`
  * `Disabled`
  * `SourceTestLiveEpochTransitionDurableAuditFinalization`
  * `ProductionLiveEpochTransitionDurableAuditFinalizationUnavailable`
  * `MainNetLiveEpochTransitionDurableAuditFinalizationUnavailable`
* `ProductionLiveEpochTransitionDurableAuditFinalizationRequest`
* `ProductionLiveEpochTransitionDurableAuditFinalizationInputs`
* `ProductionLiveEpochTransitionDurableAuditFinalizationDecision`
* `ProductionLiveEpochTransitionDurableAuditFinalizationArtifact`
* `ProductionLiveEpochTransitionDurableAuditFinalizationOutcome`
* `ProductionLiveEpochTransitionDurableAuditFinalizationRecoveryOutcome`
* `LiveEpochTransitionDurableAuditFinalizationKind`
* `LiveEpochTransitionDurableAuditFinalizationAuthoritySource`
* `EmptyLiveEpochTransitionDurableAuditFinalizationReplaySet`
* `LiveEpochTransitionDurableAuditFinalizationFixtureState` (source/test only).

(Note: the module preserves the family's established `...ExecutorPolicy` /
`...ExecutorKind` naming used by the Run 305–325 ancestor modules; this is the
concrete realization of the task's suggested `...Policy` / `...Kind` taxonomy.)

---

## 5. Run 325/326 post-commit-audit artifact binding

The sole accepted authority source is
`LiveEpochTransitionDurableAuditFinalizationAuthoritySource::VerifiedPostCommitAuditDecision`
carrying an accepted `ProductionLiveEpochTransitionPostCommitAuditDecision` with
`Some(post_commit_audit_artifact)`. The inputs bind, and the executor
re-verifies: the post-commit-audit decision id/request-id/content-digest/
transcript-digest and post-commit-audit nonce; the re-exposed commit-receipt /
commit-authorization / mutation-execution / execution-preparation / runtime-handoff
decision tuples and nonces; the full re-exposed guarded-mutation /
staged-application / authorization / application / rotation / governance /
validator-set tuple; the epoch-transition target; the current/proposed/delta
validator-set digests; validator-set epoch/version; quorum/threshold; and
custody/attestation/durable-replay bindings where represented.

Accepted tests compose the real Run 303/304 → 305/306 → 307/308 → 309/310 →
311/312 → 313/314 → 315/316 → 317/318 → 319/320 → 321/322 → 323/324 → 325/326
accept chain, building a genuine accepted post-commit-audit decision (which
itself is built on a genuine accepted commit-receipt decision) before feeding it
into the Run 327 executor.

---

## 6. Live durable-audit finalization / audit-ledger-preparation artifact model

The artifact carries deterministic `durable_audit_finalization_id`,
`audit_request_id`, `durable_audit_finalization_digest`, `audit_content_digest`,
and `audit_transcript_digest`, and encodes the exact future production
audit-ledger / audit-finalization preconditions and postconditions: expected
previous post-commit-audit artifact digest; expected commit-receipt artifact
digest; expected commit-execution artifact digest; expected resulting
validator-set digest; expected resulting validator-set epoch/version; expected
target consensus epoch; expected durable replay domain; expected audit sink
domain; expected audit ledger domain; expected audit schema version; expected
audit-seal domain separator; expected audit-finalization domain separator;
required governance epoch; required authority sequence; required replay window;
required no-conflicting-commit marker; required no-prior-audit-seal marker;
required no-prior-audit-finalization marker; required production runtime handle
availability; required durable replay availability; required audit sink
availability; required audit ledger availability; and optional future
settlement/publication availability where represented (neither is written).

---

## 7. Accepted source/test evidence

`accept_all_scenarios_devnet` and `accept_all_scenarios_testnet` accept every
validator-set scenario (Add / Remove / Update / NoOp / Identity / Retire /
Emergency / AuthSync / Bulk) on DevNet and TestNet, asserting the emitted kind,
environment, epoch-transition target, and re-exposed post-commit-audit / guarded
/ staged nonces. Determinism tests confirm the id/request/content/transcript
digests are stable under re-evaluation.

---

## 8. Rejection / fail-closed evidence

The executor rejects, fail-closed with no artifact: missing/unverified
post-commit-audit decision; an accepted post-commit-audit decision without an
artifact; and each ancestor decision "alone" — commit-receipt, commit-execution,
commit-authorization, mutation-execution, execution-preparation, runtime-handoff,
guarded-mutation, staged-application, live-application authorization, application,
rotation plan, governance-execution intent, and governance proof. It also rejects
fixture-only, local-operator, peer-majority, custody-only, RemoteSigner-only,
attestation-only, and arbitrary-validator-set-bytes authority. Every field
binding (environment / chain / genesis / authority root / governance / rotation /
application / authorization / staged / guarded / runtime-handoff /
execution-preparation / mutation-execution / commit-authorization /
commit-execution / commit-receipt / post-commit-audit ids, digests, and nonces;
validator-set digests / epoch / version; epoch target; audit / durable-replay /
audit-sink / audit-ledger domains) has a dedicated `wrong_*` mutation test
proving fail-closed rejection.

---

## 9. MainNet refusal evidence

Even a fully valid source/test DevNet/TestNet artifact does not enable MainNet.
The `MainnetProductionLiveEpochTransitionDurableAuditFinalizationRequired` policy
and the `MainNetLiveEpochTransitionDurableAuditFinalizationUnavailable` kind are
reachable but fail closed as unavailable absent complete production authority
criteria.

---

## 10. Replay / idempotency evidence

Replay, idempotency, equivocation, and freshness are enforced fail-closed: a
previously observed request id in the replay set is rejected, and recovery over a
replay window is deterministic and non-mutating.

---

## 11. Fixture-state evidence

The only mutation any positive path performs is against a caller-owned in-memory
`LiveEpochTransitionDurableAuditFinalizationFixtureState` used exclusively by the
tests. It is explicitly distinct from production runtime, durable replay,
receipt, audit, audit-ledger, settlement, and publication state, and is never
persisted.

---

## 12. Non-mutation evidence

Every outcome is proven non-mutating with respect to production state. The
boundary produces only a typed artifact: it applies no live production
validator-set change, performs no production epoch transition, commits/finalizes
no production runtime state, writes no production receipt / audit record / audit
seal / audit-finalization record / durable replay / settlement / publication
record, makes no `BasicHotStuffEngine::transition_to_epoch` call, writes no
`meta:current_epoch`, injects no `PAYLOAD_KIND_RECONFIG` block, calls no Run 070,
and mutates no consensus / validator / epoch-counter / `LivePqcTrustState` /
trust-bundle-sequence / authority-marker / session state.

---

## 13. Tests run

* `cargo build -p qbind-node --lib` — pass.
* `cargo test -p qbind-node --test run_327_production_live_epoch_transition_durable_audit_finalization_tests` — 175 passed.
* `cargo test -p qbind-node --test run_325_production_live_epoch_transition_post_commit_audit_tests` — 175 passed.
* `cargo test -p qbind-node --test run_323_production_live_epoch_transition_commit_receipt_tests` — 175 passed.
* `cargo test -p qbind-node --test run_321_production_live_epoch_transition_commit_execution_tests` — 167 passed.
* `cargo test -p qbind-node --test run_319_production_live_epoch_transition_commit_authorization_tests` — 158 passed.
* `cargo test -p qbind-node --test run_317_production_live_epoch_transition_mutation_execution_tests` — 149 passed.
* `cargo test -p qbind-node --test run_315_production_live_epoch_transition_execution_preparation_tests` — 139 passed.
* `cargo test -p qbind-node --test run_313_production_epoch_transition_runtime_handoff_tests` — 151 passed.
* `cargo test -p qbind-node --test run_311_production_guarded_epoch_transition_mutation_executor_tests` — 124 passed.
* `cargo test -p qbind-node --test run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests` — 121 passed.
* `cargo test -p qbind-node --test run_307_production_live_validator_set_application_authorization_tests` — 135 passed.
* `cargo test -p qbind-node --test run_305_production_validator_set_rotation_application_executor_tests` — 126 passed.
* `cargo test -p qbind-node --test run_303_production_validator_set_rotation_intent_tests` — 131 passed.
* `cargo test -p qbind-node --test run_301_production_governance_execution_engine_tests` — 117 passed.
* `cargo test -p qbind-node --lib` — 1377 passed.

---

## 14. Security scans

* **Secret scanning** was run over the changed files (module, tests, docs, and
  `lib.rs`); no secrets, credentials, tokens, or API keys were introduced. The
  module and tests use only synthetic fixture strings.
* **CodeQL** — see the CodeQL result recorded at the end of this section. The Run
  327 change is additive source/test/docs only (a new pure-logic boundary module
  with no I/O, no network, no `unsafe`, and no new dependencies), so its security
  surface is limited to deterministic in-memory hashing and comparisons.

**CodeQL result.** The `codeql_checker` tool was invoked for the Run 327 change
(declared non-trivial: a new production-crate source module plus tests and a
`lib.rs` registration). **Outcome: the invocation timed out** — the tool returned
"Operation cancelled due to timeout" and instructed not to re-run it, matching the
documented Run 325 precedent that CodeQL cannot build a database for this large
multi-crate workspace within the available time budget. **No CodeQL coverage is
therefore claimed for Run 327.** The change remains additive, pure-logic,
non-mutating source/test/docs with no I/O, no network, no `unsafe`, and no new
dependencies; secret scanning (above) completed cleanly with no findings. A future
run should re-attempt CodeQL in an environment with sufficient time/resources for
the full workspace.

**Docs-hygiene note (Run 326 helper-hash label).** In the Run 326 release-binary
evidence `summary.txt` the helper-hash label was recorded as `helper_320_sha256`.
Run 327 renames the label to `helper_326_sha256` to match the run it belongs to.
The actual hash value is preserved verbatim and no Run 326 evidence is
reinterpreted.

---

## 15. C4/C5 matrix status

The live epoch-transition durable-audit finalization / audit-ledger preparation
row moves **Red → Yellow** (source/test only). It is **not** Green; Yellow →
Green-for-scope is deferred to Run 328 release-binary evidence. No live
production validator-set mutation, production epoch transition, production
commit/finalization, production receipt/audit write, production audit seal,
production audit-finalization write, durable replay write, settlement,
publication, external publication, MainNet readiness, C4 closure, or C5 closure
is claimed.

---

## 16. Honest limitations

* Source/test only. No release-binary evidence in Run 327 (deferred to Run 328).
* Production and MainNet durable-audit-finalization / audit-ledger paths are
  reachable but fail closed as unavailable; no production audit-ledger backend
  exists.
* No production runtime wiring and no CLI flag are added.
* The boundary proves only that a typed, deterministic, policy-gated,
  non-mutating durable-audit-finalization / audit-ledger-preparation artifact can
  be derived from a verified post-commit-audit decision — it proves nothing about
  live production commit/finalization, receipt/audit writes, audit seals,
  audit-ledger writes, durable replay writes, or MainNet readiness.

---

## 17. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**.

---

## 18. Suggested Run 328 next step

Capture **release-binary evidence** for the Run 327 live epoch-transition
durable-audit finalization / audit-ledger preparation boundary: add
`crates/qbind-node/examples/run_328_production_live_epoch_transition_durable_audit_finalization_release_binary_helper.rs`,
`scripts/devnet/run_328_production_live_epoch_transition_durable_audit_finalization_release_binary.sh`,
and `docs/devnet/run_328_.../`, exercising the real Run 327 executor in release
mode across the accepted / rejection / MainNet-policy / replay-recovery /
fixture-state / non-mutation / reachability tables, and move the row Yellow →
Green-for-scope only.
