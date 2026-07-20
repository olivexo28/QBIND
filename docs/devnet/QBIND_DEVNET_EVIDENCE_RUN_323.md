# QBIND DevNet Evidence — Run 323

Source/test **live epoch-transition commit receipt / post-commit
audit-preparation** boundary implementation.

Run 323 is **source/test only**. It is **not** release-binary evidence.
Release-binary evidence is deferred to Run 324.

---

## 1. Exact verdict

**PASS — Run 323 source/test live epoch-transition commit receipt /
post-commit audit-preparation boundary implemented.**

A new narrow source/test boundary consumes a verified Run 321/322 non-mutating
live epoch-transition **commit-execution decision** (the accepted
`ProductionLiveEpochTransitionCommitExecutionDecision` output that
`is_accept()` and carries `Some(commit_execution_artifact)`) and produces a
typed, deterministic, policy-gated **live commit-receipt / post-commit
audit-preparation artifact** that describes exactly what a future live
production post-commit receipt / audit step (Run 324+ / release) would perform,
together with the exact future-executor preconditions and postconditions.
Default posture is `Disabled` / fail-closed.

Despite the name, Run 323 **does not** write a production commit receipt, audit
ledger, durable replay record, settlement record, publication record, authority
marker, trust-bundle sequence file, or any runtime state. It produces **only**
a typed artifact and may, on a source/test-bounded path, mutate **only** an
explicit caller-owned in-memory `LiveEpochTransitionCommitReceiptFixtureState`.
It **does not** wire into production runtime. It **does not** add a public CLI
flag. It **does not** enable MainNet. It **does not** apply a live production
validator-set change. It **does not** perform a production epoch transition. It
**does not** commit or finalize production runtime state. It **does not** call
`BasicHotStuffEngine::transition_to_epoch` on production runtime state. It
**does not** write `meta:current_epoch`. It **does not** inject a
`PAYLOAD_KIND_RECONFIG` block. It mutates no production consensus validator
state, epoch counters, `LivePqcTrustState`, trust-bundle sequence files,
authority markers, or sessions. It calls neither Run 070 nor any runtime
wiring. Production and MainNet post-commit receipt/audit kinds are reachable but
fail closed as unavailable. MainNet remains refused. Full C4 remains OPEN. C5
remains OPEN.

The live epoch-transition commit receipt / post-commit audit-preparation
boundary matrix row moves **Red → Yellow** (source/test implementation landed;
release-binary evidence pending Run 324). It is **not** marked Green. No
release-binary evidence, live production validator-set mutation, production
epoch transition, production commit/finalization, production receipt/audit
write, MainNet readiness, C4 closure, or C5 closure is claimed. Prior
Green-for-scope rows (Run 322 commit-execution release-binary, Run 320
commit-authorization release-binary, Run 318 mutation-execution release-binary,
etc.) are unchanged and not reinterpreted.

---

## 2. Files changed

New:

* `crates/qbind-node/src/pqc_production_live_epoch_transition_commit_receipt.rs` — boundary module.
* `crates/qbind-node/tests/run_323_production_live_epoch_transition_commit_receipt_tests.rs` — 175 source/test cases.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_323.md` — this evidence report.

Modified:

* `crates/qbind-node/src/lib.rs` — registered `pub mod pqc_production_live_epoch_transition_commit_receipt;`.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — added a new live epoch-transition commit receipt row Red → Yellow; refreshed status line; added Run 323 changelog entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/whitepaper/contradiction.md` — narrow Run 323 changelog entries.

---

## 3. Boundary design summary

`ProductionLiveEpochTransitionCommitReceiptExecutor` takes:

* a `ProductionLiveEpochTransitionCommitReceiptRequest` (a commit-receipt
  authority source, an explicit proposed epoch-transition target, a
  commit-receipt nonce, plus optional custody / attestation / durable-replay
  bindings),
* `ProductionLiveEpochTransitionCommitReceiptInputs` (operator-trusted expected
  values including the consumed `expected_commit_execution_*` binding, the
  re-exposed `expected_commit_authorization_*`, `expected_mutation_execution_*`,
  `expected_execution_preparation_*`, and `expected_runtime_handoff_*` ancestor
  bindings, the full re-exposed guarded-mutation / staged-application /
  authorization / application / rotation / governance / validator-set tuple,
  trust domain, evidence requirements, replay/freshness anchors, and the
  current-validator-set epoch/version fail-closed preflight preconditions), and
* a commit-receipt replay set.

It performs a pure policy / kind / MainNet preflight gate (fails closed before
any binding), resolves the authority source (only a verified Run 321/322
commit-execution decision carrying `Some(commit_execution_artifact)` is
accepted), cross-checks the consumed decision + re-exposed artifact against the
trusted inputs and trust domain, enforces replay / idempotency / equivocation /
freshness fail-closed, and — only on full success — emits a deterministic typed
`ProductionLiveEpochTransitionCommitReceiptArtifact`. Every reject path returns
a typed non-mutating outcome with no artifact.

---

## 4. Policy / kind / commit-receipt taxonomy

Policy (`ProductionLiveEpochTransitionCommitReceiptExecutorPolicy`):

* `Disabled` (default; fails closed with no evaluation),
* `AllowSourceTestLiveEpochTransitionCommitReceipt` (only source/test path),
* `RequireProductionLiveEpochTransitionCommitReceipt` (reachable, fails closed
  as unavailable),
* `MainnetProductionLiveEpochTransitionCommitReceiptRequired` (reachable, fails
  closed as unavailable).

Kind (`ProductionLiveEpochTransitionCommitReceiptExecutorKind`):

* `Disabled`,
* `SourceTestLiveEpochTransitionCommitReceipt`,
* `ProductionLiveEpochTransitionCommitReceipt` (reachable but fails closed as
  `ProductionLiveEpochTransitionCommitReceiptUnavailable`),
* MainNet variant fails closed as
  `MainNetLiveEpochTransitionCommitReceiptUnavailable`.

Supporting types: `ProductionLiveEpochTransitionCommitReceiptRequest`,
`...Inputs`, `...Decision`, `...Artifact`, `...Outcome`,
`...RecoveryOutcome`, the `LiveEpochTransitionCommitReceiptReplaySet` trait
(with an `EmptyLiveEpochTransitionCommitReceiptReplaySet`), and the test-only
`LiveEpochTransitionCommitReceiptFixtureState`.

**Note (naming substitution):** the suggested taxonomy used `...Policy` /
`...Kind`; to stay mechanically consistent with the accepted Run 319/321
ancestor boundaries, the concrete types retain the `Executor` infix
(`...ExecutorPolicy` / `...ExecutorKind`). Behaviour is identical to the
suggested taxonomy.

---

## 5. Run 321/322 commit-execution artifact binding

The sole accepted authority source is
`LiveEpochTransitionCommitReceiptAuthoritySource::VerifiedCommitExecutionDecision`
carrying a Run 321/322 `ProductionLiveEpochTransitionCommitExecutionDecision`
that `is_accept()` and carries `Some(commit_execution_artifact)`. The boundary
binds the consumed decision id / request-id / commit-execution digest /
transcript-digest, verifies the prepared artifact's `content_digest()`
reproduces the decision's `commit_execution_digest`
(commit-execution-decision-integrity check), and binds the re-exposed
commit-execution nonce. Through the consumed artifact it re-binds the ancestor
commit-authorization, mutation-execution, execution-preparation,
runtime-handoff, guarded-mutation, staged-application, authorization,
application, rotation, governance, and validator-set tuples plus every nonce.

---

## 6. Live commit-receipt / post-commit audit-preparation artifact model

`ProductionLiveEpochTransitionCommitReceiptArtifact` carries deterministic
`commit_receipt_id`, `request_id`, `commit_receipt_digest`, and
`transcript_digest`; re-exposes the full consumed + ancestor authority tuple;
and encodes the exact future production receipt/audit preconditions and
postconditions: expected previous commit-execution artifact digest, expected
resulting validator-set digest + epoch/version, expected target consensus
epoch, expected durable replay domain, expected audit sink domain, required
governance epoch, required authority sequence, required replay window, required
no-conflicting-commit marker, and required production-runtime-handle /
durable-replay / audit-sink availability. Optional future settlement /
publication availability is represented where applicable but **never written**.
`content_digest()` is a domain-separated SHA3-256 over every field except the
four identifier fields, so re-evaluation is deterministic.

---

## 7. Accepted source/test evidence

Tests compose the real Run 303/304 → 305/306 → 307/308 → 309/310 → 311/312 →
313/314 → 315/316 → 317/318 → 319/320 → 321/322 accept chain to produce a
verified accepted Run 321/322 commit-execution decision, then feed it into the
Run 323 executor. Accepted DevNet/TestNet source-test commit-receipt /
audit-preparation artifacts are produced for all scenarios; digests are
deterministic under re-evaluation; the artifact re-exposes the consumed
commit-execution and ancestor commit-authorization / guarded-mutation /
staged-application tuples and nonces intact.

---

## 8. Rejection / fail-closed evidence

Fail-closed rejections (typed, non-mutating, no artifact) cover: wrong
environment / chain / genesis / authority-root; wrong governance domain / epoch
/ proposal / execution ids / digests; wrong rotation / application /
live-authorization / staged-application / guarded-mutation / runtime-handoff /
execution-preparation / mutation-execution / commit-authorization /
commit-execution ids, digests, and nonces; wrong current/proposed/delta
validator-set digests; wrong validator-set epoch/version preconditions and
postconditions; wrong epoch-transition target; missing / unverified
commit-execution decision; accepted commit-execution decision without an
artifact; and **decision-alone** rejection for each ancestor
(commit-authorization, mutation-execution, execution-preparation,
runtime-handoff, guarded-mutation, staged-application, live-authorization,
application, rotation, governance-execution-intent, governance-proof) plus
fixture-only / local-operator / peer-majority / custody-only / RemoteSigner-only
/ attestation-only / arbitrary-validator-set-bytes.

---

## 9. MainNet refusal evidence

A MainNet trust domain or MainNet binding environment is refused
(`MainNetRefused`). The MainNet production policy on any domain fails closed as
`MainNetProductionLiveEpochTransitionCommitReceiptUnavailable`. No MainNet
production authority is wired; a fully valid source/test DevNet/TestNet artifact
does not enable MainNet behaviour.

---

## 10. Replay / idempotency evidence

Replay / idempotency / equivocation / freshness are enforced fail-closed:
replayed commit-receipt ids are rejected, stale governance epoch / authority
sequence / validator-set epoch / validator-set version are rejected, and the
recovery window re-derives the same record deterministically without mutation.

---

## 11. Fixture-state evidence

`LiveEpochTransitionCommitReceiptFixtureState` is an explicit caller-owned
in-memory structure used **only** by tests. Its apply path is idempotent and
never touches production runtime, durable stores, receipts, or audit records.

---

## 12. Non-mutation evidence

Every outcome (accept and reject) reports `is_non_mutating() == true`. No Run
070 apply, no `LivePqcTrustState` mutation, no trust swap, no session eviction,
no PQC trust-bundle sequence write, no authority-marker write, no durable-replay
/ receipt / audit / settlement / publication write, no KMS/HSM signing call, no
RemoteSigner fallback, and no default runtime wiring.

---

## 13. Tests run

* `cargo build -p qbind-node --lib` — pass.
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
* **CodeQL** — the CodeQL checker was invoked over the Run 323 change but
  **did not complete** (it was cancelled due to a timeout on this large
  workspace). Accordingly **no CodeQL coverage is claimed** for Run 323. The
  Run 323 change is additive source/test/docs only (a new pure-logic boundary
  module with no I/O, no network, no `unsafe`, and no new dependencies), so its
  security surface is limited to deterministic in-memory hashing and
  comparisons; a follow-up CodeQL run may be captured with the Run 324
  release-binary evidence.

---

## 15. C4/C5 matrix status

The live epoch-transition commit receipt / post-commit audit-preparation row
moves **Red → Yellow** (source/test only). It is **not** Green; Yellow →
Green-for-scope is deferred to Run 324 release-binary evidence. No live
production validator-set mutation, production epoch transition, production
commit/finalization, production receipt/audit write, MainNet readiness, C4
closure, or C5 closure is claimed.

---

## 16. Honest limitations

* Source/test only. No release-binary evidence in Run 323 (deferred to Run 324).
* Production and MainNet commit-receipt/audit paths are reachable but fail closed
  as unavailable; no production receipt/audit backend exists.
* No production runtime wiring and no CLI flag are added.
* The boundary proves only that a typed, deterministic, policy-gated,
  non-mutating post-commit receipt / audit-preparation artifact can be derived
  from a verified commit-execution decision — it proves nothing about live
  production commit/finalization, receipt/audit writes, or MainNet readiness.

---

## 17. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**.

---

## 18. Suggested Run 324 next step

Capture **release-binary evidence** for the Run 323 live epoch-transition commit
receipt / post-commit audit-preparation boundary: add
`crates/qbind-node/examples/run_324_production_live_epoch_transition_commit_receipt_release_binary_helper.rs`,
`scripts/devnet/run_324_production_live_epoch_transition_commit_receipt_release_binary.sh`,
and `docs/devnet/run_324_.../`, exercising the real Run 323 executor in release
mode across the accepted / rejection / MainNet-policy / replay-recovery /
fixture-state / non-mutation / reachability tables, and move the row
**Yellow → Green-for-scope**. Full C4 / C5 remain OPEN.
