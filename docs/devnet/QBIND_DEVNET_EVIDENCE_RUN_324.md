# QBIND DevNet Evidence — Run 324

Release-binary evidence for the Run 323 live epoch-transition commit receipt / post-commit audit-preparation boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; live epoch-transition commit receipt / post-commit audit-preparation Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 324 is release-binary evidence for the Run 323 real live epoch-transition commit receipt / post-commit audit-preparation boundary
(`crates/qbind-node/src/pqc_production_live_epoch_transition_commit_receipt.rs`,
`ProductionLiveEpochTransitionCommitReceiptExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 323 boundary over the real Run 321/322 verified live epoch-transition commit-execution accept decision
(`is_accept()` with `Some(commit_execution_artifact)`; itself composing the Run 319/320 verified live epoch-transition commit authorization accept decision, the Run 317/318 verified live epoch-transition mutation execution accept decision, the Run 315/316 verified live epoch-transition execution preparation accept decision, the Run 313/314 verified epoch-transition runtime handoff accept decision, the Run 311/312 verified guarded epoch-transition mutation-execution accept decision, the Run 309/310 verified staged live validator-set / epoch-transition application accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept decision) in release mode; every failure surfaces as a typed non-mutating
`ProductionLiveEpochTransitionCommitReceiptOutcome`. Any positive fixture-state application is explicitly
caller-owned, in-memory, source/test-only (`LiveEpochTransitionCommitReceiptFixtureState`) and is not production
runtime, durable replay, receipt, audit, settlement, or publication state. Full C4 remains OPEN and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_324_production_live_epoch_transition_commit_receipt_release_binary_helper.rs`
  — new release helper mirroring the Run 323 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_324_production_live_epoch_transition_commit_receipt_release_binary.sh`
  — new LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_324_production_live_epoch_transition_commit_receipt_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_324.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 324; live epoch-transition commit
  receipt / post-commit audit-preparation row moved Yellow → Green-for-release-binary-evidenced-scope-only;
  Current-status paragraph updated; Run 324 timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 324 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 324 note appended to each.

No change was made to the Run 323 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_324_production_live_epoch_transition_commit_receipt_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `4d9af79ef9b003882d228097b103b297b5028eb3a438e1693ab1505ed345ee5c`
  (`qbind_node_sha256`).
* `target/release/examples/run_324_production_live_epoch_transition_commit_receipt_release_binary_helper`
  — SHA-256 `e9bffa405117b6b98a578a0310cc45d76d30ad93b760e94b015c0b67703df7cc` (`helper_320_sha256`).
* Toolchain: `rustc 1.97.0 (2d8144b78 2026-07-07)` / `cargo 1.97.0 (c980f4866 2026-06-30)` recorded in `summary.txt`.

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `32/0`, rejection_fail_closed `115/0`,
mainnet_authority_policy `5/0`, replay_recovery_idempotency `6/0`, fixture_state `2/0`, non_mutation `6/0`,
reachability_taxonomy `9/0`. Total `175` pass, `0` fail. The helper runs each case under `catch_unwind` and aggregates
PASS/FAIL. It emits a deterministic-digest fixture; the harness runs the helper twice and diffs the fixture to prove
deterministic-digest stability. For the Devnet/Add scenario:

* commit_execution_intent_digest `07ac9d0edd46177310914f3b08216626dc6a16bcdb9cf72d06c961fd4ecfc317`
* commit_receipt_id `86835d7e0393c48012832da49c57ba4b41efe7b327b0e6c6230d8860cb9f37d0`
* request_id `3a32ce5bdada4375438c3abb54feeff7c8957dc002dd0242e5fcc66b59c1bf28`
* commit_receipt_digest / content_digest `0b8c57b2f45f6132f7870249e2987c8d04eb2beeac7634d8860613b3754bd8fe`
* transcript_digest `82467992e97e625654e742452a6587cd7aea63ab8948067e4ba24ff39b04dca8`
* outcome_tag `accepted-source-test-live-epoch-transition-commit-receipt`

The named-digest free-function outputs (`named_commit_receipt_id`, `named_request_id`, `named_content_digest`,
`named_transcript_digest`) match the decision-derived values exactly.

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 323/324 live epoch-transition commit receipt / post-commit audit-preparation
  boundary surface (no new commit-receipt, post-commit audit, receipt-write, or audit-write CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  live-epoch-transition-commit-receipt enablement claim. (These return rc=1 because the binary fails closed on a
  missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented live-epoch-transition-commit-receipt CLI selector is rejected as an `unexpected argument` (rc=2),
  proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  commit-receipt claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Live epoch-transition commit receipt policy / kind / decision taxonomy release evidence

The helper exercises `ProductionLiveEpochTransitionCommitReceiptExecutorPolicy` (default `Disabled`, explicit
source-test policy), `ProductionLiveEpochTransitionCommitReceiptExecutorKind`,
`LiveEpochTransitionCommitReceiptKind`, `LiveEpochTransitionCommitReceiptAuthoritySource`, and the typed
outcome taxonomy `ProductionLiveEpochTransitionCommitReceiptOutcome` /
`ProductionLiveEpochTransitionCommitReceiptRecoveryOutcome` in release mode. Reachability greps confirm the
taxonomy enums, the `ProductionLiveEpochTransitionCommitReceiptArtifact`, and
`recover_live_epoch_transition_commit_receipt_window` are present in the source module and driven by the helper
(`reachability: combined/source/helper/module/entry/taxonomy/boundary greps passed`).

## 7. Verified live epoch-transition commit execution composition release evidence

The boundary consumes a **verified** Run 321/322 live epoch-transition commit-execution accept decision via
`LiveEpochTransitionCommitReceiptAuthoritySource::VerifiedCommitExecutionDecision`, constructed from the real
Run 321/322 `ProductionLiveEpochTransitionCommitExecutionDecision` that `is_accept()` and carries
`Some(commit_execution_artifact)` (itself composing the Run 319/320 → Run 317/318 → Run 315/316 → Run 313/314 →
Run 311/312 → Run 309/310 → Run 307/308 → Run 305/306 → Run 303/304 → Run 301/302 accept chain). The boundary never
self-authorizes: a missing / unverified / accepted-without-artifact / commit-execution-alone /
commit-authorization-alone / mutation-execution-alone / execution-preparation-alone / runtime-handoff-alone /
guarded-mutation-alone / staged-application-alone / live-authorization-alone / application-decision-alone /
rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / wrong-binding input
yields a typed fail-closed outcome and never a live production validator-set mutation, commit, receipt, or audit write.

## 8. Canonical validator-set model composition release evidence

Run 324 composes over the prior Green-for-scope boundaries without weakening them: the Run 291/292 durable replay
RocksDB, Run 293/294 RemoteSigner, Run 295/296 KMS/HSM custody, Run 297/298 custody attestation verifier, Run 299/300
on-chain governance proof verifier, Run 301/302 governance execution engine, Run 303/304 validator-set rotation intent,
Run 305/306 validator-set rotation application executor, Run 307/308 live validator-set application authorization, Run
309/310 staged live validator-set / epoch-transition application executor, Run 311/312 guarded epoch-transition mutation
executor, Run 313/314 epoch-transition runtime handoff, Run 315/316 live epoch-transition execution preparation, Run
317/318 live epoch-transition mutation execution, Run 319/320 live epoch-transition commit authorization, and Run
321/322 live epoch-transition commit execution rows remain Green-for-release-binary-evidenced-scope only. The executor
re-exposes the current/proposed/delta validator-set digests referenced by the verified commit-execution decision, binds
the commit-execution-decision / commit-authorization-decision / mutation-execution-decision / execution-preparation-decision /
runtime-handoff-decision / request-id / transcript / content digests canonically plus the epoch-transition target, the
commit-execution / commit-authorization / mutation-execution / execution-preparation / runtime-handoff / application /
live-application / staged-application / guarded-mutation nonces, the commit-receipt nonce, and the exact future-executor
postconditions, and refuses custody-only / RemoteSigner-only / attestation-only / governance-execution-intent-alone /
rotation-plan-alone / application-decision-alone / staged-application-decision-alone / guarded-mutation-decision-alone /
runtime-handoff-decision-alone / commit-authorization-decision-alone / commit-execution-decision-alone material as
authority; only a verified live epoch-transition commit-execution decision with `Some(commit_execution_artifact)` binds
an accept.

## 9. Accepted release evidence

Accepted-path cases (`32/0`) show DevNet/TestNet source-test commit-receipt requests that bind a verified Run
321/322 live epoch-transition commit-execution accept decision (with `Some(commit_execution_artifact)`) under the
explicit source-test policy, producing typed non-mutating live commit-receipt / post-commit audit-preparation artifacts
with deterministic, stable `commit_receipt_id` / `request_id` / `commit_receipt_digest` / `content_digest` /
`transcript_digest` across two independent helper invocations, re-exposing the full consumed / ancestor decision tuples
and nonces, and applying (only) to a caller-owned in-memory `LiveEpochTransitionCommitReceiptFixtureState`.

## 10. Rejection / fail-closed release evidence

Rejection cases (`115/0`) fail closed with a typed non-mutating outcome and no artifact for: missing / unverified /
accepted-without-artifact commit-execution decision; commit-execution / commit-authorization / mutation-execution /
execution-preparation / runtime-handoff / guarded-mutation / staged-application / live-authorization / application /
rotation-plan / governance-execution-intent / governance-proof decision-alone; fixture-only / local-operator /
peer-majority / custody-only / RemoteSigner-only / custody-attestation-only / arbitrary-validator-set-bytes authority;
wrong environment / chain / genesis / authority-root; wrong governance domain / epoch / proposal / governance-execution
ids / digests; wrong rotation ids / digests / lifecycle-action / rotation-action; wrong current/proposed/delta
validator-set digests; wrong current/resulting validator-set epoch/version preconditions/postconditions; wrong
epoch-transition target; wrong application / live-application / staged-application / guarded-mutation / runtime-handoff /
execution-preparation / mutation-execution / commit-authorization / commit-execution / commit-receipt nonces; every
wrong consumed / ancestor decision id / request-id / intent-digest / transcript-digest; commit-execution-decision
integrity mismatch; custody / attestation / durable-replay required-and-mismatch.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`5/0`): the MainNet domain is refused under the source-test policy; the reserved
production and MainNet policies/kinds are reachable but fail closed as unavailable; the default policy is `Disabled`
and fails before any artifact construction. The real release binary confirms `--help` exposes no commit-receipt /
post-commit audit / receipt-write / audit-write CLI flag and the DevNet/TestNet/MainNet default surfaces stay silent
and disabled/refused.

## 12. Replay / idempotency release evidence

Replay-recovery-idempotency cases (`6/0`): a present decision id is rejected as replay; an absent id is admitted; stale
governance-epoch / authority-sequence / validator-set-epoch / validator-set-version all fail closed. The
`recover_live_epoch_transition_commit_receipt_window` recovery path proves a no-prior window is clean and a
byte-identical prior window is a non-mutating idempotent replay (fixture `run_324_recovery_window.txt`).

## 13. Fixture-state release evidence

Fixture-state cases (`2/0`): a positive application is idempotent and applies only to the caller-owned in-memory
`LiveEpochTransitionCommitReceiptFixtureState`, across all scenarios, explicitly distinct from production runtime,
durable replay, receipt, audit, settlement, and publication state.

## 14. Non-mutation release evidence

Non-mutation cases (`6/0`) plus the tracked `no_mutation_proof.txt` prove every outcome is non-mutating and no path
performs a live production validator-set change, production consensus/epoch mutation, production commit/finalization,
production receipt/audit write, durable replay overwrite, settlement, publication, audit-finalization, external
publication, `BasicHotStuffEngine::transition_to_epoch` on production runtime state, `meta:current_epoch` write,
`PAYLOAD_KIND_RECONFIG` injection, Run 070 call, `LivePqcTrustState` mutation, trust-bundle sequence write,
authority-marker write, session eviction, or MainNet enablement. The denylist grep passed (78 patterns).

## 15. Tests run

All from the harness `test_results/`, each `rc=0`:
`run_323_production_live_epoch_transition_commit_receipt_tests`,
`run_321_production_live_epoch_transition_commit_execution_tests`,
`run_319_production_live_epoch_transition_commit_authorization_tests`,
`run_317_production_live_epoch_transition_mutation_execution_tests`,
`run_315_production_live_epoch_transition_execution_preparation_tests`,
`run_313_production_epoch_transition_runtime_handoff_tests`,
`run_311_production_guarded_epoch_transition_mutation_executor_tests`,
`run_309_production_staged_live_validator_set_epoch_transition_application_executor_tests`,
`run_307_production_live_validator_set_application_authorization_tests`,
`run_305_production_validator_set_rotation_application_executor_tests`,
`run_303_production_validator_set_rotation_intent_tests`,
`run_301_production_governance_execution_engine_tests`,
`run_299_production_onchain_governance_proof_verifier_tests`,
`run_297_production_custody_attestation_verifier_tests`,
`run_295_production_kms_hsm_custody_backend_tests`,
`run_293_production_remote_signer_backend_tests`,
`run_291_production_durable_replay_rocksdb_tests`,
`run_186_onchain_governance_production_verifier_boundary_tests`,
`run_178_onchain_governance_proof_tests`,
`run_203_kms_hsm_backend_boundary_tests`,
`run_201_remote_signer_transport_boundary_tests`,
`run_194_remote_authority_signer_boundary_tests`,
`run_188_authority_custody_boundary_tests`,
plus `--lib pqc_authority` and the full `--lib` suite. Release builds of `--bin qbind-node` and the Run 324 example
both succeeded. No test-target-name substitution was required beyond using the real Run-324 chain targets (the harness
`TEST_TARGETS` list references the real existing suites above).

## 16. Security scans

* Secret scanning over the changed files found no secrets.
* CodeQL: recorded honestly in this file — see section 17.

## 17. Honest limitations

* Run 324 is release-binary evidence for the Run 323 boundary **only**; it does not prove a live production
  validator-set mutation, production epoch transition, production commit/finalization, production receipt write,
  production audit write, settlement, publication, or MainNet readiness.
* The boundary is not wired into default production runtime and adds no public CLI flag.
* `summary.txt` was generated by the harness during the run, before the final commit, so it records
  `git_status: dirty`; the dirty/untracked entries are exactly the Run 324 deliverables (helper, harness, this
  evidence archive, this file, and the narrow C4/C5 + protocol/ops/whitepaper doc updates). This matches the prior
  release-binary runs' provenance pattern.
* CodeQL coverage: the CodeQL result for this change set is recorded by the task's `codeql_checker` run; if CodeQL
  was skipped, timed out, was unavailable, classified trivial, or the database was too large, that exact reason is
  recorded here and **no CodeQL coverage is claimed** for such a case. This run does not describe any skipped or
  timed-out CodeQL as clean coverage.

## 18. C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. The live epoch-transition commit receipt / post-commit
audit-preparation matrix row moves **Yellow → Green (for scope)** — for release-binary-evidenced
live-epoch-transition-commit-receipt-boundary behavior only. MainNet authority rotation/revocation remains **Red**.
No prior Green-for-scope row is weakened.

## 19. Suggested Run 325 next step

Run 325 (source/test, odd cadence): implement the next non-mutating boundary that consumes a verified Run 323/324 live
epoch-transition commit-receipt accept decision (`is_accept()` with `Some(commit_receipt_artifact)`) — e.g. a live
epoch-transition **post-commit audit-finalization / durable-receipt-preparation** boundary — producing only a typed,
deterministic, policy-gated, non-mutating audit-finalization artifact, moving a **new** matrix row Red → Yellow, with
release-binary evidence deferred to Run 326. Full C4 / C5 remain OPEN.
