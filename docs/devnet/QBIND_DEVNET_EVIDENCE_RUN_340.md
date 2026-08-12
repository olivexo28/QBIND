# QBIND DevNet Evidence — Run 340

Release-binary evidence for the Run 339 live epoch-transition settlement / finalization execution boundary.

Run 340 is **release-binary evidence only**. It proves the real Run 339 live epoch-transition settlement / finalization execution boundary in release mode. It does **not** add a new source/test boundary, does **not** wire the boundary into normal node operation, adds **no public CLI flag**, does **not** enable MainNet, performs **no** live production validator-set mutation, performs **no** production epoch transition, performs **no** production commit/finalization, and writes **no** production receipt, audit, audit seal, audit-finalization, audit-ledger, external-publication, durable replay, settlement, settlement-finalization, or publication record. Full **C4 remains OPEN**, **C5 remains OPEN**, and MainNet authority rotation/revocation remains **Red**.

## 1. Exact verdict

**PASS (release-binary evidence only; live epoch-transition settlement / finalization execution Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 340 is release-binary evidence for the Run 339 real live epoch-transition settlement / finalization execution boundary
(`crates/qbind-node/src/pqc_production_live_epoch_transition_settlement_execution.rs`,
`ProductionLiveEpochTransitionSettlementExecutionExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 339 boundary over the real Run 337/338 verified live epoch-transition settlement / finalization execution-preparation accept decision
(`is_accept()` with `Some(settlement_execution_preparation_artifact)`; itself composing the Run 335/336 verified live
epoch-transition settlement / finalization-preparation accept decision, the Run 333/334 verified live
epoch-transition external-publication accept decision, the Run 331/332 verified live
epoch-transition durable-audit publication accept decision, the Run 329/330 verified live
epoch-transition audit-ledger commitment accept decision, the Run 327/328 verified live
epoch-transition durable-audit finalization accept decision, the Run 325/326 verified live
epoch-transition post-commit audit accept decision, the Run 323/324 verified live epoch-transition commit-receipt accept
decision, the Run 321/322 verified live epoch-transition commit execution accept decision, the Run 319/320 verified live
epoch-transition commit authorization accept decision, the Run 317/318 verified live epoch-transition mutation execution
accept decision, the Run 315/316 verified live epoch-transition execution preparation accept decision, the Run 313/314
verified epoch-transition runtime handoff accept decision, the Run 311/312 verified guarded epoch-transition
mutation-execution accept decision, the Run 309/310 verified staged live validator-set / epoch-transition application
accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the Run 305/306
verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept
decision, and the Run 301/302 verified governance execution accept decision) in release mode; every failure surfaces as a
typed non-mutating `ProductionLiveEpochTransitionSettlementExecutionOutcome`. Any positive fixture-state application is
explicitly caller-owned, in-memory, source/test-only (`LiveEpochTransitionSettlementExecutionFixtureState`) and is not
production runtime, durable replay, receipt, audit, audit-ledger, settlement, or publication state. Full C4 remains OPEN
and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_340_production_live_epoch_transition_settlement_execution_release_binary_helper.rs`
  — release helper mirroring the Run 339 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_340_production_live_epoch_transition_settlement_execution_release_binary.sh`
  — LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_340_production_live_epoch_transition_settlement_execution_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_340.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 340; live epoch-transition
  settlement / finalization execution row moved Yellow → Green-for-scope only;
  Current-status paragraph updated; Run 340 timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 340 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 340 note appended to each (five narrative docs).

No change was made to the Run 339 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_340_production_live_epoch_transition_settlement_execution_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `5ab635668e14edcc47d2e7a4c5a7eeff5683f9a4144b26109f23d416db6c1f91`
  (`qbind_node_sha256`).
* `target/release/examples/run_340_production_live_epoch_transition_settlement_execution_release_binary_helper`
  — SHA-256 `dac159fb1bc0537241e937f297101c760cf3fe5b759f9f8fe1a5767cfbddca82` (`helper_340_sha256`).
* Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)` recorded in `summary.txt`.

The real release binaries were built during this Run 340 run (`cargo build -p qbind-node --release` and
`cargo build -p qbind-node --example run_340_..._helper --release` both succeeded). The hashes above are the exact
values recorded by the committed harness `summary.txt`, which is treated as the final harness result for Run 340.

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `14/0`, rejection_fail_closed `97/0`,
mainnet_authority_policy `5/0`, replay_recovery_idempotency `6/0`, fixture_state `2/0`, non_mutation `6/0`,
reachability_taxonomy `9/0`. Total **139 pass, 0 fail**. The helper runs each case under `catch_unwind` and aggregates
PASS/FAIL. It emits a deterministic-digest fixture; the harness runs the helper twice and diffs the fixture to prove
deterministic-digest stability. For the Add scenario:

* settlement_execution_id `01fd30e63e044b138b7d583640b5a7e9cd3e598969b2b7bf0f968b2ec8a2d885`
* request_id `da7b56f1753ddd1184c9868506e08ff334afa3c1dcdee935de088df8a42702a4`
* settlement_execution_digest / content_digest `0331581160728356aebdd10bd221bcc516aa04b6712d5174f17f33b5a1bbbdd1`
* transcript_digest `33e38bd53da205d6b593938f86103d1e4bd1a94b6b045d7e80079a80c8b3659b`
* epoch_transition_target `11`; staged_kind `StageApplyValidatorAdd`
* outcome_tag `accepted-source-test-live-epoch-transition-settlement-execution`

The named-digest free-function outputs (`named_settlement_execution_id`, `named_request_id`, `named_content_digest`,
`named_transcript_digest`) match the decision-derived values exactly.

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 339 live epoch-transition settlement / finalization execution boundary surface
  (no new settlement, settlement-finalization, external-publication, audit-ledger, audit-seal, durable-audit,
  publication, or audit-write CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  live-epoch-transition-settlement-execution enablement claim. (These return rc=1 because the binary fails closed on a
  missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented live-epoch-transition-settlement-execution CLI selector is rejected as an `unexpected argument` (rc=2),
  proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  settlement-execution claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Accepted release evidence

Accepted-path cases show DevNet/TestNet source-test settlement-execution requests that bind a verified Run
337/338 live epoch-transition settlement / finalization execution-preparation accept decision (with `Some(settlement_execution_preparation_artifact)`; itself composing the Run 335/336 verified live epoch-transition settlement / finalization-preparation accept decision)
under the explicit source-test policy, producing typed non-mutating live settlement / finalization execution artifacts
with deterministic, stable `settlement_execution_id` / `request_id` /
`settlement_execution_digest` / `content_digest` / `transcript_digest` across two independent helper invocations,
re-exposing the full consumed / ancestor decision tuples and nonces, and applying (only) to a caller-owned in-memory
`LiveEpochTransitionSettlementExecutionFixtureState`.

## 7. Rejection / fail-closed evidence

Rejection cases fail closed with a typed non-mutating outcome and no artifact for: missing / unverified /
accepted-without-artifact settlement-execution-preparation decision; settlement-execution-preparation / external-publication / durable-audit-publication /
audit-ledger-commitment / durable-audit-finalization / post-commit-audit / commit-receipt / commit-execution /
commit-authorization / mutation-execution / execution-preparation / runtime-handoff / guarded-mutation /
staged-application / live-authorization / application / rotation-plan / governance-execution / governance-proof
decision-alone; fixture-only / local-operator / peer-majority / custody-only / RemoteSigner-only /
custody-attestation-only / arbitrary-validator-set-bytes authority; wrong environment / chain / genesis / authority-root;
wrong governance domain / epoch / proposal / governance-execution ids / digests; wrong rotation ids / digests /
lifecycle-action / rotation-action; wrong current/proposed/delta validator-set digests; wrong current/resulting
validator-set epoch/version preconditions/postconditions; wrong epoch-transition target; wrong application /
live-application / staged-application / guarded-mutation / runtime-handoff / execution-preparation / mutation-execution /
commit-authorization / commit-receipt / post-commit-audit / external-publication nonces; every wrong consumed /
ancestor decision id / request-id / intent-digest / transcript-digest; external-publication-decision integrity
mismatch; custody / attestation / durable-replay required-and-mismatch.

## 8. MainNet refusal / authority policy evidence

MainNet-authority-policy cases (`5/0`): the MainNet domain is refused under the source-test policy; the reserved
production and MainNet policies/kinds are reachable but fail closed as unavailable; the default policy is `Disabled`
and fails before any artifact construction. The real release binary confirms `--help` exposes no settlement /
settlement-finalization / external-publication / audit-ledger / audit-seal / durable-audit / publication / audit-write
CLI flag and the DevNet/TestNet/MainNet default surfaces stay silent and disabled/refused. MainNet authority
rotation/revocation remains **Red**.

## 9. Replay / idempotency evidence

Replay-recovery-idempotency cases (`6/0`): a present decision id is rejected as replay; an absent id is admitted; stale
governance-epoch / authority-sequence / validator-set-epoch / validator-set-version all fail closed. The
`recover_live_epoch_transition_settlement_execution_window` recovery path proves a no-prior window is clean and a
byte-identical prior window is a non-mutating idempotent replay (`staged_application_id=gov-decision-id-1`).

## 10. Fixture-state evidence

Fixture-state cases (`2/0`): a positive application is idempotent and applies only to the caller-owned in-memory
`LiveEpochTransitionSettlementExecutionFixtureState`, across all scenarios, explicitly distinct from production runtime,
durable replay, receipt, audit, audit-ledger, settlement, and publication state.

## 11. Non-mutation evidence

Non-mutation cases (`6/0`) plus the tracked `no_mutation_proof.txt` prove every outcome is non-mutating and no path
performs a live production validator-set change, production consensus/epoch mutation, production commit/finalization,
production receipt/audit write, durable replay overwrite, settlement, settlement-finalization, publication,
audit-finalization, audit-ledger commitment, external publication, `BasicHotStuffEngine::transition_to_epoch` on
production runtime state, `meta:current_epoch` write, `PAYLOAD_KIND_RECONFIG` injection, Run 070 call,
`LivePqcTrustState` mutation, trust-bundle sequence write, authority-marker write, session eviction, or MainNet
enablement. The denylist grep passed (83 patterns).

## 12. Tests run

The Run 340 release harness
(`scripts/devnet/run_340_production_live_epoch_transition_settlement_execution_release_binary.sh`) was executed
end-to-end for this change set. It ran the full boundary regression corpus (31 test targets, run
from the newest Run 339 boundary suite back through the ancestor chain, plus `--lib pqc_authority` and the full
`--lib` suite), each recording `rc=0` in the tracked `summary.txt`. Representative results (final values recorded
verbatim in `summary.txt`):

* `cargo test -p qbind-node --test run_339_production_live_epoch_transition_settlement_execution_tests` — **passed; 0 failed**.
* `cargo test -p qbind-node --test run_337_production_live_epoch_transition_settlement_execution_preparation_tests` — **passed; 0 failed**.
* `cargo test -p qbind-node --test run_333_production_live_epoch_transition_external_publication_tests` — **passed; 0 failed**.
* `cargo test -p qbind-node --lib` — full library suite passed.
* `bash -n scripts/devnet/run_340_production_live_epoch_transition_settlement_execution_release_binary.sh` — syntax OK.
* `cargo build -p qbind-node --release` — succeeded.
* `cargo build -p qbind-node --example run_340_production_live_epoch_transition_settlement_execution_release_binary_helper --release` — succeeded.

The harness `summary.txt` records `verdict: PASS` for the full Run 339 → ancestor chain of boundary test suites plus
`--lib pqc_authority` and the full `--lib` suite. The committed `summary.txt` is treated as the final harness result
for Run 340.

## 13. Security scans

* **Secret scanning** was run over all Run 340 changed files: the release helper
  (`crates/qbind-node/examples/run_340_..._helper.rs`), the harness script
  (`scripts/devnet/run_340_..._release_binary.sh`), the archive tracked files (`README.md`, `summary.txt`, `.gitignore`),
  this canonical evidence doc, the C4/C5 criteria doc, and the five narrative docs. **No secrets were found.**
* **CodeQL:** the `codeql_checker` tool was invoked for the Run 340 change set (declared **non-trivial**, because the
  change set adds a new compiled Rust example and a bash harness script). It returned, verbatim: *"Analysis was skipped
  because the database size is too large."* (0 alerts, but only because **no analysis ran**). CodeQL therefore performed
  **no** analysis of this change set — most plausibly because the ~5,000-line generated release helper plus the large
  evidence corpus pushed the CodeQL database over its size limit. **No CodeQL coverage is claimed for Run 340;** this
  skipped result is explicitly **not** described as clean coverage. See section 14 for the full provenance.

## 14. C4/C5 matrix status

Full **C4 remains OPEN**. **C5 remains OPEN**. The live epoch-transition settlement / finalization execution matrix
row is **Green (for scope)** — for release-binary-evidenced
live-epoch-transition-settlement-execution-boundary behavior only (source/test in Run 339; release-binary evidence
positive in Run 340). MainNet authority rotation/revocation remains **Red**. No prior Green-for-scope row is weakened.

**CodeQL provenance (recorded verbatim).** The `codeql_checker` tool was invoked for the Run 340 change set, declared
**non-trivial** (the change set adds a new compiled Rust example and a bash harness script). It returned, verbatim:
**`Analysis Result for 'rust'. Found 0 alerts: - rust: Analysis was skipped because the database size is too large.`**
The reported "0 alerts" is a consequence of the analysis being **skipped**, **not** a clean scan. This is a
tool/infrastructure limitation (most plausibly the ~5,000-line generated helper plus the large evidence docs pushing the
CodeQL database over its size limit), **not** a reported code finding and **not** a clean result. Because CodeQL
**ran no analysis**, **no CodeQL coverage is claimed for Run 340**; this skipped result is explicitly **not** described as
clean coverage. Secret scanning (a separate tool) did run over all changed files and found no secrets.

## 15. Honest limitations

* Run 340 is release-binary evidence for the Run 339 boundary **only**; it does not prove a live production
  validator-set mutation, production epoch transition, production commit/finalization, production receipt write,
  production audit write, production external-publication, settlement, settlement-finalization, publication, or MainNet
  readiness.
* The boundary is not wired into default production runtime and adds no public CLI flag.
* **`git_status: dirty` explanation.** The committed harness `summary.txt` records `git_status: dirty` at
  `git_commit` `a4ba6b427f9f95380bed4e4a9561faba4cfadefe` (the Run 340 progress commit that had landed the release helper
  and the first round of docs). The
  `summary.txt` is generated by the harness **while the run is in progress**, so at generation time the remaining Run 340
  deliverables were still uncommitted/untracked: the evidence archive (`README.md`, `summary.txt`,
  `.gitignore`), this canonical evidence doc, and the final in-place doc refinements. Those files are committed as part of
  the same Run 340 change set that publishes
  this evidence doc; the `dirty` marker reflects only the in-progress harness snapshot and not any unexplained
  working-tree drift.
* **CodeQL coverage:** the `codeql_checker` tool was invoked and returned *"Analysis was skipped because the database
  size is too large."* (recorded verbatim in section 14). Because CodeQL **ran no analysis**, **no CodeQL coverage is
  claimed for Run 340**; the skipped result is **not** described as clean coverage.

## 16. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. The live epoch-transition settlement / finalization execution row is
**Green-for-scope only** (Run 339 source/test + Run 340 release-binary evidence). MainNet
authority rotation/revocation remains **Red**. There is no live production validator-set mutation, no production epoch
transition, no production commit/finalization, no production receipt/audit/audit-seal/audit-finalization/audit-ledger/
external-publication/durable-replay/settlement/settlement-finalization/publication write, no default runtime wiring, no
public CLI enablement, and no C4/C5 closure claim.

## 17. Suggested Run 341 next step

Run 341 (source/test, odd cadence): implement the next non-mutating boundary that consumes a verified Run 339/340 live
epoch-transition settlement / finalization execution accept decision (`is_accept()` with
`Some(settlement_execution_artifact)`) — e.g. a live epoch-transition **final settlement / authority-lifecycle
completion** boundary — producing only a typed, deterministic, policy-gated, non-mutating artifact, moving a **new**
matrix row Red → Yellow, with release-binary evidence deferred to Run 342. Full C4 / C5 remain OPEN. Do not begin
Run 341 as part of this Run 340 change set.