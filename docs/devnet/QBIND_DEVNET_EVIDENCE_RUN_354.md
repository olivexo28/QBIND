# QBIND DevNet Evidence — Run 354

Release-binary evidence for the Run 353 live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness boundary.

Run 354 is **release-binary evidence only**. It proves the real Run 353 live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness boundary in release mode. It does **not** add a new source/test boundary, does **not** wire the boundary into normal node operation, adds **no public CLI flag**, does **not** enable MainNet, performs **no** live production validator-set mutation, performs **no** production epoch transition, performs **no** production commit/finalization, and writes **no** production execution-sink-prewrite, post-final-execution-confirmation, final-execution, authority-activation, authority-activation-authorization, final-settlement, authority-lifecycle-completion, receipt, audit, audit seal, audit-finalization, audit-ledger, external-publication, durable replay, settlement, settlement-finalization, settlement-execution, or publication record. Full **C4 remains OPEN**, **C5 remains OPEN**, and MainNet authority rotation/revocation remains **Red**.

## 1. Exact verdict

**PASS (release-binary evidence only; live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 354 is release-binary evidence for the Run 353 real live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness boundary
(`crates/qbind-node/src/pqc_production_live_epoch_transition_authority_activation_execution_sink_prewrite.rs`,
`ProductionLiveEpochTransitionAuthorityActivationExecutionSinkPrewriteExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 353 boundary over the real Run 353/354 verified live epoch-transition authority-activation post-final-execution-confirmation accept decision
(`is_accept()` with `Some(authority_activation_post_final_execution_confirmation_artifact)`; itself composing the Run 349/350 verified live epoch-transition authority-activation final-execution accept decision, the Run 347/348 verified live epoch-transition authority-activation execution-preparation / final-execution preflight accept decision, the Run 345/346 verified live epoch-transition authority-activation authorization / final-execution readiness accept decision, the Run 343/344 verified live
epoch-transition authority-lifecycle activation-readiness / post-completion attestation accept decision, the Run 341/342 verified live
epoch-transition final settlement / authority-lifecycle completion accept decision, the Run 339/340 verified live
epoch-transition settlement / finalization execution accept decision, the Run 337/338 verified live
epoch-transition settlement / finalization execution-preparation accept decision, the Run 335/336 verified live
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
typed non-mutating `ProductionLiveEpochTransitionAuthorityActivationExecutionSinkPrewriteOutcome`. Any positive fixture-state application is
explicitly caller-owned, in-memory, source/test-only (`LiveEpochTransitionAuthorityActivationExecutionSinkPrewriteFixtureState`) and is not
production runtime, durable replay, receipt, audit, audit-ledger, settlement, settlement-execution, or publication state. Full C4 remains OPEN
and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_354_production_live_epoch_transition_authority_activation_execution_sink_prewrite_release_binary_helper.rs`
  — release helper mirroring the Run 353 test corpus as release-linked cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_354_production_live_epoch_transition_authority_activation_execution_sink_prewrite_release_binary.sh`
  — executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_354_production_live_epoch_transition_authority_activation_execution_sink_prewrite_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_354.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 354; live epoch-transition
  authority-activation execution-sink prewrite / sink-commit-readiness row moved Yellow → Green-for-scope only;
  current-status paragraph updated; Run 353/354 timeline entry advanced.
* `docs/whitepaper/contradiction.md` — Run 354 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 354 note appended to each (five narrative docs).

No change was made to the Run 353 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_354_production_live_epoch_transition_authority_activation_execution_sink_prewrite_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 recorded as `qbind_node_sha256` in the tracked `summary.txt` at run time.
* `target/release/examples/run_354_production_live_epoch_transition_authority_activation_execution_sink_prewrite_release_binary_helper`
  — SHA-256 recorded as `helper_354_sha256` in the tracked `summary.txt` at run time.
* Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)` recorded in `summary.txt`.

The real release binaries were built during this Run 354 run (`cargo build -p qbind-node --release` and
`cargo build -p qbind-node --example run_354_..._helper --release` both succeeded). The hashes above are the exact
values recorded by the committed harness `summary.txt`, which is treated as the final harness result for Run 354.

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `29/0`, determinism `1/0`, mainnet_refusal `2/0`,
rejection_fail_closed `136/0`, replay_recovery_idempotency `7/0`. Total **175 pass, 0 fail** (registered_cases=175).
The helper runs each case under `catch_unwind` and aggregates PASS/FAIL. It emits a deterministic-digest fixture; the
harness runs the helper twice and diffs the fixture to prove deterministic-digest stability. For the accepted scenario:

* authority_activation_execution_sink_prewrite_id `9867fd1e4b3123665624b84acfad8fd17e174e8c5bf6b2a79795fb7bbd4855c6`
* request_id `7b6ae7e62ac7f3697434223d7e42934b658d1a9c537651ad7867474cfe36984a`
* authority_activation_execution_sink_prewrite_digest / content_digest `d4e1913e052e5772b6d5c1c7fc2e408ff609fb514e35e8f28103af9e61b95043`
* transcript_digest `2ef0ac0d86b387cd31d409eeccd617e86a3da88d67083e1cefa865ee20352663`
* environment `Devnet`; epoch_transition_target `11`; staged_kind `stage-apply-validator-add`
* recovery `IdempotentReplayObserved { staged_application_id: "gov-decision-id-1" }`

The artifact `content_digest()` equals `authority_activation_execution_sink_prewrite_digest` and is stable across repeated evaluation, matching the decision-derived values exactly.

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 353 live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness boundary surface
  (no new execution-sink-prewrite, final-execution, authority-activation, authority-activation-authorization, final-settlement, authority-lifecycle-completion, settlement, settlement-execution, external-publication,
  audit-ledger, audit-seal, durable-audit, publication, or audit-write CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  live-epoch-transition-authority-activation-execution-sink-prewrite enablement claim. (These return rc=1 because the binary fails closed on a
  missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented live-epoch-transition-authority-activation-execution-sink-prewrite CLI selector is rejected as an `unexpected argument` (rc=2),
  proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  authority-activation-execution-sink-prewrite claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Accepted release evidence

Accepted-path cases show DevNet/TestNet source-test authority-activation-execution-sink-prewrite requests that bind a verified Run
353/354 live epoch-transition authority-activation post-final-execution-confirmation accept decision (with `Some(authority_activation_post_final_execution_confirmation_artifact)`; itself composing the Run 349/350 verified live epoch-transition authority-activation final-execution accept decision and the Run 347/348 verified live epoch-transition authority-activation execution-preparation / final-execution preflight accept decision)
under the explicit source-test policy, producing typed non-mutating live authority-activation execution-sink prewrite / sink-commit-readiness artifacts
with deterministic, stable `authority_activation_execution_sink_prewrite_id` / `request_id` /
`authority_activation_execution_sink_prewrite_digest` / `content_digest` / `transcript_digest` across two independent helper invocations,
re-exposing the full consumed / ancestor decision tuples and nonces, and applying (only) to a caller-owned in-memory
`LiveEpochTransitionAuthorityActivationExecutionSinkPrewriteFixtureState`.

## 7. Rejection / fail-closed evidence

Rejection cases fail closed with a typed non-mutating outcome and no artifact for: missing / unverified /
accepted-without-artifact authority-activation-post-final-execution-confirmation decision; authority-activation-post-final-execution-confirmation / authority-activation-final-execution / authority-activation-execution-preparation / authority-activation-authorization / settlement-execution /
settlement-preparation / external-publication / durable-audit-publication /
audit-ledger-commitment / durable-audit-finalization / post-commit-audit / commit-receipt / commit-execution /
commit-authorization / mutation-execution / execution-preparation / runtime-handoff / guarded-mutation /
staged-application / live-authorization / application / rotation-plan / governance-execution / governance-proof
decision-alone; fixture-only / local-operator / peer-majority / custody-only / RemoteSigner-only /
custody-attestation-only / arbitrary-validator-set-bytes authority; wrong environment / chain / genesis / authority-root;
wrong governance domain / epoch / proposal / governance-execution ids / digests; wrong rotation ids / digests /
lifecycle-action / rotation-action; wrong current/proposed/delta validator-set digests; wrong current/resulting
validator-set epoch/version preconditions/postconditions; wrong epoch-transition target; wrong application /
live-application / staged-application / guarded-mutation / runtime-handoff / execution-preparation / mutation-execution /
commit-authorization / commit-receipt / post-commit-audit / external-publication / authority-activation-post-final-execution-confirmation / authority-activation-final-execution nonces; every wrong consumed /
ancestor decision id / request-id / intent-digest / transcript-digest; authority-activation-post-final-execution-confirmation-decision integrity
mismatch; custody / attestation / durable-replay required-and-mismatch.

## 8. MainNet refusal / authority policy evidence

MainNet-refusal cases (`2/0`): the MainNet domain is refused under the source-test policy; the reserved
production and MainNet policies/kinds are reachable but fail closed as unavailable; the default policy is `Disabled`
and fails before any artifact construction. The real release binary confirms `--help` exposes no execution-sink-prewrite / final-execution /
authority-activation / authority-activation-authorization / final-settlement / authority-lifecycle-completion / settlement / settlement-execution / external-publication / audit-ledger / audit-seal / durable-audit / publication / audit-write
CLI flag and the DevNet/TestNet/MainNet default surfaces stay silent and disabled/refused. MainNet authority
rotation/revocation remains **Red**.

## 9. Replay / idempotency evidence

Replay-recovery-idempotency cases (`7/0`): a present decision id is rejected as replay; an absent id is admitted; stale
governance-epoch / authority-sequence / validator-set-epoch / validator-set-version all fail closed. The
`recover_live_epoch_transition_authority_activation_execution_sink_prewrite_window` recovery path proves a no-prior window is clean and a
byte-identical prior window is a non-mutating idempotent replay (`staged_application_id=gov-decision-id-1`).

## 10. Fixture-state evidence

Fixture-state application is idempotent and applies only to the caller-owned in-memory
`LiveEpochTransitionAuthorityActivationExecutionSinkPrewriteFixtureState`, across all scenarios, explicitly distinct from production runtime,
durable replay, receipt, audit, audit-ledger, settlement, settlement-execution, and publication state.

## 11. Non-mutation evidence

The tracked `no_mutation_proof.txt` proves every outcome is non-mutating and no path
performs a live production validator-set change, production consensus/epoch mutation, production commit/finalization,
production receipt/audit write, durable replay overwrite, settlement, settlement-finalization, settlement-execution, final settlement,
authority-lifecycle completion, authority-activation-authorization, authority activation, final execution, post-final-execution confirmation, publication,
audit-finalization, audit-ledger commitment, external publication, `BasicHotStuffEngine::transition_to_epoch` on
production runtime state, `meta:current_epoch` write, `PAYLOAD_KIND_RECONFIG` injection, Run 070 call,
`LivePqcTrustState` mutation, trust-bundle sequence write, authority-marker write, session eviction, or MainNet
enablement. The denylist grep passed (90 patterns).

## 12. Tests run

The Run 354 release harness
(`scripts/devnet/run_354_production_live_epoch_transition_authority_activation_execution_sink_prewrite_release_binary.sh`) was
**re-executed end-to-end WITHOUT `RUN_354_SKIP_TESTS=1`** for this change set, so real per-target test results were
captured. It ran the full boundary regression corpus (38 test targets, run from the newest Run 353 boundary suite back
through the ancestor chain, plus `--lib pqc_authority` and the full `--lib` suite), each recording a real `rc=0` in the
tracked `summary.txt`. Across all targets **10,992 test cases passed and 0 failed**. The previous
`tests:skipped(RUN_354_SKIP_TESTS=1)` marker has been removed from the regenerated `summary.txt`, which now lists a real
`test:<target> rc=0` line for every target plus `lib:pqc_authority rc=0` and `lib:lib_all rc=0`. Representative results
(final values recorded verbatim in `summary.txt`):

* `cargo test -p qbind-node --test run_353_production_live_epoch_transition_authority_activation_execution_sink_prewrite_tests` — **1146 passed; 0 failed** (rc=0).
* `cargo test -p qbind-node --test run_351_production_live_epoch_transition_authority_activation_post_final_execution_confirmation_tests` — **939 passed; 0 failed** (rc=0).
* `cargo test -p qbind-node --test run_349_production_live_epoch_transition_authority_activation_final_execution_tests` — **732 passed; 0 failed** (rc=0).
* `cargo test -p qbind-node --test run_347_production_live_epoch_transition_authority_activation_execution_preparation_tests` — **732 passed; 0 failed** (rc=0).
* `cargo test -p qbind-node --test run_345_production_live_epoch_transition_authority_activation_authorization_tests` — **700 passed; 0 failed** (rc=0).
* `cargo test -p qbind-node --test run_343_production_live_epoch_transition_authority_lifecycle_post_completion_attestation_tests` — **700 passed; 0 failed** (rc=0).
* `cargo test -p qbind-node --lib pqc_authority` — **164 passed; 0 failed** (rc=0).
* `cargo test -p qbind-node --lib` — full library suite **1377 passed; 0 failed** (rc=0).
* `cargo build -p qbind-node --release` — succeeded.
* `cargo build -p qbind-node --example run_354_production_live_epoch_transition_authority_activation_execution_sink_prewrite_release_binary_helper --release` — succeeded.

The harness `summary.txt` records `verdict: PASS` for the full Run 353 → ancestor chain of boundary test suites plus
`--lib pqc_authority` and the full `--lib` suite, with real per-target `rc=0` results and no skip marker. The committed
`summary.txt` is treated as the final harness result for Run 354.

## 13. Security scans

* **Secret scanning** was run over all Run 354 changed files: the release helper
  (`crates/qbind-node/examples/run_354_..._helper.rs`), the harness script
  (`scripts/devnet/run_354_..._release_binary.sh`), the archive tracked files (`README.md`, `summary.txt`, `.gitignore`),
  this canonical evidence doc, the C4/C5 criteria doc, and the five narrative docs. **No secrets were found.**
* **CodeQL:** the `codeql_checker` tool was invoked for the Run 354 evidence-reconciliation change set. Its result is
  recorded verbatim in section 14 (`Skipped: all changes are trivial.` for this doc-only reconciliation diff; a prior
  invocation over the original example+harness change set was skipped for database size). In every case CodeQL performed
  no static analysis of Run 354 code, so **no CodeQL coverage is claimed for Run 354** and no skipped result is described
  as clean coverage.

## 14. C4/C5 matrix status

Full **C4 remains OPEN**. **C5 remains OPEN**. The live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness matrix
row is **Green (for scope)** — for release-binary-evidenced
live-epoch-transition-authority-activation-execution-sink-prewrite-boundary behavior only (source/test in Run 353; release-binary evidence
positive in Run 354). MainNet authority rotation/revocation remains **Red**. No prior Green-for-scope row is weakened.

**CodeQL provenance (recorded verbatim).** The `codeql_checker` tool was invoked for the Run 354 evidence-reconciliation
change set. Because this reconciliation change set is **documentation/evidence-only** (the harness-regenerated
`summary.txt` with real per-target `rc=0` results and this evidence doc's updated test-results section — no production
source, test, or build code was modified), the tool's verbatim result is: `Skipped: all changes are trivial.` A prior
invocation over the original Run 354 change set (which added the compiled Rust example and the bash harness) returned,
verbatim: `Analysis Result for 'rust'. Found 0 alerts: - rust: Analysis was skipped because the database size is too
large.` In both cases CodeQL performed **no** static analysis of Run 354 code — one skipped as trivial (doc-only diff),
the other skipped due to database size — so **no CodeQL coverage is claimed for Run 354** and neither skipped result is
described as a clean scan. Secret scanning (a separate tool) did run over all changed files and found no secrets.

## 15. Honest limitations

* Run 354 is release-binary evidence for the Run 353 boundary **only**; it does not prove a live production
  validator-set mutation, production epoch transition, production commit/finalization, production receipt write,
  production audit write, production external-publication, settlement, settlement-finalization, settlement-execution,
  final settlement, authority-lifecycle completion, authority activation, final execution, post-final-execution confirmation, publication, or MainNet readiness.
* The boundary is not wired into default production runtime and adds no public CLI flag.
* The `supp_*` supplemental Run 353 tests live in a private nested submodule that is not reachable from the helper
  entry point, so they are exercised by the `run_353_..._tests` test target (run by the harness) rather than by the
  release helper; the helper registers the core boundary cases that cover the required properties.
* **Helper structure deviation.** To reach the boundary dispatch from a release-example `fn main()`, the Run 353 boundary
  module (`run_353_authority_activation_execution_sink_prewrite`, nested inside the Run 349
  `run_349_authority_activation_final_execution` module in the source test) is re-exported as a `pub mod` in the helper
  example, with a `helper_main()` entry point added inside it. This is the only structural deviation from a verbatim copy
  of the Run 353 test module; it changes no boundary logic, adds no `#[test]`, and does not alter the production library.
* **`git_status: dirty` explanation.** The committed harness `summary.txt` may record `git_status: dirty` at its
  `git_commit`, because the `summary.txt` is generated by the harness **while the run is in progress**, so at generation
  time the remaining Run 354 deliverables may still be uncommitted/untracked: the evidence archive (`README.md`,
  `summary.txt`, `.gitignore`), this canonical evidence doc, and the final in-place doc refinements. Those files are
  committed as part of the same Run 354 change set that publishes this evidence doc; the `dirty` marker reflects only the
  in-progress harness snapshot and not any unexplained working-tree drift.
* **CodeQL coverage:** where the `codeql_checker` tool performs no analysis (e.g. a skipped result), **no CodeQL coverage
  is claimed for Run 354**; the skipped result is **not** described as clean coverage.

## 16. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. The live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness row is
**Green-for-scope only** (Run 353 source/test + Run 354 release-binary evidence). MainNet
authority rotation/revocation remains **Red**. There is no live production validator-set mutation, no production epoch
transition, no production commit/finalization, no production receipt/audit/audit-seal/audit-finalization/audit-ledger/
external-publication/durable-replay/settlement/settlement-finalization/settlement-execution/final-settlement/publication write, no default runtime wiring, no
public CLI enablement, and no C4/C5 closure claim.

## 17. Suggested Run 355 next step

Run 355 (source/test, odd cadence): implement the next non-mutating boundary that consumes a verified Run 353/354 live
epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness accept decision (`is_accept()` with
`Some(authority_activation_execution_sink_prewrite_artifact)`) — the next live epoch-transition authority-activation
execution-sink boundary — producing only a typed, deterministic, policy-gated,
non-mutating artifact that describes exactly what a future production execution sink must re-verify, moving a **new**
matrix row Red → Yellow, with release-binary evidence deferred to Run 356. Full C4 / C5 remain OPEN. Do not begin
production execution-sink wiring, MainNet enablement, or any live mutation.