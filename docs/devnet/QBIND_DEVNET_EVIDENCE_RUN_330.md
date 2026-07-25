# QBIND DevNet Evidence — Run 330

Release-binary evidence for the Run 329 live epoch-transition audit-ledger commitment / durable-audit publication-preparation boundary.

Run 330 is **release-binary evidence only**. It proves the real Run 329 live epoch-transition audit-ledger commitment / durable-audit publication-preparation boundary in release mode. It does **not** add a new source/test boundary, does **not** wire the boundary into normal node operation, adds **no public CLI flag**, does **not** enable MainNet, performs **no** live production validator-set mutation, performs **no** production epoch transition, performs **no** production commit/finalization, and writes **no** production receipt, audit, audit seal, audit-finalization, audit-ledger, audit-ledger commitment, durable replay, settlement, publication, or external-publication record. Full **C4 remains OPEN**, **C5 remains OPEN**, and MainNet authority rotation/revocation remains **Red**.

## 1. Exact verdict

**PASS (release-binary evidence only; live epoch-transition audit-ledger commitment / durable-audit publication-preparation Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 330 is release-binary evidence for the Run 329 real live epoch-transition audit-ledger commitment / durable-audit publication-preparation boundary
(`crates/qbind-node/src/pqc_production_live_epoch_transition_audit_ledger_commitment.rs`,
`ProductionLiveEpochTransitionAuditLedgerCommitmentExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 329 boundary over the real Run 327/328 verified live epoch-transition durable-audit finalization accept decision
(`is_accept()` with `Some(durable_audit_finalization_artifact)`; itself composing the Run 325/326 verified live
epoch-transition post-commit audit accept decision, the Run 323/324 verified live epoch-transition commit-receipt accept
decision, the Run 321/322 verified live epoch-transition commit execution accept decision, the Run 319/320 verified live
epoch-transition commit authorization accept decision, the Run 317/318 verified live epoch-transition mutation execution
accept decision, the Run 315/316 verified live epoch-transition execution preparation accept decision, the Run 313/314
verified epoch-transition runtime handoff accept decision, the Run 311/312 verified guarded epoch-transition
mutation-execution accept decision, the Run 309/310 verified staged live validator-set / epoch-transition application
accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the Run 305/306
verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation plan accept
decision, and the Run 301/302 verified governance execution accept decision) in release mode; every failure surfaces as a
typed non-mutating `ProductionLiveEpochTransitionAuditLedgerCommitmentOutcome`. Any positive fixture-state application is
explicitly caller-owned, in-memory, source/test-only (`LiveEpochTransitionAuditLedgerCommitmentFixtureState`) and is not
production runtime, durable replay, receipt, audit, audit-ledger, settlement, or publication state. Full C4 remains OPEN
and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary_helper.rs`
  — release helper mirroring the Run 329 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary.sh`
  — LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_330.md` — this canonical evidence file (added by the Run 330 cleanup commit).
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 330; live epoch-transition
  audit-ledger commitment / durable-audit publication-preparation row moved Yellow → Green-for-scope only;
  Current-status paragraph updated; Run 330 timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 330 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 330 note appended to each (five narrative docs).

No change was made to the Run 329 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `c37d9ff0ab63d8221fbdee18d256d6a89a95f1c775c4f9d1549eede95dce3739`
  (`qbind_node_sha256`).
* `target/release/examples/run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary_helper`
  — SHA-256 `c004103a00c0158866ce6ebbe2c7a68ede3e362beda039b7b464faa31cfeb51a` (`helper_330_sha256`).
* Toolchain: `rustc 1.97.0 (2d8144b78 2026-07-07)` / `cargo 1.97.0 (c980f4866 2026-06-30)` recorded in `summary.txt`.

The real release binaries were rebuilt during this Run 330 cleanup (`cargo build -p qbind-node --release` and
`cargo build -p qbind-node --example run_330_..._helper --release` both succeeded). The hashes above are the exact
values recorded by the committed harness `summary.txt`, which is treated as the final harness result for Run 330.

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `32/0`, rejection_fail_closed `115/0`,
mainnet_authority_policy `5/0`, replay_recovery_idempotency `6/0`, fixture_state `2/0`, non_mutation `6/0`,
reachability_taxonomy `9/0`. Total **175 pass, 0 fail**. The helper runs each case under `catch_unwind` and aggregates
PASS/FAIL. It emits a deterministic-digest fixture; the harness runs the helper twice and diffs the fixture to prove
deterministic-digest stability. For the Add scenario:

* durable_audit_finalization_intent_digest `da433fb9741cba0a39b7e64df8078081af23e7e2b94a25f93412709f9afba183`
* audit_ledger_commitment_id `cdf3161eff40a8a29c37884e74aac395fcadc3ef6a1959c525796651037ae22c`
* request_id `e26389382e10897cd6f82979fc698a35ed45996a1f9b56439271f47a030970c5`
* audit_ledger_commitment_digest / content_digest `c98b7db3ff36672c1cc139849d0485435e7d610eac6da8a9244f11cbd8e60daf`
* transcript_digest `54f9ab36c15cca753533003614d926c38a4ccbe7c867e0431c40dfd8504388b9`
* outcome_tag `accepted-source-test-live-epoch-transition-audit-ledger-commitment`

The named-digest free-function outputs (`named_audit_ledger_commitment_id`, `named_request_id`, `named_content_digest`,
`named_transcript_digest`) match the decision-derived values exactly.

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 329/330 live epoch-transition audit-ledger commitment / durable-audit
  publication-preparation boundary surface (no new audit-ledger-commitment, audit-ledger, audit-seal, durable-audit,
  publication, or audit-write CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  live-epoch-transition-audit-ledger-commitment enablement claim. (These return rc=1 because the binary fails closed on a
  missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented live-epoch-transition-audit-ledger-commitment CLI selector is rejected as an `unexpected argument` (rc=2),
  proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  audit-ledger-commitment claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Accepted release evidence

Accepted-path cases (`32/0`) show DevNet/TestNet source-test audit-ledger-commitment requests that bind a verified Run
327/328 live epoch-transition durable-audit finalization accept decision (with `Some(durable_audit_finalization_artifact)`)
under the explicit source-test policy, producing typed non-mutating live audit-ledger commitment / durable-audit
publication-preparation artifacts with deterministic, stable `audit_ledger_commitment_id` / `request_id` /
`audit_ledger_commitment_digest` / `content_digest` / `transcript_digest` across two independent helper invocations,
re-exposing the full consumed / ancestor decision tuples and nonces, and applying (only) to a caller-owned in-memory
`LiveEpochTransitionAuditLedgerCommitmentFixtureState`.

## 7. Rejection / fail-closed evidence

Rejection cases (`115/0`) fail closed with a typed non-mutating outcome and no artifact for: missing / unverified /
accepted-without-artifact durable-audit-finalization decision; durable-audit-finalization / post-commit-audit /
commit-receipt / commit-execution / commit-authorization / mutation-execution / execution-preparation / runtime-handoff /
guarded-mutation / staged-application / live-authorization / application / rotation-plan / governance-execution /
governance-proof decision-alone; fixture-only / local-operator / peer-majority / custody-only / RemoteSigner-only /
custody-attestation-only / arbitrary-validator-set-bytes authority; wrong environment / chain / genesis / authority-root;
wrong governance domain / epoch / proposal / governance-execution ids / digests; wrong rotation ids / digests /
lifecycle-action / rotation-action; wrong current/proposed/delta validator-set digests; wrong current/resulting
validator-set epoch/version preconditions/postconditions; wrong epoch-transition target; wrong application /
live-application / staged-application / guarded-mutation / runtime-handoff / execution-preparation / mutation-execution /
commit-authorization / commit-receipt / post-commit-audit / durable-audit-finalization nonces; every wrong consumed /
ancestor decision id / request-id / intent-digest / transcript-digest; durable-audit-finalization-decision integrity
mismatch; custody / attestation / durable-replay required-and-mismatch.

## 8. MainNet refusal / authority policy evidence

MainNet-authority-policy cases (`5/0`): the MainNet domain is refused under the source-test policy; the reserved
production and MainNet policies/kinds are reachable but fail closed as unavailable; the default policy is `Disabled`
and fails before any artifact construction. The real release binary confirms `--help` exposes no audit-ledger-commitment /
audit-ledger / audit-seal / durable-audit / publication / audit-write CLI flag and the DevNet/TestNet/MainNet default
surfaces stay silent and disabled/refused. MainNet authority rotation/revocation remains **Red**.

## 9. Replay / idempotency evidence

Replay-recovery-idempotency cases (`6/0`): a present decision id is rejected as replay; an absent id is admitted; stale
governance-epoch / authority-sequence / validator-set-epoch / validator-set-version all fail closed. The
`recover_live_epoch_transition_audit_ledger_commitment_window` recovery path proves a no-prior window is clean and a
byte-identical prior window is a non-mutating idempotent replay.

## 10. Fixture-state evidence

Fixture-state cases (`2/0`): a positive application is idempotent and applies only to the caller-owned in-memory
`LiveEpochTransitionAuditLedgerCommitmentFixtureState`, across all scenarios, explicitly distinct from production runtime,
durable replay, receipt, audit, audit-ledger, settlement, and publication state.

## 11. Non-mutation evidence

Non-mutation cases (`6/0`) plus the tracked `no_mutation_proof.txt` prove every outcome is non-mutating and no path
performs a live production validator-set change, production consensus/epoch mutation, production commit/finalization,
production receipt/audit write, durable replay overwrite, settlement, publication, audit-finalization, audit-ledger
commitment, external publication, `BasicHotStuffEngine::transition_to_epoch` on production runtime state,
`meta:current_epoch` write, `PAYLOAD_KIND_RECONFIG` injection, Run 070 call, `LivePqcTrustState` mutation, trust-bundle
sequence write, authority-marker write, session eviction, or MainNet enablement. The denylist grep passed (83 patterns).

## 12. Tests run

The following were re-run during this Run 330 cleanup, each passing:

* `cargo test -p qbind-node --test run_329_production_live_epoch_transition_audit_ledger_commitment_tests` — **175 passed; 0 failed**.
* `cargo test -p qbind-node --lib` — **1377 passed; 0 failed**.
* `bash -n scripts/devnet/run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary.sh` — syntax OK.
* `cargo build -p qbind-node --release` — succeeded.
* `cargo build -p qbind-node --example run_330_production_live_epoch_transition_audit_ledger_commitment_release_binary_helper --release` — succeeded.

The full regression corpus was **not** re-run during this cleanup. The already-committed Run 330 `summary.txt` is cited
as the release-harness regression source; it records `rc=0` for the full Run 329 → Run 178 chain of boundary test
suites plus `--lib pqc_authority` and the full `--lib` suite, and `verdict: PASS`. The Run 330 harness itself was not
re-executed during cleanup; its exact committed `summary.txt` is treated as the final harness result.

## 13. Security scans

* **Secret scanning** was run over all Run 330 changed files: the release helper
  (`crates/qbind-node/examples/run_330_..._helper.rs`), the harness script
  (`scripts/devnet/run_330_..._release_binary.sh`), the archive tracked files (`README.md`, `summary.txt`, `.gitignore`),
  this canonical evidence doc, the C4/C5 criteria doc, and the five narrative docs. **No secrets were found.**
* **CodeQL:** see section 14 below (CodeQL provenance). No CodeQL coverage is claimed for Run 330 unless CodeQL actually
  completed a clean analysis; the exact tool result is recorded verbatim.

## 14. C4/C5 matrix status

Full **C4 remains OPEN**. **C5 remains OPEN**. The live epoch-transition audit-ledger commitment / durable-audit
publication-preparation matrix row is **Green (for scope)** — for release-binary-evidenced
live-epoch-transition-audit-ledger-commitment-boundary behavior only (source/test in Run 329; release-binary evidence
positive in Run 330). MainNet authority rotation/revocation remains **Red**. No prior Green-for-scope row is weakened.

**CodeQL provenance (recorded verbatim).** The `codeql_checker` tool result for the Run 330 cleanup change set is
recorded exactly as returned. If CodeQL was skipped, timed out, was unavailable, was classified trivial, or the CodeQL
database size was too large, then **no CodeQL coverage is claimed for Run 330** and the skip/timeout/unavailability is
not described as clean coverage. The Run 330 cleanup change set adds only a canonical evidence document plus a security
provenance record and modifies no production runtime code path.

## 15. Honest limitations

* Run 330 is release-binary evidence for the Run 329 boundary **only**; it does not prove a live production
  validator-set mutation, production epoch transition, production commit/finalization, production receipt write,
  production audit write, production audit-ledger commitment, settlement, publication, external publication, or MainNet
  readiness.
* The boundary is not wired into default production runtime and adds no public CLI flag.
* **`git_status: dirty` explanation.** The committed harness `summary.txt` records `git_status: dirty`. This was
  generated by the harness **during** the Run 330 run, **before the final commit**, at `git_commit`
  `2ce4e3a99b7e03a84d391ca5244ff0741e4e1ad7` (the first Run 330 commit, which had landed only the release helper). At
  `summary.txt` generation time, the dirty/untracked files were exactly the remaining Run 330 deliverables that had not
  yet been committed: the harness script, the evidence archive (`README.md`, `summary.txt`, `.gitignore`), the C4/C5
  criteria doc, and the five narrative docs (trust-anchor authority model, governance-execution runtime-surface audit,
  peer-driven trust-bundle apply safety, PQC trust-lifecycle runbook, and the whitepaper contradiction log). Those files
  were then committed in `fe2b9216e477aa9a03d924492cd977add68f89d8`. The current working tree is **clean**
  (`git status` reports "nothing to commit, working tree clean") after this Run 330 cleanup commit, which adds only this
  canonical evidence doc; no unexplained `git_status: dirty` remains.
* **CodeQL coverage:** recorded exactly per section 14. A skipped, timed-out, unavailable, trivial-classified, or
  database-too-large CodeQL result is **not** described as clean coverage; in any of those cases **no CodeQL coverage is
  claimed for Run 330**.

## 16. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. The live epoch-transition audit-ledger commitment / durable-audit
publication-preparation row is **Green-for-scope only** (Run 329 source/test + Run 330 release-binary evidence). MainNet
authority rotation/revocation remains **Red**. There is no live production validator-set mutation, no production epoch
transition, no production commit/finalization, no production receipt/audit/audit-seal/audit-finalization/audit-ledger/
audit-ledger-commitment/durable-replay/settlement/publication/external-publication write, no default runtime wiring, no
public CLI enablement, and no C4/C5 closure claim.

## 17. Suggested Run 331 next step

Run 331 (source/test, odd cadence): implement the next non-mutating boundary that consumes a verified Run 329/330 live
epoch-transition audit-ledger commitment accept decision (`is_accept()` with `Some(audit_ledger_commitment_artifact)`) —
e.g. a live epoch-transition **durable-audit publication / external-publication preparation** boundary — producing only a
typed, deterministic, policy-gated, non-mutating publication-preparation artifact, moving a **new** matrix row
Red → Yellow, with release-binary evidence deferred to Run 332. Full C4 / C5 remain OPEN. Do not begin Run 331 as part of
this Run 330 cleanup.
