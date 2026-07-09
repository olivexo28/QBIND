# QBIND DevNet Evidence — Run 312

Release-binary evidence for the Run 311 guarded epoch-transition mutation executor boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; guarded epoch-transition mutation executor Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 312 is release-binary evidence for the Run 311 real guarded epoch-transition mutation
executor boundary (`crates/qbind-node/src/pqc_production_guarded_epoch_transition_mutation_executor.rs`,
`ProductionGuardedEpochTransitionMutationExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 311 boundary over the real Run 309/310 verified staged live validator-set / epoch-transition application accept
decision (`is_accept()` with `Some(staged_application_record)`; itself composing the Run 307/308 verified live
validator-set application authorization accept decision, the Run 305/306 verified validator-set rotation application
accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified
governance execution accept decision) in release mode; every failure surfaces as a typed non-mutating
`ProductionGuardedEpochTransitionMutationOutcome`. Any positive fixture-ledger application is explicitly caller-owned,
in-memory, source/test-only (`GuardedEpochTransitionFixtureLedger`) and is not production runtime state. Full C4
remains OPEN and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_312_production_guarded_epoch_transition_mutation_executor_release_binary_helper.rs`
  — new release helper mirroring the Run 311 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_312_production_guarded_epoch_transition_mutation_executor_release_binary.sh`
  — new LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_312_production_guarded_epoch_transition_mutation_executor_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_312.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 312; guarded epoch-transition mutation
  executor row moved Yellow → Green-for-release-binary-evidenced-scope-only; C4 summary updated; Run 312 timeline
  entry appended.
* `docs/whitepaper/contradiction.md` — Run 312 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 312 note appended to each.

No change was made to the Run 311 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_312_production_guarded_epoch_transition_mutation_executor_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 recorded as `qbind_node_sha256` in `summary.txt`.
* `target/release/examples/run_312_production_guarded_epoch_transition_mutation_executor_release_binary_helper`
  — SHA-256 recorded as `helper_312_sha256` in `summary.txt`.
* Toolchain: `rustc 1.96.1`, `cargo 1.96.1` (recorded in `summary.txt`).

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `29/0`, rejection_fail_closed `59/0`,
mainnet_authority_policy `6/0`, replay_recovery_idempotency `10/0`, fixture_ledger `3/0`, non_mutation `7/0`,
reachability_taxonomy `10/0`. Total `124` pass, `0` fail. The helper runs each case under `catch_unwind` and aggregates
PASS/FAIL. It emits a deterministic-digest fixture; the harness runs the helper twice and diffs the fixture to prove
deterministic-digest stability:

* authorization_intent_digest `2e68313bc36f5567fe4508ac7935c7ea093660a718c0f34fddcfd10a1b1f2cfb`
* staged_application_id `gov-decision-id-1`
* intent_digest `0d260ebd5806820fa490b8aae10ce3cd4f7e73c47a5732ac45403effade06d27`
* record_digest `0d260ebd5806820fa490b8aae10ce3cd4f7e73c47a5732ac45403effade06d27`
* request_id `f303cac42dc1dcf71b5813f525b34fde6a47ffe3fdd0b179014a38cd39fbf862`
* transcript_digest `7c622ac07f27a0b39988b7aa4b0bc7378d4859a2b2ac20d5a529253cc0d4470e`
* outcome_tag `accepted-source-test-guarded-epoch-transition-mutation`

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 311/312 guarded epoch-transition mutation boundary surface (no new CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  guarded-epoch-transition-mutation enablement claim. (These return rc=1 because the binary fails closed on a missing
  `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented guarded-epoch-transition-mutation CLI selector is rejected as an `unexpected argument` (rc=2), proving no
  such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  guarded-mutation claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Guarded epoch-transition mutation policy / kind / decision taxonomy release evidence

The helper exercises `ProductionGuardedEpochTransitionMutationExecutorPolicy` (default `Disabled`, explicit
source-test policy), `ProductionGuardedEpochTransitionMutationExecutorKind`, `GuardedEpochTransitionMutationKind`,
`GuardedEpochTransitionMutationAuthoritySource`, and the typed outcome taxonomy
`ProductionGuardedEpochTransitionMutationOutcome` / `ProductionGuardedEpochTransitionMutationRecoveryOutcome` in
release mode. Reachability greps confirm the taxonomy enums are present in the source module and driven by the helper.

## 7. Verified staged application composition release evidence

The boundary consumes a **verified** Run 309/310 staged live validator-set / epoch-transition application accept
decision via `GuardedEpochTransitionMutationAuthoritySource`, constructed from the real Run 309/310
`ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision` that `is_accept()` and carries
`Some(staged_application_record)` (itself composing the Run 307/308 verified live validator-set application
authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision, the Run
303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept
decision). The boundary never self-authorizes: a missing / unverified / accepted-without-staged-record /
application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone /
fixture / wrong-binding staged input yields a typed fail-closed outcome and never a live validator-set mutation.

## 8. Canonical validator-set model composition release evidence

Run 312 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable replay
RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain
governance proof verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent, Run
305/306 validator-set rotation application executor, Run 307/308 live validator-set application authorization, and Run
309/310 staged live validator-set / epoch-transition application executor rows remain
Green-for-release-binary-evidenced-scope only. The executor re-exposes the current/proposed/delta validator-set
digests referenced by the verified staged decision, binds the staged-application-decision / authorization-decision /
application-decision / request-id / transcript / staged-record digests canonically plus the epoch-transition target
and application / live-application / staged-application / guarded-mutation nonces, and refuses custody-only /
RemoteSigner-only / attestation-only / governance-execution-intent-alone / rotation-plan-alone /
application-decision-alone / staged-application-decision-alone material as authority; only a verified staged live
validator-set / epoch-transition application decision with `Some(staged_application_record)` binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`29/0`) show DevNet/TestNet source-test guarded-mutation requests that bind a verified Run
309/310 staged live validator-set / epoch-transition application accept decision (with `Some(staged_application_record)`)
under the explicit source-test policy produce typed non-mutating guarded mutation-execution records with stable
staged-record / intent / request-id / transcript digests and a deterministic `staged_application_id`, and never apply
a live production validator-set change.

## 10. Rejection / fail-closed release evidence

Rejection cases (`59/0`) show missing / unverified staged decision, accepted-decision-without-staged-record,
application-decision-alone, rotation-plan-alone, governance-execution-intent-alone, governance-proof-alone,
fixture-only material, local-operator, peer-majority, custody-only, remote-signer-only, custody-attestation-only,
arbitrary-validator-set-bytes, wrong-field governance / rotation / validator-set binding,
staged-application-decision-integrity mismatch, wrong epoch-transition target, wrong application / live-application /
staged-application nonce, replayed guarded-mutation id, and stale governance-epoch / authority-sequence /
validator-set-epoch / validator-set-version inputs each fail closed as a typed non-mutating
`ProductionGuardedEpochTransitionMutationOutcome` with no fallback to fixture / local-operator / peer-majority /
governance-proof-alone / governance-execution-intent-alone / rotation-plan-alone / application-decision-alone /
staged-application-decision-alone / RemoteSigner / custody-only / custody-attestation material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`6/0`) show `MainNet` is refused absent production authority criteria (fixture /
local-operator / peer-majority / remote-signer-only / custody-alone / custody-attestation-alone / governance-proof-alone
/ governance-execution-intent-alone / rotation-plan-alone / application-decision-alone / staged-application-decision-alone
/ accepted-without-staged-record are all insufficient), the default policy is `Disabled` (fails closed before any
binding or record construction), the reserved production executor policy/kind is reachable but returns the typed
unavailable outcome, and a valid DevNet/TestNet source-test accept does not enable MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`10/0`) show `recover_guarded_epoch_transition_mutation_window` and the
`GuardedEpochTransitionMutationReplaySet` boundary reject replays idempotently and recover the guarded-mutation window
deterministically without production mutation; conflicting staged-application-decision / request-id / intent-digest in
the same window fail closed rather than being treated as idempotent, and stale epoch/sequence/version inputs fail
closed in evaluation. A divergent guarded-mutation nonce yields a different `request_id` / `staged_application_id`, so
a persisted window is not idempotently matched and cannot be replayed into an accept. The Run 311 boundary also
exposes an explicit `WrongStagedApplicationNonce` reject and `expected_staged_application_nonce` field, so a wrong
staged-application nonce is additionally proven through a dedicated fail-closed variant.

## 13. Fixture-ledger release evidence

Fixture-ledger cases (`3/0`) exercise the caller-owned in-memory `GuardedEpochTransitionFixtureLedger` used only by
source/test evidence: an accepted guarded-mutation record can be applied into the explicit test-owned ledger
(`apply_prepared_execution`), applied ids are tracked (`has_applied` / `applied_execution_ids`), and re-application is
idempotent. This ledger is not production runtime state, is not consensus/validator/epoch state, and is never
constructed by the production binary.

## 14. Non-mutation evidence

Non-mutation cases (`7/0`) plus the harness no-mutation proof confirm the boundary produces only typed non-mutating
guarded mutation-execution records and every reject is non-mutating with respect to production state. The release
helper drives the real Run 311 `ProductionGuardedEpochTransitionMutationExecutor` only through the source/test
boundary, only for DevNet/TestNet identities on the accept path. It performs **no Run 070 call, no `LivePqcTrustState`
mutation, no live validator-set mutation, no consensus validator-set mutation, no epoch-counter mutation, no
`BasicHotStuffEngine::transition_to_epoch` call on production runtime state, no `meta:current_epoch` write, no
`PAYLOAD_KIND_RECONFIG` block injection, no trust swap, no session eviction, no PQC trust-bundle sequence write, no
authority marker write, no durable replay overwrite, no settlement, no external publication, and no raw local
production signing key load.** The only mutation any path performs is into the explicit caller-owned in-memory
source/test fixture ledger.

## 15. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the boundary, adds no CLI flag, and enables neither the boundary
by default nor MainNet. S1–S6 confirm the default surfaces are silent on guarded epoch-transition mutation
enablement, an invented guarded-mutation CLI selector is rejected as an unexpected argument, and the denylist of
forbidden positive-claim patterns is clean across captured logs and helper output (help text and helper summary
excluded).

## 16. Tests run and results

Harness exit `0`. Regression corpus (all `rc=0`), recorded in `summary.txt`: `run_311` (primary Run 311 source tests)
first, then `run_309`, `run_307`, `run_305`, `run_303`, `run_301`, `run_299`, `run_297`, `run_295`, `run_293`,
`run_291`, `run_186`, `run_178`, `run_203`, `run_201`, `run_194`, `run_188`, `--lib pqc_authority`, and `--lib`.

## 17. Security scans

* Secret scanning over the changed files reported **no secrets**.
* CodeQL: the `codeql_checker` tool was invoked over the Run 312 change set (new Rust example helper + new harness
  shell script + documentation/evidence artifacts). Any alerts it surfaced were investigated and addressed; the exact
  status is recorded in the PR/session summary. No clean-CodeQL-coverage claim is made beyond what the tool actually
  reported.

## 18. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary readiness from
production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292 durable replay RocksDB, Run 294
RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain governance proof
verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent boundary, Run 305/306
validator-set rotation application / epoch-transition executor boundary, Run 307/308 live validator-set application /
epoch-transition authorization boundary, Run 309/310 staged live validator-set / epoch-transition application
executor boundary, and now the Run 311/312 guarded epoch-transition mutation executor boundary. Red production rows
(MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility /
incident response, full MainNet release-binary evidence under production custody) remain Red. Run 312 does not
reinterpret this as C4/C5 closure and does not make guarded epoch-transition mutation MainNet-ready.

## 19. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no live validator-set, consensus, or epoch-counter mutation; no
  `BasicHotStuffEngine::transition_to_epoch` call on production runtime state; no `meta:current_epoch` write; no
  `PAYLOAD_KIND_RECONFIG` block injection; no trust-bundle sequence or authority marker file writes; no settlement /
  external publication.
* A verified staged live validator-set / epoch-transition application decision is never turned into a live production
  mutation — accepts produce typed non-mutating guarded mutation-execution records only; the only mutation is into an
  explicit caller-owned in-memory source/test fixture ledger.
* Missing / unverified / accepted-without-staged-record staged decisions, and application-decision-alone /
  rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator /
  peer-majority / custody-only / RemoteSigner-only / attestation-only / arbitrary-bytes material, are never accepted
  as production authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over all changed files reported **no secrets**.

## 20. Honest limitations

Run 312 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the
boundary into the default runtime, and does not implement MainNet authority rotation/revocation, live validator-set
mutation, consensus reconfiguration, epoch transition, settlement, or external publication. It closes only the Run
311 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310
Green-for-scope statuses. The `ProductionGuardedEpochTransitionMutationError` type named generically in the task does
not exist as a separate enum; the real boundary surfaces every failure as a typed non-mutating variant of
`ProductionGuardedEpochTransitionMutationOutcome`. These substitutions are recorded in the helper module doc, the
harness header, the archive README, and here. The tracked `summary.txt` records `git_status: dirty` because it
captures the working-tree state at harness time (the newly generated `summary.txt` was itself untracked and this
canonical evidence file plus the doc updates were pending commit); all per-run generated artifacts are `.gitignore`d.

## 21. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 312 makes no C4/C5 closure claim, no MainNet-readiness claim, and no
runtime default-enablement claim. The guarded epoch-transition mutation executor row is Green-for-scope only; MainNet
authority rotation/revocation under production custody remains Red.

## 22. Suggested Run 313 next step

Proceed to the next Red-row closure campaign toward MainNet authority rotation/revocation under production custody.
**Run 313 — source/test next-stage guarded/live epoch-transition mutation boundary** (or the next narrowest Red row
per the C4/C5 matrix): source/test only, deterministic, default `Disabled`/fail-closed, MainNet refused, consuming a
verified Run 311/312 guarded mutation-execution record and producing the next typed artifact toward a future live
mutation, without live production validator-set mutation or epoch transition, with release-binary evidence deferred to
Run 314.
