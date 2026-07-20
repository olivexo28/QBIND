# QBIND DevNet Evidence — Run 322

Release-binary evidence for the Run 321 live epoch-transition commit execution boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; live epoch-transition commit execution Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 322 is release-binary evidence for the Run 321 real live epoch-transition commit execution boundary
(`crates/qbind-node/src/pqc_production_live_epoch_transition_commit_execution.rs`,
`ProductionLiveEpochTransitionCommitExecutionExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 321 boundary over the real Run 319/320 verified live epoch-transition commit-authorization accept decision
(`is_accept()` with `Some(commit_authorization_artifact)`; itself composing the Run 317/318 verified live epoch-transition mutation execution accept decision, the Run 315/316 verified live epoch-transition execution preparation accept decision, the Run 313/314 verified epoch-transition runtime
handoff accept decision, the Run 311/312 verified guarded epoch-transition mutation-execution accept decision, the Run
309/310 verified staged live validator-set / epoch-transition application accept decision, the Run 307/308 verified live
validator-set application authorization accept decision, the Run 305/306 verified validator-set rotation application
accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified
governance execution accept decision) in release mode; every failure surfaces as a typed non-mutating
`ProductionLiveEpochTransitionCommitExecutionOutcome`. Any positive fixture-state application is explicitly
caller-owned, in-memory, source/test-only (`LiveEpochTransitionCommitExecutionFixtureState`) and is not production
runtime state. Full C4 remains OPEN and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_322_production_live_epoch_transition_commit_execution_release_binary_helper.rs`
  — new release helper mirroring the Run 321 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_322_production_live_epoch_transition_commit_execution_release_binary.sh`
  — new LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_322_production_live_epoch_transition_commit_execution_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_322.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 322; live epoch-transition commit
  execution row moved Yellow → Green-for-release-binary-evidenced-scope-only; Current-status paragraph updated; Run 322
  timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 322 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 322 note appended to each.

No change was made to the Run 321 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_322_production_live_epoch_transition_commit_execution_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `8040b7be0393835fbb320abfd9d5a4e8096c96c8a720f370ec2d9bfbf43a27de`
  (`qbind_node_sha256`).
* `target/release/examples/run_322_production_live_epoch_transition_commit_execution_release_binary_helper`
  — SHA-256 `70730da3f165e606dc352b90d58ac111762b3dec2d479a55c3653ccf7db7286e` (`helper_320_sha256`).
* Toolchain: `rustc 1.97.0 (2d8144b78 2026-07-07)` / `cargo 1.97.0 (c980f4866 2026-06-30)` recorded in `summary.txt`.

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `31/0`, rejection_fail_closed `109/0`,
mainnet_authority_policy `5/0`, replay_recovery_idempotency `6/0`, fixture_state `2/0`, non_mutation `5/0`,
reachability_taxonomy `9/0`. Total `167` pass, `0` fail. The helper runs each case under `catch_unwind` and aggregates
PASS/FAIL. It emits a deterministic-digest fixture; the harness runs the helper twice and diffs the fixture to prove
deterministic-digest stability:

* commit_authorization_intent_digest `7377b97e4de50930e9d8f112910de99049c8ed7f583dea38022c3c6b6a5779b4`
* commit_execution_id `19a6f2a2c5ecdf081b5c801d9110d867568bfc548df587bdf2fcc94bc94bb53e`
* request_id `ac99c0afcffb6ae7c68e09e84b4bf2408c9a6a80704196f70e38be9cf7957e68`
* commit_execution_digest / content_digest `07ac9d0edd46177310914f3b08216626dc6a16bcdb9cf72d06c961fd4ecfc317`
* transcript_digest `90fb5d41102285698889256cd8aea2ee6dbed064af9cad87aaea4c8f4690c830`
* outcome_tag `accepted-source-test-live-epoch-transition-commit-execution`

The named-digest free-function outputs (`named_commit_execution_id`, `named_request_id`, `named_content_digest`,
`named_transcript_digest`) match the decision-derived values exactly.

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 321/322 live epoch-transition commit execution boundary surface (no new CLI
  flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  live-epoch-transition-commit-execution enablement claim. (These return rc=1 because the binary fails closed on a
  missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented live-epoch-transition-commit-execution CLI selector
  (`--p2p-commit-execution-policy`) is rejected as an `unexpected argument` (rc=2), proving no such public CLI flag
  exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  commit-execution claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Live epoch-transition commit execution policy / kind / decision taxonomy release evidence

The helper exercises `ProductionLiveEpochTransitionCommitExecutionExecutorPolicy` (default `Disabled`, explicit
source-test policy), `ProductionLiveEpochTransitionCommitExecutionExecutorKind`,
`LiveEpochTransitionCommitExecutionKind`, `LiveEpochTransitionCommitExecutionAuthoritySource`, and the typed
outcome taxonomy `ProductionLiveEpochTransitionCommitExecutionOutcome` /
`ProductionLiveEpochTransitionCommitExecutionRecoveryOutcome` in release mode. Reachability greps confirm the
taxonomy enums, the `ProductionLiveEpochTransitionCommitExecutionArtifact`, and
`recover_live_epoch_transition_commit_execution_window` are present in the source module and driven by the helper.

## 7. Verified live epoch-transition commit authorization composition release evidence

The boundary consumes a **verified** Run 319/320 live epoch-transition commit-authorization accept decision via
`LiveEpochTransitionCommitExecutionAuthoritySource::VerifiedCommitAuthorizationDecision`, constructed from the real
Run 319/320 `ProductionLiveEpochTransitionCommitAuthorizationDecision` that `is_accept()` and carries
`Some(commit_authorization_artifact)` (itself composing the Run 317/318 verified live epoch-transition mutation execution accept decision, the Run 315/316 verified live epoch-transition execution preparation accept decision, the Run 313/314 verified epoch-transition runtime handoff accept
decision, the Run 311/312 verified guarded epoch-transition mutation-execution accept decision, the Run 309/310 verified
staged live validator-set / epoch-transition application accept decision, the Run 307/308 verified live validator-set
application authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision,
the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution
accept decision). The boundary never self-authorizes: a missing / unverified / accepted-without-artifact /
commit-authorization-alone / runtime-handoff-alone / guarded-mutation-alone / staged-application-alone /
live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone /
governance-proof-alone / fixture / wrong-binding input yields a typed fail-closed outcome and never a live production
validator-set mutation.

## 8. Canonical validator-set model composition release evidence

Run 322 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable replay
RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain
governance proof verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent, Run
305/306 validator-set rotation application executor, Run 307/308 live validator-set application authorization, Run
309/310 staged live validator-set / epoch-transition application executor, Run 311/312 guarded epoch-transition
mutation executor, Run 313/314 epoch-transition runtime handoff, Run 315/316 live epoch-transition execution
preparation, and Run 319/320 live epoch-transition commit authorization rows remain Green-for-release-binary-evidenced-scope only. The executor re-exposes the
current/proposed/delta validator-set digests referenced by the verified commit-authorization decision, binds the
commit-authorization-decision / runtime-handoff-decision / guarded-mutation-decision / staged-application-decision /
authorization-decision / request-id / transcript / preparation digests canonically plus the epoch-transition target,
the commit-authorization / runtime-handoff / application / live-application / staged-application / guarded-mutation
nonces, the commit-execution nonce, and the exact future-executor postconditions (expected previous / resulting set
digests + epoch/version, delta digest, target consensus epoch, required governance epoch / authority sequence / replay
window), and refuses custody-only / RemoteSigner-only / attestation-only / governance-execution-intent-alone /
rotation-plan-alone / application-decision-alone / staged-application-decision-alone / guarded-mutation-decision-alone /
runtime-handoff-decision-alone / commit-authorization-decision-alone material as authority; only a verified live
epoch-transition commit-authorization decision with `Some(commit_authorization_artifact)` binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`31/0`) show DevNet/TestNet source-test commit-execution requests that bind a verified Run
319/320 live epoch-transition commit-authorization accept decision (with `Some(commit_authorization_artifact)`) under the
explicit source-test policy produce typed non-mutating live-commit execution artifacts with stable content /
content / request-id / transcript digests and a deterministic `commit_execution_id`, and never apply a live production
validator-set change.

## 10. Rejection / fail-closed release evidence

Rejection cases (`109/0`) show missing / unverified commit-authorization decision, accepted-decision-without-artifact,
commit-authorization-alone, runtime-handoff-alone, guarded-mutation-alone, staged-application-alone,
live-authorization-alone, application-decision-alone, rotation-plan-alone, governance-execution-intent-alone,
governance-proof-alone, fixture-only material, local-operator, peer-majority, custody-only, remote-signer-only,
custody-attestation-only, arbitrary-validator-set-bytes, wrong-field commit-authorization / runtime-handoff / guarded /
staged / authorization / governance / rotation / validator-set binding, commit-authorization-decision-integrity
mismatch, current-validator-set epoch/version preflight, wrong epoch-transition target, wrong commit-authorization /
runtime-handoff / application / live-application / staged-application / guarded-mutation / commit-execution nonce,
replayed commit-execution id, and stale governance-epoch / authority-sequence / validator-set-epoch / validator-set-version
inputs each fail closed as a typed non-mutating `ProductionLiveEpochTransitionCommitExecutionOutcome` with no fallback
to fixture / local-operator / peer-majority / governance-proof-alone / governance-execution-intent-alone /
rotation-plan-alone / application-decision-alone / staged-application-decision-alone / guarded-mutation-decision-alone /
runtime-handoff-decision-alone / commit-authorization-decision-alone / RemoteSigner / custody-only /
custody-attestation material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`5/0`) show `MainNet` is refused absent production authority criteria (fixture /
local-operator / peer-majority / remote-signer-only / custody-alone / custody-attestation-alone / governance-proof-alone
/ governance-execution-intent-alone / rotation-plan-alone / application-decision-alone / staged-application-decision-alone
/ guarded-mutation-decision-alone / runtime-handoff-decision-alone / commit-authorization-decision-alone /
accepted-without-artifact are all insufficient), the default policy is `Disabled` (fails closed before any binding or
artifact construction), the reserved production executor policy/kind is reachable but returns the typed unavailable
outcome, and a valid DevNet/TestNet source-test accept does not enable MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`6/0`) show `recover_live_epoch_transition_commit_execution_window` and the
`LiveEpochTransitionCommitExecutionReplaySet` boundary reject replays idempotently and recover the
commit-execution window deterministically without production mutation; conflicting commit-authorization-decision /
request-id / execution-digest in the same window fail closed rather than being treated as idempotent, and stale
epoch/sequence/version inputs fail closed in evaluation. A divergent commit-execution nonce yields a different
`request_id` / `commit_execution_id`, so a persisted window is not idempotently matched and cannot be replayed into an
accept.

## 13. Fixture-state release evidence

Fixture-state cases (`2/0`) exercise the caller-owned in-memory `LiveEpochTransitionCommitExecutionFixtureState`
used only by source/test evidence: an accepted commit-execution artifact can be applied into the explicit
test-owned state, applied ids are tracked, and re-application is idempotent. This state is not production runtime state,
is not consensus/validator/epoch state, and is never constructed by the production binary.

## 14. Non-mutation evidence

Non-mutation cases (`5/0`) plus the harness no-mutation proof confirm the boundary produces only typed non-mutating
live-commit execution artifacts and every reject is non-mutating with respect to production state.
The release helper drives the real Run 321 `ProductionLiveEpochTransitionCommitExecutionExecutor` only through the
source/test boundary, only for DevNet/TestNet identities on the accept path. It performs **no Run 070 call, no
`LivePqcTrustState` mutation, no live validator-set mutation, no consensus validator-set mutation, no epoch-counter
mutation, no `BasicHotStuffEngine::transition_to_epoch` call on production runtime state, no `meta:current_epoch`
write, no `PAYLOAD_KIND_RECONFIG` block injection, no trust swap, no session eviction, no PQC trust-bundle sequence
write, no authority marker write, no durable replay overwrite, no settlement, no external publication, and no raw local
production signing key load.** The only mutation any path performs is into the explicit caller-owned in-memory
source/test fixture state.

## 15. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the boundary, adds no CLI flag, and enables neither the boundary
by default nor MainNet. S1–S6 confirm the default surfaces are silent on live epoch-transition commit execution
enablement, an invented commit-execution CLI selector is rejected as an unexpected argument, and the denylist of
forbidden positive-claim patterns is clean across captured logs and helper output (help text and helper summary
excluded).

## 16. Tests run and results

Harness exit `0`, final `verdict: PASS`. Regression corpus — all **24 targets `rc=0`** (22 integration-test
targets plus `--lib pqc_authority` and `--lib`), recorded in `summary.txt`: `run_321` (primary Run 321 source tests)
first, then `run_319`, `run_317`, `run_315`, `run_313`, `run_311`, `run_309`, `run_307`, `run_305`, `run_303`, `run_301`, `run_299`,
`run_297`, `run_295`, `run_293`, `run_291`, `run_186`, `run_178`, `run_203`, `run_201`, `run_194`, `run_188`,
`--lib pqc_authority`, and `--lib`. Scenario exit codes: S1 `rc=0`, S2/S3/S4/S6 `rc=1`, S5 `rc=2`; helper first and
second invocations both `rc=0` with identical deterministic digests.

## 17. Security scans

* Secret scanning over the changed files reported **no secrets**.
* CodeQL: the `codeql_checker` tool was invoked over the Run 322 change set (new Rust example helper + new harness
  shell script + documentation/evidence artifacts) but **did not complete — the analysis timed out before returning any
  results**. **No CodeQL coverage is claimed for Run 322** and the incomplete run must not be interpreted as a clean
  CodeQL result. The Run 322 change set adds no new production runtime
  code path: the only new compiled code is the release-example helper (which mirrors the already-reviewed Run 321 test
  corpus and performs no production mutation) and the bash harness (which only builds, greps, and runs existing
  binaries/tests). Secret scanning over all changed files reported no secrets.

## 18. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary readiness from
production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292 durable replay RocksDB, Run 294
RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain governance proof
verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent boundary, Run 305/306
validator-set rotation application / epoch-transition executor boundary, Run 307/308 live validator-set application /
epoch-transition authorization boundary, Run 309/310 staged live validator-set / epoch-transition application
executor boundary, Run 311/312 guarded epoch-transition mutation executor boundary, Run 313/314 epoch-transition
runtime handoff / live-mutation preflight boundary, Run 315/316 live epoch-transition execution preparation boundary, Run 319/320 live epoch-transition commit authorization boundary,
and now the Run 321/322 live epoch-transition commit execution boundary. Red production rows (MainNet authority
rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response, full
MainNet release-binary evidence under production custody) remain Red. Run 322 does not reinterpret this as C4/C5
closure and does not make live epoch-transition commit execution MainNet-ready.

## 19. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no live validator-set, consensus, or epoch-counter mutation; no
  `BasicHotStuffEngine::transition_to_epoch` call on production runtime state; no `meta:current_epoch` write; no
  `PAYLOAD_KIND_RECONFIG` block injection; no trust-bundle sequence or authority marker file writes; no settlement /
  external publication.
* A verified live epoch-transition commit-authorization decision is never turned into a live production
  mutation — accepts produce typed non-mutating live-commit execution artifacts only; the only
  mutation is into an explicit caller-owned in-memory source/test fixture state.
* Missing / unverified / accepted-without-artifact commit-authorization decisions, and
  commit-authorization-alone / runtime-handoff-alone / guarded-mutation-alone / staged-application-alone /
  live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone /
  governance-proof-alone / fixture / local-operator / peer-majority / custody-only / RemoteSigner-only /
  attestation-only / arbitrary-bytes material, are never accepted as production authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over all changed files reported **no secrets**.

## 20. Honest limitations

Run 322 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the
boundary into the default runtime, and does not implement MainNet authority rotation/revocation, live validator-set
mutation, consensus reconfiguration, epoch transition, settlement, or external publication. It closes only the Run
321 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 /
312 / 314 / 316 / 318 / 320 Green-for-scope statuses. The `ProductionLiveEpochTransitionCommitExecutionError` type named
generically in the task does not exist as a separate enum; the real boundary surfaces every failure as a typed
non-mutating variant of `ProductionLiveEpochTransitionCommitExecutionOutcome`. The Run 321 boundary produces a
non-mutating `ProductionLiveEpochTransitionCommitExecutionArtifact` (rather than a mutation "record"); the `Artifact`
and `ProductionLiveEpochTransitionCommitExecutionProtocolVersion` symbols are proven reachable in the source module
plus exercised via the helper reachability probe. These substitutions are recorded in the helper module doc, the
harness header, the archive README, and here. The tracked `summary.txt` records `git_status: dirty` because it is
generated during the harness run, before the Run 322 change set is committed. At harness time the working tree contained
exactly the in-flight Run 322 deliverables committed together with this run — the new helper
(`crates/qbind-node/examples/run_322_production_live_epoch_transition_commit_execution_release_binary_helper.rs`), the
new harness (`scripts/devnet/run_322_production_live_epoch_transition_commit_execution_release_binary.sh`), this
evidence file, the archive `README.md` / `summary.txt` / `.gitignore`, and the documentation edits to
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, and
`docs/whitepaper/contradiction.md` — plus the `.gitignore`d per-run generated artifacts. No other files were dirty.

## 21. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 322 makes no C4/C5 closure claim, no MainNet-readiness claim, and no
runtime default-enablement claim. The live epoch-transition commit execution row is Green-for-scope
only; MainNet authority rotation/revocation under production custody remains Red.

## 22. Suggested Run 323 next step

Proceed to the next Red-row closure campaign toward MainNet authority rotation/revocation under production custody.
**Run 323 — source/test next-stage live epoch-transition commit finalization / settlement boundary** (or the next narrowest Red
row per the C4/C5 matrix): source/test only, deterministic, default `Disabled`/fail-closed, MainNet refused, consuming a
verified Run 321/322 live epoch-transition commit execution accept decision and emitting only a typed non-mutating
next-stage artifact for a future live production executor, with release-binary evidence to follow in Run 324.