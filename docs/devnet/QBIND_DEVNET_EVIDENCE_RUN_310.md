# QBIND DevNet Evidence — Run 310

Release-binary evidence for the Run 309 staged live validator-set / epoch-transition application executor boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; staged live validator-set / epoch-transition application executor Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 310 is release-binary evidence for the Run 309 real staged live validator-set / epoch-transition application
executor boundary (`crates/qbind-node/src/pqc_production_staged_live_validator_set_epoch_transition_application_executor.rs`,
`ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 309 boundary over the real Run 307/308 verified live validator-set application authorization accept decision
(`is_accept()` with `Some(authorization_intent)`; itself composing the Run 305/306 verified validator-set rotation
application accept decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run
301/302 verified governance execution accept decision) in release mode; every failure surfaces as a typed
non-mutating `ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome`. Full C4 remains OPEN and C5 remains
OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_310_production_staged_live_validator_set_epoch_transition_application_executor_release_binary_helper.rs`
  — new release helper mirroring the Run 309 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_310_production_staged_live_validator_set_epoch_transition_application_executor_release_binary.sh`
  — new LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_310_production_staged_live_validator_set_epoch_transition_application_executor_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_310.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 310; staged live validator-set /
  epoch-transition application executor row moved Yellow → Green-for-release-binary-evidenced-scope-only; C4 summary
  updated; Run 310 timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 310 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 310 note appended to each.

No change was made to the Run 309 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_310_production_staged_live_validator_set_epoch_transition_application_executor_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `e66123805dcd148f8dda16587bc0df33d8238eaebecd22edaa8373b08d63f4c5`
  (recorded as `qbind_node_sha256` in `summary.txt`).
* `target/release/examples/run_310_production_staged_live_validator_set_epoch_transition_application_executor_release_binary_helper`
  — SHA-256 `0573595e6b3828c3cc2ab6332f4b61aa0b50fa42e883d0c0288ed2e04edd4410`
  (recorded as `helper_310_sha256` in `summary.txt`).
* Toolchain: `rustc 1.96.1`, `cargo 1.96.1` (recorded in `summary.txt`).

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `35/0`, rejection_fail_closed `65/0`,
mainnet_authority_policy `7/0`, replay_recovery_idempotency `6/0`, non_mutation `3/0`, reachability_taxonomy `5/0`.
Total `121` pass, `0` fail. The helper runs each case under `catch_unwind` and aggregates PASS/FAIL. It emits a
deterministic-digest fixture; the harness runs the helper twice and diffs the fixture to prove deterministic-digest
stability:

* authorization_intent_digest `2e68313bc36f5567fe4508ac7935c7ea093660a718c0f34fddcfd10a1b1f2cfb`
* staged_application_id `gov-decision-id-1`
* intent_digest `68ef9f43a89dd1c0973c39329f81bd60d3f3c845fa008946a71fcf9b7d0bff3d`
* request_id `1b03103b1ed3263b721d91cad25c345e359d42faf10542755f936a80dbc092e0`
* transcript_digest `63f2ec149ef767733b6761ce452f54deebfec742a1900d00c92871f96123e03c`
* outcome_tag `accepted-source-test-staged-live-validator-set-epoch-transition-application`

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 309/310 staged live validator-set / epoch-transition application boundary surface (no new CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  staged-live-validator-set / epoch-transition application enablement claim. (These return rc=1 because the binary
  fails closed on a missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented staged-live-validator-set-epoch-transition-application CLI selector is rejected as an
  `unexpected argument` (rc=2), proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  staged-application claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Staged live validator-set / epoch-transition application policy / kind / decision taxonomy release evidence

The helper exercises `ProductionStagedLiveValidatorSetEpochTransitionApplicationPolicy` (default `Disabled`, explicit
source-test policy), `ProductionStagedLiveValidatorSetEpochTransitionApplicationKind`,
`StagedLiveValidatorSetEpochTransitionApplicationKind`,
`StagedLiveValidatorSetEpochTransitionApplicationAuthoritySource`, and the typed outcome taxonomy
`ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome` /
`ProductionStagedLiveValidatorSetEpochTransitionApplicationRecoveryOutcome` in release mode. Reachability greps
confirm the taxonomy enums are present in the source module and driven by the helper.

## 7. Verified live validator-set application authorization composition release evidence

The boundary consumes a **verified** Run 307/308 live validator-set application authorization accept decision via
`StagedLiveValidatorSetEpochTransitionApplicationAuthoritySource`, constructed from the real Run 307/308
`ProductionLiveValidatorSetApplicationAuthorizationDecision` that `is_accept()` and carries
`Some(authorization_intent)` (itself composing the Run 305/306 verified validator-set rotation application accept
decision, the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified
governance execution accept decision). The boundary never self-authorizes: a missing / unverified /
accepted-without-authorization-intent / application-decision-alone / rotation-plan-alone /
governance-execution-intent-alone / governance-proof-alone / fixture / wrong-binding authorization input yields a
typed fail-closed outcome and never a live validator-set mutation.

## 8. Canonical validator-set model composition release evidence

Run 310 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable replay
RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain
governance proof verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent, Run
305/306 validator-set rotation application executor, and Run 307/308 live validator-set application authorization
rows remain Green-for-release-binary-evidenced-scope only. The executor re-exposes the current/proposed/delta
validator-set digests referenced by the verified authorization decision, binds the authorization-decision /
application-decision / request-id / transcript / authorization-intent digests canonically plus the epoch-transition
target and application / live-application / staged-application nonces, and refuses custody-only / RemoteSigner-only /
attestation-only / governance-execution-intent-alone / rotation-plan-alone / application-decision-alone material as
authorization authority; only a verified live validator-set application authorization decision with
`Some(authorization_intent)` binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`35/0`) show DevNet/TestNet source-test staged-application requests that bind a verified Run
307/308 live validator-set application authorization accept decision (with `Some(authorization_intent)`) under the
explicit source-test policy produce typed non-mutating staged epoch-transition application records with stable
authorization-intent / intent / request-id / transcript digests and a deterministic `staged_application_id`, and
never apply a live validator-set change.

## 10. Rejection / fail-closed release evidence

Rejection cases (`65/0`) show missing / unverified authorization decision, accepted-decision-without-authorization-intent,
application-decision-alone, rotation-plan-alone, governance-execution-intent-alone, governance-proof-alone,
fixture-only material, local-operator, peer-majority, custody-only, remote-signer-only, custody-attestation-only,
arbitrary-validator-set-bytes, wrong-field governance / rotation / validator-set binding, authorization-decision-integrity
mismatch, wrong epoch-transition target, wrong application / live-application nonce, replayed staged-application id,
and stale governance-epoch / authority-sequence / validator-set-epoch / validator-set-version inputs each fail closed
as a typed non-mutating `ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome` with no fallback to
fixture / local-operator / peer-majority / governance-proof-alone / governance-execution-intent-alone /
rotation-plan-alone / application-decision-alone / RemoteSigner / custody-only / custody-attestation material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`7/0`) show `MainNet` is refused absent production authority criteria (fixture /
local-operator / peer-majority / remote-signer-only / custody-alone / custody-attestation-alone / governance-proof-alone
/ governance-execution-intent-alone / rotation-plan-alone / application-decision-alone / accepted-without-authorization-intent
are all insufficient), the default policy is `Disabled` (fails closed before any binding or staged-record
construction), the reserved production application policy is reachable but returns the typed unavailable outcome, and
a valid DevNet/TestNet source-test accept does not enable MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`6/0`) show `recover_staged_live_validator_set_epoch_transition_application_window` and the
`StagedLiveValidatorSetEpochTransitionApplicationReplaySet` boundary reject replays idempotently and recover the
staged-application window deterministically without mutation; conflicting authorization-decision / request-id /
intent-digest in the same window fail closed rather than being treated as idempotent, and stale epoch/sequence/version
inputs fail closed in evaluation. A divergent staged-application nonce yields a different `request_id` /
`staged_application_id`, so a persisted window is not idempotently matched and cannot be replayed into an accept.

## 13. Non-mutation evidence

Non-mutation cases (`3/0`) plus the harness no-mutation proof confirm the boundary produces only typed non-mutating
staged epoch-transition application records and every reject is non-mutating. The release helper drives the real Run
309 `ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor` only through the source/test boundary, only
for DevNet/TestNet identities on the accept path. It performs **no Run 070 call, no `LivePqcTrustState` mutation, no
live validator-set mutation, no consensus validator-set mutation, no epoch-counter mutation, no
`BasicHotStuffEngine::transition_to_epoch` call, no `meta:current_epoch` write, no `PAYLOAD_KIND_RECONFIG` block
injection, no trust swap, no session eviction, no PQC trust-bundle sequence write, no authority marker write, no
durable replay overwrite, no settlement, no external publication, and no raw local production signing key load.**

## 14. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the boundary, adds no CLI flag, and enables neither the boundary
by default nor MainNet. S1–S6 confirm the default surfaces are silent on staged live validator-set / epoch-transition
application enablement, an invented staged-application CLI selector is rejected as an unexpected argument, and the
denylist of forbidden positive-claim patterns (52 patterns) is clean across captured logs and helper output (help
text and helper summary excluded).

## 15. Tests run and results

Harness exit `0`. Regression corpus (all `rc=0`), recorded in `summary.txt`: `run_309` (primary Run 309 source
tests) first, then `run_307`, `run_305`, `run_303`, `run_301`, `run_299`, `run_297`, `run_295`, `run_293`, `run_291`,
`run_186`, `run_178`, `run_203`, `run_201`, `run_194`, `run_188`, `--lib pqc_authority`, and `--lib`.

## 16. Security scans

* Secret scanning over the changed files reported **no secrets**.
* CodeQL: **skipped / classified trivial — no CodeQL coverage is claimed for Run 310.** The `codeql_checker` tool was
  invoked and returned `Skipped: all changes are trivial`. The exact reason is that the Run 310 change set consists
  only of documentation and evidence artifacts (the canonical evidence file, the harness-generated `summary.txt`, and
  narrow documentation updates in this session; the release helper example and LF harness shell script were committed
  in a prior session and are unchanged here). No production or test source code was modified in the analyzed change
  set, so CodeQL classified the change as trivial and did not run an analysis database. No clean-CodeQL-coverage claim
  is made for Run 310.

## 17. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary readiness from
production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292 durable replay RocksDB, Run 294
RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain governance proof
verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent boundary, Run 305/306
validator-set rotation application / epoch-transition executor boundary, Run 307/308 live validator-set application /
epoch-transition authorization boundary, and now the Run 309/310 staged live validator-set / epoch-transition
application executor boundary. Red production rows (MainNet authority rotation/revocation under production custody,
production signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under
production custody) remain Red. Run 310 does not reinterpret this as C4/C5 closure and does not make staged live
validator-set / epoch-transition application MainNet-ready.

## 18. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no live validator-set, consensus, or epoch-counter mutation; no
  `BasicHotStuffEngine::transition_to_epoch` call; no `meta:current_epoch` write; no `PAYLOAD_KIND_RECONFIG` block
  injection; no trust-bundle sequence or authority marker file writes; no settlement / external publication.
* A verified live validator-set application authorization decision is never turned into a live mutation — accepts
  produce typed non-mutating staged epoch-transition application records only.
* Missing / unverified / accepted-without-authorization-intent authorization decisions, and application-decision-alone
  / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator /
  peer-majority / custody-only / RemoteSigner-only / attestation-only / arbitrary-bytes material, are never accepted
  as production authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over all changed files reported **no secrets**.

## 19. Honest limitations

Run 310 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the
boundary into the default runtime, and does not implement MainNet authority rotation/revocation, live validator-set
mutation, consensus reconfiguration, epoch transition, settlement, or external publication. It closes only the Run
309 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308
Green-for-scope statuses. The `ProductionStagedLiveValidatorSetEpochTransitionApplicationError` type named
generically in the task does not exist as a separate enum; the real boundary surfaces every failure as a typed
non-mutating variant of `ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome`. There is likewise no
`WrongStagedApplicationNonce` outcome variant: the staged-application nonce binds the deterministic `request_id` /
staged record, so a divergent staged nonce is proven through staged-application replay-rejection and independent-clean
recovery rather than a dedicated wrong-nonce reject variant. These substitutions are recorded in the helper module
doc, the harness header, the archive README, and here. The tracked `summary.txt` records `git_status: dirty` because
it captures the working-tree state at harness time (the newly generated `summary.txt` was itself untracked and this
canonical evidence file plus the doc updates were pending commit); the only untracked file at generation time was the
`summary.txt` itself, and all per-run generated artifacts are `.gitignore`d.

## 20. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 310 makes no C4/C5 closure claim, no MainNet-readiness claim, and no
runtime default-enablement claim. The staged live validator-set / epoch-transition application executor row is
Green-for-scope only; MainNet authority rotation/revocation under production custody remains Red.

## 21. Suggested Run 311 next step

Proceed to the next Red-row closure campaign toward MainNet authority rotation/revocation under production custody.
**Run 311 — source/test real production mutating epoch-transition executor boundary** (or the next narrowest Red row
per the C4/C5 matrix): source/test only, deterministic, default `Disabled`/fail-closed, MainNet refused, consuming a
verified Run 309/310 staged epoch-transition application record and producing the next typed staged/guarded artifact
toward a future live mutation, without live validator-set mutation or epoch transition, with release-binary evidence
deferred to Run 312.
