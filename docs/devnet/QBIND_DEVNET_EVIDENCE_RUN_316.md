# QBIND DevNet Evidence — Run 316

Release-binary evidence for the Run 315 live epoch-transition execution preparation boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; live epoch-transition execution preparation Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 316 is release-binary evidence for the Run 315 real live epoch-transition execution preparation boundary
(`crates/qbind-node/src/pqc_production_live_epoch_transition_execution_preparation.rs`,
`ProductionLiveEpochTransitionExecutionPreparationExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 315 boundary over the real Run 313/314 verified epoch-transition runtime handoff accept decision
(`is_accept()` with `Some(handoff_package)`; itself composing the Run 311/312 verified guarded epoch-transition
mutation-execution accept decision, the Run 309/310 verified staged live validator-set / epoch-transition application
accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the Run
305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation
plan accept decision, and the Run 301/302 verified governance execution accept decision) in release mode; every failure
surfaces as a typed non-mutating `ProductionLiveEpochTransitionExecutionPreparationOutcome`. Any positive fixture-state
application is explicitly caller-owned, in-memory, source/test-only
(`LiveEpochTransitionExecutionPreparationFixtureState`) and is not production runtime state. Full C4 remains OPEN and C5
remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_316_production_live_epoch_transition_execution_preparation_release_binary_helper.rs`
  — new release helper mirroring the Run 315 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_316_production_live_epoch_transition_execution_preparation_release_binary.sh`
  — new LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_316_production_live_epoch_transition_execution_preparation_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_316.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 316; live epoch-transition execution
  preparation row moved Yellow → Green-for-release-binary-evidenced-scope-only; C4 summary updated; Run 316 timeline
  entry appended.
* `docs/whitepaper/contradiction.md` — Run 316 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 316 note appended to each.

No change was made to the Run 315 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_316_production_live_epoch_transition_execution_preparation_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `ad7e2d896ecc148f811ecc166480efde8d46394ab281477d53c9cd70bcbaf2d4`
  (`qbind_node_sha256`).
* `target/release/examples/run_316_production_live_epoch_transition_execution_preparation_release_binary_helper`
  — SHA-256 `0e618a5ae998fc38d7fbd42547c24b0bf3d2404e1d0a4268be7d4f63a2845b3b` (`helper_316_sha256`).
* Toolchain: `rustc 1.96.1` / `cargo 1.96.1` recorded in `summary.txt`.

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `26/0`, rejection_fail_closed `91/0`,
mainnet_authority_policy `5/0`, replay_recovery_idempotency `6/0`, fixture_state `2/0`, non_mutation `3/0`,
reachability_taxonomy `6/0`. Total `139` pass, `0` fail. The helper runs each case under `catch_unwind` and aggregates
PASS/FAIL. It emits a deterministic-digest fixture; the harness runs the helper twice and diffs the fixture to prove
deterministic-digest stability:

* runtime_handoff_intent_digest `85a6ffab67e671fe140fed0f9ff3ca51e1795ab3fd63cc5632bf14da7bb6ea0b`
* preparation_id `d031cf013eec578e161633daf428465281fee25b808c8894ddc404ccc08b2f07`
* request_id `4d3a5ea9443ec90cdbb6c995f21638d97924a78e8cd92245ffb86051abcf423f`
* preparation_digest / content_digest `ac3a8e16d67b9c5a144d58c0bc804ac5ad1f6fa8b8cefb8e355f6e3093fd6482`
* transcript_digest `a53f4a3ca8430bef50fc837a3db278b981ac73b7ec71bb0b74542c4470971d0d`
* outcome_tag `accepted-source-test-live-epoch-transition-execution-preparation`

The named-digest free-function outputs (`named_preparation_id`, `named_request_id`, `named_transcript_digest`) match
the decision-derived values exactly.

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 315/316 live epoch-transition execution preparation boundary surface (no new CLI
  flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  live-epoch-transition-execution-preparation enablement claim. (These return rc=1 because the binary fails closed on a
  missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented live-epoch-transition-execution-preparation CLI selector
  (`--p2p-execution-preparation-policy`) is rejected as an `unexpected argument` (rc=2), proving no such public CLI flag
  exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  execution-preparation claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Live epoch-transition execution preparation policy / kind / decision taxonomy release evidence

The helper exercises `ProductionLiveEpochTransitionExecutionPreparationExecutorPolicy` (default `Disabled`, explicit
source-test policy), `ProductionLiveEpochTransitionExecutionPreparationExecutorKind`,
`LiveEpochTransitionExecutionPreparationKind`, `LiveEpochTransitionExecutionPreparationAuthoritySource`, and the typed
outcome taxonomy `ProductionLiveEpochTransitionExecutionPreparationOutcome` /
`ProductionLiveEpochTransitionExecutionPreparationRecoveryOutcome` in release mode. Reachability greps confirm the
taxonomy enums, the `ProductionLiveEpochTransitionExecutionPreparationArtifact`, and
`recover_live_epoch_transition_execution_preparation_window` are present in the source module and driven by the helper.

## 7. Verified epoch-transition runtime handoff composition release evidence

The boundary consumes a **verified** Run 313/314 epoch-transition runtime handoff accept decision via
`LiveEpochTransitionExecutionPreparationAuthoritySource`, constructed from the real Run 313/314
`ProductionEpochTransitionRuntimeHandoffDecision` that `is_accept()` and carries `Some(handoff_package)` (itself
composing the Run 311/312 verified guarded epoch-transition mutation-execution accept decision, the Run 309/310 verified
staged live validator-set / epoch-transition application accept decision, the Run 307/308 verified live validator-set
application authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision,
the Run 303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution
accept decision). The boundary never self-authorizes: a missing / unverified / accepted-without-package /
runtime-handoff-alone / guarded-mutation-alone / staged-application-alone / live-authorization-alone /
application-decision-alone / rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture /
wrong-binding input yields a typed fail-closed outcome and never a live production validator-set mutation.

## 8. Canonical validator-set model composition release evidence

Run 316 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable replay
RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain
governance proof verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent, Run
305/306 validator-set rotation application executor, Run 307/308 live validator-set application authorization, Run
309/310 staged live validator-set / epoch-transition application executor, Run 311/312 guarded epoch-transition
mutation executor, and Run 313/314 epoch-transition runtime handoff rows remain
Green-for-release-binary-evidenced-scope only. The executor re-exposes the current/proposed/delta validator-set digests
referenced by the verified runtime-handoff decision, binds the runtime-handoff-decision / guarded-mutation-decision /
staged-application-decision / authorization-decision / request-id / transcript / handoff digests canonically plus the
epoch-transition target, the runtime-handoff / application / live-application / staged-application / guarded-mutation
nonces, the execution-preparation nonce, and the exact future-executor preconditions (current/proposed set digests,
current-validator-set epoch/version fail-closed preflight, delta digest, target epoch, required governance epoch /
authority sequence / replay window), and refuses custody-only / RemoteSigner-only / attestation-only /
governance-execution-intent-alone / rotation-plan-alone / application-decision-alone / staged-application-decision-alone /
guarded-mutation-decision-alone / runtime-handoff-decision-alone material as authority; only a verified epoch-transition
runtime handoff decision with `Some(handoff_package)` binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`26/0`) show DevNet/TestNet source-test execution-preparation requests that bind a verified Run
313/314 epoch-transition runtime handoff accept decision (with `Some(handoff_package)`) under the explicit source-test
policy produce typed non-mutating live-execution preparation artifacts with stable preparation / content / request-id /
transcript digests and a deterministic `preparation_id`, and never apply a live production validator-set change.

## 10. Rejection / fail-closed release evidence

Rejection cases (`91/0`) show missing / unverified runtime-handoff decision, accepted-decision-without-package,
runtime-handoff-alone, guarded-mutation-alone, staged-application-alone, live-authorization-alone,
application-decision-alone, rotation-plan-alone, governance-execution-intent-alone, governance-proof-alone,
fixture-only material, local-operator, peer-majority, custody-only, remote-signer-only, custody-attestation-only,
arbitrary-validator-set-bytes, wrong-field runtime-handoff / guarded / staged / authorization / governance / rotation /
validator-set binding, runtime-handoff-decision-integrity mismatch, current-validator-set epoch/version preflight,
wrong epoch-transition target, wrong runtime-handoff / application / live-application / staged-application /
guarded-mutation nonce, replayed execution-preparation id, and stale governance-epoch / authority-sequence /
validator-set-epoch / validator-set-version inputs each fail closed as a typed non-mutating
`ProductionLiveEpochTransitionExecutionPreparationOutcome` with no fallback to fixture / local-operator / peer-majority /
governance-proof-alone / governance-execution-intent-alone / rotation-plan-alone / application-decision-alone /
staged-application-decision-alone / guarded-mutation-decision-alone / runtime-handoff-decision-alone / RemoteSigner /
custody-only / custody-attestation material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`5/0`) show `MainNet` is refused absent production authority criteria (fixture /
local-operator / peer-majority / remote-signer-only / custody-alone / custody-attestation-alone / governance-proof-alone
/ governance-execution-intent-alone / rotation-plan-alone / application-decision-alone / staged-application-decision-alone
/ guarded-mutation-decision-alone / runtime-handoff-decision-alone / accepted-without-package are all insufficient), the
default policy is `Disabled` (fails closed before any binding or artifact construction), the reserved production
executor policy/kind is reachable but returns the typed unavailable outcome, and a valid DevNet/TestNet source-test
accept does not enable MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`6/0`) show `recover_live_epoch_transition_execution_preparation_window` and the
`LiveEpochTransitionExecutionPreparationReplaySet` boundary reject replays idempotently and recover the
execution-preparation window deterministically without production mutation; conflicting runtime-handoff-decision /
request-id / preparation-digest in the same window fail closed rather than being treated as idempotent, and stale
epoch/sequence/version inputs fail closed in evaluation. A divergent execution-preparation nonce yields a different
`request_id` / `preparation_id`, so a persisted window is not idempotently matched and cannot be replayed into an
accept.

## 13. Fixture-state release evidence

Fixture-state cases (`2/0`) exercise the caller-owned in-memory `LiveEpochTransitionExecutionPreparationFixtureState`
used only by source/test evidence: an accepted execution-preparation artifact can be applied into the explicit
test-owned state, applied ids are tracked, and re-application is idempotent. This state is not production runtime state,
is not consensus/validator/epoch state, and is never constructed by the production binary.

## 14. Non-mutation evidence

Non-mutation cases (`3/0`) plus the harness no-mutation proof confirm the boundary produces only typed non-mutating
live-execution preparation artifacts and every reject is non-mutating with respect to production state.
The release helper drives the real Run 315 `ProductionLiveEpochTransitionExecutionPreparationExecutor` only through the
source/test boundary, only for DevNet/TestNet identities on the accept path. It performs **no Run 070 call, no
`LivePqcTrustState` mutation, no live validator-set mutation, no consensus validator-set mutation, no epoch-counter
mutation, no `BasicHotStuffEngine::transition_to_epoch` call on production runtime state, no `meta:current_epoch`
write, no `PAYLOAD_KIND_RECONFIG` block injection, no trust swap, no session eviction, no PQC trust-bundle sequence
write, no authority marker write, no durable replay overwrite, no settlement, no external publication, and no raw local
production signing key load.** The only mutation any path performs is into the explicit caller-owned in-memory
source/test fixture state.

## 15. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the boundary, adds no CLI flag, and enables neither the boundary
by default nor MainNet. S1–S6 confirm the default surfaces are silent on live epoch-transition execution preparation
enablement, an invented execution-preparation CLI selector is rejected as an unexpected argument, and the denylist of
forbidden positive-claim patterns is clean across captured logs and helper output (help text and helper summary
excluded).

## 16. Tests run and results

Harness exit `0`. Regression corpus (all `rc=0`), recorded in `summary.txt`: `run_315` (primary Run 315 source tests)
first, then `run_313`, `run_311`, `run_309`, `run_307`, `run_305`, `run_303`, `run_301`, `run_299`, `run_297`,
`run_295`, `run_293`, `run_291`, `run_186`, `run_178`, `run_203`, `run_201`, `run_194`, `run_188`,
`--lib pqc_authority`, and `--lib`.

## 17. Security scans

* Secret scanning over the changed files reported **no secrets**.
* CodeQL: the `codeql_checker` tool was invoked over the Run 316 change set (new Rust example helper + new harness
  shell script + documentation/evidence artifacts) but **did not complete — the operation was cancelled due to
  timeout** and returned no results. **No CodeQL coverage is claimed for Run 316** and the timed-out run must not be
  interpreted as a clean CodeQL result. The Run 316 change set adds no new production runtime code path: the only new
  compiled code is the release-example helper (which mirrors the already-reviewed Run 315 test corpus and performs no
  production mutation) and the bash harness (which only builds, greps, and runs existing binaries/tests). Secret
  scanning over all changed files reported no secrets.

## 18. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary readiness from
production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292 durable replay RocksDB, Run 294
RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain governance proof
verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent boundary, Run 305/306
validator-set rotation application / epoch-transition executor boundary, Run 307/308 live validator-set application /
epoch-transition authorization boundary, Run 309/310 staged live validator-set / epoch-transition application
executor boundary, Run 311/312 guarded epoch-transition mutation executor boundary, Run 313/314 epoch-transition
runtime handoff / live-mutation preflight boundary, and now the Run 315/316 live epoch-transition execution
preparation boundary. Red production rows (MainNet authority rotation/revocation under production custody, production
signing audit trail / crypto-agility / incident response, full MainNet release-binary evidence under production
custody) remain Red. Run 316 does not reinterpret this as C4/C5 closure and does not make live epoch-transition
execution preparation MainNet-ready.

## 19. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no live validator-set, consensus, or epoch-counter mutation; no
  `BasicHotStuffEngine::transition_to_epoch` call on production runtime state; no `meta:current_epoch` write; no
  `PAYLOAD_KIND_RECONFIG` block injection; no trust-bundle sequence or authority marker file writes; no settlement /
  external publication.
* A verified epoch-transition runtime handoff decision is never turned into a live production
  mutation — accepts produce typed non-mutating live-execution preparation artifacts only; the only
  mutation is into an explicit caller-owned in-memory source/test fixture state.
* Missing / unverified / accepted-without-package runtime-handoff decisions, and runtime-handoff-alone /
  guarded-mutation-alone / staged-application-alone / live-authorization-alone / application-decision-alone /
  rotation-plan-alone / governance-execution-intent-alone / governance-proof-alone / fixture / local-operator /
  peer-majority / custody-only / RemoteSigner-only / attestation-only / arbitrary-bytes material, are never accepted as
  production authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over all changed files reported **no secrets**.

## 20. Honest limitations

Run 316 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the
boundary into the default runtime, and does not implement MainNet authority rotation/revocation, live validator-set
mutation, consensus reconfiguration, epoch transition, settlement, or external publication. It closes only the Run
315 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 /
312 / 314 Green-for-scope statuses. The `ProductionLiveEpochTransitionExecutionPreparationError` type named generically
in the task does not exist as a separate enum; the real boundary surfaces every failure as a typed non-mutating variant
of `ProductionLiveEpochTransitionExecutionPreparationOutcome`. The Run 315 boundary produces a non-mutating
`ProductionLiveEpochTransitionExecutionPreparationArtifact` (rather than a mutation "record"); the `Artifact` and
`ProductionLiveEpochTransitionExecutionPreparationProtocolVersion` symbols are proven reachable in the source module
plus exercised via the helper reachability probe. On the accept path the boundary derives `preparation_id`/`request_id`
using the consumed runtime-handoff decision's `handoff_digest` as the guarded-mutation-intent-digest binding input; the
deterministic-digest fixture and named-digest free functions agree, so the derived and named digests match exactly.
These substitutions are recorded in the helper module doc, the harness header, the archive README, and here. The
tracked `summary.txt` records the working-tree state at harness time (`git_status: dirty`, reflecting the in-flight
documentation/evidence edits committed together with this run); all per-run generated artifacts are `.gitignore`d.

## 21. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 316 makes no C4/C5 closure claim, no MainNet-readiness claim, and no
runtime default-enablement claim. The live epoch-transition execution preparation row is Green-for-scope
only; MainNet authority rotation/revocation under production custody remains Red.

## 22. Suggested Run 317 next step

Proceed to the next Red-row closure campaign toward MainNet authority rotation/revocation under production custody.
**Run 317 — source/test next-stage live epoch-transition mutation execution boundary** (or the next narrowest Red row
per the C4/C5 matrix): source/test only, deterministic, default `Disabled`/fail-closed, MainNet refused, consuming a
verified Run 315/316 live epoch-transition execution preparation accept decision and emitting only a typed non-mutating
next-stage artifact, with release-binary evidence deferred to Run 318.
