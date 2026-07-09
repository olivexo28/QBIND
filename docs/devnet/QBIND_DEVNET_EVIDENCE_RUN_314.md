# QBIND DevNet Evidence — Run 314

Release-binary evidence for the Run 313 epoch-transition runtime handoff / live-mutation preflight boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; epoch-transition runtime handoff / live-mutation preflight Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 314 is release-binary evidence for the Run 313 real epoch-transition runtime handoff / live-mutation
preflight boundary (`crates/qbind-node/src/pqc_production_epoch_transition_runtime_handoff.rs`,
`ProductionEpochTransitionRuntimeHandoffExecutor`). It adds no new production runtime wiring, no
public CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real
Run 313 boundary over the real Run 311/312 verified guarded epoch-transition mutation-execution accept
decision (`is_accept()` with `Some(staged_application_record)`; itself composing the Run 309/310 verified staged live
validator-set / epoch-transition application accept decision, the Run 307/308 verified live validator-set application
authorization accept decision, the Run 305/306 verified validator-set rotation application accept decision, the Run
303/304 verified validator-set rotation plan accept decision, and the Run 301/302 verified governance execution accept
decision) in release mode; every failure surfaces as a typed non-mutating
`ProductionEpochTransitionRuntimeHandoffOutcome`. Any positive fixture-state application is explicitly caller-owned,
in-memory, source/test-only (`EpochTransitionRuntimeHandoffFixtureState`) and is not production runtime state. Full C4
remains OPEN and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_314_production_epoch_transition_runtime_handoff_release_binary_helper.rs`
  — new release helper mirroring the Run 313 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_314_production_epoch_transition_runtime_handoff_release_binary.sh`
  — new LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression corpus,
  `summary.txt` emission).
* `docs/devnet/run_314_production_epoch_transition_runtime_handoff_release_binary/`
  — evidence archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_314.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 314; epoch-transition runtime handoff /
  live-mutation preflight row moved Yellow → Green-for-release-binary-evidenced-scope-only; C4 summary updated; Run 314
  timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 314 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 314 note appended to each.

No change was made to the Run 313 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_314_production_epoch_transition_runtime_handoff_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 recorded as `qbind_node_sha256` in `summary.txt`.
* `target/release/examples/run_314_production_epoch_transition_runtime_handoff_release_binary_helper`
  — SHA-256 recorded as `helper_314_sha256` in `summary.txt`.
* Toolchain: `rustc` / `cargo` versions recorded in `summary.txt`.

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `31/0`, rejection_fail_closed `80/0`,
mainnet_authority_policy `6/0`, replay_recovery_idempotency `10/0`, fixture_state `3/0`, non_mutation `9/0`,
reachability_taxonomy `12/0`. Total `151` pass, `0` fail. The helper runs each case under `catch_unwind` and aggregates
PASS/FAIL. It emits a deterministic-digest fixture; the harness runs the helper twice and diffs the fixture to prove
deterministic-digest stability:

* guarded_mutation_intent_digest `0d260ebd5806820fa490b8aae10ce3cd4f7e73c47a5732ac45403effade06d27`
* handoff_id `c140d606d71609686f09c2203815fe6d49be0b446f9c38bbcb8c347b1dcb4d32`
* request_id `63ae9911c34b661e678d3e9b669bbb8f667f8af60429d9d9700cbc05584dca14`
* handoff_digest / content_digest `85a6ffab67e671fe140fed0f9ff3ca51e1795ab3fd63cc5632bf14da7bb6ea0b`
* transcript_digest `3d36168fc9075fcf3a6f315b10690a875944713a436e0761bc54bc6f2c9fe244`
* outcome_tag `accepted-source-test-epoch-transition-runtime-handoff`

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 313/314 epoch-transition runtime handoff boundary surface (no new CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  epoch-transition-runtime-handoff enablement claim. (These return rc=1 because the binary fails closed on a missing
  `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented epoch-transition-runtime-handoff CLI selector (`--p2p-runtime-handoff-policy`) is rejected as an
  `unexpected argument` (rc=2), proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  runtime-handoff claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Epoch-transition runtime handoff policy / kind / decision taxonomy release evidence

The helper exercises `ProductionEpochTransitionRuntimeHandoffExecutorPolicy` (default `Disabled`, explicit
source-test policy), `ProductionEpochTransitionRuntimeHandoffExecutorKind`, `EpochTransitionRuntimeHandoffKind`,
`EpochTransitionRuntimeHandoffAuthoritySource`, and the typed outcome taxonomy
`ProductionEpochTransitionRuntimeHandoffOutcome` / `ProductionEpochTransitionRuntimeHandoffRecoveryOutcome` in
release mode. Reachability greps confirm the taxonomy enums are present in the source module and driven by the helper.

## 7. Verified guarded mutation-execution composition release evidence

The boundary consumes a **verified** Run 311/312 guarded epoch-transition mutation-execution accept
decision via `EpochTransitionRuntimeHandoffAuthoritySource`, constructed from the real Run 311/312
`ProductionGuardedEpochTransitionMutationDecision` that `is_accept()` and carries
`Some(staged_application_record)` (itself composing the Run 309/310 verified staged live validator-set / epoch-transition
application accept decision, the Run 307/308 verified live validator-set application authorization accept decision, the
Run 305/306 verified validator-set rotation application accept decision, the Run 303/304 verified validator-set rotation
plan accept decision, and the Run 301/302 verified governance execution accept decision). The boundary never
self-authorizes: a missing / unverified / accepted-without-guarded-record / staged-application-alone /
live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone /
governance-proof-alone / fixture / wrong-binding guarded input yields a typed fail-closed outcome and never a live
production validator-set mutation.

## 8. Canonical validator-set model composition release evidence

Run 314 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable replay
RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain
governance proof verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent, Run
305/306 validator-set rotation application executor, Run 307/308 live validator-set application authorization, Run
309/310 staged live validator-set / epoch-transition application executor, and Run 311/312 guarded epoch-transition
mutation executor rows remain Green-for-release-binary-evidenced-scope only. The executor re-exposes the
current/proposed/delta validator-set digests referenced by the verified guarded decision, binds the
guarded-mutation-decision / staged-application-decision / authorization-decision / application-decision / request-id /
transcript / staged-record digests canonically plus the epoch-transition target, the application / live-application /
staged-application / guarded-mutation nonces, the runtime-handoff nonce, and the exact future-executor preconditions
(current/proposed set digests, current-validator-set epoch/version fail-closed preflight, delta digest, target epoch,
required governance epoch / authority sequence / replay window), and refuses custody-only / RemoteSigner-only /
attestation-only / governance-execution-intent-alone / rotation-plan-alone / application-decision-alone /
staged-application-decision-alone / guarded-mutation-decision-alone material as authority; only a verified guarded
epoch-transition mutation-execution decision with `Some(staged_application_record)` binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`31/0`) show DevNet/TestNet source-test runtime-handoff requests that bind a verified Run
311/312 guarded epoch-transition mutation-execution accept decision (with `Some(staged_application_record)`)
under the explicit source-test policy produce typed non-mutating runtime handoff / live-mutation preflight packages
with stable handoff / content / request-id / transcript digests and a deterministic `handoff_id`, and never apply
a live production validator-set change.

## 10. Rejection / fail-closed release evidence

Rejection cases (`80/0`) show missing / unverified guarded decision, accepted-decision-without-guarded-record,
staged-application-alone, live-authorization-alone, application-decision-alone, rotation-plan-alone,
governance-execution-intent-alone, governance-proof-alone, fixture-only material, local-operator, peer-majority,
custody-only, remote-signer-only, custody-attestation-only, arbitrary-validator-set-bytes, wrong-field guarded /
staged / authorization / governance / rotation / validator-set binding, guarded-mutation-decision-integrity mismatch,
current-validator-set epoch/version preflight, wrong epoch-transition target, wrong application / live-application /
staged-application / guarded-mutation nonce, replayed runtime-handoff id, and stale governance-epoch /
authority-sequence / validator-set-epoch / validator-set-version inputs each fail closed as a typed non-mutating
`ProductionEpochTransitionRuntimeHandoffOutcome` with no fallback to fixture / local-operator / peer-majority /
governance-proof-alone / governance-execution-intent-alone / rotation-plan-alone / application-decision-alone /
staged-application-decision-alone / guarded-mutation-decision-alone / RemoteSigner / custody-only / custody-attestation
material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`6/0`) show `MainNet` is refused absent production authority criteria (fixture /
local-operator / peer-majority / remote-signer-only / custody-alone / custody-attestation-alone / governance-proof-alone
/ governance-execution-intent-alone / rotation-plan-alone / application-decision-alone / staged-application-decision-alone
/ guarded-mutation-decision-alone / accepted-without-guarded-record are all insufficient), the default policy is
`Disabled` (fails closed before any binding or package construction), the reserved production executor policy/kind is
reachable but returns the typed unavailable outcome, and a valid DevNet/TestNet source-test accept does not enable
MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`10/0`) show `recover_epoch_transition_runtime_handoff_window` and the
`EpochTransitionRuntimeHandoffReplaySet` boundary reject replays idempotently and recover the runtime-handoff window
deterministically without production mutation; conflicting guarded-mutation-decision / request-id / handoff-digest in
the same window fail closed rather than being treated as idempotent, and stale epoch/sequence/version inputs fail
closed in evaluation. A divergent runtime-handoff nonce yields a different `request_id` / `handoff_id`, so a persisted
window is not idempotently matched and cannot be replayed into an accept.

## 13. Fixture-state release evidence

Fixture-state cases (`3/0`) exercise the caller-owned in-memory `EpochTransitionRuntimeHandoffFixtureState` used only
by source/test evidence: an accepted runtime-handoff package can be applied into the explicit test-owned state
(`apply_prepared_execution`), applied ids are tracked (`has_applied` / `applied_execution_ids`), and re-application is
idempotent. This state is not production runtime state, is not consensus/validator/epoch state, and is never
constructed by the production binary.

## 14. Non-mutation evidence

Non-mutation cases (`9/0`) plus the harness no-mutation proof confirm the boundary produces only typed non-mutating
runtime handoff / live-mutation preflight packages and every reject is non-mutating with respect to production state.
The release helper drives the real Run 313 `ProductionEpochTransitionRuntimeHandoffExecutor` only through the
source/test boundary, only for DevNet/TestNet identities on the accept path. It performs **no Run 070 call, no
`LivePqcTrustState` mutation, no live validator-set mutation, no consensus validator-set mutation, no epoch-counter
mutation, no `BasicHotStuffEngine::transition_to_epoch` call on production runtime state, no `meta:current_epoch`
write, no `PAYLOAD_KIND_RECONFIG` block injection, no trust swap, no session eviction, no PQC trust-bundle sequence
write, no authority marker write, no durable replay overwrite, no settlement, no external publication, and no raw local
production signing key load.** The only mutation any path performs is into the explicit caller-owned in-memory
source/test fixture state.

## 15. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the boundary, adds no CLI flag, and enables neither the boundary
by default nor MainNet. S1–S6 confirm the default surfaces are silent on epoch-transition runtime handoff
enablement, an invented runtime-handoff CLI selector is rejected as an unexpected argument, and the denylist of
forbidden positive-claim patterns is clean across captured logs and helper output (help text and helper summary
excluded).

## 16. Tests run and results

Harness exit `0`. Regression corpus (all `rc=0`), recorded in `summary.txt`: `run_313` (primary Run 313 source tests)
first, then `run_311`, `run_309`, `run_307`, `run_305`, `run_303`, `run_301`, `run_299`, `run_297`, `run_295`,
`run_293`, `run_291`, `run_186`, `run_178`, `run_203`, `run_201`, `run_194`, `run_188`, `--lib pqc_authority`, and
`--lib`.

## 17. Security scans

* Secret scanning over the changed files reported **no secrets**.
* CodeQL: the `codeql_checker` tool was invoked over the Run 314 change set (new Rust example helper + new harness
  shell script + documentation/evidence artifacts) but **did not complete — the operation was cancelled due to
  timeout** and returned no results. **No CodeQL coverage is claimed for Run 314** and the timed-out run must not be
  interpreted as a clean CodeQL result. The Run 314 change set adds no new production runtime code path: the only new
  compiled code is the release-example helper (which mirrors the already-reviewed Run 313 test corpus and performs no
  production mutation) and the bash harness (which only builds, greps, and runs existing binaries/tests). Secret
  scanning over all changed files reported no secrets.

## 18. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary readiness from
production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292 durable replay RocksDB, Run 294
RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain governance proof
verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent boundary, Run 305/306
validator-set rotation application / epoch-transition executor boundary, Run 307/308 live validator-set application /
epoch-transition authorization boundary, Run 309/310 staged live validator-set / epoch-transition application
executor boundary, Run 311/312 guarded epoch-transition mutation executor boundary, and now the Run 313/314
epoch-transition runtime handoff / live-mutation preflight boundary. Red production rows
(MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility /
incident response, full MainNet release-binary evidence under production custody) remain Red. Run 314 does not
reinterpret this as C4/C5 closure and does not make epoch-transition runtime handoff MainNet-ready.

## 19. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no live validator-set, consensus, or epoch-counter mutation; no
  `BasicHotStuffEngine::transition_to_epoch` call on production runtime state; no `meta:current_epoch` write; no
  `PAYLOAD_KIND_RECONFIG` block injection; no trust-bundle sequence or authority marker file writes; no settlement /
  external publication.
* A verified guarded epoch-transition mutation-execution decision is never turned into a live production
  mutation — accepts produce typed non-mutating runtime handoff / live-mutation preflight packages only; the only
  mutation is into an explicit caller-owned in-memory source/test fixture state.
* Missing / unverified / accepted-without-guarded-record guarded decisions, and staged-application-alone /
  live-authorization-alone / application-decision-alone / rotation-plan-alone / governance-execution-intent-alone /
  governance-proof-alone / fixture / local-operator / peer-majority / custody-only / RemoteSigner-only /
  attestation-only / arbitrary-bytes material, are never accepted as production authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over all changed files reported **no secrets**.

## 20. Honest limitations

Run 314 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the
boundary into the default runtime, and does not implement MainNet authority rotation/revocation, live validator-set
mutation, consensus reconfiguration, epoch transition, settlement, or external publication. It closes only the Run
313 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302 / 304 / 306 / 308 / 310 /
312 Green-for-scope statuses. The `ProductionEpochTransitionRuntimeHandoffError` type named generically in the task does
not exist as a separate enum; the real boundary surfaces every failure as a typed non-mutating variant of
`ProductionEpochTransitionRuntimeHandoffOutcome`. The Run 313 boundary produces a non-mutating
`ProductionEpochTransitionRuntimeHandoffPackage` (rather than a mutation "record"); the `Package` and
`ProductionEpochTransitionRuntimeHandoffProtocolVersion` symbols are proven reachable in the source module rather than
separately exercised by the helper. These substitutions are recorded in the helper module doc, the harness header, the
archive README, and here. The tracked `summary.txt` records the working-tree state at harness time; all per-run
generated artifacts are `.gitignore`d.

## 21. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 314 makes no C4/C5 closure claim, no MainNet-readiness claim, and no
runtime default-enablement claim. The epoch-transition runtime handoff / live-mutation preflight row is Green-for-scope
only; MainNet authority rotation/revocation under production custody remains Red.

## 22. Suggested Run 315 next step

Proceed to the next Red-row closure campaign toward MainNet authority rotation/revocation under production custody.
**Run 315 — source/test next-stage epoch-transition live-mutation boundary** (or the next narrowest Red row per the
C4/C5 matrix): source/test only, deterministic, default `Disabled`/fail-closed, MainNet refused, consuming a verified
Run 313/314 runtime handoff / live-mutation preflight package and producing the next typed artifact toward a future
live mutation, without live production validator-set mutation or epoch transition, with release-binary evidence
deferred to Run 316.
