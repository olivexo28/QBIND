# QBIND DevNet Evidence — Run 306

Release-binary evidence for the Run 305 validator-set rotation application / epoch-transition executor boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; validator-set rotation application executor Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 306 is release-binary evidence for the Run 305 real validator-set rotation application / epoch-transition
executor boundary (`crates/qbind-node/src/pqc_production_validator_set_rotation_application_executor.rs`,
`ProductionValidatorSetRotationApplicationExecutor`). It adds no new production runtime wiring, no public CLI
flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real Run 305
boundary over the real Run 303/304 verified validator-set rotation plan accept decision (itself composing the
Run 301/302 verified governance execution accept decision) in release mode; every failure surfaces as a typed
non-mutating `ProductionValidatorSetRotationApplicationOutcome`. Full C4 remains OPEN and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_306_production_validator_set_rotation_application_executor_release_binary_helper.rs`
  — new release helper mirroring the Run 305 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_306_production_validator_set_rotation_application_executor_release_binary.sh` — new
  LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression
  corpus, `summary.txt` emission).
* `docs/devnet/run_306_production_validator_set_rotation_application_executor_release_binary/` — evidence
  archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_306.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 306; validator-set rotation
  application / epoch-transition executor row moved Yellow → Green-for-release-binary-evidenced-scope-only;
  C4 summary updated; Run 306 timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 306 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 306 note appended to each.

No change was made to the Run 305 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_306_production_validator_set_rotation_application_executor_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `d5085033334cfdb0c815832989958b0fba92f0d2b87e738903b253cc7e02aa6e`
  (recorded as `qbind_node_sha256` in `summary.txt`).
* `target/release/examples/run_306_production_validator_set_rotation_application_executor_release_binary_helper`
  — SHA-256 `a238c60ce96d8fc2d805bb73a6cbfd94dab6657d759da02c4bebe65c01b83083`
  (recorded as `helper_306_sha256` in `summary.txt`).
* Toolchain: `rustc 1.96.0`, `cargo 1.96.0` (recorded in `summary.txt`).

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `30/0`, rejection_fail_closed `55/0`,
mainnet_authority_policy `9/0`, replay_recovery_idempotency `8/0`, non_mutation `14/0`,
reachability_taxonomy `11/0`. Total `127` pass, `0` fail. The helper runs each case under `catch_unwind`
and aggregates PASS/FAIL. It emits `fixtures/run_306_deterministic_digests.txt`; the harness runs the helper
twice and diffs the fixture to prove deterministic-digest stability:

* rotation_plan_digest `24313f4d2a3723598152a2b96ac777d9fe9afe2d903a77445db202802cabdf83`
* intent_digest `40480ca935ba2dc31a3b15b02ddb2435b336f500bd673d93e633ecd1ad8ec605`
* request_id `ab48aca99ce759ae121a60cd721cc686f016ab251e3f58f0255f822e158c55d6`
* transcript_digest `6b0bd769b6155f83e3568732319d11bab0eb287222e4496c6a29e47ac7a20e8a`
* outcome_tag `accepted-source-test-validator-set-rotation-application-decision`

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 305/306 validator-set rotation application boundary surface (no new CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  validator-set-rotation-application / epoch-transition enablement claim. (These return rc=1 because the binary
  fails closed on a missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented validator-set-rotation-application CLI selector
  (`--p2p-validator-set-rotation-application-policy allow-source-test`) is rejected as an `unexpected argument`
  (rc=2), proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  rotation-application claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Validator-set rotation application policy / kind / decision taxonomy release evidence

The helper exercises `ProductionValidatorSetRotationApplicationPolicy` (default `Disabled`, explicit
`AllowSourceTestValidatorSetRotationApplication` policy), `ProductionValidatorSetRotationApplicationKind`,
`ValidatorSetRotationApplicationDecisionKind`, `ValidatorSetRotationApplicationAuthoritySource`, and the typed
outcome taxonomy `ProductionValidatorSetRotationApplicationOutcome` /
`ProductionValidatorSetRotationApplicationRecoveryOutcome` in release mode. Reachability greps confirm the
taxonomy enums are present in the source module and driven by the helper.

## 7. Verified validator-set rotation plan composition release evidence

The boundary consumes a **verified** Run 303/304 validator-set rotation plan accept decision via
`ValidatorSetRotationApplicationAuthoritySource`, constructed from the real Run 303/304
`ProductionValidatorSetRotationDecision` / `ProductionValidatorSetRotationPlan` (itself composing the Run
301/302 verified governance execution accept decision). The boundary never self-authorizes: a missing /
unverified / governance-execution-intent-alone / governance-proof-alone / fixture / wrong-binding rotation-plan
input yields a typed fail-closed outcome and never a live validator-set mutation.

## 8. Canonical validator-set model composition release evidence

Run 306 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable replay
RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain
governance proof verifier, Run 302 governance execution engine, and Run 303/304 validator-set rotation intent
rows remain Green-for-release-binary-evidenced-scope only. The executor digests the current/proposed
validator-set snapshot referenced by the verified rotation plan, binds the rotation-plan / request-id /
transcript digests canonically, and refuses custody-only / RemoteSigner-only / attestation-only /
governance-execution-intent-alone material as application authority; only a verified validator-set rotation
plan binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`30/0`) show DevNet/TestNet source-test rotation application decisions that bind a verified
Run 303/304 validator-set rotation plan accept decision under the explicit
`AllowSourceTestValidatorSetRotationApplication` policy produce typed non-mutating validator-set rotation
application decisions/intents with stable rotation-plan / request-id / transcript digests, and never apply a
live validator-set change.

## 10. Rejection / fail-closed release evidence

Rejection cases (`55/0`) show missing / unverified rotation plan, governance-execution-intent-alone,
governance-proof-alone, fixture-alone, local-operator, peer-majority, custody-only, remote-signer-only,
custody-attestation-only, arbitrary-validator-set-bytes, wrong-field rotation-plan/validator-set binding,
rotation-plan-digest mismatch, application-policy-id / epoch-transition-target mismatch, non-monotonic
epoch/version, replayed application nonce, and stale governance-epoch / authority-sequence / validator-set-epoch
/ validator-set-version inputs each fail closed as a typed non-mutating
`ProductionValidatorSetRotationApplicationOutcome` with no fallback to fixture / local-operator / peer-majority
/ governance-proof-alone / governance-execution-intent-alone / RemoteSigner / custody-only / custody-attestation
material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`9/0`) show `MainNet` is refused absent production authority criteria
(fixture / local-operator / peer-majority / remote-signer-only / custody-alone / custody-attestation-alone /
governance-proof-alone / governance-execution-intent-alone / rotation-plan-alone-without-application-policy are
all insufficient), the default policy is `Disabled` (fails closed before any binding or application-intent
construction), the reserved production application policy is reachable but returns
`ProductionValidatorSetRotationApplicationUnavailable` /
`MainNetProductionValidatorSetRotationApplicationUnavailable`, and a valid DevNet/TestNet source-test accept
does not enable MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`8/0`) show `recover_validator_set_rotation_application_window` and the
`ValidatorSetRotationApplicationReplaySet` boundary reject replays idempotently and recover the application
window deterministically without mutation; conflicting rotation-plan / request-id / intent-digest in the same
window fail closed rather than being treated as idempotent, and stale epoch/sequence/version inputs fail closed
in evaluation.

## 13. Non-mutation evidence

Non-mutation cases (`14/0`) plus the harness no-mutation proof confirm the boundary produces only typed
non-mutating decisions/intents and every reject is non-mutating. The release helper drives the real Run 305
`ProductionValidatorSetRotationApplicationExecutor` only through the source/test boundary, only for
DevNet/TestNet identities on the accept path. It performs **no Run 070 call, no `LivePqcTrustState` mutation,
no live validator-set mutation, no consensus validator-set mutation, no epoch-counter mutation, no
`BasicHotStuffEngine::transition_to_epoch` call, no `meta:current_epoch` write, no reconfig-block injection,
no trust swap, no session eviction, no PQC trust-bundle sequence write, no authority marker write, no durable
replay overwrite, no settlement, no external publication, and no raw local production signing key load.**

## 14. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the boundary, adds no CLI flag, and enables neither the
boundary by default nor MainNet. S1–S6 confirm the default surfaces are silent on validator-set rotation
application / epoch-transition enablement, an invented rotation-application CLI selector is rejected as an
unexpected argument, and the denylist of forbidden positive-claim patterns (43 patterns) is clean across
captured logs and helper output (help text and helper summary excluded).

## 15. Tests run and results

Harness exit `0`. Regression corpus (all `rc=0`), recorded in `summary.txt`: `run_305` (primary Run 305 source
tests) first, then `run_303`, `run_301`, `run_299`, `run_297`, `run_295`, `run_293`, `run_291`, `run_186`,
`run_178`, `run_203`, `run_201`, `run_194`, `run_188`, `--lib pqc_authority`, and `--lib`.

## 16. Security scans

* Secret scanning over the changed files reported **no secrets**.
* CodeQL: see §Security below. Recorded honestly; no clean-coverage claim is implied unless the analysis
  actually completed.

## 17. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary readiness from
production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292 durable replay RocksDB, Run
294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain governance
proof verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent boundary, and
now the Run 305/306 validator-set rotation application / epoch-transition executor boundary. Red production rows
(MainNet authority rotation/revocation under production custody, production signing audit trail / crypto-agility
/ incident response, full MainNet release-binary evidence under production custody) remain Red. Run 306 does not
reinterpret this as C4/C5 closure and does not make validator-set rotation application MainNet-ready.

## 18. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no live validator-set, consensus, or epoch-counter mutation;
  no `BasicHotStuffEngine::transition_to_epoch` call; no `meta:current_epoch` write; no reconfig-block
  injection; no trust-bundle sequence or authority marker file writes; no settlement / external publication.
* A verified validator-set rotation plan is never turned into a live mutation — accepts produce typed
  non-mutating application decisions/intents only.
* Fixture / unverified-rotation-plan / governance-execution-intent-alone / governance-proof-alone /
  local-operator / peer-majority / custody-only / RemoteSigner-only / attestation-only / arbitrary-bytes
  material is never accepted as production application authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over all changed files reported **no secrets**.

## 19. Honest limitations

Run 306 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the
boundary into the default runtime, and does not implement MainNet authority rotation/revocation, live
validator-set mutation, consensus reconfiguration, epoch transition, settlement, or external publication. It
closes only the Run 305 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 /
302 / 304 Green-for-scope statuses. The `ProductionValidatorSetRotationApplicationError` type named generically
in the task does not exist as a separate enum; the real boundary surfaces every failure as a typed non-mutating
variant of `ProductionValidatorSetRotationApplicationOutcome`, and this substitution is recorded in the helper
module doc, the harness header, the archive README, and here.

## 20. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 306 makes no C4/C5 closure claim, no MainNet-readiness claim, and
no runtime default-enablement claim. The validator-set rotation application / epoch-transition executor row is
Green-for-scope only; MainNet authority rotation/revocation under production custody remains Red.

## 21. Suggested Run 307 next step

Proceed to the next Red-row closure campaign toward MainNet authority rotation/revocation under production
custody. **Run 307 — source/test real production live validator-set / epoch-transition application boundary**
(or the next narrowest Red row per the C4/C5 matrix): source/test only, deterministic, default
`Disabled`/fail-closed, MainNet refused, non-mutating on rejection, consuming a verified Run 305/306 validator-set
rotation application decision and producing a typed non-mutating live-application intent, with release-binary
evidence deferred to Run 308.
