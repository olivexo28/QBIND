# QBIND DevNet Evidence — Run 308

Release-binary evidence for the Run 307 live validator-set application / epoch-transition authorization boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; live validator-set application authorization Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 308 is release-binary evidence for the Run 307 real live validator-set application / epoch-transition
authorization boundary (`crates/qbind-node/src/pqc_production_live_validator_set_application_authorization.rs`,
`ProductionLiveValidatorSetApplicationAuthorizationExecutor`). It adds no new production runtime wiring, no public
CLI flag, no default enablement, and no MainNet enablement. The release helper links and exercises the real Run 307
boundary over the real Run 305/306 verified validator-set rotation application accept decision (`is_accept()` with
`Some(application_intent)`; itself composing the Run 303/304 verified validator-set rotation plan accept decision and
the Run 301/302 verified governance execution accept decision) in release mode; every failure surfaces as a typed
non-mutating `ProductionLiveValidatorSetApplicationAuthorizationOutcome`. Full C4 remains OPEN and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_308_production_live_validator_set_application_authorization_release_binary_helper.rs`
  — new release helper mirroring the Run 307 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_308_production_live_validator_set_application_authorization_release_binary.sh` — new
  LF-clean, executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof, regression
  corpus, `summary.txt` emission).
* `docs/devnet/run_308_production_live_validator_set_application_authorization_release_binary/` — evidence
  archive (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_308.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 308; live validator-set
  application / epoch-transition authorization row moved Yellow → Green-for-release-binary-evidenced-scope-only;
  C4 summary updated; Run 308 timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 308 entry.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — narrow Run 308 note appended to each.

No change was made to the Run 307 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked
`docs/devnet/run_308_production_live_validator_set_application_authorization_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `7009fdf9c86b491b95b5bd073612e125a37469d514f8068dc777ec8a2743159b`
  (recorded as `qbind_node_sha256` in `summary.txt`).
* `target/release/examples/run_308_production_live_validator_set_application_authorization_release_binary_helper`
  — SHA-256 `8fb9275f14d5b2b5d2b8cdb388719cf276bcce292d6f09692c2ad1f2b553ffda`
  (recorded as `helper_308_sha256` in `summary.txt`).
* Toolchain: `rustc 1.96.0`, `cargo 1.96.0` (recorded in `summary.txt`).

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `31/0`, rejection_fail_closed `62/0`,
mainnet_authority_policy `9/0`, replay_recovery_idempotency `8/0`, non_mutation `15/0`,
reachability_taxonomy `11/0`. Total `136` pass, `0` fail. The helper runs each case under `catch_unwind`
and aggregates PASS/FAIL. It emits `fixtures/run_308_deterministic_digests.txt`; the harness runs the helper
twice and diffs the fixture to prove deterministic-digest stability:

* application_intent_digest `40480ca935ba2dc31a3b15b02ddb2435b336f500bd673d93e633ecd1ad8ec605`
* intent_digest `2e68313bc36f5567fe4508ac7935c7ea093660a718c0f34fddcfd10a1b1f2cfb`
* request_id `1a00a280d513930cd1aa10c9e591b1633be02ec438b722029f635303e4f9cba3`
* transcript_digest `28929160717ed45eb881d3c02522b4b794fb0b46ac5e35a9d6c03a363b4fd777`
* outcome_tag `accepted-source-test-live-validator-set-application-authorization`

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 307/308 live validator-set application authorization boundary surface (no new CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  live-validator-set-application / epoch-transition authorization enablement claim. (These return rc=1 because the
  binary fails closed on a missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 invented live-validator-set-application-authorization CLI selector
  (`--p2p-live-validator-set-application-authorization-policy allow-source-test`) is rejected as an
  `unexpected argument` (rc=2), proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent on
  authorization claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Live validator-set application authorization policy / kind / decision taxonomy release evidence

The helper exercises `ProductionLiveValidatorSetApplicationAuthorizationPolicy` (default `Disabled`, explicit
source-test policy), `ProductionLiveValidatorSetApplicationAuthorizationKind`,
`LiveValidatorSetApplicationAuthorizationKind`, `LiveValidatorSetApplicationAuthorizationAuthoritySource`, and the
typed outcome taxonomy `ProductionLiveValidatorSetApplicationAuthorizationOutcome` /
`ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome` in release mode. Reachability greps confirm the
taxonomy enums are present in the source module and driven by the helper.

## 7. Verified validator-set rotation application composition release evidence

The boundary consumes a **verified** Run 305/306 validator-set rotation application accept decision via
`LiveValidatorSetApplicationAuthorizationAuthoritySource::VerifiedApplicationDecision`, constructed from the real
Run 305/306 `ProductionValidatorSetRotationApplicationDecision` that `is_accept()` and carries
`Some(application_intent)` (itself composing the Run 303/304 verified validator-set rotation plan accept decision and
the Run 301/302 verified governance execution accept decision). The boundary never self-authorizes: a missing /
unverified / accepted-without-application-intent / rotation-plan-alone / governance-execution-intent-alone /
governance-proof-alone / fixture / wrong-binding application input yields a typed fail-closed outcome and never a
live validator-set mutation.

## 8. Canonical validator-set model composition release evidence

Run 308 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable replay
RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain
governance proof verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent, and Run
305/306 validator-set rotation application executor rows remain Green-for-release-binary-evidenced-scope only. The
executor digests the current/proposed/delta validator-set snapshot referenced by the verified application decision,
binds the application-decision / request-id / transcript / authorization-intent digests canonically plus the
epoch-transition target and live-application nonce, and refuses custody-only / RemoteSigner-only / attestation-only
/ governance-execution-intent-alone / rotation-plan-alone material as authorization authority; only a verified
validator-set rotation application decision with `Some(application_intent)` binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`31/0`) show DevNet/TestNet source-test authorization requests that bind a verified
Run 305/306 validator-set rotation application accept decision (with `Some(application_intent)`) under the explicit
source-test policy produce typed non-mutating live-application authorization intents with stable
application-intent / intent / request-id / transcript digests, and never apply a live validator-set change.

## 10. Rejection / fail-closed release evidence

Rejection cases (`62/0`) show missing / unverified application decision, accepted-decision-without-application-intent,
rotation-plan-alone, governance-execution-intent-alone, governance-proof-alone, fixture-only application decision,
local-operator, peer-majority, custody-only, remote-signer-only, custody-attestation-only, arbitrary-validator-set-bytes,
wrong-field governance/rotation/validator-set binding, application-decision-integrity mismatch,
application-policy-id / epoch-transition-target mismatch, wrong application / live-application nonce, non-monotonic
epoch/version, replayed authorization id, and stale governance-epoch / authority-sequence / validator-set-epoch /
validator-set-version inputs each fail closed as a typed non-mutating
`ProductionLiveValidatorSetApplicationAuthorizationOutcome` with no fallback to fixture / local-operator /
peer-majority / governance-proof-alone / governance-execution-intent-alone / rotation-plan-alone / RemoteSigner /
custody-only / custody-attestation material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`9/0`) show `MainNet` is refused absent production authority criteria
(fixture / local-operator / peer-majority / remote-signer-only / custody-alone / custody-attestation-alone /
governance-proof-alone / governance-execution-intent-alone / rotation-plan-alone / accepted-without-application-intent
are all insufficient), the default policy is `Disabled` (fails closed before any binding or authorization-intent
construction), the reserved production authorization policy is reachable but returns the typed unavailable outcome,
and a valid DevNet/TestNet source-test accept does not enable MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`8/0`) show `recover_live_validator_set_application_authorization_window` and the
`LiveValidatorSetApplicationAuthorizationReplaySet` boundary reject replays idempotently and recover the
authorization window deterministically without mutation; conflicting application-decision / request-id /
intent-digest in the same window fail closed rather than being treated as idempotent, and stale
epoch/sequence/version inputs fail closed in evaluation.

## 13. Non-mutation evidence

Non-mutation cases (`15/0`) plus the harness no-mutation proof confirm the boundary produces only typed
non-mutating authorization intents and every reject is non-mutating. The release helper drives the real Run 307
`ProductionLiveValidatorSetApplicationAuthorizationExecutor` only through the source/test boundary, only for
DevNet/TestNet identities on the accept path. It performs **no Run 070 call, no `LivePqcTrustState` mutation,
no live validator-set mutation, no consensus validator-set mutation, no epoch-counter mutation, no
`BasicHotStuffEngine::transition_to_epoch` call, no `meta:current_epoch` write, no `PAYLOAD_KIND_RECONFIG`
block injection, no trust swap, no session eviction, no PQC trust-bundle sequence write, no authority marker write,
no durable replay overwrite, no settlement, no external publication, and no raw local production signing key load.**

## 14. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the boundary, adds no CLI flag, and enables neither the
boundary by default nor MainNet. S1–S6 confirm the default surfaces are silent on live validator-set
application / epoch-transition authorization enablement, an invented authorization CLI selector is rejected as an
unexpected argument, and the denylist of forbidden positive-claim patterns is clean across
captured logs and helper output (help text and helper summary excluded).

## 15. Tests run and results

Harness exit `0`. Regression corpus (all `rc=0`), recorded in `summary.txt`: `run_307` (primary Run 307 source
tests) first, then `run_305`, `run_303`, `run_301`, `run_299`, `run_297`, `run_295`, `run_293`, `run_291`,
`run_186`, `run_178`, `run_203`, `run_201`, `run_194`, `run_188`, `--lib pqc_authority`, and `--lib`.

## 16. Security scans

* Secret scanning over the changed files reported **no secrets**.
* CodeQL: see §Security below. Recorded honestly; no clean-coverage claim is implied unless the analysis
  actually completed.

## 17. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary readiness from
production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292 durable replay RocksDB, Run
294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run 300 on-chain governance
proof verifier, Run 302 governance execution engine, Run 303/304 validator-set rotation intent boundary, Run
305/306 validator-set rotation application / epoch-transition executor boundary, and now the Run 307/308 live
validator-set application / epoch-transition authorization boundary. Red production rows (MainNet authority
rotation/revocation under production custody, production signing audit trail / crypto-agility / incident response,
full MainNet release-binary evidence under production custody) remain Red. Run 308 does not reinterpret this as
C4/C5 closure and does not make live validator-set application authorization MainNet-ready.

## 18. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no live validator-set, consensus, or epoch-counter mutation;
  no `BasicHotStuffEngine::transition_to_epoch` call; no `meta:current_epoch` write; no `PAYLOAD_KIND_RECONFIG`
  block injection; no trust-bundle sequence or authority marker file writes; no settlement / external publication.
* A verified validator-set rotation application decision is never turned into a live mutation — accepts produce
  typed non-mutating authorization intents only.
* Missing / unverified / accepted-without-application-intent application decisions, and rotation-plan-alone /
  governance-execution-intent-alone / governance-proof-alone / fixture / local-operator / peer-majority /
  custody-only / RemoteSigner-only / attestation-only / arbitrary-bytes material, are never accepted as production
  authorization authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over all changed files reported **no secrets**.

## 19. Honest limitations

Run 308 is release-binary evidence only. It does not enable any production mutating behavior, does not wire the
boundary into the default runtime, and does not implement MainNet authority rotation/revocation, live
validator-set mutation, consensus reconfiguration, epoch transition, settlement, or external publication. It
closes only the Run 307 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 /
302 / 304 / 306 Green-for-scope statuses. The `ProductionLiveValidatorSetApplicationAuthorizationError` type
named generically in the task does not exist as a separate enum; the real boundary surfaces every failure as a
typed non-mutating variant of `ProductionLiveValidatorSetApplicationAuthorizationOutcome`, and this substitution
is recorded in the helper module doc, the harness header, the archive README, and here.

## 20. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 308 makes no C4/C5 closure claim, no MainNet-readiness claim, and
no runtime default-enablement claim. The live validator-set application / epoch-transition authorization row is
Green-for-scope only; MainNet authority rotation/revocation under production custody remains Red.

## 21. Suggested Run 309 next step

Proceed to the next Red-row closure campaign toward MainNet authority rotation/revocation under production
custody. **Run 309 — source/test real production mutating live validator-set / epoch-transition application
executor boundary** (or the next narrowest Red row per the C4/C5 matrix): source/test only, deterministic, default
`Disabled`/fail-closed, MainNet refused, consuming a verified Run 307/308 live validator-set application
authorization intent and producing a typed staged epoch-transition application record without live mutation, with
release-binary evidence deferred to Run 310.