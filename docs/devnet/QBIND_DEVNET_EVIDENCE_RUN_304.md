# QBIND DevNet Evidence — Run 304

Release-binary evidence for the Run 303 validator-set rotation / authority-set synchronization intent boundary.

## 1. Exact verdict

**PASS (release-binary evidence only; validator-set rotation Green-for-scope; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

Run 304 is release-binary evidence for the Run 303 real validator-set rotation / authority-set synchronization intent boundary
(`crates/qbind-node/src/pqc_production_validator_set_rotation_intent.rs`,
`ProductionValidatorSetRotationBoundary`). It adds no new production runtime wiring, no public CLI
flag, no default enablement, and no MainNet enablement. The release helper links and exercises the
real Run 303 boundary over the real Run 301/302 verified governance execution accept decision in release
mode; every failure surfaces as a typed non-mutating `ProductionValidatorSetRotationOutcome`. Full C4
remains OPEN and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_304_production_validator_set_rotation_intent_release_binary_helper.rs`
  — new release helper mirroring the Run 303 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator and a release-symbol reachability probe.
* `scripts/devnet/run_304_production_validator_set_rotation_intent_release_binary.sh` — new LF-clean,
  executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof,
  regression corpus, `summary.txt` emission).
* `docs/devnet/run_304_production_validator_set_rotation_intent_release_binary/` — evidence archive
  (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_304.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 304; validator-set
  rotation / authority-set synchronization row moved Yellow → Green-for-release-binary-evidenced-scope-only;
  C4 summary updated; Run 304 timeline entry appended.
* `docs/whitepaper/contradiction.md` — Run 304 entry.

No change was made to the Run 303 boundary source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked `docs/devnet/run_304_production_validator_set_rotation_intent_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `543f3f89e951bb23e6ce827f13148149a5966967622363a5b117350eb278c713`
  (recorded as `qbind_node_sha256` in `summary.txt`).
* `target/release/examples/run_304_production_validator_set_rotation_intent_release_binary_helper` —
  SHA-256 `21d4696d4d978e5ddd30c09620f00267667cb63fa4e61fed584d2a7f61458517`
  (recorded as `helper_304_sha256` in `summary.txt`).
* Toolchain: `rustc 1.96.0`, `cargo 1.96.0` (recorded in `summary.txt`).

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `30/0`, rejection_fail_closed `58/0`,
mainnet_authority_policy `12/0`, replay_recovery_idempotency `13/0`, non_mutation `8/0`,
reachability_taxonomy `11/0`. Total `132` pass, `0` fail. The helper runs each case under
`catch_unwind` and aggregates PASS/FAIL. It emits `fixtures/run_304_deterministic_digests.txt`; the
harness runs the helper twice and diffs the fixture to prove deterministic-digest stability:

* plan_digest `24313f4d2a3723598152a2b96ac777d9fe9afe2d903a77445db202802cabdf83`
* request_id `ec4f00b3815308ad15df13a00bcd8bad2301dfc301c117661dcbcf40f96057b2`
* transcript_digest `6bfb7b5650cec287f71c190d84337eb586340d235e0296486b0d92dad949fb7c`
* outcome_tag `accepted-source-test-validator-set-rotation-plan`

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 303/304 validator-set rotation boundary surface (no new CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  validator-set-rotation / authority-set-synchronization enablement claim. (These return rc=1 because the
  binary fails closed on a missing `--genesis-path`; the harness asserts surface silence, not rc=0, for
  S2–S4.)
* S5 invented validator-set-rotation CLI selector (`--p2p-validator-set-rotation-policy allow-source-test`)
  is rejected as an `unexpected argument` (rc=2), proving no such public CLI flag exists.
* S6 default DevNet genesis-hash surface fails closed requiring `--genesis-path` (rc=1) and stays silent
  on rotation claims.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5_no_selector=2 S6_default_parse=1` in `summary.txt`.

## 6. Validator-set rotation policy / kind / plan taxonomy release evidence

The helper exercises `ProductionValidatorSetRotationPolicy` (default `Disabled`, explicit
`AllowSourceTestValidatorSetRotationIntent` policy), `ProductionValidatorSetRotationKind`,
`ProductionValidatorSetRotationPlanKind`, `ValidatorSetRotationAction`, and the typed outcome taxonomy
`ProductionValidatorSetRotationOutcome` / `ProductionValidatorSetRotationRecoveryOutcome` in release
mode. Reachability greps confirm the taxonomy enums are present in the source module and driven by the
helper.

## 7. Verified governance execution intent composition release evidence

The boundary consumes a **verified** Run 301/302 governance execution accept decision via
`ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent`, constructed from the real Run
301/302 `ProductionGovernanceExecutionDecision` / `ProductionGovernanceExecutionIntent`. The boundary
never self-authorizes: a missing / unverified / on-chain-proof-alone / fixture / wrong-binding
governance input yields a typed fail-closed outcome and never a live validator-set mutation.

## 8. Canonical validator-set model composition release evidence

Run 304 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable
replay RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier,
Run 300 on-chain governance proof verifier, and Run 302 governance execution engine rows remain
Green-for-release-binary-evidenced-scope only. The boundary digests the current/proposed
`CanonicalValidatorSetSnapshot` (`CanonicalValidatorIdentity` / `CanonicalValidatorRecord` /
`ValidatorSetChange` / `ValidatorSetDelta`), sorts validator records canonically before digesting, and
refuses custody-only / RemoteSigner-only / attestation-only material as rotation authority; only a
verified governance execution intent binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`30/0`) show DevNet/TestNet source-test rotation intents that bind a verified
Run 301/302 governance execution accept decision under the explicit
`AllowSourceTestValidatorSetRotationIntent` policy produce typed non-mutating validator-set rotation
plans (`ValidatorAdd` / `ValidatorRemove` / `ValidatorMetadataUpdate` / `ValidatorIdentityRotation` /
`ValidatorRetirement` / `NoOpAlreadySynchronized` / `BulkValidatorSetRotation` /
`AuthoritySetSynchronization`) with stable plan / request-id / transcript digests.

## 10. Rejection / fail-closed release evidence

Rejection cases (`58/0`) show missing / unverified governance intent, on-chain-proof-alone,
fixture-alone, local-operator, peer-majority, custody-only, remote-signer-only, custody-attestation-only,
wrong-field governance/validator-set binding, current/proposed-set-digest mismatch, validator-set
epoch/version mismatch, non-monotonic epoch/version, empty-proposed-set, duplicate
id/consensus/transport/authority key, unknown removal/update, conflicting/ambiguous/unsupported delta,
unsupported rotation action, custody/attestation/durable-replay required-and-mismatch, replayed rotation
nonce, and stale governance-epoch/authority-sequence/validator-set-epoch/validator-set-version inputs
each fail closed as a typed non-mutating `ProductionValidatorSetRotationOutcome` with no fallback to
fixture / local-operator / peer-majority / on-chain-proof-alone / RemoteSigner / custody-only /
custody-attestation material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`12/0`) show `MainNet` is refused absent production authority criteria
(fixture / local-operator / peer-majority / remote-signer-only / custody-alone / custody-attestation-alone
/ on-chain-proof-alone / governance-intent-alone are all insufficient), the default policy is `Disabled`
(fails closed before any binding or plan construction), the reserved
`RequireProductionValidatorSetRotation` / `MainnetProductionValidatorSetRotationRequired` policies are
reachable but return `ProductionValidatorSetRotationUnavailable` /
`MainNetProductionValidatorSetRotationUnavailable`, and a valid DevNet/TestNet source-test accept does
not enable MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`13/0`) show `recover_validator_set_rotation_window` and the
`ValidatorSetRotationReplaySet` boundary reject replays idempotently and recover the rotation window
deterministically without mutation; conflicting proposed/current/lifecycle/intent-digest in the same
window fail closed rather than being treated as idempotent, and stale epoch/sequence/version inputs fail
closed in evaluation.

## 13. Non-mutation evidence

Non-mutation cases (`8/0`) plus the harness no-mutation proof confirm the boundary produces only typed
non-mutating plans and every reject is non-mutating. The release helper drives the real Run 303
`ProductionValidatorSetRotationBoundary` only through the source/test boundary, only for DevNet/TestNet
identities on the accept path. It performs **no Run 070 call, no `LivePqcTrustState` mutation, no live
validator-set mutation, no consensus validator-set mutation, no `BasicHotStuffEngine::transition_to_epoch`
call, no `meta:current_epoch` write, no reconfig-block injection, no trust swap, no session eviction, no
PQC trust-bundle sequence write, no authority marker write, no durable replay overwrite, no settlement,
no external publication, and no raw local production signing key load.**

## 14. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the boundary, adds no CLI flag, and enables neither
the boundary by default nor MainNet. S1–S6 confirm the default surfaces are silent on validator-set
rotation / authority-set synchronization enablement, an invented rotation CLI selector is rejected as an
unexpected argument, and the denylist of forbidden positive-claim patterns (37 patterns) is clean across
captured logs and helper output (help text and helper summary excluded).

## 15. Tests run and results

Harness exit `0`. Regression corpus (all `rc=0`), recorded in `summary.txt`: `run_303` (primary Run 303
source tests) first, then `run_301`, `run_299`, `run_297`, `run_295`, `run_293`, `run_291`, `run_186`,
`run_178`, `run_203`, `run_201`, `run_194`, `run_188`, `--lib pqc_authority`, and `--lib`.

## 16. Security scans

* Secret scanning over the changed files reported **no secrets**.
* CodeQL: see §Security below. Recorded honestly; no clean-coverage claim is implied unless the analysis
  actually completed.

## 17. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary
readiness from production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292 durable
replay RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier, Run
300 on-chain governance proof verifier, Run 302 governance execution engine, and now the Run 303/304
validator-set rotation / authority-set synchronization intent boundary. Red production rows (MainNet
authority rotation/revocation under production custody, production signing audit trail / crypto-agility /
incident response, full MainNet release-binary evidence under production custody) remain Red. Run 304
does not reinterpret this as C4/C5 closure and does not make validator-set rotation MainNet-ready.

## 18. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no live validator-set or consensus mutation; no
  `BasicHotStuffEngine::transition_to_epoch` call; no `meta:current_epoch` write; no reconfig-block
  injection; no trust-bundle sequence or authority marker file writes; no settlement / external
  publication.
* Verified governance execution intent is never turned into a live mutation — accepts produce typed
  non-mutating plans only.
* Fixture / unverified-governance-intent / on-chain-proof-alone / local-operator / peer-majority /
  custody-only / RemoteSigner-only / attestation-only material is never accepted as production rotation
  authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over all changed files reported **no secrets**.

## 19. Honest limitations

Run 304 is release-binary evidence only. It does not enable any production mutating behavior, does not
wire the boundary into the default runtime, and does not implement MainNet authority rotation/revocation,
live validator-set mutation, consensus reconfiguration, settlement, or external publication. It closes
only the Run 303 release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 / 302
Green-for-scope statuses. The `ProductionValidatorSetRotationError` type named generically in the task
does not exist as a separate enum; the real boundary surfaces every failure as a typed non-mutating
variant of `ProductionValidatorSetRotationOutcome`, and this substitution is recorded in the helper
module doc, the harness header, and here.

## 20. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 304 makes no C4/C5 closure claim, no MainNet-readiness
claim, and no runtime default-enablement claim. The validator-set rotation / authority-set
synchronization row is Green-for-scope only; MainNet authority rotation/revocation under production
custody remains Red.

## 21. Suggested Run 305 next step

Proceed to the next Red-row closure campaign toward MainNet authority rotation/revocation under
production custody. **Run 305 — source/test real production authority-rotation / revocation application
boundary** (or the next narrowest Red row per the C4/C5 matrix): source/test only, deterministic, default
`Disabled`/fail-closed, MainNet refused, non-mutating on rejection, consuming a verified Run 303/304
validator-set rotation plan and producing a typed non-mutating application intent, with release-binary
evidence deferred to Run 306.
