# QBIND DevNet Evidence — Run 302

Release-binary evidence for the Run 301 production governance execution engine.

## 1. Exact verdict

**PASS (release-binary evidence only; Full C4 OPEN; C5 OPEN).**

Run 302 is release-binary evidence for the Run 301 real production governance execution engine
(`crates/qbind-node/src/pqc_production_governance_execution_engine.rs`,
`ProductionGovernanceExecutionEngine`). It adds no new production runtime wiring, no public CLI
flag, no default enablement, and no MainNet enablement. The release helper links and exercises the
real Run 301 engine over the real Run 299 verified on-chain governance proof decision in release
mode; every failure surfaces as a typed non-mutating `ProductionGovernanceExecutionOutcome`. Full C4
remains OPEN and C5 remains OPEN.

## 2. Files changed

* `crates/qbind-node/examples/run_302_production_governance_execution_engine_release_binary_helper.rs`
  — new release helper mirroring the Run 301 test corpus as release-linked free-function cases plus a
  `run_case`/`main` aggregator.
* `scripts/devnet/run_302_production_governance_execution_engine_release_binary.sh` — new LF-clean,
  executable end-to-end harness (release builds, helper twice + deterministic-digest diff, S1–S6
  real-binary scenarios, reachability greps, C4/C5 taxonomy greps, denylist, no-mutation proof,
  regression corpus, `summary.txt` emission).
* `docs/devnet/run_302_production_governance_execution_engine_release_binary/` — evidence archive
  (`README.md`, `summary.txt`, `.gitignore`; per-run artifacts git-ignored).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_302.md` — this canonical evidence file.
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status line advanced to Run 302; governance
  execution engine row moved Yellow → Green-for-release-binary-evidenced-scope-only; Run 301 + Run 302
  timeline entries appended.
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — narrow Run 302 evidence notes.
* `docs/whitepaper/contradiction.md` — Run 302 entry.

No change was made to the Run 301 engine source or any other production runtime code.

## 3. Release artifacts and hashes

Captured in the tracked `docs/devnet/run_302_production_governance_execution_engine_release_binary/summary.txt`:

* `target/release/qbind-node` — SHA-256 `1ae729605934543b891c5ae10300973e4106a4b20147e11d2ccb2e407c8bee59`
  (recorded as `qbind_node_sha256` in `summary.txt`).
* `target/release/examples/run_302_production_governance_execution_engine_release_binary_helper` —
  SHA-256 `eb20488fc6f63f5c72e13efc3d0b6bcb85c4884a7d3b211fe70566d9d4030710`
  (recorded as `helper_302_sha256` in `summary.txt`).
* Toolchain: `rustc 1.96.0`, `cargo 1.96.0` (recorded in `summary.txt`).

## 4. Helper corpus results

Release helper verdict **PASS**. Per-table: accepted_compatible `33/0`, rejection_fail_closed `43/0`,
mainnet_authority_policy `8/0`, replay_recovery_idempotency `13/0`, non_mutation `10/0`,
reachability_taxonomy `11/0`. Total `118` pass, `0` fail. The helper runs each case under
`catch_unwind` and aggregates PASS/FAIL. It emits `fixtures/run_302_deterministic_digests.txt`; the
harness runs the helper twice and diffs the fixture to prove deterministic-digest stability:

* request_id `1e62f3d10847ecee63da12a5285843b4ade57f13752260491b72d034355955bb`
* intent_digest `88bbc0c3df90f873c446307c3568b17be4b59ca6e284114c0d4f8ce2b6eb9d85`
* transcript_digest `32e29707d5949c6da5fe5d1de097e3a62f661c54406a2d22e7a8ae27a7bfcd58`
* outcome_tag `accepted-source-test-governance-execution-intent`

## 5. Real-binary scenarios

* S1 `--help` → rc=0, hides the Run 301/302 governance execution engine surface (no new CLI flag).
* S2 DevNet, S3 TestNet, S4 MainNet (`--print-genesis-hash --env …`) → each surface is silent on any
  governance-execution-engine enablement claim. (These return rc=1 because the binary fails closed on a
  missing `--genesis-path`; the harness asserts surface silence, not rc=0, for S2–S4.)
* S5 hidden governance-execution selector (`--p2p-trust-bundle-governance-execution-policy
  fixture-governance-allowed`) still parses; no new governance-execution-engine CLI selector is added.
* S6 invalid governance-execution selector (`bogus-policy`) fails closed before any mutation and emits
  `invalid governance-execution policy selector`.

Recorded as `release_binary_scenarios: S1_help=0 S2=1 S3=1 S4=1 S5=1 S6=1` in `summary.txt`.

## 6. Governance execution policy / kind / intent taxonomy release evidence

The helper exercises `ProductionGovernanceExecutionEnginePolicy` (default `Disabled`, explicit
source/test production policy), `ProductionGovernanceExecutionEngineKind`,
`ProductionGovernanceExecutionIntentKind`, and the typed outcome taxonomy
`ProductionGovernanceExecutionOutcome` / `ProductionGovernanceExecutionRecoveryOutcome` in release
mode. Reachability greps confirm the taxonomy enums are present in the source module and driven by the
helper.

## 7. Verified on-chain governance proof binding release evidence

The engine consumes a **verified** Run 299 on-chain governance proof decision via
`GovernanceExecutionProofBinding` / `GovernanceExecutionProofSource`, constructed from the real Run 299
`ProductionOnChainGovernanceProofVerifier`. The engine never self-authorizes: an unverified/malformed/
wrong-domain/wrong-binding proof yields a typed fail-closed outcome and never a live mutation.

## 8. Custody / attestation / durable replay composition release evidence

Run 302 composes over the prior Green-for-scope boundaries without weakening them: the Run 292 durable
replay RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation verifier,
and Run 300 on-chain governance proof verifier rows remain Green-for-release-binary-evidenced-scope
only. The engine refuses custody-only / RemoteSigner-only / attestation-only material as governance
execution authority; only a verified on-chain governance proof decision binds an accept.

## 9. Accepted release evidence

Accepted-path cases (`33/0`) show DevNet/TestNet source-test production intents that bind a verified
Run 299 proof decision under the explicit source/test production policy produce typed non-mutating
authority-lifecycle execution intents with stable request-id / intent / transcript digests.

## 10. Rejection / fail-closed release evidence

Rejection cases (`43/0`) show missing / malformed / unsupported / replay / wrong-domain /
wrong-binding / unverified-proof / expired / quorum-not-met / threshold-not-met inputs each fail closed
as a typed non-mutating `ProductionGovernanceExecutionOutcome` with no fallback to fixture /
local-operator / peer-majority / RemoteSigner / custody-only / custody-attestation material.

## 11. MainNet refusal / authority policy release evidence

MainNet-authority-policy cases (`8/0`) show `MainNet` is refused absent production authority criteria,
the default policy is `Disabled` (fails closed before any parsing/verification), and the fixture proof
(suite `0xA1`) is rejected as production authority and refused for MainNet.

## 12. Replay / recovery / idempotency release evidence

Replay/recovery cases (`13/0`) show `recover_production_governance_execution_window` and the
`GovernanceExecutionReplaySet` boundary reject replays idempotently and recover the execution window
deterministically without mutation.

## 13. Production-binary default-disabled/silent evidence

The production `qbind-node` binary never constructs the engine, adds no CLI flag, and enables neither
the engine by default nor MainNet. S1–S6 confirm the default surfaces are silent on governance
execution engine enablement, and the denylist of forbidden positive-claim patterns is clean across
captured logs and helper output (help text and helper summary excluded).

## 14. Tests run and results

Harness exit `0`. Regression corpus (all `rc=0`), recorded in `summary.txt`: `run_301` (primary Run 301
source tests) first, then `run_299`, `run_297`, `run_295`, `run_293`, `run_291`, `run_186`, `run_178`,
`run_203`, `run_201`, `run_194`, `run_188`, the preceding even release-binary evidence corpus `run_290`
… `run_224`, `--lib pqc_authority`, and `--lib`.

**Known pre-existing issue (not introduced by Run 302):** the unrelated
`m16_epoch_transition_hardening_tests.rs` target has a pre-existing compile failure and is therefore
not part of the Run 302 corpus. This is reported honestly and is outside Run 302 scope.

## 15. C4/C5 matrix taxonomy status

The C4/C5 closure-criteria matrix taxonomy clarification remains present and separates boundary
readiness from production readiness. Green-for-release-binary-evidenced-scope-only rows: Run 292
durable replay RocksDB, Run 294 RemoteSigner, Run 296 KMS/HSM custody, Run 298 custody attestation
verifier, Run 300 on-chain governance proof verifier, and now the Run 301/302 governance execution
engine. Red production rows (validator-set rotation / authority-set synchronization, MainNet authority
rotation/revocation under production custody, production signing audit trail / crypto-agility /
incident response, full MainNet release-binary evidence under production custody) remain Red. Run 302
does not reinterpret this as C4/C5 closure.

## 16. Security invariants preserved

* No Run 070 call; no `LivePqcTrustState` mutation; no trust-bundle sequence or authority marker file
  writes; no validator-set rotation; no settlement / external publication.
* Verified proof is never turned into a live mutation — accepts produce typed non-mutating intents only.
* Fixture / local-operator / peer-majority / custody-only / RemoteSigner-only / attestation-only
  material is never accepted as production governance execution authority.
* No new public CLI surface; default `Disabled`/fail-closed; MainNet refused.
* Secret scanning over the changed files reported **no secrets**.
* CodeQL: _[to be finalized — see below]_.

## 17. Honest limitations

Run 302 is release-binary evidence only. It does not enable any production mutating behavior, does not
wire the engine into the default runtime, and does not implement validator-set rotation /
authority-set synchronization, settlement, or external publication. It closes only the Run 301
release-binary evidence gap and does not weaken the Run 292 / 294 / 296 / 298 / 300 Green-for-scope
statuses. The `ProductionGovernanceExecutionError` type named generically in the task does not exist as
a separate enum; the real engine surfaces every failure as a typed non-mutating variant of
`ProductionGovernanceExecutionOutcome`, and this substitution is recorded in the helper module doc and
here.

## 18. C4/C5 status

**Full C4 remains OPEN. C5 remains OPEN.** Run 302 makes no C4/C5 closure claim, no MainNet-readiness
claim, and no runtime default-enablement claim.

## 19. Suggested Run 303 next step

Begin the next Red-row closure campaign: **Run 303 — source/test validator-set rotation /
authority-set synchronization intent boundary.** After Run 302, durable replay, RemoteSigner, KMS/HSM
custody, custody attestation verifier, on-chain governance proof verifier, and the governance execution
engine can all be Green-for-scope, so the next C4/C5 blocker is validator-set rotation / authority-set
synchronization. Run 303 should be source/test only, deterministic, default `Disabled`/fail-closed,
MainNet refused, non-mutating on rejection, producing a typed rotation/synchronization plan or intent
only, with release-binary evidence deferred to Run 304.
