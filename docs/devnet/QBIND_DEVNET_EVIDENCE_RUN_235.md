# QBIND DevNet evidence — Run 235

**Title.** Release-binary governance evaluator post-mutation replay consume
boundary evidence.

**Status.** PASS (release-binary). Run 235 is the release-binary evidence run
for the Run 234 source/test governance evaluator **post-mutation replay consume
boundary**. It proves, in release mode, that the consume step that records a
governance decision as consumed runs **only after a successful mutation** — it
is after-success-only. Run 230 proved a typed replay/freshness state boundary,
Run 231 closed its release-binary evidence, Run 232 composed that boundary into
the Run 224 evaluator-runtime integration path as a mandatory pre-mutation gate,
Run 233 closed that composition's release-binary evidence, and Run 234 added the
strict after-success-only consume boundary at the source/test level. Run 235
proves on real `target/release/qbind-node` plus a release-built helper that the
release-built code exposes and exercises the consume boundary: consume is
after-success-only; legacy-bypass, deferred (fresh-but-not-yet-effective),
validation-only, authorized-but-not-applied, failed-apply, rolled-back,
unsupported-surface, and MainNet-refused outcomes never consume; the
DevNet/TestNet fixture writer records consumed only on an explicit after-success
`perform_post_mutation_consume` call (with a prior observation); the
production / MainNet consume writers remain callable but always fail closed
unavailable; MainNet peer-driven apply remains refused and never consumes even
when the replay state would otherwise be fresh; and the consume
authorization / transcript / record digests are deterministic in release mode.

Run 235 is **release-binary evidence only**. It implements **no** real
governance execution engine, **no** real on-chain governance proof verifier,
**no** real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, **no** MainNet peer-driven apply enablement, and **no**
validator-set rotation. It changes **no** wire, schema, marker, sequence, or
trust-bundle format and introduces **no** RocksDB schema, file format, or
database migration.

## Strict scope

* Release-binary evidence only.
* Uses a release-built helper and the real `target/release/qbind-node` where
  applicable.
* No production source behavior change.
* No real governance execution engine; no real on-chain governance proof
  verifier.
* No MainNet governance enablement; no MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend; no RemoteSigner backend.
* No RocksDB schema change; no file format change; no database migration; no
  network wire schema change; no trust-bundle / authority-marker / sequence
  schema change.
* No autonomous apply; no automatic apply on receipt; no peer-majority
  authority.
* Does not weaken Runs 070, 130–234, and does not claim full C4 or C5 closure.

## Release helper

`crates/qbind-node/examples/run_235_governance_evaluator_replay_consume_boundary_release_binary_helper.rs`

The release-built helper exercises the Run 234 consume-boundary symbols through
production library code and emits a tabular PASS/FAIL corpus (`accepted` /
`rejection` / `reachability`) plus a fixture dump (consume outcome tags,
before/after fixture replay-store snapshots, consume authorization / transcript /
record digests, and a symbol inventory). The pure entry point is
`evaluate_post_mutation_consume`; the explicit-consume entry point is
`perform_post_mutation_consume`, which calls the Run 230
`GovernanceEvaluatorReplayStateWriter::mark_consumed` **only** on the
after-success consume path.

### Accepted / compatible cases (A1–A21)

* **A1** — legacy bypass does not consume (`DoNotConsumeLegacyBypass`).
* **A2** — `ProceedDeferred` does not consume (`DoNotConsumeDeferred`).
* **A3** — validation-only success does not consume
  (`DoNotConsumeValidationOnly`).
* **A4** — authorized-but-not-applied does not consume
  (`DoNotConsumeBeforeApply`).
* **A5** — apply failed does not consume (`DoNotConsumeApplyFailed`).
* **A6** — rolled-back mutation does not consume (`DoNotConsumeRolledBack`).
* **A7** — unsupported surface does not consume
  (`DoNotConsumeUnsupportedSurface`).
* **A8** — MainNet refused does not consume (`DoNotConsumeMainNetRefused`).
* **A9** — DevNet fixture consume records consumed only after
  `AppliedSuccessfully` (`ConsumeFixtureAfterSuccess`).
* **A10** — TestNet fixture consume records consumed only after
  `AppliedSuccessfully` (`ConsumeFixtureAfterSuccess`).
* **A11** — after fixture consume, the same decision validates as
  already-consumed / fail-closed through the Run 230 state.
* **A12** — consume authorization digest is deterministic in release mode.
* **A13** — consume transcript digest is deterministic in release mode.
* **A14** — post-mutation consume record digest is deterministic in release
  mode.
* **A15** — the consume binding includes every required field (replay state
  key, request / response / decision digests, lifecycle action, candidate
  digest, sequence, replay nonce, environment, chain id, genesis hash,
  validation surface, mutation surface, and mutation completion status).
* **A16** — the production consume writer is callable and fails closed
  unavailable (`FailClosedProductionConsumeUnavailable`).
* **A17** — the MainNet consume writer is callable and fails closed
  unavailable / refused (`FailClosedMainNetConsumeUnavailable`).
* **A18** — the Run 232 replay/freshness runtime integration remains compatible
  when the consume boundary is not wired.
* **A19** — Run 233 release behavior remains compatible.
* **A20** — Run 231 replay/freshness standalone release behavior remains
  compatible.
* **A21** — Run 229 peer evaluator-context release behavior remains compatible.

### Rejection cases (R1–R33)

R1 wrong replay state key digest, R2 wrong source identity digest, R3 wrong
request digest, R4 wrong response digest, R5 wrong transcript digest, R6 wrong
decision digest, R7 wrong proposal id, R8 wrong decision id, R9 wrong lifecycle
action, R10 wrong candidate digest, R11 wrong authority-domain sequence, R12
wrong effective epoch, R13 wrong expiry epoch, R14 wrong replay nonce, R15 wrong
environment, R16 wrong chain, R17 wrong genesis, R18 wrong validation surface,
R19 wrong mutation surface, R20 consume before apply, R21 consume after failed
apply, R22 consume after rollback, R23 consume on a validation-only surface, R24
consume on an unsupported surface, R25 production consume unavailable, R26
MainNet consume unavailable/refused, R27 local operator cannot satisfy the
consume policy, R28 peer majority cannot satisfy the consume policy, R29
validator-set rotation unsupported, R30 policy-change action unsupported, R31
malformed consume state, R32 consume rejection produces no Run 070 call, no live
trust swap, no session eviction, no sequence write, and no marker write, R33
MainNet peer-driven apply remains refused and does not consume even when the
replay state is fresh. Every rejection surfaces as a typed
`ConsumeBoundaryOutcome` non-consume / fail-closed variant returned from a pure
function; the writer is never called on a non-consume path.

## Release harness

`scripts/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary.sh`

The harness:

* builds `target/release/qbind-node` and the release helper;
* captures the helper binary SHA-256 + ELF Build ID and the `qbind-node`
  release binary SHA-256 + ELF Build ID;
* runs the helper A1–A21 / R1–R33 corpus and asserts `verdict: PASS`;
* runs real-binary surface scenarios (`--help`, default DevNet/TestNet/MainNet,
  hidden governance-execution selector parse + invalid-selector fail-closed)
  and asserts the binary never claims an active consume-boundary / governance
  surface;
* writes source-reachability grep proof for the Run 234 symbols
  (`pqc_governance_evaluator_replay_consume_boundary`,
  `MutationAuthorizationOutcome`, `MutationCompletionStatus`,
  `ConsumeBoundaryOutcome`, `evaluate_post_mutation_consume`,
  `perform_post_mutation_consume`, `ConsumeFixtureAfterSuccess`,
  `FailClosedConsumeUnavailable`, `FailClosedProductionConsumeUnavailable`,
  `FailClosedMainNetConsumeUnavailable`, the consume
  authorization / transcript / record digest helpers, the fixture consume writer
  path, the production / MainNet consume unavailable path, and the MainNet
  peer-driven refusal guard);
* proves an empty denylist across captured logs (no MainNet apply, no
  autonomous apply, no apply-on-receipt, no peer-majority authority, no real
  governance engine / on-chain verifier / KMS / HSM / RemoteSigner / custody
  active claim, no validator-set rotation, no `--p2p-trusted-root` fallback, no
  active DummySig/DummyKem/DummyAead, no RocksDB/file/schema/migration/wire/
  marker/sequence drift, no marker write before sequence commit, no
  marker/sequence write on validation-only surfaces);
* records the no-mutation / mutation proofs;
* runs the regression test targets below.

## Validation commands

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_235_governance_evaluator_replay_consume_boundary_release_binary_helper`
* `bash scripts/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary.sh`
* `cargo test -p qbind-node --test run_234_governance_evaluator_replay_consume_boundary_tests`
* `cargo test -p qbind-node --test run_232_governance_evaluator_replay_runtime_integration_tests`
* `cargo test -p qbind-node --test run_230_governance_evaluator_replay_state_tests`
* `cargo test -p qbind-node --test run_228_peer_evaluator_context_representation_tests`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`

(Plus the Run 220 / 217 / 215 / 213 / 211 / 157 / 152 / 150 / 148 / 142
regression targets exercised by the harness.) The exact captured commands,
stdout/stderr logs, per-scenario exit codes, consume authorization / transcript /
record digests, consume boundary outcome and mutation completion status values,
and before/after fixture-store snapshots are recorded under
`docs/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary/`
(generated artifacts are `.gitignore`d; `summary.txt` is tracked).

## Acceptance mapping

1. The release-built helper exercises the Run 234 consume boundary through
   release library symbols.
2. Consume is allowed only after successful mutation completion — only
   `ConsumeFixtureAfterSuccess` (after `AppliedSuccessfully`) consumes.
3. Deferred is not consumed (`DoNotConsumeDeferred`).
4. Validation-only is not consumed (`DoNotConsumeValidationOnly`).
5. Failed/rolled-back mutation is not consumed (`DoNotConsumeApplyFailed` /
   `DoNotConsumeRolledBack`).
6. Fixture consume remains DevNet/TestNet evidence-only.
7. Production / MainNet consume remains unavailable / fail-closed.
8. Rejections are non-mutating (the boundary is pure; the writer is never called
   on a non-consume path).
9. MainNet peer-driven apply remains refused and does not consume even when the
   state is fresh.
10. No storage / schema / migration / RocksDB / file-format change is claimed.
11. Existing Run 233, Run 231, Run 229, Run 227, and Run 225 release behavior
    remains compatible.
12. No full C4 or C5 closure is claimed.

## Limitations / honest gaps

* Run 235 is release-binary evidence for a pure, local/source-test-only
  post-mutation consume boundary; the boundary performs no I/O and authorizes no
  mutation directly.
* The boundary composes the Run 230 reader/writer traits and projects the Run
  232 runtime-integration outcome into its `MutationAuthorizationOutcome` view.
* Consume is after-success-only — only `ConsumeFixtureAfterSuccess` (after
  `AppliedSuccessfully`) authorizes a fixture consume; deferred,
  validation-only, authorized-but-not-applied, failed-apply, rolled-back,
  unsupported-surface, and MainNet-refused outcomes never consume.
* Fixture consume remains DevNet/TestNet evidence-only (the
  `FixtureReplayStateStore` is an in-process map; it reads as `Unavailable` for
  a MainNet environment and introduces no storage format).
* Production / MainNet consume remains unavailable / fail-closed; no real
  governance engine or on-chain proof verifier is implemented.
* No RocksDB / file / schema / migration / storage format change is
  implemented.
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* Full C4 remains OPEN.
* C5 remains OPEN.